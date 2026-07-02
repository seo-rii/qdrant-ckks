use std::collections::{HashMap, HashSet};

use ahash::AHashMap;
use common::counter::hardware_accumulator::HwMeasurementAcc;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;

use super::{Collection, collection_encryption_uses_private_oram_bucket_store};
use crate::collection::payload_index_schema::PayloadIndexSchema;
use crate::collection_state::{ShardInfo, State};
use crate::config::{CollectionConfigInternal, CollectionParams};
use crate::operations::types::{CollectionError, CollectionResult};
use crate::shards::replica_set::ShardReplicaSet;
use crate::shards::resharding::ReshardState;
use crate::shards::shard::{PeerId, ShardId};
use crate::shards::shard_holder::ShardTransferChange;
use crate::shards::shard_holder::shard_mapping::ShardKeyMapping;
use crate::shards::transfer::ShardTransfer;

impl Collection {
    pub async fn check_config_compatible(
        &self,
        config: &CollectionConfigInternal,
    ) -> CollectionResult<()> {
        self.collection_config
            .read()
            .await
            .params
            .check_compatible(&config.params)
    }

    pub async fn apply_state(
        &self,
        state: State,
        this_peer_id: PeerId,
        abort_transfer: impl FnMut(ShardTransfer),
    ) -> CollectionResult<()> {
        let State {
            config,
            shards,
            resharding,
            transfers,
            shards_key_mapping,
            payload_index_schema,
        } = state;

        self.apply_config(config).await?;
        self.apply_shard_transfers(transfers, this_peer_id, abort_transfer)
            .await?;
        self.apply_reshard_state(resharding).await?;
        self.apply_shard_info(shards, shards_key_mapping).await?;
        self.apply_payload_index_schema(payload_index_schema)
            .await?;
        Ok(())
    }

    async fn apply_shard_transfers(
        &self,
        shard_transfers: HashSet<ShardTransfer>,
        this_peer_id: PeerId,
        mut abort_transfer: impl FnMut(ShardTransfer),
    ) -> CollectionResult<()> {
        let private_oram_bucket_store_collection = {
            let config = self.collection_config.read().await;
            config
                .params
                .effective_encryption()
                .as_ref()
                .is_some_and(collection_encryption_uses_private_oram_bucket_store)
        };
        validate_private_oram_apply_shard_transfers_until_supported(
            &shard_transfers,
            private_oram_bucket_store_collection,
        )?;

        let old_transfers = self
            .shards_holder
            .read()
            .await
            .shard_transfers
            .read()
            .clone();
        for transfer in shard_transfers.intersection(&old_transfers) {
            log::debug!("Aborting shard transfer: {transfer:?}");
        }
        for transfer in old_transfers.difference(&shard_transfers) {
            log::debug!("Aborting shard transfer: {transfer:?}");
        }
        for transfer in shard_transfers.difference(&old_transfers) {
            if transfer.from == this_peer_id {
                // Abort transfer as sender should not learn about the transfer from snapshot
                // If this happens it mean the sender is probably outdated and it is safer to abort
                abort_transfer(transfer.clone());
                // Since we remove the transfer from our list below, we don't invoke regular abort logic on this node
                // Do it here explicitly so we don't miss a silent abort change
                let _ = self
                    .shards_holder
                    .read()
                    .await
                    .shard_transfer_changes
                    .send(ShardTransferChange::Abort(transfer.key()));
            }
        }
        self.shards_holder
            .write()
            .await
            .shard_transfers
            .write(|transfers| *transfers = shard_transfers)?;
        Ok(())
    }

    async fn apply_reshard_state(&self, resharding: Option<ReshardState>) -> CollectionResult<()> {
        let private_oram_bucket_store_collection = {
            let config = self.collection_config.read().await;
            config
                .params
                .effective_encryption()
                .as_ref()
                .is_some_and(collection_encryption_uses_private_oram_bucket_store)
        };
        validate_private_oram_apply_reshard_state_until_supported(
            resharding.as_ref(),
            private_oram_bucket_store_collection,
        )?;

        // We don't have to explicitly abort resharding or bump shard replica states, because:
        // - peers are not driving resharding themselves
        // - ongoing (resharding) shard transfers are explicitly updated
        // - shard replica set states are explicitly updated
        self.shards_holder
            .write()
            .await
            .resharding_state
            .write(|state| *state = resharding)?;
        Ok(())
    }

    async fn apply_config(&self, new_config: CollectionConfigInternal) -> CollectionResult<()> {
        let recreate_optimizers;

        {
            let mut config = self.collection_config.write().await;

            if config.uuid != new_config.uuid {
                return Err(CollectionError::service_error(format!(
                    "collection {} UUID mismatch: \
                     UUID of existing collection is different from UUID of collection in Raft snapshot: \
                     existing collection UUID: {:?}, Raft snapshot collection UUID: {:?}",
                    self.id, config.uuid, new_config.uuid,
                )));
            }

            if let Err(err) = config.params.check_compatible(&new_config.params) {
                // Stop consensus with a service error, if new config is incompatible with current one.
                //
                // We expect that `apply_config` is only called when configs are compatible, otherwise
                // collection have to be *recreated*.
                return Err(CollectionError::service_error(err.to_string()));
            }
            validate_private_oram_apply_config_layout_until_supported(
                &config.params,
                &new_config.params,
            )?;

            // Destructure `new_config`, to ensure we compare all config fields. Compiler would
            // complain, if new field is added to `CollectionConfig` struct, but not destructured
            // explicitly. We have to explicitly compare config fields, because we want to compare
            // `wal_config` and `strict_mode_config` independently of other fields.
            let CollectionConfigInternal {
                params,
                hnsw_config,
                optimizer_config,
                wal_config,
                quantization_config,
                strict_mode_config,
                uuid: _,
                metadata,
            } = &new_config;

            let is_core_config_updated = params != &config.params
                || hnsw_config != &config.hnsw_config
                || optimizer_config != &config.optimizer_config
                || quantization_config != &config.quantization_config;

            let is_metadata_updated = metadata != &config.metadata;

            let is_wal_config_updated = wal_config != &config.wal_config;
            let is_strict_mode_config_updated = strict_mode_config != &config.strict_mode_config;

            let is_config_updated = is_core_config_updated
                || is_wal_config_updated
                || is_strict_mode_config_updated
                || is_metadata_updated;

            if !is_config_updated {
                return Ok(());
            }

            if is_wal_config_updated {
                log::warn!(
                    "WAL config of collection {} updated when applying Raft snapshot, \
                     but updated WAL config will only be applied on Qdrant restart",
                    self.id,
                );
            }

            *config = new_config;

            // We need to recreate optimizers, if "core" config was updated
            recreate_optimizers = is_core_config_updated;
        }

        self.collection_config.read().await.save(&self.path)?;

        self.print_warnings().await;

        if recreate_optimizers {
            self.recreate_optimizers_blocking().await?;
        }

        Ok(())
    }

    async fn apply_shard_info(
        &self,
        shards: AHashMap<ShardId, ShardInfo>,
        shards_key_mapping: ShardKeyMapping,
    ) -> CollectionResult<()> {
        let mut extra_shards: AHashMap<ShardId, ShardReplicaSet> = AHashMap::new();

        let shard_ids = shards.keys().copied().collect::<HashSet<_>>();
        let private_oram_bucket_store_collection = {
            let config = self.collection_config.read().await;
            config
                .params
                .effective_encryption()
                .as_ref()
                .is_some_and(collection_encryption_uses_private_oram_bucket_store)
        };

        // There are two components, where shard-related info is stored:
        // Shard objects themselves and shard_holder, that maps shard_keys to shards.

        // On the first state of the update, we update state of shards themselves
        // and create new shards if needed

        let mut shards_holder = self.shards_holder.write().await;

        let current_shard_ids = shards_holder
            .get_shards()
            .map(|(shard_id, _)| shard_id)
            .collect::<HashSet<_>>();
        let current_shards_key_mapping = shards_holder.get_shard_key_to_ids_mapping();
        let current_replica_peers = shards_holder
            .get_shards()
            .map(|(shard_id, replica_set)| {
                (
                    shard_id,
                    replica_set.peers().keys().copied().collect::<HashSet<_>>(),
                )
            })
            .collect::<HashMap<_, _>>();

        validate_private_oram_apply_shard_info_until_supported(
            &shards,
            &shards_key_mapping,
            &current_shard_ids,
            &current_shards_key_mapping,
            &current_replica_peers,
            private_oram_bucket_store_collection,
        )?;

        for (shard_id, shard_info) in shards {
            let shard_key = shards_key_mapping.shard_key(shard_id);
            match shards_holder.get_shard_mut(shard_id) {
                Some(replica_set) => {
                    replica_set
                        .apply_state(shard_info.replicas, shard_key)
                        .await?;
                }
                None => {
                    let shard_replicas: Vec<_> = shard_info.replicas.keys().copied().collect();
                    let mut replica_set = self
                        .create_replica_set(shard_id, shard_key.clone(), &shard_replicas, None)
                        .await?;
                    replica_set
                        .apply_state(shard_info.replicas, shard_key)
                        .await?;
                    extra_shards.insert(shard_id, replica_set);
                }
            }
        }

        // On the second step, we register missing shards and remove extra shards
        shards_holder
            .apply_shards_state(shard_ids, shards_key_mapping, extra_shards)
            .await
    }

    async fn apply_payload_index_schema(
        &self,
        payload_index_schema: PayloadIndexSchema,
    ) -> CollectionResult<()> {
        let state = self.state().await;

        for field_name in state.payload_index_schema.schema.keys() {
            if !payload_index_schema.schema.contains_key(field_name) {
                self.drop_payload_index(field_name.clone()).await?;
            }
        }

        for (field_name, field_schema) in payload_index_schema.schema {
            // This function is only used in collection state recovery and thus an unmeasured internal operation.
            self.create_payload_index(field_name, field_schema, HwMeasurementAcc::disposable())
                .await?;
        }
        Ok(())
    }

    /// Truncate unapplied WAL records for all local shards in the collection.
    /// Returns amount of removed records.
    pub async fn truncate_unapplied_wal(&self) -> CollectionResult<usize> {
        let shard_holder = self.shards_holder.clone().read_owned().await;

        let results = self
            .update_runtime
            .spawn(async move {
                let local_updates: FuturesUnordered<_> = shard_holder
                    .all_shards()
                    .map(|shard| shard.truncate_unapplied_wal())
                    .collect();

                let results: Vec<_> = local_updates.collect().await;

                results
            })
            .await?;

        results.into_iter().sum()
    }
}

fn validate_private_oram_apply_reshard_state_until_supported(
    resharding: Option<&ReshardState>,
    private_oram_bucket_store_collection: bool,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection || resharding.is_none() {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot apply resharding state for private ORAM collections: collection-local encrypted \
         ORAM buckets cannot be moved by consensus snapshot apply until ORAM bucket migration and \
         consensus-backed epoch/root ownership are implemented",
    ))
}

fn validate_private_oram_apply_config_layout_until_supported(
    current: &CollectionParams,
    next: &CollectionParams,
) -> CollectionResult<()> {
    let private_oram_bucket_store_collection = current
        .effective_encryption()
        .as_ref()
        .is_some_and(collection_encryption_uses_private_oram_bucket_store);
    if !private_oram_bucket_store_collection {
        return Ok(());
    }

    if current.shard_number == next.shard_number
        && current.sharding_method == next.sharding_method
        && current.replication_factor == next.replication_factor
    {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot apply shard layout config change for private ORAM collections: collection-local \
         encrypted ORAM buckets cannot be repartitioned or replicated by consensus snapshot apply \
         until ORAM bucket migration and consensus-backed epoch/root ownership are implemented",
    ))
}

fn validate_private_oram_apply_shard_transfers_until_supported(
    shard_transfers: &HashSet<ShardTransfer>,
    private_oram_bucket_store_collection: bool,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection || shard_transfers.is_empty() {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot apply shard transfer state for private ORAM collections: encrypted ORAM bucket \
         transfer and consensus-backed epoch/root ownership are not implemented for consensus \
         snapshot apply",
    ))
}

fn validate_private_oram_apply_shard_info_until_supported(
    shards: &AHashMap<ShardId, ShardInfo>,
    shards_key_mapping: &ShardKeyMapping,
    current_shard_ids: &HashSet<ShardId>,
    current_shards_key_mapping: &ShardKeyMapping,
    current_replica_peers: &HashMap<ShardId, HashSet<PeerId>>,
    private_oram_bucket_store_collection: bool,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection {
        return Ok(());
    }

    let shard_ids = shards.keys().copied().collect::<HashSet<_>>();
    let membership_changes = shards.iter().any(|(shard_id, shard_info)| {
        let incoming_peers = shard_info.replicas.keys().copied().collect::<HashSet<_>>();
        current_replica_peers.get(shard_id) != Some(&incoming_peers)
    });
    let touches_resharding_replica_state = shards.values().any(|shard_info| {
        shard_info
            .replicas
            .values()
            .any(|state| state.is_resharding())
    });

    if shard_ids == *current_shard_ids
        && shards_key_mapping == current_shards_key_mapping
        && !membership_changes
        && !touches_resharding_replica_state
    {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot apply shard-info layout change for private ORAM collections: collection-local \
         encrypted ORAM buckets cannot be moved, deleted, or reassigned by consensus snapshot \
         apply until ORAM bucket migration and consensus-backed epoch/root ownership are \
         implemented",
    ))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use uuid::Uuid;

    use super::*;
    use crate::config::{
        CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector,
        ShardingMethod,
    };
    use crate::operations::cluster_ops::ReshardingDirection;
    use crate::shards::replica_set::replica_set_state::ReplicaState;
    use crate::shards::transfer::ShardTransferMethod;

    #[test]
    fn private_oram_apply_reshard_state_guard_redacts_collection_details() {
        let resharding = ReshardState::new(
            Uuid::nil(),
            ReshardingDirection::Up,
            2,
            3,
            Some("tenant-secret-shard-key".into()),
        );

        validate_private_oram_apply_reshard_state_until_supported(None, true).unwrap();
        validate_private_oram_apply_reshard_state_until_supported(Some(&resharding), false)
            .unwrap();

        let err =
            validate_private_oram_apply_reshard_state_until_supported(Some(&resharding), true)
                .unwrap_err();
        let rendered = format!("{err:?}");

        assert!(rendered.contains("cannot apply resharding state for private ORAM collections"));
        assert!(rendered.contains("collection-local encrypted ORAM buckets"));
        assert!(rendered.contains("consensus-backed epoch/root"));
        assert!(!rendered.contains("tenant-secret-shard-key"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
        assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));
    }

    #[test]
    fn private_oram_apply_config_layout_guard_redacts_collection_details() {
        let private_params = private_oram_params_fixture();

        validate_private_oram_apply_config_layout_until_supported(&private_params, &private_params)
            .unwrap();

        let mut ordinary_changed = CollectionParams::empty();
        ordinary_changed.shard_number = NonZeroU32::new(2).unwrap();
        validate_private_oram_apply_config_layout_until_supported(
            &CollectionParams::empty(),
            &ordinary_changed,
        )
        .unwrap();

        let mut changed_shards = private_params.clone();
        changed_shards.shard_number = NonZeroU32::new(2).unwrap();
        let mut changed_method = private_params.clone();
        changed_method.sharding_method = Some(ShardingMethod::Custom);
        let mut changed_replication = private_params.clone();
        changed_replication.replication_factor = NonZeroU32::new(2).unwrap();

        for next in [changed_shards, changed_method, changed_replication] {
            let err =
                validate_private_oram_apply_config_layout_until_supported(&private_params, &next)
                    .unwrap_err();
            let rendered = format!("{err:?}");

            assert!(rendered.contains("cannot apply shard layout config change"));
            assert!(rendered.contains("collection-local encrypted ORAM buckets"));
            assert!(rendered.contains("consensus-backed epoch/root"));
            assert!(!rendered.contains("tenant-a/vector-private-rk"));
            assert!(!rendered.contains("docs_text_private_hnsw"));
            assert!(!rendered.contains("docs_private_hnsw_v1"));
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains("private_result_oram"));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));
        }
    }

    #[test]
    fn private_oram_apply_config_layout_guard_redacts_client_state_aliases() {
        let private_params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("clientStateCiphertextHash.json".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![
                    EncryptionRuleRef {
                        id: "encryptedClientStateCiphertext.json".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![
                                "positionMapBackup.json".to_string(),
                                "positionMapBackups.json".to_string(),
                                "position_map_backup.json".to_string(),
                                "clientState.json".to_string(),
                                "clientStates.json".to_string(),
                                "client_state.json".to_string(),
                                "client_states.json".to_string(),
                                "clientStateBackup.json".to_string(),
                                "clientStateBackups.json".to_string(),
                                "client_state_backup.json".to_string(),
                                "clientStateSnapshot.json".to_string(),
                                "clientStateSnapshots.json".to_string(),
                                "client_state_snapshot.json".to_string(),
                                "client_state_snapshots.json".to_string(),
                                "clientStateCiphertext.json".to_string(),
                                "clientStateCiphertextHashes.json".to_string(),
                                "clientStateCiphertextSha256.json".to_string(),
                                "clientStateCiphertextsSha256.json".to_string(),
                                "client_state_ciphertext_hash.json".to_string(),
                                "client_state_ciphertext_hash.bin".to_string(),
                                "client_state_ciphertext_hashes.json".to_string(),
                                "client_state_ciphertext_sha256.json".to_string(),
                                "client_state_ciphertexts_sha256.bin".to_string(),
                                "client_state_ciphertexts_sha256.json".to_string(),
                                "encryptedClientStateBackup.json".to_string(),
                                "encryptedClientStateBackups.json".to_string(),
                                "encryptedClientState.json".to_string(),
                                "encryptedClientStates.json".to_string(),
                                "encrypted_client_states.json".to_string(),
                                "encrypted_client_state_backup.json".to_string(),
                                "encryptedClientStateSnapshot.json".to_string(),
                                "encryptedClientStateSnapshots.json".to_string(),
                                "encrypted_client_state_backups.json".to_string(),
                                "encrypted_client_state_snapshot.json".to_string(),
                                "encrypted_client_state_snapshots.json".to_string(),
                                "encryptedClientStateCiphertextHash.json".to_string(),
                                "encryptedClientStateCiphertextHashes.json".to_string(),
                                "encryptedClientStateCiphertextSha256.json".to_string(),
                                "encryptedClientStateCiphertextsSha256.json".to_string(),
                                "encrypted_client_state_ciphertext_hash.json".to_string(),
                                "encrypted_client_state_ciphertext_hash.bin".to_string(),
                                "encrypted_client_state_ciphertext_hashes.json".to_string(),
                                "encrypted_client_state_ciphertext_sha256.json".to_string(),
                                "encrypted_client_state_ciphertexts_sha256.bin".to_string(),
                                "encrypted_client_state_ciphertexts_sha256.json".to_string(),
                            ],
                        },
                        instance: "oramPositionMapBackups.json".to_string(),
                        binding: Some(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    },
                    EncryptionRuleRef {
                        id: "tokenMapBackup.json".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec![
                                "stashBackup.json".to_string(),
                                "stashBackups.json".to_string(),
                                "stash_backup.json".to_string(),
                                "stateCiphertext.json".to_string(),
                                "stateCiphertextHashes.json".to_string(),
                                "stateCiphertextSha256.json".to_string(),
                                "stateCiphertextsSha256.json".to_string(),
                                "state_ciphertext_hash.bin".to_string(),
                                "state_ciphertext_hash.json".to_string(),
                                "state_ciphertext_hashes.json".to_string(),
                                "state_ciphertext_hashes.bin".to_string(),
                                "state_ciphertext_sha256.json".to_string(),
                                "state_ciphertexts_sha256.bin".to_string(),
                                "state_ciphertexts_sha256.json".to_string(),
                                "tokenPositionMapBackup.json".to_string(),
                                "tokenMapBackups.json".to_string(),
                                "token_map_backup.json".to_string(),
                                "token_map_backups.json".to_string(),
                                "tokenPositionMapBackups.json".to_string(),
                                "token_position_map_backup.json".to_string(),
                                "token_position_map_backups.json".to_string(),
                            ],
                        },
                        instance: "oramPositionMapBackup.json".to_string(),
                        binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
                    },
                ],
            }),
            ..CollectionParams::empty()
        };
        let mut changed_layout = private_params.clone();
        changed_layout.shard_number = NonZeroU32::new(2).unwrap();

        let err = validate_private_oram_apply_config_layout_until_supported(
            &private_params,
            &changed_layout,
        )
        .unwrap_err();
        let rendered = format!("{err:?}");

        assert!(rendered.contains("cannot apply shard layout config change"));
        assert!(rendered.contains("consensus-backed epoch/root"));
        for sentinel in [
            "clientState",
            "clientStates",
            "client_state",
            "client_states",
            "clientStateBackup",
            "clientStateBackups",
            "client_state_backup",
            "clientStateSnapshot",
            "clientStateSnapshots",
            "client_state_snapshot",
            "client_state_snapshots",
            "clientStateCiphertext",
            "clientStateCiphertextHash",
            "clientStateCiphertextHashes",
            "clientStateCiphertextSha256",
            "clientStateCiphertextsSha256",
            "client_state_ciphertext_hash",
            "client_state_ciphertext_hashes",
            "client_state_ciphertext_sha256",
            "client_state_ciphertexts_sha256",
            "encryptedClientStateBackup",
            "encryptedClientStateBackups",
            "encryptedClientState",
            "encryptedClientStates",
            "encrypted_client_states",
            "encrypted_client_state_backup",
            "encryptedClientStateSnapshot",
            "encryptedClientStateSnapshots",
            "encrypted_client_state_backups",
            "encrypted_client_state_snapshot",
            "encrypted_client_state_snapshots",
            "encryptedClientStateCiphertext",
            "encryptedClientStateCiphertextHash",
            "encryptedClientStateCiphertextHashes",
            "encryptedClientStateCiphertextSha256",
            "encryptedClientStateCiphertextsSha256",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_hashes",
            "encrypted_client_state_ciphertext_sha256",
            "encrypted_client_state_ciphertexts_sha256",
            "positionMapBackup",
            "positionMapBackups",
            "position_map_backup",
            "oramPositionMapBackup",
            "oramPositionMapBackups",
            "oram_position_map_backup",
            "tokenMapBackup",
            "tokenMapBackups",
            "token_map_backup",
            "token_map_backups",
            "tokenPositionMapBackup",
            "tokenPositionMapBackups",
            "token_position_map_backup",
            "token_position_map_backups",
            "stateCiphertext",
            "stateCiphertextHash",
            "stateCiphertextHashes",
            "stateCiphertextSha256",
            "stateCiphertextsSha256",
            "state_ciphertext_hash",
            "state_ciphertext_hashes",
            "state_ciphertext_sha256",
            "state_ciphertexts_sha256",
            "stashBackup",
            "stashBackups",
            "stash_backup",
            qdrant_sec::PRIVATE_HNSW_ORAM_BINDING,
            qdrant_sec::PRIVATE_RESULT_ORAM_BINDING,
            "private_hnsw_oram",
            "private_result_oram",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "private ORAM consensus apply leaked client-state alias `{sentinel}`: {rendered}",
            );
        }
    }

    #[test]
    fn private_oram_apply_shard_transfers_guard_redacts_collection_details() {
        let transfers = HashSet::from([ShardTransfer {
            shard_id: 9,
            to_shard_id: Some(10),
            from: 1001,
            to: 2002,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            filter: None,
        }]);

        validate_private_oram_apply_shard_transfers_until_supported(&HashSet::new(), true).unwrap();
        validate_private_oram_apply_shard_transfers_until_supported(&transfers, false).unwrap();

        let err = validate_private_oram_apply_shard_transfers_until_supported(&transfers, true)
            .unwrap_err();
        let rendered = format!("{err:?}");

        assert!(
            rendered.contains("cannot apply shard transfer state for private ORAM collections")
        );
        assert!(rendered.contains("encrypted ORAM bucket transfer"));
        assert!(rendered.contains("consensus-backed epoch/root"));
        assert!(!rendered.contains("shard 9"));
        assert!(!rendered.contains("1001"));
        assert!(!rendered.contains("2002"));
        assert!(!rendered.contains("StreamRecords"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
        assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));
    }

    #[test]
    fn private_oram_apply_shard_info_guard_redacts_collection_details() {
        let mut current_mapping = ShardKeyMapping::default();
        current_mapping.insert("tenant-secret-shard-key".into(), HashSet::from([1]));

        let current_shard_ids = HashSet::from([1]);
        let current_replica_peers = HashMap::from([(1, HashSet::from([7]))]);

        let active_shards = shard_info_fixture(1, [(7, ReplicaState::Active)]);
        validate_private_oram_apply_shard_info_until_supported(
            &active_shards,
            &current_mapping,
            &current_shard_ids,
            &current_mapping,
            &current_replica_peers,
            true,
        )
        .unwrap();

        for state_only_update in [
            ReplicaState::Dead,
            ReplicaState::Partial,
            ReplicaState::Initializing,
            ReplicaState::Listener,
            ReplicaState::PartialSnapshot,
            ReplicaState::Recovery,
            ReplicaState::ActiveRead,
            ReplicaState::ManualRecovery,
        ] {
            validate_private_oram_apply_shard_info_until_supported(
                &shard_info_fixture(1, [(7, state_only_update)]),
                &current_mapping,
                &current_shard_ids,
                &current_mapping,
                &current_replica_peers,
                true,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "private ORAM consensus apply must allow non-resharding state-only sync for {state_only_update:?}: {err}"
                )
            });
        }

        for (shards, mapping) in [
            (
                shard_info_fixture(2, [(7, ReplicaState::Active)]),
                current_mapping.clone(),
            ),
            (
                shard_info_fixture(1, [(8, ReplicaState::Active)]),
                current_mapping.clone(),
            ),
            (
                shard_info_fixture(1, [(7, ReplicaState::Resharding)]),
                current_mapping.clone(),
            ),
            (active_shards.clone(), ShardKeyMapping::default()),
        ] {
            validate_private_oram_apply_shard_info_until_supported(
                &shards,
                &mapping,
                &current_shard_ids,
                &current_mapping,
                &current_replica_peers,
                false,
            )
            .unwrap();

            let err = validate_private_oram_apply_shard_info_until_supported(
                &shards,
                &mapping,
                &current_shard_ids,
                &current_mapping,
                &current_replica_peers,
                true,
            )
            .unwrap_err();
            let rendered = format!("{err:?}");

            assert!(rendered.contains("cannot apply shard-info layout change"));
            assert!(rendered.contains("collection-local encrypted ORAM buckets"));
            assert!(rendered.contains("consensus-backed epoch/root"));
            assert!(!rendered.contains("tenant-secret-shard-key"));
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains("private_result_oram"));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));
        }
    }

    fn shard_info_fixture(
        shard_id: ShardId,
        replicas: impl IntoIterator<Item = (PeerId, ReplicaState)>,
    ) -> AHashMap<ShardId, ShardInfo> {
        AHashMap::from_iter([(
            shard_id,
            ShardInfo {
                replicas: HashMap::from_iter(replicas),
            },
        )])
    }

    fn private_oram_params_fixture() -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/vector-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "docs_text_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["text".to_string()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }
}
