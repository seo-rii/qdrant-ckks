use std::collections::HashMap;
use std::sync::Arc;

use collection::collection::Collection;
use collection::collection_state;
use collection::config::CollectionParams;
use collection::shards::CollectionId;
use collection::shards::collection_shard_distribution::CollectionShardDistribution;
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::shard::PeerId;

use super::TableOfContent;
use crate::content_manager::collection_meta_ops::*;
use crate::content_manager::collections_ops::Checker as _;
use crate::content_manager::consensus::operation_sender::OperationSender;
use crate::content_manager::consensus_ops::ConsensusOperations;
use crate::content_manager::errors::StorageError;
use crate::content_manager::{CollectionContainer, consensus_manager};

impl CollectionContainer for TableOfContent {
    fn perform_collection_meta_op(
        &self,
        operation: CollectionMetaOperations,
    ) -> Result<bool, StorageError> {
        self.perform_collection_meta_op_sync(operation)
    }

    fn collections_snapshot(&self) -> consensus_manager::CollectionsSnapshot {
        self.collections_snapshot_sync()
    }

    fn apply_collections_snapshot(
        &self,
        data: consensus_manager::CollectionsSnapshot,
    ) -> Result<(), StorageError> {
        self.apply_collections_snapshot(data)
    }

    fn remove_peer(&self, peer_id: PeerId) -> Result<(), StorageError> {
        self.general_runtime.block_on(async {
            // Validation:
            // 1. Check that we are not removing some unique shards (removed)

            // Validation passed

            self.remove_shards_at_peer(peer_id).await?;

            if self.this_peer_id == peer_id {
                // We are detaching the current peer, so we need to remove all connections
                // Remove all peers from the channel service

                let ids_to_drop: Vec<_> = self
                    .channel_service
                    .id_to_address
                    .read()
                    .keys()
                    .filter(|id| **id != self.this_peer_id)
                    .copied()
                    .collect();
                for id in ids_to_drop {
                    self.channel_service.remove_peer(id).await;
                }
            } else {
                self.channel_service.remove_peer(peer_id).await;
            }
            Ok(())
        })
    }

    fn sync_local_state(&self) -> Result<(), StorageError> {
        self.general_runtime.block_on(async {
            let collections = self.collections.read().await;
            let transfer_failure_callback =
                Self::on_transfer_failure_callback(self.consensus_proposal_sender.clone());
            let transfer_success_callback =
                Self::on_transfer_success_callback(self.consensus_proposal_sender.clone());

            for collection in collections.values() {
                let finish_shard_initialize = Self::change_peer_state_callback(
                    self.consensus_proposal_sender.clone(),
                    collection.name().to_string(),
                    ReplicaState::Active,
                    Some(ReplicaState::Initializing),
                );
                let convert_to_listener_callback = Self::change_peer_state_callback(
                    self.consensus_proposal_sender.clone(),
                    collection.name().to_string(),
                    ReplicaState::Listener,
                    Some(ReplicaState::Active),
                );
                let convert_from_listener_to_active_callback = Self::change_peer_state_callback(
                    self.consensus_proposal_sender.clone(),
                    collection.name().to_string(),
                    ReplicaState::Active,
                    Some(ReplicaState::Listener),
                );

                collection
                    .sync_local_state(
                        transfer_failure_callback.clone(),
                        transfer_success_callback.clone(),
                        finish_shard_initialize,
                        convert_to_listener_callback,
                        convert_from_listener_to_active_callback,
                    )
                    .await?;
            }
            Ok(())
        })
    }
}

fn collection_params_bind_crypto_identity(params: &CollectionParams) -> bool {
    params.effective_encryption().is_some()
}

fn encrypted_uuid_mismatch_requires_fail_closed(
    existing_params: &CollectionParams,
    snapshot_params: &CollectionParams,
) -> bool {
    collection_params_bind_crypto_identity(existing_params)
        || collection_params_bind_crypto_identity(snapshot_params)
}

#[cfg(test)]
mod tests {
    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector,
    };

    use super::{
        collection_params_bind_crypto_identity, encrypted_uuid_mismatch_requires_fail_closed,
    };

    fn encrypted_params() -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/payload".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    #[test]
    fn collection_params_bind_crypto_identity_for_encrypted_configs() {
        assert!(!collection_params_bind_crypto_identity(
            &CollectionParams::empty()
        ));

        let encrypted = encrypted_params();

        assert!(collection_params_bind_crypto_identity(&encrypted));
    }

    #[test]
    fn encrypted_uuid_mismatch_requires_fail_closed_for_encrypted_configs() {
        let plaintext = CollectionParams::empty();
        let encrypted = encrypted_params();

        assert!(!encrypted_uuid_mismatch_requires_fail_closed(
            &plaintext, &plaintext,
        ));
        assert!(encrypted_uuid_mismatch_requires_fail_closed(
            &encrypted, &plaintext,
        ));
        assert!(encrypted_uuid_mismatch_requires_fail_closed(
            &plaintext, &encrypted,
        ));
    }
}

impl TableOfContent {
    fn collections_snapshot_sync(&self) -> consensus_manager::CollectionsSnapshot {
        self.general_runtime.block_on(self.collections_snapshot())
    }

    async fn collections_snapshot(&self) -> consensus_manager::CollectionsSnapshot {
        let mut collections: HashMap<CollectionId, collection_state::State> = HashMap::new();
        for (id, collection) in self.collections.read().await.iter() {
            collections.insert(id.clone(), collection.state().await);
        }
        consensus_manager::CollectionsSnapshot {
            collections,
            aliases: self.alias_persistence.read().await.state().clone(),
        }
    }

    fn apply_collections_snapshot(
        &self,
        data: consensus_manager::CollectionsSnapshot,
    ) -> Result<(), StorageError> {
        self.general_runtime.block_on(async {
            let mut collections = self.collections.write().await;

            for (id, state) in &data.collections {
                if let Some(collection) = collections.get(id) {
                    let collection_config = collection.config_snapshot().await;
                    let collection_uuid = collection_config.uuid;

                    let recreate_collection = if collection_uuid != state.config.uuid {
                        if encrypted_uuid_mismatch_requires_fail_closed(
                            &collection_config.params,
                            &state.config.params,
                        ) {
                            return Err(StorageError::service_error(format!(
                                "encrypted collection {id} UUID mismatch while applying Raft snapshot: \
                                 existing collection UUID: {collection_uuid:?}, \
                                 Raft snapshot collection UUID: {:?}; refusing encrypted collection rebind",
                                state.config.uuid,
                            )));
                        }

                        log::warn!(
                            "Recreating collection {id}, because collection UUID is different: \
                             existing collection UUID: {collection_uuid:?}, \
                             Raft snapshot collection UUID: {:?}",
                            state.config.uuid,
                        );

                        true
                    } else if let Err(err) = collection.check_config_compatible(&state.config).await {
                        log::warn!(
                            "Recreating collection {id}, because collection config is incompatible: \
                             {err}",
                        );

                        true
                    } else {
                        false
                    };

                    if recreate_collection {
                        // Drop `collections` lock
                        drop(collections);

                        // Delete collection
                        self.delete_collection(id).await?;

                        // Re-acquire `collections` lock 🙄
                        collections = self.collections.write().await;
                    }
                }

                let collection_exists = collections.contains_key(id);

                // Create collection if not present locally
                if !collection_exists {
                    let collection_path = self.create_collection_path(id).await?;
                    let snapshots_path = self.create_snapshots_path(id).await?;
                    let shard_distribution =
                        CollectionShardDistribution::from_shards_info(state.shards.clone());
                    let collection = Collection::new(
                        id.clone(),
                        self.this_peer_id,
                        &collection_path,
                        &snapshots_path,
                        &state.config,
                        self.storage_config
                            .to_shared_storage_config(self.is_distributed())
                            .into(),
                        shard_distribution,
                        Some(state.shards_key_mapping.clone()),
                        self.channel_service.clone(),
                        Self::change_peer_from_state_callback(
                            self.consensus_proposal_sender.clone(),
                            id.clone(),
                            ReplicaState::Dead,
                        ),
                        Self::request_shard_transfer_callback(
                            self.consensus_proposal_sender.clone(),
                            id.clone(),
                        ),
                        Self::abort_shard_transfer_callback(
                            self.consensus_proposal_sender.clone(),
                            id.clone(),
                        ),
                        Some(self.search_runtime.handle().clone()),
                        Some(self.update_runtime.handle().clone()),
                        self.optimizer_resource_budget.clone(),
                        self.storage_config.optimizers_overwrite.clone(),
                    )
                    .await?;
                    collections.validate_collection_not_exists(id)?;
                    collections.insert(id.clone(), Arc::new(collection));
                }

                let Some(collection) = collections.get(id) else {
                    return Err(StorageError::service_error(format!(
                        "collection {id} is missing after snapshot apply",
                    )));
                };

                // Update collection state
                if &collection.state().await != state {
                    if let Some(proposal_sender) = self.consensus_proposal_sender.clone() {
                        // In some cases on state application it might be needed to abort the transfer
                        let abort_transfer = |transfer| {
                            if let Err(error) =
                                proposal_sender.send(ConsensusOperations::abort_transfer(
                                    id.clone(),
                                    transfer,
                                    "sender was not up to date",
                                ))
                            {
                                log::error!(
                                    "Can't report transfer progress to consensus: {error}"
                                )
                            };
                        };
                        collection
                            .apply_state(state.clone(), self.this_peer_id(), abort_transfer)
                            .await?;
                    } else {
                        log::error!("Can't apply state: single node mode");
                    }
                }

                // Mark local shards as dead (to initiate shard transfer),
                // if collection has been created during snapshot application
                if !collection_exists {
                    for shard_id in collection.get_local_shards().await {
                        let shard_holder = collection.shards_holder().read_owned().await;

                        let Some(replica_set) = shard_holder.get_shard(shard_id) else {
                            continue;
                        };

                        if replica_set.is_local().await {
                            replica_set.add_locally_disabled(None, self.this_peer_id, None);
                        }
                    }
                }
            }

            // Collect names of collections that are present locally
            let collection_names: Vec<_> = collections.keys().cloned().collect();

            // Drop `collections` lock
            drop(collections);

            // Remove collections that are present locally, but are not in the snapshot state
            for collection_name in &collection_names {
                if !data.collections.contains_key(collection_name) {
                    log::debug!(
                        "Deleting collection {collection_name} \
                         because it is not part of the consensus snapshot",
                    );

                    self.delete_collection(collection_name).await?;
                }
            }

            // Apply alias mapping
            self.alias_persistence
                .write()
                .await
                .apply_state(data.aliases)?;

            Ok(())
        })
    }

    async fn remove_shards_at_peer(&self, peer_id: PeerId) -> Result<(), StorageError> {
        let collections = self.collections.read().await;
        for collection in collections.values() {
            collection.remove_shards_at_peer(peer_id).await?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn remove_shards_at_peer_sync(&self, peer_id: PeerId) -> Result<(), StorageError> {
        self.general_runtime
            .block_on(self.remove_shards_at_peer(peer_id))
    }

    fn on_transfer_failure_callback(
        proposal_sender: Option<OperationSender>,
    ) -> collection::collection::OnTransferFailure {
        Arc::new(move |transfer, collection_name, reason| {
            if let Some(proposal_sender) = &proposal_sender {
                let operation = ConsensusOperations::abort_transfer(
                    collection_name.clone(),
                    transfer.clone(),
                    reason,
                );
                if let Err(send_error) = proposal_sender.send(operation) {
                    log::error!(
                        "Can't send proposal to abort transfer of shard {} of collection {collection_name}. Error: {send_error}",
                        transfer.shard_id,
                    );
                }
            }
        })
    }

    fn on_transfer_success_callback(
        proposal_sender: Option<OperationSender>,
    ) -> collection::collection::OnTransferSuccess {
        Arc::new(move |transfer, collection_name| {
            if let Some(proposal_sender) = &proposal_sender {
                let operation =
                    ConsensusOperations::finish_transfer(collection_name.clone(), transfer.clone());
                if let Err(send_error) = proposal_sender.send(operation) {
                    log::error!(
                        "Can't send proposal to complete transfer of shard {} of collection {collection_name}. Error: {send_error}",
                        transfer.shard_id,
                    );
                }
            }
        })
    }
}
