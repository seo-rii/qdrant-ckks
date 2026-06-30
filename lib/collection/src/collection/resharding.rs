use std::num::NonZeroU32;

use futures::Future;

use super::{Collection, collection_encryption_uses_private_oram_bucket_store};
use crate::config::ShardingMethod;
use crate::hash_ring::HashRingRouter;
use crate::operations::cluster_ops::ReshardingDirection;
use crate::operations::types::{CollectionError, CollectionResult};
use crate::shards::replica_set::replica_set_state::ReplicaState;
use crate::shards::resharding::{ReshardKey, ReshardState};
use crate::shards::transfer::ShardTransferConsensus;

impl Collection {
    pub async fn resharding_state(&self) -> Option<ReshardState> {
        self.shards_holder
            .read()
            .await
            .resharding_state
            .read()
            .clone()
    }

    /// Start a new resharding operation
    ///
    /// # Cancel safety
    ///
    /// This method is *not* cancel safe.
    pub async fn start_resharding<T, F>(
        &self,
        resharding_key: ReshardKey,
        _consensus: Box<dyn ShardTransferConsensus>,
        _on_finish: T,
        _on_error: F,
    ) -> CollectionResult<()>
    where
        T: Future<Output = ()> + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.validate_private_oram_resharding_operation_until_supported("start resharding")
            .await?;

        {
            let mut shard_holder = self.shards_holder.write().await;

            shard_holder.check_start_resharding(&resharding_key)?;

            // If scaling up, create a new replica set
            let replica_set = if resharding_key.direction == ReshardingDirection::Up {
                let replica_set = self
                    .create_replica_set(
                        resharding_key.shard_id,
                        resharding_key.shard_key.clone(),
                        &[resharding_key.peer_id],
                        Some(ReplicaState::Resharding),
                    )
                    .await?;

                Some(replica_set)
            } else {
                None
            };

            shard_holder
                .start_resharding_unchecked(resharding_key.clone(), replica_set)
                .await?;

            if resharding_key.direction == ReshardingDirection::Up {
                let mut config = self.collection_config.write().await;
                match config.params.sharding_method.unwrap_or_default() {
                    // If adding a shard, increase persisted count so we load it on restart
                    ShardingMethod::Auto => {
                        debug_assert_eq!(config.params.shard_number.get(), resharding_key.shard_id);

                        config.params.shard_number =
                            config.params.shard_number.checked_add(1).ok_or_else(|| {
                                CollectionError::service_error(
                                    "cannot have more than u32::MAX shards after resharding",
                                )
                            })?;
                        if let Err(err) = config.save(&self.path) {
                            log::error!(
                                "Failed to update and save collection config during resharding: {err}",
                            );
                        }
                    }
                    // Custom shards don't use the persisted count, we don't change it
                    ShardingMethod::Custom => {}
                }
            }
        }

        // Drive resharding
        // self.drive_resharding(resharding_key, consensus, false, on_finish, on_error)
        //     .await?;

        Ok(())
    }

    pub async fn commit_read_hashring(&self, resharding_key: &ReshardKey) -> CollectionResult<()> {
        self.validate_private_oram_resharding_operation_until_supported("commit read hash ring")
            .await?;

        let mut shards_holder = self.shards_holder.write().await;

        shards_holder.commit_read_hashring(resharding_key)?;

        // Invalidate clean state for shards we copied points out of
        // These shards must be cleaned or dropped to ensure they don't contain irrelevant points
        match resharding_key.direction {
            // On resharding up: related shards below new shard key are affected
            ReshardingDirection::Up => match shards_holder.rings.get(&resharding_key.shard_key) {
                Some(HashRingRouter::Resharding { old, new: _ }) => {
                    self.invalidate_clean_local_shards(old.nodes().clone())
                        .await;
                }
                Some(HashRingRouter::Single(ring)) => {
                    debug_assert!(false, "must have resharding hash ring during resharding");
                    self.invalidate_clean_local_shards(ring.nodes().clone())
                        .await;
                }
                None => {
                    debug_assert!(false, "must have hash ring for resharding key");
                }
            },
            // On resharding down: shard we're about to remove is affected
            ReshardingDirection::Down => {
                self.invalidate_clean_local_shards([resharding_key.shard_id])
                    .await;
            }
        }

        Ok(())
    }

    pub async fn commit_write_hashring(&self, resharding_key: &ReshardKey) -> CollectionResult<()> {
        self.validate_private_oram_resharding_operation_until_supported("commit write hash ring")
            .await?;

        self.shards_holder
            .write()
            .await
            .commit_write_hashring(resharding_key)
    }

    pub async fn finish_resharding(&self, resharding_key: ReshardKey) -> CollectionResult<()> {
        self.validate_private_oram_resharding_operation_until_supported("finish resharding")
            .await?;

        let mut shard_holder = self.shards_holder.write().await;

        shard_holder.check_finish_resharding(&resharding_key)?;
        shard_holder.finish_resharding_unchecked(&resharding_key)?;

        if resharding_key.direction == ReshardingDirection::Down {
            // Remove the shard we've now migrated all points out of
            if let Some(shard_key) = &resharding_key.shard_key {
                shard_holder.remove_shard_from_key_mapping(resharding_key.shard_id, shard_key)?;
            }

            shard_holder
                .drop_and_remove_shard(resharding_key.shard_id)
                .await?;

            {
                let mut config = self.collection_config.write().await;
                match config.params.sharding_method.unwrap_or_default() {
                    // If removing a shard, decrease persisted count so we don't load it on restart
                    ShardingMethod::Auto => {
                        debug_assert_eq!(
                            config.params.shard_number.get() - 1,
                            resharding_key.shard_id,
                        );

                        config.params.shard_number = config
                            .params
                            .shard_number
                            .get()
                            .checked_sub(1)
                            .and_then(NonZeroU32::new)
                            .ok_or_else(|| {
                                CollectionError::service_error(
                                    "cannot have zero shards after finishing resharding",
                                )
                            })?;

                        if let Err(err) = config.save(&self.path) {
                            log::error!(
                                "Failed to update and save collection config during resharding: {err}"
                            );
                        }
                    }
                    // Custom shards don't use the persisted count, we don't change it
                    ShardingMethod::Custom => {}
                }
            }
        }

        Ok(())
    }

    pub async fn abort_resharding(
        &self,
        resharding_key: ReshardKey,
        force: bool,
    ) -> CollectionResult<()> {
        log::warn!(
            "Invalidating local cleanup tasks and aborting resharding {resharding_key} (force: {force})"
        );

        let shard_holder = self.shards_holder.read().await;

        if !force {
            shard_holder.check_abort_resharding(&resharding_key)?;
        } else {
            log::warn!("Force-aborting resharding {resharding_key}");
        }

        // Invalidate clean state for shards we copied new points into
        // These shards must be cleaned or dropped to ensure they don't contain irrelevant points
        match resharding_key.direction {
            // On resharding up: new shard now has invalid points, shard will likely be dropped
            ReshardingDirection::Up => {
                self.invalidate_clean_local_shards([resharding_key.shard_id])
                    .await;
            }
            // On resharding down: existing shards may have new points moved into them
            ReshardingDirection::Down => match shard_holder.rings.get(&resharding_key.shard_key) {
                Some(HashRingRouter::Resharding { old: _, new }) => {
                    self.invalidate_clean_local_shards(new.nodes().clone())
                        .await;
                }
                Some(HashRingRouter::Single(ring)) => {
                    debug_assert!(false, "must have resharding hash ring during resharding");
                    self.invalidate_clean_local_shards(ring.nodes().clone())
                        .await;
                }
                None => {
                    debug_assert!(false, "must have hash ring for resharding key");
                }
            },
        }

        // Abort all resharding transfer related to this specific resharding operation
        let resharding_transfers =
            shard_holder.get_transfers(|t| t.is_related_to_resharding(&resharding_key));
        for transfer in resharding_transfers {
            self.abort_shard_transfer(transfer, &shard_holder).await?;
        }

        drop(shard_holder); // drop the read lock before acquiring write lock
        let mut shard_holder = self.shards_holder.write().await;

        shard_holder
            .abort_resharding(resharding_key.clone(), force)
            .await?;

        // Decrease the persisted shard count, ensures we don't load dropped shard on restart
        if resharding_key.direction == ReshardingDirection::Up {
            let mut config = self.collection_config.write().await;
            match config.params.sharding_method.unwrap_or_default() {
                // If removing a shard, decrease persisted count so we don't load it on restart
                ShardingMethod::Auto => {
                    debug_assert_eq!(
                        config.params.shard_number.get() - 1,
                        resharding_key.shard_id,
                    );

                    config.params.shard_number = config
                        .params
                        .shard_number
                        .get()
                        .checked_sub(1)
                        .and_then(NonZeroU32::new)
                        .ok_or_else(|| {
                            CollectionError::service_error(
                                "cannot have zero shards after aborting resharding",
                            )
                        })?;

                    if let Err(err) = config.save(&self.path) {
                        log::error!(
                            "Failed to update and save collection config during resharding: {err}"
                        );
                    }
                }
                // Custom shards don't use the persisted count, we don't change it
                ShardingMethod::Custom => {}
            }
        }

        Ok(())
    }

    async fn validate_private_oram_resharding_operation_until_supported(
        &self,
        operation_name: &str,
    ) -> CollectionResult<()> {
        let private_oram_bucket_store_collection = {
            let config = self.collection_config.read().await;
            config
                .params
                .effective_encryption()
                .as_ref()
                .is_some_and(collection_encryption_uses_private_oram_bucket_store)
        };
        validate_private_oram_resharding_until_supported(
            operation_name,
            private_oram_bucket_store_collection,
        )
    }
}

fn validate_private_oram_resharding_until_supported(
    _operation_name: &str,
    private_oram_bucket_store_collection: bool,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot proceed with resharding for private ORAM collections: encrypted ORAM bucket migration \
         and consensus-backed epoch/root ownership are not implemented for resharding",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_ORAM_RESHARDING_OPERATION_NAMES: &[&str] = &[
        "start resharding",
        "commit read hash ring",
        "private-resharding-operation-sentinel",
        "stashBackup.json",
        "stashBackups.json",
        "stash_backup.json",
        "tokenPositionMapBackup.json",
        "tokenPositionMapBackups.json",
        "token_position_map_backup.json",
        "oramPositionMapBackup.json",
        "oramPositionMapBackups.json",
        "oram_position_map_backup.json",
        "positionMapBackup.json",
        "positionMapBackups.json",
        "position_map_backup.json",
        "clientStateCiphertext.json",
        "clientStateSnapshot.json",
        "clientStateSnapshots.json",
        "client_state_snapshot.bin",
        "client_state_snapshots.bin",
        "clientStateCiphertextHash.json",
        "clientStateCiphertextHashes.json",
        "clientStateCiphertextSha256.json",
        "clientStateCiphertextsSha256.json",
        "client_state_ciphertext_hashes.json",
        "client_state_ciphertext_sha256.json",
        "client_state_ciphertexts_sha256.json",
        "encryptedClientStateCiphertext.json",
        "encryptedClientStateCiphertextHash.json",
        "encryptedClientStateCiphertextHashes.json",
        "encryptedClientStateCiphertextSha256.json",
        "encryptedClientStateCiphertextsSha256.json",
        "encrypted_client_state_ciphertext_hash.json",
        "encrypted_client_state_ciphertext_hashes.json",
        "encrypted_client_state_ciphertext_sha256.json",
        "encrypted_client_state_ciphertexts_sha256.json",
        "encrypted_client_state.bin",
        "encrypted_client_state_backup.bin",
        "encrypted_client_state_backups.bin",
        "encryptedClientStateSnapshot.json",
        "encryptedClientStateSnapshots.json",
        "encrypted_client_state_snapshot.bin",
        "encrypted_client_state_snapshots.bin",
        "stateCiphertext.json",
        "stateCiphertextHash.json",
        "stateCiphertextHashes.json",
        "stateCiphertextSha256.json",
        "stateCiphertextsSha256.json",
        "state_ciphertext_hashes.json",
        "state_ciphertext_sha256.json",
        "state_ciphertexts_sha256.json",
        "state_ciphertext.bin",
        "state_ciphertext_hash.bin",
    ];

    const PRIVATE_ORAM_RESHARDING_REDACTION_STEMS: &[&str] = &[
        "stashBackup",
        "stashBackups",
        "stash_backup",
        "tokenPositionMapBackup",
        "tokenPositionMapBackups",
        "token_position_map_backup",
        "oramPositionMapBackup",
        "oramPositionMapBackups",
        "oram_position_map_backup",
        "positionMapBackup",
        "positionMapBackups",
        "position_map_backup",
        "clientStateCiphertext",
        "clientStateSnapshot",
        "clientStateSnapshots",
        "client_state_snapshot",
        "client_state_snapshots",
        "clientStateCiphertextHash",
        "clientStateCiphertextHashes",
        "clientStateCiphertextSha256",
        "clientStateCiphertextsSha256",
        "client_state_ciphertext_hashes",
        "client_state_ciphertext_sha256",
        "client_state_ciphertexts_sha256",
        "encryptedClientStateCiphertext",
        "encryptedClientStateCiphertextHash",
        "encryptedClientStateCiphertextHashes",
        "encryptedClientStateCiphertextSha256",
        "encryptedClientStateCiphertextsSha256",
        "encrypted_client_state",
        "encrypted_client_state_backup",
        "encrypted_client_state_backups",
        "encryptedClientStateSnapshot",
        "encryptedClientStateSnapshots",
        "encrypted_client_state_snapshot",
        "encrypted_client_state_snapshots",
        "encrypted_client_state_ciphertext_hash",
        "encrypted_client_state_ciphertext_hashes",
        "encrypted_client_state_ciphertext_sha256",
        "encrypted_client_state_ciphertexts_sha256",
        "stateCiphertext",
        "stateCiphertextHash",
        "stateCiphertextHashes",
        "stateCiphertextSha256",
        "stateCiphertextsSha256",
        "state_ciphertext",
        "state_ciphertext_hash",
        "state_ciphertext_hashes",
        "state_ciphertext_sha256",
        "state_ciphertexts_sha256",
    ];

    #[test]
    fn private_oram_resharding_operation_guard_redacts_collection_details() {
        validate_private_oram_resharding_until_supported("start resharding", false).unwrap();

        for &operation_name in PRIVATE_ORAM_RESHARDING_OPERATION_NAMES {
            let err =
                validate_private_oram_resharding_until_supported(operation_name, true).unwrap_err();
            let rendered = format!("{err:?}");

            assert!(
                rendered.contains("cannot proceed with resharding for private ORAM collections")
            );
            assert!(rendered.contains("encrypted ORAM bucket migration"));
            assert!(rendered.contains("consensus-backed epoch/root"));
            assert!(!rendered.contains(operation_name));
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains("private_result_oram"));
            for &leaked_alias in PRIVATE_ORAM_RESHARDING_REDACTION_STEMS {
                assert!(!rendered.contains(leaked_alias), "{rendered}");
            }
            assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));
        }
    }
}
