use std::collections::HashSet;

use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::fs::sync_parent_dir_async;
use fs_err::tokio as tokio_fs;
use segment::types::ShardKey;

use super::{Collection, collection_encryption_uses_private_oram_bucket_store};
use crate::collection::payload_index_schema::validate_payload_index_schema_for_encryption;
use crate::config::ShardingMethod;
use crate::operations::types::{CollectionError, CollectionResult};
use crate::operations::{
    CollectionUpdateOperations, CreateIndex, FieldIndexOperations, OperationWithClockTag,
};
use crate::shards::replica_set::ShardReplicaSet;
use crate::shards::replica_set::replica_set_state::ReplicaState;
use crate::shards::shard::{PeerId, ShardId, ShardsPlacement};
use crate::shards::shard_config::ShardConfig;
use crate::shards::shard_trait::WaitUntil;

impl Collection {
    pub async fn create_replica_set(
        &self,
        shard_id: ShardId,
        shard_key: Option<ShardKey>,
        replicas: &[PeerId],
        init_state: Option<ReplicaState>,
    ) -> CollectionResult<ShardReplicaSet> {
        self.validate_private_oram_replica_set_creation_until_supported()
            .await?;

        let is_local = replicas.contains(&self.this_peer_id);

        let peers = replicas
            .iter()
            .copied()
            .filter(|peer_id| *peer_id != self.this_peer_id)
            .collect();

        let effective_optimizers_config = self.effective_optimizers_config().await?;

        ShardReplicaSet::build(
            shard_id,
            shard_key,
            self.name().to_string(),
            self.this_peer_id,
            is_local,
            peers,
            self.notify_peer_failure_cb.clone(),
            self.abort_shard_transfer_cb.clone(),
            &self.path,
            self.collection_config.clone(),
            effective_optimizers_config,
            self.shared_storage_config.clone(),
            self.payload_index_schema.clone(),
            self.channel_service.clone(),
            self.update_runtime.clone(),
            self.search_runtime.clone(),
            self.optimizer_resource_budget.clone(),
            Some(init_state.unwrap_or(ReplicaState::Active)),
        )
        .await
    }

    /// # Cancel safety
    ///
    /// Public callers execute this meta operation in a spawned task, so HTTP request cancellation
    /// does not cancel the shard-key creation future. Synchronous error paths after a replica set
    /// is created roll back the uncommitted shard directory or the whole new shard key.
    pub async fn create_shard_key(
        &self,
        shard_key: ShardKey,
        placement: ShardsPlacement,
        init_state: ReplicaState,
    ) -> CollectionResult<()> {
        self.validate_private_oram_shard_key_change_until_supported("create shard key")
            .await?;

        let hw_counter = HwMeasurementAcc::disposable(); // Internal operation. No measurement needed.

        let state = self.state().await;
        match state.config.params.sharding_method.unwrap_or_default() {
            ShardingMethod::Auto => {
                return Err(CollectionError::bad_request(format!(
                    "Shard Key {shard_key} cannot be created with Auto sharding method"
                )));
            }
            ShardingMethod::Custom => {}
        }

        if state.shards_key_mapping.contains_key(&shard_key) {
            return Err(CollectionError::bad_request(format!(
                "Shard key {shard_key} already exists"
            )));
        }

        let all_peers: HashSet<_> = self
            .channel_service
            .id_to_address
            .read()
            .keys()
            .cloned()
            .collect();

        let unknown_peers: Vec<_> = placement
            .iter()
            .flatten()
            .filter(|peer_id| !all_peers.contains(peer_id))
            .collect();

        if !unknown_peers.is_empty() {
            return Err(CollectionError::bad_request(format!(
                "Shard Key {shard_key} placement contains unknown peers: {unknown_peers:?}"
            )));
        }

        let max_shard_id = state.max_shard_id();
        let payload_schema = self.payload_index_schema.read().schema.clone();
        validate_payload_index_schema_for_encryption(
            payload_schema.iter(),
            &state.config.params,
            "create shard key",
        )?;

        for (idx, shard_replicas_placement) in placement.iter().enumerate() {
            let shard_id = max_shard_id + idx as ShardId + 1;

            let replica_set = self
                .create_replica_set(
                    shard_id,
                    Some(shard_key.clone()),
                    shard_replicas_placement,
                    Some(init_state),
                )
                .await?;

            let add_result = async {
                validate_payload_index_schema_for_encryption(
                    payload_schema.iter(),
                    &self.state().await.config.params,
                    "create shard key",
                )?;

                for (field_name, field_schema) in payload_schema.iter() {
                    let create_index_op = CollectionUpdateOperations::FieldIndexOperation(
                        FieldIndexOperations::CreateIndex(CreateIndex {
                            field_name: field_name.clone(),
                            field_schema: Some(field_schema.clone()),
                        }),
                    );

                    replica_set
                        .update_local(
                            OperationWithClockTag::from(create_index_op),
                            WaitUntil::Visible,
                            None,
                            hw_counter.clone(),
                            false,
                        ) // TODO: Assign clock tag!? 🤔
                        .await?;
                }

                let current_payload_schema = self.payload_index_schema.read().schema.clone();
                let current_state = self.state().await;
                validate_payload_index_schema_for_encryption(
                    current_payload_schema.iter(),
                    &current_state.config.params,
                    "create shard key",
                )?;

                Ok::<_, CollectionError>(())
            }
            .await;

            if let Err(err) = add_result {
                cleanup_unadded_replica_set(replica_set).await?;
                return Err(err);
            }

            if let Err(err) = self
                .shards_holder
                .write()
                .await
                .add_shard(shard_id, replica_set, Some(shard_key.clone()))
                .await
            {
                if let Err(cleanup_err) = self
                    .shards_holder
                    .write()
                    .await
                    .remove_shard_key(&shard_key)
                    .await
                {
                    log::error!(
                        "failed to rollback shard key {shard_key} after add_shard failure: {cleanup_err}",
                    );
                }
                return Err(err);
            }
        }

        Ok(())
    }

    pub async fn drop_shard_key(&self, shard_key: ShardKey) -> CollectionResult<()> {
        self.validate_private_oram_shard_key_change_until_supported("drop shard key")
            .await?;

        let state = self.state().await;

        match state.config.params.sharding_method.unwrap_or_default() {
            ShardingMethod::Auto => {
                return Err(CollectionError::bad_request(format!(
                    "Shard Key {shard_key} cannot be removed with Auto sharding method"
                )));
            }
            ShardingMethod::Custom => {}
        }

        let resharding_state = self
            .resharding_state()
            .await
            .filter(|state| state.shard_key.as_ref() == Some(&shard_key));

        if let Some(state) = resharding_state
            && let Err(err) = self.abort_resharding(state.key(), true).await
        {
            log::error!(
                "failed to abort resharding {} while deleting shard key {shard_key}: {err}",
                state.key(),
            );
        }

        // Invalidate local shard cleaning tasks
        match self
            .shards_holder
            .read()
            .await
            .get_shard_ids_by_key(&shard_key)
        {
            Ok(shard_ids) => self.invalidate_clean_local_shards(shard_ids).await,
            Err(err) => {
                log::warn!("Failed to invalidate local shard cleaning task, ignoring: {err}");
            }
        }

        self.shards_holder
            .write()
            .await
            .remove_shard_key(&shard_key)
            .await
    }

    pub async fn get_shard_ids(&self, shard_key: &ShardKey) -> CollectionResult<Vec<ShardId>> {
        self.shards_holder
            .read()
            .await
            .get_shard_key_to_ids_mapping()
            .get(shard_key)
            .map(|ids| ids.iter().cloned().collect())
            .ok_or_else(|| {
                CollectionError::bad_input(format!(
                    "Shard key {shard_key} does not exist for collection {}",
                    self.name()
                ))
            })
    }

    pub async fn get_replicas(
        &self,
        shard_key: &ShardKey,
    ) -> CollectionResult<Vec<(ShardId, PeerId)>> {
        let shard_ids = self.get_shard_ids(shard_key).await?;
        let shard_holder = self.shards_holder.read().await;
        let mut replicas = Vec::new();
        for shard_id in shard_ids {
            if let Some(replica_set) = shard_holder.get_shard(shard_id) {
                for (peer_id, _) in replica_set.peers() {
                    replicas.push((shard_id, peer_id));
                }
            }
        }
        Ok(replicas)
    }

    async fn validate_private_oram_shard_key_change_until_supported(
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
        validate_private_oram_shard_key_change_until_supported(
            operation_name,
            private_oram_bucket_store_collection,
        )
    }

    async fn validate_private_oram_replica_set_creation_until_supported(
        &self,
    ) -> CollectionResult<()> {
        let private_oram_bucket_store_collection = {
            let config = self.collection_config.read().await;
            config
                .params
                .effective_encryption()
                .as_ref()
                .is_some_and(collection_encryption_uses_private_oram_bucket_store)
        };
        validate_private_oram_replica_set_creation_until_supported(
            private_oram_bucket_store_collection,
        )
    }
}

async fn cleanup_unadded_replica_set(replica_set: ShardReplicaSet) -> CollectionResult<()> {
    let shard_path = replica_set.shard_path.clone();
    replica_set.stop_gracefully().await;

    let shard_config_path = ShardConfig::get_config_path(&shard_path);
    match tokio_fs::remove_file(&shard_config_path).await {
        Ok(()) => {
            sync_parent_dir_async(&shard_config_path).await?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(CollectionError::service_error(err.to_string())),
    }

    match tokio_fs::remove_dir_all(&shard_path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CollectionError::service_error(err.to_string())),
    }
}

fn validate_private_oram_shard_key_change_until_supported(
    _operation_name: &str,
    private_oram_bucket_store_collection: bool,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot change shard-key layout for private ORAM collections: collection-local encrypted ORAM \
         buckets cannot be moved or deleted by shard-key layout changes until ORAM bucket \
         migration and consensus-backed epoch/root ownership are implemented",
    ))
}

fn validate_private_oram_replica_set_creation_until_supported(
    private_oram_bucket_store_collection: bool,
) -> CollectionResult<()> {
    if !private_oram_bucket_store_collection {
        return Ok(());
    }

    Err(CollectionError::bad_input(
        "cannot create replica set for private ORAM collections: collection-local encrypted ORAM \
         buckets cannot be assigned to new shard replicas until ORAM bucket migration and \
         consensus-backed epoch/root ownership are implemented",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_oram_shard_key_change_guard_redacts_collection_details() {
        validate_private_oram_shard_key_change_until_supported("create shard key", false).unwrap();

        for operation_name in [
            "create shard key",
            "drop shard key",
            "private-shard-key-operation-sentinel",
            "positionMapBackups.json",
        ] {
            let err = validate_private_oram_shard_key_change_until_supported(operation_name, true)
                .unwrap_err();
            let rendered = format!("{err:?}");

            assert!(
                rendered.contains("cannot change shard-key layout for private ORAM collections")
            );
            assert!(rendered.contains("collection-local encrypted ORAM buckets"));
            assert!(rendered.contains("consensus-backed epoch/root"));
            assert!(!rendered.contains(operation_name));
            assert!(!rendered.contains("private_hnsw_oram"));
            assert!(!rendered.contains("private_result_oram"));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
            assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));
        }
    }

    #[test]
    fn private_oram_replica_set_creation_guard_redacts_collection_details() {
        validate_private_oram_replica_set_creation_until_supported(false).unwrap();

        let err = validate_private_oram_replica_set_creation_until_supported(true).unwrap_err();
        let rendered = format!("{err:?}");

        assert!(rendered.contains("cannot create replica set for private ORAM collections"));
        assert!(rendered.contains("collection-local encrypted ORAM buckets"));
        assert!(rendered.contains("consensus-backed epoch/root"));
        assert!(!rendered.contains("private_hnsw_oram"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING));
        assert!(!rendered.contains(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING));
    }
}
