use std::collections::HashSet;
use std::path::Path;

use common::fs::read_json;
use common::storage_version::StorageVersion as _;
use common::tar_ext::BuilderExt;
use common::tar_unpack::tar_unpack_file;
use fs_err::File;
use qdrant_sec::{
    DistanceKind, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_HNSW_ORAM_BINDING,
    PrivateHnswOramManifest, PrivateHnswOramSignature, ResultPrivacyMode,
    validate_private_hnsw_oram_manifest_shape, validate_private_hnsw_oram_manifest_signature_shape,
};
use segment::types::SnapshotFormat;
use segment::utils::fs::move_all;
use shard::files::PAYLOAD_INDEX_CONFIG_FILE;
use shard::snapshots::snapshot_data::SnapshotData;
use shard::snapshots::snapshot_manifest::{RecoveryType, SnapshotManifest};
use tokio::sync::OwnedRwLockReadGuard;

use super::Collection;
use crate::collection::CollectionVersion;
use crate::common::snapshot_stream::SnapshotStream;
use crate::common::snapshots_manager::SnapshotStorageManager;
use crate::config::{
    COLLECTION_CONFIG_FILE, CollectionConfigInternal, CollectionParams, CryptoMigrationState,
    EncryptionSelector, ShardingMethod,
};
use crate::operations::snapshot_ops::SnapshotDescription;
use crate::operations::types::{CollectionError, CollectionResult, NodeType};
use crate::private_hnsw_oram_store::{PRIVATE_HNSW_ORAM_DIR, PrivateHnswOramStore};
use crate::private_result_oram_store::PRIVATE_RESULT_ORAM_DIR;
use crate::shards::local_shard::LocalShard;
use crate::shards::remote_shard::RemoteShard;
use crate::shards::replica_set::ShardReplicaSet;
use crate::shards::shard::{PeerId, ShardId};
use crate::shards::shard_config::{self, ShardConfig};
use crate::shards::shard_holder::shard_mapping::ShardKeyMapping;
use crate::shards::shard_holder::{SHARD_KEY_MAPPING_FILE, ShardHolder, shard_not_found_error};
use crate::shards::shard_path;

impl Collection {
    pub fn get_snapshots_storage_manager(&self) -> CollectionResult<SnapshotStorageManager> {
        SnapshotStorageManager::new(&self.shared_storage_config.snapshots_config)
    }

    pub async fn list_snapshots(&self) -> CollectionResult<Vec<SnapshotDescription>> {
        let snapshot_manager = self.get_snapshots_storage_manager()?;
        snapshot_manager.list_snapshots(&self.snapshots_path).await
    }

    /// Creates a snapshot of the collection.
    ///
    /// The snapshot is created in three steps:
    /// 1. Create a temporary directory and create a snapshot of each shard in it.
    /// 2. Archive the temporary directory into a single file.
    /// 3. Move the archive to the final location.
    ///
    /// # Arguments
    ///
    /// * `global_temp_dir`: directory used to host snapshots while they are being created
    /// * `this_peer_id`: current peer id
    ///
    /// returns: Result<SnapshotDescription, CollectionError>
    pub async fn create_snapshot(
        &self,
        global_temp_dir: &Path,
        this_peer_id: PeerId,
    ) -> CollectionResult<SnapshotDescription> {
        {
            let collection_config = self.collection_config.read().await;
            ensure_snapshot_crypto_migration_state_allows_snapshot(
                self.name(),
                &collection_config.params,
            )?;
        }

        let snapshot_name = format!(
            "{}-{this_peer_id}-{}.snapshot",
            self.name(),
            chrono::Utc::now().format("%Y-%m-%d-%H-%M-%S"),
        );

        // Final location of snapshot
        let snapshot_path = self.snapshots_path.join(&snapshot_name);
        log::info!("Creating collection snapshot {snapshot_name} into {snapshot_path:?}");

        // Dedicated temporary file for archiving this snapshot (deleted on drop)
        let snapshot_temp_arc_file = tempfile::Builder::new()
            .prefix(&format!("{snapshot_name}-arc-"))
            .tempfile_in(global_temp_dir)
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to create temporary snapshot directory {}/{snapshot_name}-arc-XXXX: \
                     {err}",
                    global_temp_dir.display(),
                ))
            })?;

        let tar = BuilderExt::new_seekable_owned(File::create(snapshot_temp_arc_file.path())?);

        // Create snapshot of each shard
        {
            let snapshot_temp_temp_dir = tempfile::Builder::new()
                .prefix(&format!("{snapshot_name}-temp-"))
                .tempdir_in(global_temp_dir)
                .map_err(|err| {
                    CollectionError::service_error(format!(
                        "failed to create temporary snapshot directory {}/{snapshot_name}-temp-XXXX: \
                         {err}",
                        global_temp_dir.display(),
                    ))
                })?;

            let mut futures = Vec::new();
            {
                let shards_holder = self.shards_holder.read().await;

                // Create snapshot of each shard
                for (shard_id, replica_set) in shards_holder.get_shards() {
                    let shard_snapshot_path = shard_path(Path::new(""), shard_id);

                    // If node is listener, we can save whatever currently is in the storage
                    let save_wal = self.shared_storage_config.node_type != NodeType::Listener;
                    let future = replica_set
                        .create_snapshot(
                            snapshot_temp_temp_dir.path(),
                            tar.descend(&shard_snapshot_path)?,
                            SnapshotFormat::Regular,
                            None,
                            save_wal,
                        )
                        .await?;
                    futures.push(future);
                }
            }

            for future in futures {
                future.await.map_err(|err| {
                    CollectionError::service_error(format!("failed to create snapshot: {err}"))
                })?;
            }
        }

        // Save collection config and version
        tar.append_data(
            CollectionVersion::current_raw().as_bytes().to_vec(),
            Path::new(common::storage_version::VERSION_FILE),
        )
        .await?;

        tar.append_data(
            self.collection_config.read().await.to_bytes()?,
            Path::new(COLLECTION_CONFIG_FILE),
        )
        .await?;

        self.shards_holder
            .read()
            .await
            .save_key_mapping_to_tar(&tar)
            .await?;

        self.payload_index_schema
            .save_to_tar(&tar, Path::new(PAYLOAD_INDEX_CONFIG_FILE))
            .await?;

        let private_hnsw_oram_path = self.path.join(PRIVATE_HNSW_ORAM_DIR);
        if private_hnsw_oram_path.exists() {
            let tar = tar.clone();
            tokio::task::spawn_blocking(move || {
                tar.blocking_append_dir_all(
                    &private_hnsw_oram_path,
                    Path::new(PRIVATE_HNSW_ORAM_DIR),
                )
            })
            .await
            .map_err(CollectionError::from)??;
        }

        let private_result_oram_path = self.path.join(PRIVATE_RESULT_ORAM_DIR);
        if private_result_oram_path.exists() {
            let tar = tar.clone();
            tokio::task::spawn_blocking(move || {
                tar.blocking_append_dir_all(
                    &private_result_oram_path,
                    Path::new(PRIVATE_RESULT_ORAM_DIR),
                )
            })
            .await
            .map_err(CollectionError::from)??;
        }

        tar.finish().await.map_err(|err| {
            CollectionError::service_error(format!("failed to create snapshot archive: {err}"))
        })?;

        let snapshot_manager = self.get_snapshots_storage_manager()?;
        snapshot_manager
            .store_file(snapshot_temp_arc_file.path(), snapshot_path.as_path())
            .await
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to store snapshot archive to {}: {err}",
                    snapshot_temp_arc_file.path().display()
                ))
            })
    }

    /// Restore collection from snapshot
    ///
    /// This method performs blocking IO.
    pub fn restore_snapshot(
        snapshot_data: SnapshotData,
        target_dir: &Path,
        this_peer_id: PeerId,
        is_distributed: bool,
    ) -> CollectionResult<()> {
        match snapshot_data {
            SnapshotData::Packed(snapshot_path) => {
                tar_unpack_file(&snapshot_path, target_dir)?;
                snapshot_path.close()?;
            }
            SnapshotData::Unpacked(snapshot_dir) => {
                // already unpacked snapshot, validate files and move to target dir
                let snapshot_dir_path = snapshot_dir.path();
                move_all(snapshot_dir_path, target_dir)?;
            }
        }

        let config = CollectionConfigInternal::load(target_dir)?;
        config.validate_and_warn();
        ensure_private_result_oram_snapshot_restore_not_present(target_dir)?;
        let configured_shards = config.params.shard_number.get();

        let shard_ids_list: Vec<_> = match config.params.sharding_method.unwrap_or_default() {
            ShardingMethod::Auto => (0..configured_shards).collect(),
            ShardingMethod::Custom => {
                // Load shard mapping from disk
                let mapping_path = target_dir.join(SHARD_KEY_MAPPING_FILE);
                debug_assert!(
                    mapping_path.exists(),
                    "Shard mapping file must exist once custom sharding is used"
                );
                if !mapping_path.exists() {
                    Vec::new()
                } else {
                    let shard_key_mapping: ShardKeyMapping = read_json(&mapping_path)?;
                    shard_key_mapping.shard_ids()
                }
            }
        };

        // Check that all shard ids are unique
        debug_assert_eq!(
            shard_ids_list.len(),
            shard_ids_list.iter().collect::<HashSet<_>>().len(),
            "Shard mapping must contain all shards",
        );

        for shard_id in shard_ids_list {
            let shard_path = shard_path(target_dir, shard_id);
            let shard_config_opt = ShardConfig::load(&shard_path)?;
            if let Some(shard_config) = shard_config_opt {
                match shard_config.r#type {
                    shard_config::ShardType::Local => LocalShard::restore_snapshot(&shard_path)?,
                    shard_config::ShardType::Remote { .. } => {
                        RemoteShard::restore_snapshot(&shard_path)
                    }
                    shard_config::ShardType::Temporary => {}
                    shard_config::ShardType::ReplicaSet => ShardReplicaSet::restore_snapshot(
                        &shard_path,
                        this_peer_id,
                        is_distributed,
                    )?,
                }
            } else {
                return Err(CollectionError::service_error(format!(
                    "Can't read shard config at {}",
                    shard_path.display()
                )));
            }
        }

        Ok(())
    }

    pub fn validate_private_hnsw_oram_snapshot_restore_layout(
        collection_name: &str,
        config: &CollectionConfigInternal,
        collection_dir: &Path,
    ) -> CollectionResult<()> {
        let Some(encryption) = config.params.effective_encryption() else {
            return Ok(());
        };
        let stable_crypto_id = config.stable_crypto_id(collection_name)?;

        for rule in encryption
            .rules
            .iter()
            .filter(|rule| rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING))
        {
            let EncryptionSelector::VectorNames { names } = &rule.selector else {
                return Err(CollectionError::bad_request(format!(
                    "private HNSW ORAM snapshot rule {} must use vector_names selector",
                    rule.id,
                )));
            };
            for vector_name in names {
                validate_private_hnsw_oram_vector_snapshot(
                    collection_dir,
                    &stable_crypto_id,
                    &config.params,
                    vector_name,
                )?;
            }
        }

        Ok(())
    }

    /// # Cancel safety
    ///
    /// This method is *not* cancel safe.
    pub async fn recover_local_shard_from(
        &self,
        snapshot_shard_path: &Path,
        recovery_type: RecoveryType,
        shard_id: ShardId,
        cancel: cancel::CancellationToken,
    ) -> CollectionResult<bool> {
        // TODO:
        //   Check that shard snapshot is compatible with the collection
        //   (see `VectorsConfig::check_compatible_with_segment_config`)

        // `ShardHolder::recover_local_shard_from` is *not* cancel safe
        // (see `ShardReplicaSet::restore_local_replica_from`)
        let res = self
            .shards_holder
            .read()
            .await
            .recover_local_shard_from(
                snapshot_shard_path,
                recovery_type,
                &self.path,
                shard_id,
                cancel,
            )
            .await?;

        Ok(res)
    }

    pub async fn list_shard_snapshots(
        &self,
        shard_id: ShardId,
    ) -> CollectionResult<Vec<SnapshotDescription>> {
        self.shards_holder
            .read()
            .await
            .list_shard_snapshots(&self.snapshots_path, shard_id)
            .await
    }

    pub async fn create_shard_snapshot(
        &self,
        shard_id: ShardId,
        temp_dir: &Path,
    ) -> CollectionResult<SnapshotDescription> {
        let snapshot_creator = self
            .shards_holder
            .read()
            .await
            .create_shard_snapshot(&self.snapshots_path, self.name(), shard_id, temp_dir)
            .await?;
        // We don't hold shards_holder lock here on purpose,
        // because snapshot creation may take a long time,
        // and we don't want to block other operations on the collection.
        let (snapshot_description, _) = snapshot_creator.await?;
        Ok(snapshot_description)
    }

    pub async fn stream_shard_snapshot(
        &self,
        shard_id: ShardId,
        manifest: Option<SnapshotManifest>,
        temp_dir: &Path,
    ) -> CollectionResult<SnapshotStream> {
        let shard = OwnedRwLockReadGuard::try_map(
            self.shards_holder.clone().read_owned().await,
            |shard_holder| shard_holder.get_shard(shard_id),
        )
        .map_err(|_| shard_not_found_error(shard_id))?;

        ShardHolder::stream_shard_snapshot(shard, self.name(), shard_id, manifest, temp_dir).await
    }

    /// # Cancel safety
    ///
    /// This method is cancel safe.
    #[expect(clippy::too_many_arguments)]
    pub async fn restore_shard_snapshot(
        &self,
        shard_id: ShardId,
        snapshot_data: SnapshotData,
        recovery_type: RecoveryType,
        this_peer_id: PeerId,
        is_distributed: bool,
        temp_dir: &Path,
        cancel: cancel::CancellationToken,
    ) -> CollectionResult<impl Future<Output = CollectionResult<()>> + 'static> {
        // `ShardHolder::validate_shard_snapshot` is cancel safe, so we explicitly cancel it
        // when token is triggered
        let shard_holder = self.shards_holder.clone().read_owned().await;

        let collection_path = self.path.clone();
        let collection_name = self.name().to_string();
        let collection_params = self.collection_config.read().await.params.clone();

        let temp_dir = temp_dir.to_path_buf();

        // `ShardHolder::restore_shard_snapshot` is *not* cancel safe, so we spawn it onto runtime,
        // so that it won't be cancelled if current future is dropped
        let restore = self.update_runtime.spawn(async move {
            shard_holder
                .restore_shard_snapshot(
                    snapshot_data,
                    recovery_type,
                    &collection_path,
                    collection_params,
                    &collection_name,
                    shard_id,
                    this_peer_id,
                    is_distributed,
                    &temp_dir,
                    cancel,
                )
                .await?;

            CollectionResult::Ok(())
        });

        // Flatten nested `Result<Result<()>>` into `Result<()>`
        let restore = async move {
            restore.await.map_err(CollectionError::from)??;
            Ok(())
        };

        Ok(restore)
    }

    pub async fn assert_shard_exists(&self, shard_id: ShardId) -> CollectionResult<()> {
        self.shards_holder
            .read()
            .await
            .assert_shard_exists(shard_id)
    }

    pub async fn try_take_partial_snapshot_recovery_lock(
        &self,
        shard_id: ShardId,
        recovery_type: RecoveryType,
    ) -> CollectionResult<Option<tokio::sync::OwnedRwLockWriteGuard<()>>> {
        self.shards_holder
            .read()
            .await
            .try_take_partial_snapshot_recovery_lock(shard_id, recovery_type)
    }

    pub async fn get_partial_snapshot_manifest(
        &self,
        shard_id: ShardId,
    ) -> CollectionResult<SnapshotManifest> {
        self.shards_holder
            .read()
            .await
            .get_shard(shard_id)
            .ok_or_else(|| shard_not_found_error(shard_id))?
            .get_partial_snapshot_manifest()
            .await
    }
}

fn ensure_snapshot_crypto_migration_state_allows_snapshot(
    collection_name: &str,
    params: &CollectionParams,
) -> CollectionResult<()> {
    let Some(encryption) = params.effective_encryption() else {
        return Ok(());
    };
    if encryption.migration_state != CryptoMigrationState::Active {
        return Err(CollectionError::bad_request(format!(
            "encrypted collection {collection_name} snapshot creation requires \
             migration_state=active; current state is {:?}. Finish or roll back the crypto \
             migration before creating a snapshot because in-flight migration snapshots are not \
             recovery-supported.",
            encryption.migration_state,
        )));
    }

    Ok(())
}

fn ensure_private_result_oram_snapshot_restore_not_present(
    collection_dir: &Path,
) -> CollectionResult<()> {
    let private_result_oram_path = collection_dir.join(PRIVATE_RESULT_ORAM_DIR);
    if private_result_oram_path.exists() {
        return Err(CollectionError::bad_request(format!(
            "private result ORAM snapshot restore requires {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER}, \
             which is reserved until the payload ORAM provider runtime is implemented"
        )));
    }

    Ok(())
}

fn validate_private_hnsw_oram_vector_snapshot(
    collection_dir: &Path,
    stable_crypto_id: &str,
    params: &CollectionParams,
    vector_name: &str,
) -> CollectionResult<()> {
    let vector_params = params.vectors.get_params(vector_name).ok_or_else(|| {
        CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot vector '{vector_name}' is not configured",
        ))
    })?;
    let expected_dim = u32::try_from(vector_params.size.get()).map_err(|_| {
        CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot vector '{vector_name}' dimension exceeds u32",
        ))
    })?;
    let expected_distance = private_hnsw_distance_kind(vector_params.distance);

    let store = PrivateHnswOramStore::new(collection_dir, vector_name)?;
    let (manifest, signature) = store.read_manifest()?;
    validate_private_hnsw_oram_restore_manifest(
        &manifest,
        &signature,
        stable_crypto_id,
        vector_name,
        expected_dim,
        expected_distance,
    )?;

    let current_epoch = store.read_current_epoch()?;
    if current_epoch.index_epoch != manifest.index_epoch
        || current_epoch.root_hash != manifest.root_hash
    {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot vector '{vector_name}' current epoch/root does not match manifest",
        )));
    }

    store.read_bucket(
        0,
        manifest.index_epoch,
        manifest.bucket_count,
        private_hnsw_restore_max_bucket_ciphertext_bytes(&manifest)?,
    )?;
    store.read_merkle_path_batch(
        &[0],
        manifest.index_epoch,
        &manifest.root_hash,
        manifest.bucket_count,
    )?;

    Ok(())
}

fn validate_private_hnsw_oram_restore_manifest(
    manifest: &PrivateHnswOramManifest,
    signature: &PrivateHnswOramSignature,
    stable_crypto_id: &str,
    vector_name: &str,
    expected_dim: u32,
    expected_distance: DistanceKind,
) -> CollectionResult<()> {
    validate_private_hnsw_oram_manifest_shape(manifest).map_err(private_hnsw_restore_error)?;
    validate_private_hnsw_oram_manifest_signature_shape(signature)
        .map_err(private_hnsw_restore_error)?;
    if manifest.result_privacy != ResultPrivacyMode::IdsVisible {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot restore supports result_privacy=ids_visible only; \
             private_payload_oram_required requires {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER}, \
             which is reserved until the payload ORAM provider exists"
        )));
    }
    if signature.key_id != manifest.owner_signing_key_id {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot manifest signature key_id {} does not match owner_signing_key_id {}",
            signature.key_id, manifest.owner_signing_key_id,
        )));
    }
    if manifest.collection_id != stable_crypto_id {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot manifest collection_id mismatch: expected {stable_crypto_id}, found {}",
            manifest.collection_id,
        )));
    }
    if manifest.vector_name != vector_name {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot manifest vector_name mismatch: expected {vector_name}, found {}",
            manifest.vector_name,
        )));
    }
    if manifest.dim != expected_dim {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot manifest dim mismatch for vector '{vector_name}': expected {expected_dim}, found {}",
            manifest.dim,
        )));
    }
    if manifest.distance != expected_distance {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot manifest distance mismatch for vector '{vector_name}'",
        )));
    }
    Ok(())
}

fn private_hnsw_restore_max_bucket_ciphertext_bytes(
    manifest: &PrivateHnswOramManifest,
) -> CollectionResult<usize> {
    let block_size = usize::try_from(manifest.oram.block_size_bytes).map_err(|_| {
        CollectionError::bad_request("private HNSW ORAM block_size_bytes exceeds usize")
    })?;
    let bucket_size = usize::try_from(manifest.oram.bucket_size)
        .map_err(|_| CollectionError::bad_request("private HNSW ORAM bucket_size exceeds usize"))?;
    block_size
        .checked_mul(bucket_size)
        .and_then(|size| size.checked_add(4096))
        .ok_or_else(|| CollectionError::bad_request("private HNSW ORAM bucket size overflows"))
}

fn private_hnsw_restore_error(err: qdrant_sec::PrivateHnswOramError) -> CollectionError {
    CollectionError::bad_request(err.to_string())
}

fn private_hnsw_distance_kind(distance: segment::types::Distance) -> DistanceKind {
    match distance {
        segment::types::Distance::Cosine => DistanceKind::Cosine,
        segment::types::Distance::Euclid => DistanceKind::Euclid,
        segment::types::Distance::Dot => DistanceKind::Dot,
        segment::types::Distance::Manhattan => DistanceKind::Manhattan,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        FixedBudgetParams, OramKind, OramParams, PrivateHnswOramBucket, PrivateHnswParams,
        ResultPrivacyMode, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
    };
    use segment::types::{Distance, HnswConfig};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::*;
    use crate::config::{
        CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams, EncryptionRuleRef,
        WalConfig,
    };
    use crate::operations::types::VectorsConfig;
    use crate::operations::vector_params_builder::VectorParamsBuilder;
    use crate::optimizers_builder::OptimizersConfig;

    fn params_with_migration_state(migration_state: CryptoMigrationState) -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state,
                rules: Vec::new(),
            }),
            ..CollectionParams::empty()
        }
    }

    fn private_hnsw_config(uuid: Uuid) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                vectors: VectorsConfig::Multi(BTreeMap::from([(
                    "text".into(),
                    VectorParamsBuilder::new(1536, Distance::Cosine).build(),
                )])),
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
                        instance: "docs_text_private_hnsw".to_string(),
                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig::fixture(),
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(uuid),
            metadata: None,
        }
    }

    fn private_hnsw_manifest(collection_id: String) -> PrivateHnswOramManifest {
        PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id,
            vector_name: "text".to_string(),
            key_id: "tenant-a/vector-private-rk".to_string(),
            rk_id: "tenant-a/vector-private-rk".to_string(),
            rk_epoch: 7,
            dim: 1536,
            distance: DistanceKind::Cosine,
            hnsw: PrivateHnswParams {
                m: 32,
                ef_construction: 128,
                max_layers: 16,
                fixed_neighbor_slots: 64,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 8192,
                tree_height: 3,
                path_batch_size: 2,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 32,
                base_layer_steps: 256,
                paths_per_round: 2,
                fixed_result_k: 10,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[9; 32]),
            bucket_count: 1,
            logical_node_count: 3,
            dummy_node_count: 1,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1,
        }
    }

    fn write_private_hnsw_snapshot_fixture(
        collection_dir: &Path,
        manifest: &PrivateHnswOramManifest,
    ) {
        let store = PrivateHnswOramStore::new(collection_dir, "text").unwrap();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        };
        store.write_manifest(manifest, &signature).unwrap();
        store
            .write_initial_epoch(&crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            })
            .unwrap();

        let ciphertext = BASE64URL_NOPAD.encode(b"encrypted bucket 0");
        let ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(b"encrypted bucket 0").as_ref());
        store
            .write_bucket(
                &PrivateHnswOramBucket {
                    version: 1,
                    bucket_id: 0,
                    index_epoch: manifest.index_epoch,
                    ciphertext,
                    ciphertext_sha256,
                    bucket_commitment: BASE64URL_NOPAD.encode(&[9; 32]),
                },
                manifest.index_epoch,
                manifest.bucket_count,
                private_hnsw_restore_max_bucket_ciphertext_bytes(manifest).unwrap(),
            )
            .unwrap();
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                vec![BASE64URL_NOPAD.encode(&[9; 32])],
            )
            .unwrap();
    }

    #[test]
    fn snapshot_crypto_migration_state_guard_rejects_in_flight_states() {
        ensure_snapshot_crypto_migration_state_allows_snapshot(
            "docs",
            &params_with_migration_state(CryptoMigrationState::Active),
        )
        .unwrap();
        ensure_snapshot_crypto_migration_state_allows_snapshot(
            "docs",
            &params_with_migration_state(CryptoMigrationState::Disabled),
        )
        .unwrap();

        for migration_state in [
            CryptoMigrationState::Encrypting,
            CryptoMigrationState::Rotating,
            CryptoMigrationState::Decrypting,
        ] {
            let err = ensure_snapshot_crypto_migration_state_allows_snapshot(
                "docs",
                &params_with_migration_state(migration_state),
            )
            .expect_err("in-flight crypto migration snapshots must fail closed");
            assert!(
                err.to_string().contains("migration_state=active"),
                "unexpected error for {migration_state:?}: {err}",
            );
        }
    }

    #[test]
    fn private_result_oram_restore_guard_rejects_reserved_directory() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-reserved")
            .tempdir()
            .unwrap();

        ensure_private_result_oram_snapshot_restore_not_present(temp_dir.path()).unwrap();

        fs::create_dir(temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR)).unwrap();
        let err =
            ensure_private_result_oram_snapshot_restore_not_present(temp_dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains(PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER)
        );
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_accepts_manifest_epoch_and_bucket() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-ok")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_result_private_manifest() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-result-private")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.result_privacy = ResultPrivacyMode::PrivatePayloadOramRequired;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("result_privacy=ids_visible"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_signature_key_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-signature-key")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        store
            .write_manifest(
                &manifest,
                &PrivateHnswOramSignature {
                    alg: "ed25519".to_string(),
                    key_id: "tenant-a/private-hnsw-signing-v2".to_string(),
                    sig: BASE64URL_NOPAD.encode(&[7; 64]),
                },
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("signature key_id"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_context_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-context")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(Uuid::from_u128(8).to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("collection_id mismatch"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_vector_metadata_mismatch() {
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);

        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-vector-name")
            .tempdir()
            .unwrap();
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.vector_name = "title".to_string();
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("vector_name mismatch"));

        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-dim")
            .tempdir()
            .unwrap();
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.dim = 768;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("dim mismatch"));

        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-distance")
            .tempdir()
            .unwrap();
        let mut manifest = private_hnsw_manifest(uuid.to_string());
        manifest.distance = DistanceKind::Dot;
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("distance mismatch"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_missing_bucket_zero() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        };
        store.write_manifest(&manifest, &signature).unwrap();
        store
            .write_initial_epoch(&crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            })
            .unwrap();
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                vec![BASE64URL_NOPAD.encode(&[9; 32])],
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("00000000.bucket"));
    }
}
