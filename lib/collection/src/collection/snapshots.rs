use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

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
        let collection_config = {
            let collection_config = self.collection_config.read().await;
            ensure_snapshot_crypto_migration_state_allows_snapshot(
                self.name(),
                &collection_config.params,
            )?;
            let collection_config = collection_config.clone();
            let configured_private_hnsw_vectors =
                private_hnsw_oram_configured_vectors(&collection_config.params)?;
            validate_private_hnsw_oram_snapshot_store_matches_config(
                &self.path,
                &configured_private_hnsw_vectors,
            )?;
            collection_config
        };

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
            collection_config.to_bytes()?,
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

        if let Some(private_hnsw_oram_path) =
            private_oram_snapshot_source_dir(&self.path, PRIVATE_HNSW_ORAM_DIR)?
        {
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

        if let Some(private_result_oram_path) =
            private_oram_snapshot_source_dir(&self.path, PRIVATE_RESULT_ORAM_DIR)?
        {
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
        let restore_collection_name = target_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("restored_collection");
        Self::validate_private_hnsw_oram_snapshot_restore_layout(
            restore_collection_name,
            &config,
            target_dir,
        )
        .map_err(|err| sanitize_private_hnsw_snapshot_layout_error(target_dir, err))?;
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
        let configured_vectors = private_hnsw_oram_configured_vectors(&config.params)?;

        validate_private_hnsw_oram_snapshot_store_matches_config(
            collection_dir,
            &configured_vectors,
        )?;

        if configured_vectors.is_empty() {
            return Ok(());
        }

        let stable_crypto_id = config.stable_crypto_id(collection_name)?;
        for vector_name in configured_vectors {
            validate_private_hnsw_oram_vector_snapshot(
                collection_dir,
                &stable_crypto_id,
                &config.params,
                &vector_name,
            )?;
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
        self.validate_private_hnsw_oram_shard_snapshot_allowed("shard snapshot creation")
            .await?;

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
        self.validate_private_hnsw_oram_shard_snapshot_allowed("shard snapshot streaming")
            .await?;

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
        validate_private_hnsw_oram_shard_snapshot_operation(
            &collection_name,
            &collection_params,
            "shard snapshot recovery",
        )?;

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
        self.validate_private_hnsw_oram_shard_snapshot_allowed("partial shard snapshot manifest")
            .await?;

        self.shards_holder
            .read()
            .await
            .get_shard(shard_id)
            .ok_or_else(|| shard_not_found_error(shard_id))?
            .get_partial_snapshot_manifest()
            .await
    }

    pub async fn validate_private_hnsw_oram_shard_snapshot_allowed(
        &self,
        operation_name: &str,
    ) -> CollectionResult<()> {
        let params = self.collection_config.read().await.params.clone();
        validate_private_hnsw_oram_shard_snapshot_operation(self.name(), &params, operation_name)
    }
}

fn private_oram_snapshot_source_dir(
    collection_dir: &Path,
    dir_name: &str,
) -> CollectionResult<Option<PathBuf>> {
    let source_dir = collection_dir.join(dir_name);
    match std::fs::symlink_metadata(&source_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            Err(CollectionError::service_error(format!(
                "{dir_name} snapshot source must be a non-symlink directory",
            )))
        }
        Ok(_) => Ok(Some(source_dir)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CollectionError::service_error(format!(
            "failed to inspect {dir_name} snapshot source: {err}"
        ))),
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
    match std::fs::symlink_metadata(&private_result_oram_path) {
        Ok(_) => Err(CollectionError::bad_request(format!(
            "private result ORAM snapshot restore requires {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER}, \
             which is reserved until the payload ORAM provider runtime is implemented"
        ))),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CollectionError::service_error(format!(
            "failed to inspect private result ORAM snapshot restore guard: {err}"
        ))),
    }
}

fn validate_private_hnsw_oram_shard_snapshot_operation(
    collection_name: &str,
    params: &CollectionParams,
    operation_name: &str,
) -> CollectionResult<()> {
    if private_hnsw_oram_configured_vectors(params)?.is_empty() {
        return Ok(());
    }

    Err(CollectionError::bad_request(format!(
        "{operation_name} for private HNSW ORAM collection {collection_name} is disabled until \
         shard snapshots include collection-local encrypted ORAM buckets with epoch/root parity; \
         use collection snapshot/restore preflight",
    )))
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

    let max_bucket_ciphertext_bytes = private_hnsw_restore_max_bucket_ciphertext_bytes(&manifest)?;
    let mut bucket_commitments = Vec::new();
    for bucket_id in 0..manifest.bucket_count {
        let bucket = store.read_bucket(
            bucket_id,
            manifest.index_epoch,
            manifest.bucket_count,
            max_bucket_ciphertext_bytes,
        )?;
        bucket_commitments.push(bucket.bucket_commitment);
    }
    let bucket_root = PrivateHnswOramStore::merkle_root_for_commitments(&bucket_commitments)?;
    if bucket_root != manifest.root_hash {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM snapshot vector '{vector_name}' bucket commitments do not match manifest root_hash",
        )));
    }
    let last_bucket_id = manifest.bucket_count.saturating_sub(1);
    let bucket_ids = if last_bucket_id == 0 {
        vec![0]
    } else {
        vec![0, last_bucket_id]
    };
    store.read_merkle_path_batch(
        &bucket_ids,
        manifest.index_epoch,
        &manifest.root_hash,
        manifest.bucket_count,
    )?;

    Ok(())
}

fn private_hnsw_oram_configured_vectors(
    params: &CollectionParams,
) -> CollectionResult<HashSet<String>> {
    let mut configured_vectors = HashSet::new();
    let Some(encryption) = params.effective_encryption() else {
        return Ok(configured_vectors);
    };

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
        configured_vectors.extend(names.iter().cloned());
    }

    Ok(configured_vectors)
}

fn validate_private_hnsw_oram_snapshot_store_matches_config(
    collection_dir: &Path,
    configured_vectors: &HashSet<String>,
) -> CollectionResult<()> {
    let private_hnsw_root = collection_dir.join(PRIVATE_HNSW_ORAM_DIR);
    let metadata = match std::fs::symlink_metadata(&private_hnsw_root) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound && configured_vectors.is_empty() => {
            return Ok(());
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot store is missing for configured vector rules",
            ));
        }
        Err(_) => {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot store root cannot be inspected",
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot store root must be a non-symlink directory",
        ));
    }

    if configured_vectors.is_empty() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot store is present without a matching collection encryption rule",
        ));
    }

    let entries = std::fs::read_dir(&private_hnsw_root).map_err(|_| {
        CollectionError::bad_request("private HNSW ORAM snapshot store root cannot be read")
    })?;
    let mut stored_vectors = HashSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM snapshot store entry cannot be read")
        })?;
        let file_name = entry.file_name().into_string().map_err(|_| {
            CollectionError::bad_request(
                "private HNSW ORAM snapshot contains a non-UTF-8 vector store",
            )
        })?;
        let entry_metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            CollectionError::bad_request(
                "private HNSW ORAM snapshot vector store cannot be inspected",
            )
        })?;
        if entry_metadata.file_type().is_symlink() || !entry_metadata.file_type().is_dir() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot vector store must be a non-symlink directory",
            ));
        }
        if !configured_vectors.contains(&file_name) {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM snapshot contains an unconfigured vector store",
            ));
        }
        stored_vectors.insert(file_name);
    }

    if stored_vectors.len() != configured_vectors.len() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM snapshot is missing a configured vector store",
        ));
    }

    Ok(())
}

fn sanitize_private_hnsw_snapshot_layout_error(
    collection_dir: &Path,
    err: CollectionError,
) -> CollectionError {
    let rendered = err.to_string();
    if rendered.contains(collection_dir.to_string_lossy().as_ref())
        || rendered.contains(PRIVATE_HNSW_ORAM_DIR)
    {
        return CollectionError::bad_request("private HNSW ORAM snapshot layout validation failed");
    }
    err
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
        let bucket_count = 3;
        let commitments = private_hnsw_snapshot_leaf_commitments(bucket_count);
        let root_hash = PrivateHnswOramStore::merkle_root_for_commitments(&commitments).unwrap();

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
                block_size_bytes: 16384,
                tree_height: 1,
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
            root_hash,
            bucket_count,
            logical_node_count: 3,
            dummy_node_count: 1,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1,
        }
    }

    fn private_hnsw_snapshot_leaf_commitments(bucket_count: u64) -> Vec<String> {
        (0..bucket_count)
            .map(|bucket_id| BASE64URL_NOPAD.encode(&[9 + bucket_id as u8; 32]))
            .collect()
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

        let commitments = private_hnsw_snapshot_leaf_commitments(manifest.bucket_count);
        for (bucket_id, commitment) in commitments.iter().enumerate() {
            let plaintext = format!("encrypted bucket {bucket_id}");
            let ciphertext = BASE64URL_NOPAD.encode(plaintext.as_bytes());
            let ciphertext_sha256 =
                BASE64URL_NOPAD.encode(Sha256::digest(plaintext.as_bytes()).as_ref());
            store
                .write_bucket(
                    &PrivateHnswOramBucket {
                        version: 1,
                        bucket_id: bucket_id as u64,
                        index_epoch: manifest.index_epoch,
                        ciphertext,
                        ciphertext_sha256,
                        bucket_commitment: commitment.clone(),
                    },
                    manifest.index_epoch,
                    manifest.bucket_count,
                    private_hnsw_restore_max_bucket_ciphertext_bytes(manifest).unwrap(),
                )
                .unwrap();
        }
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                commitments,
            )
            .unwrap();
    }

    fn private_hnsw_snapshot_bucket_path(collection_dir: &Path, bucket_id: u64) -> PathBuf {
        collection_dir
            .join(PRIVATE_HNSW_ORAM_DIR)
            .join("text")
            .join("buckets")
            .join(format!("{bucket_id:08}.bucket"))
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
    fn private_oram_snapshot_source_dir_accepts_only_present_directories() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source")
            .tempdir()
            .unwrap();

        assert!(
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR)
                .unwrap()
                .is_none()
        );

        fs::create_dir(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();
        assert!(
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn private_hnsw_oram_shard_snapshot_operations_fail_closed_until_bucket_parity_supported() {
        let empty_params = CollectionParams::empty();
        validate_private_hnsw_oram_shard_snapshot_operation(
            "docs",
            &empty_params,
            "shard snapshot creation",
        )
        .unwrap();

        let config = private_hnsw_config(Uuid::from_u128(7));
        for operation_name in [
            "shard snapshot creation",
            "shard snapshot streaming",
            "shard snapshot recovery",
            "partial shard snapshot manifest",
        ] {
            let err = validate_private_hnsw_oram_shard_snapshot_operation(
                "docs",
                &config.params,
                operation_name,
            )
            .expect_err("private HNSW ORAM shard snapshots must fail closed");
            let rendered = err.to_string();
            assert!(
                rendered.contains(&format!(
                    "{operation_name} for private HNSW ORAM collection docs"
                )),
                "unexpected error: {rendered}",
            );
            assert!(
                rendered.contains("collection-local encrypted ORAM buckets"),
                "unexpected error: {rendered}",
            );
            assert!(
                rendered.contains("collection snapshot/restore preflight"),
                "unexpected error: {rendered}",
            );
            assert!(!rendered.contains(PRIVATE_HNSW_ORAM_DIR));
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_oram_snapshot_source_dir_rejects_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-oram-snapshot-source-symlink")
            .tempdir()
            .unwrap();

        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-private-hnsw-oram"),
            temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_HNSW_ORAM_DIR).unwrap_err();

        assert!(err.to_string().contains("non-symlink directory"));
        assert!(!err.to_string().contains("outside-private-hnsw-oram"));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_snapshot_source_dir_rejects_symlink_without_target_leak() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-snapshot-source-symlink")
            .tempdir()
            .unwrap();

        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-private-result-oram"),
            temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
        )
        .unwrap();

        let err =
            private_oram_snapshot_source_dir(temp_dir.path(), PRIVATE_RESULT_ORAM_DIR).unwrap_err();

        assert!(err.to_string().contains("non-symlink directory"));
        assert!(!err.to_string().contains("outside-private-result-oram"));
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
        let err = err.to_string();
        assert!(err.contains(PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
        assert!(!err.contains(temp_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn private_result_oram_restore_guard_rejects_reserved_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-restore-symlink")
            .tempdir()
            .unwrap();

        std::os::unix::fs::symlink(
            temp_dir.path().join("missing-result-oram-target"),
            temp_dir.path().join(PRIVATE_RESULT_ORAM_DIR),
        )
        .unwrap();

        let err =
            ensure_private_result_oram_snapshot_restore_not_present(temp_dir.path()).unwrap_err();

        assert!(
            err.to_string()
                .contains(PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER)
        );
        assert!(!err.to_string().contains("missing-result-oram-target"));
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
    fn private_hnsw_oram_restore_preflight_rejects_missing_store_for_configured_rule() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-store")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("missing for configured vector rules")
        );
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_missing_configured_vector_store() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-vector-store")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        fs::create_dir(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR)).unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("missing a configured vector store")
        );
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_store_without_binding() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-orphan-store")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut config = private_hnsw_config(uuid);
        config.params.encryption.as_mut().unwrap().rules.clear();
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("without a matching collection encryption rule")
        );
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_unconfigured_vector_store() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-unconfigured-vector")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        fs::create_dir(temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR).join("title")).unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("unconfigured vector store"));
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_root_dir_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-root-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-private-hnsw-root"),
            temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR),
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("non-symlink directory"));
        assert!(!err.to_string().contains("outside-private-hnsw-root"));
        assert!(!err.to_string().contains(PRIVATE_HNSW_ORAM_DIR));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_bucket_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bucket-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let bucket_path = private_hnsw_snapshot_bucket_path(temp_dir.path(), 0);
        fs::remove_file(&bucket_path).unwrap();
        std::os::unix::fs::symlink(temp_dir.path().join("outside.bucket"), &bucket_path).unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("non-symlink regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_world_readable_bucket_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-world-readable-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);
        let bucket_path = private_hnsw_snapshot_bucket_path(temp_dir.path(), 0);
        fs::set_permissions(&bucket_path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("must not be group/world accessible")
        );
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

    #[cfg(unix)]
    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_vector_dir_symlink() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-vector-dir-symlink")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let private_hnsw_root = temp_dir.path().join(PRIVATE_HNSW_ORAM_DIR);
        fs::create_dir(&private_hnsw_root).unwrap();
        std::os::unix::fs::symlink(
            temp_dir.path().join("outside-private-hnsw-vector"),
            private_hnsw_root.join("text"),
        )
        .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("non-symlink directory"));
        assert!(!err.to_string().contains("outside-private-hnsw-vector"));
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
    fn private_hnsw_oram_restore_preflight_rejects_current_epoch_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-current-epoch")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        store
            .compare_and_swap_epoch(
                &crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                    index_epoch: manifest.index_epoch,
                    root_hash: manifest.root_hash.clone(),
                },
                &crate::private_hnsw_oram_store::PrivateHnswOramEpochState {
                    index_epoch: manifest.index_epoch + 1,
                    root_hash: BASE64URL_NOPAD.encode(&[8; 32]),
                },
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("current epoch/root"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_bucket_commitment_root_mismatch() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-bad-bucket-commitment")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        write_private_hnsw_snapshot_fixture(temp_dir.path(), &manifest);

        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        let mut bucket = store
            .read_bucket(
                1,
                manifest.index_epoch,
                manifest.bucket_count,
                private_hnsw_restore_max_bucket_ciphertext_bytes(&manifest).unwrap(),
            )
            .unwrap();
        bucket.bucket_commitment = BASE64URL_NOPAD.encode(&[99; 32]);
        store
            .write_bucket(
                &bucket,
                manifest.index_epoch,
                manifest.bucket_count,
                private_hnsw_restore_max_bucket_ciphertext_bytes(&manifest).unwrap(),
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("bucket commitments"));
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
                private_hnsw_snapshot_leaf_commitments(manifest.bucket_count),
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

    #[test]
    fn private_hnsw_oram_storage_restore_runs_sanitized_layout_preflight() {
        let snapshot_dir = tempfile::Builder::new()
            .prefix("private-hnsw-storage-restore-source")
            .tempdir()
            .unwrap();
        let target_dir = tempfile::Builder::new()
            .prefix("private-hnsw-storage-restore-target")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        fs::write(
            snapshot_dir.path().join(COLLECTION_CONFIG_FILE),
            config.to_bytes().unwrap(),
        )
        .unwrap();
        let store = PrivateHnswOramStore::new(snapshot_dir.path(), "text").unwrap();
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
                private_hnsw_snapshot_leaf_commitments(manifest.bucket_count),
            )
            .unwrap();

        let err = Collection::restore_snapshot(
            SnapshotData::Unpacked(snapshot_dir),
            target_dir.path(),
            0,
            true,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("private HNSW ORAM snapshot layout validation failed"));
        assert!(!err.contains(target_dir.path().to_string_lossy().as_ref()));
        assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
        assert!(!err.contains("00000000.bucket"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_missing_last_bucket() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-last-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        let leaf0 = BASE64URL_NOPAD.encode(&[9; 32]);
        let leaf1 = BASE64URL_NOPAD.encode(&[10; 32]);
        let leaf2 = BASE64URL_NOPAD.encode(&[11; 32]);

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

        for (bucket_id, leaf, plaintext) in [
            (0, leaf0.clone(), b"encrypted bucket 0".as_slice()),
            (1, leaf1.clone(), b"encrypted bucket 1".as_slice()),
        ] {
            let ciphertext = BASE64URL_NOPAD.encode(plaintext);
            let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(plaintext).as_ref());
            store
                .write_bucket(
                    &PrivateHnswOramBucket {
                        version: 1,
                        bucket_id,
                        index_epoch: manifest.index_epoch,
                        ciphertext,
                        ciphertext_sha256,
                        bucket_commitment: leaf,
                    },
                    manifest.index_epoch,
                    manifest.bucket_count,
                    private_hnsw_restore_max_bucket_ciphertext_bytes(&manifest).unwrap(),
                )
                .unwrap();
        }
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                vec![leaf0, leaf1, leaf2],
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("00000002.bucket"));
    }

    #[test]
    fn private_hnsw_oram_restore_preflight_rejects_missing_middle_bucket() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-restore-missing-middle-bucket")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let config = private_hnsw_config(uuid);
        let manifest = private_hnsw_manifest(uuid.to_string());
        let leaf0 = BASE64URL_NOPAD.encode(&[9; 32]);
        let leaf1 = BASE64URL_NOPAD.encode(&[10; 32]);
        let leaf2 = BASE64URL_NOPAD.encode(&[11; 32]);

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

        for (bucket_id, leaf, plaintext) in [
            (0, leaf0.clone(), b"encrypted bucket 0".as_slice()),
            (2, leaf2.clone(), b"encrypted bucket 2".as_slice()),
        ] {
            let ciphertext = BASE64URL_NOPAD.encode(plaintext);
            let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(plaintext).as_ref());
            store
                .write_bucket(
                    &PrivateHnswOramBucket {
                        version: 1,
                        bucket_id,
                        index_epoch: manifest.index_epoch,
                        ciphertext,
                        ciphertext_sha256,
                        bucket_commitment: leaf,
                    },
                    manifest.index_epoch,
                    manifest.bucket_count,
                    private_hnsw_restore_max_bucket_ciphertext_bytes(&manifest).unwrap(),
                )
                .unwrap();
        }
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                vec![leaf0, leaf1, leaf2],
            )
            .unwrap();

        let err = Collection::validate_private_hnsw_oram_snapshot_restore_layout(
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("00000001.bucket"));
    }
}
