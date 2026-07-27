use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use collection::collection::Collection;
use collection::collection_state;
use collection::config::{CollectionParams, ShardingMethod};
use collection::operations::cluster_ops::ReshardingDirection;
use collection::shards::CollectionId;
use collection::shards::collection_shard_distribution::CollectionShardDistribution;
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::resharding::{ReshardKey, ReshardState, ReshardingStage};
use collection::shards::shard::PeerId;
use fs_err::OpenOptions;
use serde::{Deserialize, Serialize};

use super::TableOfContent;
use crate::content_manager::collection_meta_ops::*;
use crate::content_manager::collections_ops::Checker as _;
use crate::content_manager::consensus::operation_sender::OperationSender;
use crate::content_manager::consensus::persistent::{
    private_oram_epoch_snapshot_value, private_oram_layout_snapshot_value,
};
use crate::content_manager::consensus_ops::{
    ConsensusOperations, PrivateOramCollectionLayoutTransition, PrivateOramConsensusLayout,
    PrivateOramLayoutTransitionState, PrivateOramReshardingOperation,
    PrivateOramShardKeyLayoutChange, PrivateOramShardKeyLayoutChangeKind,
    PrivateOramShardLayoutEntry, PrivateOramShardTransferFinish, PrivateOramShardTransferStart,
    canonical_private_oram_index_state_digest, canonical_private_oram_shard_layout_digest,
    classify_private_oram_replica_removal_layout_transition,
    classify_private_oram_resharding_layout_transition,
    classify_private_oram_shard_key_layout_transition,
    classify_private_oram_shard_transfer_layout_transition, private_oram_index_keys_for_config,
    private_oram_transfer_consensus_layouts, private_oram_transfer_consensus_states,
};
use crate::content_manager::errors::StorageError;
use crate::content_manager::{CollectionContainer, consensus_manager};

const PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_FILE: &str = "private_oram_snapshot_recovery.json";
const PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_VERSION: u16 = 1;
const PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_MAX_BYTES: u64 = 16 * 1024;
const PRIVATE_ORAM_SNAPSHOT_RECOVERY_ABORT_RETRY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramSnapshotRecoveryMarker {
    version: u16,
    resharding_key: ReshardKey,
}

fn invalid_private_oram_snapshot_recovery_marker() -> StorageError {
    StorageError::service_error("private ORAM snapshot recovery marker is invalid")
}

fn private_oram_snapshot_recovery_marker_path(collection_path: &Path) -> PathBuf {
    collection_path.join(PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_FILE)
}

fn read_private_oram_snapshot_recovery_marker(
    collection_path: &Path,
) -> Result<Option<PrivateOramSnapshotRecoveryMarker>, StorageError> {
    let marker_path = private_oram_snapshot_recovery_marker_path(collection_path);
    let metadata = match fs_err::symlink_metadata(&marker_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid_private_oram_snapshot_recovery_marker()),
    };
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_MAX_BYTES
    {
        return Err(invalid_private_oram_snapshot_recovery_marker());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid_private_oram_snapshot_recovery_marker());
        }
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&marker_path)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    if bytes.len() as u64 != metadata.len() {
        return Err(invalid_private_oram_snapshot_recovery_marker());
    }
    let marker: PrivateOramSnapshotRecoveryMarker = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    if marker.version != PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_VERSION {
        return Err(invalid_private_oram_snapshot_recovery_marker());
    }
    Ok(Some(marker))
}

fn write_private_oram_snapshot_recovery_marker(
    collection_path: &Path,
    resharding_key: &ReshardKey,
) -> Result<(), StorageError> {
    let marker = PrivateOramSnapshotRecoveryMarker {
        version: PRIVATE_ORAM_SNAPSHOT_RECOVERY_MARKER_VERSION,
        resharding_key: resharding_key.clone(),
    };
    if let Some(existing) = read_private_oram_snapshot_recovery_marker(collection_path)? {
        return if existing == marker {
            Ok(())
        } else {
            Err(invalid_private_oram_snapshot_recovery_marker())
        };
    }

    let marker_path = private_oram_snapshot_recovery_marker_path(collection_path);
    common::fs::atomic_save_json(&marker_path, &marker)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs_err::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    }
    OpenOptions::new()
        .read(true)
        .open(&marker_path)
        .and_then(|file| file.sync_all())
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    common::fs::sync_parent_dir(&marker_path)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    Ok(())
}

fn remove_private_oram_snapshot_recovery_marker(
    collection_path: &Path,
) -> Result<(), StorageError> {
    if read_private_oram_snapshot_recovery_marker(collection_path)?.is_none() {
        return Ok(());
    }
    let marker_path = private_oram_snapshot_recovery_marker_path(collection_path);
    fs_err::remove_file(&marker_path)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())?;
    common::fs::sync_parent_dir(&marker_path)
        .map_err(|_| invalid_private_oram_snapshot_recovery_marker())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateOramActiveReshardSnapshotAction {
    Apply,
    AbortForReplicaRecovery,
}

impl CollectionContainer for TableOfContent {
    fn perform_collection_meta_op(
        &self,
        operation: CollectionMetaOperations,
    ) -> Result<bool, StorageError> {
        self.perform_collection_meta_op_sync(operation)
    }

    fn perform_private_oram_resharding_meta_op(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<bool, StorageError> {
        self.general_runtime
            .block_on(self.perform_private_oram_resharding_meta_op(operation))
    }

    fn perform_private_oram_collection_layout_meta_op(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<bool, StorageError> {
        self.general_runtime
            .block_on(self.perform_private_oram_collection_layout_meta_op(transition))
    }

    fn private_oram_layout_transition_state(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        self.general_runtime
            .block_on(self.private_oram_layout_transition_state_async(transition))
    }

    fn private_oram_shard_transfer_start_state(
        &self,
        operation: &PrivateOramShardTransferStart,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        self.general_runtime
            .block_on(self.private_oram_shard_transfer_state_async(
                &operation.collection_meta,
                PrivateOramShardTransferPhase::Start,
            ))
    }

    fn private_oram_shard_transfer_finish_state(
        &self,
        operation: &PrivateOramShardTransferFinish,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        self.general_runtime
            .block_on(self.private_oram_shard_transfer_state_async(
                &operation.collection_meta,
                PrivateOramShardTransferPhase::Finish,
            ))
    }

    fn private_oram_resharding_state(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        self.general_runtime
            .block_on(self.private_oram_resharding_state_async(operation))
    }

    fn collections_snapshot(&self) -> consensus_manager::CollectionsSnapshot {
        self.collections_snapshot_sync()
    }

    fn apply_collections_snapshot(
        &self,
        data: consensus_manager::CollectionsSnapshot,
    ) -> Result<(), StorageError> {
        self.apply_collections_snapshot_inner(data, None)
    }

    fn apply_collections_snapshot_with_private_oram_state(
        &self,
        data: consensus_manager::CollectionsSnapshot,
        private_oram: consensus_manager::PrivateOramSnapshotState<'_>,
    ) -> Result<(), StorageError> {
        self.apply_collections_snapshot_inner(data, Some(private_oram))
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
                if let Some(marker) =
                    read_private_oram_snapshot_recovery_marker(collection.path())?
                {
                    match collection.resharding_state().await {
                        Some(state)
                            if state.key() == marker.resharding_key
                                && state.stage == ReshardingStage::MigratingPoints =>
                        {
                            let should_request_abort = {
                                let mut requests = self
                                    .private_oram_snapshot_recovery_abort_requests
                                    .lock()
                                    .await;
                                let now = Instant::now();
                                match requests.get(collection.name()) {
                                    Some(last_request)
                                        if now.duration_since(*last_request)
                                            < PRIVATE_ORAM_SNAPSHOT_RECOVERY_ABORT_RETRY_INTERVAL =>
                                    {
                                        false
                                    }
                                    _ => {
                                        requests.insert(collection.name().to_string(), now);
                                        true
                                    }
                                }
                            };
                            if should_request_abort {
                                log::warn!(
                                    "Requesting private ORAM active reshard rollback for snapshot replica recovery",
                                );
                                let Some(proposal_sender) = &self.consensus_proposal_sender else {
                                    return Err(invalid_private_oram_snapshot_recovery_marker());
                                };
                                if proposal_sender
                                    .send(ConsensusOperations::abort_resharding(
                                        collection.name().to_string(),
                                        marker.resharding_key,
                                    ))
                                    .is_err()
                                {
                                    self.private_oram_snapshot_recovery_abort_requests
                                        .lock()
                                        .await
                                        .remove(collection.name());
                                    return Err(StorageError::service_error(
                                        "private ORAM snapshot recovery abort could not be scheduled",
                                    ));
                                }
                            }
                            continue;
                        }
                        Some(_) => {
                            return Err(invalid_private_oram_snapshot_recovery_marker());
                        }
                        None => {
                            remove_private_oram_snapshot_recovery_marker(collection.path())?;
                            self.private_oram_snapshot_recovery_abort_requests
                                .lock()
                                .await
                                .remove(collection.name());
                        }
                    }
                }
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

impl TableOfContent {
    async fn private_oram_resharding_state_async(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        let (collection_name, phase, resharding_key) = match operation.collection_meta.as_ref() {
            CollectionMetaOperations::Resharding(
                collection_name,
                ReshardingOperation::Start(key),
            ) => (collection_name, PrivateOramReshardingPhase::Start, key),
            CollectionMetaOperations::Resharding(
                collection_name,
                ReshardingOperation::Finish(key),
            ) => (collection_name, PrivateOramReshardingPhase::Finish, key),
            _ => return Err(invalid_private_oram_resharding_layout_transition()),
        };
        if resharding_key != &operation.transition.resharding_key {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let collection = self.get_collection_unchecked(collection_name).await?;
        let config = collection.config_snapshot().await;
        let collection_id = config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_resharding_layout_transition())?;
        let configured_keys = private_oram_index_keys_for_config(&config, collection_name)?;
        let transition_keys = operation
            .transition
            .index_states
            .iter()
            .map(|binding| binding.key.clone())
            .collect::<Vec<_>>();
        if collection_id != operation.transition.layout.key.collection_id
            || configured_keys.is_empty()
            || configured_keys != transition_keys
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if !shard_holder.get_transfers(|_| true).is_empty() {
            return Err(invalid_private_oram_resharding_layout_transition());
        }
        let resharding_state = shard_holder.resharding_state();
        let resharding_is_active = match resharding_state.as_ref() {
            Some(state) if state.matches(resharding_key) => true,
            Some(_) => return Err(invalid_private_oram_resharding_layout_transition()),
            None => false,
        };
        if matches!(phase, PrivateOramReshardingPhase::Finish)
            && resharding_state
                .as_ref()
                .is_some_and(|state| state.stage != ReshardingStage::WriteHashRingCommitted)
        {
            return Err(invalid_private_oram_resharding_layout_transition());
        }

        let mut entries = Vec::new();
        for (shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            let is_scale_up_target = resharding_is_active
                && matches!(phase, PrivateOramReshardingPhase::Start)
                && resharding_key.direction == ReshardingDirection::Up
                && shard_id == resharding_key.shard_id;
            if is_scale_up_target {
                let mut target_owners = peers.keys().copied().collect::<Vec<_>>();
                target_owners.sort_unstable();
                if replica_set.shard_key() != resharding_key.shard_key.as_ref()
                    || target_owners != operation.transition.target_shard_owner_peer_ids
                    || peers.values().any(|state| {
                        !matches!(state, ReplicaState::Resharding | ReplicaState::Active)
                    })
                {
                    return Err(invalid_private_oram_resharding_layout_transition());
                }
                continue;
            }

            let allows_scale_down_transition = resharding_is_active
                && matches!(phase, PrivateOramReshardingPhase::Start)
                && resharding_key.direction == ReshardingDirection::Down;
            if peers.is_empty()
                || peers.values().any(|state| {
                    *state != ReplicaState::Active
                        && !(allows_scale_down_transition
                            && *state == ReplicaState::ReshardingScaleDown)
                })
            {
                return Err(invalid_private_oram_resharding_layout_transition());
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: peers.keys().copied().collect(),
            });
        }

        let layout_state = classify_private_oram_resharding_layout_transition(
            &collection_id,
            shard_holder.get_sharding_method(),
            &entries,
            &operation.transition,
        )?;
        match (
            phase,
            resharding_is_active,
            resharding_key.direction,
            layout_state,
        ) {
            (
                PrivateOramReshardingPhase::Start,
                false,
                _,
                PrivateOramLayoutTransitionState::Pending,
            )
            | (
                PrivateOramReshardingPhase::Finish,
                true,
                ReshardingDirection::Up,
                PrivateOramLayoutTransitionState::Applied,
            )
            | (
                PrivateOramReshardingPhase::Finish,
                true,
                ReshardingDirection::Down,
                PrivateOramLayoutTransitionState::Pending,
            ) => Ok(PrivateOramLayoutTransitionState::Pending),
            (
                PrivateOramReshardingPhase::Start,
                true,
                _,
                PrivateOramLayoutTransitionState::Pending,
            )
            | (
                PrivateOramReshardingPhase::Finish,
                false,
                _,
                PrivateOramLayoutTransitionState::Applied,
            ) => Ok(PrivateOramLayoutTransitionState::Applied),
            _ => Err(invalid_private_oram_resharding_layout_transition()),
        }
    }

    async fn private_oram_layout_transition_state_async(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        let (collection_name, replica_removal) = match (
            transition.collection_meta.as_ref(),
            transition.shard_key_change.as_ref(),
        ) {
            (CollectionMetaOperations::UpdateCollection(update), None) => {
                let removal = update
                    .private_oram_replica_removal_only()
                    .ok_or_else(invalid_private_oram_layout_transition)?;
                (&update.collection_name, Some(removal))
            }
            (CollectionMetaOperations::CreateShardKey(operation), Some(change))
                if private_oram_shard_key_change_matches_create(operation, change) =>
            {
                (&operation.collection_name, None)
            }
            (CollectionMetaOperations::DropShardKey(operation), Some(change))
                if change.kind == PrivateOramShardKeyLayoutChangeKind::Drop
                    && change.shard_key == operation.shard_key =>
            {
                (&operation.collection_name, None)
            }
            _ => return Err(invalid_private_oram_layout_transition()),
        };
        let Some(expected_layout) = transition.layout.expected.as_ref() else {
            return Err(invalid_private_oram_layout_transition());
        };

        let collection = self.get_collection_unchecked(collection_name).await?;
        let config = collection.config_snapshot().await;
        let collection_id = config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_layout_transition())?;
        let configured_keys = private_oram_index_keys_for_config(&config, collection_name)?;
        let transition_keys = transition
            .leases
            .iter()
            .map(|binding| binding.key.clone())
            .collect::<Vec<_>>();
        if collection_id != transition.layout.key.collection_id
            || configured_keys.is_empty()
            || configured_keys != transition_keys
        {
            return Err(invalid_private_oram_layout_transition());
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if shard_holder.resharding_state().is_some()
            || !shard_holder.get_transfers(|_| true).is_empty()
        {
            return Err(invalid_private_oram_layout_transition());
        }
        let mut entries = Vec::new();
        for (current_shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            if peers.is_empty() || peers.values().any(|state| *state != ReplicaState::Active) {
                return Err(invalid_private_oram_layout_transition());
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id: current_shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids: peers.keys().copied().collect(),
            });
        }
        match (replica_removal, transition.shard_key_change.as_ref()) {
            (Some((shard_id, peer_id)), None) => {
                classify_private_oram_replica_removal_layout_transition(
                    &collection_id,
                    shard_holder.get_sharding_method(),
                    &entries,
                    shard_id,
                    peer_id,
                    expected_layout,
                    &transition.layout.new,
                )
            }
            (None, Some(change)) => classify_private_oram_shard_key_layout_transition(
                &collection_id,
                shard_holder.get_sharding_method(),
                &entries,
                change,
                expected_layout,
                &transition.layout.new,
            ),
            _ => Err(invalid_private_oram_layout_transition()),
        }
    }

    async fn private_oram_shard_transfer_state_async(
        &self,
        collection_meta: &CollectionMetaOperations,
        phase: PrivateOramShardTransferPhase,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        let CollectionMetaOperations::TransferShard(collection_name, operation) = collection_meta
        else {
            return Err(invalid_private_oram_transfer_layout_transition());
        };
        let transfer = match (phase, operation) {
            (PrivateOramShardTransferPhase::Start, ShardTransferOperations::Start(transfer))
            | (PrivateOramShardTransferPhase::Finish, ShardTransferOperations::Finish(transfer)) => {
                transfer
            }
            _ => return Err(invalid_private_oram_transfer_layout_transition()),
        };
        let transition = transfer
            .private_oram_layout_transition
            .as_ref()
            .ok_or_else(invalid_private_oram_transfer_layout_transition)?;
        let (layout_key, expected_layout, new_layout) =
            private_oram_transfer_consensus_layouts(transition);
        let transition_keys = private_oram_transfer_consensus_states(transition)
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>();

        let collection = self.get_collection_unchecked(collection_name).await?;
        let config = collection.config_snapshot().await;
        let collection_id = config
            .stable_crypto_id(collection_name)
            .map_err(|_| invalid_private_oram_transfer_layout_transition())?;
        if collection_id != layout_key.collection_id
            || private_oram_index_keys_for_config(&config, collection_name)? != transition_keys
        {
            return Err(invalid_private_oram_transfer_layout_transition());
        }

        let shard_holder = collection.shards_holder().read_owned().await;
        if shard_holder.resharding_state().is_some() {
            return Err(invalid_private_oram_transfer_layout_transition());
        }
        let transfers = shard_holder.get_transfers(|_| true);
        let transfer_is_active = match transfers.as_slice() {
            [] => false,
            [active] if active == transfer => true,
            _ => return Err(invalid_private_oram_transfer_layout_transition()),
        };
        let mut entries = Vec::new();
        for (shard_id, replica_set) in shard_holder.get_shards() {
            let peers = replica_set.peers();
            let mut owner_peer_ids = Vec::new();
            for (peer_id, state) in peers {
                let is_transfer_target = shard_id == transfer.shard_id && peer_id == transfer.to;
                if transfer_is_active && is_transfer_target {
                    if state == ReplicaState::Active {
                        return Err(invalid_private_oram_transfer_layout_transition());
                    }
                    continue;
                }
                if !transfer_is_active
                    && matches!(phase, PrivateOramShardTransferPhase::Start)
                    && is_transfer_target
                    && state == ReplicaState::Dead
                {
                    continue;
                }
                if state != ReplicaState::Active {
                    return Err(invalid_private_oram_transfer_layout_transition());
                }
                owner_peer_ids.push(peer_id);
            }
            if owner_peer_ids.is_empty() {
                return Err(invalid_private_oram_transfer_layout_transition());
            }
            entries.push(PrivateOramShardLayoutEntry {
                shard_id,
                shard_key: replica_set.shard_key().cloned(),
                owner_peer_ids,
            });
        }
        let layout_state = classify_private_oram_shard_transfer_layout_transition(
            &collection_id,
            shard_holder.get_sharding_method(),
            &entries,
            transfer,
            &expected_layout,
            &new_layout,
        )?;
        match (phase, transfer_is_active, layout_state) {
            (
                PrivateOramShardTransferPhase::Start,
                false,
                PrivateOramLayoutTransitionState::Pending,
            )
            | (
                PrivateOramShardTransferPhase::Finish,
                true,
                PrivateOramLayoutTransitionState::Pending,
            ) => Ok(PrivateOramLayoutTransitionState::Pending),
            (
                PrivateOramShardTransferPhase::Start,
                true,
                PrivateOramLayoutTransitionState::Pending,
            )
            | (
                PrivateOramShardTransferPhase::Finish,
                false,
                PrivateOramLayoutTransitionState::Applied,
            ) => Ok(PrivateOramLayoutTransitionState::Applied),
            _ => Err(invalid_private_oram_transfer_layout_transition()),
        }
    }
}

#[derive(Clone, Copy)]
enum PrivateOramShardTransferPhase {
    Start,
    Finish,
}

#[derive(Clone, Copy)]
enum PrivateOramReshardingPhase {
    Start,
    Finish,
}

fn private_oram_shard_key_change_matches_create(
    operation: &CreateShardKey,
    change: &PrivateOramShardKeyLayoutChange,
) -> bool {
    if change.kind != PrivateOramShardKeyLayoutChangeKind::Create
        || change.shard_key != operation.shard_key
        || operation.initial_state != Some(ReplicaState::Active)
        || change.entries.len() != operation.placement.len()
    {
        return false;
    }
    let mut entries = change.entries.clone();
    entries.sort_by_key(|entry| entry.shard_id);
    entries
        .iter()
        .zip(&operation.placement)
        .all(|(entry, placement)| {
            let mut owners = entry.owner_peer_ids.clone();
            let mut placement = placement.clone();
            owners.sort_unstable();
            placement.sort_unstable();
            owners == placement
        })
}

fn invalid_private_oram_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM collection layout transition is invalid")
}

fn invalid_private_oram_transfer_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM shard transfer layout transition is invalid")
}

fn invalid_private_oram_resharding_layout_transition() -> StorageError {
    StorageError::bad_request("private ORAM resharding layout transition is invalid")
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

fn invalid_private_oram_resharding_snapshot() -> StorageError {
    StorageError::bad_request("private ORAM active reshard Raft snapshot state is invalid")
}

fn private_oram_snapshot_shard_key(
    state: &collection_state::State,
    shard_id: collection::shards::shard::ShardId,
    sharding_method: ShardingMethod,
) -> Result<Option<segment::types::ShardKey>, StorageError> {
    let shard_key = state.shards_key_mapping.shard_key(shard_id);
    if matches!(
        (sharding_method, shard_key.as_ref()),
        (ShardingMethod::Auto, None) | (ShardingMethod::Custom, Some(_))
    ) {
        Ok(shard_key)
    } else {
        Err(invalid_private_oram_resharding_snapshot())
    }
}

fn validate_private_oram_snapshot_shard_mapping(
    state: &collection_state::State,
    sharding_method: ShardingMethod,
) -> Result<(), StorageError> {
    let shard_ids = state.shards.keys().copied().collect::<HashSet<_>>();
    let mapped = state
        .shards_key_mapping
        .iter_shard_ids()
        .collect::<Vec<_>>();
    let mapped_ids = mapped.iter().copied().collect::<HashSet<_>>();
    let valid = match sharding_method {
        ShardingMethod::Auto => mapped.is_empty(),
        ShardingMethod::Custom => mapped.len() == mapped_ids.len() && mapped_ids == shard_ids,
    };
    if !valid
        || matches!(sharding_method, ShardingMethod::Auto)
            && state.config.params.shard_number.get() as usize != shard_ids.len()
    {
        return Err(invalid_private_oram_resharding_snapshot());
    }
    Ok(())
}

fn private_oram_stable_snapshot_layout_entries(
    state: &collection_state::State,
) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
    if state.shards.is_empty() || state.resharding.is_some() || !state.transfers.is_empty() {
        return Err(invalid_private_oram_resharding_snapshot());
    }
    let sharding_method = state.config.params.sharding_method.unwrap_or_default();
    validate_private_oram_snapshot_shard_mapping(state, sharding_method)?;
    let mut entries = Vec::with_capacity(state.shards.len());
    for (shard_id, shard) in &state.shards {
        if shard.replicas.is_empty()
            || shard
                .replicas
                .values()
                .any(|replica_state| *replica_state != ReplicaState::Active)
        {
            return Err(invalid_private_oram_resharding_snapshot());
        }
        entries.push(PrivateOramShardLayoutEntry {
            shard_id: *shard_id,
            shard_key: private_oram_snapshot_shard_key(state, *shard_id, sharding_method)?,
            owner_peer_ids: shard.replicas.keys().copied().collect(),
        });
    }
    Ok(entries)
}

fn private_oram_active_reshard_snapshot_layout_entries(
    state: &collection_state::State,
    resharding: &ReshardState,
) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
    if state.shards.is_empty()
        || state
            .transfers
            .iter()
            .any(|transfer| !transfer.is_private_oram_preinstalled_transfer_for(Some(resharding)))
        || resharding.stage != ReshardingStage::MigratingPoints && !state.transfers.is_empty()
    {
        return Err(invalid_private_oram_resharding_snapshot());
    }

    let sharding_method = state.config.params.sharding_method.unwrap_or_default();
    validate_private_oram_snapshot_shard_mapping(state, sharding_method)?;
    let mut target_seen = false;
    let mut entries = Vec::with_capacity(state.shards.len());
    for (shard_id, shard) in &state.shards {
        let shard_key = private_oram_snapshot_shard_key(state, *shard_id, sharding_method)?;
        if shard.replicas.is_empty() {
            return Err(invalid_private_oram_resharding_snapshot());
        }

        let is_target = *shard_id == resharding.shard_id;
        if is_target {
            target_seen = true;
            if shard_key.as_ref() != resharding.shard_key.as_ref()
                || !shard.replicas.contains_key(&resharding.peer_id)
            {
                return Err(invalid_private_oram_resharding_snapshot());
            }
        }

        if resharding.direction == ReshardingDirection::Up && is_target {
            if shard.replicas.len() != 1
                || shard.replicas.values().any(|replica_state| {
                    !matches!(
                        replica_state,
                        ReplicaState::Resharding | ReplicaState::Active
                    ) || resharding.stage != ReshardingStage::MigratingPoints
                        && *replica_state != ReplicaState::Active
                })
            {
                return Err(invalid_private_oram_resharding_snapshot());
            }
            continue;
        }

        let valid_replica_states = shard.replicas.values().all(|replica_state| {
            *replica_state == ReplicaState::Active
                || resharding.direction == ReshardingDirection::Down
                    && resharding.stage == ReshardingStage::MigratingPoints
                    && !is_target
                    && *replica_state == ReplicaState::ReshardingScaleDown
        });
        if !valid_replica_states {
            return Err(invalid_private_oram_resharding_snapshot());
        }
        entries.push(PrivateOramShardLayoutEntry {
            shard_id: *shard_id,
            shard_key,
            owner_peer_ids: shard.replicas.keys().copied().collect(),
        });
    }
    if !target_seen || entries.is_empty() {
        return Err(invalid_private_oram_resharding_snapshot());
    }
    Ok(entries)
}

fn private_oram_snapshot_layout_matches(
    collection_id: &str,
    state: &collection_state::State,
    entries: &[PrivateOramShardLayoutEntry],
    layout: &PrivateOramConsensusLayout,
) -> Result<(), StorageError> {
    let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
        collection_id,
        state.config.params.sharding_method.unwrap_or_default(),
        entries,
    )
    .map_err(|_| invalid_private_oram_resharding_snapshot())?;
    if owner_peer_ids != layout.owner_peer_ids || layout_digest != layout.layout_digest {
        return Err(invalid_private_oram_resharding_snapshot());
    }
    Ok(())
}

fn private_oram_snapshot_can_bootstrap_new_scale_up_target(
    incoming: &collection_state::State,
    resharding: &ReshardState,
    layout: &PrivateOramConsensusLayout,
    this_peer_id: PeerId,
) -> bool {
    if resharding.direction != ReshardingDirection::Up
        || resharding.stage != ReshardingStage::MigratingPoints
        || resharding.peer_id != this_peer_id
        || layout.owner_peer_ids.contains(&this_peer_id)
        || incoming.transfers.len() != 1
    {
        return false;
    }

    let Some(target_shard) = incoming.shards.get(&resharding.shard_id) else {
        return false;
    };
    if target_shard.replicas.len() != 1
        || target_shard.replicas.get(&this_peer_id) != Some(&ReplicaState::Resharding)
        || incoming.shards.iter().any(|(shard_id, shard)| {
            *shard_id != resharding.shard_id && shard.replicas.contains_key(&this_peer_id)
        })
    {
        return false;
    }

    let transfer = incoming
        .transfers
        .iter()
        .next()
        .expect("validated one private ORAM resharding transfer");
    transfer.to == this_peer_id
        && transfer.from != this_peer_id
        && transfer.to_shard_id == Some(resharding.shard_id)
        && transfer.is_private_oram_preinstalled_transfer_for(Some(resharding))
        && incoming
            .shards
            .get(&transfer.shard_id)
            .and_then(|shard| shard.replicas.get(&transfer.from))
            == Some(&ReplicaState::Active)
}

fn private_oram_snapshot_can_rollback_redundant_pre_layout_owner(
    incoming: &collection_state::State,
    resharding: &ReshardState,
    layout: &PrivateOramConsensusLayout,
    pre_layout_entries: &[PrivateOramShardLayoutEntry],
    this_peer_id: PeerId,
) -> bool {
    let is_scale_down_endpoint = resharding.peer_id == this_peer_id;
    if resharding.stage != ReshardingStage::MigratingPoints
        || !layout.owner_peer_ids.contains(&this_peer_id)
        || incoming
            .transfers
            .iter()
            .any(|transfer| transfer.from == this_peer_id || transfer.to == this_peer_id)
    {
        return false;
    }
    if is_scale_down_endpoint
        && (resharding.direction != ReshardingDirection::Down
            || !incoming.transfers.is_empty()
            || incoming.shards.values().any(|shard| {
                shard
                    .replicas
                    .values()
                    .any(|state| *state != ReplicaState::Active)
            }))
    {
        return false;
    }

    let local_pre_layout_entries = pre_layout_entries
        .iter()
        .filter(|entry| entry.owner_peer_ids.contains(&this_peer_id))
        .collect::<Vec<_>>();
    if is_scale_down_endpoint
        && (local_pre_layout_entries.len() != 1
            || local_pre_layout_entries[0].shard_id != resharding.shard_id)
    {
        return false;
    }
    !local_pre_layout_entries.is_empty()
        && local_pre_layout_entries.iter().all(|entry| {
            incoming.shards.get(&entry.shard_id).is_some_and(|shard| {
                matches!(
                    shard.replicas.get(&this_peer_id),
                    Some(ReplicaState::Active | ReplicaState::ReshardingScaleDown)
                ) && shard.replicas.iter().any(|(peer_id, state)| {
                    *peer_id != this_peer_id && *state == ReplicaState::Active
                })
            })
        })
}

fn classify_private_oram_active_reshard_snapshot(
    collection_name: &str,
    current: Option<&collection_state::State>,
    incoming: &collection_state::State,
    snapshot: consensus_manager::PrivateOramSnapshotState<'_>,
    this_peer_id: PeerId,
) -> Result<Option<PrivateOramActiveReshardSnapshotAction>, StorageError> {
    let Some(incoming_resharding) = incoming.resharding.as_ref() else {
        return Ok(None);
    };
    let incoming_keys = private_oram_index_keys_for_config(&incoming.config, collection_name)?;
    if incoming_keys.is_empty() {
        return Ok(None);
    }
    let collection_id = incoming
        .config
        .stable_crypto_id(collection_name)
        .map_err(|_| invalid_private_oram_resharding_snapshot())?;
    if let Some(current) = current {
        let current_keys = private_oram_index_keys_for_config(&current.config, collection_name)?;
        if incoming_keys != current_keys
            || current
                .config
                .stable_crypto_id(collection_name)
                .map_err(|_| invalid_private_oram_resharding_snapshot())?
                != collection_id
            || current.config.params.sharding_method != incoming.config.params.sharding_method
            || current.config.params.replication_factor != incoming.config.params.replication_factor
        {
            return Err(invalid_private_oram_resharding_snapshot());
        }
    }

    let mut index_states = Vec::with_capacity(incoming_keys.len());
    for key in &incoming_keys {
        let incoming_epoch = private_oram_epoch_snapshot_value(snapshot.incoming_epochs, key)
            .ok_or_else(invalid_private_oram_resharding_snapshot)?;
        let current_epoch = private_oram_epoch_snapshot_value(snapshot.current_epochs, key);
        let current_epoch_matches = match current {
            Some(_) => current_epoch == Some(incoming_epoch),
            None => current_epoch.is_none() || current_epoch == Some(incoming_epoch),
        };
        if !current_epoch_matches {
            return Err(invalid_private_oram_resharding_snapshot());
        }
        index_states.push((key.clone(), incoming_epoch.clone()));
    }
    let index_state_digest =
        canonical_private_oram_index_state_digest(&collection_id, &index_states)
            .map_err(|_| invalid_private_oram_resharding_snapshot())?;
    let layout_key = crate::content_manager::consensus_ops::PrivateOramLayoutKey {
        collection_id: collection_id.clone(),
    };
    let incoming_layout =
        private_oram_layout_snapshot_value(snapshot.incoming_layouts, &layout_key)
            .ok_or_else(invalid_private_oram_resharding_snapshot)?;
    let current_layout = private_oram_layout_snapshot_value(snapshot.current_layouts, &layout_key);
    if current_layout.is_some_and(|current_layout| current_layout != incoming_layout)
        || current.is_some() && current_layout.is_none() && incoming_layout.generation != 1
        || incoming_layout.index_state_digest != index_state_digest
    {
        return Err(invalid_private_oram_resharding_snapshot());
    }

    let incoming_entries =
        private_oram_active_reshard_snapshot_layout_entries(incoming, incoming_resharding)?;
    private_oram_snapshot_layout_matches(
        &collection_id,
        incoming,
        &incoming_entries,
        incoming_layout,
    )?;

    let Some(current) = current else {
        let topology_only_non_owner = !incoming_layout.owner_peer_ids.contains(&this_peer_id)
            && !incoming
                .shards
                .values()
                .any(|shard| shard.replicas.contains_key(&this_peer_id))
            && !incoming
                .transfers
                .iter()
                .any(|transfer| transfer.from == this_peer_id || transfer.to == this_peer_id);
        let action = if topology_only_non_owner
            || private_oram_snapshot_can_bootstrap_new_scale_up_target(
                incoming,
                incoming_resharding,
                incoming_layout,
                this_peer_id,
            ) {
            PrivateOramActiveReshardSnapshotAction::Apply
        } else if private_oram_snapshot_can_rollback_redundant_pre_layout_owner(
            incoming,
            incoming_resharding,
            incoming_layout,
            &incoming_entries,
            this_peer_id,
        ) {
            PrivateOramActiveReshardSnapshotAction::AbortForReplicaRecovery
        } else {
            return Err(invalid_private_oram_resharding_snapshot());
        };
        return Ok(Some(action));
    };

    match current.resharding.as_ref() {
        None => {
            let current_entries = private_oram_stable_snapshot_layout_entries(current)?;
            private_oram_snapshot_layout_matches(
                &collection_id,
                current,
                &current_entries,
                incoming_layout,
            )?;
            let config_transition_matches = match incoming_resharding.direction {
                ReshardingDirection::Up => current
                    .config
                    .params
                    .shard_number
                    .checked_add(1)
                    .is_some_and(|count| count == incoming.config.params.shard_number),
                ReshardingDirection::Down => {
                    current.config.params.shard_number == incoming.config.params.shard_number
                }
            };
            if !config_transition_matches {
                return Err(invalid_private_oram_resharding_snapshot());
            }
        }
        Some(current_resharding) => {
            if current_resharding.key() != incoming_resharding.key()
                || current_resharding.stage > incoming_resharding.stage
                || current.config.params.shard_number != incoming.config.params.shard_number
                || current.shards.keys().collect::<HashSet<_>>()
                    != incoming.shards.keys().collect::<HashSet<_>>()
            {
                return Err(invalid_private_oram_resharding_snapshot());
            }
            let current_entries =
                private_oram_active_reshard_snapshot_layout_entries(current, current_resharding)?;
            private_oram_snapshot_layout_matches(
                &collection_id,
                current,
                &current_entries,
                incoming_layout,
            )?;
            for (shard_id, current_shard) in &current.shards {
                let incoming_shard = incoming
                    .shards
                    .get(shard_id)
                    .ok_or_else(invalid_private_oram_resharding_snapshot)?;
                if current_shard.replicas.keys().collect::<HashSet<_>>()
                    != incoming_shard.replicas.keys().collect::<HashSet<_>>()
                    || current_shard
                        .replicas
                        .iter()
                        .any(|(peer_id, replica_state)| {
                            *replica_state == ReplicaState::Active
                                && incoming_shard.replicas.get(peer_id)
                                    != Some(&ReplicaState::Active)
                        })
                {
                    return Err(invalid_private_oram_resharding_snapshot());
                }
            }
        }
    }

    Ok(Some(PrivateOramActiveReshardSnapshotAction::Apply))
}

#[cfg(test)]
fn validate_private_oram_active_reshard_snapshot(
    collection_name: &str,
    current: Option<&collection_state::State>,
    incoming: &collection_state::State,
    snapshot: consensus_manager::PrivateOramSnapshotState<'_>,
    this_peer_id: PeerId,
) -> Result<bool, StorageError> {
    Ok(classify_private_oram_active_reshard_snapshot(
        collection_name,
        current,
        incoming,
        snapshot,
        this_peer_id,
    )?
    .is_some())
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::num::NonZeroU32;

    use ahash::AHashMap;
    use collection::collection::payload_index_schema::PayloadIndexSchema;
    use collection::collection_state::{ShardInfo, State};
    use collection::config::{
        CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams,
        CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, ShardingMethod, WalConfig,
    };
    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::optimizers_builder::OptimizersConfig;
    use collection::shards::replica_set::replica_set_state::ReplicaState;
    use collection::shards::resharding::{ReshardState, ReshardingStage};
    use collection::shards::transfer::{ShardTransfer, ShardTransferMethod};
    use data_encoding::BASE64URL_NOPAD;
    use fs_err as fs;
    use segment::types::HnswConfig;
    use uuid::Uuid;

    use super::{
        PrivateOramActiveReshardSnapshotAction, classify_private_oram_active_reshard_snapshot,
        collection_params_bind_crypto_identity, encrypted_uuid_mismatch_requires_fail_closed,
        private_oram_snapshot_recovery_marker_path, read_private_oram_snapshot_recovery_marker,
        remove_private_oram_snapshot_recovery_marker,
        validate_private_oram_active_reshard_snapshot, write_private_oram_snapshot_recovery_marker,
    };
    use crate::content_manager::consensus::persistent::{
        private_oram_epoch_key_digest, private_oram_layout_key_digest,
    };
    use crate::content_manager::consensus_manager::PrivateOramSnapshotState;
    use crate::content_manager::consensus_ops::{
        PrivateOramConsensusEpoch, PrivateOramConsensusLayout, PrivateOramLayoutKey,
        PrivateOramShardLayoutEntry, canonical_private_oram_index_state_digest,
        canonical_private_oram_shard_layout_digest, private_oram_index_keys_for_config,
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

    fn test_optimizers_config() -> OptimizersConfig {
        OptimizersConfig {
            deleted_threshold: 0.1,
            vacuum_min_vector_number: 1000,
            default_segment_number: 0,
            max_segment_size: None,
            #[expect(deprecated)]
            memmap_threshold: None,
            indexing_threshold: Some(100_000),
            flush_interval_sec: 60,
            max_optimization_threads: Some(0),
            prevent_unoptimized: None,
        }
    }

    fn private_oram_snapshot_config(shard_number: u32) -> CollectionConfigInternal {
        let mut params = CollectionParams::empty();
        params.shard_number = NonZeroU32::new(shard_number).unwrap();
        params.encryption = Some(CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a/private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "private-result".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["body".to_string()],
                },
                instance: "docs-private-result".to_string(),
                binding: Some("private-result-oram/v1".to_string()),
            }],
        });
        CollectionConfigInternal {
            params,
            hnsw_config: HnswConfig::default(),
            optimizer_config: test_optimizers_config(),
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(Uuid::from_u128(0x1234567890abcdef1234567890abcdef)),
            metadata: None,
        }
    }

    fn private_oram_active_snapshot_fixture() -> (
        State,
        State,
        HashMap<String, PrivateOramConsensusEpoch>,
        HashMap<String, PrivateOramConsensusLayout>,
    ) {
        let current = State {
            config: private_oram_snapshot_config(1),
            shards: AHashMap::from([(
                0,
                ShardInfo {
                    replicas: HashMap::from([(11, ReplicaState::Active)]),
                },
            )]),
            resharding: None,
            transfers: HashSet::new(),
            shards_key_mapping: Default::default(),
            payload_index_schema: PayloadIndexSchema::default(),
        };
        let resharding = ReshardState::new(Uuid::nil(), ReshardingDirection::Up, 22, 1, None);
        let incoming = State {
            config: private_oram_snapshot_config(2),
            shards: AHashMap::from([
                (
                    0,
                    ShardInfo {
                        replicas: HashMap::from([(11, ReplicaState::Active)]),
                    },
                ),
                (
                    1,
                    ShardInfo {
                        replicas: HashMap::from([(22, ReplicaState::Resharding)]),
                    },
                ),
            ]),
            resharding: Some(resharding),
            transfers: HashSet::from([ShardTransfer {
                shard_id: 0,
                to_shard_id: Some(1),
                from: 11,
                to: 22,
                sync: true,
                method: Some(ShardTransferMethod::ReshardingStreamRecords),
                private_oram_preinstalled: true,
                private_oram_layout_transition: None,
                filter: None,
            }]),
            shards_key_mapping: Default::default(),
            payload_index_schema: PayloadIndexSchema::default(),
        };

        let collection_id = incoming.config.stable_crypto_id("docs").unwrap();
        let keys = private_oram_index_keys_for_config(&incoming.config, "docs").unwrap();
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[3; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[4; 32])),
        };
        let epochs = HashMap::from([(private_oram_epoch_key_digest(&keys[0]), epoch.clone())]);
        let index_state_digest =
            canonical_private_oram_index_state_digest(&collection_id, &[(keys[0].clone(), epoch)])
                .unwrap();
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &[PrivateOramShardLayoutEntry {
                shard_id: 0,
                shard_key: None,
                owner_peer_ids: vec![11],
            }],
        )
        .unwrap();
        let layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids,
            layout_digest,
            index_state_digest,
        };
        let layout_key = PrivateOramLayoutKey { collection_id };
        let layouts = HashMap::from([(private_oram_layout_key_digest(&layout_key), layout)]);
        (current, incoming, epochs, layouts)
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

    #[test]
    fn private_oram_active_reshard_snapshot_requires_exact_consensus_bound_pre_layout() {
        let (current, incoming, epochs, layouts) = private_oram_active_snapshot_fixture();
        let context = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &layouts,
        };
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&incoming),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );

        let mut wrong_layouts = layouts.clone();
        wrong_layouts.values_mut().next().unwrap().layout_digest = BASE64URL_NOPAD.encode(&[9; 32]);
        let err = validate_private_oram_active_reshard_snapshot(
            "docs",
            Some(&current),
            &incoming,
            PrivateOramSnapshotState {
                incoming_epochs: &epochs,
                current_epochs: &epochs,
                incoming_layouts: &wrong_layouts,
                current_layouts: &layouts,
            },
            33,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("private ORAM active reshard Raft snapshot state is invalid")
        );

        let mut wrong_epochs = epochs.clone();
        wrong_epochs.values_mut().next().unwrap().index_epoch += 1;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &wrong_epochs,
                    current_epochs: &epochs,
                    incoming_layouts: &layouts,
                    current_layouts: &layouts,
                },
                33,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_active_reshard_snapshot_allows_only_first_layout_initialization() {
        let (current, incoming, epochs, layouts) = private_oram_active_snapshot_fixture();
        let empty_layouts = HashMap::new();
        let context = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&incoming),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );

        let mut later_layouts = layouts.clone();
        later_layouts.values_mut().next().unwrap().generation = 2;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &epochs,
                    incoming_layouts: &later_layouts,
                    current_layouts: &empty_layouts,
                },
                33,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_new_peer_active_reshard_snapshot_allows_only_recoverable_roles() {
        let (_, incoming, epochs, layouts) = private_oram_active_snapshot_fixture();
        let empty_epochs = HashMap::new();
        let empty_layouts = HashMap::new();

        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &empty_epochs,
                    incoming_layouts: &layouts,
                    current_layouts: &empty_layouts,
                },
                33,
            )
            .unwrap()
        );

        let mut later_layouts = layouts.clone();
        later_layouts.values_mut().next().unwrap().generation = 7;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &empty_epochs,
                    incoming_layouts: &later_layouts,
                    current_layouts: &empty_layouts,
                },
                33,
            )
            .unwrap()
        );
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &epochs,
                    incoming_layouts: &later_layouts,
                    current_layouts: &later_layouts,
                },
                33,
            )
            .unwrap()
        );

        let mut wrong_epochs = epochs.clone();
        wrong_epochs.values_mut().next().unwrap().index_epoch += 1;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &wrong_epochs,
                    incoming_layouts: &layouts,
                    current_layouts: &empty_layouts,
                },
                33,
            )
            .is_err()
        );

        let mut wrong_layouts = layouts.clone();
        wrong_layouts.values_mut().next().unwrap().generation += 1;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &incoming,
                PrivateOramSnapshotState {
                    incoming_epochs: &epochs,
                    current_epochs: &empty_epochs,
                    incoming_layouts: &layouts,
                    current_layouts: &wrong_layouts,
                },
                33,
            )
            .is_err()
        );

        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &empty_epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };
        assert!(
            validate_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 11,)
                .is_err()
        );
        assert!(
            validate_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 22,)
                .unwrap()
        );

        let mut missing_transfer = incoming.clone();
        missing_transfer.transfers.clear();
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &missing_transfer,
                snapshot,
                22,
            )
            .is_err()
        );

        let mut active_target = incoming.clone();
        *active_target
            .shards
            .get_mut(&1)
            .unwrap()
            .replicas
            .get_mut(&22)
            .unwrap() = ReplicaState::Active;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &active_target,
                snapshot,
                22,
            )
            .is_err()
        );

        let mut target_is_existing_owner = incoming;
        target_is_existing_owner
            .shards
            .get_mut(&0)
            .unwrap()
            .replicas
            .insert(22, ReplicaState::Active);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                None,
                &target_is_existing_owner,
                snapshot,
                22,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_new_redundant_owner_snapshot_requires_exact_reshard_rollback() {
        let (_, mut incoming, epochs, _) = private_oram_active_snapshot_fixture();
        incoming
            .shards
            .get_mut(&0)
            .unwrap()
            .replicas
            .insert(12, ReplicaState::Active);

        let collection_id = incoming.config.stable_crypto_id("docs").unwrap();
        let keys = private_oram_index_keys_for_config(&incoming.config, "docs").unwrap();
        let epoch = epochs.values().next().unwrap().clone();
        let index_state_digest =
            canonical_private_oram_index_state_digest(&collection_id, &[(keys[0].clone(), epoch)])
                .unwrap();
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &[PrivateOramShardLayoutEntry {
                shard_id: 0,
                shard_key: None,
                owner_peer_ids: vec![11, 12],
            }],
        )
        .unwrap();
        let layout_key = PrivateOramLayoutKey { collection_id };
        let layouts = HashMap::from([(
            private_oram_layout_key_digest(&layout_key),
            PrivateOramConsensusLayout {
                generation: 1,
                owner_peer_ids,
                layout_digest,
                index_state_digest,
            },
        )]);
        let empty_epochs = HashMap::new();
        let empty_layouts = HashMap::new();
        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &empty_epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };

        assert_eq!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 12,)
                .unwrap(),
            Some(PrivateOramActiveReshardSnapshotAction::AbortForReplicaRecovery),
        );
        assert!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 11,)
                .is_err(),
            "the active transfer source must not bootstrap through non-endpoint rollback",
        );

        let mut committed = incoming;
        committed.resharding.as_mut().unwrap().stage = ReshardingStage::ReadHashRingCommitted;
        committed.transfers.clear();
        assert!(
            classify_private_oram_active_reshard_snapshot("docs", None, &committed, snapshot, 12,)
                .is_err(),
            "snapshot rollback must close after the read hash ring is committed",
        );
    }

    #[test]
    fn private_oram_wiped_redundant_scale_down_endpoint_requires_exact_rollback() {
        let mut incoming = State {
            config: private_oram_snapshot_config(2),
            shards: AHashMap::from([
                (
                    0,
                    ShardInfo {
                        replicas: HashMap::from([
                            (11, ReplicaState::Active),
                            (44, ReplicaState::Active),
                        ]),
                    },
                ),
                (
                    1,
                    ShardInfo {
                        replicas: HashMap::from([
                            (22, ReplicaState::Active),
                            (33, ReplicaState::Active),
                        ]),
                    },
                ),
            ]),
            resharding: Some(ReshardState::new(
                Uuid::nil(),
                ReshardingDirection::Down,
                22,
                1,
                None,
            )),
            transfers: HashSet::new(),
            shards_key_mapping: Default::default(),
            payload_index_schema: PayloadIndexSchema::default(),
        };
        let collection_id = incoming.config.stable_crypto_id("docs").unwrap();
        let keys = private_oram_index_keys_for_config(&incoming.config, "docs").unwrap();
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[23; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[24; 32])),
        };
        let epochs = HashMap::from([(private_oram_epoch_key_digest(&keys[0]), epoch.clone())]);
        let index_state_digest =
            canonical_private_oram_index_state_digest(&collection_id, &[(keys[0].clone(), epoch)])
                .unwrap();
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &[
                PrivateOramShardLayoutEntry {
                    shard_id: 0,
                    shard_key: None,
                    owner_peer_ids: vec![11, 44],
                },
                PrivateOramShardLayoutEntry {
                    shard_id: 1,
                    shard_key: None,
                    owner_peer_ids: vec![22, 33],
                },
            ],
        )
        .unwrap();
        let layout_key = PrivateOramLayoutKey { collection_id };
        let layouts = HashMap::from([(
            private_oram_layout_key_digest(&layout_key),
            PrivateOramConsensusLayout {
                generation: 1,
                owner_peer_ids,
                layout_digest,
                index_state_digest,
            },
        )]);
        let empty_epochs = HashMap::new();
        let empty_layouts = HashMap::new();
        let snapshot = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &empty_epochs,
            incoming_layouts: &layouts,
            current_layouts: &empty_layouts,
        };

        assert_eq!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 22,)
                .unwrap(),
            Some(PrivateOramActiveReshardSnapshotAction::AbortForReplicaRecovery),
        );

        incoming.transfers.insert(ShardTransfer {
            shard_id: 1,
            to_shard_id: Some(0),
            from: 22,
            to: 11,
            sync: true,
            method: Some(ShardTransferMethod::ReshardingStreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: None,
            filter: None,
        });
        assert!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 22,)
                .is_err(),
            "an in-flight scale-down transfer source must remain fail closed",
        );

        incoming.transfers.clear();
        incoming.resharding.as_mut().unwrap().stage = ReshardingStage::ReadHashRingCommitted;
        assert!(
            classify_private_oram_active_reshard_snapshot("docs", None, &incoming, snapshot, 22,)
                .is_err(),
            "a committed scale-down endpoint must remain fail closed",
        );
    }

    #[test]
    fn private_oram_snapshot_recovery_marker_is_durable_exact_and_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let key = ReshardState::new(Uuid::new_v4(), ReshardingDirection::Up, 22, 1, None).key();
        write_private_oram_snapshot_recovery_marker(temp.path(), &key).unwrap();
        write_private_oram_snapshot_recovery_marker(temp.path(), &key).unwrap();

        let marker = read_private_oram_snapshot_recovery_marker(temp.path())
            .unwrap()
            .unwrap();
        assert_eq!(marker.resharding_key, key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = fs::metadata(private_oram_snapshot_recovery_marker_path(temp.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }

        let other = ReshardState::new(Uuid::new_v4(), ReshardingDirection::Up, 22, 1, None).key();
        assert!(write_private_oram_snapshot_recovery_marker(temp.path(), &other).is_err());
        remove_private_oram_snapshot_recovery_marker(temp.path()).unwrap();
        assert!(
            read_private_oram_snapshot_recovery_marker(temp.path())
                .unwrap()
                .is_none()
        );

        let marker_path = private_oram_snapshot_recovery_marker_path(temp.path());
        fs::write(&marker_path, b"recovery-marker-secret-sentinel").unwrap();
        let rendered = match read_private_oram_snapshot_recovery_marker(temp.path()) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("malformed private ORAM recovery marker must fail closed"),
        };
        assert!(!rendered.contains("recovery-marker-secret-sentinel"));
    }

    #[cfg(unix)]
    #[test]
    fn private_oram_snapshot_recovery_marker_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside.json");
        fs::write(&outside, b"{}").unwrap();
        symlink(
            &outside,
            private_oram_snapshot_recovery_marker_path(temp.path()),
        )
        .unwrap();
        assert!(read_private_oram_snapshot_recovery_marker(temp.path()).is_err());
    }

    #[test]
    fn private_oram_active_reshard_snapshot_rejects_unmarked_or_regressing_state() {
        let (current, incoming, epochs, layouts) = private_oram_active_snapshot_fixture();
        let context = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &layouts,
        };

        let mut unmarked = incoming.clone();
        unmarked.transfers = unmarked
            .transfers
            .into_iter()
            .map(|transfer| ShardTransfer {
                private_oram_preinstalled: false,
                ..transfer
            })
            .collect();
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &unmarked,
                context,
                33,
            )
            .is_err()
        );

        let mut advanced = incoming.clone();
        advanced.resharding.as_mut().unwrap().stage = ReshardingStage::ReadHashRingCommitted;
        advanced.transfers.clear();
        advanced
            .shards
            .get_mut(&1)
            .unwrap()
            .replicas
            .insert(22, ReplicaState::Active);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&advanced),
                &incoming,
                context,
                33,
            )
            .is_err()
        );

        let mut active_current = incoming.clone();
        active_current
            .shards
            .get_mut(&1)
            .unwrap()
            .replicas
            .insert(22, ReplicaState::Active);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&active_current),
                &incoming,
                context,
                33,
            )
            .is_err()
        );
    }

    #[test]
    fn private_oram_scale_down_snapshot_accepts_only_receiver_resharding_state() {
        let current = State {
            config: private_oram_snapshot_config(2),
            shards: AHashMap::from([
                (
                    0,
                    ShardInfo {
                        replicas: HashMap::from([(11, ReplicaState::Active)]),
                    },
                ),
                (
                    1,
                    ShardInfo {
                        replicas: HashMap::from([(22, ReplicaState::Active)]),
                    },
                ),
            ]),
            resharding: None,
            transfers: HashSet::new(),
            shards_key_mapping: Default::default(),
            payload_index_schema: PayloadIndexSchema::default(),
        };
        let mut incoming = current.clone();
        incoming.resharding = Some(ReshardState::new(
            Uuid::nil(),
            ReshardingDirection::Down,
            22,
            1,
            None,
        ));
        let collection_id = incoming.config.stable_crypto_id("docs").unwrap();
        let keys = private_oram_index_keys_for_config(&incoming.config, "docs").unwrap();
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[13; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[14; 32])),
        };
        let epochs = HashMap::from([(private_oram_epoch_key_digest(&keys[0]), epoch.clone())]);
        let index_state_digest =
            canonical_private_oram_index_state_digest(&collection_id, &[(keys[0].clone(), epoch)])
                .unwrap();
        let entries = [
            PrivateOramShardLayoutEntry {
                shard_id: 0,
                shard_key: None,
                owner_peer_ids: vec![11],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![22],
            },
        ];
        let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
            &collection_id,
            ShardingMethod::Auto,
            &entries,
        )
        .unwrap();
        let layout_key = PrivateOramLayoutKey { collection_id };
        let layouts = HashMap::from([(
            private_oram_layout_key_digest(&layout_key),
            PrivateOramConsensusLayout {
                generation: 1,
                owner_peer_ids,
                layout_digest,
                index_state_digest,
            },
        )]);
        let context = PrivateOramSnapshotState {
            incoming_epochs: &epochs,
            current_epochs: &epochs,
            incoming_layouts: &layouts,
            current_layouts: &layouts,
        };

        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &incoming,
                context,
                33,
            )
            .unwrap()
        );
        let mut committed = incoming.clone();
        committed.resharding.as_mut().unwrap().stage = ReshardingStage::ReadHashRingCommitted;
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&incoming),
                &committed,
                context,
                33,
            )
            .unwrap()
        );

        let mut receiver_transition = incoming.clone();
        receiver_transition
            .shards
            .get_mut(&0)
            .unwrap()
            .replicas
            .insert(11, ReplicaState::ReshardingScaleDown);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &receiver_transition,
                context,
                33,
            )
            .unwrap()
        );

        let mut wrong_target = incoming.clone();
        wrong_target
            .shards
            .get_mut(&1)
            .unwrap()
            .replicas
            .insert(22, ReplicaState::ReshardingScaleDown);
        assert!(
            validate_private_oram_active_reshard_snapshot(
                "docs",
                Some(&current),
                &wrong_target,
                context,
                33,
            )
            .is_err()
        );
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

    fn apply_collections_snapshot_inner(
        &self,
        data: consensus_manager::CollectionsSnapshot,
        private_oram_snapshot: Option<consensus_manager::PrivateOramSnapshotState<'_>>,
    ) -> Result<(), StorageError> {
        self.general_runtime.block_on(async {
            let mut collections = self.collections.write().await;
            let mut validated_private_oram_resharding = HashSet::new();
            let mut private_oram_snapshot_recovery_aborts = HashMap::new();
            for (id, state) in &data.collections {
                if state.resharding.is_none()
                    || private_oram_index_keys_for_config(&state.config, id)?.is_empty()
                {
                    continue;
                }
                let private_oram_snapshot = private_oram_snapshot
                    .ok_or_else(invalid_private_oram_resharding_snapshot)?;
                let current = match collections.get(id) {
                    Some(collection) => Some(collection.state().await),
                    None => None,
                };
                if let Some(action) = classify_private_oram_active_reshard_snapshot(
                    id,
                    current.as_ref(),
                    state,
                    private_oram_snapshot,
                    self.this_peer_id,
                )? {
                    validated_private_oram_resharding.insert(id.clone());
                    if action
                        == PrivateOramActiveReshardSnapshotAction::AbortForReplicaRecovery
                    {
                        private_oram_snapshot_recovery_aborts.insert(
                            id.clone(),
                            state
                                .resharding
                                .as_ref()
                                .expect("validated active private ORAM reshard")
                                .key(),
                        );
                    }
                }
            }

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
                    if let Some(resharding_key) = private_oram_snapshot_recovery_aborts.get(id) {
                        write_private_oram_snapshot_recovery_marker(
                            &collection_path,
                            resharding_key,
                        )?;
                    }
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
                        if validated_private_oram_resharding.contains(id) {
                            collection
                                .apply_validated_private_oram_resharding_snapshot_state(
                                    state.clone(),
                                    self.this_peer_id(),
                                    abort_transfer,
                                )
                                .await?;
                        } else {
                            collection
                                .apply_state(state.clone(), self.this_peer_id(), abort_transfer)
                                .await?;
                        }
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
