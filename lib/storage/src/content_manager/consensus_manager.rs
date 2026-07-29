use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Display;
use std::future::Future;
use std::ops::Deref;
use std::path::Path;
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use chrono::Utc;
use collection::collection_state;
use collection::common::is_ready::IsReady;
use collection::operations::types::PeerMetadata;
use collection::shards::CollectionId;
use collection::shards::shard::PeerId;
use common::defaults;
use futures::future::join_all;
use parking_lot::{Mutex, RwLock};
use raft::eraftpb::{ConfChange, ConfChangeType, ConfChangeV2, Entry as RaftEntry, EntryType};
use raft::{GetEntriesContext, RaftState, RawNode, SoftState, Storage};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::time::error::Elapsed;
use tokio_util::task::AbortOnDropHandle;
use tonic::transport::Uri;

use super::CollectionContainer;
use super::alias_mapping::AliasMapping;
use super::consensus_ops::{
    ConsensusOperations, PrivateOramCollectionLayoutTransition, PrivateOramConsensusEpoch,
    PrivateOramConsensusLayout, PrivateOramEpochKey, PrivateOramExternalRecoveryKey,
    PrivateOramExternalRecoveryState, PrivateOramLayoutKey, PrivateOramLayoutTransitionState,
    PrivateOramReshardingOperation, PrivateOramSessionLease, PrivateOramShardTransferFinish,
    PrivateOramShardTransferStart, SnapshotStatus,
};
use super::errors::StorageError;
use crate::content_manager::consensus::consensus_wal::ConsensusOpWal;
use crate::content_manager::consensus::entry_queue::EntryId;
use crate::content_manager::consensus::operation_sender::OperationSender;
use crate::content_manager::consensus::persistent::Persistent;
use crate::types::{
    ClusterInfo, ClusterStatus, ConsensusThreadStatus, MessageSendErrors, PeerAddressById,
    PeerInfo, PeerMetadataById, RaftInfo,
};

pub mod prelude {
    use crate::content_manager::toc::TableOfContent;

    pub type ConsensusState = super::ConsensusManager<TableOfContent>;
}

/// Allow us updating our peer metadata once every 60 seconds
const CONSENSUS_PEER_METADATA_UPDATE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SnapshotData {
    pub collections_data: CollectionsSnapshot,
    #[serde(with = "crate::serialize_peer_addresses")]
    pub address_by_id: PeerAddressById,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata_by_id: PeerMetadataById,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub cluster_metadata: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_epochs: HashMap<String, PrivateOramConsensusEpoch>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_session_leases: HashMap<String, PrivateOramSessionLease>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_layouts: HashMap<String, PrivateOramConsensusLayout>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub private_oram_external_recoveries: HashMap<String, PrivateOramExternalRecoveryState>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CollectionsSnapshot {
    pub collections: HashMap<CollectionId, collection_state::State>,
    pub aliases: AliasMapping,
}

#[derive(Clone, Copy)]
pub struct PrivateOramSnapshotState<'a> {
    pub incoming_epochs: &'a HashMap<String, PrivateOramConsensusEpoch>,
    pub current_epochs: &'a HashMap<String, PrivateOramConsensusEpoch>,
    pub incoming_layouts: &'a HashMap<String, PrivateOramConsensusLayout>,
    pub current_layouts: &'a HashMap<String, PrivateOramConsensusLayout>,
}

impl TryFrom<&[u8]> for SnapshotData {
    type Error = serde_cbor::Error;

    fn try_from(bytes: &[u8]) -> Result<SnapshotData, Self::Error> {
        serde_cbor::from_slice(bytes)
    }
}

pub struct ConsensusManager<C: CollectionContainer> {
    pub persistent: RwLock<Persistent>,
    /// Notifies if the current node knows who the leader and is not in the process of election
    /// Otherwise the proposals are not accepted
    pub is_leader_established: Arc<IsReady>,
    wal: Mutex<ConsensusOpWal>,
    /// Raft consensus state, which is not saved on disk.
    /// They will change on restart anyway (role + leader id)
    soft_state: RwLock<Option<SoftState>>,
    /// Storage-related container. Should apply and persist changes not related to consensus
    /// (user changes)
    toc: Arc<C>,
    /// Operation apply notifier.
    /// Fires a signal if some specific operation is applied to the state machine.
    /// Signal is changed on change proposal and triggered if the change was applied by consensus on this peer.
    /// Also sends the result of the operation.
    on_consensus_op_apply:
        Mutex<HashMap<ConsensusOperations, broadcast::Sender<Result<bool, StorageError>>>>,
    /// Propose operation to the consensus.
    /// Sends messages to the consensus thread, which is defined externally, outside of the state.
    /// (e.g. in the `src/consensus.rs`)
    propose_sender: OperationSender,
    /// Status of the consensus thread, changed by the consensus thread
    consensus_thread_status: RwLock<ConsensusThreadStatus>,
    /// Consensus thread errors, changed by the consensus thread
    message_send_failures: RwLock<HashMap<String, MessageSendErrors>>,
    /// Local peer metadata proposed to consensus for cluster capability checks.
    current_peer_metadata: PeerMetadata,
    /// Last time we attempted to update the peer metadata
    next_peer_metadata_update_attempt: Mutex<Instant>,
}

impl<C: CollectionContainer> ConsensusManager<C> {
    pub fn new(
        persistent_state: Persistent,
        toc: Arc<C>,
        propose_sender: OperationSender,
        storage_path: &Path,
        current_peer_metadata: PeerMetadata,
    ) -> Result<Self, StorageError> {
        let mut wal = ConsensusOpWal::new(storage_path)?;

        // When our Raft index and last snapshot index match, the last thing we did is apply a Raft
        // snapshot. It is possible that we crashed before clearing the WAL, so we still do it now.
        // Specifically, if the last operation was applying a snapshot and our WAL does still have
        // older Raft entries, we clear the whole WAL. Consensus will take care of us catching up
        // with the rest.
        // See `apply_snapshot` function and <https://github.com/qdrant/qdrant/pull/7577>.
        let raft_index = persistent_state.state().hard_state.commit;
        let snapshot_index = persistent_state.latest_snapshot_meta.index;
        let last_operation_was_snapshot = raft_index == persistent_state.latest_snapshot_meta.index;
        if last_operation_was_snapshot
            && let Ok(Some(last)) = wal.last_entry()
            && last.index < snapshot_index
        {
            log::warn!(
                "Consensus WAL was not cleared after applying consensus snapshot, clearing it now"
            );
            wal.clear()?;
        }

        Ok(Self {
            persistent: RwLock::new(persistent_state),
            is_leader_established: Arc::new(IsReady::default()),
            wal: Mutex::new(wal),
            soft_state: RwLock::new(None),
            toc,
            on_consensus_op_apply: Default::default(),
            propose_sender,
            consensus_thread_status: RwLock::new(ConsensusThreadStatus::Working {
                last_update: Utc::now(),
            }),
            message_send_failures: Default::default(),
            current_peer_metadata,
            next_peer_metadata_update_attempt: Mutex::new(Instant::now()),
        })
    }

    pub fn report_snapshot(
        &self,
        peer_id: u64,
        status: impl Into<SnapshotStatus>,
    ) -> Result<(), StorageError> {
        self.propose_sender
            .send(ConsensusOperations::report_snapshot(peer_id, status))
            .map_err(|_err| {
                StorageError::service_error(
                    "failed to send ReportSnapshot message to consensus thread",
                )
            })
    }

    pub fn record_message_send_failure<E: Error>(&self, peer_address: &Uri, error: E) {
        let mut message_send_failures = self.message_send_failures.write();
        let entry = message_send_failures
            .entry(peer_address.to_string())
            .or_default();
        // Log only first error
        if entry.count == 0 {
            log::warn!("Failed to send message to {peer_address} with error: {error}")
        }
        entry.count += 1;
        entry.latest_error = Some(error.to_string());
        entry.latest_error_timestamp = Some(Utc::now());
    }

    pub fn record_message_send_success(&self, peer_address: &Uri) {
        self.message_send_failures
            .write()
            .remove(&peer_address.to_string());
    }

    pub fn record_consensus_working(&self) {
        *self.consensus_thread_status.write() = ConsensusThreadStatus::Working {
            last_update: Utc::now(),
        }
    }

    pub fn on_consensus_stopped(&self) {
        *self.consensus_thread_status.write() = ConsensusThreadStatus::Stopped
    }

    pub fn on_consensus_thread_err<E: Display>(&self, err: E) {
        *self.consensus_thread_status.write() = ConsensusThreadStatus::StoppedWithErr {
            err: err.to_string(),
        }
    }

    pub fn set_raft_soft_state(&self, state: &SoftState) {
        *self.soft_state.write() = Some(SoftState { ..*state });
    }

    pub fn this_peer_id(&self) -> PeerId {
        self.persistent.read().this_peer_id
    }

    pub fn peers(&self) -> Vec<PeerId> {
        self.persistent
            .read()
            .peer_address_by_id()
            .keys()
            .copied()
            .collect()
    }

    pub fn first_voter(&self) -> PeerId {
        let state = self.persistent.read();

        match state.first_voter() {
            Some(peer_id) if peer_id != PeerId::MAX => peer_id,
            _ => state.this_peer_id(),
        }
    }

    pub fn set_first_voter(&self, id: PeerId) -> Result<(), StorageError> {
        self.persistent.write().set_first_voter(id)
    }

    pub fn recover_first_voter(&self) -> Result<(), StorageError> {
        if self.persistent.read().first_voter().is_none() {
            log::debug!("Recovering first voter peer...");

            let wal = self.wal.lock();
            let peers = self.peers();

            if let Some(peer_id) = recover_first_voter(&wal, &peers)? {
                log::debug!("Recovered first voter peer {peer_id}");
                self.set_first_voter(peer_id)?;
            }
        }

        Ok(())
    }

    /// Report aggregated information about the cluster.
    /// Useful for API reporting.
    pub fn cluster_status(&self) -> ClusterStatus {
        let persistent = self.persistent.read();
        let hard_state = &persistent.state.hard_state;
        let peers = persistent
            .peer_address_by_id()
            .into_iter()
            .map(|(peer_id, uri)| {
                (
                    peer_id,
                    PeerInfo {
                        uri: uri.to_string(),
                    },
                )
            })
            .collect();
        let pending_operations = persistent.unapplied_entities_count();
        let soft_state = self.soft_state.read();
        let leader = soft_state.as_ref().map(|state| state.leader_id);
        let role = soft_state.as_ref().map(|state| state.raft_state.into());
        let peer_id = persistent.this_peer_id;
        let is_voter = persistent.state.conf_state.get_voters().contains(&peer_id);
        ClusterStatus::Enabled(ClusterInfo {
            peer_id,
            peers,
            raft_info: RaftInfo {
                term: hard_state.term,
                commit: hard_state.commit,
                pending_operations,
                leader,
                role,
                is_voter,
            },
            consensus_thread_status: self.consensus_thread_status.read().clone(),
            message_send_failures: self.message_send_failures.read().clone(),
        })
    }

    /// Handle peer removal operation.
    ///
    /// 1. Try to remove peer
    /// 2. Handle peer removal error
    /// 3. Report to the listeners
    ///
    /// Return if consensus should be stopped.
    pub fn on_peer_remove(&self, peer_id: PeerId) -> Result<bool, StorageError> {
        let mut stop_consensus: bool = false;

        let report = match self.remove_peer(peer_id) {
            Ok(()) => {
                if self.this_peer_id() == peer_id {
                    stop_consensus = true;
                }
                Ok(true)
            }
            Err(err) => match err {
                err @ StorageError::ServiceError { .. } => {
                    return Err(err);
                }
                _ => Err(err),
            },
        };
        let operation = ConsensusOperations::RemovePeer(peer_id);
        let on_apply = self.on_consensus_op_apply.lock().remove(&operation);
        if let Some(on_apply) = on_apply
            && on_apply.send(report).is_err()
        {
            log::warn!(
                "Failed to notify on consensus operation completion: channel receiver is dropped",
            )
        }
        Ok(stop_consensus)
    }

    pub fn set_unapplied_entries(
        &self,
        first_index: EntryId,
        last_index: EntryId,
    ) -> Result<(), raft::Error> {
        self.persistent
            .write()
            .set_unapplied_entries(first_index, last_index)
            .map_err(raft_error_other)
    }

    /// Process the consensus operation, which are already committed.
    /// If return Error - consensus should be stopped with error.
    /// Return `true` if consensus should be stopped (peer removed)
    /// Return `false` if everything is ok.
    pub fn apply_entries<T: Storage>(&self, raw_node: &mut RawNode<T>) -> anyhow::Result<bool> {
        use raft::eraftpb::EntryType;

        self.persistent
            .write()
            .save_if_dirty()
            .context("Failed to save new state of applied entries queue")?;

        loop {
            let unapplied_index = self.persistent.read().current_unapplied_entry();
            let Some(entry_index) = unapplied_index else {
                break;
            };
            log::debug!("Applying committed entry with index {entry_index}");
            let entry = self
                .wal
                .lock()
                .entry(entry_index)
                .context(format!("Failed to get entry at index {entry_index}"))?;
            let stop_consensus: bool = if entry.data.is_empty() {
                // Empty entry, when the peer becomes Leader it will send an empty entry.
                false
            } else {
                match entry.get_entry_type() {
                    EntryType::EntryNormal => {
                        let operation_result = self.apply_normal_entry(&entry);
                        match operation_result {
                            Ok(result) => {
                                log::debug!(
                                    "Successfully applied consensus operation entry. Index: {}. Result: {result}",
                                    entry.index,
                                );
                                false
                            }
                            Err(err @ StorageError::ServiceError { .. }) => {
                                // This is a service error - stop consensus. Peer can be restarted when the problem is fixed.
                                return Err(err)
                                    .context("Failed to apply collection meta operation entry");
                            }
                            Err(err) => {
                                log::warn!(
                                    "Failed to apply collection meta operation entry with user error: {err}",
                                );
                                // This is a user error so we can safely consider it applied but with error as it was incorrect.
                                false
                            }
                        }
                    }
                    EntryType::EntryConfChangeV2 => {
                        let stop_consensus = self
                            .apply_conf_change_entry(&entry, raw_node)
                            .context("Failed to apply configuration change entry")?;
                        log::debug!(
                            "Successfully applied configuration change entry. Index: {}. Stop consensus: {}",
                            entry.index,
                            stop_consensus
                        );
                        stop_consensus
                    }
                    ty @ EntryType::EntryConfChange => {
                        return Err(anyhow!("Unexpected entry type: {ty:?}"));
                    }
                }
            };
            if stop_consensus {
                return Ok(stop_consensus);
            }
            self.persistent
                .write()
                .entry_applied()
                .context("Failed to save new state of applied entries queue")?;
        }
        Ok(false) // do not stop consensus
    }

    /// Process the consensus operation, which are already committed.
    /// In this particular function - operations related to the cluster topology change:
    ///
    /// - AddPeer (different states)
    /// - RemovePeer
    pub fn apply_conf_change_entry<T: Storage>(
        &self,
        entry: &RaftEntry,
        raw_node: &mut RawNode<T>,
    ) -> Result<bool, StorageError> {
        let change: ConfChangeV2 = prost_for_raft::Message::decode(entry.get_data())?;

        let conf_state = raw_node.apply_conf_change(&change)?;
        log::debug!("Applied conf state {conf_state:?}");
        self.persistent
            .write()
            .apply_state_update(|state| state.conf_state = conf_state)?;

        let mut stop_consensus: bool = false;
        for single_change in &change.changes {
            match single_change.change_type() {
                ConfChangeType::AddNode => {
                    let context = entry.get_context();

                    if !context.is_empty() {
                        let peer_uri = str::from_utf8(context)
                            .map_err(|err| {
                                StorageError::service_error(format!(
                                    "failed to parse peer URI: {err}"
                                ))
                            })?
                            .parse()
                            .map_err(|err| {
                                StorageError::service_error(format!(
                                    "failed to parse peer URI: {err}"
                                ))
                            })?;

                        self.add_peer(single_change.node_id, peer_uri)?;
                    } else {
                        debug_assert!(
                            self.peer_address_by_id()
                                .contains_key(&single_change.node_id),
                            "Peer should be already known"
                        )
                    }
                }
                ConfChangeType::RemoveNode => {
                    log::debug!("Removing node {}", single_change.node_id);
                    stop_consensus |= self.on_peer_remove(single_change.node_id)?;
                }
                ConfChangeType::AddLearnerNode => {
                    log::debug!("Adding learner node {}", single_change.node_id);
                    if let Ok(peer_uri) = String::from_utf8_lossy(entry.get_context())
                        .deref()
                        .try_into()
                    {
                        let peer_uri: Uri = peer_uri;
                        // Add peer to state
                        self.add_peer(single_change.node_id, peer_uri.clone())?;

                        // Notify the submitter, that operation was performed
                        {
                            let operation = ConsensusOperations::AddPeer {
                                peer_id: single_change.node_id,
                                uri: peer_uri.to_string(),
                            };
                            let on_apply = self.on_consensus_op_apply.lock().remove(&operation);
                            if let Some(on_apply) = on_apply
                                && on_apply.send(Ok(true)).is_err()
                            {
                                log::warn!(
                                    "Failed to notify on consensus operation completion: channel receiver is dropped",
                                )
                            }
                        }
                    } else if entry.get_context().is_empty() {
                        // Allow empty context for compatibility
                        log::warn!(
                            "Outdated peer addition entry found with index: {}",
                            entry.get_index()
                        )
                    } else {
                        // Should not be reachable as it is checked in API
                        return Err(StorageError::service_error("Failed to parse peer uri"));
                    }
                }
            }
        }
        Ok(stop_consensus)
    }

    /// Process the consensus operation, which are already committed.
    /// In this particular function - operations related to user data:
    ///
    /// - CreateCollection
    /// - DropCollection
    /// - Update collection params
    /// - Update collection aliases
    /// - Shards operations (transfer, remove, sync)
    /// - e.t.c
    ///
    pub fn apply_normal_entry(&self, entry: &RaftEntry) -> Result<bool, StorageError> {
        let operation: ConsensusOperations = entry.try_into()?;
        let on_apply = self.on_consensus_op_apply.lock().remove(&operation);
        let result = match operation {
            ConsensusOperations::CollectionMeta(operation) => {
                self.toc.perform_collection_meta_op(*operation)
            }

            ConsensusOperations::AddPeer { .. } | ConsensusOperations::RemovePeer(_) => {
                // RemovePeer or AddPeer should be converted into native ConfChangeV2 message before sending to the Raft.
                // So we do not expect to receive these operations as a normal entry.
                // This is a debug assert so production migrations should be ok.
                // TODO: parse into CollectionMetaOperation as we will not handle other cases here, but this removes compatibility with previous entry storage
                debug_assert!(
                    false,
                    "Do not expect RemovePeer or AddPeer to be directly proposed"
                );
                Ok(false)
            }

            ConsensusOperations::UpdatePeerMetadata { peer_id, metadata } => self
                .persistent
                .write()
                .update_peer_metadata(peer_id, metadata)
                .map(|()| true),

            ConsensusOperations::UpdateClusterMetadata { key, value } => {
                self.persistent
                    .write()
                    .update_cluster_metadata_key(key, value);
                Ok(true)
            }

            ConsensusOperations::CompareAndSwapPrivateOramEpoch(operation) => self
                .persistent
                .write()
                .compare_and_swap_private_oram_epoch(&operation)
                .map(|()| true),
            ConsensusOperations::CompareAndSwapPrivateOramSessionLease(operation) => self
                .persistent
                .write()
                .compare_and_swap_private_oram_session_lease(&operation)
                .map(|()| true),
            ConsensusOperations::ApplyPrivateOramExternalRecovery(operation) => self
                .persistent
                .write()
                .apply_private_oram_external_recovery(&operation)
                .map(|()| true),
            ConsensusOperations::CompareAndSwapPrivateOramLayout(operation) => self
                .persistent
                .write()
                .compare_and_swap_private_oram_layout(&operation)
                .map(|()| true),
            ConsensusOperations::ApplyPrivateOramCollectionLayout(operation) => {
                self.apply_private_oram_collection_layout_transition(&operation)
            }
            ConsensusOperations::StartPrivateOramShardTransfer(operation) => {
                self.apply_private_oram_shard_transfer_start(&operation)
            }
            ConsensusOperations::FinishPrivateOramShardTransfer(operation) => {
                self.apply_private_oram_shard_transfer_finish(&operation)
            }
            ConsensusOperations::StartPrivateOramResharding(operation) => {
                self.apply_private_oram_resharding_start(&operation)
            }
            ConsensusOperations::FinishPrivateOramResharding(operation) => {
                self.apply_private_oram_resharding_finish(&operation)
            }

            ConsensusOperations::RequestSnapshot | ConsensusOperations::ReportSnapshot { .. } => {
                Err(StorageError::service_error(
                    "snapshot consensus operation cannot be applied as a normal Raft entry",
                ))
            }
        };

        if let Some(on_apply) = on_apply
            && on_apply.send(result.clone()).is_err()
        {
            log::warn!(
                "Failed to notify on consensus operation completion: channel receiver is dropped",
            )
        }
        result
    }

    fn apply_private_oram_collection_layout_transition(
        &self,
        transition: &PrivateOramCollectionLayoutTransition,
    ) -> Result<bool, StorageError> {
        let topology_state = self.toc.private_oram_layout_transition_state(transition)?;
        self.persistent
            .read()
            .validate_private_oram_collection_layout_transition(transition)?;
        self.persistent
            .write()
            .compare_and_swap_private_oram_layout(&transition.layout)?;

        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self
                .toc
                .perform_private_oram_collection_layout_meta_op(transition);
            if !matches!(apply_result, Ok(true))
                && self.toc.private_oram_layout_transition_state(transition)?
                    != PrivateOramLayoutTransitionState::Applied
            {
                return Err(StorageError::service_error(
                    "private ORAM collection layout transition was not applied",
                ));
            }
        }
        if self.toc.private_oram_layout_transition_state(transition)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM collection layout transition did not reach its committed state",
            ));
        }
        Ok(true)
    }

    fn apply_private_oram_shard_transfer_start(
        &self,
        operation: &PrivateOramShardTransferStart,
    ) -> Result<bool, StorageError> {
        let topology_state = self
            .toc
            .private_oram_shard_transfer_start_state(operation)?;
        let precommitted_recovery = self
            .persistent
            .read()
            .validate_private_oram_shard_transfer_start(operation)?;
        if let Some(layout) = precommitted_recovery {
            self.persistent
                .write()
                .compare_and_swap_private_oram_layout(&layout)?;
        }
        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self
                .toc
                .perform_collection_meta_op((*operation.collection_meta).clone());
            if !matches!(apply_result, Ok(true))
                && self
                    .toc
                    .private_oram_shard_transfer_start_state(operation)?
                    != PrivateOramLayoutTransitionState::Applied
            {
                return Err(StorageError::service_error(
                    "private ORAM shard transfer start was not applied",
                ));
            }
        }
        if self
            .toc
            .private_oram_shard_transfer_start_state(operation)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM shard transfer start did not reach its committed state",
            ));
        }
        Ok(true)
    }

    fn apply_private_oram_shard_transfer_finish(
        &self,
        operation: &PrivateOramShardTransferFinish,
    ) -> Result<bool, StorageError> {
        let topology_state = self
            .toc
            .private_oram_shard_transfer_finish_state(operation)?;
        let layout = self
            .persistent
            .read()
            .validate_private_oram_shard_transfer_finish(operation)?;
        self.persistent
            .write()
            .compare_and_swap_private_oram_layout(&layout)?;
        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self
                .toc
                .perform_collection_meta_op((*operation.collection_meta).clone());
            if !matches!(apply_result, Ok(true))
                && self
                    .toc
                    .private_oram_shard_transfer_finish_state(operation)?
                    != PrivateOramLayoutTransitionState::Applied
            {
                return Err(StorageError::service_error(
                    "private ORAM shard transfer finish was not applied",
                ));
            }
        }
        if self
            .toc
            .private_oram_shard_transfer_finish_state(operation)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM shard transfer finish did not reach its committed state",
            ));
        }
        Ok(true)
    }

    fn apply_private_oram_resharding_start(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<bool, StorageError> {
        let topology_state = self.toc.private_oram_resharding_state(operation)?;
        self.persistent
            .read()
            .validate_private_oram_resharding_operation(operation)?;
        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self.toc.perform_private_oram_resharding_meta_op(operation);
            if !matches!(apply_result, Ok(true))
                && self.toc.private_oram_resharding_state(operation)?
                    != PrivateOramLayoutTransitionState::Applied
            {
                return Err(StorageError::service_error(
                    "private ORAM resharding start was not applied",
                ));
            }
        }
        if self.toc.private_oram_resharding_state(operation)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM resharding start did not reach its committed state",
            ));
        }
        Ok(true)
    }

    fn apply_private_oram_resharding_finish(
        &self,
        operation: &PrivateOramReshardingOperation,
    ) -> Result<bool, StorageError> {
        let topology_state = self.toc.private_oram_resharding_state(operation)?;
        let layout = self
            .persistent
            .read()
            .validate_private_oram_resharding_operation(operation)?;
        self.persistent
            .write()
            .compare_and_swap_private_oram_layout(&layout)?;
        if topology_state == PrivateOramLayoutTransitionState::Pending {
            let apply_result = self.toc.perform_private_oram_resharding_meta_op(operation);
            if !matches!(apply_result, Ok(true))
                && self.toc.private_oram_resharding_state(operation)?
                    != PrivateOramLayoutTransitionState::Applied
            {
                return Err(StorageError::service_error(
                    "private ORAM resharding finish was not applied",
                ));
            }
        }
        if self.toc.private_oram_resharding_state(operation)?
            != PrivateOramLayoutTransitionState::Applied
        {
            return Err(StorageError::service_error(
                "private ORAM resharding finish did not reach its committed state",
            ));
        }
        Ok(true)
    }

    // Outer `Result` is "fatal" error, inner `Result` is "transient"/"local" error.
    pub fn apply_snapshot(
        &self,
        snapshot: &raft::eraftpb::Snapshot,
    ) -> Result<Result<(), StorageError>, StorageError> {
        let meta = snapshot.get_metadata();

        let SnapshotData {
            collections_data,
            address_by_id,
            metadata_by_id,
            cluster_metadata,
            private_oram_epochs,
            private_oram_session_leases,
            private_oram_layouts,
            private_oram_external_recoveries,
        } = snapshot.get_data().try_into()?;

        Persistent::validate_private_oram_snapshot_state(
            &private_oram_epochs,
            &private_oram_session_leases,
            &private_oram_layouts,
            &private_oram_external_recoveries,
        )?;
        let (
            current_private_oram_epochs,
            current_private_oram_layouts,
            current_private_oram_external_recoveries,
        ) = {
            let persistent = self.persistent.read();
            (
                persistent.private_oram_epochs.clone(),
                persistent.private_oram_layouts.clone(),
                persistent.private_oram_external_recoveries.clone(),
            )
        };
        crate::content_manager::consensus::persistent::validate_private_oram_external_recovery_snapshot_transition(
            &current_private_oram_external_recoveries,
            &private_oram_external_recoveries,
        )?;
        self.toc
            .apply_collections_snapshot_with_private_oram_state(
                collections_data,
                PrivateOramSnapshotState {
                    incoming_epochs: &private_oram_epochs,
                    current_epochs: &current_private_oram_epochs,
                    incoming_layouts: &private_oram_layouts,
                    current_layouts: &current_private_oram_layouts,
                },
            )?;
        self.persistent.write().update_from_snapshot(
            meta,
            address_by_id,
            metadata_by_id,
            cluster_metadata,
            private_oram_epochs,
            private_oram_session_leases,
            private_oram_layouts,
            private_oram_external_recoveries,
        )?;

        // Clear now obsolete WAL entries after persisting new Raft state
        // This way we prevent a crash due to an empty WAL if we crash right after clearing it,
        // without bumping the Raft state. If we now crash after persisting the new state but
        // before clearing the WAL, we will clear the WAL on next startup by truncating all entries
        // above our commit.
        self.wal.lock().clear()?;

        Ok(Ok(()))
    }

    pub fn set_hard_state(&self, hard_state: raft::eraftpb::HardState) -> Result<(), StorageError> {
        self.persistent
            .write()
            .apply_state_update(move |state| state.hard_state = hard_state)
    }

    pub fn set_conf_state(&self, conf_state: raft::eraftpb::ConfState) -> Result<(), StorageError> {
        self.persistent
            .write()
            .apply_state_update(move |state| state.conf_state = conf_state)
    }

    /// Check if the consensus have empty operations log
    pub fn is_new_deployment(&self) -> bool {
        self.hard_state().term == 0
    }

    pub fn hard_state(&self) -> raft::eraftpb::HardState {
        self.persistent.read().state().hard_state.clone()
    }

    pub fn conf_state(&self) -> raft::eraftpb::ConfState {
        self.persistent.read().state().conf_state.clone()
    }

    pub fn set_commit_index(&self, index: u64) -> Result<(), StorageError> {
        self.persistent
            .write()
            .apply_state_update(|state| state.hard_state.commit = index)
    }

    pub fn peer_has_shards(&self, peer_id: PeerId) -> bool {
        self.toc
            .collections_snapshot()
            .collections
            .values()
            .flat_map(|state| state.shards.values())
            .flat_map(|shard_info| shard_info.replicas.keys())
            .any(|&id| id == peer_id)
    }

    pub fn add_peer(&self, peer_id: PeerId, uri: Uri) -> Result<(), StorageError> {
        self.persistent.write().insert_peer(peer_id, uri)
    }

    pub fn remove_peer(&self, peer_id: PeerId) -> Result<(), StorageError> {
        // We sincerely apologize for this piece of code.
        // The `id_to_address` is shared between `channel_pool` and `persistent`,
        // plus we need to make additional removing in the `channel_pool`.
        // So we handle `remove_peer` inside the `toc` and persist changes in the `persistent` after that.
        self.toc.remove_peer(peer_id)?;

        let persistent = self.persistent.read();
        persistent.peer_metadata_by_id.write().remove(&peer_id);
        persistent.save()
    }

    async fn await_receiver(
        &self,
        mut receiver: Receiver<Result<bool, StorageError>>,
        wait_timeout: Duration,
        operation: &ConsensusOperations,
    ) -> Result<bool, StorageError> {
        let timeout_res = tokio::time::timeout(wait_timeout, receiver.recv())
            .await
            .map_err(|_: Elapsed| {
                self.on_consensus_op_apply.lock().remove(operation);
                StorageError::service_error(format!(
                    "Waiting for consensus operation commit failed. Timeout set at: {} seconds",
                    wait_timeout.as_secs_f64(),
                ))
            })?;
        // 2 possible errors to forward: channel sender dropped OR operation failed
        timeout_res.map_err(|err| {
            StorageError::service_error(format!("Error occurred while waiting for consensus operation. Channel sender dropped ({err})"))
        })?
    }

    pub fn await_for_multiple_operations(
        &self,
        operations: Vec<ConsensusOperations>,
        wait_timeout: Option<Duration>,
    ) -> impl Future<Output = Result<Result<(), StorageError>, Elapsed>> {
        let mut receivers = vec![];
        for operation in operations {
            // one-shot broadcast channel
            let (sender, mut receiver) = broadcast::channel(1);
            let mut on_apply_lock = self.on_consensus_op_apply.lock();
            // check that the exact same operation is not already in-flight
            match on_apply_lock.get(&operation) {
                Some(existing_sender) => {
                    // subscribe to existing sender for faster feedback
                    receiver = existing_sender.subscribe()
                }
                None => {
                    // insert new sender
                    on_apply_lock.insert(operation, sender);
                }
            };
            receivers.push(receiver);
        }

        async move {
            let await_for_all = join_all(receivers.iter_mut().map(|receiver| receiver.recv()));
            let results = tokio::time::timeout(
                wait_timeout.unwrap_or(defaults::CONSENSUS_META_OP_WAIT),
                await_for_all,
            )
            .await?;
            for result in results {
                match result {
                    Ok(response_res) => match response_res {
                        Ok(_) => {}
                        Err(err) => return Ok(Err(err)),
                    },
                    Err(recv_error) => return Ok(Err(recv_error.into())),
                }
            }
            Ok(Ok(()))
        }
    }

    /// Wait and block until consensus reaches a `term` and actually applies the `commit`.
    ///
    /// # Errors
    ///
    /// Returns an error if we have diverged commit/term for example.
    pub async fn wait_for_consensus_commit(
        &self,
        commit: u64,
        term: u64,
        consensus_tick: Duration,
        timeout: Duration,
    ) -> Result<(), ()> {
        let start = Instant::now();

        // TODO: naive approach with spinlock for waiting on commit/term, find better way
        while start.elapsed() < timeout {
            let (current_commit, current_term) = self.persistent.read().applied_commit_term();

            // Okay if on the same term and have at least the specified commit
            let is_ok = current_term == term && current_commit >= commit;
            if is_ok {
                return Ok(());
            }

            // Fail if on a newer term
            let is_fail = current_term > term;
            if is_fail {
                return Err(());
            }

            tokio::time::sleep(consensus_tick).await
        }

        // Fail on timeout
        Err(())
    }

    /// Send operation to the consensus thread and listen for the result.
    ///
    /// # Arguments
    ///
    /// * `operation` - operation to propose
    /// * `wait_timeout` - How long do we need to wait for the confirmation
    pub async fn propose_consensus_op_with_await(
        &self,
        operation: ConsensusOperations,
        wait_timeout: Option<Duration>,
    ) -> Result<bool, StorageError> {
        let wait_timeout = wait_timeout.unwrap_or(defaults::CONSENSUS_META_OP_WAIT);

        let is_leader_established = self.is_leader_established.clone();

        let await_ready_for_timeout_future =
            AbortOnDropHandle::new(tokio::task::spawn_blocking(move || {
                is_leader_established.await_ready_for_timeout(wait_timeout)
            }));

        let is_leader_established = await_ready_for_timeout_future
            .await
            .map_err(|err| StorageError::service_error(err.to_string()))?;

        if !is_leader_established {
            return Err(StorageError::service_error(format!(
                "Failed to propose operation: leader is not established within {wait_timeout:?}"
            )));
        }

        // one-shot broadcast channel
        let (sender, mut receiver) = broadcast::channel(1);
        {
            // acquire lock to insert new operation to apply
            let mut on_apply_lock = self.on_consensus_op_apply.lock();
            // check that the exact same operation is not already in-flight
            match on_apply_lock.get(&operation) {
                Some(existing_sender) => {
                    // subscribe to existing sender for faster feedback
                    receiver = existing_sender.subscribe()
                }
                None => {
                    // propose operation to consensus thread
                    self.propose_sender.send(operation.clone())?;
                    // insert new sender
                    on_apply_lock.insert(operation.clone(), sender);
                }
            };
        }

        let res = self
            .await_receiver(receiver, wait_timeout, &operation)
            .await?;
        Ok(res)
    }

    pub fn peer_address_by_id(&self) -> PeerAddressById {
        self.persistent.read().peer_address_by_id()
    }

    pub fn private_oram_epoch(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Option<PrivateOramConsensusEpoch> {
        self.persistent.read().private_oram_epoch(key)
    }

    pub fn private_oram_session_lease(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Option<PrivateOramSessionLease> {
        self.persistent.read().private_oram_session_lease(key)
    }

    pub fn private_oram_external_recovery(
        &self,
        key: &PrivateOramExternalRecoveryKey,
    ) -> Option<PrivateOramExternalRecoveryState> {
        self.persistent.read().private_oram_external_recovery(key)
    }

    pub fn private_oram_layout(
        &self,
        key: &PrivateOramLayoutKey,
    ) -> Option<PrivateOramConsensusLayout> {
        self.persistent.read().private_oram_layout(key)
    }

    pub fn peer_count(&self) -> usize {
        self.persistent.read().peer_address_by_id.read().len()
    }

    pub fn append_entries(&self, entries: Vec<RaftEntry>) -> Result<(), StorageError> {
        self.wal.lock().append_entries(entries)
    }

    pub fn last_applied_entry(&self) -> Option<u64> {
        self.persistent.read().last_applied_entry()
    }

    pub fn sync_local_state(&self) -> Result<(), StorageError> {
        self.try_update_peer_metadata();
        self.toc.sync_local_state()
    }

    pub fn clear_wal(&self) -> Result<(), StorageError> {
        self.wal.lock().clear()
    }

    pub fn compact_wal(&self, min_entries_to_compact: u64) -> Result<bool, StorageError> {
        if min_entries_to_compact == 0 {
            return Ok(false);
        }

        let Some(first_entry) = self.wal.lock().first_entry()? else {
            return Ok(false);
        };

        let Some(last_applied_index) = self.persistent.read().last_applied_entry() else {
            return Ok(false);
        };

        debug_assert!(
            first_entry.index <= last_applied_index + 1,
            "Raft WAL is missing {} unapplied entries (last applied index: {}, first WAL entry index: {})",
            first_entry.index - last_applied_index - 1,
            last_applied_index,
            first_entry.index,
        );

        if last_applied_index.saturating_sub(first_entry.index) < min_entries_to_compact {
            return Ok(false);
        }

        self.wal.lock().compact(last_applied_index)?;
        Ok(true)
    }

    /// Try to update our peer metadata if it's outdated
    ///
    /// It rate limits updating to `CONSENSUS_PEER_METADATA_UPDATE_INTERVAL`.
    fn try_update_peer_metadata(&self) {
        // Throttle updates to prevent spamming consensus
        if Instant::now() < *self.next_peer_metadata_update_attempt.lock() {
            return;
        }

        if !self
            .persistent
            .read()
            .is_our_metadata_outdated(&self.current_peer_metadata)
        {
            return;
        }

        log::debug!("Proposing consensus peer metadata update for this peer");
        let result = self
            .propose_sender
            .send(ConsensusOperations::UpdatePeerMetadata {
                peer_id: self.this_peer_id(),
                metadata: self.current_peer_metadata.clone(),
            });
        if let Err(err) = result {
            log::error!("Failed to propose consensus peer metadata update for this peer: {err}");
        }
        *self.next_peer_metadata_update_attempt.lock() =
            Instant::now() + CONSENSUS_PEER_METADATA_UPDATE_INTERVAL;
    }
}

fn recover_first_voter(
    wal: &ConsensusOpWal,
    peers: &[PeerId],
) -> Result<Option<PeerId>, StorageError> {
    let Some(first_entry) = wal.first_entry()? else {
        log::debug!("Skipped recovering first voter peer: WAL is empty");
        return Ok(None);
    };

    let Some(last_entry) = wal.last_entry()? else {
        log::error!(
            "Failed to recover first voter peer: \
             WAL contains first entry, but no last entry"
        );

        return Ok(None);
    };

    if first_entry.index != 1 {
        log::warn!("Failed to recover first voter peer: WAL is truncated");
        return Ok(Some(PeerId::MAX));
    }

    // Try to recover first voter peer from WAL (if it was not removed from cluster yet!):
    // - collect a list of current peers
    // - scroll WAL and *remove* a peer from the list when `AddPeer`/`AddLearnerPeer` operation encountered
    // - if there's exactly one peer left in the list at the end, this peer should be the first voter

    let mut peers: HashSet<_> = peers.iter().copied().collect();

    for index in first_entry.index..last_entry.index + 1 {
        let entry = wal.entry(index)?;

        match entry.get_entry_type() {
            EntryType::EntryConfChangeV2 => {
                let change: ConfChangeV2 = prost_for_raft::Message::decode(entry.get_data())?;

                for change in change.changes {
                    match change.get_change_type() {
                        ConfChangeType::AddNode | ConfChangeType::AddLearnerNode => {
                            peers.remove(&change.get_node_id());
                        }

                        ConfChangeType::RemoveNode => (),
                    }
                }
            }

            EntryType::EntryConfChange => {
                log::warn!(
                    "Encountered deprecated ConfChange message while recovering first voter peer"
                );

                let change: ConfChange = prost_for_raft::Message::decode(entry.get_data())?;

                match change.get_change_type() {
                    ConfChangeType::AddNode | ConfChangeType::AddLearnerNode => {
                        peers.remove(&change.get_node_id());
                    }

                    ConfChangeType::RemoveNode => (),
                }
            }

            EntryType::EntryNormal => (),
        }
    }

    if peers.len() > 1 {
        log::warn!(
            "Failed to recover first voter peer: \
             found multiple peers without ConfChange entry in WAL: \
             {peers:?}"
        );

        return Ok(Some(PeerId::MAX));
    }

    Ok(peers.into_iter().next())
}

/// Implementation of the methods for Raft library to get information from
/// our implementation of the storage.
/// Well tested magic
impl<C: CollectionContainer> Storage for ConsensusManager<C> {
    fn initial_state(&self) -> raft::Result<RaftState> {
        Ok(self.persistent.read().state.clone())
    }

    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        _context: GetEntriesContext,
    ) -> raft::Result<Vec<RaftEntry>> {
        let max_size: Option<_> = max_size.into();
        let first_index = self.first_index()?;
        if low < first_index {
            log::debug!(
                "Requested entries from {low} to {high} are already compacted (first index: {first_index})"
            );
            return Err(raft::Error::Store(raft::StorageError::Compacted));
        }

        log::debug!("Requesting entries from {low} to {high}");

        if high > self.last_index()? + 1 {
            return Err(raft_error_other(std::io::Error::other(format!(
                "index out of bound (last: {}, high: {})",
                self.last_index()? + 1,
                high
            ))));
        }
        self.wal.lock().entries(low, high, max_size)
    }

    fn term(&self, idx: u64) -> raft::Result<u64> {
        let wal_guard = self.wal.lock();
        let persistent = self.persistent.read();
        let snapshot_meta = persistent.latest_snapshot_meta();
        if idx == snapshot_meta.index {
            return Ok(snapshot_meta.term);
        }
        Ok(wal_guard.entry(idx)?.term)
    }

    fn first_index(&self) -> raft::Result<u64> {
        let index = match self.wal.lock().first_entry().map_err(raft_error_other)? {
            Some(entry) => entry.index,
            None => self.persistent.read().latest_snapshot_meta().index + 1,
        };
        Ok(index)
    }

    fn last_index(&self) -> raft::Result<u64> {
        let index = match self.wal.lock().last_entry().map_err(raft_error_other)? {
            Some(entry) => entry.index,
            None => self.persistent.read().latest_snapshot_meta().index,
        };
        Ok(index)
    }

    fn snapshot(&self, request_index: u64, _to: u64) -> raft::Result<raft::eraftpb::Snapshot> {
        let collections_data = self.toc.collections_snapshot();

        // Lock first WAL and then persistent to avoid deadlock
        let wal_guard = self.wal.lock();
        // TODO: Should we lock `persistent` *before* calling `TableOfContent::collections_snapshot`!?
        let persistent = self.persistent.read();

        if persistent.state.hard_state.commit < request_index {
            // TODO: `raft::storage::MemStorage::snapshot` does `snapshot.mut_metadata().index = request_index` in this case... 🤔
            return Err(raft::Error::Store(
                raft::StorageError::SnapshotTemporarilyUnavailable,
            ));
        }

        let data = SnapshotData {
            collections_data,
            address_by_id: persistent.peer_address_by_id(),
            metadata_by_id: persistent.peer_metadata_by_id(),
            cluster_metadata: persistent.cluster_metadata.clone(),
            private_oram_epochs: persistent.private_oram_epochs.clone(),
            private_oram_session_leases: persistent.private_oram_session_leases.clone(),
            private_oram_layouts: persistent.private_oram_layouts.clone(),
            private_oram_external_recoveries: persistent.private_oram_external_recoveries.clone(),
        };

        let raft_state = persistent.state();

        // Index of snapshot is the current *commit* index.
        let index = raft_state.hard_state.commit;

        // Term of snapshot is the term of the entry at current commit index. Not the current term!
        //
        // Last committed entry should either be available in the WAL, or, if current node applied
        // Raft snapshot (and so completely compacted the WAL) and no new entries were committed yet,
        // it should be the term of `latest_snapshot_meta`.
        let term = if index == persistent.latest_snapshot_meta.index {
            persistent.latest_snapshot_meta.term
        } else {
            wal_guard.entry(index)?.term
        };

        let meta = raft::eraftpb::SnapshotMetadata {
            conf_state: Some(raft_state.conf_state.clone()),
            index,
            term,
        };

        let snapshot = raft::eraftpb::Snapshot {
            data: serde_cbor::to_vec(&data).map_err(raft_error_other)?,
            metadata: Some(meta),
        };

        Ok(snapshot)
    }
}

#[derive(Clone)]
pub struct ConsensusStateRef(pub Arc<prelude::ConsensusState>);

impl Deref for ConsensusStateRef {
    type Target = prelude::ConsensusState;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl From<prelude::ConsensusState> for ConsensusStateRef {
    fn from(state: prelude::ConsensusState) -> Self {
        Self(Arc::new(state))
    }
}

impl Storage for ConsensusStateRef {
    fn initial_state(&self) -> raft::Result<RaftState> {
        self.0.initial_state()
    }

    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        context: GetEntriesContext,
    ) -> raft::Result<Vec<RaftEntry>> {
        self.0.entries(low, high, max_size, context)
    }

    fn term(&self, idx: u64) -> raft::Result<u64> {
        self.0.term(idx)
    }

    fn first_index(&self) -> raft::Result<EntryId> {
        self.0.first_index()
    }

    fn last_index(&self) -> raft::Result<EntryId> {
        self.0.last_index()
    }

    fn snapshot(&self, request_index: u64, to: u64) -> raft::Result<raft::eraftpb::Snapshot> {
        self.0.snapshot(request_index, to)
    }
}

pub fn raft_error_other(e: impl std::error::Error) -> raft::Error {
    #[derive(thiserror::Error, Debug)]
    #[error("{0}")]
    struct StrError(String);

    raft::Error::Store(raft::StorageError::Other(Box::new(StrError(e.to_string()))))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};

    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::operations::types::PeerMetadata;
    use collection::shards::resharding::ReshardKey;
    use collection::shards::shard::PeerId;
    use collection::shards::transfer::{
        PrivateOramTransferIndexKind, PrivateOramTransferIndexState,
        PrivateOramTransferLayoutState, PrivateOramTransferLayoutTransition, ShardTransfer,
        ShardTransferMethod,
    };
    use data_encoding::BASE64URL_NOPAD;
    use proptest::prelude::*;
    use raft::eraftpb::{
        ConfChange, ConfChangeSingle, ConfChangeType, ConfChangeV2, Entry, EntryType,
    };
    use raft::storage::{MemStorage, Storage};
    use tempfile::Builder;
    use uuid::Uuid;

    use super::{ConsensusManager, SnapshotData};
    use crate::content_manager::CollectionContainer;
    use crate::content_manager::consensus::consensus_wal::ConsensusOpWal;
    use crate::content_manager::consensus::entry_queue::EntryApplyProgressQueue;
    use crate::content_manager::consensus::operation_sender::OperationSender;
    use crate::content_manager::consensus::persistent::Persistent;
    use crate::content_manager::consensus_ops::{
        CompareAndSwapPrivateOramEpoch, CompareAndSwapPrivateOramExternalRecovery,
        CompareAndSwapPrivateOramLayout, CompareAndSwapPrivateOramSessionLease,
        ConsensusOperations, PrivateOramCollectionLayoutTransition, PrivateOramConsensusEpoch,
        PrivateOramConsensusLayout, PrivateOramEpochKey, PrivateOramExternalRecoveryKey,
        PrivateOramExternalRecoveryLease, PrivateOramExternalRecoveryOperation,
        PrivateOramExternalRecoveryPhase, PrivateOramExternalRecoveryState, PrivateOramIndexKind,
        PrivateOramLayoutIndexStateBinding, PrivateOramLayoutKey, PrivateOramLayoutLeaseBinding,
        PrivateOramLayoutTransitionState, PrivateOramReshardingLayoutTransition,
        PrivateOramReshardingOperation, PrivateOramSessionLease, PrivateOramShardTransferFinish,
        PrivateOramShardTransferStart, canonical_private_oram_index_state_digest,
    };

    #[test]
    fn update_is_applied() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let mut state = Persistent::load_or_init(dir.path(), false, false, None).unwrap();
        assert_eq!(state.state().hard_state.commit, 0);
        state
            .apply_state_update(|state| state.hard_state.commit = 1)
            .unwrap();
        assert_eq!(state.state().hard_state.commit, 1);
    }

    #[test]
    fn save_failure() {
        let mut state = Persistent {
            path: "./unexistent_dir/file".into(),
            ..Default::default()
        };
        assert!(
            state
                .apply_state_update(|state| { state.hard_state.commit = 1 })
                .is_err(),
        );
    }

    #[test]
    fn state_is_loaded() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let mut state = Persistent::load_or_init(dir.path(), false, false, None).unwrap();
        state
            .apply_state_update(|state| state.hard_state.commit = 1)
            .unwrap();
        assert_eq!(state.state().hard_state.commit, 1);

        let state_loaded = Persistent::load_or_init(dir.path(), false, false, None).unwrap();
        assert_eq!(state_loaded.state().hard_state.commit, 1);
    }

    #[test]
    fn default_peer_id_is_persisted() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let peer_id = Some(101);
        let state = Persistent::load_or_init(dir.path(), false, false, peer_id).unwrap();
        assert_eq!(state.this_peer_id, 101);

        let state_loaded = Persistent::load_or_init(dir.path(), false, false, None).unwrap();
        assert_eq!(state_loaded.this_peer_id, 101);
    }

    #[test]
    fn unapplied_entries() {
        let mut entries = EntryApplyProgressQueue::new(0, 2);
        assert_eq!(entries.current(), Some(0));
        assert_eq!(entries.len(), 3);
        entries.applied();
        assert_eq!(entries.current(), Some(1));
        assert_eq!(entries.len(), 2);
        entries.applied();
        assert_eq!(entries.current(), Some(2));
        assert_eq!(entries.len(), 1);
        entries.applied();
        assert_eq!(entries.current(), None);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn correct_entry_with_offset() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let mut wal = ConsensusOpWal::new(dir.path()).unwrap();
        wal.append_entries(vec![Entry {
            index: 4,
            ..Default::default()
        }])
        .unwrap();
        wal.append_entries(vec![Entry {
            index: 5,
            ..Default::default()
        }])
        .unwrap();
        wal.append_entries(vec![Entry {
            index: 6,
            ..Default::default()
        }])
        .unwrap();
        assert_eq!(wal.entry(5).unwrap().index, 5)
    }

    #[test]
    fn at_least_1_entry() {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let mut wal = ConsensusOpWal::new(dir.path()).unwrap();
        wal.append_entries(vec![
            Entry {
                index: 4,
                ..Default::default()
            },
            Entry {
                index: 5,
                ..Default::default()
            },
        ])
        .unwrap();
        // Even when `max_size` is `0` this fn should return at least 1 entry
        assert_eq!(wal.entries(4, 5, Some(0)).unwrap().len(), 1)
    }

    #[derive(Default)]
    struct NoCollections {
        snapshot_apply_count: AtomicUsize,
    }

    impl CollectionContainer for NoCollections {
        fn perform_collection_meta_op(
            &self,
            _operation: crate::content_manager::collection_meta_ops::CollectionMetaOperations,
        ) -> Result<bool, crate::content_manager::errors::StorageError> {
            Ok(true)
        }

        fn private_oram_layout_transition_state(
            &self,
            _transition: &crate::content_manager::consensus_ops::PrivateOramCollectionLayoutTransition,
        ) -> Result<
            crate::content_manager::consensus_ops::PrivateOramLayoutTransitionState,
            crate::content_manager::errors::StorageError,
        > {
            Err(crate::content_manager::errors::StorageError::service_error(
                "private ORAM collection layout transitions require a collection container",
            ))
        }

        fn private_oram_shard_transfer_start_state(
            &self,
            _operation: &crate::content_manager::consensus_ops::PrivateOramShardTransferStart,
        ) -> Result<
            crate::content_manager::consensus_ops::PrivateOramLayoutTransitionState,
            crate::content_manager::errors::StorageError,
        > {
            Err(crate::content_manager::errors::StorageError::service_error(
                "private ORAM shard transfers require a collection container",
            ))
        }

        fn private_oram_shard_transfer_finish_state(
            &self,
            _operation: &crate::content_manager::consensus_ops::PrivateOramShardTransferFinish,
        ) -> Result<
            crate::content_manager::consensus_ops::PrivateOramLayoutTransitionState,
            crate::content_manager::errors::StorageError,
        > {
            Err(crate::content_manager::errors::StorageError::service_error(
                "private ORAM shard transfers require a collection container",
            ))
        }

        fn private_oram_resharding_state(
            &self,
            _operation: &crate::content_manager::consensus_ops::PrivateOramReshardingOperation,
        ) -> Result<
            crate::content_manager::consensus_ops::PrivateOramLayoutTransitionState,
            crate::content_manager::errors::StorageError,
        > {
            Err(crate::content_manager::errors::StorageError::service_error(
                "private ORAM resharding requires a collection container",
            ))
        }

        fn collections_snapshot(&self) -> super::CollectionsSnapshot {
            super::CollectionsSnapshot::default()
        }

        fn apply_collections_snapshot(
            &self,
            _data: super::CollectionsSnapshot,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            self.snapshot_apply_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn remove_peer(
            &self,
            _peer_id: PeerId,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn sync_local_state(&self) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }
    }

    struct LayoutTransitionCollections {
        state: AtomicU8,
        apply_count: AtomicUsize,
        fail_after_apply: bool,
    }

    impl LayoutTransitionCollections {
        fn new(fail_after_apply: bool) -> Self {
            Self {
                state: AtomicU8::new(0),
                apply_count: AtomicUsize::new(0),
                fail_after_apply,
            }
        }
    }

    impl CollectionContainer for LayoutTransitionCollections {
        fn perform_collection_meta_op(
            &self,
            operation: crate::content_manager::collection_meta_ops::CollectionMetaOperations,
        ) -> Result<bool, crate::content_manager::errors::StorageError> {
            assert!(matches!(
                operation,
                crate::content_manager::collection_meta_ops::CollectionMetaOperations::Nop {
                    token: 7
                }
            ));
            self.apply_count.fetch_add(1, Ordering::SeqCst);
            self.state.store(1, Ordering::SeqCst);
            if self.fail_after_apply {
                Err(crate::content_manager::errors::StorageError::service_error(
                    "injected post-apply failure",
                ))
            } else {
                Ok(true)
            }
        }

        fn private_oram_layout_transition_state(
            &self,
            _transition: &PrivateOramCollectionLayoutTransition,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Ok(if self.state.load(Ordering::SeqCst) == 0 {
                PrivateOramLayoutTransitionState::Pending
            } else {
                PrivateOramLayoutTransitionState::Applied
            })
        }

        fn private_oram_shard_transfer_start_state(
            &self,
            _operation: &PrivateOramShardTransferStart,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM shard transfer start",
            ))
        }

        fn private_oram_shard_transfer_finish_state(
            &self,
            _operation: &PrivateOramShardTransferFinish,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM shard transfer finish",
            ))
        }

        fn private_oram_resharding_state(
            &self,
            _operation: &PrivateOramReshardingOperation,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM resharding operation",
            ))
        }

        fn collections_snapshot(&self) -> super::CollectionsSnapshot {
            super::CollectionsSnapshot::default()
        }

        fn apply_collections_snapshot(
            &self,
            _data: super::CollectionsSnapshot,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn remove_peer(
            &self,
            _peer_id: PeerId,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn sync_local_state(&self) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }
    }

    struct ShardTransferCollections {
        state: AtomicU8,
        start_apply_count: AtomicUsize,
        finish_apply_count: AtomicUsize,
    }

    impl ShardTransferCollections {
        fn new() -> Self {
            Self {
                state: AtomicU8::new(0),
                start_apply_count: AtomicUsize::new(0),
                finish_apply_count: AtomicUsize::new(0),
            }
        }
    }

    impl CollectionContainer for ShardTransferCollections {
        fn perform_collection_meta_op(
            &self,
            operation: crate::content_manager::collection_meta_ops::CollectionMetaOperations,
        ) -> Result<bool, crate::content_manager::errors::StorageError> {
            use crate::content_manager::collection_meta_ops::{
                CollectionMetaOperations, ShardTransferOperations,
            };

            match operation {
                CollectionMetaOperations::TransferShard(_, ShardTransferOperations::Start(_)) => {
                    assert_eq!(self.state.load(Ordering::SeqCst), 0);
                    self.start_apply_count.fetch_add(1, Ordering::SeqCst);
                    self.state.store(1, Ordering::SeqCst);
                }
                CollectionMetaOperations::TransferShard(_, ShardTransferOperations::Finish(_)) => {
                    assert_eq!(self.state.load(Ordering::SeqCst), 1);
                    self.finish_apply_count.fetch_add(1, Ordering::SeqCst);
                    self.state.store(2, Ordering::SeqCst);
                }
                _ => {
                    return Err(crate::content_manager::errors::StorageError::service_error(
                        "unexpected private ORAM shard transfer operation",
                    ));
                }
            }
            Err(crate::content_manager::errors::StorageError::service_error(
                "injected post-apply failure",
            ))
        }

        fn private_oram_layout_transition_state(
            &self,
            _transition: &PrivateOramCollectionLayoutTransition,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM collection layout transition",
            ))
        }

        fn private_oram_shard_transfer_start_state(
            &self,
            _operation: &PrivateOramShardTransferStart,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            match self.state.load(Ordering::SeqCst) {
                0 => Ok(PrivateOramLayoutTransitionState::Pending),
                1 => Ok(PrivateOramLayoutTransitionState::Applied),
                _ => Err(crate::content_manager::errors::StorageError::service_error(
                    "private ORAM shard transfer start state is invalid",
                )),
            }
        }

        fn private_oram_shard_transfer_finish_state(
            &self,
            _operation: &PrivateOramShardTransferFinish,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            match self.state.load(Ordering::SeqCst) {
                1 => Ok(PrivateOramLayoutTransitionState::Pending),
                2 => Ok(PrivateOramLayoutTransitionState::Applied),
                _ => Err(crate::content_manager::errors::StorageError::service_error(
                    "private ORAM shard transfer finish state is invalid",
                )),
            }
        }

        fn private_oram_resharding_state(
            &self,
            _operation: &PrivateOramReshardingOperation,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM resharding operation",
            ))
        }

        fn collections_snapshot(&self) -> super::CollectionsSnapshot {
            super::CollectionsSnapshot::default()
        }

        fn apply_collections_snapshot(
            &self,
            _data: super::CollectionsSnapshot,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn remove_peer(
            &self,
            _peer_id: PeerId,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn sync_local_state(&self) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }
    }

    struct ReshardingCollections {
        state: AtomicU8,
        start_apply_count: AtomicUsize,
        finish_apply_count: AtomicUsize,
    }

    impl ReshardingCollections {
        fn new() -> Self {
            Self {
                state: AtomicU8::new(0),
                start_apply_count: AtomicUsize::new(0),
                finish_apply_count: AtomicUsize::new(0),
            }
        }
    }

    impl CollectionContainer for ReshardingCollections {
        fn perform_collection_meta_op(
            &self,
            operation: crate::content_manager::collection_meta_ops::CollectionMetaOperations,
        ) -> Result<bool, crate::content_manager::errors::StorageError> {
            use crate::content_manager::collection_meta_ops::{
                CollectionMetaOperations, ReshardingOperation,
            };

            match operation {
                CollectionMetaOperations::Resharding(_, ReshardingOperation::Start(_)) => {
                    assert_eq!(self.state.load(Ordering::SeqCst), 0);
                    self.start_apply_count.fetch_add(1, Ordering::SeqCst);
                    self.state.store(1, Ordering::SeqCst);
                }
                CollectionMetaOperations::Resharding(_, ReshardingOperation::Finish(_)) => {
                    assert_eq!(self.state.load(Ordering::SeqCst), 1);
                    self.finish_apply_count.fetch_add(1, Ordering::SeqCst);
                    self.state.store(2, Ordering::SeqCst);
                }
                _ => {
                    return Err(crate::content_manager::errors::StorageError::service_error(
                        "unexpected private ORAM resharding meta operation",
                    ));
                }
            }
            Err(crate::content_manager::errors::StorageError::service_error(
                "injected post-apply failure",
            ))
        }

        fn private_oram_layout_transition_state(
            &self,
            _transition: &PrivateOramCollectionLayoutTransition,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM collection layout transition",
            ))
        }

        fn private_oram_shard_transfer_start_state(
            &self,
            _operation: &PrivateOramShardTransferStart,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM shard transfer start",
            ))
        }

        fn private_oram_shard_transfer_finish_state(
            &self,
            _operation: &PrivateOramShardTransferFinish,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            Err(crate::content_manager::errors::StorageError::service_error(
                "unexpected private ORAM shard transfer finish",
            ))
        }

        fn private_oram_resharding_state(
            &self,
            operation: &PrivateOramReshardingOperation,
        ) -> Result<PrivateOramLayoutTransitionState, crate::content_manager::errors::StorageError>
        {
            use crate::content_manager::collection_meta_ops::{
                CollectionMetaOperations, ReshardingOperation,
            };

            match (
                operation.collection_meta.as_ref(),
                self.state.load(Ordering::SeqCst),
            ) {
                (CollectionMetaOperations::Resharding(_, ReshardingOperation::Start(_)), 0) => {
                    Ok(PrivateOramLayoutTransitionState::Pending)
                }
                (CollectionMetaOperations::Resharding(_, ReshardingOperation::Start(_)), 1) => {
                    Ok(PrivateOramLayoutTransitionState::Applied)
                }
                (CollectionMetaOperations::Resharding(_, ReshardingOperation::Finish(_)), 1) => {
                    Ok(PrivateOramLayoutTransitionState::Pending)
                }
                (CollectionMetaOperations::Resharding(_, ReshardingOperation::Finish(_)), 2) => {
                    Ok(PrivateOramLayoutTransitionState::Applied)
                }
                _ => Err(crate::content_manager::errors::StorageError::service_error(
                    "private ORAM resharding state is invalid",
                )),
            }
        }

        fn collections_snapshot(&self) -> super::CollectionsSnapshot {
            super::CollectionsSnapshot::default()
        }

        fn apply_collections_snapshot(
            &self,
            _data: super::CollectionsSnapshot,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn remove_peer(
            &self,
            _peer_id: PeerId,
        ) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }

        fn sync_local_state(&self) -> Result<(), crate::content_manager::errors::StorageError> {
            Ok(())
        }
    }

    #[test]
    fn private_oram_collection_layout_transition_applies_layout_before_meta_and_replays() {
        let dir = Builder::new()
            .prefix("private_oram_collection_layout_transition")
            .tempdir()
            .unwrap();
        let collection_id = "collection-uuid-1";
        let epoch_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[43; 32])),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[44; 32]),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.to_string(),
        };
        let current = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[45; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[46; 32]),
        };
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[47; 32]),
            index_state_digest: canonical_private_oram_index_state_digest(
                collection_id,
                &[(epoch_key.clone(), epoch.clone())],
            )
            .unwrap(),
        };
        let transition = PrivateOramCollectionLayoutTransition {
            layout: CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: Some(current.clone()),
                new: next.clone(),
            },
            leases: vec![PrivateOramLayoutLeaseBinding {
                key: epoch_key.clone(),
                lease: lease.clone(),
            }],
            shard_key_change: None,
            collection_meta: Box::new(
                crate::content_manager::collection_meta_ops::CollectionMetaOperations::Nop {
                    token: 7,
                },
            ),
        };
        let entry = Entry {
            data: serde_cbor::to_vec(&ConsensusOperations::ApplyPrivateOramCollectionLayout(
                transition,
            ))
            .unwrap(),
            ..Default::default()
        };

        let mut persistent = Persistent::load_or_init(dir.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: epoch_key.clone(),
                expected: None,
                new: epoch,
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: epoch_key,
                expected: None,
                new: Some(lease),
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: None,
                new: current,
            })
            .unwrap();
        let collections = Arc::new(LayoutTransitionCollections::new(true));
        let (sender, _) = mpsc::channel();
        let manager = ConsensusManager::new(
            persistent,
            collections.clone(),
            OperationSender::new(sender),
            dir.path(),
            PeerMetadata::current(),
        )
        .unwrap();

        assert!(manager.apply_normal_entry(&entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next.clone()));
        assert_eq!(collections.apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next));
        assert_eq!(collections.apply_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn private_oram_shard_transfer_start_and_finish_replay_after_post_apply_failures() {
        use crate::content_manager::collection_meta_ops::{
            CollectionMetaOperations, ShardTransferOperations,
        };

        let dir = Builder::new()
            .prefix("private_oram_shard_transfer_transition")
            .tempdir()
            .unwrap();
        let collection_id = "collection-uuid-1";
        let epoch_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[41; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[42; 32])),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[43; 32]),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.to_string(),
        };
        let index_state_digest = canonical_private_oram_index_state_digest(
            collection_id,
            &[(epoch_key.clone(), epoch.clone())],
        )
        .unwrap();
        let current = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[44; 32]),
            index_state_digest: index_state_digest.clone(),
        };
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[46; 32]),
            index_state_digest,
        };
        let transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 7,
            to: 9,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: Some(PrivateOramTransferLayoutTransition {
                collection_id: collection_id.to_string(),
                expected: PrivateOramTransferLayoutState {
                    generation: current.generation,
                    owner_peer_ids: current.owner_peer_ids.clone(),
                    layout_digest: current.layout_digest.clone(),
                    index_state_digest: current.index_state_digest.clone(),
                },
                new: PrivateOramTransferLayoutState {
                    generation: next.generation,
                    owner_peer_ids: next.owner_peer_ids.clone(),
                    layout_digest: next.layout_digest.clone(),
                    index_state_digest: next.index_state_digest.clone(),
                },
                index_states: vec![PrivateOramTransferIndexState {
                    index_kind: PrivateOramTransferIndexKind::Hnsw,
                    index_name: epoch_key.index_name.clone(),
                    index_epoch: epoch.index_epoch,
                    root_hash: epoch.root_hash.clone(),
                    writeback_digest: epoch.writeback_digest.clone(),
                }],
            }),
            filter: None,
        };
        let start = PrivateOramShardTransferStart {
            leases: vec![PrivateOramLayoutLeaseBinding {
                key: epoch_key.clone(),
                lease: lease.clone(),
            }],
            collection_meta: Box::new(CollectionMetaOperations::TransferShard(
                "docs".to_string(),
                ShardTransferOperations::Start(transfer.clone()),
            )),
        };
        let finish = PrivateOramShardTransferFinish {
            collection_meta: Box::new(CollectionMetaOperations::TransferShard(
                "docs".to_string(),
                ShardTransferOperations::Finish(transfer),
            )),
        };
        let start_entry = Entry {
            data: serde_cbor::to_vec(&ConsensusOperations::StartPrivateOramShardTransfer(start))
                .unwrap(),
            ..Default::default()
        };
        let finish_entry = Entry {
            data: serde_cbor::to_vec(&ConsensusOperations::FinishPrivateOramShardTransfer(finish))
                .unwrap(),
            ..Default::default()
        };
        let recovery_epoch_key = epoch_key.clone();
        let recovery_epoch = epoch.clone();
        let recovery_lease = lease.clone();
        let precommitted = PrivateOramConsensusLayout {
            generation: current.generation,
            owner_peer_ids: next.owner_peer_ids.clone(),
            layout_digest: next.layout_digest.clone(),
            index_state_digest: next.index_state_digest.clone(),
        };

        let mut persistent = Persistent::load_or_init(dir.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: epoch_key.clone(),
                expected: None,
                new: epoch,
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: epoch_key,
                expected: None,
                new: Some(lease),
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: None,
                new: current.clone(),
            })
            .unwrap();
        let collections = Arc::new(ShardTransferCollections::new());
        let (sender, _) = mpsc::channel();
        let manager = ConsensusManager::new(
            persistent,
            collections.clone(),
            OperationSender::new(sender),
            dir.path(),
            PeerMetadata::current(),
        )
        .unwrap();

        assert!(manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(current));
        assert_eq!(collections.start_apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(collections.start_apply_count.load(Ordering::SeqCst), 1);

        assert!(manager.apply_normal_entry(&finish_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next.clone()));
        assert_eq!(collections.finish_apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&finish_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next.clone()));
        assert_eq!(collections.finish_apply_count.load(Ordering::SeqCst), 1);

        let recovery_dir = Builder::new()
            .prefix("private_oram_precommitted_recovery_transition")
            .tempdir()
            .unwrap();
        let mut recovery_persistent =
            Persistent::load_or_init(recovery_dir.path(), true, false, Some(7)).unwrap();
        recovery_persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: recovery_epoch_key.clone(),
                expected: None,
                new: recovery_epoch,
            })
            .unwrap();
        recovery_persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: recovery_epoch_key,
                expected: None,
                new: Some(recovery_lease),
            })
            .unwrap();
        recovery_persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: None,
                new: precommitted,
            })
            .unwrap();
        let recovery_collections = Arc::new(ShardTransferCollections::new());
        let (sender, _) = mpsc::channel();
        let recovery_manager = ConsensusManager::new(
            recovery_persistent,
            recovery_collections.clone(),
            OperationSender::new(sender),
            recovery_dir.path(),
            PeerMetadata::current(),
        )
        .unwrap();

        assert!(recovery_manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(
            recovery_manager.private_oram_layout(&layout_key),
            Some(next.clone()),
        );
        assert_eq!(
            recovery_collections
                .start_apply_count
                .load(Ordering::SeqCst),
            1,
        );
        assert!(recovery_manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(
            recovery_manager.private_oram_layout(&layout_key),
            Some(next),
        );
        assert_eq!(
            recovery_collections
                .start_apply_count
                .load(Ordering::SeqCst),
            1,
        );
    }

    #[test]
    fn private_oram_resharding_start_and_finish_replay_after_post_apply_failures() {
        use crate::content_manager::collection_meta_ops::{
            CollectionMetaOperations, ReshardingOperation,
        };

        let dir = Builder::new()
            .prefix("private_oram_resharding_transition")
            .tempdir()
            .unwrap();
        let collection_id = "qdrant-sec-resharding-collection-sentinel";
        let index_name_sentinel = "qdrant-sec-resharding-index-sentinel";
        let root_sentinel = BASE64URL_NOPAD.encode(&[91; 32]);
        let lease_hash_sentinel = BASE64URL_NOPAD.encode(&[92; 32]);
        let epoch_key = PrivateOramEpochKey {
            collection_id: collection_id.to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: index_name_sentinel.to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: root_sentinel.clone(),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[93; 32])),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: lease_hash_sentinel.clone(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let index_state_digest = canonical_private_oram_index_state_digest(
            collection_id,
            &[(epoch_key.clone(), epoch.clone())],
        )
        .unwrap();
        let layout_key = PrivateOramLayoutKey {
            collection_id: collection_id.to_string(),
        };
        let current = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[94; 32]),
            index_state_digest: index_state_digest.clone(),
        };
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[95; 32]),
            index_state_digest,
        };
        let resharding_key = ReshardKey {
            uuid: Uuid::from_u128(31),
            direction: ReshardingDirection::Up,
            peer_id: 9,
            shard_id: 2,
            shard_key: None,
        };
        let transition = PrivateOramReshardingLayoutTransition {
            resharding_key: resharding_key.clone(),
            target_shard_owner_peer_ids: vec![9],
            layout: CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: Some(current.clone()),
                new: next.clone(),
            },
            index_states: vec![PrivateOramLayoutIndexStateBinding {
                key: epoch_key.clone(),
                state: epoch.clone(),
            }],
        };
        let leases = vec![PrivateOramLayoutLeaseBinding {
            key: epoch_key.clone(),
            lease: lease.clone(),
        }];
        let start = PrivateOramReshardingOperation {
            leases: leases.clone(),
            transition: transition.clone(),
            collection_meta: Box::new(CollectionMetaOperations::Resharding(
                "qdrant-sec-resharding-name-sentinel".to_string(),
                ReshardingOperation::Start(resharding_key.clone()),
            )),
        };
        let finish = PrivateOramReshardingOperation {
            leases,
            transition,
            collection_meta: Box::new(CollectionMetaOperations::Resharding(
                "qdrant-sec-resharding-name-sentinel".to_string(),
                ReshardingOperation::Finish(resharding_key),
            )),
        };
        let start_operation = ConsensusOperations::StartPrivateOramResharding(start);
        let finish_operation = ConsensusOperations::FinishPrivateOramResharding(finish);
        for rendered in [
            format!("{start_operation:?}"),
            format!("{:?}", start_operation.redacted_log()),
            format!("{finish_operation:?}"),
            format!("{:?}", finish_operation.redacted_log()),
        ] {
            for sentinel in [
                collection_id,
                index_name_sentinel,
                &root_sentinel,
                &lease_hash_sentinel,
                "qdrant-sec-resharding-name-sentinel",
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }
        let start_entry = Entry {
            data: serde_cbor::to_vec(&start_operation).unwrap(),
            ..Default::default()
        };
        let finish_entry = Entry {
            data: serde_cbor::to_vec(&finish_operation).unwrap(),
            ..Default::default()
        };

        let mut persistent = Persistent::load_or_init(dir.path(), true, false, Some(7)).unwrap();
        persistent
            .compare_and_swap_private_oram_epoch(&CompareAndSwapPrivateOramEpoch {
                key: epoch_key.clone(),
                expected: None,
                new: epoch,
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_session_lease(&CompareAndSwapPrivateOramSessionLease {
                key: epoch_key,
                expected: None,
                new: Some(lease),
            })
            .unwrap();
        persistent
            .compare_and_swap_private_oram_layout(&CompareAndSwapPrivateOramLayout {
                key: layout_key.clone(),
                expected: None,
                new: current.clone(),
            })
            .unwrap();
        let collections = Arc::new(ReshardingCollections::new());
        let (sender, _) = mpsc::channel();
        let manager = ConsensusManager::new(
            persistent,
            collections.clone(),
            OperationSender::new(sender),
            dir.path(),
            PeerMetadata::current(),
        )
        .unwrap();

        assert!(manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(current));
        assert_eq!(collections.start_apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&start_entry).unwrap());
        assert_eq!(collections.start_apply_count.load(Ordering::SeqCst), 1);

        assert!(manager.apply_normal_entry(&finish_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next.clone()));
        assert_eq!(collections.finish_apply_count.load(Ordering::SeqCst), 1);
        assert!(manager.apply_normal_entry(&finish_entry).unwrap());
        assert_eq!(manager.private_oram_layout(&layout_key), Some(next));
        assert_eq!(collections.finish_apply_count.load(Ordering::SeqCst), 1);
    }

    fn setup_storages(
        entries: Vec<Entry>,
        path: &std::path::Path,
    ) -> (ConsensusManager<NoCollections>, MemStorage) {
        let persistent = Persistent::load_or_init(path, true, false, None).unwrap();
        let (sender, _) = mpsc::channel();
        let consensus_state = ConsensusManager::new(
            persistent,
            Arc::new(NoCollections::default()),
            OperationSender::new(sender),
            path,
            PeerMetadata::current(),
        )
        .expect("initialize consensus manager");
        let mem_storage = MemStorage::new();
        mem_storage.wl().append(entries.as_ref()).unwrap();
        consensus_state.append_entries(entries).unwrap();
        (consensus_state, mem_storage)
    }

    #[test]
    fn private_oram_epoch_cas_replays_and_survives_raft_snapshot_restore() {
        let source_dir = Builder::new()
            .prefix("private_oram_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let initial = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            writeback_digest: None,
        };
        let next = PrivateOramConsensusEpoch {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[11; 32])),
        };

        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(
                    key.clone(),
                    None,
                    initial.clone(),
                ))
                .unwrap(),
        );
        assert_eq!(source.private_oram_epoch(&key), Some(initial.clone()));
        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(
                    key.clone(),
                    None,
                    initial.clone(),
                ))
                .unwrap(),
        );

        let stale = source
            .apply_normal_entry(&private_oram_epoch_entry(key.clone(), None, next.clone()))
            .unwrap_err();
        assert!(
            stale
                .to_string()
                .contains("consensus epoch/root CAS precondition failed"),
        );
        assert_eq!(source.private_oram_epoch(&key), Some(initial.clone()));

        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(
                    key.clone(),
                    Some(initial.clone()),
                    next.clone(),
                ))
                .unwrap(),
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(
                    key.clone(),
                    Some(initial.clone()),
                    next.clone(),
                ))
                .unwrap(),
        );

        let conflicting_digest = source
            .apply_normal_entry(&private_oram_epoch_entry(
                key.clone(),
                Some(initial),
                PrivateOramConsensusEpoch {
                    index_epoch: next.index_epoch,
                    root_hash: next.root_hash.clone(),
                    writeback_digest: Some(BASE64URL_NOPAD.encode(&[12; 32])),
                },
            ))
            .unwrap_err();
        assert!(
            conflicting_digest
                .to_string()
                .contains("consensus epoch/root CAS precondition failed"),
        );
        assert_eq!(source.private_oram_epoch(&key), Some(next.clone()));

        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(snapshot_data.private_oram_epochs.len(), 1);

        let target_dir = Builder::new()
            .prefix("private_oram_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(target.private_oram_epoch(&key), Some(next));
    }

    #[test]
    fn private_oram_session_lease_survives_raft_snapshot_restore() {
        let source_dir = Builder::new()
            .prefix("private_oram_lease_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
        let key = PrivateOramEpochKey {
            collection_id: "collection-uuid-1".to_string(),
            index_kind: PrivateOramIndexKind::ResultPayload,
            index_name: String::new(),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[31; 32]),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        assert!(
            source
                .apply_normal_entry(&private_oram_session_lease_entry(
                    key.clone(),
                    None,
                    Some(lease.clone()),
                ))
                .unwrap()
        );
        assert_eq!(source.private_oram_session_lease(&key), Some(lease.clone()));

        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(snapshot_data.private_oram_session_leases.len(), 1);

        let target_dir = Builder::new()
            .prefix("private_oram_lease_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(target.private_oram_session_lease(&key), Some(lease));
    }

    #[test]
    fn private_oram_external_recovery_survives_raft_snapshot_restore() {
        let source_dir = Builder::new()
            .prefix("private_oram_recovery_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
        let key = PrivateOramExternalRecoveryKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let epoch_key = PrivateOramEpochKey {
            collection_id: key.collection_id.clone(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: "text".to_string(),
        };
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[40; 32]),
            writeback_digest: None,
        };
        let index_states = vec![PrivateOramLayoutIndexStateBinding {
            key: epoch_key.clone(),
            state: epoch.clone(),
        }];
        let layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: BASE64URL_NOPAD.encode(&[39; 32]),
            index_state_digest: canonical_private_oram_index_state_digest(
                &key.collection_id,
                &[(epoch_key.clone(), epoch.clone())],
            )
            .unwrap(),
        };
        let checkpoint_digest = BASE64URL_NOPAD.encode(&[41; 32]);
        let acquired = PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            active_lease: Some(PrivateOramExternalRecoveryLease {
                owner_peer_id: 7,
                operation_id_hash: BASE64URL_NOPAD.encode(&[42; 32]),
                checkpoint_digest: checkpoint_digest.clone(),
                backup_generation: 7,
                issued_at_unix: 100,
                expires_at_unix: 160,
            }),
        };
        let committed = PrivateOramExternalRecoveryState {
            committed_backup_generation: 7,
            committed_checkpoint_digest: Some(checkpoint_digest),
            active_lease: None,
        };

        assert!(
            source
                .apply_normal_entry(&private_oram_epoch_entry(epoch_key, None, epoch,))
                .unwrap()
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_layout_entry(
                    PrivateOramLayoutKey {
                        collection_id: key.collection_id.clone(),
                    },
                    None,
                    layout.clone(),
                ))
                .unwrap()
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_external_recovery_entry(
                    PrivateOramExternalRecoveryPhase::Begin,
                    CompareAndSwapPrivateOramExternalRecovery {
                        key: key.clone(),
                        expected: None,
                        new: Some(acquired.clone()),
                    },
                    layout.clone(),
                    index_states.clone(),
                ))
                .unwrap()
        );
        assert!(
            source
                .apply_normal_entry(&private_oram_external_recovery_entry(
                    PrivateOramExternalRecoveryPhase::Commit,
                    CompareAndSwapPrivateOramExternalRecovery {
                        key: key.clone(),
                        expected: Some(acquired),
                        new: Some(committed.clone()),
                    },
                    layout,
                    index_states,
                ))
                .unwrap()
        );

        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(snapshot_data.private_oram_external_recoveries.len(), 1);

        let target_dir = Builder::new()
            .prefix("private_oram_recovery_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(target.private_oram_external_recovery(&key), Some(committed));
    }

    #[test]
    fn private_oram_layout_cas_replays_and_survives_raft_snapshot_restore() {
        let source_dir = Builder::new()
            .prefix("private_oram_layout_raft_source")
            .tempdir()
            .unwrap();
        let (source, _) = setup_storages(Vec::new(), source_dir.path());
        let key = PrivateOramLayoutKey {
            collection_id: "collection-uuid-1".to_string(),
        };
        let initial = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7, 9],
            layout_digest: BASE64URL_NOPAD.encode(&[51; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[52; 32]),
        };
        let next = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: vec![7, 9, 11],
            layout_digest: BASE64URL_NOPAD.encode(&[53; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[54; 32]),
        };

        let initial_entry = private_oram_layout_entry(key.clone(), None, initial.clone());
        assert!(source.apply_normal_entry(&initial_entry).unwrap());
        assert!(source.apply_normal_entry(&initial_entry).unwrap());
        assert_eq!(source.private_oram_layout(&key), Some(initial.clone()));

        let transition_entry = private_oram_layout_entry(key.clone(), Some(initial), next.clone());
        assert!(source.apply_normal_entry(&transition_entry).unwrap());
        assert!(source.apply_normal_entry(&transition_entry).unwrap());

        let snapshot = source.snapshot(0, 0).unwrap();
        let snapshot_data: SnapshotData = snapshot.get_data().try_into().unwrap();
        assert_eq!(snapshot_data.private_oram_layouts.len(), 1);

        let target_dir = Builder::new()
            .prefix("private_oram_layout_raft_target")
            .tempdir()
            .unwrap();
        let (target, _) = setup_storages(Vec::new(), target_dir.path());
        target.apply_snapshot(&snapshot).unwrap().unwrap();
        assert_eq!(target.private_oram_layout(&key), Some(next));
    }

    #[test]
    fn malformed_private_oram_snapshot_maps_fail_before_collection_apply() {
        let valid_digest = BASE64URL_NOPAD.encode(&[61; 32]);
        let epoch = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: valid_digest.clone(),
            writeback_digest: Some(valid_digest.clone()),
        };
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: valid_digest.clone(),
            issued_at_unix: 100,
            expires_at_unix: 160,
        };
        let layout = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: vec![7],
            layout_digest: valid_digest.clone(),
            index_state_digest: valid_digest.clone(),
        };
        let recovery = PrivateOramExternalRecoveryState {
            committed_backup_generation: 1,
            committed_checkpoint_digest: Some(valid_digest),
            active_lease: None,
        };
        let malformed_snapshots = [
            SnapshotData {
                collections_data: Default::default(),
                address_by_id: Default::default(),
                metadata_by_id: Default::default(),
                cluster_metadata: Default::default(),
                private_oram_epochs: std::collections::HashMap::from([(
                    "invalid-epoch-key".to_string(),
                    epoch,
                )]),
                private_oram_session_leases: Default::default(),
                private_oram_layouts: Default::default(),
                private_oram_external_recoveries: Default::default(),
            },
            SnapshotData {
                collections_data: Default::default(),
                address_by_id: Default::default(),
                metadata_by_id: Default::default(),
                cluster_metadata: Default::default(),
                private_oram_epochs: Default::default(),
                private_oram_session_leases: std::collections::HashMap::from([(
                    "invalid-lease-key".to_string(),
                    lease,
                )]),
                private_oram_layouts: Default::default(),
                private_oram_external_recoveries: Default::default(),
            },
            SnapshotData {
                collections_data: Default::default(),
                address_by_id: Default::default(),
                metadata_by_id: Default::default(),
                cluster_metadata: Default::default(),
                private_oram_epochs: Default::default(),
                private_oram_session_leases: Default::default(),
                private_oram_layouts: std::collections::HashMap::from([(
                    "invalid-layout-key".to_string(),
                    layout,
                )]),
                private_oram_external_recoveries: Default::default(),
            },
            SnapshotData {
                collections_data: Default::default(),
                address_by_id: Default::default(),
                metadata_by_id: Default::default(),
                cluster_metadata: Default::default(),
                private_oram_epochs: Default::default(),
                private_oram_session_leases: Default::default(),
                private_oram_layouts: Default::default(),
                private_oram_external_recoveries: std::collections::HashMap::from([(
                    "invalid-recovery-key".to_string(),
                    recovery,
                )]),
            },
        ];

        for (index, snapshot_data) in malformed_snapshots.into_iter().enumerate() {
            let dir = Builder::new()
                .prefix(&format!("malformed_private_oram_snapshot_{index}"))
                .tempdir()
                .unwrap();
            let (target, _) = setup_storages(Vec::new(), dir.path());
            let snapshot = raft::eraftpb::Snapshot {
                data: serde_cbor::to_vec(&snapshot_data).unwrap(),
                metadata: Some(Default::default()),
            };

            let err = target.apply_snapshot(&snapshot).unwrap_err();
            assert!(err.to_string().contains("snapshot is invalid"));
            assert_eq!(target.toc.snapshot_apply_count.load(Ordering::SeqCst), 0);
            let persistent = target.persistent.read();
            assert!(persistent.private_oram_epochs.is_empty());
            assert!(persistent.private_oram_session_leases.is_empty());
            assert!(persistent.private_oram_layouts.is_empty());
            assert!(persistent.private_oram_external_recoveries.is_empty());
        }
    }

    #[test]
    fn raft_snapshot_without_private_oram_epochs_remains_compatible() {
        let snapshot = SnapshotData {
            collections_data: Default::default(),
            address_by_id: Default::default(),
            metadata_by_id: Default::default(),
            cluster_metadata: Default::default(),
            private_oram_epochs: Default::default(),
            private_oram_session_leases: Default::default(),
            private_oram_layouts: Default::default(),
            private_oram_external_recoveries: Default::default(),
        };
        let mut legacy_value = serde_json::to_value(snapshot).unwrap();
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_epochs");
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_session_leases");
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_layouts");
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_external_recoveries");

        let decoded: SnapshotData = serde_json::from_value(legacy_value).unwrap();
        assert!(decoded.private_oram_epochs.is_empty());
        assert!(decoded.private_oram_session_leases.is_empty());
        assert!(decoded.private_oram_layouts.is_empty());
        assert!(decoded.private_oram_external_recoveries.is_empty());
    }

    #[test]
    fn private_oram_epoch_without_writeback_digest_remains_compatible() {
        let legacy_epoch = serde_json::json!({
            "index_epoch": 42,
            "root_hash": BASE64URL_NOPAD.encode(&[42; 32]),
        });

        let decoded: PrivateOramConsensusEpoch = serde_json::from_value(legacy_epoch).unwrap();
        assert_eq!(decoded.writeback_digest, None);
    }

    fn private_oram_epoch_entry(
        key: PrivateOramEpochKey,
        expected: Option<PrivateOramConsensusEpoch>,
        new: PrivateOramConsensusEpoch,
    ) -> Entry {
        let operation =
            ConsensusOperations::CompareAndSwapPrivateOramEpoch(CompareAndSwapPrivateOramEpoch {
                key,
                expected,
                new,
            });
        Entry {
            data: serde_cbor::to_vec(&operation).unwrap(),
            ..Default::default()
        }
    }

    fn private_oram_session_lease_entry(
        key: PrivateOramEpochKey,
        expected: Option<PrivateOramSessionLease>,
        new: Option<PrivateOramSessionLease>,
    ) -> Entry {
        let operation = ConsensusOperations::CompareAndSwapPrivateOramSessionLease(
            CompareAndSwapPrivateOramSessionLease { key, expected, new },
        );
        Entry {
            data: serde_cbor::to_vec(&operation).unwrap(),
            ..Default::default()
        }
    }

    fn private_oram_external_recovery_entry(
        phase: PrivateOramExternalRecoveryPhase,
        recovery: CompareAndSwapPrivateOramExternalRecovery,
        layout: PrivateOramConsensusLayout,
        index_states: Vec<PrivateOramLayoutIndexStateBinding>,
    ) -> Entry {
        let operation = ConsensusOperations::ApplyPrivateOramExternalRecovery(
            PrivateOramExternalRecoveryOperation {
                phase,
                recovery,
                layout,
                index_states,
            },
        );
        Entry {
            data: serde_cbor::to_vec(&operation).unwrap(),
            ..Default::default()
        }
    }

    fn private_oram_layout_entry(
        key: PrivateOramLayoutKey,
        expected: Option<PrivateOramConsensusLayout>,
        new: PrivateOramConsensusLayout,
    ) -> Entry {
        let operation =
            ConsensusOperations::CompareAndSwapPrivateOramLayout(CompareAndSwapPrivateOramLayout {
                key,
                expected,
                new,
            });
        Entry {
            data: serde_cbor::to_vec(&operation).unwrap(),
            ..Default::default()
        }
    }

    prop_compose! {
        fn gen_entries(min_entries: u64, max_entries: u64)(n in min_entries..max_entries, inc_term_every in 1u64..max_entries) -> Vec<Entry> {
            (1..=n).map(|index| Entry {index, term: 1 + index/inc_term_every, ..Default::default()}).collect::<Vec<Entry>>()
        }
    }

    proptest! {
        #[test]
        fn check_first_and_last_indexes(entries in gen_entries(0, 100)) {
            let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
            let (consensus_state, mem_storage) = setup_storages(entries, dir.path());
            prop_assert_eq!(mem_storage.last_index(), consensus_state.last_index());
            prop_assert_eq!(mem_storage.first_index(), consensus_state.first_index());
        }

        #[test]
        fn check_term(entries in gen_entries(0, 100), id in 0u64..100) {
            let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
            let (consensus_state, mem_storage) = setup_storages(entries, dir.path());
            prop_assert_eq!(mem_storage.term(id), consensus_state.term(id))
        }

        #[test]
        fn check_entries(entries in gen_entries(1, 100),
                low in 0u64..100,
                len in 1u64..100,
                max_size in proptest::option::of(proptest::num::u64::ANY)
            ) {
            let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
            let (consensus_state, mem_storage) = setup_storages(entries, dir.path());
            let mut high = low + len;
            let last_index = mem_storage.last_index().unwrap();
            if high > last_index + 1 {
                high = last_index + 1;
            }
            let mut low = low;
            if low > last_index {
                low = last_index;
            }
            let context_1 = raft::storage::GetEntriesContext::empty(false);
            let context_2 = raft::storage::GetEntriesContext::empty(false);
            prop_assert_eq!(mem_storage.entries(low, high, max_size, context_1), consensus_state.entries(low, high, max_size, context_2));
        }
    }

    #[test]
    fn recover_first_voter() {
        let (_dir, wal) = wal(0);
        let peers = vec![1337, 42, 69];
        assert_eq!(
            super::recover_first_voter(&wal, &peers).unwrap(),
            Some(1337)
        );
    }

    #[test]
    fn recover_first_voter_empty() {
        let (_dir, wal) = empty_wal();
        let peers = vec![1337, 42, 69];
        assert_eq!(super::recover_first_voter(&wal, &peers).unwrap(), None);
    }

    #[test]
    fn recover_first_voter_committed() {
        let (_dir, wal) = wal(1);
        let peers = vec![1337, 42, 69];
        assert_eq!(super::recover_first_voter(&wal, &peers).unwrap(), None);
    }

    #[test]
    fn recover_first_voter_truncated() {
        let (_dir, wal) = wal(2);
        let peers = vec![1337, 42, 69];
        assert_eq!(
            super::recover_first_voter(&wal, &peers).unwrap(),
            Some(PeerId::MAX)
        );
    }

    #[test]
    fn recover_first_voter_multiple_peers() {
        let (_dir, wal) = wal(0);
        let peers = vec![1337, 42, 69, 228];
        assert_eq!(
            super::recover_first_voter(&wal, &peers).unwrap(),
            Some(PeerId::MAX)
        );
    }

    fn wal(first_index: u64) -> (tempfile::TempDir, ConsensusOpWal) {
        let (dir, mut wal) = empty_wal();
        wal.append_entries(entries(first_index)).unwrap();
        (dir, wal)
    }

    fn empty_wal() -> (tempfile::TempDir, ConsensusOpWal) {
        let dir = Builder::new().prefix("raft_state_test").tempdir().unwrap();
        let wal = ConsensusOpWal::new(dir.path()).unwrap();
        (dir, wal)
    }

    fn entries(first_index: u64) -> Vec<Entry> {
        use ConfChangeType::*;

        let mut entries = vec![
            conf_change_v2(first_index, &[(AddNode, 1337)]),
            conf_change_v2(
                first_index + 1,
                &[(AddLearnerNode, 42), (AddLearnerNode, 69)],
            ),
            conf_change_v2(first_index + 2, &[(AddNode, 42)]),
            conf_change(first_index + 3, RemoveNode, 228),
            conf_change(first_index + 4, AddLearnerNode, 666),
            conf_change_v2(first_index + 5, &[(AddNode, 69)]),
            conf_change(first_index + 6, AddNode, 666),
        ];

        // Remove first entry if `first_index` is 0, so that second entry would line up with index 1
        if first_index == 0 {
            entries.remove(0);
        }

        entries
    }

    fn conf_change_v2(index: u64, changes: &[(ConfChangeType, PeerId)]) -> Entry {
        let mut conf_change = ConfChangeV2::default();

        for &(change_type, node_id) in changes {
            conf_change.changes.push(ConfChangeSingle {
                change_type: change_type as _,
                node_id,
            });
        }

        Entry {
            index,
            entry_type: EntryType::EntryConfChangeV2 as _,
            data: prost_for_raft::Message::encode_to_vec(&conf_change),
            ..Default::default()
        }
    }

    fn conf_change(index: u64, change_type: ConfChangeType, node_id: PeerId) -> Entry {
        let conf_change = ConfChange {
            change_type: change_type as _,
            node_id,
            ..Default::default()
        };

        Entry {
            index,
            entry_type: EntryType::EntryConfChange as _,
            data: prost_for_raft::Message::encode_to_vec(&conf_change),
            ..Default::default()
        }
    }
}
