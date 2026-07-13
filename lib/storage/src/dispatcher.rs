use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use api::grpc::qdrant::{
    CompletePrivateOramWritebackRequest, InstallPrivateOramIndexRequest,
    PreparePrivateOramWritebackRequest, PrivateOramReplicationBucket,
    PrivateOramReplicationEpochState, PrivateOramReplicationIndexKind,
    PrivateOramReplicationSignature, PrivateOramReplicationTransition,
};
use api::rest::models::HardwareUsage;
use collection::common::fetch_vectors::CollectionName;
use collection::config::ShardingMethod;
use collection::operations::verification::VerificationPass;
use collection::private_hnsw_oram_store::{
    PrivateHnswOramConsensusWriteback, PrivateHnswOramWritebackBatch,
};
use collection::private_result_oram_store::{
    PrivateResultOramConsensusWriteback, PrivateResultOramWritebackBatch,
};
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::shard::PeerId;
use common::counter::hardware_accumulator::HwSharedDrain;
use common::defaults::CONSENSUS_META_OP_WAIT;
use data_encoding::BASE64URL_NOPAD;
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;
use segment::types::ShardKey;

use crate::content_manager::collection_meta_ops::AliasOperations;
use crate::content_manager::consensus_ops::{
    CompareAndSwapPrivateOramEpoch, CompareAndSwapPrivateOramSessionLease,
    PrivateOramConsensusEpoch, PrivateOramEpochKey, PrivateOramIndexKind, PrivateOramSessionLease,
};
use crate::content_manager::shard_distribution::ShardDistributionProposal;
use crate::rbac::{Auth, CollectionMultipass};
use crate::{
    ClusterStatus, CollectionMetaOperations, ConsensusOperations, ConsensusStateRef, StorageError,
    TableOfContent,
};

#[derive(Clone)]
pub struct Dispatcher {
    toc: Arc<TableOfContent>,
    consensus_state: Option<ConsensusStateRef>,
    resharding_enabled: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramReplicaPrepareAck {
    pub peer_id: PeerId,
    pub writeback_digest: String,
}

impl Debug for PrivateOramReplicaPrepareAck {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramReplicaPrepareAck")
            .field("peer_id", &self.peer_id)
            .field("writeback_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateOramRecoveryAction {
    Clean,
    AbortPending,
    FinalizePending,
}

pub struct PrivateOramEpochRef<'a> {
    pub index_epoch: u64,
    pub root_hash: &'a str,
}

pub struct PrivateOramPendingTransitionRef<'a> {
    pub old: PrivateOramEpochRef<'a>,
    pub new: PrivateOramEpochRef<'a>,
    pub writeback_digest: &'a str,
}

impl Dispatcher {
    pub fn new(toc: Arc<TableOfContent>) -> Self {
        Self {
            toc,
            consensus_state: None,
            resharding_enabled: false,
        }
    }

    pub fn with_consensus(self, state_ref: ConsensusStateRef, resharding_enabled: bool) -> Self {
        Self {
            consensus_state: Some(state_ref),
            resharding_enabled,
            ..self
        }
    }

    /// Get the table of content.
    /// The `_auth` and `_verification_pass` parameter are not used, but it's required to verify caller's possession
    /// of both objects.
    pub fn toc(&self, _auth: &Auth, _verification_pass: &VerificationPass) -> &Arc<TableOfContent> {
        &self.toc
    }

    pub fn consensus_state(&self) -> Option<&ConsensusStateRef> {
        self.consensus_state.as_ref()
    }

    pub fn this_peer_id(&self) -> PeerId {
        self.toc.this_peer_id
    }

    pub fn is_resharding_enabled(&self) -> bool {
        self.resharding_enabled
    }

    /// If `wait_timeout` is not supplied - then default duration will be used.
    ///
    /// This function needs to be called from a runtime with timers enabled.
    ///
    /// ## Cancel safety
    ///
    /// This function is cancel safe.
    ///
    /// On deployments without consensus - a submitted operation is always run to completion.
    pub async fn submit_collection_meta_op(
        &self,
        operation: CollectionMetaOperations,
        auth: Auth,
        wait_timeout: Option<Duration>,
    ) -> Result<bool, StorageError> {
        auth.check_collection_meta_operation(&operation)?;

        // if distributed deployment is enabled
        if let Some(state) = self.consensus_state.as_ref() {
            let start = Instant::now();

            // List of operations to await for collection to be operational
            let mut expect_operations: Vec<ConsensusOperations> = vec![];

            let op = match operation {
                CollectionMetaOperations::CreateCollection(mut op) => {
                    if !op.is_distribution_set() {
                        match op.create_collection.sharding_method.unwrap_or_default() {
                            ShardingMethod::Auto => {
                                // Suggest even distribution of shards across nodes
                                let number_of_peers = state.0.peer_count();

                                let collection_defaults =
                                    self.toc.storage_config.collection.as_ref();

                                let shard_distribution = self.toc.suggest_shard_distribution(
                                    &op,
                                    collection_defaults,
                                    number_of_peers,
                                );

                                // Expect all replicas to become active eventually
                                for (shard_id, peer_ids) in &shard_distribution.distribution {
                                    for peer_id in peer_ids {
                                        expect_operations.push(
                                            ConsensusOperations::initialize_replica(
                                                op.collection_name.clone(),
                                                *shard_id,
                                                *peer_id,
                                            ),
                                        );
                                    }
                                }

                                op.set_distribution(shard_distribution);
                            }
                            ShardingMethod::Custom => {
                                // If custom sharding is used - we don't create any shards in advance
                                let empty_distribution = ShardDistributionProposal::empty();
                                op.set_distribution(empty_distribution);
                            }
                        }
                    }

                    if let Some(uuid) = &op.create_collection.uuid {
                        if op.should_preserve_explicit_uuid() {
                            log::info!(
                                "Preserving collection UUID {uuid} for internal create collection {} operation",
                                op.collection_name,
                            );
                        } else {
                            log::warn!(
                                "Collection UUID {uuid} explicitly specified, \
                                 when proposing create collection {} operation, \
                                 new random UUID will be generated instead",
                                op.collection_name,
                            );
                        }
                    }

                    if !op.should_preserve_explicit_uuid() || op.create_collection.uuid.is_none() {
                        op.create_collection.uuid = Some(uuid::Uuid::new_v4());
                    }

                    CollectionMetaOperations::CreateCollection(op)
                }
                CollectionMetaOperations::CreateShardKey(op) => {
                    CollectionMetaOperations::CreateShardKey(op)
                }

                op => op,
            };

            let operation_awaiter =
                // If explicit timeout is set - then we need to wait for all expected operations.
                // E.g. in case of `CreateCollection` we will explicitly wait for all replicas to be activated.
                // We need to register receivers(by calling the function) before submitting the operation.
                if !expect_operations.is_empty() {
                    Some(state.await_for_multiple_operations(expect_operations, wait_timeout))
                } else {
                    None
                };

            let do_sync_nodes = match &op {
                // Sync nodes after collection or shard key creation
                CollectionMetaOperations::CreateCollection(_)
                | CollectionMetaOperations::CreateShardKey(_) => true,

                // Sync nodes when creating or renaming collection aliases
                CollectionMetaOperations::ChangeAliases(changes) => {
                    changes.actions.iter().any(|change| match change {
                        AliasOperations::CreateAlias(_) | AliasOperations::RenameAlias(_) => true,
                        AliasOperations::DeleteAlias(_) => false,
                    })
                }

                // TODO(resharding): Do we need/want to synchronize `Resharding` operations?
                CollectionMetaOperations::Resharding(_, _) => false,

                // No need to sync nodes for other operations
                CollectionMetaOperations::UpdateCollection(_)
                | CollectionMetaOperations::ApplyCryptoMigration(_)
                | CollectionMetaOperations::DeleteCollection(_)
                | CollectionMetaOperations::TransferShard(_, _)
                | CollectionMetaOperations::SetShardReplicaState(_)
                | CollectionMetaOperations::DropShardKey(_)
                | CollectionMetaOperations::CreatePayloadIndex(_)
                | CollectionMetaOperations::DropPayloadIndex(_)
                | CollectionMetaOperations::Nop { .. } => false,

                #[cfg(feature = "staging")]
                CollectionMetaOperations::TestSlowDown(_) => false,
            };

            // During creation of a shard key, we must ensure that all replicas are ready to accept
            // write requests, so the client-side script can rely on the fact that the
            // shard creation request is complete.
            //
            // For this we explicitly wait for validation this, we do following checks:
            //
            // 1. Wait for consensus to accept shard create operation on current machine.
            //    ( here newly created shards should start to report state change from `Inactive` to `Active` )
            // 2. Wait for all local shards to become active.
            //    ( At this stage we are sure, that all consensus operations are created, but might not be applied everywhere )
            // 3. Wait for all remote peers to have at least the same state as the current peer.
            //    ( So we are sure, that all remote peers have also switched to `Active` state )
            let create_shard_key = match &op {
                CollectionMetaOperations::CreateShardKey(op) => {
                    let collection_name: CollectionName = op.collection_name.clone();
                    let shard_key = op.shard_key.clone();
                    let initial_state = op.initial_state;
                    Some((collection_name, shard_key, initial_state))
                }
                _ => None,
            };

            // Send operation to consensus and wait for it to be applied locally
            let res = state
                .propose_consensus_op_with_await(
                    ConsensusOperations::CollectionMeta(Box::new(op)),
                    wait_timeout,
                )
                .await?;

            if let Some(operation_awaiter) = operation_awaiter {
                // Actually await for expected operations to complete on the consensus
                match operation_awaiter.await {
                    Ok(Ok(())) => {} // all good
                    Ok(Err(err)) => {
                        log::warn!("Not all expected operations were completed: {err}")
                    }
                    Err(err) => log::warn!("Awaiting for expected operations timed out: {err}"),
                }
            }

            // Wait for shards activation
            if let Some((collection_name, shard_key, initial_state)) = create_shard_key
                && initial_state.is_none()
            {
                // Only do if initial state is not set because we only wanted to wait for Active since introducing
                // the Initial state which needs a transition to Active.
                let remaining_timeout =
                    wait_timeout.map(|timeout| timeout.saturating_sub(start.elapsed()));
                self.wait_for_shard_key_activation(collection_name, shard_key, remaining_timeout)
                    .await?;
            };

            // On some operations, synchronize all nodes to ensure all are ready for point operations
            if do_sync_nodes {
                let remaining_timeout =
                    wait_timeout.map(|timeout| timeout.saturating_sub(start.elapsed()));
                if let Err(err) = self.await_consensus_sync(remaining_timeout).await {
                    log::warn!(
                        "Failed to synchronize all nodes after collection operation in time, some nodes may not be ready: {err}",
                    );
                }
            }

            Ok(res)
        } else {
            let toc = self.toc.clone();
            tokio::task::spawn(async move { toc.perform_collection_meta_op(operation).await })
                .await?
        }
    }

    pub fn cluster_status(&self) -> ClusterStatus {
        match self.consensus_state.as_ref() {
            Some(state) => state.cluster_status(),
            None => ClusterStatus::Disabled,
        }
    }

    pub async fn submit_private_oram_epoch_cas(
        &self,
        operation: CompareAndSwapPrivateOramEpoch,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM consensus epoch/root CAS requires distributed mode",
            )
        })?;
        let applied = consensus_state
            .propose_consensus_op_with_await(
                ConsensusOperations::CompareAndSwapPrivateOramEpoch(operation),
                wait_timeout,
            )
            .await?;
        if !applied {
            return Err(StorageError::service_error(
                "private ORAM consensus epoch/root CAS was not applied",
            ));
        }
        Ok(())
    }

    pub async fn submit_private_oram_session_lease_cas(
        &self,
        operation: CompareAndSwapPrivateOramSessionLease,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM consensus session lease CAS requires distributed mode",
            )
        })?;
        let applied = consensus_state
            .propose_consensus_op_with_await(
                ConsensusOperations::CompareAndSwapPrivateOramSessionLease(operation),
                wait_timeout,
            )
            .await?;
        if !applied {
            return Err(StorageError::service_error(
                "private ORAM consensus session lease CAS was not applied",
            ));
        }
        Ok(())
    }

    pub fn private_hnsw_oram_writeback_cas(
        &self,
        collection_id: String,
        vector_name: String,
        writeback: &PrivateHnswOramConsensusWriteback,
    ) -> Result<CompareAndSwapPrivateOramEpoch, StorageError> {
        self.private_oram_writeback_cas(
            PrivateOramEpochKey {
                collection_id,
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: vector_name,
            },
            writeback.old.index_epoch,
            &writeback.old.root_hash,
            writeback.new.index_epoch,
            &writeback.new.root_hash,
            &writeback.writeback_digest,
        )
    }

    pub fn private_result_oram_writeback_cas(
        &self,
        collection_id: String,
        writeback: &PrivateResultOramConsensusWriteback,
    ) -> Result<CompareAndSwapPrivateOramEpoch, StorageError> {
        self.private_oram_writeback_cas(
            PrivateOramEpochKey {
                collection_id,
                index_kind: PrivateOramIndexKind::ResultPayload,
                index_name: String::new(),
            },
            writeback.old.index_epoch,
            &writeback.old.root_hash,
            writeback.new.index_epoch,
            &writeback.new.root_hash,
            &writeback.writeback_digest,
        )
    }

    pub fn private_oram_initial_epoch_cas(
        &self,
        key: PrivateOramEpochKey,
        index_epoch: u64,
        root_hash: String,
    ) -> Result<CompareAndSwapPrivateOramEpoch, StorageError> {
        validate_private_oram_root_hash(&root_hash)?;
        Ok(CompareAndSwapPrivateOramEpoch {
            key,
            expected: None,
            new: PrivateOramConsensusEpoch {
                index_epoch,
                root_hash,
                writeback_digest: None,
            },
        })
    }

    fn private_oram_writeback_cas(
        &self,
        key: PrivateOramEpochKey,
        old_epoch: u64,
        old_root_hash: &str,
        new_epoch: u64,
        new_root_hash: &str,
        writeback_digest: &str,
    ) -> Result<CompareAndSwapPrivateOramEpoch, StorageError> {
        let expected = self.private_oram_consensus_epoch(&key)?.ok_or_else(|| {
            StorageError::bad_request(
                "private ORAM consensus writeback ownership is not initialized",
            )
        })?;
        if expected.index_epoch != old_epoch || expected.root_hash != old_root_hash {
            return Err(StorageError::bad_request(
                "private ORAM local writeback does not match consensus epoch/root",
            ));
        }
        Ok(CompareAndSwapPrivateOramEpoch {
            key,
            expected: Some(expected),
            new: PrivateOramConsensusEpoch {
                index_epoch: new_epoch,
                root_hash: new_root_hash.to_string(),
                writeback_digest: Some(writeback_digest.to_string()),
            },
        })
    }

    /// Coordinates a private ORAM writeback around the replicated epoch/root commit point.
    ///
    /// `prepare` must durably persist an owner-signed, idempotent local writeback journal.
    /// `abort` must remove that journal only while the active local view is still unchanged.
    /// `finalize` must be safe to retry after the exact consensus CAS has already applied.
    pub async fn coordinate_private_oram_writeback<Prepare, Abort, Finalize>(
        &self,
        operation: CompareAndSwapPrivateOramEpoch,
        wait_timeout: Option<Duration>,
        prepare: Prepare,
        abort: Abort,
        finalize: Finalize,
    ) -> Result<(), StorageError>
    where
        Prepare: FnOnce() -> Result<(), StorageError>,
        Abort: FnOnce() -> Result<(), StorageError>,
        Finalize: FnOnce() -> Result<(), StorageError>,
    {
        prepare()?;
        if let Err(consensus_error) = self
            .submit_private_oram_epoch_cas(operation, wait_timeout)
            .await
        {
            abort()?;
            return Err(consensus_error);
        }
        finalize()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_replicated_private_oram_writeback<
        PrepareLocal,
        PrepareReplicas,
        PrepareReplicasFuture,
        AbortLocal,
        AbortReplicas,
        AbortReplicasFuture,
        FinalizeLocal,
        FinalizeReplicas,
        FinalizeReplicasFuture,
    >(
        &self,
        operation: CompareAndSwapPrivateOramEpoch,
        required_replica_peers: &BTreeSet<PeerId>,
        wait_timeout: Option<Duration>,
        prepare_local: PrepareLocal,
        prepare_replicas: PrepareReplicas,
        abort_local: AbortLocal,
        abort_replicas: AbortReplicas,
        finalize_local: FinalizeLocal,
        finalize_replicas: FinalizeReplicas,
    ) -> Result<(), StorageError>
    where
        PrepareLocal: FnOnce() -> Result<(), StorageError>,
        PrepareReplicas: FnOnce() -> PrepareReplicasFuture,
        PrepareReplicasFuture:
            Future<Output = Result<Vec<PrivateOramReplicaPrepareAck>, StorageError>>,
        AbortLocal: FnOnce() -> Result<(), StorageError>,
        AbortReplicas: FnOnce() -> AbortReplicasFuture,
        AbortReplicasFuture: Future<Output = Result<(), StorageError>>,
        FinalizeLocal: FnOnce() -> Result<(), StorageError>,
        FinalizeReplicas: FnOnce() -> FinalizeReplicasFuture,
        FinalizeReplicasFuture: Future<Output = Result<(), StorageError>>,
    {
        let expected_digest = operation.new.writeback_digest.as_deref().ok_or_else(|| {
            StorageError::bad_request(
                "replicated private ORAM writeback requires a consensus digest",
            )
        })?;
        validate_private_oram_writeback_digest(expected_digest)?;
        prepare_local()?;

        let replica_acks = match prepare_replicas().await {
            Ok(replica_acks) => replica_acks,
            Err(prepare_error) => {
                let remote_abort = abort_replicas().await;
                let local_abort = abort_local();
                remote_abort?;
                local_abort?;
                return Err(prepare_error);
            }
        };
        if let Err(ack_error) = validate_private_oram_replica_prepare_acks(
            required_replica_peers,
            &replica_acks,
            expected_digest,
        ) {
            let remote_abort = abort_replicas().await;
            let local_abort = abort_local();
            remote_abort?;
            local_abort?;
            return Err(ack_error);
        }

        if let Err(consensus_error) = self
            .submit_private_oram_epoch_cas(operation, wait_timeout)
            .await
        {
            let remote_abort = abort_replicas().await;
            let local_abort = abort_local();
            remote_abort?;
            local_abort?;
            return Err(consensus_error);
        }

        finalize_replicas().await?;
        finalize_local()
    }

    /// Resolve the exact peers that must durably prepare a collection-local private ORAM
    /// writeback. Private ORAM storage is not shard-local, so v1 only permits collections whose
    /// shards all have the same fully-active replica membership.
    pub async fn private_oram_replication_peers(
        &self,
        collection_name: &CollectionName,
    ) -> Result<BTreeSet<PeerId>, StorageError> {
        let collection = self
            .toc
            .get_collection(&CollectionMultipass.issue_pass(collection_name))
            .await?;
        let shard_holder = collection.shards_holder().read_owned().await;
        let shard_peer_states = shard_holder
            .all_shards()
            .map(|replica_set| replica_set.peers())
            .collect::<Vec<_>>();
        let peers =
            derive_private_oram_replication_peers(&shard_peer_states, self.toc.this_peer_id)?;

        let known_addresses = self.toc.get_channel_service().id_to_address.read();
        if peers.iter().any(|peer_id| {
            *peer_id != self.toc.this_peer_id && !known_addresses.contains_key(peer_id)
        }) {
            return Err(StorageError::service_error(
                "private ORAM replication peer address is unavailable",
            ));
        }
        Ok(peers)
    }

    pub async fn prepare_private_hnsw_oram_replicas(
        &self,
        replica_peers: &BTreeSet<PeerId>,
        collection_name: &str,
        collection_id: &str,
        vector_name: &str,
        batch: &PrivateHnswOramWritebackBatch,
        transition: &PrivateHnswOramConsensusWriteback,
    ) -> Result<Vec<PrivateOramReplicaPrepareAck>, StorageError> {
        self.prepare_private_oram_replicas(
            replica_peers,
            private_hnsw_oram_prepare_request(
                collection_name,
                collection_id,
                vector_name,
                batch,
                transition,
            )?,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_private_hnsw_oram_writeback<PrepareLocal, AbortLocal, FinalizeLocal>(
        &self,
        collection_name: CollectionName,
        collection_id: String,
        vector_name: String,
        batch: PrivateHnswOramWritebackBatch,
        transition: PrivateHnswOramConsensusWriteback,
        wait_timeout: Option<Duration>,
        prepare_local: PrepareLocal,
        abort_local: AbortLocal,
        finalize_local: FinalizeLocal,
    ) -> Result<(), StorageError>
    where
        PrepareLocal: FnOnce() -> Result<(), StorageError>,
        AbortLocal: FnOnce() -> Result<(), StorageError>,
        FinalizeLocal: FnOnce() -> Result<(), StorageError>,
    {
        let operation = self.private_hnsw_oram_writeback_cas(
            collection_id.clone(),
            vector_name.clone(),
            &transition,
        )?;
        let mut replica_peers = self
            .private_oram_replication_peers(&collection_name)
            .await?;
        replica_peers.remove(&self.toc.this_peer_id);
        let completion_request = private_oram_complete_request(
            &collection_name,
            &collection_id,
            PrivateOramReplicationIndexKind::Hnsw,
            &vector_name,
            transition.old.index_epoch,
            &transition.old.root_hash,
            transition.new.index_epoch,
            &transition.new.root_hash,
            &transition.writeback_digest,
            &batch.commit_signature.key_id,
        )?;
        let abort_request = completion_request.clone();
        self.coordinate_replicated_private_oram_writeback(
            operation,
            &replica_peers,
            wait_timeout,
            prepare_local,
            || {
                self.prepare_private_hnsw_oram_replicas(
                    &replica_peers,
                    &collection_name,
                    &collection_id,
                    &vector_name,
                    &batch,
                    &transition,
                )
            },
            abort_local,
            || self.complete_private_oram_replicas(&replica_peers, abort_request, true),
            finalize_local,
            || self.complete_private_oram_replicas(&replica_peers, completion_request, false),
        )
        .await
    }

    pub async fn prepare_private_result_oram_replicas(
        &self,
        replica_peers: &BTreeSet<PeerId>,
        collection_name: &str,
        collection_id: &str,
        batch: &PrivateResultOramWritebackBatch,
        transition: &PrivateResultOramConsensusWriteback,
    ) -> Result<Vec<PrivateOramReplicaPrepareAck>, StorageError> {
        self.prepare_private_oram_replicas(
            replica_peers,
            private_result_oram_prepare_request(collection_name, collection_id, batch, transition)?,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_private_result_oram_writeback<PrepareLocal, AbortLocal, FinalizeLocal>(
        &self,
        collection_name: CollectionName,
        collection_id: String,
        batch: PrivateResultOramWritebackBatch,
        transition: PrivateResultOramConsensusWriteback,
        wait_timeout: Option<Duration>,
        prepare_local: PrepareLocal,
        abort_local: AbortLocal,
        finalize_local: FinalizeLocal,
    ) -> Result<(), StorageError>
    where
        PrepareLocal: FnOnce() -> Result<(), StorageError>,
        AbortLocal: FnOnce() -> Result<(), StorageError>,
        FinalizeLocal: FnOnce() -> Result<(), StorageError>,
    {
        let operation =
            self.private_result_oram_writeback_cas(collection_id.clone(), &transition)?;
        let mut replica_peers = self
            .private_oram_replication_peers(&collection_name)
            .await?;
        replica_peers.remove(&self.toc.this_peer_id);
        let completion_request = private_oram_complete_request(
            &collection_name,
            &collection_id,
            PrivateOramReplicationIndexKind::Result,
            "",
            transition.old.index_epoch,
            &transition.old.root_hash,
            transition.new.index_epoch,
            &transition.new.root_hash,
            &transition.writeback_digest,
            &batch.commit_signature.key_id,
        )?;
        let abort_request = completion_request.clone();
        self.coordinate_replicated_private_oram_writeback(
            operation,
            &replica_peers,
            wait_timeout,
            prepare_local,
            || {
                self.prepare_private_result_oram_replicas(
                    &replica_peers,
                    &collection_name,
                    &collection_id,
                    &batch,
                    &transition,
                )
            },
            abort_local,
            || self.complete_private_oram_replicas(&replica_peers, abort_request, true),
            finalize_local,
            || self.complete_private_oram_replicas(&replica_peers, completion_request, false),
        )
        .await
    }

    pub async fn complete_private_hnsw_oram_recovery_replicas(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        vector_name: &str,
        transition: &PrivateHnswOramConsensusWriteback,
        signing_key_id: &str,
        abort: bool,
    ) -> Result<(), StorageError> {
        self.complete_private_oram_recovery_replicas(
            collection_name,
            collection_id,
            PrivateOramReplicationIndexKind::Hnsw,
            vector_name,
            transition.old.index_epoch,
            &transition.old.root_hash,
            transition.new.index_epoch,
            &transition.new.root_hash,
            &transition.writeback_digest,
            signing_key_id,
            abort,
        )
        .await
    }

    pub async fn complete_private_result_oram_recovery_replicas(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        transition: &PrivateResultOramConsensusWriteback,
        signing_key_id: &str,
        abort: bool,
    ) -> Result<(), StorageError> {
        self.complete_private_oram_recovery_replicas(
            collection_name,
            collection_id,
            PrivateOramReplicationIndexKind::Result,
            "",
            transition.old.index_epoch,
            &transition.old.root_hash,
            transition.new.index_epoch,
            &transition.new.root_hash,
            &transition.writeback_digest,
            signing_key_id,
            abort,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_private_oram_recovery_replicas(
        &self,
        collection_name: &CollectionName,
        collection_id: &str,
        index_kind: PrivateOramReplicationIndexKind,
        index_name: &str,
        old_epoch: u64,
        old_root_hash: &str,
        new_epoch: u64,
        new_root_hash: &str,
        writeback_digest: &str,
        signing_key_id: &str,
        abort: bool,
    ) -> Result<(), StorageError> {
        let mut replica_peers = self.private_oram_replication_peers(collection_name).await?;
        replica_peers.remove(&self.toc.this_peer_id);
        let request = private_oram_complete_request(
            collection_name,
            collection_id,
            index_kind,
            index_name,
            old_epoch,
            old_root_hash,
            new_epoch,
            new_root_hash,
            writeback_digest,
            signing_key_id,
        )?;
        self.complete_private_oram_replicas(&replica_peers, request, abort)
            .await
    }

    async fn prepare_private_oram_replicas(
        &self,
        replica_peers: &BTreeSet<PeerId>,
        request: PreparePrivateOramWritebackRequest,
    ) -> Result<Vec<PrivateOramReplicaPrepareAck>, StorageError> {
        let channel_service = self.toc.get_channel_service();
        let mut pending = replica_peers
            .iter()
            .map(|peer_id| {
                let peer_id = *peer_id;
                let request = request.clone();
                async move {
                    channel_service
                        .prepare_private_oram_writeback(peer_id, request)
                        .await
                        .map(|writeback_digest| PrivateOramReplicaPrepareAck {
                            peer_id,
                            writeback_digest,
                        })
                }
            })
            .collect::<FuturesUnordered<_>>();
        let mut acknowledgements = Vec::with_capacity(replica_peers.len());
        let mut first_error = None;
        while let Some(result) = pending.next().await {
            match result {
                Ok(acknowledgement) => acknowledgements.push(acknowledgement),
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        Ok(acknowledgements)
    }

    pub async fn complete_private_oram_replicas(
        &self,
        replica_peers: &BTreeSet<PeerId>,
        request: CompletePrivateOramWritebackRequest,
        abort: bool,
    ) -> Result<(), StorageError> {
        let channel_service = self.toc.get_channel_service();
        let mut pending = replica_peers
            .iter()
            .map(|peer_id| {
                let peer_id = *peer_id;
                let request = request.clone();
                async move {
                    let result = if abort {
                        channel_service
                            .abort_private_oram_writeback(peer_id, request)
                            .await
                    } else {
                        channel_service
                            .finalize_private_oram_writeback(peer_id, request)
                            .await
                    };
                    result.and_then(|completed| {
                        if abort || completed {
                            Ok(())
                        } else {
                            Err(
                                collection::operations::types::CollectionError::service_error(
                                    format!(
                                        "private ORAM finalize was not completed on peer {peer_id}"
                                    ),
                                ),
                            )
                        }
                    })
                }
            })
            .collect::<FuturesUnordered<_>>();
        let mut first_error = None;
        while let Some(result) = pending.next().await {
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn coordinate_private_oram_initial_install(
        &self,
        collection_name: &CollectionName,
        key: PrivateOramEpochKey,
        request: InstallPrivateOramIndexRequest,
        expected_epoch: u64,
        expected_root_hash: &str,
        wait_timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        validate_private_oram_root_hash(expected_root_hash)?;
        let mut replica_peers = self.private_oram_replication_peers(collection_name).await?;
        replica_peers.remove(&self.toc.this_peer_id);
        let channel_service = self.toc.get_channel_service();
        let mut pending = replica_peers
            .iter()
            .map(|peer_id| {
                let peer_id = *peer_id;
                let request = request.clone();
                async move {
                    channel_service
                        .install_private_oram_index(peer_id, request)
                        .await
                        .and_then(|response| {
                            if response.index_epoch == expected_epoch
                                && response.root_hash == expected_root_hash
                            {
                                Ok(())
                            } else {
                                Err(collection::operations::types::CollectionError::service_error(
                                    format!(
                                        "private ORAM initial install acknowledgement is invalid on peer {peer_id}"
                                    ),
                                ))
                            }
                        })
                }
            })
            .collect::<FuturesUnordered<_>>();
        let mut first_error = None;
        while let Some(result) = pending.next().await {
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        let operation = self.private_oram_initial_epoch_cas(
            key,
            expected_epoch,
            expected_root_hash.to_string(),
        )?;
        self.submit_private_oram_epoch_cas(operation, wait_timeout)
            .await
    }

    pub fn private_oram_consensus_epoch(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Result<Option<PrivateOramConsensusEpoch>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM consensus epoch/root state requires distributed mode",
            )
        })?;
        Ok(consensus_state.private_oram_epoch(key))
    }

    pub fn private_oram_consensus_session_lease(
        &self,
        key: &PrivateOramEpochKey,
    ) -> Result<Option<PrivateOramSessionLease>, StorageError> {
        let consensus_state = self.consensus_state.as_ref().ok_or_else(|| {
            StorageError::service_error(
                "private ORAM consensus session lease requires distributed mode",
            )
        })?;
        Ok(consensus_state.private_oram_session_lease(key))
    }

    pub async fn await_consensus_sync(
        &self,
        timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let timeout = timeout.unwrap_or(CONSENSUS_META_OP_WAIT);

        let Some(state) = self.consensus_state.as_ref() else {
            return Ok(());
        };

        let state = state.hard_state();
        let term = state.term;
        let commit = state.commit;
        let channel_service = self.toc.get_channel_service();
        let this_peer_id = self.toc.this_peer_id;

        channel_service
            .await_commit_on_all_peers(this_peer_id, commit, term, timeout)
            .await?;

        log::debug!("Consensus is synchronized with term: {term}, commit: {commit}");

        Ok(())
    }

    /// Waits for all shards of a specific shard key to become active.
    pub async fn wait_for_shard_key_activation(
        &self,
        collection_name: CollectionName,
        shard_key: ShardKey,
        timeout: Option<Duration>,
    ) -> Result<(), StorageError> {
        let timeout = timeout.unwrap_or(CONSENSUS_META_OP_WAIT);

        let mut wait_for_active = FuturesUnordered::new();

        {
            let shard_holder = self
                .toc
                .get_collection(&CollectionMultipass.issue_pass(&collection_name))
                .await?
                .shards_holder()
                .read_owned()
                .await;

            for replica_set in shard_holder.all_shards() {
                if replica_set.shard_key() != Some(&shard_key) {
                    continue;
                }

                for (peer_id, replica_state) in replica_set.peers() {
                    if replica_state == ReplicaState::Active {
                        continue;
                    }

                    wait_for_active.push(replica_set.wait_for_state(
                        peer_id,
                        ReplicaState::Active,
                        timeout,
                    ));
                }
            }
        }

        while let Some(result) = wait_for_active.next().await {
            result?;
        }

        Ok(())
    }

    pub fn all_hw_metrics(&self) -> HashMap<String, HardwareUsage> {
        self.toc.all_hw_metrics()
    }

    #[must_use]
    pub fn get_collection_hw_metrics(&self, collection: String) -> Arc<HwSharedDrain> {
        self.toc.get_collection_hw_metrics(collection)
    }
}

fn validate_private_oram_replica_prepare_acks(
    required_replica_peers: &BTreeSet<PeerId>,
    replica_acks: &[PrivateOramReplicaPrepareAck],
    expected_digest: &str,
) -> Result<(), StorageError> {
    validate_private_oram_writeback_digest(expected_digest)?;
    let mut acknowledged_peers = BTreeSet::new();
    for ack in replica_acks {
        if ack.writeback_digest != expected_digest || !acknowledged_peers.insert(ack.peer_id) {
            return Err(StorageError::bad_request(
                "private ORAM replica prepare acknowledgements are invalid",
            ));
        }
    }
    if &acknowledged_peers != required_replica_peers {
        return Err(StorageError::bad_request(
            "private ORAM replica prepare acknowledgements are incomplete",
        ));
    }
    Ok(())
}

pub fn private_hnsw_oram_prepare_request(
    collection_name: &str,
    collection_id: &str,
    vector_name: &str,
    batch: &PrivateHnswOramWritebackBatch,
    transition: &PrivateHnswOramConsensusWriteback,
) -> Result<PreparePrivateOramWritebackRequest, StorageError> {
    if batch.old != transition.old || batch.new != transition.new {
        return Err(StorageError::bad_request(
            "private HNSW ORAM replication batch transition does not match",
        ));
    }
    validate_private_oram_writeback_digest(&transition.writeback_digest)?;
    Ok(PreparePrivateOramWritebackRequest {
        collection_name: collection_name.to_string(),
        collection_id: collection_id.to_string(),
        index_kind: PrivateOramReplicationIndexKind::Hnsw as i32,
        vector_name: vector_name.to_string(),
        version: u32::from(batch.version),
        transition: Some(private_oram_transition(
            batch.old.index_epoch,
            &batch.old.root_hash,
            batch.new.index_epoch,
            &batch.new.root_hash,
            &transition.writeback_digest,
        )),
        bucket_count: batch.bucket_count,
        updated_buckets: batch
            .updated_buckets
            .iter()
            .map(|bucket| PrivateOramReplicationBucket {
                version: u32::from(bucket.version),
                bucket_id: bucket.bucket_id,
                index_epoch: bucket.index_epoch,
                ciphertext: bucket.ciphertext.clone(),
                ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                bucket_commitment: bucket.bucket_commitment.clone(),
            })
            .collect(),
        commit_signature: Some(PrivateOramReplicationSignature {
            alg: batch.commit_signature.alg.clone(),
            key_id: batch.commit_signature.key_id.clone(),
            sig: batch.commit_signature.sig.clone(),
        }),
    })
}

pub fn private_result_oram_prepare_request(
    collection_name: &str,
    collection_id: &str,
    batch: &PrivateResultOramWritebackBatch,
    transition: &PrivateResultOramConsensusWriteback,
) -> Result<PreparePrivateOramWritebackRequest, StorageError> {
    if batch.old != transition.old || batch.new != transition.new {
        return Err(StorageError::bad_request(
            "private result ORAM replication batch transition does not match",
        ));
    }
    validate_private_oram_writeback_digest(&transition.writeback_digest)?;
    Ok(PreparePrivateOramWritebackRequest {
        collection_name: collection_name.to_string(),
        collection_id: collection_id.to_string(),
        index_kind: PrivateOramReplicationIndexKind::Result as i32,
        vector_name: String::new(),
        version: u32::from(batch.version),
        transition: Some(private_oram_transition(
            batch.old.index_epoch,
            &batch.old.root_hash,
            batch.new.index_epoch,
            &batch.new.root_hash,
            &transition.writeback_digest,
        )),
        bucket_count: batch.bucket_count,
        updated_buckets: batch
            .updated_buckets
            .iter()
            .map(|bucket| PrivateOramReplicationBucket {
                version: u32::from(bucket.version),
                bucket_id: bucket.bucket_id,
                index_epoch: bucket.index_epoch,
                ciphertext: bucket.ciphertext.clone(),
                ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                bucket_commitment: bucket.bucket_commitment.clone(),
            })
            .collect(),
        commit_signature: Some(PrivateOramReplicationSignature {
            alg: batch.commit_signature.alg.clone(),
            key_id: batch.commit_signature.key_id.clone(),
            sig: batch.commit_signature.sig.clone(),
        }),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn private_oram_complete_request(
    collection_name: &str,
    collection_id: &str,
    index_kind: PrivateOramReplicationIndexKind,
    vector_name: &str,
    old_epoch: u64,
    old_root_hash: &str,
    new_epoch: u64,
    new_root_hash: &str,
    writeback_digest: &str,
    signing_key_id: &str,
) -> Result<CompletePrivateOramWritebackRequest, StorageError> {
    if index_kind == PrivateOramReplicationIndexKind::Unspecified
        || (index_kind == PrivateOramReplicationIndexKind::Hnsw && vector_name.is_empty())
        || (index_kind == PrivateOramReplicationIndexKind::Result && !vector_name.is_empty())
    {
        return Err(StorageError::bad_request(
            "private ORAM replication completion identity is invalid",
        ));
    }
    validate_private_oram_writeback_digest(writeback_digest)?;
    Ok(CompletePrivateOramWritebackRequest {
        collection_name: collection_name.to_string(),
        collection_id: collection_id.to_string(),
        index_kind: index_kind as i32,
        vector_name: vector_name.to_string(),
        transition: Some(private_oram_transition(
            old_epoch,
            old_root_hash,
            new_epoch,
            new_root_hash,
            writeback_digest,
        )),
        signing_key_id: signing_key_id.to_string(),
    })
}

fn private_oram_transition(
    old_epoch: u64,
    old_root_hash: &str,
    new_epoch: u64,
    new_root_hash: &str,
    writeback_digest: &str,
) -> PrivateOramReplicationTransition {
    PrivateOramReplicationTransition {
        old: Some(PrivateOramReplicationEpochState {
            index_epoch: old_epoch,
            root_hash: old_root_hash.to_string(),
        }),
        new: Some(PrivateOramReplicationEpochState {
            index_epoch: new_epoch,
            root_hash: new_root_hash.to_string(),
        }),
        writeback_digest: writeback_digest.to_string(),
    }
}

fn derive_private_oram_replication_peers(
    shard_peer_states: &[HashMap<PeerId, ReplicaState>],
    this_peer_id: PeerId,
) -> Result<BTreeSet<PeerId>, StorageError> {
    let Some(first_shard) = shard_peer_states.first() else {
        return Err(StorageError::service_error(
            "private ORAM replication requires at least one shard",
        ));
    };
    if shard_peer_states
        .iter()
        .any(|peers| peers.is_empty() || peers.values().any(|state| *state != ReplicaState::Active))
    {
        return Err(StorageError::service_error(
            "private ORAM replication requires fully active shard replicas",
        ));
    }

    let expected = first_shard.keys().copied().collect::<BTreeSet<_>>();
    if !expected.contains(&this_peer_id)
        || shard_peer_states
            .iter()
            .skip(1)
            .any(|peers| peers.keys().copied().collect::<BTreeSet<_>>() != expected)
    {
        return Err(StorageError::service_error(
            "private ORAM replication requires identical shard replica membership",
        ));
    }
    Ok(expected)
}

fn validate_private_oram_writeback_digest(digest: &str) -> Result<(), StorageError> {
    let decoded = BASE64URL_NOPAD.decode(digest.as_bytes()).map_err(|_| {
        StorageError::bad_request("private ORAM replicated writeback digest is invalid")
    })?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != digest {
        return Err(StorageError::bad_request(
            "private ORAM replicated writeback digest is invalid",
        ));
    }
    Ok(())
}

fn validate_private_oram_root_hash(root_hash: &str) -> Result<(), StorageError> {
    let decoded = BASE64URL_NOPAD
        .decode(root_hash.as_bytes())
        .map_err(|_| StorageError::bad_request("private ORAM consensus root hash is invalid"))?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != root_hash {
        return Err(StorageError::bad_request(
            "private ORAM consensus root hash is invalid",
        ));
    }
    Ok(())
}

pub fn classify_private_oram_recovery(
    consensus: Option<&PrivateOramConsensusEpoch>,
    local: PrivateOramEpochRef<'_>,
    pending: Option<PrivateOramPendingTransitionRef<'_>>,
) -> Result<PrivateOramRecoveryAction, StorageError> {
    validate_private_oram_root_hash(local.root_hash)?;
    let consensus = consensus.ok_or_else(|| {
        StorageError::bad_request("private ORAM consensus ownership is not initialized")
    })?;
    validate_private_oram_root_hash(&consensus.root_hash)?;
    if let Some(digest) = consensus.writeback_digest.as_deref() {
        validate_private_oram_writeback_digest(digest)?;
    }

    let Some(pending) = pending else {
        if local.index_epoch == consensus.index_epoch && local.root_hash == consensus.root_hash {
            return Ok(PrivateOramRecoveryAction::Clean);
        }
        return Err(StorageError::bad_request(
            "private ORAM local state does not match consensus",
        ));
    };

    validate_private_oram_root_hash(pending.old.root_hash)?;
    validate_private_oram_root_hash(pending.new.root_hash)?;
    validate_private_oram_writeback_digest(pending.writeback_digest)?;
    let local_is_old =
        local.index_epoch == pending.old.index_epoch && local.root_hash == pending.old.root_hash;
    let local_is_new =
        local.index_epoch == pending.new.index_epoch && local.root_hash == pending.new.root_hash;
    if pending.new.index_epoch <= pending.old.index_epoch || (!local_is_old && !local_is_new) {
        return Err(StorageError::bad_request(
            "private ORAM pending recovery state is inconsistent",
        ));
    }

    let consensus_is_new = consensus.index_epoch == pending.new.index_epoch
        && consensus.root_hash == pending.new.root_hash
        && consensus.writeback_digest.as_deref() == Some(pending.writeback_digest);
    if consensus_is_new {
        return Ok(PrivateOramRecoveryAction::FinalizePending);
    }

    let consensus_is_old = consensus.index_epoch == pending.old.index_epoch
        && consensus.root_hash == pending.old.root_hash;
    if local_is_old && consensus_is_old {
        return Ok(PrivateOramRecoveryAction::AbortPending);
    }

    Err(StorageError::bad_request(
        "private ORAM pending recovery does not match consensus",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_oram_recovery_requires_exact_consensus_state() {
        let old_root = BASE64URL_NOPAD.encode(&[1; 32]);
        let new_root = BASE64URL_NOPAD.encode(&[2; 32]);
        let unrelated_root = BASE64URL_NOPAD.encode(&[3; 32]);
        let previous_digest = BASE64URL_NOPAD.encode(&[4; 32]);
        let writeback_digest = BASE64URL_NOPAD.encode(&[5; 32]);
        let old_consensus = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: old_root.clone(),
            writeback_digest: Some(previous_digest),
        };
        let new_consensus = PrivateOramConsensusEpoch {
            index_epoch: 43,
            root_hash: new_root.clone(),
            writeback_digest: Some(writeback_digest.clone()),
        };
        let local_old = || PrivateOramEpochRef {
            index_epoch: 42,
            root_hash: &old_root,
        };
        let local_new = || PrivateOramEpochRef {
            index_epoch: 43,
            root_hash: &new_root,
        };
        let pending = || PrivateOramPendingTransitionRef {
            old: local_old(),
            new: local_new(),
            writeback_digest: &writeback_digest,
        };

        assert_eq!(
            classify_private_oram_recovery(Some(&old_consensus), local_old(), None).unwrap(),
            PrivateOramRecoveryAction::Clean,
        );
        assert_eq!(
            classify_private_oram_recovery(Some(&old_consensus), local_old(), Some(pending()),)
                .unwrap(),
            PrivateOramRecoveryAction::AbortPending,
        );
        for local in [local_old(), local_new()] {
            assert_eq!(
                classify_private_oram_recovery(Some(&new_consensus), local, Some(pending()),)
                    .unwrap(),
                PrivateOramRecoveryAction::FinalizePending,
            );
        }

        let wrong_digest_consensus = PrivateOramConsensusEpoch {
            writeback_digest: Some(BASE64URL_NOPAD.encode(&[6; 32])),
            ..new_consensus.clone()
        };
        let unrelated_consensus = PrivateOramConsensusEpoch {
            index_epoch: 44,
            root_hash: unrelated_root.clone(),
            writeback_digest: None,
        };
        for mismatch in [
            classify_private_oram_recovery(Some(&new_consensus), local_old(), None).unwrap_err(),
            classify_private_oram_recovery(
                Some(&wrong_digest_consensus),
                local_old(),
                Some(pending()),
            )
            .unwrap_err(),
            classify_private_oram_recovery(Some(&old_consensus), local_new(), Some(pending()))
                .unwrap_err(),
            classify_private_oram_recovery(
                Some(&unrelated_consensus),
                local_old(),
                Some(pending()),
            )
            .unwrap_err(),
            classify_private_oram_recovery(None, local_old(), None).unwrap_err(),
        ] {
            let rendered = mismatch.to_string();
            for sentinel in [
                old_root.as_str(),
                new_root.as_str(),
                unrelated_root.as_str(),
                writeback_digest.as_str(),
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }

        let malformed = "private-oram-recovery-root-sentinel";
        let malformed = classify_private_oram_recovery(
            Some(&old_consensus),
            PrivateOramEpochRef {
                index_epoch: 42,
                root_hash: malformed,
            },
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(malformed.contains("consensus root hash is invalid"));
        assert!(!malformed.contains("sentinel"));
    }

    #[test]
    fn private_oram_replica_prepare_acks_require_exact_peers_and_digest() {
        let digest = BASE64URL_NOPAD.encode(&[42; 32]);
        let required = BTreeSet::from([7, 9]);
        let valid = vec![
            PrivateOramReplicaPrepareAck {
                peer_id: 9,
                writeback_digest: digest.clone(),
            },
            PrivateOramReplicaPrepareAck {
                peer_id: 7,
                writeback_digest: digest.clone(),
            },
        ];
        validate_private_oram_replica_prepare_acks(&required, &valid, &digest).unwrap();

        let rendered = format!("{:?}", valid[0]);
        assert!(rendered.contains("peer_id: 9"), "{rendered}");
        assert!(!rendered.contains(&digest), "{rendered}");

        let missing = validate_private_oram_replica_prepare_acks(&required, &valid[..1], &digest)
            .unwrap_err()
            .to_string();
        assert!(missing.contains("acknowledgements are incomplete"));

        let duplicate = validate_private_oram_replica_prepare_acks(
            &required,
            &[valid[0].clone(), valid[0].clone()],
            &digest,
        )
        .unwrap_err()
        .to_string();
        assert!(duplicate.contains("acknowledgements are invalid"));

        let mismatched_digest = BASE64URL_NOPAD.encode(&[43; 32]);
        let mismatch = validate_private_oram_replica_prepare_acks(
            &required,
            &[PrivateOramReplicaPrepareAck {
                peer_id: 7,
                writeback_digest: mismatched_digest.clone(),
            }],
            &digest,
        )
        .unwrap_err()
        .to_string();
        assert!(mismatch.contains("acknowledgements are invalid"));
        assert!(!mismatch.contains(&digest));
        assert!(!mismatch.contains(&mismatched_digest));

        let malformed_digest = "private-oram-replica-digest-sentinel";
        let malformed =
            validate_private_oram_replica_prepare_acks(&BTreeSet::new(), &[], malformed_digest)
                .unwrap_err()
                .to_string();
        assert!(malformed.contains("replicated writeback digest is invalid"));
        assert!(!malformed.contains(malformed_digest));
    }

    #[test]
    fn private_oram_replication_peers_require_identical_fully_active_membership() {
        let active = HashMap::from([(7, ReplicaState::Active), (9, ReplicaState::Active)]);
        let reversed = HashMap::from([(9, ReplicaState::Active), (7, ReplicaState::Active)]);
        assert_eq!(
            derive_private_oram_replication_peers(&[active.clone(), reversed], 7).unwrap(),
            BTreeSet::from([7, 9]),
        );

        let no_shards = derive_private_oram_replication_peers(&[], 7)
            .unwrap_err()
            .to_string();
        assert!(no_shards.contains("at least one shard"));

        let mut transitioning = active.clone();
        transitioning.insert(9, ReplicaState::ActiveRead);
        let transitioning =
            derive_private_oram_replication_peers(&[active.clone(), transitioning], 7)
                .unwrap_err()
                .to_string();
        assert!(transitioning.contains("fully active shard replicas"));

        let mismatched = derive_private_oram_replication_peers(
            &[active.clone(), HashMap::from([(7, ReplicaState::Active)])],
            7,
        )
        .unwrap_err()
        .to_string();
        assert!(mismatched.contains("identical shard replica membership"));

        let local_missing = derive_private_oram_replication_peers(&[active], 11)
            .unwrap_err()
            .to_string();
        assert!(local_missing.contains("identical shard replica membership"));
        assert!(!local_missing.contains("11"));
    }

    #[test]
    fn private_oram_completion_wire_request_preserves_exact_transition() {
        let digest = BASE64URL_NOPAD.encode(&[47; 32]);
        let request = private_oram_complete_request(
            "docs",
            "collection-id",
            PrivateOramReplicationIndexKind::Hnsw,
            "text",
            42,
            "old-root",
            43,
            "new-root",
            &digest,
            "owner-key",
        )
        .unwrap();
        assert_eq!(
            request.index_kind,
            PrivateOramReplicationIndexKind::Hnsw as i32
        );
        assert_eq!(request.vector_name, "text");
        assert_eq!(request.transition.unwrap().writeback_digest, digest,);

        let error = private_oram_complete_request(
            "docs",
            "collection-id",
            PrivateOramReplicationIndexKind::Result,
            "text",
            42,
            "old-root",
            43,
            "new-root",
            &BASE64URL_NOPAD.encode(&[48; 32]),
            "owner-key",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("completion identity is invalid"));
        assert!(!error.contains("old-root"));
        assert!(!error.contains("new-root"));

        let root_sentinel = "private-oram-invalid-root-sentinel";
        let error = validate_private_oram_root_hash(root_sentinel)
            .unwrap_err()
            .to_string();
        assert!(error.contains("consensus root hash is invalid"));
        assert!(!error.contains(root_sentinel));
    }
}
