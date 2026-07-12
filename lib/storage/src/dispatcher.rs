use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Debug, Formatter};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use api::rest::models::HardwareUsage;
use collection::common::fetch_vectors::CollectionName;
use collection::config::ShardingMethod;
use collection::operations::verification::VerificationPass;
use collection::private_hnsw_oram_store::PrivateHnswOramConsensusWriteback;
use collection::private_result_oram_store::PrivateResultOramConsensusWriteback;
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
    CompareAndSwapPrivateOramEpoch, PrivateOramConsensusEpoch, PrivateOramEpochKey,
    PrivateOramIndexKind,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
