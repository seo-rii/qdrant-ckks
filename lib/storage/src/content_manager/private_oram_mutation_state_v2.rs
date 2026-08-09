//! Durable V2 parent state codec for private ORAM mutation reconciliation.
//!
//! The V1 descriptor remains the signed mutation identity. V2 replaces only the mutable state
//! codec so an old `Complete` record can never be confused with point publication or abort.

#![allow(
    dead_code,
    reason = "the V2 codec is wired into the journal writer in the next D3-C slice"
)]

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use collection::shards::shard::PeerId;
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PrivateOramIndexKindV2, PrivateOramPointOperationKindV1, PrivateOramVisiblePointRecordV1,
    private_oram_no_server_point_record_v1_digest, private_oram_visible_point_record_v1_digest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::consensus_ops::{
    PrivateOramMutationLease, PrivateOramMutationLeasePhase,
    canonical_private_oram_consensus_state_record_digest,
};
#[cfg(test)]
use super::private_oram_mutation_journal::derive_consensus_evidence;
use super::private_oram_mutation_journal::{
    MAX_STATE_BYTES, PrivateOramMutationConsensusEvidenceV1,
    PrivateOramMutationJournalDescriptorV1, PrivateOramMutationJournalError,
    PrivateOramMutationJournalStateV1, PrivateOramMutationOwnerPrepareEvidenceV1,
    PrivateOramMutationReconcileDispositionV1, expected_owner_recovery_authority_digest_v2,
    private_oram_point_id_digest, validate_consensus_evidence_shape, validate_owner_prepares,
    validate_state,
};
use super::private_oram_point_staging::PrivateOramDurablePointStageTokenV1;

pub(super) const PRIVATE_ORAM_MUTATION_STATE_V2_VERSION: u16 = 2;
pub(super) const PRIVATE_ORAM_POINT_RESOLUTION_RECEIPT_V2_VERSION: u16 = 1;

const STATE_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-mutation-parent-state/v2";
const OWNER_TERMINAL_EVIDENCE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-owner-terminal-evidence/v2";
const POINT_RESOLUTION_RECEIPT_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-point-resolution-receipt/v2";
const POINT_REPLICA_SET_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-point-replica-set/v2";
const COLLECTION_ID_DIGEST_DOMAIN_V2: &[u8] = b"qdrant-sec/private-oram-collection-id-digest/v2";
const MAX_POINT_RESOLUTION_OBSERVATIONS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PrivateOramMutationJournalPhaseV2 {
    LeaseAcquired,
    OwnersPrepared,
    PointStageDurable,
    DecisionDurable,
    RemotesTerminal,
    LocalTerminal,
    PointResolved,
}

impl PrivateOramMutationJournalPhaseV2 {
    pub(super) const fn sequence(self) -> u64 {
        match self {
            Self::LeaseAcquired => 1,
            Self::OwnersPrepared => 2,
            Self::PointStageDurable => 3,
            Self::DecisionDurable => 4,
            Self::RemotesTerminal => 5,
            Self::LocalTerminal => 6,
            Self::PointResolved => 7,
        }
    }

    const fn from_sequence(sequence: u64) -> Option<Self> {
        match sequence {
            1 => Some(Self::LeaseAcquired),
            2 => Some(Self::OwnersPrepared),
            3 => Some(Self::PointStageDurable),
            4 => Some(Self::DecisionDurable),
            5 => Some(Self::RemotesTerminal),
            6 => Some(Self::LocalTerminal),
            7 => Some(Self::PointResolved),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum PrivateOramMutationStatePredecessorV2 {
    Genesis,
    PreviousV2 {
        sequence: u64,
        phase: PrivateOramMutationJournalPhaseV2,
        record_digest: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum PrivateOramPointReplicaObservationV2 {
    Exact {
        shard_id: u32,
        peer_id: PeerId,
        point_semantic_digest: String,
    },
    Absent {
        shard_id: u32,
        peer_id: PeerId,
    },
}

impl PrivateOramPointReplicaObservationV2 {
    fn key(&self) -> (u32, PeerId) {
        match self {
            Self::Exact {
                shard_id, peer_id, ..
            }
            | Self::Absent { shard_id, peer_id } => (*shard_id, *peer_id),
        }
    }
}

impl Debug for PrivateOramPointReplicaObservationV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact {
                shard_id, peer_id, ..
            } => f
                .debug_struct("Exact")
                .field("shard_id", shard_id)
                .field("peer_id", peer_id)
                .field("point_semantic_digest", &"[redacted]")
                .finish(),
            Self::Absent { shard_id, peer_id } => f
                .debug_struct("Absent")
                .field("shard_id", shard_id)
                .field("peer_id", peer_id)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateOramPointReplicaTargetV2 {
    pub(super) shard_id: u32,
    pub(super) peer_id: PeerId,
}

impl PrivateOramPointReplicaTargetV2 {
    const fn key(&self) -> (u32, PeerId) {
        (self.shard_id, self.peer_id)
    }
}

impl Debug for PrivateOramPointReplicaTargetV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPointReplicaTargetV2")
            .field("shard_id", &self.shard_id)
            .field("peer_id", &self.peer_id)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateOramPointResolutionReceiptV2 {
    pub(super) version: u16,
    pub(super) collection_id_digest: String,
    pub(super) mutation_digest: String,
    pub(super) point_operation_digest: String,
    pub(super) child_descriptor_digest: String,
    pub(super) staged_insert_sha256: String,
    pub(super) canonical_point_id_digest: String,
    pub(super) layout_generation: u64,
    pub(super) layout_digest: String,
    pub(super) target_shard_ids: Vec<u32>,
    pub(super) replicas: Vec<PrivateOramPointReplicaTargetV2>,
    pub(super) replica_set_digest: String,
    pub(super) expected_point_semantic_digest: String,
    pub(super) observations: Vec<PrivateOramPointReplicaObservationV2>,
    pub(super) parent_local_terminal_record_digest: String,
    pub(super) receipt_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrivateOramPointResolutionOutcomeV2 {
    PublishedExactNew,
    AbortedExactOld,
}

impl Debug for PrivateOramPointResolutionReceiptV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramPointResolutionReceiptV2")
            .field("version", &self.version)
            .field("collection_id_digest", &"[redacted]")
            .field("mutation_digest", &"[redacted]")
            .field("point_operation_digest", &"[redacted]")
            .field("child_descriptor_digest", &"[redacted]")
            .field("staged_insert_sha256", &"[redacted]")
            .field("canonical_point_id_digest", &"[redacted]")
            .field("layout_generation", &self.layout_generation)
            .field("layout_digest", &"[redacted]")
            .field("target_shard_count", &self.target_shard_ids.len())
            .field("replica_count", &self.replicas.len())
            .field("replica_set_digest", &"[redacted]")
            .field("expected_point_semantic_digest", &"[redacted]")
            .field("observation_count", &self.observations.len())
            .field("parent_local_terminal_record_digest", &"[redacted]")
            .field("receipt_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum PrivateOramMutationStateOriginV2 {
    FreshV2,
    MigratedV1 {
        legacy_phase: super::private_oram_mutation_journal::PrivateOramMutationJournalPhaseV1,
        legacy_record_digest: String,
        legacy_state_file_sha256: String,
    },
}

impl Debug for PrivateOramMutationStateOriginV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::FreshV2 => f.write_str("FreshV2"),
            Self::MigratedV1 { legacy_phase, .. } => f
                .debug_struct("MigratedV1")
                .field("legacy_phase", legacy_phase)
                .field("legacy_record_digest", &"[redacted]")
                .field("legacy_state_file_sha256", &"[redacted]")
                .finish(),
        }
    }
}

impl Debug for PrivateOramMutationStatePredecessorV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Genesis => f.write_str("Genesis"),
            Self::PreviousV2 {
                sequence, phase, ..
            } => f
                .debug_struct("PreviousV2")
                .field("sequence", sequence)
                .field("phase", phase)
                .field("record_digest", &"[redacted]")
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum PrivateOramMutationPointStageEvidenceV2 {
    PrivateOramPointStaging {
        point_id: String,
        staged_insert_sha256: String,
        canonical_point_id_digest: String,
        point_semantic_digest: String,
        child_descriptor_digest: String,
        target_shard_ids: Vec<u32>,
        parent_owners_prepared_record_digest: String,
    },
    NoServerPointRecord {
        parent_owners_prepared_record_digest: String,
    },
}

pub(super) fn private_oram_point_stage_evidence_v2_from_durable_token(
    durable_stage: &PrivateOramDurablePointStageTokenV1,
) -> PrivateOramMutationPointStageEvidenceV2 {
    PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
        point_id: durable_stage.point_id().to_string(),
        staged_insert_sha256: durable_stage.frame_sha256().to_string(),
        canonical_point_id_digest: durable_stage.canonical_point_id_digest().to_string(),
        point_semantic_digest: durable_stage.point_semantic_digest().to_string(),
        child_descriptor_digest: durable_stage.child_descriptor_digest().to_string(),
        target_shard_ids: durable_stage.target_shard_ids().to_vec(),
        parent_owners_prepared_record_digest: durable_stage
            .parent_owners_prepared_record_digest()
            .to_string(),
    }
}

impl Debug for PrivateOramMutationPointStageEvidenceV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateOramPointStaging { .. } => {
                f.write_str("PrivateOramPointStaging([redacted])")
            }
            Self::NoServerPointRecord { .. } => f.write_str("NoServerPointRecord([redacted])"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PrivateOramMutationDecisionKindV2 {
    ExactNew,
    ExactOldAbort,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum PrivateOramMutationDecisionEvidenceV2 {
    ExactNew {
        consensus: PrivateOramMutationConsensusEvidenceV1,
        committed_lease: Box<PrivateOramMutationLease>,
    },
    ExactOldAbort {
        old_consensus_record_digest: String,
        old_consensus_state_sequence: u64,
        old_consensus_signed_state_digest: String,
        abort_decided_lease: Box<PrivateOramMutationLease>,
    },
}

impl PrivateOramMutationDecisionEvidenceV2 {
    pub(super) const fn kind(&self) -> PrivateOramMutationDecisionKindV2 {
        match self {
            Self::ExactNew { .. } => PrivateOramMutationDecisionKindV2::ExactNew,
            Self::ExactOldAbort { .. } => PrivateOramMutationDecisionKindV2::ExactOldAbort,
        }
    }

    pub(super) fn authority_record_digest(&self) -> &str {
        match self {
            Self::ExactNew { consensus, .. } => &consensus.committed_record_digest,
            Self::ExactOldAbort {
                old_consensus_record_digest,
                ..
            } => old_consensus_record_digest,
        }
    }

    pub(super) fn decided_lease(&self) -> &PrivateOramMutationLease {
        match self {
            Self::ExactNew {
                committed_lease, ..
            } => committed_lease,
            Self::ExactOldAbort {
                abort_decided_lease,
                ..
            } => abort_decided_lease,
        }
    }

    pub(super) const fn reconcile_disposition(&self) -> PrivateOramMutationReconcileDispositionV1 {
        match self {
            Self::ExactNew { .. } => PrivateOramMutationReconcileDispositionV1::ExactNew,
            Self::ExactOldAbort { .. } => {
                PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided
            }
        }
    }
}

impl Debug for PrivateOramMutationDecisionEvidenceV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactNew { .. } => f.write_str("ExactNew([redacted])"),
            Self::ExactOldAbort { .. } => f.write_str("ExactOldAbort([redacted])"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PrivateOramMutationOwnerTerminalKindV2 {
    FinalizedNew,
    AbortedOld,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateOramMutationOwnerTerminalIndexEvidenceV2 {
    pub(super) kind: PrivateOramIndexKindV2,
    pub(super) index_name: String,
    pub(super) prepared_journal_digest: String,
    pub(super) terminal_state_digest: String,
}

impl Debug for PrivateOramMutationOwnerTerminalIndexEvidenceV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnerTerminalIndexEvidenceV2")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("terminal_state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateOramMutationOwnerTerminalEvidenceV2 {
    pub(super) owner_peer_id: PeerId,
    pub(super) journal_descriptor_digest: String,
    pub(super) prepared_state_digest: String,
    pub(super) terminal_record_digest: String,
    pub(super) parent_descriptor_digest: String,
    pub(super) decision_authority_record_digest: String,
    pub(super) reconciliation_authority_digest: String,
    pub(super) indexes: Vec<PrivateOramMutationOwnerTerminalIndexEvidenceV2>,
    pub(super) terminal_evidence_digest: String,
}

impl Debug for PrivateOramMutationOwnerTerminalEvidenceV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnerTerminalEvidenceV2")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("journal_descriptor_digest", &"[redacted]")
            .field("prepared_state_digest", &"[redacted]")
            .field("terminal_record_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("decision_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .field("terminal_evidence_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateOramMutationOwnerTerminalBatchV2 {
    pub(super) kind: PrivateOramMutationOwnerTerminalKindV2,
    pub(super) owners: Vec<PrivateOramMutationOwnerTerminalEvidenceV2>,
}

impl Debug for PrivateOramMutationOwnerTerminalBatchV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnerTerminalBatchV2")
            .field("kind", &self.kind)
            .field("owner_count", &self.owners.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "evidence",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum PrivateOramMutationPointResolutionEvidenceV2 {
    PublishedExactNew {
        receipt: PrivateOramPointResolutionReceiptV2,
    },
    AbortedExactOld {
        receipt: PrivateOramPointResolutionReceiptV2,
    },
    NoServerPointRecord {
        decision_kind: PrivateOramMutationDecisionKindV2,
        parent_local_terminal_record_digest: String,
    },
}

impl Debug for PrivateOramMutationPointResolutionEvidenceV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublishedExactNew { .. } => f.write_str("PublishedExactNew([redacted])"),
            Self::AbortedExactOld { .. } => f.write_str("AbortedExactOld([redacted])"),
            Self::NoServerPointRecord { .. } => f.write_str("NoServerPointRecord([redacted])"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivateOramMutationJournalStateV2 {
    pub(super) version: u16,
    pub(super) sequence: u64,
    pub(super) phase: PrivateOramMutationJournalPhaseV2,
    pub(super) origin: PrivateOramMutationStateOriginV2,
    pub(super) predecessor: PrivateOramMutationStatePredecessorV2,
    pub(super) owner_prepares: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
    pub(super) point_stage: Option<PrivateOramMutationPointStageEvidenceV2>,
    pub(super) decision: Option<PrivateOramMutationDecisionEvidenceV2>,
    pub(super) remote_terminals: Option<PrivateOramMutationOwnerTerminalBatchV2>,
    pub(super) local_terminals: Option<PrivateOramMutationOwnerTerminalBatchV2>,
    pub(super) point_resolution: Option<PrivateOramMutationPointResolutionEvidenceV2>,
    pub(super) record_digest: String,
}

impl Debug for PrivateOramMutationJournalStateV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournalStateV2")
            .field("version", &self.version)
            .field("sequence", &self.sequence)
            .field("phase", &self.phase)
            .field("origin", &self.origin)
            .field("predecessor", &self.predecessor)
            .field("owner_prepare_count", &self.owner_prepares.len())
            .field("has_point_stage", &self.point_stage.is_some())
            .field("decision", &self.decision)
            .field(
                "remote_terminal_owner_count",
                &self
                    .remote_terminals
                    .as_ref()
                    .map(|batch| batch.owners.len()),
            )
            .field(
                "local_terminal_owner_count",
                &self
                    .local_terminals
                    .as_ref()
                    .map(|batch| batch.owners.len()),
            )
            .field("point_resolution", &self.point_resolution)
            .field("record_digest", &"[redacted]")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "the V2 writer consumes the dual decoder after explicit V1 cutover policy"
)]
/// Structurally valid disk data. V2 evidence is still untrusted until live resources are reopened.
pub(super) enum DecodedPrivateOramMutationStateUntrusted {
    V1(Box<PrivateOramMutationJournalStateV1>),
    UntrustedV2(Box<PrivateOramMutationJournalStateV2>),
}

#[derive(Deserialize)]
struct StateVersionProbe {
    version: u16,
}

#[allow(
    dead_code,
    reason = "the V2 writer consumes the dual decoder after explicit V1 cutover policy"
)]
pub(super) fn decode_untrusted_private_oram_mutation_state(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    bytes: &[u8],
) -> Result<DecodedPrivateOramMutationStateUntrusted, PrivateOramMutationJournalError> {
    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            > MAX_STATE_BYTES
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let probe: StateVersionProbe =
        serde_json::from_slice(bytes).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    match probe.version {
        1 => {
            let state: PrivateOramMutationJournalStateV1 = serde_json::from_slice(bytes)
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
            validate_state(descriptor, &state)?;
            Ok(DecodedPrivateOramMutationStateUntrusted::V1(Box::new(
                state,
            )))
        }
        PRIVATE_ORAM_MUTATION_STATE_V2_VERSION => {
            let state: PrivateOramMutationJournalStateV2 = serde_json::from_slice(bytes)
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
            validate_private_oram_mutation_state_v2_structure(descriptor, &state)?;
            Ok(DecodedPrivateOramMutationStateUntrusted::UntrustedV2(
                Box::new(state),
            ))
        }
        _ => Err(PrivateOramMutationJournalError::Corrupt),
    }
}

#[cfg(test)]
pub(super) fn exact_new_decision_v2_for_test(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    committed_lease: &PrivateOramMutationLease,
    committed_state: &super::consensus_ops::PrivateOramConsensusCollectionStateV2,
) -> Result<PrivateOramMutationDecisionEvidenceV2, PrivateOramMutationJournalError> {
    Ok(PrivateOramMutationDecisionEvidenceV2::ExactNew {
        consensus: derive_consensus_evidence(descriptor, committed_lease, committed_state)?,
        committed_lease: Box::new(committed_lease.clone()),
    })
}

#[cfg(test)]
pub(super) fn exact_old_abort_decision_v2_for_test(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    abort_decided_lease: &PrivateOramMutationLease,
    old_consensus: &super::consensus_ops::PrivateOramConsensusCollectionStateV2,
) -> Result<PrivateOramMutationDecisionEvidenceV2, PrivateOramMutationJournalError> {
    if old_consensus != &descriptor.expected_consensus_old_state {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    validate_abort_decided_lease(descriptor, abort_decided_lease)?;
    Ok(PrivateOramMutationDecisionEvidenceV2::ExactOldAbort {
        old_consensus_record_digest: canonical_private_oram_consensus_state_record_digest(
            old_consensus,
        )
        .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?,
        old_consensus_state_sequence: old_consensus.state_sequence,
        old_consensus_signed_state_digest: old_consensus.signed_state_digest.clone(),
        abort_decided_lease: Box::new(abort_decided_lease.clone()),
    })
}

pub(super) fn private_oram_owner_terminal_evidence_v2_digest(
    descriptor_digest: &str,
    kind: PrivateOramMutationOwnerTerminalKindV2,
    evidence: &PrivateOramMutationOwnerTerminalEvidenceV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_TERMINAL_EVIDENCE_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, descriptor_digest)?;
    hasher.update([owner_terminal_kind_tag(kind)]);
    hasher.update(evidence.owner_peer_id.to_be_bytes());
    hash_digest(&mut hasher, &evidence.journal_descriptor_digest)?;
    hash_digest(&mut hasher, &evidence.prepared_state_digest)?;
    hash_digest(&mut hasher, &evidence.terminal_record_digest)?;
    hash_digest(&mut hasher, &evidence.parent_descriptor_digest)?;
    hash_digest(&mut hasher, &evidence.decision_authority_record_digest)?;
    hash_digest(&mut hasher, &evidence.reconciliation_authority_digest)?;
    hash_len(&mut hasher, evidence.indexes.len())?;
    for index in &evidence.indexes {
        hasher.update([index_kind_tag(index.kind)]);
        hash_string(&mut hasher, &index.index_name)?;
        hash_digest(&mut hasher, &index.prepared_journal_digest)?;
        hash_digest(&mut hasher, &index.terminal_state_digest)?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

/// Validates the canonical on-disk shape and parent-derived authority bindings.
///
/// Terminal child files and point replicas remain live resources. A coordinator must re-open
/// those resources and compare them with this state before using it as cleanup or clear authority.
pub(super) fn validate_private_oram_mutation_state_v2_structure(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    let rank = state.phase.sequence();
    if state.version != PRIVATE_ORAM_MUTATION_STATE_V2_VERSION
        || state.sequence != rank
        || !matches!(state.origin, PrivateOramMutationStateOriginV2::FreshV2)
        || !is_sha256_digest(&state.record_digest)
        || (rank >= 2) == state.owner_prepares.is_empty()
        || (rank >= 3) != state.point_stage.is_some()
        || (rank >= 4) != state.decision.is_some()
        || (rank >= 5) != state.remote_terminals.is_some()
        || (rank >= 6) != state.local_terminals.is_some()
        || (rank >= 7) != state.point_resolution.is_some()
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if rank >= 2 {
        validate_owner_prepares(descriptor, &state.owner_prepares)?;
    }
    if let Some(point_stage) = &state.point_stage {
        validate_point_stage_v2(descriptor, point_stage)?;
    }
    if let Some(decision) = &state.decision {
        validate_decision_v2(descriptor, decision)?;
    }
    if let Some(batch) = &state.remote_terminals {
        validate_terminal_batch_v2(descriptor, state, batch, false)?;
    }
    if let Some(batch) = &state.local_terminals {
        validate_terminal_batch_v2(descriptor, state, batch, true)?;
    }

    let canonical_chain = canonical_state_chain_v2(descriptor, state)?;
    if canonical_chain.last() != Some(state) {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if let Some(point_stage) = &state.point_stage {
        let owners_prepared = canonical_chain
            .get(1)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if point_stage_parent_record_digest(point_stage) != owners_prepared.record_digest {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    if let Some(point_resolution) = &state.point_resolution {
        let local_terminal = canonical_chain
            .get(5)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        validate_point_resolution_v2(
            descriptor,
            state,
            point_resolution,
            &local_terminal.record_digest,
        )?;
    }
    Ok(())
}

fn validate_point_stage_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    evidence: &PrivateOramMutationPointStageEvidenceV2,
) -> Result<(), PrivateOramMutationJournalError> {
    let mutation = &descriptor.mutation_bundle.mutation;
    let (kind, digest) = match evidence {
        PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
            point_id,
            staged_insert_sha256,
            canonical_point_id_digest,
            point_semantic_digest,
            child_descriptor_digest,
            target_shard_ids,
            parent_owners_prepared_record_digest,
        } => {
            if !is_sha256_digest(staged_insert_sha256)
                || !is_sha256_digest(canonical_point_id_digest)
                || !is_sha256_digest(point_semantic_digest)
                || !is_sha256_digest(child_descriptor_digest)
                || !is_sha256_digest(parent_owners_prepared_record_digest)
                || target_shard_ids.is_empty()
                || target_shard_ids.windows(2).any(|pair| pair[0] >= pair[1])
                || canonical_point_id_digest != &private_oram_point_id_digest(point_id)?
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            (
                PrivateOramPointOperationKindV1::VisiblePointRecord,
                private_oram_visible_point_record_v1_digest(
                    &mutation.collection_id,
                    &mutation.manifest_digest,
                    &mutation.mutation_id,
                    PrivateOramVisiblePointRecordV1 {
                        point_id,
                        staged_insert_sha256,
                    },
                )?,
            )
        }
        PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        } => {
            if !is_sha256_digest(parent_owners_prepared_record_digest) {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            (
                PrivateOramPointOperationKindV1::NoServerPointRecord,
                private_oram_no_server_point_record_v1_digest(
                    &mutation.collection_id,
                    &mutation.manifest_digest,
                    &mutation.mutation_id,
                )?,
            )
        }
    };
    if mutation.point_operation_kind != kind || mutation.point_operation_digest != digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_decision_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    decision: &PrivateOramMutationDecisionEvidenceV2,
) -> Result<(), PrivateOramMutationJournalError> {
    match decision {
        PrivateOramMutationDecisionEvidenceV2::ExactNew {
            consensus,
            committed_lease,
        } => {
            validate_consensus_evidence_shape(descriptor, consensus)?;
            validate_committed_lease(descriptor, committed_lease, consensus)
        }
        PrivateOramMutationDecisionEvidenceV2::ExactOldAbort {
            old_consensus_record_digest,
            old_consensus_state_sequence,
            old_consensus_signed_state_digest,
            abort_decided_lease,
        } => {
            let old = &descriptor.expected_consensus_old_state;
            let expected_record_digest = canonical_private_oram_consensus_state_record_digest(old)
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
            if old_consensus_record_digest != &expected_record_digest
                || old_consensus_state_sequence != &old.state_sequence
                || old_consensus_signed_state_digest != &old.signed_state_digest
            {
                return Err(PrivateOramMutationJournalError::Corrupt);
            }
            validate_abort_decided_lease(descriptor, abort_decided_lease)
        }
    }
}

fn validate_abort_decided_lease(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    lease: &PrivateOramMutationLease,
) -> Result<(), PrivateOramMutationJournalError> {
    let preparing = &descriptor.preparing_lease;
    if !matches!(lease.phase, PrivateOramMutationLeasePhase::AbortDecided)
        || lease.generation != preparing.generation
        || lease.collection_id != preparing.collection_id
        || lease.owner_peer_id != preparing.owner_peer_id
        || lease.mutation_id != preparing.mutation_id
        || lease.signed_mutation_digest != preparing.signed_mutation_digest
        || lease.transition_digest != preparing.transition_digest
        || lease.base_record_digest != preparing.base_record_digest
        || lease.base_state_sequence != preparing.base_state_sequence
        || lease.writer_lease_digest != preparing.writer_lease_digest
        || lease.writer_fence != preparing.writer_fence
        || lease.issued_at_unix != preparing.issued_at_unix
        || lease.expires_at_unix < preparing.expires_at_unix
        || lease.renewal_revision < preparing.renewal_revision
        || (lease.renewal_revision == preparing.renewal_revision
            && lease.expires_at_unix != preparing.expires_at_unix)
        || (lease.renewal_revision > preparing.renewal_revision
            && lease.expires_at_unix <= preparing.expires_at_unix)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_committed_lease(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    lease: &PrivateOramMutationLease,
    consensus: &PrivateOramMutationConsensusEvidenceV1,
) -> Result<(), PrivateOramMutationJournalError> {
    let preparing = &descriptor.preparing_lease;
    let PrivateOramMutationLeasePhase::ConsensusCommitted {
        committed_record_digest,
        committed_state_sequence,
        committed_signed_state_digest,
        receipt_digest,
    } = &lease.phase
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    if lease.generation != preparing.generation
        || lease.collection_id != preparing.collection_id
        || lease.owner_peer_id != preparing.owner_peer_id
        || lease.mutation_id != preparing.mutation_id
        || lease.signed_mutation_digest != preparing.signed_mutation_digest
        || lease.transition_digest != preparing.transition_digest
        || lease.base_record_digest != preparing.base_record_digest
        || lease.base_state_sequence != preparing.base_state_sequence
        || lease.writer_lease_digest != preparing.writer_lease_digest
        || lease.writer_fence != preparing.writer_fence
        || lease.issued_at_unix != preparing.issued_at_unix
        || lease.expires_at_unix < preparing.expires_at_unix
        || lease.renewal_revision < preparing.renewal_revision
        || (lease.renewal_revision == preparing.renewal_revision
            && lease.expires_at_unix != preparing.expires_at_unix)
        || (lease.renewal_revision > preparing.renewal_revision
            && lease.expires_at_unix <= preparing.expires_at_unix)
        || committed_record_digest != &consensus.committed_record_digest
        || committed_state_sequence != &consensus.committed_state_sequence
        || committed_signed_state_digest != &consensus.committed_signed_state_digest
        || receipt_digest != &consensus.receipt_digest
        || lease.renewal_revision != consensus.lease_renewal_revision
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validate_terminal_batch_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    batch: &PrivateOramMutationOwnerTerminalBatchV2,
    local: bool,
) -> Result<(), PrivateOramMutationJournalError> {
    let decision = state
        .decision
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    let expected_kind = match decision.kind() {
        PrivateOramMutationDecisionKindV2::ExactNew => {
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew
        }
        PrivateOramMutationDecisionKindV2::ExactOldAbort => {
            PrivateOramMutationOwnerTerminalKindV2::AbortedOld
        }
    };
    let expected_peers = descriptor
        .owner_requirements
        .iter()
        .filter(|requirement| (requirement.peer_id == descriptor.coordinator_peer_id) == local)
        .map(|requirement| requirement.peer_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if batch.kind != expected_kind
        || batch.owners.len() != expected_peers.len()
        || batch
            .owners
            .windows(2)
            .any(|pair| pair[0].owner_peer_id >= pair[1].owner_peer_id)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for (owner, expected_peer_id) in batch.owners.iter().zip(expected_peers) {
        let (expected_consensus_authority, expected_reconciliation_authority) =
            expected_owner_recovery_authority_digest_v2(
                descriptor,
                state,
                decision.decided_lease(),
                decision.reconcile_disposition(),
                expected_peer_id,
            )?;
        if owner.owner_peer_id != expected_peer_id
            || owner.parent_descriptor_digest != descriptor.descriptor_digest
            || owner.decision_authority_record_digest != expected_consensus_authority
            || owner.reconciliation_authority_digest != expected_reconciliation_authority
            || !is_sha256_digest(&owner.journal_descriptor_digest)
            || !is_sha256_digest(&owner.prepared_state_digest)
            || !is_sha256_digest(&owner.terminal_record_digest)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let requirements = descriptor
            .owner_requirements
            .iter()
            .filter(|requirement| requirement.peer_id == expected_peer_id)
            .collect::<Vec<_>>();
        if owner.indexes.len() != requirements.len()
            || owner
                .indexes
                .windows(2)
                .any(|pair| terminal_index_order(&pair[0], &pair[1]) != Ordering::Less)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        for (index, requirement) in owner.indexes.iter().zip(requirements) {
            let prepared = state.owner_prepares.iter().find(|prepared| {
                prepared.peer_id == expected_peer_id
                    && prepared.kind == index.kind
                    && prepared.index_name == index.index_name
            });
            if requirement.kind != index.kind
                || requirement.index_name != index.index_name
                || prepared.is_none_or(|prepared| {
                    prepared.prepared_journal_digest != index.prepared_journal_digest
                })
                || !is_sha256_digest(&index.terminal_state_digest)
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
        if owner.terminal_evidence_digest
            != private_oram_owner_terminal_evidence_v2_digest(
                &descriptor.descriptor_digest,
                batch.kind,
                owner,
            )?
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok(())
}

fn validate_point_resolution_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    evidence: &PrivateOramMutationPointResolutionEvidenceV2,
    expected_local_terminal_record_digest: &str,
) -> Result<(), PrivateOramMutationJournalError> {
    let point_stage = state
        .point_stage
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    let decision = state
        .decision
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    match (point_stage, decision.kind(), evidence) {
        (
            PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging { .. },
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationPointResolutionEvidenceV2::PublishedExactNew { receipt },
        ) => validate_point_resolution_receipt_v2(
            descriptor,
            point_stage,
            receipt,
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            expected_local_terminal_record_digest,
        )?,
        (
            PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging { .. },
            PrivateOramMutationDecisionKindV2::ExactOldAbort,
            PrivateOramMutationPointResolutionEvidenceV2::AbortedExactOld { receipt },
        ) => validate_point_resolution_receipt_v2(
            descriptor,
            point_stage,
            receipt,
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld,
            expected_local_terminal_record_digest,
        )?,
        (
            PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord { .. },
            expected_kind,
            PrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
                decision_kind,
                parent_local_terminal_record_digest,
            },
        ) if *decision_kind == expected_kind
            && parent_local_terminal_record_digest == expected_local_terminal_record_digest => {}
        _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
    }
    Ok(())
}

fn validate_point_resolution_receipt_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    point_stage: &PrivateOramMutationPointStageEvidenceV2,
    receipt: &PrivateOramPointResolutionReceiptV2,
    outcome: PrivateOramPointResolutionOutcomeV2,
    expected_local_terminal_record_digest: &str,
) -> Result<(), PrivateOramMutationJournalError> {
    let PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
        staged_insert_sha256,
        canonical_point_id_digest,
        point_semantic_digest,
        child_descriptor_digest,
        target_shard_ids,
        ..
    } = point_stage
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let mutation = &descriptor.mutation_bundle.mutation;
    if receipt.version != PRIVATE_ORAM_POINT_RESOLUTION_RECEIPT_V2_VERSION
        || receipt.collection_id_digest
            != private_oram_collection_id_digest_v2(&mutation.collection_id)?
        || receipt.mutation_digest != descriptor.mutation_digest
        || receipt.point_operation_digest != mutation.point_operation_digest
        || receipt.child_descriptor_digest.as_str() != child_descriptor_digest
        || receipt.staged_insert_sha256.as_str() != staged_insert_sha256
        || receipt.canonical_point_id_digest.as_str() != canonical_point_id_digest
        || receipt.expected_point_semantic_digest.as_str() != point_semantic_digest
        || receipt.layout_generation != mutation.layout_generation
        || receipt.layout_digest != mutation.new_state.state.layout_digest
        || receipt.target_shard_ids.as_slice() != target_shard_ids.as_slice()
        || receipt.parent_local_terminal_record_digest != expected_local_terminal_record_digest
        || receipt.target_shard_ids.is_empty()
        || receipt
            .target_shard_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || !is_sha256_digest(&receipt.replica_set_digest)
        || receipt.replicas.is_empty()
        || receipt.replicas.len() > MAX_POINT_RESOLUTION_OBSERVATIONS
        || receipt
            .replicas
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
        || receipt.observations.is_empty()
        || receipt.observations.len() > MAX_POINT_RESOLUTION_OBSERVATIONS
        || receipt
            .observations
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let target_shards = receipt
        .target_shard_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let replica_shards = receipt
        .replicas
        .iter()
        .map(PrivateOramPointReplicaTargetV2::key)
        .map(|(shard_id, _)| shard_id)
        .collect::<BTreeSet<_>>();
    if replica_shards != target_shards
        || receipt.observations.len() != receipt.replicas.len()
        || receipt
            .observations
            .iter()
            .map(PrivateOramPointReplicaObservationV2::key)
            .ne(receipt
                .replicas
                .iter()
                .map(PrivateOramPointReplicaTargetV2::key))
        || receipt.replica_set_digest
            != private_oram_point_replica_set_digest_v2(&receipt.replicas)?
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    match outcome {
        PrivateOramPointResolutionOutcomeV2::PublishedExactNew => {
            let expected_semantic_digest = receipt.expected_point_semantic_digest.as_str();
            if !is_sha256_digest(expected_semantic_digest)
                || receipt.observations.iter().any(|observation| {
                    !matches!(
                        observation,
                        PrivateOramPointReplicaObservationV2::Exact {
                            point_semantic_digest,
                            ..
                        } if point_semantic_digest == expected_semantic_digest
                    )
                })
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
        PrivateOramPointResolutionOutcomeV2::AbortedExactOld => {
            if !is_sha256_digest(&receipt.expected_point_semantic_digest)
                || receipt.observations.iter().any(|observation| {
                    !matches!(
                        observation,
                        PrivateOramPointReplicaObservationV2::Absent { .. }
                    )
                })
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
    }
    if receipt.receipt_digest != private_oram_point_resolution_receipt_v2_digest(outcome, receipt)?
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

pub(super) fn private_oram_point_resolution_receipt_v2_digest(
    outcome: PrivateOramPointResolutionOutcomeV2,
    receipt: &PrivateOramPointResolutionReceiptV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(POINT_RESOLUTION_RECEIPT_DIGEST_DOMAIN_V2);
    hasher.update(receipt.version.to_be_bytes());
    hasher.update([match outcome {
        PrivateOramPointResolutionOutcomeV2::PublishedExactNew => 1,
        PrivateOramPointResolutionOutcomeV2::AbortedExactOld => 2,
    }]);
    hash_digest(&mut hasher, &receipt.collection_id_digest)?;
    hash_digest(&mut hasher, &receipt.mutation_digest)?;
    hash_digest(&mut hasher, &receipt.point_operation_digest)?;
    hash_digest(&mut hasher, &receipt.child_descriptor_digest)?;
    hash_digest(&mut hasher, &receipt.staged_insert_sha256)?;
    hash_digest(&mut hasher, &receipt.canonical_point_id_digest)?;
    hasher.update(receipt.layout_generation.to_be_bytes());
    hash_digest(&mut hasher, &receipt.layout_digest)?;
    hash_len(&mut hasher, receipt.target_shard_ids.len())?;
    for shard_id in &receipt.target_shard_ids {
        hasher.update(shard_id.to_be_bytes());
    }
    hash_len(&mut hasher, receipt.replicas.len())?;
    for replica in &receipt.replicas {
        hasher.update(replica.shard_id.to_be_bytes());
        hasher.update(replica.peer_id.to_be_bytes());
    }
    hash_digest(&mut hasher, &receipt.replica_set_digest)?;
    hash_digest(&mut hasher, &receipt.expected_point_semantic_digest)?;
    hash_len(&mut hasher, receipt.observations.len())?;
    for observation in &receipt.observations {
        match observation {
            PrivateOramPointReplicaObservationV2::Exact {
                shard_id,
                peer_id,
                point_semantic_digest,
            } => {
                hasher.update([1]);
                hasher.update(shard_id.to_be_bytes());
                hasher.update(peer_id.to_be_bytes());
                hash_digest(&mut hasher, point_semantic_digest)?;
            }
            PrivateOramPointReplicaObservationV2::Absent { shard_id, peer_id } => {
                hasher.update([2]);
                hasher.update(shard_id.to_be_bytes());
                hasher.update(peer_id.to_be_bytes());
            }
        }
    }
    hash_digest(&mut hasher, &receipt.parent_local_terminal_record_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(super) fn private_oram_point_replica_set_digest_v2(
    replicas: &[PrivateOramPointReplicaTargetV2],
) -> Result<String, PrivateOramMutationJournalError> {
    if replicas.is_empty()
        || replicas.len() > MAX_POINT_RESOLUTION_OBSERVATIONS
        || replicas
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut hasher = Sha256::new();
    hasher.update(POINT_REPLICA_SET_DIGEST_DOMAIN_V2);
    hash_len(&mut hasher, replicas.len())?;
    for replica in replicas {
        hasher.update(replica.shard_id.to_be_bytes());
        hasher.update(replica.peer_id.to_be_bytes());
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(super) fn private_oram_collection_id_digest_v2(
    collection_id: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(COLLECTION_ID_DIGEST_DOMAIN_V2);
    hash_string(&mut hasher, collection_id)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn canonical_state_chain_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    source: &PrivateOramMutationJournalStateV2,
) -> Result<Vec<PrivateOramMutationJournalStateV2>, PrivateOramMutationJournalError> {
    let mut chain = Vec::with_capacity(source.phase.sequence() as usize);
    for sequence in 1..=source.phase.sequence() {
        let phase = PrivateOramMutationJournalPhaseV2::from_sequence(sequence)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let predecessor = chain.last().map_or(
            PrivateOramMutationStatePredecessorV2::Genesis,
            |previous: &PrivateOramMutationJournalStateV2| {
                PrivateOramMutationStatePredecessorV2::PreviousV2 {
                    sequence: previous.sequence,
                    phase: previous.phase,
                    record_digest: previous.record_digest.clone(),
                }
            },
        );
        let mut candidate = source.clone();
        candidate.version = PRIVATE_ORAM_MUTATION_STATE_V2_VERSION;
        candidate.sequence = sequence;
        candidate.phase = phase;
        candidate.predecessor = predecessor;
        if sequence < 2 {
            candidate.owner_prepares.clear();
        }
        if sequence < 3 {
            candidate.point_stage = None;
        }
        if sequence < 4 {
            candidate.decision = None;
        }
        if sequence < 5 {
            candidate.remote_terminals = None;
        }
        if sequence < 6 {
            candidate.local_terminals = None;
        }
        if sequence < 7 {
            candidate.point_resolution = None;
        }
        candidate.record_digest.clear();
        candidate.record_digest =
            state_record_digest_v2(&descriptor.descriptor_digest, &candidate)?;
        chain.push(candidate);
    }
    Ok(chain)
}

pub(super) fn initial_private_oram_mutation_state_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<PrivateOramMutationJournalStateV2, PrivateOramMutationJournalError> {
    let mut state = PrivateOramMutationJournalStateV2 {
        version: PRIVATE_ORAM_MUTATION_STATE_V2_VERSION,
        sequence: PrivateOramMutationJournalPhaseV2::LeaseAcquired.sequence(),
        phase: PrivateOramMutationJournalPhaseV2::LeaseAcquired,
        origin: PrivateOramMutationStateOriginV2::FreshV2,
        predecessor: PrivateOramMutationStatePredecessorV2::Genesis,
        owner_prepares: Vec::new(),
        point_stage: None,
        decision: None,
        remote_terminals: None,
        local_terminals: None,
        point_resolution: None,
        record_digest: String::new(),
    };
    state.record_digest = state_record_digest_v2(&descriptor.descriptor_digest, &state)?;
    validate_private_oram_mutation_state_v2_structure(descriptor, &state)?;
    Ok(state)
}

pub(super) fn next_private_oram_mutation_state_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    current: &PrivateOramMutationJournalStateV2,
    phase: PrivateOramMutationJournalPhaseV2,
    update: impl FnOnce(
        &mut PrivateOramMutationJournalStateV2,
    ) -> Result<(), PrivateOramMutationJournalError>,
) -> Result<PrivateOramMutationJournalStateV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_state_v2_structure(descriptor, current)?;
    if phase.sequence() != current.sequence + 1 {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let mut next = current.clone();
    next.sequence = phase.sequence();
    next.phase = phase;
    next.predecessor = PrivateOramMutationStatePredecessorV2::PreviousV2 {
        sequence: current.sequence,
        phase: current.phase,
        record_digest: current.record_digest.clone(),
    };
    update(&mut next)?;
    next.record_digest.clear();
    next.record_digest = state_record_digest_v2(&descriptor.descriptor_digest, &next)?;
    validate_private_oram_mutation_state_v2_structure(descriptor, &next)?;
    Ok(next)
}

pub(super) fn canonical_private_oram_mutation_state_history_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    source: &PrivateOramMutationJournalStateV2,
) -> Result<Vec<PrivateOramMutationJournalStateV2>, PrivateOramMutationJournalError> {
    canonical_state_chain_v2(descriptor, source)
}

pub(super) fn record_digest_at_phase_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    phase: PrivateOramMutationJournalPhaseV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let history = canonical_state_chain_v2(descriptor, state)?;
    let index = usize::try_from(
        phase
            .sequence()
            .checked_sub(1)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?,
    )
    .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    history
        .get(index)
        .map(|predecessor| predecessor.record_digest.clone())
        .ok_or(PrivateOramMutationJournalError::Corrupt)
}

#[cfg(test)]
pub(super) fn canonical_private_oram_mutation_state_v2_for_test(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    source: &PrivateOramMutationJournalStateV2,
) -> Result<PrivateOramMutationJournalStateV2, PrivateOramMutationJournalError> {
    canonical_state_chain_v2(descriptor, source)?
        .pop()
        .ok_or(PrivateOramMutationJournalError::Corrupt)
}

#[cfg(test)]
pub(super) fn state_record_digest_v2_for_test(
    descriptor_digest: &str,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    state_record_digest_v2(descriptor_digest, state)
}

fn state_record_digest_v2(
    descriptor_digest: &str,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(STATE_DIGEST_DOMAIN_V2);
    hash_digest(&mut hasher, descriptor_digest)?;
    hasher.update(state.version.to_be_bytes());
    hasher.update(state.sequence.to_be_bytes());
    hasher.update([state.phase.sequence() as u8]);
    hash_origin(&mut hasher, &state.origin)?;
    hash_predecessor(&mut hasher, &state.predecessor)?;
    hash_len(&mut hasher, state.owner_prepares.len())?;
    for prepared in &state.owner_prepares {
        hasher.update(prepared.peer_id.to_be_bytes());
        hasher.update([index_kind_tag(prepared.kind)]);
        hash_string(&mut hasher, &prepared.index_name)?;
        hash_digest(&mut hasher, &prepared.prepared_journal_digest)?;
    }
    hash_point_stage(&mut hasher, state.point_stage.as_ref())?;
    hash_decision(&mut hasher, state.decision.as_ref())?;
    hash_terminal_batch(&mut hasher, state.remote_terminals.as_ref())?;
    hash_terminal_batch(&mut hasher, state.local_terminals.as_ref())?;
    hash_point_resolution(&mut hasher, state.point_resolution.as_ref())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn hash_predecessor(
    hasher: &mut Sha256,
    predecessor: &PrivateOramMutationStatePredecessorV2,
) -> Result<(), PrivateOramMutationJournalError> {
    match predecessor {
        PrivateOramMutationStatePredecessorV2::Genesis => hasher.update([0]),
        PrivateOramMutationStatePredecessorV2::PreviousV2 {
            sequence,
            phase,
            record_digest,
        } => {
            hasher.update([1]);
            hasher.update(sequence.to_be_bytes());
            hasher.update([phase.sequence() as u8]);
            hash_digest(hasher, record_digest)?;
        }
    }
    Ok(())
}

fn hash_origin(
    hasher: &mut Sha256,
    origin: &PrivateOramMutationStateOriginV2,
) -> Result<(), PrivateOramMutationJournalError> {
    match origin {
        PrivateOramMutationStateOriginV2::FreshV2 => hasher.update([1]),
        PrivateOramMutationStateOriginV2::MigratedV1 {
            legacy_phase,
            legacy_record_digest,
            legacy_state_file_sha256,
        } => {
            hasher.update([2, legacy_phase.sequence() as u8]);
            hash_digest(hasher, legacy_record_digest)?;
            hash_digest(hasher, legacy_state_file_sha256)?;
        }
    }
    Ok(())
}

fn hash_point_stage(
    hasher: &mut Sha256,
    evidence: Option<&PrivateOramMutationPointStageEvidenceV2>,
) -> Result<(), PrivateOramMutationJournalError> {
    match evidence {
        None => hasher.update([0]),
        Some(PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
            point_id,
            staged_insert_sha256,
            canonical_point_id_digest,
            point_semantic_digest,
            child_descriptor_digest,
            target_shard_ids,
            parent_owners_prepared_record_digest,
        }) => {
            hasher.update([1]);
            hash_string(hasher, point_id)?;
            hash_digest(hasher, staged_insert_sha256)?;
            hash_digest(hasher, canonical_point_id_digest)?;
            hash_digest(hasher, point_semantic_digest)?;
            hash_digest(hasher, child_descriptor_digest)?;
            hash_len(hasher, target_shard_ids.len())?;
            for shard_id in target_shard_ids {
                hasher.update(shard_id.to_be_bytes());
            }
            hash_digest(hasher, parent_owners_prepared_record_digest)?;
        }
        Some(PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        }) => {
            hasher.update([2]);
            hash_digest(hasher, parent_owners_prepared_record_digest)?;
        }
    }
    Ok(())
}

fn hash_decision(
    hasher: &mut Sha256,
    decision: Option<&PrivateOramMutationDecisionEvidenceV2>,
) -> Result<(), PrivateOramMutationJournalError> {
    match decision {
        None => hasher.update([0]),
        Some(PrivateOramMutationDecisionEvidenceV2::ExactNew {
            consensus,
            committed_lease,
        }) => {
            hasher.update([1]);
            hash_digest(hasher, &consensus.committed_record_digest)?;
            hasher.update(consensus.committed_state_sequence.to_be_bytes());
            hash_digest(hasher, &consensus.committed_signed_state_digest)?;
            hash_digest(hasher, &consensus.receipt_digest)?;
            hash_digest(hasher, &consensus.transition_digest)?;
            hasher.update(consensus.lease_renewal_revision.to_be_bytes());
            hash_active_lease(hasher, committed_lease)?;
        }
        Some(PrivateOramMutationDecisionEvidenceV2::ExactOldAbort {
            old_consensus_record_digest,
            old_consensus_state_sequence,
            old_consensus_signed_state_digest,
            abort_decided_lease,
        }) => {
            hasher.update([2]);
            hash_digest(hasher, old_consensus_record_digest)?;
            hasher.update(old_consensus_state_sequence.to_be_bytes());
            hash_digest(hasher, old_consensus_signed_state_digest)?;
            hash_active_lease(hasher, abort_decided_lease)?;
        }
    }
    Ok(())
}

fn hash_terminal_batch(
    hasher: &mut Sha256,
    batch: Option<&PrivateOramMutationOwnerTerminalBatchV2>,
) -> Result<(), PrivateOramMutationJournalError> {
    let Some(batch) = batch else {
        hasher.update([0]);
        return Ok(());
    };
    hasher.update([1, owner_terminal_kind_tag(batch.kind)]);
    hash_len(hasher, batch.owners.len())?;
    for owner in &batch.owners {
        hasher.update(owner.owner_peer_id.to_be_bytes());
        hash_digest(hasher, &owner.journal_descriptor_digest)?;
        hash_digest(hasher, &owner.prepared_state_digest)?;
        hash_digest(hasher, &owner.terminal_record_digest)?;
        hash_digest(hasher, &owner.parent_descriptor_digest)?;
        hash_digest(hasher, &owner.decision_authority_record_digest)?;
        hash_digest(hasher, &owner.reconciliation_authority_digest)?;
        hash_len(hasher, owner.indexes.len())?;
        for index in &owner.indexes {
            hasher.update([index_kind_tag(index.kind)]);
            hash_string(hasher, &index.index_name)?;
            hash_digest(hasher, &index.prepared_journal_digest)?;
            hash_digest(hasher, &index.terminal_state_digest)?;
        }
        hash_digest(hasher, &owner.terminal_evidence_digest)?;
    }
    Ok(())
}

fn hash_point_resolution(
    hasher: &mut Sha256,
    evidence: Option<&PrivateOramMutationPointResolutionEvidenceV2>,
) -> Result<(), PrivateOramMutationJournalError> {
    match evidence {
        None => hasher.update([0]),
        Some(PrivateOramMutationPointResolutionEvidenceV2::PublishedExactNew { receipt }) => {
            hasher.update([1]);
            hash_digest(hasher, &receipt.receipt_digest)?;
        }
        Some(PrivateOramMutationPointResolutionEvidenceV2::AbortedExactOld { receipt }) => {
            hasher.update([2]);
            hash_digest(hasher, &receipt.receipt_digest)?;
        }
        Some(PrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
            decision_kind,
            parent_local_terminal_record_digest,
        }) => {
            hasher.update([3, decision_kind_tag(*decision_kind)]);
            hash_digest(hasher, parent_local_terminal_record_digest)?;
        }
    }
    Ok(())
}

fn hash_active_lease(
    hasher: &mut Sha256,
    lease: &PrivateOramMutationLease,
) -> Result<(), PrivateOramMutationJournalError> {
    hasher.update(lease.generation.to_be_bytes());
    hash_string(hasher, &lease.collection_id)?;
    hasher.update(lease.owner_peer_id.to_be_bytes());
    hash_digest(hasher, &lease.mutation_id)?;
    hash_digest(hasher, &lease.signed_mutation_digest)?;
    hash_digest(hasher, &lease.transition_digest)?;
    hash_digest(hasher, &lease.base_record_digest)?;
    hasher.update(lease.base_state_sequence.to_be_bytes());
    hash_digest(hasher, &lease.writer_lease_digest)?;
    hasher.update(lease.writer_fence.to_be_bytes());
    hasher.update(lease.issued_at_unix.to_be_bytes());
    hasher.update(lease.expires_at_unix.to_be_bytes());
    hasher.update(lease.renewal_revision.to_be_bytes());
    match &lease.phase {
        PrivateOramMutationLeasePhase::Preparing => hasher.update([1]),
        PrivateOramMutationLeasePhase::AbortDecided => hasher.update([2]),
        PrivateOramMutationLeasePhase::ConsensusCommitted {
            committed_record_digest,
            committed_state_sequence,
            committed_signed_state_digest,
            receipt_digest,
        } => {
            hasher.update([3]);
            hash_digest(hasher, committed_record_digest)?;
            hasher.update(committed_state_sequence.to_be_bytes());
            hash_digest(hasher, committed_signed_state_digest)?;
            hash_digest(hasher, receipt_digest)?;
        }
    }
    Ok(())
}

fn point_stage_parent_record_digest(evidence: &PrivateOramMutationPointStageEvidenceV2) -> &str {
    match evidence {
        PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
            parent_owners_prepared_record_digest,
            ..
        }
        | PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        } => parent_owners_prepared_record_digest,
    }
}

fn terminal_index_order(
    left: &PrivateOramMutationOwnerTerminalIndexEvidenceV2,
    right: &PrivateOramMutationOwnerTerminalIndexEvidenceV2,
) -> Ordering {
    (index_kind_tag(left.kind), left.index_name.as_bytes())
        .cmp(&(index_kind_tag(right.kind), right.index_name.as_bytes()))
}

const fn decision_kind_tag(kind: PrivateOramMutationDecisionKindV2) -> u8 {
    match kind {
        PrivateOramMutationDecisionKindV2::ExactNew => 1,
        PrivateOramMutationDecisionKindV2::ExactOldAbort => 2,
    }
}

const fn owner_terminal_kind_tag(kind: PrivateOramMutationOwnerTerminalKindV2) -> u8 {
    match kind {
        PrivateOramMutationOwnerTerminalKindV2::FinalizedNew => 1,
        PrivateOramMutationOwnerTerminalKindV2::AbortedOld => 2,
    }
}

const fn index_kind_tag(kind: PrivateOramIndexKindV2) -> u8 {
    match kind {
        PrivateOramIndexKindV2::Hnsw => 1,
        PrivateOramIndexKindV2::Result => 2,
    }
}

fn hash_digest(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if decoded.len() != 32 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    hasher.update(decoded);
    Ok(())
}

fn hash_string(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let len = u64::try_from(value.len()).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    hasher.update(len.to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

fn hash_len(hasher: &mut Sha256, len: usize) -> Result<(), PrivateOramMutationJournalError> {
    let len = u64::try_from(len).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    hasher.update(len.to_be_bytes());
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    BASE64URL_NOPAD
        .decode(value.as_bytes())
        .is_ok_and(|decoded| decoded.len() == 32)
}
