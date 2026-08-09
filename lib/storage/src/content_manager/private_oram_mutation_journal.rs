use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::io::{self, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use collection::operations::types::{CollectionError, CollectionResult};
use collection::private_oram_owner_journal::{
    PrivateOramOwnerRecoveryIndexProjectionInputV1, PrivateOramOwnerRecoveryIndexProjectionV1,
    PrivateOramOwnerRecoveryProjectionV1,
};
use collection::shards::shard::PeerId;
use collection::{
    PrivateOramOwnerRecoveryPairOutcomeV1, PrivateOramOwnerRecoveryParentBridgeV1,
    PrivateOramOwnerRecoveryParentDispositionV1, PrivateOramOwnerRecoveryParentInputV1,
    PrivateOramOwnerRecoveryParentVerifierV1, PrivateOramOwnerRecoveryStoreDispositionV1,
    PrivateOramOwnerRecoveryStorePairResourcesV1, PrivateOramOwnerRecoveryTerminalEvidenceV1,
    classify_private_oram_owner_recovery_store_pair_v1,
    new_private_oram_owner_recovery_parent_bridge_v1, recover_private_oram_owner_store_pair_v1,
};
use data_encoding::BASE64URL_NOPAD;
use fs_err as fs;
use fs_err::{File, OpenOptions};
use fs4::fs_std::FileExt;
use qdrant_sec::{
    PrivateOramAppendMutationBundleV1, PrivateOramAppendWritebackDigestInput,
    PrivateOramIndexKindV2, PrivateOramMutationError, PrivateOramPointOperationKindV1,
    PrivateOramSignatureVerification, PrivateOramSignedStateV2, PrivateOramVisiblePointRecordV1,
    private_oram_append_mutation_v1_digest, private_oram_append_writeback_v1_digest,
    private_oram_no_server_point_record_v1_digest, private_oram_signed_state_v2_digest,
    private_oram_visible_point_record_v1_digest, validate_private_oram_append_mutation_v1_shape,
    validate_private_oram_append_mutation_v1_signature,
    validate_private_oram_signed_state_v2_signature,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

use super::consensus_manager::PrivateOramMutationReconcileSnapshotV1;
use super::consensus_ops::{
    PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION, PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
    PRIVATE_ORAM_MUTATION_RECEIPT_VERSION, PrivateOramConsensusCollectionIndexStateV2,
    PrivateOramConsensusCollectionStateV2, PrivateOramConsensusEpoch,
    PrivateOramConsensusTransitionV2, PrivateOramIndexKind, PrivateOramMutationLease,
    PrivateOramMutationLeasePhase, PrivateOramMutationLeaseSlotV2, PrivateOramMutationReceiptV2,
    canonical_private_oram_consensus_state_record_digest,
    canonical_private_oram_mutation_receipt_digest,
    canonical_private_oram_mutation_transition_digest,
};
use super::private_oram_mutation_state_v2::{
    PrivateOramMutationDecisionEvidenceV2 as RawPrivateOramMutationDecisionEvidenceV2,
    PrivateOramMutationDecisionKindV2 as ValidatedPrivateOramMutationDecisionKindV2,
    PrivateOramMutationPointResolutionEvidenceV2 as RawPrivateOramMutationPointResolutionEvidenceV2,
};
#[cfg(test)]
use super::private_oram_mutation_state_v2::{
    PrivateOramPointResolutionOutcomeV2, PrivateOramPointResolutionReceiptV2,
};
#[cfg(test)]
use super::private_oram_point_staging::PrivateOramPointStagingStore;
use super::private_oram_point_staging::{
    PrivateOramDurablePointStageTokenV1, PrivateOramPointStagingError,
};

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
mod writer_v2;

pub const PRIVATE_ORAM_MUTATION_JOURNAL_DIR: &str = "private_oram_mutations";
pub const PRIVATE_ORAM_MUTATION_JOURNAL_VERSION: u16 = 1;

const ACTIVE_DIR: &str = "active";
const TEMP_DIR: &str = "temp";
const ACTIVE_TEMP_DIR: &str = "temp";
const LOCK_FILE: &str = "journal.lock";
const DESCRIPTOR_FILE: &str = "descriptor.json";
const STATE_FILE: &str = "state.json";
const MAX_DESCRIPTOR_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_OWNER_REQUIREMENTS: usize = 65_536;
const PARENT_SYNC_ATTEMPTS: usize = 3;
const DESCRIPTOR_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-mutation-parent-descriptor/v1";
const STATE_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-mutation-parent-state/v1";
const OWNER_RECOVERY_AUTHORITY_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-recovery-authority/v1";
const POINT_ID_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-staged-point-id-digest/v1";

#[derive(Error)]
pub enum PrivateOramMutationJournalError {
    #[error("private ORAM mutation journal input is invalid")]
    InvalidInput(&'static str),
    #[error("private ORAM mutation journal contains corrupt or inconsistent state")]
    Corrupt,
    #[error("another private ORAM mutation journal is active")]
    ConcurrentMutation,
    #[error("private ORAM mutation journal phase transition is invalid")]
    InvalidTransition,
    #[error("private ORAM mutation journal has a legacy V1 state that requires explicit recovery")]
    LegacyV1State,
    #[error("private ORAM mutation journal signature validation failed")]
    Signature(#[source] PrivateOramMutationError),
    #[error("private ORAM mutation journal I/O failed before publication")]
    Io(#[source] io::Error),
    #[error("private ORAM mutation journal publication outcome is indeterminate")]
    Indeterminate,
    #[error("private ORAM mutation point staging validation failed")]
    PointStaging(#[source] PrivateOramPointStagingError),
}

impl Debug for PrivateOramMutationJournalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => f.debug_tuple("InvalidInput").field(field).finish(),
            Self::Corrupt => f.write_str("Corrupt"),
            Self::ConcurrentMutation => f.write_str("ConcurrentMutation"),
            Self::InvalidTransition => f.write_str("InvalidTransition"),
            Self::LegacyV1State => f.write_str("LegacyV1State"),
            Self::Signature(_) => f.write_str("Signature([redacted])"),
            Self::Io(_) => f.write_str("Io([redacted])"),
            Self::Indeterminate => f.write_str("Indeterminate"),
            Self::PointStaging(_) => f.write_str("PointStaging([redacted])"),
        }
    }
}

impl From<PrivateOramPointStagingError> for PrivateOramMutationJournalError {
    fn from(error: PrivateOramPointStagingError) -> Self {
        Self::PointStaging(error)
    }
}

impl From<PrivateOramMutationError> for PrivateOramMutationJournalError {
    fn from(error: PrivateOramMutationError) -> Self {
        Self::Signature(error)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationOwnerRequirementV1 {
    pub peer_id: PeerId,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub writeback_digest: String,
}

impl Debug for PrivateOramMutationOwnerRequirementV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnerRequirementV1")
            .field("peer_id", &self.peer_id)
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationOwnerPrepareEvidenceV1 {
    pub peer_id: PeerId,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub prepared_journal_digest: String,
}

impl Debug for PrivateOramMutationOwnerPrepareEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnerPrepareEvidenceV1")
            .field("peer_id", &self.peer_id)
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationOwnerFinalizeEvidenceV1 {
    pub peer_id: PeerId,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub prepared_journal_digest: String,
    pub finalized_state_digest: String,
}

impl Debug for PrivateOramMutationOwnerFinalizeEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationOwnerFinalizeEvidenceV1")
            .field("peer_id", &self.peer_id)
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("finalized_state_digest", &"[redacted]")
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
pub enum PrivateOramMutationPointStageEvidenceV1 {
    PrivateOramPointStaging {
        point_id: String,
        staged_insert_sha256: String,
        canonical_point_id_digest: String,
        child_descriptor_digest: String,
        parent_owners_prepared_record_digest: String,
    },
    NoServerPointRecord {
        parent_owners_prepared_record_digest: String,
    },
}

impl Debug for PrivateOramMutationPointStageEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateOramPointStaging { .. } => {
                f.write_str("PrivateOramPointStaging([redacted])")
            }
            Self::NoServerPointRecord { .. } => f.write_str("NoServerPointRecord([redacted])"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationConsensusEvidenceV1 {
    pub committed_record_digest: String,
    pub committed_state_sequence: u64,
    pub committed_signed_state_digest: String,
    pub receipt_digest: String,
    pub transition_digest: String,
    pub lease_renewal_revision: u64,
}

impl Debug for PrivateOramMutationConsensusEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationConsensusEvidenceV1")
            .field("committed_record_digest", &"[redacted]")
            .field("committed_state_sequence", &self.committed_state_sequence)
            .field("committed_signed_state_digest", &"[redacted]")
            .field("receipt_digest", &"[redacted]")
            .field("transition_digest", &"[redacted]")
            .field("lease_renewal_revision", &self.lease_renewal_revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramMutationJournalPhaseV1 {
    LeaseAcquired,
    OwnersPrepared,
    PointStageDurable,
    ConsensusCommitted,
    RemotesFinalized,
    LocalFinalized,
    Complete,
}

impl PrivateOramMutationJournalPhaseV1 {
    pub(super) const fn sequence(self) -> u64 {
        match self {
            Self::LeaseAcquired => 1,
            Self::OwnersPrepared => 2,
            Self::PointStageDurable => 3,
            Self::ConsensusCommitted => 4,
            Self::RemotesFinalized => 5,
            Self::LocalFinalized => 6,
            Self::Complete => 7,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationJournalDescriptorV1 {
    pub version: u16,
    pub coordinator_peer_id: PeerId,
    pub mutation_digest: String,
    pub mutation_bundle: PrivateOramAppendMutationBundleV1,
    pub preparing_lease: PrivateOramMutationLease,
    pub expected_consensus_old_state: PrivateOramConsensusCollectionStateV2,
    pub owner_requirements: Vec<PrivateOramMutationOwnerRequirementV1>,
    pub descriptor_digest: String,
}

impl Debug for PrivateOramMutationJournalDescriptorV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournalDescriptorV1")
            .field("version", &self.version)
            .field("coordinator_peer_id", &self.coordinator_peer_id)
            .field("mutation_digest", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .field("preparing_lease", &self.preparing_lease)
            .field("expected_consensus_old_state", &"[redacted]")
            .field("owner_requirement_count", &self.owner_requirements.len())
            .field("descriptor_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramMutationJournalStateV1 {
    pub version: u16,
    pub sequence: u64,
    pub phase: PrivateOramMutationJournalPhaseV1,
    pub previous_record_digest: Option<String>,
    pub owner_prepares: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
    pub point_stage: Option<PrivateOramMutationPointStageEvidenceV1>,
    pub consensus: Option<PrivateOramMutationConsensusEvidenceV1>,
    pub remote_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    pub local_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    pub record_digest: String,
}

impl Debug for PrivateOramMutationJournalStateV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournalStateV1")
            .field("version", &self.version)
            .field("sequence", &self.sequence)
            .field("phase", &self.phase)
            .field("previous_record_digest", &"[redacted]")
            .field("owner_prepare_count", &self.owner_prepares.len())
            .field("has_point_stage", &self.point_stage.is_some())
            .field("has_consensus_evidence", &self.consensus.is_some())
            .field(
                "remote_finalization_count",
                &self.remote_finalizations.len(),
            )
            .field("local_finalization_count", &self.local_finalizations.len())
            .field("record_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramMutationJournalSnapshotV1 {
    pub descriptor: PrivateOramMutationJournalDescriptorV1,
    pub state: PrivateOramMutationJournalStateV1,
}

impl Debug for PrivateOramMutationJournalSnapshotV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournalSnapshotV1")
            .field("descriptor", &self.descriptor)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramMutationReconcileDispositionV1 {
    /// Observation only. Owner or point abort requires a later consensus abort decision.
    ObservedOldNeedsAbortDecision,
    /// Consensus has fenced mutation apply while the collection remains exact old.
    ExactOldAbortDecided,
    ExactNew,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramValidatedMutationReconcileContextV1 {
    snapshot: PrivateOramMutationJournalSnapshotV1,
    active_lease: PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
}

impl Debug for PrivateOramValidatedMutationReconcileContextV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedMutationReconcileContextV1")
            .field("snapshot", &"[redacted]")
            .field("active_lease", &self.active_lease)
            .field("disposition", &self.disposition)
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-B3-A context is consumed by the dormant D3-B3 coordinator"
)]
impl PrivateOramValidatedMutationReconcileContextV1 {
    pub(super) fn snapshot(&self) -> &PrivateOramMutationJournalSnapshotV1 {
        &self.snapshot
    }

    pub(super) fn active_lease(&self) -> &PrivateOramMutationLease {
        &self.active_lease
    }

    pub(super) const fn disposition(&self) -> PrivateOramMutationReconcileDispositionV1 {
        self.disposition
    }

    fn validated_decision_evidence_v2(
        &self,
    ) -> Result<RawPrivateOramMutationDecisionEvidenceV2, PrivateOramMutationJournalError> {
        build_validated_mutation_decision_evidence_v2(
            &self.snapshot.descriptor,
            &self.active_lease,
            self.disposition,
        )
    }
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
pub(super) struct PrivateOramValidatedMutationDecisionV2 {
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
    expected_descriptor_digest: String,
    expected_predecessor_record_digest: String,
}

impl Debug for PrivateOramValidatedMutationDecisionV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedMutationDecisionV2")
            .field("kind", &self.kind())
            .field("expected_descriptor_digest", &"[redacted]")
            .field("expected_predecessor_record_digest", &"[redacted]")
            .field("evidence", &"[redacted]")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
impl PrivateOramValidatedMutationDecisionV2 {
    pub(super) const fn kind(&self) -> ValidatedPrivateOramMutationDecisionKindV2 {
        self.evidence.kind()
    }
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
pub(super) struct PrivateOramValidatedDecisionDurableV2 {
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
    expected_descriptor_digest: String,
    decision_record_digest: String,
}

impl Debug for PrivateOramValidatedDecisionDurableV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedDecisionDurableV2")
            .field("kind", &self.evidence.kind())
            .field("expected_descriptor_digest", &"[redacted]")
            .field("decision_record_digest", &"[redacted]")
            .field("evidence", &"[redacted]")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
pub(super) struct PrivateOramValidatedRemotesTerminalV2 {
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
    expected_descriptor_digest: String,
    remotes_terminal_record_digest: String,
}

#[allow(
    dead_code,
    reason = "D3-C2 V2 writer remains dormant until the recovery coordinator is activated"
)]
pub(super) struct PrivateOramValidatedLocalTerminalV2 {
    evidence: RawPrivateOramMutationDecisionEvidenceV2,
    expected_descriptor_digest: String,
    local_terminal_record_digest: String,
}

impl Debug for PrivateOramValidatedLocalTerminalV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedLocalTerminalV2")
            .field("kind", &self.evidence.kind())
            .field("expected_descriptor_digest", &"[redacted]")
            .field("local_terminal_record_digest", &"[redacted]")
            .field("evidence", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramValidatedRemotesTerminalV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedRemotesTerminalV2")
            .field("kind", &self.evidence.kind())
            .field("expected_descriptor_digest", &"[redacted]")
            .field("remotes_terminal_record_digest", &"[redacted]")
            .field("evidence", &"[redacted]")
            .finish()
    }
}

fn build_validated_mutation_decision_evidence_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    active_lease: &PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
) -> Result<RawPrivateOramMutationDecisionEvidenceV2, PrivateOramMutationJournalError> {
    let evidence = match disposition {
        PrivateOramMutationReconcileDispositionV1::ExactNew => {
            let committed_state = expected_consensus_new_state(descriptor)?;
            RawPrivateOramMutationDecisionEvidenceV2::ExactNew {
                consensus: derive_consensus_evidence(descriptor, active_lease, &committed_state)?,
                committed_lease: Box::new(active_lease.clone()),
            }
        }
        PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => {
            let old = &descriptor.expected_consensus_old_state;
            RawPrivateOramMutationDecisionEvidenceV2::ExactOldAbort {
                old_consensus_record_digest: canonical_private_oram_consensus_state_record_digest(
                    old,
                )
                .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?,
                old_consensus_state_sequence: old.state_sequence,
                old_consensus_signed_state_digest: old.signed_state_digest.clone(),
                abort_decided_lease: Box::new(active_lease.clone()),
            }
        }
        PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision => {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    };
    Ok(evidence)
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PrivateOramValidatedOwnerRecoveryIndexV1 {
    requirement: PrivateOramMutationOwnerRequirementV1,
    prepared: PrivateOramMutationOwnerPrepareEvidenceV1,
}

impl Debug for PrivateOramValidatedOwnerRecoveryIndexV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedOwnerRecoveryIndexV1")
            .field("peer_id", &self.requirement.peer_id)
            .field("kind", &self.requirement.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.requirement.old_epoch)
            .field("new_epoch", &self.requirement.new_epoch)
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-B3 restart owner authority is consumed by the dormant owner RPC bridge"
)]
impl PrivateOramValidatedOwnerRecoveryIndexV1 {
    pub(super) fn requirement(&self) -> &PrivateOramMutationOwnerRequirementV1 {
        &self.requirement
    }

    pub(super) fn prepared(&self) -> &PrivateOramMutationOwnerPrepareEvidenceV1 {
        &self.prepared
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PrivateOramValidatedOwnerRecoveryAuthorityV1 {
    owner_peer_id: PeerId,
    disposition: PrivateOramMutationReconcileDispositionV1,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    parent_owners_prepared_record_digest: String,
    consensus_authority_record_digest: String,
    reconciliation_authority_digest: String,
    mutation_bundle: PrivateOramAppendMutationBundleV1,
    indexes: Vec<PrivateOramValidatedOwnerRecoveryIndexV1>,
}

impl Debug for PrivateOramValidatedOwnerRecoveryAuthorityV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedOwnerRecoveryAuthorityV1")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("disposition", &self.disposition)
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("parent_owners_prepared_record_digest", &"[redacted]")
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "D3-B3 restart owner authority is consumed by the dormant owner RPC bridge"
)]
impl PrivateOramValidatedOwnerRecoveryAuthorityV1 {
    pub(super) const fn owner_peer_id(&self) -> PeerId {
        self.owner_peer_id
    }

    pub(super) const fn disposition(&self) -> PrivateOramMutationReconcileDispositionV1 {
        self.disposition
    }

    pub(super) fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub(super) fn parent_lease_acquired_record_digest(&self) -> &str {
        &self.parent_lease_acquired_record_digest
    }

    pub(super) fn parent_owners_prepared_record_digest(&self) -> &str {
        &self.parent_owners_prepared_record_digest
    }

    pub(super) fn consensus_authority_record_digest(&self) -> &str {
        &self.consensus_authority_record_digest
    }

    pub(super) fn reconciliation_authority_digest(&self) -> &str {
        &self.reconciliation_authority_digest
    }

    pub(super) fn mutation_bundle(&self) -> &PrivateOramAppendMutationBundleV1 {
        &self.mutation_bundle
    }

    pub(super) fn indexes(&self) -> &[PrivateOramValidatedOwnerRecoveryIndexV1] {
        &self.indexes
    }

    pub(super) fn pair_recovery_projection(
        &self,
    ) -> Result<PrivateOramOwnerRecoveryProjectionV1, PrivateOramMutationJournalError> {
        if self.indexes.len() != 2
            || self.indexes[0].requirement.kind != PrivateOramIndexKindV2::Hnsw
            || self.indexes[1].requirement.kind != PrivateOramIndexKindV2::Result
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let indexes = self
            .indexes
            .iter()
            .map(|index| {
                let requirement = &index.requirement;
                let prepared = &index.prepared;
                if requirement.peer_id != self.owner_peer_id
                    || prepared.peer_id != self.owner_peer_id
                    || requirement.kind != prepared.kind
                    || requirement.index_name != prepared.index_name
                {
                    return Err(PrivateOramMutationJournalError::Corrupt);
                }
                PrivateOramOwnerRecoveryIndexProjectionV1::try_from_input(
                    PrivateOramOwnerRecoveryIndexProjectionInputV1 {
                        kind: requirement.kind,
                        index_name: &requirement.index_name,
                        old_epoch: requirement.old_epoch,
                        new_epoch: requirement.new_epoch,
                        old_root_hash: &requirement.old_root_hash,
                        new_root_hash: &requirement.new_root_hash,
                        writeback_digest: &requirement.writeback_digest,
                        prepared_journal_digest: &prepared.prepared_journal_digest,
                    },
                )
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        PrivateOramOwnerRecoveryProjectionV1::try_new(
            self.owner_peer_id,
            &self.parent_descriptor_digest,
            &self.parent_lease_acquired_record_digest,
            &self.mutation_bundle,
            indexes,
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)
    }

    pub(super) fn classify_pair_recovery_stores_v1(
        &self,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> CollectionResult<PrivateOramOwnerRecoveryStoreDispositionV1> {
        let projection = self.pair_recovery_projection().map_err(|_| {
            CollectionError::bad_request("private ORAM owner recovery authority is invalid")
        })?;
        classify_private_oram_owner_recovery_store_pair_v1(&projection, resources)
    }
}

/// Parent-tip authority that cannot outlive the held mutation-journal lock.
///
/// The consensus state and lease are an atomically captured, monotonic reconciliation snapshot;
/// this value deliberately does not retain the consensus read guard across filesystem work.
pub(super) struct PrivateOramLiveOwnerRecoveryAuthorityV1<'lock> {
    authority: PrivateOramValidatedOwnerRecoveryAuthorityV1,
    parent_lock: &'lock PrivateOramMutationJournalLock,
    parent_bridge: &'lock PrivateOramOwnerRecoveryParentBridgeV1,
    parent_verifier: &'lock PrivateOramOwnerRecoveryParentVerifierV1,
}

#[allow(
    dead_code,
    reason = "D3-C consumes validated owner terminal evidence after paired recovery"
)]
pub(super) enum PrivateOramValidatedOwnerRecoveryOutcomeV1 {
    ObservedOld,
    Finalized {
        terminal: PrivateOramOwnerRecoveryTerminalEvidenceV1,
        owner_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    },
    AbortedOld {
        terminal: PrivateOramOwnerRecoveryTerminalEvidenceV1,
    },
}

impl Debug for PrivateOramValidatedOwnerRecoveryOutcomeV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObservedOld => f.write_str("ObservedOld"),
            Self::Finalized {
                owner_finalizations,
                ..
            } => f
                .debug_struct("Finalized")
                .field("owner_finalization_count", &owner_finalizations.len())
                .field("terminal", &"[redacted]")
                .finish(),
            Self::AbortedOld { .. } => f.write_str("AbortedOld([redacted])"),
        }
    }
}

#[allow(
    dead_code,
    reason = "D3-C consumes validated owner terminal evidence after paired recovery"
)]
impl PrivateOramValidatedOwnerRecoveryOutcomeV1 {
    pub(super) fn owner_finalizations(
        &self,
    ) -> Option<&[PrivateOramMutationOwnerFinalizeEvidenceV1]> {
        match self {
            Self::Finalized {
                owner_finalizations,
                ..
            } => Some(owner_finalizations),
            Self::ObservedOld | Self::AbortedOld { .. } => None,
        }
    }

    pub(super) fn terminal(&self) -> Option<&PrivateOramOwnerRecoveryTerminalEvidenceV1> {
        match self {
            Self::ObservedOld => None,
            Self::Finalized { terminal, .. } | Self::AbortedOld { terminal } => Some(terminal),
        }
    }
}

impl Debug for PrivateOramLiveOwnerRecoveryAuthorityV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramLiveOwnerRecoveryAuthorityV1")
            .field("authority", &self.authority)
            .field("parent_lock", &"[held]")
            .finish()
    }
}

impl<'lock> PrivateOramLiveOwnerRecoveryAuthorityV1<'lock> {
    fn new(
        authority: PrivateOramValidatedOwnerRecoveryAuthorityV1,
        parent_lock: &'lock PrivateOramMutationJournalLock,
        parent_bridge: &'lock PrivateOramOwnerRecoveryParentBridgeV1,
        parent_verifier: &'lock PrivateOramOwnerRecoveryParentVerifierV1,
    ) -> Self {
        Self {
            authority,
            parent_lock,
            parent_bridge,
            parent_verifier,
        }
    }
}

#[allow(
    dead_code,
    reason = "D3-B3 restart owner authority is consumed by the dormant mutating recovery bridge"
)]
impl PrivateOramLiveOwnerRecoveryAuthorityV1<'_> {
    pub(super) const fn owner_peer_id(&self) -> PeerId {
        self.authority.owner_peer_id()
    }

    pub(super) const fn disposition(&self) -> PrivateOramMutationReconcileDispositionV1 {
        self.authority.disposition()
    }

    pub(super) fn parent_descriptor_digest(&self) -> &str {
        self.authority.parent_descriptor_digest()
    }

    pub(super) fn parent_lease_acquired_record_digest(&self) -> &str {
        self.authority.parent_lease_acquired_record_digest()
    }

    pub(super) fn parent_owners_prepared_record_digest(&self) -> &str {
        self.authority.parent_owners_prepared_record_digest()
    }

    pub(super) fn consensus_authority_record_digest(&self) -> &str {
        self.authority.consensus_authority_record_digest()
    }

    pub(super) fn reconciliation_authority_digest(&self) -> &str {
        self.authority.reconciliation_authority_digest()
    }

    pub(super) fn mutation_bundle(&self) -> &PrivateOramAppendMutationBundleV1 {
        self.authority.mutation_bundle()
    }

    fn recover_pair_v1(
        &self,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> CollectionResult<PrivateOramValidatedOwnerRecoveryOutcomeV1> {
        let input = PrivateOramOwnerRecoveryParentInputV1 {
            projection: self.authority.pair_recovery_projection().map_err(|_| {
                CollectionError::bad_request("private ORAM owner recovery authority is invalid")
            })?,
            disposition: match self.authority.disposition() {
                PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision => {
                    PrivateOramOwnerRecoveryParentDispositionV1::ObservedOldNeedsAbortDecision
                }
                PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => {
                    PrivateOramOwnerRecoveryParentDispositionV1::ExactOldAbortDecided
                }
                PrivateOramMutationReconcileDispositionV1::ExactNew => {
                    PrivateOramOwnerRecoveryParentDispositionV1::ExactNew
                }
            },
            authenticated_owner_peer_id: self.authority.owner_peer_id(),
            parent_descriptor_digest: self.authority.parent_descriptor_digest().to_string(),
            parent_owners_prepared_record_digest: self
                .authority
                .parent_owners_prepared_record_digest()
                .to_string(),
            consensus_authority_record_digest: self
                .authority
                .consensus_authority_record_digest()
                .to_string(),
            reconciliation_authority_digest: self
                .authority
                .reconciliation_authority_digest()
                .to_string(),
        };
        // SAFETY: this authority owns the matching private bridge endpoints, `parent_lock` is the
        // pinned EX lock borrowed by `with_live_owner_recovery_authority_v1`, and `input` was
        // rebuilt from typed consensus/lease authority under that same lock.
        unsafe {
            self.parent_bridge
                .with_live_parent_v1(self.parent_lock, input, |parent| {
                    recover_private_oram_owner_store_pair_v1(
                        self.parent_verifier,
                        parent,
                        resources,
                    )
                    .and_then(|outcome| self.bind_pair_outcome_v1(outcome))
                })
        }
    }

    fn bind_pair_outcome_v1(
        &self,
        outcome: PrivateOramOwnerRecoveryPairOutcomeV1,
    ) -> CollectionResult<PrivateOramValidatedOwnerRecoveryOutcomeV1> {
        match (self.authority.disposition(), outcome) {
            (
                PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision,
                PrivateOramOwnerRecoveryPairOutcomeV1::ObservedOld,
            ) => Ok(PrivateOramValidatedOwnerRecoveryOutcomeV1::ObservedOld),
            (
                PrivateOramMutationReconcileDispositionV1::ExactNew,
                PrivateOramOwnerRecoveryPairOutcomeV1::Finalized(terminal),
            ) => {
                self.validate_terminal_evidence_v1(&terminal)?;
                let owner_finalizations = terminal
                    .indexes()
                    .iter()
                    .map(|index| PrivateOramMutationOwnerFinalizeEvidenceV1 {
                        peer_id: terminal.owner_peer_id(),
                        kind: index.kind(),
                        index_name: index.index_name().to_string(),
                        prepared_journal_digest: index.prepared_journal_digest().to_string(),
                        finalized_state_digest: index.terminal_state_digest().to_string(),
                    })
                    .collect();
                Ok(PrivateOramValidatedOwnerRecoveryOutcomeV1::Finalized {
                    terminal,
                    owner_finalizations,
                })
            }
            (
                PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided,
                PrivateOramOwnerRecoveryPairOutcomeV1::AbortedOld(terminal),
            ) => {
                self.validate_terminal_evidence_v1(&terminal)?;
                Ok(PrivateOramValidatedOwnerRecoveryOutcomeV1::AbortedOld { terminal })
            }
            _ => Err(CollectionError::bad_request(
                "private ORAM owner recovery outcome is invalid",
            )),
        }
    }

    fn validate_terminal_evidence_v1(
        &self,
        terminal: &PrivateOramOwnerRecoveryTerminalEvidenceV1,
    ) -> CollectionResult<()> {
        if terminal.owner_peer_id() != self.authority.owner_peer_id()
            || terminal.parent_descriptor_digest() != self.authority.parent_descriptor_digest()
            || terminal.consensus_authority_record_digest()
                != self.authority.consensus_authority_record_digest()
            || terminal.reconciliation_authority_digest()
                != self.authority.reconciliation_authority_digest()
            || terminal.indexes().len() != self.authority.indexes().len()
        {
            return Err(CollectionError::bad_request(
                "private ORAM owner recovery outcome is invalid",
            ));
        }
        for (terminal_index, expected) in terminal.indexes().iter().zip(self.authority.indexes()) {
            if terminal_index.kind() != expected.requirement().kind
                || terminal_index.index_name() != expected.requirement().index_name
                || terminal_index.prepared_journal_digest()
                    != expected.prepared().prepared_journal_digest
            {
                return Err(CollectionError::bad_request(
                    "private ORAM owner recovery outcome is invalid",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrivateOramValidatedPointStageParentPhaseV1 {
    OwnersPrepared,
    PointStageDurable,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramValidatedPointStageParentV1 {
    descriptor: PrivateOramMutationJournalDescriptorV1,
    owners_prepared_record_digest: String,
    phase: PrivateOramValidatedPointStageParentPhaseV1,
    expected_child_descriptor_digest: Option<String>,
}

impl Debug for PrivateOramValidatedPointStageParentV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedPointStageParentV1")
            .field("descriptor", &"[redacted]")
            .field("owners_prepared_record_digest", &"[redacted]")
            .field("phase", &self.phase)
            .field(
                "has_expected_child_descriptor_digest",
                &self.expected_child_descriptor_digest.is_some(),
            )
            .finish()
    }
}

impl PrivateOramValidatedPointStageParentV1 {
    pub(super) fn descriptor(&self) -> &PrivateOramMutationJournalDescriptorV1 {
        &self.descriptor
    }

    pub(super) fn owners_prepared_record_digest(&self) -> &str {
        &self.owners_prepared_record_digest
    }

    pub(super) fn permits_new_child_install(&self) -> bool {
        self.phase == PrivateOramValidatedPointStageParentPhaseV1::OwnersPrepared
    }

    pub(super) fn expected_child_descriptor_digest(&self) -> Option<&str> {
        self.expected_child_descriptor_digest.as_deref()
    }
}

#[derive(Clone)]
pub struct PrivateOramMutationJournal {
    root: PathBuf,
    expected_owner_signing_key_id: String,
    owner_public_key: Vec<u8>,
    owner_recovery_parent_bridge: PrivateOramOwnerRecoveryParentBridgeV1,
    owner_recovery_parent_verifier: PrivateOramOwnerRecoveryParentVerifierV1,
}

impl Debug for PrivateOramMutationJournal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournal")
            .field("root", &"[redacted]")
            .field("expected_owner_signing_key_id", &"[redacted]")
            .field("owner_public_key", &"[redacted]")
            .field("owner_recovery_parent_bridge", &"[redacted]")
            .field("owner_recovery_parent_verifier", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationJournal {
    pub fn new(
        collection_path: &Path,
        expected_owner_signing_key_id: impl Into<String>,
        owner_public_key: Vec<u8>,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        let expected_owner_signing_key_id = expected_owner_signing_key_id.into();
        if expected_owner_signing_key_id.is_empty()
            || expected_owner_signing_key_id.len() > 256
            || owner_public_key.len() != 32
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "signature_verification",
            ));
        }
        let (owner_recovery_parent_bridge, owner_recovery_parent_verifier) =
            new_private_oram_owner_recovery_parent_bridge_v1();
        Ok(Self {
            root: collection_path.join(PRIVATE_ORAM_MUTATION_JOURNAL_DIR),
            expected_owner_signing_key_id,
            owner_public_key,
            owner_recovery_parent_bridge,
            owner_recovery_parent_verifier,
        })
    }

    pub fn begin(
        &self,
        coordinator_peer_id: PeerId,
        owner_peer_ids: &[PeerId],
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        preparing_lease: PrivateOramMutationLease,
        expected_consensus_old_state: PrivateOramConsensusCollectionStateV2,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        let descriptor = self.build_descriptor(
            coordinator_peer_id,
            owner_peer_ids,
            mutation_bundle,
            preparing_lease,
            expected_consensus_old_state,
        )?;
        self.ensure_root_layout()?;
        let _lock = self.acquire_lock()?;
        if path_entry_exists(&self.active_path())? {
            let current = self.load_locked()?;
            if current.descriptor == descriptor {
                sync_directory(&self.root)
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                return Ok(current);
            }
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }

        let mut state = PrivateOramMutationJournalStateV1 {
            version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
            sequence: PrivateOramMutationJournalPhaseV1::LeaseAcquired.sequence(),
            phase: PrivateOramMutationJournalPhaseV1::LeaseAcquired,
            previous_record_digest: None,
            owner_prepares: Vec::new(),
            point_stage: None,
            consensus: None,
            remote_finalizations: Vec::new(),
            local_finalizations: Vec::new(),
            record_digest: String::new(),
        };
        state.record_digest = state_record_digest(&descriptor.descriptor_digest, &state)?;
        validate_state(&descriptor, &state)?;

        let staging = tempfile::Builder::new()
            .prefix("begin-")
            .tempdir_in(self.temp_path())
            .map_err(PrivateOramMutationJournalError::Io)?;
        set_private_directory_permissions(staging.path())?;
        create_private_directory(&staging.path().join(ACTIVE_TEMP_DIR))?;
        write_new_json_private(
            &staging.path().join(DESCRIPTOR_FILE),
            &descriptor,
            MAX_DESCRIPTOR_BYTES,
        )?;
        write_new_json_private(&staging.path().join(STATE_FILE), &state, MAX_STATE_BYTES)?;
        sync_directory(staging.path())?;

        let staging_path = staging.keep();
        match fs::rename(&staging_path, self.active_path()) {
            Ok(()) => {}
            Err(error) => {
                if path_entry_exists(&self.active_path())? {
                    let current = self.load_locked()?;
                    if current.descriptor == descriptor && current.state == state {
                        sync_directory(&self.root)?;
                        return Ok(current);
                    }
                }
                return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                    PrivateOramMutationJournalError::ConcurrentMutation
                } else {
                    PrivateOramMutationJournalError::Indeterminate
                });
            }
        }
        sync_directory(&self.root).map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        self.load_locked()
    }

    pub fn load(
        &self,
    ) -> Result<Option<PrivateOramMutationJournalSnapshotV1>, PrivateOramMutationJournalError> {
        if !path_entry_exists(&self.root)? {
            return Ok(None);
        }
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let _lock = self.acquire_lock()?;
        if !path_entry_exists(&self.active_path())? {
            return Ok(None);
        }
        self.load_locked().map(Some)
    }

    fn validated_reconcile_context(
        &self,
        consensus_state: &PrivateOramConsensusCollectionStateV2,
        lease_slot: &PrivateOramMutationLeaseSlotV2,
    ) -> Result<PrivateOramValidatedMutationReconcileContextV1, PrivateOramMutationJournalError>
    {
        let snapshot = self
            .load()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        validated_reconcile_context_for_snapshot(snapshot, consensus_state, lease_slot)
    }

    #[allow(
        dead_code,
        reason = "D3-B3 coordinator consumes only an atomically captured consensus snapshot"
    )]
    pub(super) fn validated_reconcile_snapshot(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
    ) -> Result<PrivateOramValidatedMutationReconcileContextV1, PrivateOramMutationJournalError>
    {
        self.validated_reconcile_context(
            reconcile_snapshot.consensus_state(),
            reconcile_snapshot.lease_slot(),
        )
    }

    #[allow(
        dead_code,
        reason = "D3-B3 restart owner authority is consumed by the dormant owner RPC bridge"
    )]
    pub(super) fn validated_owner_recovery_authority(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_owner_peer_id: PeerId,
    ) -> Result<PrivateOramValidatedOwnerRecoveryAuthorityV1, PrivateOramMutationJournalError> {
        let context = self.validated_reconcile_snapshot(reconcile_snapshot)?;
        build_owner_recovery_authority(&context, authenticated_owner_peer_id)
    }

    #[allow(
        dead_code,
        reason = "D3-B3 mutating recovery bridge is wired after writer-wide store locking"
    )]
    pub(super) fn with_live_owner_recovery_authority_v1<R>(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_owner_peer_id: PeerId,
        action: impl for<'lock> FnOnce(&PrivateOramLiveOwnerRecoveryAuthorityV1<'lock>) -> R,
    ) -> Result<R, PrivateOramMutationJournalError> {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let parent_lock = self.acquire_lock()?;
        let snapshot = self.load_pinned_locked(&parent_lock)?;
        let context = validated_reconcile_context_for_snapshot(
            snapshot,
            reconcile_snapshot.consensus_state(),
            reconcile_snapshot.lease_slot(),
        )?;
        let expected_parent = context.snapshot.clone();
        let live = PrivateOramLiveOwnerRecoveryAuthorityV1::new(
            build_owner_recovery_authority(&context, authenticated_owner_peer_id)?,
            &parent_lock,
            &self.owner_recovery_parent_bridge,
            &self.owner_recovery_parent_verifier,
        );
        let output = action(&live);
        drop(live);
        let revalidated_parent = self.load_pinned_locked(&parent_lock)?;
        if revalidated_parent != expected_parent {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        parent_lock.validate_root_identity()?;
        drop(parent_lock);
        Ok(output)
    }

    #[allow(
        dead_code,
        reason = "D3-B3 paired recovery is wired before the dormant owner RPC bridge"
    )]
    pub(super) fn recover_live_owner_pair_v1(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<
        CollectionResult<PrivateOramValidatedOwnerRecoveryOutcomeV1>,
        PrivateOramMutationJournalError,
    > {
        let collection_path = resources
            .hnsw_store
            .root_path()
            .parent()
            .and_then(Path::parent)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if self.root != collection_path.join(PRIVATE_ORAM_MUTATION_JOURNAL_DIR) {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        self.with_live_owner_recovery_authority_v1(
            reconcile_snapshot,
            authenticated_owner_peer_id,
            |live| live.recover_pair_v1(resources),
        )
    }

    pub fn mark_owners_prepared(
        &self,
        owner_prepares: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            validate_owner_prepares(descriptor, &owner_prepares)?;
            if current.phase.sequence()
                >= PrivateOramMutationJournalPhaseV1::OwnersPrepared.sequence()
            {
                return (current.owner_prepares == owner_prepares)
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::LeaseAcquired {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.owner_prepares = owner_prepares;
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::OwnersPrepared,
            )))
        })
    }

    pub fn validated_point_stage_parent(
        &self,
    ) -> Result<PrivateOramValidatedPointStageParentV1, PrivateOramMutationJournalError> {
        let snapshot = self
            .load()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let (phase, owners_prepared_record_digest, expected_child_descriptor_digest) =
            match (&snapshot.state.phase, snapshot.state.point_stage.as_ref()) {
                (PrivateOramMutationJournalPhaseV1::OwnersPrepared, None) => (
                    PrivateOramValidatedPointStageParentPhaseV1::OwnersPrepared,
                    snapshot.state.record_digest.clone(),
                    None,
                ),
                (
                    PrivateOramMutationJournalPhaseV1::PointStageDurable,
                    Some(PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
                        child_descriptor_digest,
                        parent_owners_prepared_record_digest,
                        ..
                    }),
                ) => (
                    PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
                    parent_owners_prepared_record_digest.clone(),
                    Some(child_descriptor_digest.clone()),
                ),
                (
                    PrivateOramMutationJournalPhaseV1::PointStageDurable,
                    Some(PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
                        parent_owners_prepared_record_digest,
                    }),
                ) => (
                    PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
                    parent_owners_prepared_record_digest.clone(),
                    None,
                ),
                _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
            };
        Ok(PrivateOramValidatedPointStageParentV1 {
            descriptor: snapshot.descriptor,
            owners_prepared_record_digest,
            phase,
            expected_child_descriptor_digest,
        })
    }

    pub fn mark_private_point_stage_durable(
        &self,
        durable_stage: &PrivateOramDurablePointStageTokenV1,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        let point_stage = PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
            point_id: durable_stage.point_id().to_string(),
            staged_insert_sha256: durable_stage.frame_sha256().to_string(),
            canonical_point_id_digest: durable_stage.canonical_point_id_digest().to_string(),
            child_descriptor_digest: durable_stage.child_descriptor_digest().to_string(),
            parent_owners_prepared_record_digest: durable_stage
                .parent_owners_prepared_record_digest()
                .to_string(),
        };
        self.mark_point_stage_durable_from_tip(
            durable_stage.parent_descriptor_digest(),
            durable_stage.parent_owners_prepared_record_digest(),
            point_stage,
        )
    }

    pub fn mark_no_server_point_stage_durable(
        &self,
        parent: &PrivateOramValidatedPointStageParentV1,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.mark_point_stage_durable_from_tip(
            &parent.descriptor.descriptor_digest,
            &parent.owners_prepared_record_digest,
            PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
                parent_owners_prepared_record_digest: parent.owners_prepared_record_digest.clone(),
            },
        )
    }

    fn mark_point_stage_durable_from_tip(
        &self,
        expected_parent_descriptor_digest: &str,
        expected_owners_prepared_record_digest: &str,
        point_stage: PrivateOramMutationPointStageEvidenceV1,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            if descriptor.descriptor_digest != expected_parent_descriptor_digest {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            validate_point_stage(descriptor, &current.owner_prepares, &point_stage)?;
            if current.phase == PrivateOramMutationJournalPhaseV1::PointStageDurable {
                return (current.point_stage.as_ref() == Some(&point_stage))
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::OwnersPrepared
                || current.record_digest != expected_owners_prepared_record_digest
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.point_stage = Some(point_stage);
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::PointStageDurable,
            )))
        })
    }

    pub fn mark_consensus_committed(
        &self,
        committed_lease: &PrivateOramMutationLease,
        committed_state: &PrivateOramConsensusCollectionStateV2,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            let consensus =
                derive_consensus_evidence(descriptor, committed_lease, committed_state)?;
            if current.phase.sequence()
                >= PrivateOramMutationJournalPhaseV1::ConsensusCommitted.sequence()
            {
                return (current.consensus.as_ref() == Some(&consensus))
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::PointStageDurable {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.consensus = Some(consensus);
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::ConsensusCommitted,
            )))
        })
    }

    pub fn mark_remotes_finalized(
        &self,
        remote_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            validate_finalizations(descriptor, current, &remote_finalizations, false)?;
            if current.phase.sequence()
                >= PrivateOramMutationJournalPhaseV1::RemotesFinalized.sequence()
            {
                return (current.remote_finalizations == remote_finalizations)
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::ConsensusCommitted {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.remote_finalizations = remote_finalizations;
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::RemotesFinalized,
            )))
        })
    }

    pub fn mark_local_finalized(
        &self,
        local_finalizations: Vec<PrivateOramMutationOwnerFinalizeEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|descriptor, current| {
            validate_finalizations(descriptor, current, &local_finalizations, true)?;
            if current.phase.sequence()
                >= PrivateOramMutationJournalPhaseV1::LocalFinalized.sequence()
            {
                return (current.local_finalizations == local_finalizations)
                    .then_some(None)
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::RemotesFinalized {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            let mut next = current.clone();
            next.local_finalizations = local_finalizations;
            Ok(Some((
                next,
                PrivateOramMutationJournalPhaseV1::LocalFinalized,
            )))
        })
    }

    pub fn mark_complete(
        &self,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.transition(|_, current| {
            if current.phase == PrivateOramMutationJournalPhaseV1::Complete {
                return Ok(None);
            }
            if current.phase != PrivateOramMutationJournalPhaseV1::LocalFinalized {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            Ok(Some((
                current.clone(),
                PrivateOramMutationJournalPhaseV1::Complete,
            )))
        })
    }

    fn build_descriptor(
        &self,
        coordinator_peer_id: PeerId,
        owner_peer_ids: &[PeerId],
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        preparing_lease: PrivateOramMutationLease,
        expected_consensus_old_state: PrivateOramConsensusCollectionStateV2,
    ) -> Result<PrivateOramMutationJournalDescriptorV1, PrivateOramMutationJournalError> {
        let verification = self.signature_verification();
        validate_private_oram_append_mutation_v1_shape(&mutation_bundle.mutation)?;
        validate_private_oram_signed_state_v2_signature(
            &mutation_bundle.mutation.old_state.state,
            Some(&mutation_bundle.mutation.old_state.signature),
            verification,
        )?;
        validate_private_oram_signed_state_v2_signature(
            &mutation_bundle.mutation.new_state.state,
            Some(&mutation_bundle.mutation.new_state.signature),
            verification,
        )?;
        validate_private_oram_append_mutation_v1_signature(
            &mutation_bundle.mutation,
            Some(&mutation_bundle.signature),
            verification,
        )?;
        let mutation_digest = private_oram_append_mutation_v1_digest(&mutation_bundle.mutation)?;
        validate_preparing_lease(
            coordinator_peer_id,
            &mutation_bundle,
            &mutation_digest,
            &preparing_lease,
        )?;
        validate_expected_consensus_old_state(
            &mutation_bundle,
            &preparing_lease,
            &expected_consensus_old_state,
        )?;
        let owner_requirements = derive_owner_requirements(&mutation_bundle, owner_peer_ids)?;
        if !owner_requirements
            .iter()
            .any(|requirement| requirement.peer_id == coordinator_peer_id)
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "coordinator_peer_id",
            ));
        }
        let mut descriptor = PrivateOramMutationJournalDescriptorV1 {
            version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
            coordinator_peer_id,
            mutation_digest,
            mutation_bundle,
            preparing_lease,
            expected_consensus_old_state,
            owner_requirements,
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor_digest(&descriptor)?;
        validate_descriptor(&descriptor, verification)?;
        Ok(descriptor)
    }

    fn transition<F>(
        &self,
        update: F,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError>
    where
        F: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV1,
        ) -> Result<
            Option<(
                PrivateOramMutationJournalStateV1,
                PrivateOramMutationJournalPhaseV1,
            )>,
            PrivateOramMutationJournalError,
        >,
    {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let _lock = self.acquire_lock()?;
        let current = self.load_locked()?;
        let Some((mut next, phase)) = update(&current.descriptor, &current.state)? else {
            sync_directory(&self.active_path())
                .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
            return Ok(current);
        };
        if phase.sequence() != current.state.sequence + 1 {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        next.version = PRIVATE_ORAM_MUTATION_JOURNAL_VERSION;
        next.sequence = phase.sequence();
        next.phase = phase;
        next.previous_record_digest = Some(current.state.record_digest.clone());
        next.record_digest = state_record_digest(&current.descriptor.descriptor_digest, &next)?;
        validate_state(&current.descriptor, &next)?;
        let previous_file_sha256 = file_sha256(&self.state_path(), MAX_STATE_BYTES)?;
        write_json_atomic_classified(
            &self.state_path(),
            &self.active_temp_path(),
            &next,
            previous_file_sha256,
            &FilesystemJournalSaveBackend,
        )?;
        Ok(PrivateOramMutationJournalSnapshotV1 {
            descriptor: current.descriptor,
            state: next,
        })
    }

    fn load_locked(
        &self,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.load_locked_at_root(&self.root)
    }

    fn load_pinned_locked(
        &self,
        lock: &PrivateOramMutationJournalLock,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        self.load_locked_at_root(&lock.pinned_root_path())
    }

    fn load_locked_at_root(
        &self,
        root: &Path,
    ) -> Result<PrivateOramMutationJournalSnapshotV1, PrivateOramMutationJournalError> {
        let active = root.join(ACTIVE_DIR);
        let active_temp = active.join(ACTIVE_TEMP_DIR);
        validate_private_directory(&active)?;
        validate_private_directory(&active_temp)?;
        let descriptor: PrivateOramMutationJournalDescriptorV1 =
            read_json_private(&active.join(DESCRIPTOR_FILE), MAX_DESCRIPTOR_BYTES)?;
        validate_descriptor(&descriptor, self.signature_verification())?;
        let state: PrivateOramMutationJournalStateV1 =
            read_json_private(&active.join(STATE_FILE), MAX_STATE_BYTES)?;
        validate_state(&descriptor, &state)?;
        Ok(PrivateOramMutationJournalSnapshotV1 { descriptor, state })
    }

    fn signature_verification(&self) -> PrivateOramSignatureVerification<'_> {
        PrivateOramSignatureVerification {
            expected_key_id: &self.expected_owner_signing_key_id,
            public_key: &self.owner_public_key,
        }
    }

    fn ensure_root_layout(&self) -> Result<(), PrivateOramMutationJournalError> {
        let collection_path = self
            .root
            .parent()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let metadata =
            fs::symlink_metadata(collection_path).map_err(PrivateOramMutationJournalError::Io)?;
        if !metadata.file_type().is_dir() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        create_private_directory(&self.root)?;
        create_private_directory(&self.temp_path())
    }

    fn acquire_lock(
        &self,
    ) -> Result<PrivateOramMutationJournalLock, PrivateOramMutationJournalError> {
        let root = open_pinned_private_directory(&self.root)?;
        let path = pinned_directory_entry_path(&root, &self.root, LOCK_FILE)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        secure_open_options(&mut options, true);
        let file = options
            .open(&path)
            .map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_file_metadata(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            0,
        )?;
        FileExt::lock_exclusive(file.file()).map_err(PrivateOramMutationJournalError::Io)?;
        let current = fs::symlink_metadata(&path).map_err(PrivateOramMutationJournalError::Io)?;
        ensure_same_file(
            &file
                .metadata()
                .map_err(PrivateOramMutationJournalError::Io)?,
            &current,
        )?;
        validate_private_file_metadata(&current, 0)?;
        file.sync_all()
            .map_err(PrivateOramMutationJournalError::Io)?;
        root.validate_at_path(&self.root)?;
        sync_directory(&root.pinned_path(&self.root))?;
        Ok(PrivateOramMutationJournalLock {
            _file: file,
            root,
            root_path: self.root.clone(),
        })
    }

    fn active_path(&self) -> PathBuf {
        self.root.join(ACTIVE_DIR)
    }

    fn temp_path(&self) -> PathBuf {
        self.root.join(TEMP_DIR)
    }

    fn active_temp_path(&self) -> PathBuf {
        self.active_path().join(ACTIVE_TEMP_DIR)
    }

    fn state_path(&self) -> PathBuf {
        self.active_path().join(STATE_FILE)
    }
}

struct PinnedPrivateDirectory {
    directory: File,
}

impl PinnedPrivateDirectory {
    fn pinned_path(&self, fallback: &Path) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            let _ = fallback;
            PathBuf::from("/proc/self/fd").join(self.directory.file().as_raw_fd().to_string())
        }
        #[cfg(not(target_os = "linux"))]
        {
            fallback.to_path_buf()
        }
    }

    fn validate_at_path(&self, path: &Path) -> Result<(), PrivateOramMutationJournalError> {
        let opened = self
            .directory
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_directory_metadata(&opened)?;
        let current = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
        validate_private_directory_metadata(&current)?;
        ensure_same_directory(&opened, &current)
    }
}

fn open_pinned_private_directory(
    path: &Path,
) -> Result<PinnedPrivateDirectory, PrivateOramMutationJournalError> {
    let before = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_directory_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
    }
    let directory = options
        .open(path)
        .map_err(PrivateOramMutationJournalError::Io)?;
    let opened = directory
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_directory_metadata(&opened)?;
    ensure_same_directory(&before, &opened)?;
    let pinned = PinnedPrivateDirectory { directory };
    pinned.validate_at_path(path)?;
    Ok(pinned)
}

fn pinned_directory_entry_path(
    directory: &PinnedPrivateDirectory,
    fallback_root: &Path,
    name: &str,
) -> Result<PathBuf, PrivateOramMutationJournalError> {
    if name.is_empty() || Path::new(name).components().count() != 1 || matches!(name, "." | "..") {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(directory.pinned_path(fallback_root).join(name))
}

fn ensure_same_directory(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), PrivateOramMutationJournalError> {
    if !before.file_type().is_dir() || !after.file_type().is_dir() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

struct PrivateOramMutationJournalLock {
    _file: File,
    root: PinnedPrivateDirectory,
    root_path: PathBuf,
}

impl PrivateOramMutationJournalLock {
    fn pinned_root_path(&self) -> PathBuf {
        self.root.pinned_path(&self.root_path)
    }

    fn validate_root_identity(&self) -> Result<(), PrivateOramMutationJournalError> {
        self.root.validate_at_path(&self.root_path)
    }
}

fn validate_preparing_lease(
    coordinator_peer_id: PeerId,
    mutation_bundle: &PrivateOramAppendMutationBundleV1,
    mutation_digest: &str,
    lease: &PrivateOramMutationLease,
) -> Result<(), PrivateOramMutationJournalError> {
    let mutation = &mutation_bundle.mutation;
    if !matches!(lease.phase, PrivateOramMutationLeasePhase::Preparing)
        || lease.generation == 0
        || lease.owner_peer_id != coordinator_peer_id
        || lease.collection_id != mutation.collection_id
        || lease.mutation_id != mutation.mutation_id
        || lease.signed_mutation_digest != mutation_digest
        || lease.base_state_sequence != mutation.old_state.state.state_sequence
        || lease.writer_lease_digest != mutation.writer_lease_digest
        || lease.writer_fence != mutation.writer_fence
        || lease.issued_at_unix > mutation.issued_at_unix
        || lease.expires_at_unix < mutation.expires_at_unix
        || lease.issued_at_unix == 0
        || lease.expires_at_unix <= lease.issued_at_unix
        || !is_sha256_digest(&lease.transition_digest)
        || !is_sha256_digest(&lease.base_record_digest)
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "preparing_lease",
        ));
    }
    Ok(())
}

fn validate_expected_consensus_old_state(
    mutation_bundle: &PrivateOramAppendMutationBundleV1,
    preparing_lease: &PrivateOramMutationLease,
    consensus: &PrivateOramConsensusCollectionStateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    let signed = &mutation_bundle.mutation.old_state.state;
    let signed_state_digest = private_oram_signed_state_v2_digest(signed)?;
    let consensus_record_digest =
        canonical_private_oram_consensus_state_record_digest(consensus)
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("consensus_old_state"))?;
    if consensus.collection_id != signed.collection_id
        || consensus.manifest_digest != signed.manifest_digest
        || consensus.layout_generation != signed.layout_generation
        || consensus.layout_digest != signed.layout_digest
        || consensus.state_sequence != signed.state_sequence
        || consensus.signed_state_digest != signed_state_digest
        || consensus.client_state_digest != signed.client_state_digest
        || consensus.indexes != consensus_indexes_from_signed(signed)
        || consensus_record_digest != preparing_lease.base_record_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "consensus_old_state",
        ));
    }
    Ok(())
}

fn consensus_indexes_from_signed(
    state: &PrivateOramSignedStateV2,
) -> Vec<PrivateOramConsensusCollectionIndexStateV2> {
    state
        .indexes
        .iter()
        .map(|index| PrivateOramConsensusCollectionIndexStateV2 {
            index_kind: match index.kind {
                PrivateOramIndexKindV2::Hnsw => PrivateOramIndexKind::Hnsw,
                PrivateOramIndexKindV2::Result => PrivateOramIndexKind::ResultPayload,
            },
            index_name: match index.kind {
                PrivateOramIndexKindV2::Hnsw => index.index_name.clone(),
                PrivateOramIndexKindV2::Result => String::new(),
            },
            epoch: PrivateOramConsensusEpoch {
                index_epoch: index.index_epoch,
                root_hash: index.root_hash.clone(),
                writeback_digest: Some(index.last_writeback_digest.clone()),
            },
            logical_count: index.logical_count,
            dummy_count: index.dummy_count,
        })
        .collect()
}

fn derive_owner_requirements(
    mutation_bundle: &PrivateOramAppendMutationBundleV1,
    owner_peer_ids: &[PeerId],
) -> Result<Vec<PrivateOramMutationOwnerRequirementV1>, PrivateOramMutationJournalError> {
    let requirement_count = owner_peer_ids
        .len()
        .checked_mul(mutation_bundle.mutation.writebacks.len())
        .ok_or(PrivateOramMutationJournalError::InvalidInput(
            "owner_peer_ids",
        ))?;
    if owner_peer_ids.is_empty()
        || owner_peer_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || mutation_bundle.mutation.writebacks.is_empty()
        || requirement_count > MAX_OWNER_REQUIREMENTS
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "owner_peer_ids",
        ));
    }
    let mutation = &mutation_bundle.mutation;
    let old = &mutation.old_state.state;
    let new = &mutation.new_state.state;
    if old.indexes.len() != mutation.writebacks.len()
        || new.indexes.len() != mutation.writebacks.len()
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "mutation_indexes",
        ));
    }
    let mut index_requirements = Vec::with_capacity(mutation.writebacks.len());
    for ((old_index, new_index), writeback) in old
        .indexes
        .iter()
        .zip(&new.indexes)
        .zip(&mutation.writebacks)
    {
        if old_index.kind != writeback.kind
            || new_index.kind != writeback.kind
            || old_index.index_name != writeback.index_name
            || new_index.index_name != writeback.index_name
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "mutation_indexes",
            ));
        }
        let writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &mutation.collection_id,
                manifest_digest: &mutation.manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: old_index.index_epoch,
                new_epoch: new_index.index_epoch,
                old_root_hash: &old_index.root_hash,
                new_root_hash: &new_index.root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            })?;
        if new_index.last_writeback_digest != writeback_digest {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "writeback_digest",
            ));
        }
        index_requirements.push((old_index, new_index, writeback_digest));
    }

    let mut requirements = Vec::with_capacity(requirement_count);
    for peer_id in owner_peer_ids {
        for (old_index, new_index, writeback_digest) in &index_requirements {
            requirements.push(PrivateOramMutationOwnerRequirementV1 {
                peer_id: *peer_id,
                kind: old_index.kind,
                index_name: old_index.index_name.clone(),
                old_epoch: old_index.index_epoch,
                new_epoch: new_index.index_epoch,
                old_root_hash: old_index.root_hash.clone(),
                new_root_hash: new_index.root_hash.clone(),
                writeback_digest: writeback_digest.clone(),
            });
        }
    }
    requirements.sort_by(requirement_order);
    Ok(requirements)
}

fn validate_descriptor(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    verification: PrivateOramSignatureVerification<'_>,
) -> Result<(), PrivateOramMutationJournalError> {
    if descriptor.version != PRIVATE_ORAM_MUTATION_JOURNAL_VERSION
        || descriptor.owner_requirements.is_empty()
        || !is_sha256_digest(&descriptor.mutation_digest)
        || !is_sha256_digest(&descriptor.descriptor_digest)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_private_oram_append_mutation_v1_shape(&descriptor.mutation_bundle.mutation)?;
    validate_private_oram_signed_state_v2_signature(
        &descriptor.mutation_bundle.mutation.old_state.state,
        Some(&descriptor.mutation_bundle.mutation.old_state.signature),
        verification,
    )?;
    validate_private_oram_signed_state_v2_signature(
        &descriptor.mutation_bundle.mutation.new_state.state,
        Some(&descriptor.mutation_bundle.mutation.new_state.signature),
        verification,
    )?;
    validate_private_oram_append_mutation_v1_signature(
        &descriptor.mutation_bundle.mutation,
        Some(&descriptor.mutation_bundle.signature),
        verification,
    )?;
    if descriptor.mutation_digest
        != private_oram_append_mutation_v1_digest(&descriptor.mutation_bundle.mutation)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    validate_preparing_lease(
        descriptor.coordinator_peer_id,
        &descriptor.mutation_bundle,
        &descriptor.mutation_digest,
        &descriptor.preparing_lease,
    )?;
    validate_expected_consensus_old_state(
        &descriptor.mutation_bundle,
        &descriptor.preparing_lease,
        &descriptor.expected_consensus_old_state,
    )?;
    expected_consensus_new_state(descriptor)?;
    if descriptor.descriptor_digest != descriptor_digest(descriptor)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if descriptor
        .owner_requirements
        .windows(2)
        .any(|pair| requirement_order(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let owner_peer_ids = descriptor
        .owner_requirements
        .iter()
        .map(|requirement| requirement.peer_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if derive_owner_requirements(&descriptor.mutation_bundle, &owner_peer_ids)?
        != descriptor.owner_requirements
        || !owner_peer_ids.contains(&descriptor.coordinator_peer_id)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

pub(super) fn validate_state(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV1,
) -> Result<(), PrivateOramMutationJournalError> {
    if state.version != PRIVATE_ORAM_MUTATION_JOURNAL_VERSION
        || state.sequence != state.phase.sequence()
        || state.record_digest != state_record_digest(&descriptor.descriptor_digest, state)?
        || (state.sequence == 1) != state.previous_record_digest.is_none()
        || state
            .previous_record_digest
            .as_ref()
            .is_some_and(|digest| !is_sha256_digest(digest))
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let rank = state.phase.sequence();
    if (rank >= 2) == state.owner_prepares.is_empty()
        || (rank >= 3) != state.point_stage.is_some()
        || (rank >= 4) != state.consensus.is_some()
        || (rank < 5 && !state.remote_finalizations.is_empty())
        || (rank < 6 && !state.local_finalizations.is_empty())
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if rank >= 2 {
        validate_owner_prepares(descriptor, &state.owner_prepares)?;
    }
    if let Some(point_stage) = &state.point_stage {
        validate_point_stage(descriptor, &state.owner_prepares, point_stage)?;
    }
    if let Some(consensus) = &state.consensus {
        validate_consensus_evidence_shape(descriptor, consensus)?;
    }
    if rank >= 5 {
        validate_finalizations(descriptor, state, &state.remote_finalizations, false)?;
    }
    if rank >= 6 {
        validate_finalizations(descriptor, state, &state.local_finalizations, true)?;
    }
    Ok(())
}

pub(super) fn validate_owner_prepares(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    evidence: &[PrivateOramMutationOwnerPrepareEvidenceV1],
) -> Result<(), PrivateOramMutationJournalError> {
    if evidence.len() != descriptor.owner_requirements.len()
        || evidence
            .windows(2)
            .any(|pair| prepare_evidence_order(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for (requirement, evidence) in descriptor.owner_requirements.iter().zip(evidence) {
        if !same_owner_key(
            requirement.peer_id,
            requirement.kind,
            &requirement.index_name,
            evidence.peer_id,
            evidence.kind,
            &evidence.index_name,
        ) || !is_sha256_digest(&evidence.prepared_journal_digest)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok(())
}

fn validate_point_stage(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    owner_prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
    evidence: &PrivateOramMutationPointStageEvidenceV1,
) -> Result<(), PrivateOramMutationJournalError> {
    let mutation = &descriptor.mutation_bundle.mutation;
    let expected_parent_record_digest = owners_prepared_record_digest(descriptor, owner_prepares)?;
    let (kind, digest) = match evidence {
        PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
            point_id,
            staged_insert_sha256,
            canonical_point_id_digest,
            child_descriptor_digest,
            parent_owners_prepared_record_digest,
        } => {
            if parent_owners_prepared_record_digest != &expected_parent_record_digest
                || !is_sha256_digest(staged_insert_sha256)
                || !is_sha256_digest(canonical_point_id_digest)
                || !is_sha256_digest(child_descriptor_digest)
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
        PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        } => {
            if parent_owners_prepared_record_digest != &expected_parent_record_digest {
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

fn owners_prepared_record_digest(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    owner_prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
) -> Result<String, PrivateOramMutationJournalError> {
    let lease_acquired_record_digest = lease_acquired_record_digest(descriptor)?;
    let mut owners_prepared = PrivateOramMutationJournalStateV1 {
        version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
        sequence: PrivateOramMutationJournalPhaseV1::OwnersPrepared.sequence(),
        phase: PrivateOramMutationJournalPhaseV1::OwnersPrepared,
        previous_record_digest: Some(lease_acquired_record_digest),
        owner_prepares: owner_prepares.to_vec(),
        point_stage: None,
        consensus: None,
        remote_finalizations: Vec::new(),
        local_finalizations: Vec::new(),
        record_digest: String::new(),
    };
    owners_prepared.record_digest =
        state_record_digest(&descriptor.descriptor_digest, &owners_prepared)?;
    Ok(owners_prepared.record_digest)
}

fn lease_acquired_record_digest(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let lease_acquired = PrivateOramMutationJournalStateV1 {
        version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
        sequence: PrivateOramMutationJournalPhaseV1::LeaseAcquired.sequence(),
        phase: PrivateOramMutationJournalPhaseV1::LeaseAcquired,
        previous_record_digest: None,
        owner_prepares: Vec::new(),
        point_stage: None,
        consensus: None,
        remote_finalizations: Vec::new(),
        local_finalizations: Vec::new(),
        record_digest: String::new(),
    };
    state_record_digest(&descriptor.descriptor_digest, &lease_acquired)
}

fn build_owner_recovery_authority(
    context: &PrivateOramValidatedMutationReconcileContextV1,
    authenticated_owner_peer_id: PeerId,
) -> Result<PrivateOramValidatedOwnerRecoveryAuthorityV1, PrivateOramMutationJournalError> {
    let snapshot = &context.snapshot;
    if snapshot.state.phase.sequence()
        < PrivateOramMutationJournalPhaseV1::OwnersPrepared.sequence()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }

    let indexes = snapshot
        .descriptor
        .owner_requirements
        .iter()
        .zip(&snapshot.state.owner_prepares)
        .filter(|(requirement, _)| requirement.peer_id == authenticated_owner_peer_id)
        .map(
            |(requirement, prepared)| PrivateOramValidatedOwnerRecoveryIndexV1 {
                requirement: requirement.clone(),
                prepared: prepared.clone(),
            },
        )
        .collect::<Vec<_>>();
    if indexes.is_empty()
        || indexes.len()
            != snapshot
                .descriptor
                .mutation_bundle
                .mutation
                .writebacks
                .len()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }

    let parent_lease_acquired_record_digest = lease_acquired_record_digest(&snapshot.descriptor)?;
    let parent_owners_prepared_record_digest =
        owners_prepared_record_digest(&snapshot.descriptor, &snapshot.state.owner_prepares)?;
    let consensus_authority_record_digest = match context.disposition {
        PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision
        | PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => {
            context.active_lease.base_record_digest.clone()
        }
        PrivateOramMutationReconcileDispositionV1::ExactNew => {
            let PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                ..
            } = &context.active_lease.phase
            else {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            };
            committed_record_digest.clone()
        }
    };
    let (expected_consensus_authority_record_digest, reconciliation_authority_digest) =
        expected_owner_recovery_authority_digest_v1(
            &snapshot.descriptor,
            &snapshot.state.owner_prepares,
            &context.active_lease,
            context.disposition,
            authenticated_owner_peer_id,
        )?;
    if expected_consensus_authority_record_digest != consensus_authority_record_digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(PrivateOramValidatedOwnerRecoveryAuthorityV1 {
        owner_peer_id: authenticated_owner_peer_id,
        disposition: context.disposition,
        parent_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        parent_lease_acquired_record_digest,
        parent_owners_prepared_record_digest,
        consensus_authority_record_digest,
        reconciliation_authority_digest,
        mutation_bundle: snapshot.descriptor.mutation_bundle.clone(),
        indexes,
    })
}

pub(super) fn expected_owner_recovery_authority_digest_v1(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    owner_prepares: &[PrivateOramMutationOwnerPrepareEvidenceV1],
    active_lease: &PrivateOramMutationLease,
    disposition: PrivateOramMutationReconcileDispositionV1,
    authenticated_owner_peer_id: PeerId,
) -> Result<(String, String), PrivateOramMutationJournalError> {
    validate_owner_prepares(descriptor, owner_prepares)?;
    let parent_lease_acquired_record_digest = lease_acquired_record_digest(descriptor)?;
    let parent_owners_prepared_record_digest =
        owners_prepared_record_digest(descriptor, owner_prepares)?;
    let consensus_authority_record_digest = match (disposition, &active_lease.phase) {
        (
            PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision,
            PrivateOramMutationLeasePhase::Preparing,
        )
        | (
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided,
            PrivateOramMutationLeasePhase::AbortDecided,
        ) => active_lease.base_record_digest.clone(),
        (
            PrivateOramMutationReconcileDispositionV1::ExactNew,
            PrivateOramMutationLeasePhase::ConsensusCommitted {
                committed_record_digest,
                ..
            },
        ) => committed_record_digest.clone(),
        _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
    };
    let indexes = descriptor
        .owner_requirements
        .iter()
        .zip(owner_prepares)
        .filter(|(requirement, _)| requirement.peer_id == authenticated_owner_peer_id)
        .map(
            |(requirement, prepared)| PrivateOramValidatedOwnerRecoveryIndexV1 {
                requirement: requirement.clone(),
                prepared: prepared.clone(),
            },
        )
        .collect::<Vec<_>>();
    if indexes.is_empty() || indexes.len() != descriptor.mutation_bundle.mutation.writebacks.len() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }

    let mut hasher = Sha256::new();
    hasher.update(OWNER_RECOVERY_AUTHORITY_DIGEST_DOMAIN);
    hash_digest(&mut hasher, &descriptor.descriptor_digest)?;
    hash_digest(&mut hasher, &parent_lease_acquired_record_digest)?;
    hash_digest(&mut hasher, &parent_owners_prepared_record_digest)?;
    hash_digest(&mut hasher, &consensus_authority_record_digest)?;
    hasher.update(authenticated_owner_peer_id.to_be_bytes());
    hasher.update([match disposition {
        PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision => 1,
        PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => 2,
        PrivateOramMutationReconcileDispositionV1::ExactNew => 3,
    }]);

    let lease = active_lease;
    hasher.update(lease.generation.to_be_bytes());
    hash_string(&mut hasher, &lease.collection_id)?;
    hasher.update(lease.owner_peer_id.to_be_bytes());
    hash_digest(&mut hasher, &lease.mutation_id)?;
    hash_digest(&mut hasher, &lease.signed_mutation_digest)?;
    hash_digest(&mut hasher, &lease.transition_digest)?;
    hash_digest(&mut hasher, &lease.base_record_digest)?;
    hasher.update(lease.base_state_sequence.to_be_bytes());
    hash_digest(&mut hasher, &lease.writer_lease_digest)?;
    hasher.update(lease.writer_fence.to_be_bytes());
    hasher.update(lease.issued_at_unix.to_be_bytes());
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
            hash_digest(&mut hasher, committed_record_digest)?;
            hasher.update(committed_state_sequence.to_be_bytes());
            hash_digest(&mut hasher, committed_signed_state_digest)?;
            hash_digest(&mut hasher, receipt_digest)?;
        }
    }

    hash_len(&mut hasher, indexes.len())?;
    for index in indexes {
        let requirement = &index.requirement;
        hash_owner_key(
            &mut hasher,
            requirement.peer_id,
            requirement.kind,
            &requirement.index_name,
        )?;
        hasher.update(requirement.old_epoch.to_be_bytes());
        hasher.update(requirement.new_epoch.to_be_bytes());
        hash_digest(&mut hasher, &requirement.old_root_hash)?;
        hash_digest(&mut hasher, &requirement.new_root_hash)?;
        hash_digest(&mut hasher, &requirement.writeback_digest)?;
        hash_digest(&mut hasher, &index.prepared.prepared_journal_digest)?;
    }
    Ok((
        consensus_authority_record_digest,
        BASE64URL_NOPAD.encode(&hasher.finalize()),
    ))
}

fn validated_reconcile_context_for_snapshot(
    snapshot: PrivateOramMutationJournalSnapshotV1,
    consensus_state: &PrivateOramConsensusCollectionStateV2,
    lease_slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<PrivateOramValidatedMutationReconcileContextV1, PrivateOramMutationJournalError> {
    let active_lease = validate_reconcile_lease_slot(&snapshot.descriptor, lease_slot)?;
    let expected_new = expected_consensus_new_state(&snapshot.descriptor)?;
    let disposition = if consensus_state == &snapshot.descriptor.expected_consensus_old_state {
        if snapshot.state.phase.sequence()
            > PrivateOramMutationJournalPhaseV1::PointStageDurable.sequence()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        match &active_lease.phase {
            PrivateOramMutationLeasePhase::Preparing => {
                PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision
            }
            PrivateOramMutationLeasePhase::AbortDecided => {
                PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided
            }
            PrivateOramMutationLeasePhase::ConsensusCommitted { .. } => {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
    } else if consensus_state == &expected_new {
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV1::PointStageDurable.sequence()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let derived =
            derive_consensus_evidence(&snapshot.descriptor, &active_lease, consensus_state)?;
        if snapshot.state.consensus.as_ref().is_some_and(|recorded| {
            recorded.committed_record_digest != derived.committed_record_digest
                || recorded.committed_state_sequence != derived.committed_state_sequence
                || recorded.committed_signed_state_digest != derived.committed_signed_state_digest
                || recorded.receipt_digest != derived.receipt_digest
                || recorded.transition_digest != derived.transition_digest
                || recorded.lease_renewal_revision > derived.lease_renewal_revision
        }) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        PrivateOramMutationReconcileDispositionV1::ExactNew
    } else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    Ok(PrivateOramValidatedMutationReconcileContextV1 {
        snapshot,
        active_lease,
        disposition,
    })
}

pub(super) fn private_oram_point_id_digest(
    point_id: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(POINT_ID_DIGEST_DOMAIN);
    hash_string(&mut hasher, point_id)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_reconcile_lease_slot(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    slot: &PrivateOramMutationLeaseSlotV2,
) -> Result<PrivateOramMutationLease, PrivateOramMutationJournalError> {
    let Some(active) = slot.active.as_ref() else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let preparing = &descriptor.preparing_lease;
    if slot.version != PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION
        || slot.generation != slot.max_writer_fence
        || slot.generation != active.generation
        || slot.max_writer_fence != active.writer_fence
        || slot
            .last_clear
            .as_ref()
            .is_some_and(|clear| clear.generation >= active.generation)
        || active.generation != preparing.generation
        || active.collection_id != preparing.collection_id
        || active.owner_peer_id != preparing.owner_peer_id
        || active.mutation_id != preparing.mutation_id
        || active.signed_mutation_digest != preparing.signed_mutation_digest
        || active.transition_digest != preparing.transition_digest
        || active.base_record_digest != preparing.base_record_digest
        || active.base_state_sequence != preparing.base_state_sequence
        || active.writer_lease_digest != preparing.writer_lease_digest
        || active.writer_fence != preparing.writer_fence
        || active.issued_at_unix != preparing.issued_at_unix
        || active.expires_at_unix < preparing.expires_at_unix
        || active.renewal_revision < preparing.renewal_revision
        || (active.renewal_revision == preparing.renewal_revision
            && active.expires_at_unix != preparing.expires_at_unix)
        || (active.renewal_revision > preparing.renewal_revision
            && active.expires_at_unix <= preparing.expires_at_unix)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(active.clone())
}

pub(super) fn derive_consensus_evidence(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    committed_lease: &PrivateOramMutationLease,
    committed_state: &PrivateOramConsensusCollectionStateV2,
) -> Result<PrivateOramMutationConsensusEvidenceV1, PrivateOramMutationJournalError> {
    let preparing = &descriptor.preparing_lease;
    if committed_lease.generation != preparing.generation
        || committed_lease.collection_id != preparing.collection_id
        || committed_lease.owner_peer_id != preparing.owner_peer_id
        || committed_lease.mutation_id != preparing.mutation_id
        || committed_lease.signed_mutation_digest != preparing.signed_mutation_digest
        || committed_lease.transition_digest != preparing.transition_digest
        || committed_lease.base_record_digest != preparing.base_record_digest
        || committed_lease.base_state_sequence != preparing.base_state_sequence
        || committed_lease.writer_lease_digest != preparing.writer_lease_digest
        || committed_lease.writer_fence != preparing.writer_fence
        || committed_lease.issued_at_unix != preparing.issued_at_unix
        || committed_lease.expires_at_unix < preparing.expires_at_unix
        || committed_lease.renewal_revision < preparing.renewal_revision
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let PrivateOramMutationLeasePhase::ConsensusCommitted {
        committed_record_digest,
        committed_state_sequence,
        committed_signed_state_digest,
        receipt_digest,
    } = &committed_lease.phase
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let expected_state = expected_consensus_new_state(descriptor)?;
    if committed_state != &expected_state {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let PrivateOramConsensusTransitionV2::Mutation(receipt) = &expected_state.last_transition
    else {
        unreachable!();
    };
    let expected_receipt_digest = canonical_private_oram_mutation_receipt_digest(receipt)
        .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    let expected_record_digest =
        canonical_private_oram_consensus_state_record_digest(&expected_state)
            .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    let transition_digest = canonical_private_oram_mutation_transition_digest(
        &descriptor.expected_consensus_old_state,
        &expected_state,
    )
    .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    if committed_record_digest != &expected_record_digest
        || committed_state_sequence != &expected_state.state_sequence
        || committed_signed_state_digest != &expected_state.signed_state_digest
        || receipt_digest != &expected_receipt_digest
        || transition_digest != preparing.transition_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(PrivateOramMutationConsensusEvidenceV1 {
        committed_record_digest: expected_record_digest,
        committed_state_sequence: expected_state.state_sequence,
        committed_signed_state_digest: expected_state.signed_state_digest,
        receipt_digest: expected_receipt_digest,
        transition_digest,
        lease_renewal_revision: committed_lease.renewal_revision,
    })
}

pub(super) fn validate_consensus_evidence_shape(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    evidence: &PrivateOramMutationConsensusEvidenceV1,
) -> Result<(), PrivateOramMutationJournalError> {
    let expected_state = expected_consensus_new_state(descriptor)?;
    let PrivateOramConsensusTransitionV2::Mutation(receipt) = &expected_state.last_transition
    else {
        unreachable!();
    };
    let expected_record_digest =
        canonical_private_oram_consensus_state_record_digest(&expected_state)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let expected_receipt_digest = canonical_private_oram_mutation_receipt_digest(receipt)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if evidence.committed_record_digest != expected_record_digest
        || evidence.receipt_digest != expected_receipt_digest
        || evidence.transition_digest != descriptor.preparing_lease.transition_digest
        || evidence.committed_state_sequence != expected_state.state_sequence
        || evidence.committed_signed_state_digest != expected_state.signed_state_digest
        || evidence.lease_renewal_revision < descriptor.preparing_lease.renewal_revision
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn expected_consensus_new_state(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<PrivateOramConsensusCollectionStateV2, PrivateOramMutationJournalError> {
    let mutation = &descriptor.mutation_bundle.mutation;
    let old_state_digest = private_oram_signed_state_v2_digest(&mutation.old_state.state)?;
    let new_state_digest = private_oram_signed_state_v2_digest(&mutation.new_state.state)?;
    let receipt = PrivateOramMutationReceiptV2 {
        version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
        mutation_id: mutation.mutation_id.clone(),
        signed_mutation_digest: descriptor.mutation_digest.clone(),
        transition_digest: descriptor.preparing_lease.transition_digest.clone(),
        old_state_sequence: mutation.old_state.state.state_sequence,
        old_state_digest,
        new_state_sequence: mutation.new_state.state.state_sequence,
        new_state_digest: new_state_digest.clone(),
        point_operation_digest: mutation.point_operation_digest.clone(),
        writer_lease_digest: mutation.writer_lease_digest.clone(),
        writer_fence: mutation.writer_fence,
        mutation_lease_generation: descriptor.preparing_lease.generation,
    };
    let state = &mutation.new_state.state;
    let consensus = PrivateOramConsensusCollectionStateV2 {
        version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
        collection_id: state.collection_id.clone(),
        manifest_digest: state.manifest_digest.clone(),
        layout_generation: state.layout_generation,
        layout_digest: state.layout_digest.clone(),
        state_sequence: state.state_sequence,
        signed_state_digest: new_state_digest,
        indexes: consensus_indexes_from_signed(state),
        client_state_digest: state.client_state_digest.clone(),
        last_transition: PrivateOramConsensusTransitionV2::Mutation(receipt),
    };
    let transition_digest = canonical_private_oram_mutation_transition_digest(
        &descriptor.expected_consensus_old_state,
        &consensus,
    )
    .map_err(|_| PrivateOramMutationJournalError::InvalidTransition)?;
    if transition_digest != descriptor.preparing_lease.transition_digest {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(consensus)
}

fn validate_finalizations(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV1,
    evidence: &[PrivateOramMutationOwnerFinalizeEvidenceV1],
    local: bool,
) -> Result<(), PrivateOramMutationJournalError> {
    let requirements = descriptor
        .owner_requirements
        .iter()
        .filter(|requirement| (requirement.peer_id == descriptor.coordinator_peer_id) == local)
        .collect::<Vec<_>>();
    if evidence.len() != requirements.len()
        || evidence
            .windows(2)
            .any(|pair| finalize_evidence_order(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for (requirement, finalized) in requirements.into_iter().zip(evidence) {
        let prepared = state.owner_prepares.iter().find(|prepared| {
            same_owner_key(
                requirement.peer_id,
                requirement.kind,
                &requirement.index_name,
                prepared.peer_id,
                prepared.kind,
                &prepared.index_name,
            )
        });
        if prepared.is_none_or(|prepared| {
            prepared.prepared_journal_digest != finalized.prepared_journal_digest
        }) || !same_owner_key(
            requirement.peer_id,
            requirement.kind,
            &requirement.index_name,
            finalized.peer_id,
            finalized.kind,
            &finalized.index_name,
        ) || !is_sha256_digest(&finalized.finalized_state_digest)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok(())
}

fn descriptor_digest(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DIGEST_DOMAIN);
    hasher.update(descriptor.version.to_be_bytes());
    hasher.update(descriptor.coordinator_peer_id.to_be_bytes());
    hash_digest(&mut hasher, &descriptor.mutation_digest)?;
    hash_lease(&mut hasher, &descriptor.preparing_lease)?;
    hash_digest(
        &mut hasher,
        &canonical_private_oram_consensus_state_record_digest(
            &descriptor.expected_consensus_old_state,
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?,
    )?;
    hash_len(&mut hasher, descriptor.owner_requirements.len())?;
    for requirement in &descriptor.owner_requirements {
        hash_owner_key(
            &mut hasher,
            requirement.peer_id,
            requirement.kind,
            &requirement.index_name,
        )?;
        hasher.update(requirement.old_epoch.to_be_bytes());
        hasher.update(requirement.new_epoch.to_be_bytes());
        hash_digest(&mut hasher, &requirement.old_root_hash)?;
        hash_digest(&mut hasher, &requirement.new_root_hash)?;
        hash_digest(&mut hasher, &requirement.writeback_digest)?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn state_record_digest(
    descriptor_digest: &str,
    state: &PrivateOramMutationJournalStateV1,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(STATE_DIGEST_DOMAIN);
    hash_digest(&mut hasher, descriptor_digest)?;
    hasher.update(state.version.to_be_bytes());
    hasher.update(state.sequence.to_be_bytes());
    hasher.update([state.phase.sequence() as u8]);
    hash_optional_digest(&mut hasher, state.previous_record_digest.as_deref())?;
    hash_len(&mut hasher, state.owner_prepares.len())?;
    for evidence in &state.owner_prepares {
        hash_owner_key(
            &mut hasher,
            evidence.peer_id,
            evidence.kind,
            &evidence.index_name,
        )?;
        hash_digest(&mut hasher, &evidence.prepared_journal_digest)?;
    }
    match &state.point_stage {
        None => hasher.update([0]),
        Some(PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
            point_id,
            staged_insert_sha256,
            canonical_point_id_digest,
            child_descriptor_digest,
            parent_owners_prepared_record_digest,
        }) => {
            hasher.update([1]);
            hash_string(&mut hasher, point_id)?;
            hash_digest(&mut hasher, staged_insert_sha256)?;
            hash_digest(&mut hasher, canonical_point_id_digest)?;
            hash_digest(&mut hasher, child_descriptor_digest)?;
            hash_digest(&mut hasher, parent_owners_prepared_record_digest)?;
        }
        Some(PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        }) => {
            hasher.update([2]);
            hash_digest(&mut hasher, parent_owners_prepared_record_digest)?;
        }
    }
    match &state.consensus {
        None => hasher.update([0]),
        Some(evidence) => {
            hasher.update([1]);
            hash_digest(&mut hasher, &evidence.committed_record_digest)?;
            hasher.update(evidence.committed_state_sequence.to_be_bytes());
            hash_digest(&mut hasher, &evidence.committed_signed_state_digest)?;
            hash_digest(&mut hasher, &evidence.receipt_digest)?;
            hash_digest(&mut hasher, &evidence.transition_digest)?;
            hasher.update(evidence.lease_renewal_revision.to_be_bytes());
        }
    }
    hash_finalizations(&mut hasher, &state.remote_finalizations)?;
    hash_finalizations(&mut hasher, &state.local_finalizations)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn hash_lease(
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
    if !matches!(lease.phase, PrivateOramMutationLeasePhase::Preparing) {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "preparing_lease",
        ));
    }
    hasher.update([1]);
    Ok(())
}

fn hash_finalizations(
    hasher: &mut Sha256,
    evidence: &[PrivateOramMutationOwnerFinalizeEvidenceV1],
) -> Result<(), PrivateOramMutationJournalError> {
    hash_len(hasher, evidence.len())?;
    for evidence in evidence {
        hash_owner_key(
            hasher,
            evidence.peer_id,
            evidence.kind,
            &evidence.index_name,
        )?;
        hash_digest(hasher, &evidence.prepared_journal_digest)?;
        hash_digest(hasher, &evidence.finalized_state_digest)?;
    }
    Ok(())
}

fn hash_owner_key(
    hasher: &mut Sha256,
    peer_id: PeerId,
    kind: PrivateOramIndexKindV2,
    index_name: &str,
) -> Result<(), PrivateOramMutationJournalError> {
    hasher.update(peer_id.to_be_bytes());
    hasher.update([index_kind_tag(kind)]);
    hash_string(hasher, index_name)
}

fn hash_optional_digest(
    hasher: &mut Sha256,
    value: Option<&str>,
) -> Result<(), PrivateOramMutationJournalError> {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_digest(hasher, value)
        }
        None => {
            hasher.update([0]);
            Ok(())
        }
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

fn requirement_order(
    left: &PrivateOramMutationOwnerRequirementV1,
    right: &PrivateOramMutationOwnerRequirementV1,
) -> Ordering {
    owner_key_order(
        left.peer_id,
        left.kind,
        &left.index_name,
        right.peer_id,
        right.kind,
        &right.index_name,
    )
}

fn prepare_evidence_order(
    left: &PrivateOramMutationOwnerPrepareEvidenceV1,
    right: &PrivateOramMutationOwnerPrepareEvidenceV1,
) -> Ordering {
    owner_key_order(
        left.peer_id,
        left.kind,
        &left.index_name,
        right.peer_id,
        right.kind,
        &right.index_name,
    )
}

fn finalize_evidence_order(
    left: &PrivateOramMutationOwnerFinalizeEvidenceV1,
    right: &PrivateOramMutationOwnerFinalizeEvidenceV1,
) -> Ordering {
    owner_key_order(
        left.peer_id,
        left.kind,
        &left.index_name,
        right.peer_id,
        right.kind,
        &right.index_name,
    )
}

fn owner_key_order(
    left_peer: PeerId,
    left_kind: PrivateOramIndexKindV2,
    left_name: &str,
    right_peer: PeerId,
    right_kind: PrivateOramIndexKindV2,
    right_name: &str,
) -> Ordering {
    (left_peer, index_kind_tag(left_kind), left_name.as_bytes()).cmp(&(
        right_peer,
        index_kind_tag(right_kind),
        right_name.as_bytes(),
    ))
}

fn same_owner_key(
    left_peer: PeerId,
    left_kind: PrivateOramIndexKindV2,
    left_name: &str,
    right_peer: PeerId,
    right_kind: PrivateOramIndexKindV2,
    right_name: &str,
) -> bool {
    left_peer == right_peer && left_kind == right_kind && left_name == right_name
}

const fn index_kind_tag(kind: PrivateOramIndexKindV2) -> u8 {
    match kind {
        PrivateOramIndexKindV2::Hnsw => 1,
        PrivateOramIndexKindV2::Result => 2,
    }
}

trait JournalSaveBackend {
    fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()>;
    fn sync_parent(&self, parent: &Path) -> io::Result<()>;
}

struct FilesystemJournalSaveBackend;

impl JournalSaveBackend for FilesystemJournalSaveBackend {
    fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            candidate
                .persist(destination)
                .map(|_| ())
                .map_err(|error| error.error)
        }
        #[cfg(not(unix))]
        {
            atomicwrites::replace_atomic(candidate.path(), destination)
        }
    }

    fn sync_parent(&self, parent: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            File::open(parent)?.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
            Ok(())
        }
    }
}

fn write_json_atomic_classified<T: Serialize>(
    destination: &Path,
    temp_dir: &Path,
    value: &T,
    previous_file_sha256: [u8; 32],
    backend: &impl JournalSaveBackend,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_directory(temp_dir)?;
    let parent = destination
        .parent()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    validate_private_directory(parent)?;
    let mut candidate =
        NamedTempFile::new_in(temp_dir).map_err(PrivateOramMutationJournalError::Io)?;
    let mut candidate_hasher = Sha256::new();
    {
        let mut writer = Sha256Writer {
            inner: &mut candidate,
            hasher: &mut candidate_hasher,
        };
        serde_json::to_writer(&mut writer, value)
            .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
        writer
            .flush()
            .map_err(PrivateOramMutationJournalError::Io)?;
    }
    let candidate_file = File::from_parts(
        candidate
            .reopen()
            .map_err(PrivateOramMutationJournalError::Io)?,
        candidate.path().to_path_buf(),
    );
    candidate_file
        .sync_all()
        .map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(
        &candidate_file
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?,
        MAX_STATE_BYTES,
    )?;
    let candidate_sha256: [u8; 32] = candidate_hasher.finalize().into();
    if let Err(error) = backend.publish(candidate, destination) {
        match file_sha256(destination, MAX_STATE_BYTES) {
            Ok(actual) if actual == candidate_sha256 => {
                return sync_parent_after_publish(destination, parent, candidate_sha256, backend);
            }
            Ok(actual) if actual == previous_file_sha256 => {
                return Err(PrivateOramMutationJournalError::Io(error));
            }
            _ => return Err(PrivateOramMutationJournalError::Indeterminate),
        }
    }
    if file_sha256(destination, MAX_STATE_BYTES)
        .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?
        != candidate_sha256
    {
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    sync_parent_after_publish(destination, parent, candidate_sha256, backend)
}

fn sync_parent_after_publish(
    destination: &Path,
    parent: &Path,
    candidate_sha256: [u8; 32],
    backend: &impl JournalSaveBackend,
) -> Result<(), PrivateOramMutationJournalError> {
    for _ in 0..PARENT_SYNC_ATTEMPTS {
        if backend.sync_parent(parent).is_ok() {
            return if file_sha256(destination, MAX_STATE_BYTES)
                .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?
                == candidate_sha256
            {
                Ok(())
            } else {
                Err(PrivateOramMutationJournalError::Indeterminate)
            };
        }
        if file_sha256(destination, MAX_STATE_BYTES)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?
            != candidate_sha256
        {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
    }
    Err(PrivateOramMutationJournalError::Indeterminate)
}

struct Sha256Writer<'a, W> {
    inner: W,
    hasher: &'a mut Sha256,
}

impl<W: Write> Write for Sha256Writer<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(super) fn create_private_directory(path: &Path) -> Result<(), PrivateOramMutationJournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(PrivateOramMutationJournalError::Io)?;
            set_private_directory_permissions(path)?;
            let parent = path
                .parent()
                .ok_or(PrivateOramMutationJournalError::Corrupt)?;
            sync_directory(parent)?;
            validate_private_directory(path)
        }
        Err(error) => Err(PrivateOramMutationJournalError::Io(error)),
    }
}

pub(super) fn path_entry_exists(path: &Path) -> Result<bool, PrivateOramMutationJournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(PrivateOramMutationJournalError::Io(error)),
    }
}

pub(super) fn set_private_directory_permissions(
    path: &Path,
) -> Result<(), PrivateOramMutationJournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(PrivateOramMutationJournalError::Io)?;
    }
    Ok(())
}

pub(super) fn validate_private_directory(
    path: &Path,
) -> Result<(), PrivateOramMutationJournalError> {
    let metadata = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_directory_metadata(&metadata)
}

fn validate_private_directory_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), PrivateOramMutationJournalError> {
    if !metadata.file_type().is_dir() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7077 != 0
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

pub(super) fn write_new_json_private<T: Serialize>(
    path: &Path,
    value: &T,
    max_bytes: u64,
) -> Result<(), PrivateOramMutationJournalError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    secure_open_options(&mut options, true);
    let mut file = options
        .open(path)
        .map_err(PrivateOramMutationJournalError::Io)?;
    serde_json::to_writer(&mut file, value)
        .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
    file.flush().map_err(PrivateOramMutationJournalError::Io)?;
    let metadata = file
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(&metadata, max_bytes)?;
    file.sync_all().map_err(PrivateOramMutationJournalError::Io)
}

pub(super) fn read_json_private<T: DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, PrivateOramMutationJournalError> {
    let file = open_private_file(path, max_bytes)?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    let mut reader = file.take(read_limit);
    let value = serde_json::from_reader(&mut reader)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if reader.limit() == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(value)
}

pub(super) fn read_private_bytes_bounded(
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, PrivateOramMutationJournalError> {
    let file = open_private_file(path, max_bytes)?;
    let initial_length = file
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?
        .len()
        .min(max_bytes);
    let capacity =
        usize::try_from(initial_length).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(PrivateOramMutationJournalError::Io)?;
    if u64::try_from(bytes.len()).map_err(|_| PrivateOramMutationJournalError::Corrupt)? > max_bytes
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(bytes)
}

pub(super) fn file_sha256(
    path: &Path,
    max_bytes: u64,
) -> Result<[u8; 32], PrivateOramMutationJournalError> {
    let file = open_private_file(path, max_bytes)?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    let mut limited = file.take(read_limit);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = limited
            .read(&mut buffer)
            .map_err(PrivateOramMutationJournalError::Io)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| PrivateOramMutationJournalError::Corrupt)?)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if total > max_bytes {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

pub(super) fn open_private_file(
    path: &Path,
    max_bytes: u64,
) -> Result<File, PrivateOramMutationJournalError> {
    let before = fs::symlink_metadata(path).map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(&before, max_bytes)?;
    let mut options = OpenOptions::new();
    options.read(true);
    secure_open_options(&mut options, false);
    let file = options
        .open(path)
        .map_err(PrivateOramMutationJournalError::Io)?;
    let opened = file
        .metadata()
        .map_err(PrivateOramMutationJournalError::Io)?;
    ensure_same_file(&before, &opened)?;
    validate_private_file_metadata(&opened, max_bytes)?;
    Ok(file)
}

pub(super) fn secure_open_options(options: &mut OpenOptions, create_private: bool) {
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        if create_private {
            options.mode(0o600);
        }
    }
}

pub(super) fn validate_private_file_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), PrivateOramMutationJournalError> {
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7177 != 0
            || metadata.nlink() != 1
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

pub(super) fn ensure_same_file(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), PrivateOramMutationJournalError> {
    if before.len() != after.len() || before.file_type().is_file() != after.file_type().is_file() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<(), PrivateOramMutationJournalError> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(PrivateOramMutationJournalError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use qdrant_sec::{
        PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION, PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION, PrivateOramAppendBucketRefV1,
        PrivateOramAppendIndexWritebackV1, PrivateOramAppendMutationV1, PrivateOramIndexStateV2,
        PrivateOramSignedStateV2, PrivateOramStagedInsertFrameV1, PrivateOramStagedPointIdV1,
        PrivateOramStagedPointV1, encode_private_oram_staged_insert_frame_v1,
        package_private_oram_append_mutation_v1, package_private_oram_signed_state_v2,
        private_oram_no_server_point_record_v1_digest, private_oram_staged_insert_frame_v1_digest,
        private_oram_staged_point_semantic_v1_digest,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::content_manager::consensus_ops::{
        PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION, PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
        PrivateOramConsensusCollectionIndexStateV2, PrivateOramConsensusEpoch,
        PrivateOramIndexKind, PrivateOramMutationReceiptV2,
    };
    use crate::content_manager::private_oram_mutation_state_v2::{
        DecodedPrivateOramMutationStateUntrusted, PRIVATE_ORAM_MUTATION_STATE_V2_VERSION,
        PRIVATE_ORAM_POINT_RESOLUTION_RECEIPT_V2_VERSION, PrivateOramMutationDecisionEvidenceV2,
        PrivateOramMutationDecisionKindV2, PrivateOramMutationJournalPhaseV2,
        PrivateOramMutationJournalStateV2, PrivateOramMutationOwnerTerminalBatchV2,
        PrivateOramMutationOwnerTerminalEvidenceV2,
        PrivateOramMutationOwnerTerminalIndexEvidenceV2, PrivateOramMutationOwnerTerminalKindV2,
        PrivateOramMutationPointResolutionEvidenceV2, PrivateOramMutationPointStageEvidenceV2,
        PrivateOramMutationStateOriginV2, PrivateOramMutationStatePredecessorV2,
        PrivateOramPointReplicaObservationV2, PrivateOramPointReplicaTargetV2,
        PrivateOramPointResolutionOutcomeV2, PrivateOramPointResolutionReceiptV2,
        canonical_private_oram_mutation_state_history_v2,
        canonical_private_oram_mutation_state_v2_for_test,
        decode_untrusted_private_oram_mutation_state, exact_new_decision_v2_for_test,
        exact_old_abort_decision_v2_for_test, next_private_oram_mutation_state_v2,
        private_oram_collection_id_digest_v2, private_oram_owner_terminal_evidence_v2_digest,
        private_oram_point_replica_set_digest_v2, private_oram_point_resolution_receipt_v2_digest,
        private_oram_point_stage_evidence_v2_from_durable_token, state_record_digest_v2_for_test,
        validate_private_oram_mutation_state_v2_structure,
    };
    use crate::content_manager::private_oram_point_staging::PrivateOramPointStagingStore;

    struct Fixture {
        public_key: Vec<u8>,
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        preparing_lease: PrivateOramMutationLease,
        committed_lease: PrivateOramMutationLease,
        old_consensus: PrivateOramConsensusCollectionStateV2,
        new_consensus: PrivateOramConsensusCollectionStateV2,
        staged_frame_bytes: Option<Vec<u8>>,
    }

    fn digest(fill: u8) -> String {
        BASE64URL_NOPAD.encode(&[fill; 32])
    }

    fn pair_recovery_authority(
        seed: u8,
        marker: u8,
    ) -> PrivateOramValidatedOwnerRecoveryAuthorityV1 {
        let base = fixture(seed, marker);
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let mut mutation = base.mutation_bundle.mutation.clone();
        let result_old_root = digest(marker.wrapping_add(30));
        let result_new_root = digest(marker.wrapping_add(31));
        let result_writeback = PrivateOramAppendIndexWritebackV1 {
            kind: PrivateOramIndexKindV2::Result,
            index_name: "private-result".to_string(),
            read_path_count: 1,
            read_transcript_digest: digest(marker.wrapping_add(32)),
            updated_buckets: vec![PrivateOramAppendBucketRefV1 {
                bucket_id: 1,
                ciphertext_sha256: digest(marker.wrapping_add(33)),
                bucket_commitment: digest(marker.wrapping_add(34)),
            }],
        };
        let result_writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &mutation.collection_id,
                manifest_digest: &mutation.manifest_digest,
                kind: result_writeback.kind,
                index_name: &result_writeback.index_name,
                old_epoch: 21,
                new_epoch: 22,
                old_root_hash: &result_old_root,
                new_root_hash: &result_new_root,
                read_path_count: result_writeback.read_path_count,
                read_transcript_digest: &result_writeback.read_transcript_digest,
                updated_buckets: &result_writeback.updated_buckets,
            })
            .unwrap();
        let mut old_state = mutation.old_state.state.clone();
        old_state.indexes.push(PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Result,
            index_name: result_writeback.index_name.clone(),
            index_epoch: 21,
            root_hash: result_old_root,
            logical_count: 8,
            dummy_count: 24,
            last_writeback_digest: digest(marker.wrapping_add(35)),
        });
        let mut new_state = mutation.new_state.state.clone();
        new_state.indexes.push(PrivateOramIndexStateV2 {
            kind: PrivateOramIndexKindV2::Result,
            index_name: result_writeback.index_name.clone(),
            index_epoch: 22,
            root_hash: result_new_root,
            logical_count: 9,
            dummy_count: 23,
            last_writeback_digest: result_writeback_digest,
        });
        mutation.old_state = package_private_oram_signed_state_v2(&key_pair, old_state).unwrap();
        mutation.new_state = package_private_oram_signed_state_v2(&key_pair, new_state).unwrap();
        mutation.writebacks.push(result_writeback);
        let mutation_bundle = package_private_oram_append_mutation_v1(&key_pair, mutation).unwrap();
        let indexes = mutation_bundle
            .mutation
            .old_state
            .state
            .indexes
            .iter()
            .zip(&mutation_bundle.mutation.new_state.state.indexes)
            .enumerate()
            .map(
                |(position, (old, new))| PrivateOramValidatedOwnerRecoveryIndexV1 {
                    requirement: PrivateOramMutationOwnerRequirementV1 {
                        peer_id: 11,
                        kind: old.kind,
                        index_name: old.index_name.clone(),
                        old_epoch: old.index_epoch,
                        new_epoch: new.index_epoch,
                        old_root_hash: old.root_hash.clone(),
                        new_root_hash: new.root_hash.clone(),
                        writeback_digest: new.last_writeback_digest.clone(),
                    },
                    prepared: PrivateOramMutationOwnerPrepareEvidenceV1 {
                        peer_id: 11,
                        kind: old.kind,
                        index_name: old.index_name.clone(),
                        prepared_journal_digest: digest(
                            marker.wrapping_add(36).wrapping_add(position as u8),
                        ),
                    },
                },
            )
            .collect();
        PrivateOramValidatedOwnerRecoveryAuthorityV1 {
            owner_peer_id: 11,
            disposition: PrivateOramMutationReconcileDispositionV1::ExactNew,
            parent_descriptor_digest: digest(marker.wrapping_add(38)),
            parent_lease_acquired_record_digest: digest(marker.wrapping_add(39)),
            parent_owners_prepared_record_digest: digest(marker.wrapping_add(40)),
            consensus_authority_record_digest: digest(marker.wrapping_add(41)),
            reconciliation_authority_digest: digest(marker.wrapping_add(42)),
            mutation_bundle,
            indexes,
        }
    }

    fn fixture(seed: u8, marker: u8) -> Fixture {
        fixture_at_sequence(seed, marker, 0, false)
    }

    fn fixture_at_sequence(seed: u8, marker: u8, old_sequence: u64, visible: bool) -> Fixture {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let collection_id = "collection-uuid-1".to_string();
        let key_id = "tenant-a/private-oram-owner-v2".to_string();
        let manifest_digest = digest(marker);
        let layout_digest = digest(marker.wrapping_add(1));
        let mutation_id = digest(marker.wrapping_add(2));
        let previous_mutation_id = digest(marker.wrapping_add(13));
        let writer_lease_digest = digest(marker.wrapping_add(3));
        let old_root_hash = digest(marker.wrapping_add(4));
        let new_root_hash = digest(marker.wrapping_add(5));
        let old_writeback_digest = digest(marker.wrapping_add(6));
        let read_transcript_digest = digest(marker.wrapping_add(7));
        let writeback = PrivateOramAppendIndexWritebackV1 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: "secret-index".to_string(),
            read_path_count: 1,
            read_transcript_digest,
            updated_buckets: vec![PrivateOramAppendBucketRefV1 {
                bucket_id: 0,
                ciphertext_sha256: digest(marker.wrapping_add(8)),
                bucket_commitment: digest(marker.wrapping_add(9)),
            }],
        };
        let new_writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &collection_id,
                manifest_digest: &manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: 11,
                new_epoch: 12,
                old_root_hash: &old_root_hash,
                new_root_hash: &new_root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            })
            .unwrap();
        let old_state = PrivateOramSignedStateV2 {
            version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: manifest_digest.clone(),
            layout_generation: 5,
            layout_digest: layout_digest.clone(),
            state_sequence: old_sequence,
            indexes: vec![PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: "secret-index".to_string(),
                index_epoch: 11,
                root_hash: old_root_hash.clone(),
                logical_count: 8,
                dummy_count: 24,
                last_writeback_digest: old_writeback_digest.clone(),
            }],
            client_state_digest: digest(marker.wrapping_add(10)),
            last_mutation_id: (old_sequence > 0).then_some(previous_mutation_id.clone()),
            owner_signing_key_id: key_id.clone(),
            signed_at_unix: 80,
        };
        let new_state = PrivateOramSignedStateV2 {
            version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: manifest_digest.clone(),
            layout_generation: 5,
            layout_digest: layout_digest.clone(),
            state_sequence: old_sequence + 1,
            indexes: vec![PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: "secret-index".to_string(),
                index_epoch: 12,
                root_hash: new_root_hash.clone(),
                logical_count: 9,
                dummy_count: 23,
                last_writeback_digest: new_writeback_digest.clone(),
            }],
            client_state_digest: digest(marker.wrapping_add(11)),
            last_mutation_id: Some(mutation_id.clone()),
            owner_signing_key_id: key_id.clone(),
            signed_at_unix: 120,
        };
        let old_state_bundle = package_private_oram_signed_state_v2(&key_pair, old_state).unwrap();
        let new_state_bundle = package_private_oram_signed_state_v2(&key_pair, new_state).unwrap();
        let staged_frame = visible.then(|| PrivateOramStagedInsertFrameV1 {
            version: PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: manifest_digest.clone(),
            mutation_id: mutation_id.clone(),
            old_state_digest: private_oram_signed_state_v2_digest(&old_state_bundle.state).unwrap(),
            new_state_digest: private_oram_signed_state_v2_digest(&new_state_bundle.state).unwrap(),
            layout_generation: 5,
            layout_digest: layout_digest.clone(),
            old_state_sequence: old_sequence,
            new_state_sequence: old_sequence + 1,
            writer_lease_digest: writer_lease_digest.clone(),
            writer_fence: 9,
            target_shard_ids: vec![11],
            shard_key: None,
            point: PrivateOramStagedPointV1 {
                id: PrivateOramStagedPointIdV1::Numeric { value: 42 },
                vectors: Vec::new(),
                payload: None,
            },
        });
        let staged_frame_bytes = staged_frame
            .as_ref()
            .map(encode_private_oram_staged_insert_frame_v1)
            .transpose()
            .unwrap();
        let (point_operation_kind, point_operation_digest) = if visible {
            let staged_insert_sha256 =
                private_oram_staged_insert_frame_v1_digest(staged_frame.as_ref().unwrap()).unwrap();
            (
                PrivateOramPointOperationKindV1::VisiblePointRecord,
                private_oram_visible_point_record_v1_digest(
                    &collection_id,
                    &manifest_digest,
                    &mutation_id,
                    PrivateOramVisiblePointRecordV1 {
                        point_id: "42",
                        staged_insert_sha256: &staged_insert_sha256,
                    },
                )
                .unwrap(),
            )
        } else {
            (
                PrivateOramPointOperationKindV1::NoServerPointRecord,
                private_oram_no_server_point_record_v1_digest(
                    &collection_id,
                    &manifest_digest,
                    &mutation_id,
                )
                .unwrap(),
            )
        };
        let mutation_bundle = package_private_oram_append_mutation_v1(
            &key_pair,
            PrivateOramAppendMutationV1 {
                version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
                mutation_id: mutation_id.clone(),
                collection_id: collection_id.clone(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 5,
                writer_lease_digest: writer_lease_digest.clone(),
                writer_fence: 9,
                issued_at_unix: 100,
                expires_at_unix: 200,
                old_state: old_state_bundle,
                new_state: new_state_bundle,
                point_operation_kind,
                point_operation_digest: point_operation_digest.clone(),
                writebacks: vec![writeback],
                owner_signing_key_id: key_id,
            },
        )
        .unwrap();
        let signed_mutation_digest =
            private_oram_append_mutation_v1_digest(&mutation_bundle.mutation).unwrap();
        let old_state_digest =
            private_oram_signed_state_v2_digest(&mutation_bundle.mutation.old_state.state).unwrap();
        let new_state_digest =
            private_oram_signed_state_v2_digest(&mutation_bundle.mutation.new_state.state).unwrap();
        let old_consensus = PrivateOramConsensusCollectionStateV2 {
            version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest: manifest_digest.clone(),
            layout_generation: 5,
            layout_digest: layout_digest.clone(),
            state_sequence: old_sequence,
            signed_state_digest: old_state_digest.clone(),
            indexes: vec![PrivateOramConsensusCollectionIndexStateV2 {
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: "secret-index".to_string(),
                epoch: PrivateOramConsensusEpoch {
                    index_epoch: 11,
                    root_hash: old_root_hash,
                    writeback_digest: Some(old_writeback_digest),
                },
                logical_count: 8,
                dummy_count: 24,
            }],
            client_state_digest: mutation_bundle
                .mutation
                .old_state
                .state
                .client_state_digest
                .clone(),
            last_transition: if old_sequence == 0 {
                PrivateOramConsensusTransitionV2::Genesis
            } else {
                PrivateOramConsensusTransitionV2::Mutation(PrivateOramMutationReceiptV2 {
                    version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
                    mutation_id: previous_mutation_id,
                    signed_mutation_digest: digest(marker.wrapping_add(14)),
                    transition_digest: digest(marker.wrapping_add(15)),
                    old_state_sequence: old_sequence - 1,
                    old_state_digest: digest(marker.wrapping_add(16)),
                    new_state_sequence: old_sequence,
                    new_state_digest: old_state_digest.clone(),
                    point_operation_digest: digest(marker.wrapping_add(17)),
                    writer_lease_digest: digest(marker.wrapping_add(18)),
                    writer_fence: 1,
                    mutation_lease_generation: 1,
                })
            },
        };
        let base_record_digest =
            canonical_private_oram_consensus_state_record_digest(&old_consensus).unwrap();
        let mutation_lease_generation = 9;
        let receipt = PrivateOramMutationReceiptV2 {
            version: PRIVATE_ORAM_MUTATION_RECEIPT_VERSION,
            mutation_id: mutation_id.clone(),
            signed_mutation_digest: signed_mutation_digest.clone(),
            transition_digest: digest(marker.wrapping_add(12)),
            old_state_sequence: old_sequence,
            old_state_digest,
            new_state_sequence: old_sequence + 1,
            new_state_digest: new_state_digest.clone(),
            point_operation_digest,
            writer_lease_digest: writer_lease_digest.clone(),
            writer_fence: 9,
            mutation_lease_generation,
        };
        let mut new_consensus = PrivateOramConsensusCollectionStateV2 {
            version: PRIVATE_ORAM_CONSENSUS_COLLECTION_STATE_VERSION,
            collection_id: collection_id.clone(),
            manifest_digest,
            layout_generation: 5,
            layout_digest,
            state_sequence: old_sequence + 1,
            signed_state_digest: new_state_digest,
            indexes: vec![PrivateOramConsensusCollectionIndexStateV2 {
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: "secret-index".to_string(),
                epoch: PrivateOramConsensusEpoch {
                    index_epoch: 12,
                    root_hash: new_root_hash,
                    writeback_digest: Some(new_writeback_digest),
                },
                logical_count: 9,
                dummy_count: 23,
            }],
            client_state_digest: mutation_bundle
                .mutation
                .new_state
                .state
                .client_state_digest
                .clone(),
            last_transition: PrivateOramConsensusTransitionV2::Mutation(receipt),
        };
        let transition_digest =
            canonical_private_oram_mutation_transition_digest(&old_consensus, &new_consensus)
                .unwrap();
        let PrivateOramConsensusTransitionV2::Mutation(receipt) =
            &mut new_consensus.last_transition
        else {
            unreachable!();
        };
        receipt.transition_digest = transition_digest.clone();
        let receipt_digest = canonical_private_oram_mutation_receipt_digest(receipt).unwrap();
        let committed_record_digest =
            canonical_private_oram_consensus_state_record_digest(&new_consensus).unwrap();
        let preparing_lease = PrivateOramMutationLease {
            generation: mutation_lease_generation,
            collection_id,
            owner_peer_id: 11,
            mutation_id,
            signed_mutation_digest,
            transition_digest,
            base_record_digest,
            base_state_sequence: old_sequence,
            writer_lease_digest,
            writer_fence: 9,
            issued_at_unix: 90,
            expires_at_unix: 210,
            renewal_revision: 0,
            phase: PrivateOramMutationLeasePhase::Preparing,
        };
        let mut committed_lease = preparing_lease.clone();
        committed_lease.phase = PrivateOramMutationLeasePhase::ConsensusCommitted {
            committed_record_digest,
            committed_state_sequence: old_sequence + 1,
            committed_signed_state_digest: new_consensus.signed_state_digest.clone(),
            receipt_digest,
        };
        Fixture {
            public_key: key_pair.public_key().as_ref().to_vec(),
            mutation_bundle,
            preparing_lease,
            committed_lease,
            old_consensus,
            new_consensus,
            staged_frame_bytes,
        }
    }

    fn journal(temp: &TempDir, fixture: &Fixture) -> PrivateOramMutationJournal {
        let collection = temp.path().join("collection");
        if !collection.exists() {
            fs::create_dir(&collection).unwrap();
        }
        PrivateOramMutationJournal::new(
            &collection,
            "tenant-a/private-oram-owner-v2",
            fixture.public_key.clone(),
        )
        .unwrap()
    }

    fn begin(
        journal: &PrivateOramMutationJournal,
        fixture: &Fixture,
        owners: &[PeerId],
    ) -> PrivateOramMutationJournalSnapshotV1 {
        journal
            .begin(
                11,
                owners,
                fixture.mutation_bundle.clone(),
                fixture.preparing_lease.clone(),
                fixture.old_consensus.clone(),
            )
            .unwrap()
    }

    fn owner_prepares(
        snapshot: &PrivateOramMutationJournalSnapshotV1,
    ) -> Vec<PrivateOramMutationOwnerPrepareEvidenceV1> {
        owner_prepares_for_descriptor(&snapshot.descriptor)
    }

    fn owner_prepares_v2(
        snapshot: &writer_v2::PrivateOramMutationJournalStructuralSnapshotV2,
    ) -> Vec<PrivateOramMutationOwnerPrepareEvidenceV1> {
        owner_prepares_for_descriptor(&snapshot.descriptor)
    }

    fn owner_prepares_for_descriptor(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
    ) -> Vec<PrivateOramMutationOwnerPrepareEvidenceV1> {
        descriptor
            .owner_requirements
            .iter()
            .enumerate()
            .map(
                |(offset, requirement)| PrivateOramMutationOwnerPrepareEvidenceV1 {
                    peer_id: requirement.peer_id,
                    kind: requirement.kind,
                    index_name: requirement.index_name.clone(),
                    prepared_journal_digest: digest(150 + u8::try_from(offset).unwrap()),
                },
            )
            .collect()
    }

    fn begin_v2(
        journal: &PrivateOramMutationJournal,
        fixture: &Fixture,
        owners: &[PeerId],
    ) -> writer_v2::PrivateOramMutationJournalStructuralSnapshotV2 {
        journal
            .begin_v2(
                11,
                owners,
                fixture.mutation_bundle.clone(),
                fixture.preparing_lease.clone(),
                fixture.old_consensus.clone(),
            )
            .unwrap()
    }

    fn finalizations(
        snapshot: &PrivateOramMutationJournalSnapshotV1,
        local: bool,
    ) -> Vec<PrivateOramMutationOwnerFinalizeEvidenceV1> {
        snapshot
            .state
            .owner_prepares
            .iter()
            .filter(|evidence| {
                (evidence.peer_id == snapshot.descriptor.coordinator_peer_id) == local
            })
            .enumerate()
            .map(
                |(offset, evidence)| PrivateOramMutationOwnerFinalizeEvidenceV1 {
                    peer_id: evidence.peer_id,
                    kind: evidence.kind,
                    index_name: evidence.index_name.clone(),
                    prepared_journal_digest: evidence.prepared_journal_digest.clone(),
                    finalized_state_digest: digest(180 + u8::try_from(offset).unwrap()),
                },
            )
            .collect()
    }

    fn mark_no_server_point_stage(
        journal: &PrivateOramMutationJournal,
    ) -> PrivateOramMutationJournalSnapshotV1 {
        let parent = journal.validated_point_stage_parent().unwrap();
        journal.mark_no_server_point_stage_durable(&parent).unwrap()
    }

    fn active_lease_slot(lease: PrivateOramMutationLease) -> PrivateOramMutationLeaseSlotV2 {
        PrivateOramMutationLeaseSlotV2 {
            version: PRIVATE_ORAM_MUTATION_LEASE_SLOT_VERSION,
            generation: lease.generation,
            active: Some(lease.clone()),
            last_clear: None,
            max_writer_fence: lease.writer_fence,
        }
    }

    fn reconcile_snapshot(
        consensus_state: &PrivateOramConsensusCollectionStateV2,
        lease: PrivateOramMutationLease,
    ) -> PrivateOramMutationReconcileSnapshotV1 {
        PrivateOramMutationReconcileSnapshotV1::from_parts_for_test(
            consensus_state.clone(),
            active_lease_slot(lease),
        )
    }

    fn empty_v2_state(
        phase: PrivateOramMutationJournalPhaseV2,
    ) -> PrivateOramMutationJournalStateV2 {
        PrivateOramMutationJournalStateV2 {
            version: PRIVATE_ORAM_MUTATION_STATE_V2_VERSION,
            sequence: phase.sequence(),
            phase,
            origin: PrivateOramMutationStateOriginV2::FreshV2,
            predecessor: PrivateOramMutationStatePredecessorV2::Genesis,
            owner_prepares: Vec::new(),
            point_stage: None,
            decision: None,
            remote_terminals: None,
            local_terminals: None,
            point_resolution: None,
            record_digest: String::new(),
        }
    }

    fn v2_terminal_evidence(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
        state: &PrivateOramMutationJournalStateV2,
        owner_peer_id: PeerId,
        kind: PrivateOramMutationOwnerTerminalKindV2,
        marker: u8,
    ) -> PrivateOramMutationOwnerTerminalEvidenceV2 {
        let decision = state.decision.as_ref().unwrap();
        let (decision_authority_record_digest, reconciliation_authority_digest) =
            expected_owner_recovery_authority_digest_v1(
                descriptor,
                &state.owner_prepares,
                decision.decided_lease(),
                decision.reconcile_disposition(),
                owner_peer_id,
            )
            .unwrap();
        let indexes = descriptor
            .owner_requirements
            .iter()
            .filter(|requirement| requirement.peer_id == owner_peer_id)
            .enumerate()
            .map(|(offset, requirement)| {
                let prepared = state
                    .owner_prepares
                    .iter()
                    .find(|prepared| {
                        prepared.peer_id == owner_peer_id
                            && prepared.kind == requirement.kind
                            && prepared.index_name == requirement.index_name
                    })
                    .unwrap();
                PrivateOramMutationOwnerTerminalIndexEvidenceV2 {
                    kind: requirement.kind,
                    index_name: requirement.index_name.clone(),
                    prepared_journal_digest: prepared.prepared_journal_digest.clone(),
                    terminal_state_digest: digest(
                        marker.wrapping_add(8).wrapping_add(offset as u8),
                    ),
                }
            })
            .collect();
        let mut evidence = PrivateOramMutationOwnerTerminalEvidenceV2 {
            owner_peer_id,
            journal_descriptor_digest: digest(marker),
            prepared_state_digest: digest(marker.wrapping_add(1)),
            terminal_record_digest: digest(marker.wrapping_add(2)),
            parent_descriptor_digest: descriptor.descriptor_digest.clone(),
            decision_authority_record_digest,
            reconciliation_authority_digest,
            indexes,
            terminal_evidence_digest: String::new(),
        };
        evidence.terminal_evidence_digest = private_oram_owner_terminal_evidence_v2_digest(
            &descriptor.descriptor_digest,
            kind,
            &evidence,
        )
        .unwrap();
        evidence
    }

    fn v2_no_server_terminal_state(
        initial: &PrivateOramMutationJournalSnapshotV1,
        fixture: &Fixture,
        decision_kind: PrivateOramMutationDecisionKindV2,
        target_phase: PrivateOramMutationJournalPhaseV2,
    ) -> PrivateOramMutationJournalStateV2 {
        assert!(
            target_phase.sequence()
                >= PrivateOramMutationJournalPhaseV2::DecisionDurable.sequence()
        );
        assert_eq!(initial.descriptor.owner_requirements.len(), 1);

        let mut prepared = empty_v2_state(PrivateOramMutationJournalPhaseV2::OwnersPrepared);
        prepared.owner_prepares = owner_prepares(initial);
        let prepared =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &prepared)
                .unwrap();
        let decision = match decision_kind {
            PrivateOramMutationDecisionKindV2::ExactNew => exact_new_decision_v2_for_test(
                &initial.descriptor,
                &fixture.committed_lease,
                &fixture.new_consensus,
            )
            .unwrap(),
            PrivateOramMutationDecisionKindV2::ExactOldAbort => {
                let mut abort_decided = fixture.preparing_lease.clone();
                abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
                exact_old_abort_decision_v2_for_test(
                    &initial.descriptor,
                    &abort_decided,
                    &fixture.old_consensus,
                )
                .unwrap()
            }
        };
        let terminal_kind = match decision_kind {
            PrivateOramMutationDecisionKindV2::ExactNew => {
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew
            }
            PrivateOramMutationDecisionKindV2::ExactOldAbort => {
                PrivateOramMutationOwnerTerminalKindV2::AbortedOld
            }
        };
        let mut state = empty_v2_state(target_phase);
        state.owner_prepares = prepared.owner_prepares;
        state.point_stage = Some(
            PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
                parent_owners_prepared_record_digest: prepared.record_digest,
            },
        );
        state.decision = Some(decision);
        if target_phase.sequence() >= PrivateOramMutationJournalPhaseV2::RemotesTerminal.sequence()
        {
            state.remote_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
                kind: terminal_kind,
                owners: Vec::new(),
            });
        }
        if target_phase.sequence() >= PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence() {
            let terminal = v2_terminal_evidence(
                &initial.descriptor,
                &state,
                initial.descriptor.coordinator_peer_id,
                terminal_kind,
                211,
            );
            state.local_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
                kind: terminal_kind,
                owners: vec![terminal],
            });
        }
        if target_phase == PrivateOramMutationJournalPhaseV2::PointResolved {
            let local_terminal = canonical_private_oram_mutation_state_v2_for_test(
                &initial.descriptor,
                &PrivateOramMutationJournalStateV2 {
                    phase: PrivateOramMutationJournalPhaseV2::LocalTerminal,
                    sequence: PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence(),
                    point_resolution: None,
                    ..state.clone()
                },
            )
            .unwrap();
            state.point_resolution = Some(
                PrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
                    decision_kind,
                    parent_local_terminal_record_digest: local_terminal.record_digest,
                },
            );
        }
        canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &state).unwrap()
    }

    fn v2_visible_point_resolved_state(
        initial: &PrivateOramMutationJournalSnapshotV1,
        fixture: &Fixture,
        outcome: PrivateOramPointResolutionOutcomeV2,
    ) -> PrivateOramMutationJournalStateV2 {
        assert_eq!(initial.descriptor.owner_requirements.len(), 1);
        let frame_bytes = fixture.staged_frame_bytes.as_ref().unwrap();
        let staged_insert_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(frame_bytes));
        let child_descriptor_digest = digest(231);
        let canonical_point_id_digest = private_oram_point_id_digest("42").unwrap();

        let mut prepared = empty_v2_state(PrivateOramMutationJournalPhaseV2::OwnersPrepared);
        prepared.owner_prepares = owner_prepares(initial);
        let prepared =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &prepared)
                .unwrap();
        let (decision_kind, terminal_kind, decision) = match outcome {
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew => (
                PrivateOramMutationDecisionKindV2::ExactNew,
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                exact_new_decision_v2_for_test(
                    &initial.descriptor,
                    &fixture.committed_lease,
                    &fixture.new_consensus,
                )
                .unwrap(),
            ),
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld => {
                let mut abort_decided = fixture.preparing_lease.clone();
                abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
                (
                    PrivateOramMutationDecisionKindV2::ExactOldAbort,
                    PrivateOramMutationOwnerTerminalKindV2::AbortedOld,
                    exact_old_abort_decision_v2_for_test(
                        &initial.descriptor,
                        &abort_decided,
                        &fixture.old_consensus,
                    )
                    .unwrap(),
                )
            }
        };
        let mut state = empty_v2_state(PrivateOramMutationJournalPhaseV2::LocalTerminal);
        state.owner_prepares = prepared.owner_prepares;
        state.point_stage = Some(
            PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
                point_id: "42".to_string(),
                staged_insert_sha256: staged_insert_sha256.clone(),
                canonical_point_id_digest: canonical_point_id_digest.clone(),
                point_semantic_digest: digest(232),
                child_descriptor_digest: child_descriptor_digest.clone(),
                target_shard_ids: vec![11],
                parent_owners_prepared_record_digest: prepared.record_digest,
            },
        );
        state.decision = Some(decision);
        state.remote_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: terminal_kind,
            owners: Vec::new(),
        });
        state.local_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: terminal_kind,
            owners: vec![v2_terminal_evidence(
                &initial.descriptor,
                &state,
                initial.descriptor.coordinator_peer_id,
                terminal_kind,
                221,
            )],
        });
        let local_terminal =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &state).unwrap();
        let observations = match outcome {
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew => {
                vec![PrivateOramPointReplicaObservationV2::Exact {
                    shard_id: 11,
                    peer_id: 11,
                    point_semantic_digest: digest(232),
                }]
            }
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld => {
                vec![PrivateOramPointReplicaObservationV2::Absent {
                    shard_id: 11,
                    peer_id: 11,
                }]
            }
        };
        let replicas = vec![PrivateOramPointReplicaTargetV2 {
            shard_id: 11,
            peer_id: 11,
        }];
        let mutation = &initial.descriptor.mutation_bundle.mutation;
        let mut receipt = PrivateOramPointResolutionReceiptV2 {
            version: PRIVATE_ORAM_POINT_RESOLUTION_RECEIPT_V2_VERSION,
            collection_id_digest: private_oram_collection_id_digest_v2(&mutation.collection_id)
                .unwrap(),
            mutation_digest: initial.descriptor.mutation_digest.clone(),
            point_operation_digest: mutation.point_operation_digest.clone(),
            child_descriptor_digest,
            staged_insert_sha256,
            canonical_point_id_digest,
            layout_generation: mutation.layout_generation,
            layout_digest: mutation.new_state.state.layout_digest.clone(),
            target_shard_ids: vec![11],
            replica_set_digest: private_oram_point_replica_set_digest_v2(&replicas).unwrap(),
            replicas,
            expected_point_semantic_digest: digest(232),
            observations,
            parent_local_terminal_record_digest: local_terminal.record_digest.clone(),
            receipt_digest: String::new(),
        };
        receipt.receipt_digest =
            private_oram_point_resolution_receipt_v2_digest(outcome, &receipt).unwrap();
        state = local_terminal;
        state.phase = PrivateOramMutationJournalPhaseV2::PointResolved;
        state.sequence = PrivateOramMutationJournalPhaseV2::PointResolved.sequence();
        state.point_resolution = Some(match (decision_kind, outcome) {
            (
                PrivateOramMutationDecisionKindV2::ExactNew,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            ) => PrivateOramMutationPointResolutionEvidenceV2::PublishedExactNew { receipt },
            (
                PrivateOramMutationDecisionKindV2::ExactOldAbort,
                PrivateOramPointResolutionOutcomeV2::AbortedExactOld,
            ) => PrivateOramMutationPointResolutionEvidenceV2::AbortedExactOld { receipt },
            _ => unreachable!(),
        });
        canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &state).unwrap()
    }

    fn point_resolution_receipt_for_local_state(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
        local_state: &PrivateOramMutationJournalStateV2,
        outcome: PrivateOramPointResolutionOutcomeV2,
    ) -> PrivateOramPointResolutionReceiptV2 {
        let PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
            staged_insert_sha256,
            canonical_point_id_digest,
            point_semantic_digest,
            child_descriptor_digest,
            target_shard_ids,
            ..
        } = local_state.point_stage.as_ref().unwrap()
        else {
            panic!("expected visible point stage");
        };
        let replicas = target_shard_ids
            .iter()
            .map(|shard_id| PrivateOramPointReplicaTargetV2 {
                shard_id: *shard_id,
                peer_id: descriptor.coordinator_peer_id,
            })
            .collect::<Vec<_>>();
        let observations = replicas
            .iter()
            .map(|replica| match outcome {
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew => {
                    PrivateOramPointReplicaObservationV2::Exact {
                        shard_id: replica.shard_id,
                        peer_id: replica.peer_id,
                        point_semantic_digest: point_semantic_digest.clone(),
                    }
                }
                PrivateOramPointResolutionOutcomeV2::AbortedExactOld => {
                    PrivateOramPointReplicaObservationV2::Absent {
                        shard_id: replica.shard_id,
                        peer_id: replica.peer_id,
                    }
                }
            })
            .collect();
        let mutation = &descriptor.mutation_bundle.mutation;
        let mut receipt = PrivateOramPointResolutionReceiptV2 {
            version: PRIVATE_ORAM_POINT_RESOLUTION_RECEIPT_V2_VERSION,
            collection_id_digest: private_oram_collection_id_digest_v2(&mutation.collection_id)
                .unwrap(),
            mutation_digest: descriptor.mutation_digest.clone(),
            point_operation_digest: mutation.point_operation_digest.clone(),
            child_descriptor_digest: child_descriptor_digest.clone(),
            staged_insert_sha256: staged_insert_sha256.clone(),
            canonical_point_id_digest: canonical_point_id_digest.clone(),
            layout_generation: mutation.layout_generation,
            layout_digest: mutation.new_state.state.layout_digest.clone(),
            target_shard_ids: target_shard_ids.clone(),
            replica_set_digest: private_oram_point_replica_set_digest_v2(&replicas).unwrap(),
            replicas,
            expected_point_semantic_digest: point_semantic_digest.clone(),
            observations,
            parent_local_terminal_record_digest: local_state.record_digest.clone(),
            receipt_digest: String::new(),
        };
        receipt.receipt_digest =
            private_oram_point_resolution_receipt_v2_digest(outcome, &receipt).unwrap();
        receipt
    }

    fn v2_record_path(journal: &PrivateOramMutationJournal, sequence: u64) -> PathBuf {
        journal
            .active_path()
            .join("state_records")
            .join(format!("{sequence:020}.json"))
    }

    fn install_v2_state_for_test(
        journal: &PrivateOramMutationJournal,
        descriptor: &PrivateOramMutationJournalDescriptorV1,
        state: &PrivateOramMutationJournalStateV2,
    ) {
        let history = canonical_private_oram_mutation_state_history_v2(descriptor, state).unwrap();
        for record in history.iter().skip(1) {
            let path = v2_record_path(journal, record.sequence);
            if path.exists() {
                let existing: PrivateOramMutationJournalStateV2 =
                    read_json_private(&path, MAX_STATE_BYTES).unwrap();
                assert_eq!(&existing, record);
            } else {
                write_new_json_private(&path, record, MAX_STATE_BYTES).unwrap();
            }
        }
        fs::write(journal.state_path(), serde_json::to_vec(state).unwrap()).unwrap();
        sync_directory(&journal.active_path().join("state_records")).unwrap();
        sync_directory(&journal.active_path()).unwrap();
    }

    fn v1_snapshot_for_descriptor(
        descriptor: &PrivateOramMutationJournalDescriptorV1,
    ) -> PrivateOramMutationJournalSnapshotV1 {
        PrivateOramMutationJournalSnapshotV1 {
            descriptor: descriptor.clone(),
            state: PrivateOramMutationJournalStateV1 {
                version: PRIVATE_ORAM_MUTATION_JOURNAL_VERSION,
                sequence: 1,
                phase: PrivateOramMutationJournalPhaseV1::LeaseAcquired,
                previous_record_digest: None,
                owner_prepares: Vec::new(),
                point_stage: None,
                consensus: None,
                remote_finalizations: Vec::new(),
                local_finalizations: Vec::new(),
                record_digest: digest(250),
            },
        }
    }

    #[test]
    fn v2_writer_persists_exact_new_decision_as_actual_history() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(43, 150);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        assert_eq!(
            initial.state.phase,
            PrivateOramMutationJournalPhaseV2::LeaseAcquired
        );

        let prepared = journal
            .mark_owners_prepared_v2(owner_prepares_v2(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        assert_eq!(
            parent.owners_prepared_record_digest(),
            prepared.state.record_digest
        );
        let staged = journal
            .mark_no_server_point_stage_durable_v2(&parent)
            .unwrap();
        assert_eq!(
            staged.state.phase,
            PrivateOramMutationJournalPhaseV2::PointStageDurable
        );
        assert!(
            journal
                .validated_decision_for_v2_state(
                    &reconcile_snapshot(&fixture.old_consensus, fixture.preparing_lease.clone(),),
                    None
                )
                .is_err()
        );

        let decision = journal
            .validated_decision_for_v2_state(
                &reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone()),
                None,
            )
            .unwrap();
        assert_eq!(decision.kind(), PrivateOramMutationDecisionKindV2::ExactNew);
        let (decided, decision_durable) = journal.mark_decision_durable_v2(&decision).unwrap();
        assert_eq!(
            decided.state.phase,
            PrivateOramMutationJournalPhaseV2::DecisionDurable
        );
        assert_eq!(decided.state.sequence, 4);
        assert!(decided.pending_next_for_test().is_none());
        let (_, mut wrong_predecessor) = journal.mark_decision_durable_v2(&decision).unwrap();
        wrong_predecessor.decision_record_digest = digest(249);
        assert!(matches!(
            journal.mark_remotes_terminal_v2(&wrong_predecessor, &[]),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let (remotes, remotes_terminal) = journal
            .mark_remotes_terminal_v2(&decision_durable, &[])
            .unwrap();
        assert_eq!(
            remotes.state.phase,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal
        );
        assert!(matches!(
            journal.mark_local_terminal_v2(
                &remotes_terminal,
                &PrivateOramValidatedOwnerRecoveryOutcomeV1::ObservedOld,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        assert_eq!(
            fs::read_dir(journal.active_path().join("state_records"))
                .unwrap()
                .count(),
            5
        );
        assert_eq!(journal.load_v2().unwrap().unwrap(), remotes);
        let rendered =
            format!("{decision:?} {decision_durable:?} {remotes_terminal:?} {remotes:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
    }

    #[test]
    fn v2_writer_requires_abort_decision_for_exact_old() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(44, 160);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared_v2(owner_prepares_v2(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        journal
            .mark_no_server_point_stage_durable_v2(&parent)
            .unwrap();
        assert!(
            journal
                .validated_decision_for_v2_state(
                    &reconcile_snapshot(&fixture.old_consensus, fixture.preparing_lease.clone(),),
                    None
                )
                .is_err()
        );

        let mut abort_decided = fixture.preparing_lease.clone();
        abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
        let decision = journal
            .validated_decision_for_v2_state(
                &reconcile_snapshot(&fixture.old_consensus, abort_decided),
                None,
            )
            .unwrap();
        assert_eq!(
            decision.kind(),
            PrivateOramMutationDecisionKindV2::ExactOldAbort
        );
        let (decided, decision_durable) = journal.mark_decision_durable_v2(&decision).unwrap();
        assert_eq!(
            decided.state.phase,
            PrivateOramMutationJournalPhaseV2::DecisionDurable
        );
        assert_eq!(
            journal
                .mark_remotes_terminal_v2(&decision_durable, &[])
                .unwrap()
                .0
                .state
                .phase,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal
        );
    }

    #[test]
    fn v2_writer_point_resolution_requires_exact_local_terminal_token() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(59, 120);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let synthetic = v1_snapshot_for_descriptor(&initial.descriptor);
        let local_state = v2_no_server_terminal_state(
            &synthetic,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        install_v2_state_for_test(&journal, &initial.descriptor, &local_state);

        let local = journal.validated_local_terminal_for_current_v2().unwrap();
        let resolved = journal.mark_no_server_point_resolved_v2(&local).unwrap();
        assert_eq!(
            resolved.state.phase,
            PrivateOramMutationJournalPhaseV2::PointResolved
        );
        assert_eq!(resolved.state.sequence, 7);
        assert_eq!(
            journal.mark_no_server_point_resolved_v2(&local).unwrap(),
            resolved
        );

        let mut wrong_local = journal.validated_local_terminal_for_current_v2().unwrap();
        wrong_local.local_terminal_record_digest = digest(249);
        assert!(matches!(
            journal.mark_no_server_point_resolved_v2(&wrong_local),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let rendered = format!("{local:?} {wrong_local:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
    }

    #[test]
    fn v2_writer_rolls_forward_only_the_exact_pending_point_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(61, 160);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let synthetic = v1_snapshot_for_descriptor(&initial.descriptor);
        let local_state = v2_no_server_terminal_state(
            &synthetic,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        install_v2_state_for_test(&journal, &initial.descriptor, &local_state);
        let pending = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &local_state,
            PrivateOramMutationJournalPhaseV2::PointResolved,
            |next| {
                next.point_resolution = Some(
                    PrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
                        decision_kind: PrivateOramMutationDecisionKindV2::ExactNew,
                        parent_local_terminal_record_digest: local_state.record_digest.clone(),
                    },
                );
                Ok(())
            },
        )
        .unwrap();
        write_new_json_private(
            &v2_record_path(&journal, pending.sequence),
            &pending,
            MAX_STATE_BYTES,
        )
        .unwrap();
        let observed = journal.load_v2().unwrap().unwrap();
        assert_eq!(observed.state, local_state);
        assert_eq!(observed.pending_next_for_test(), Some(&pending));

        let local = journal.validated_local_terminal_for_current_v2().unwrap();
        let resolved = journal.mark_no_server_point_resolved_v2(&local).unwrap();
        assert_eq!(resolved.state, pending);
        assert!(resolved.pending_next_for_test().is_none());
    }

    #[test]
    fn v2_writer_validates_visible_point_receipt_under_live_stage_lock() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(60, 140, 0, true);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared_v2(owner_prepares_v2(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        let collection_path = temp.path().join("collection");
        let point_store = PrivateOramPointStagingStore::new(&collection_path);
        let (_, durable) = point_store
            .prepare(fixture.staged_frame_bytes.as_deref().unwrap(), &parent)
            .unwrap();
        let staged = journal
            .mark_private_point_stage_durable_v2(&durable)
            .unwrap();

        let mut local_state = staged.state.clone();
        local_state.phase = PrivateOramMutationJournalPhaseV2::LocalTerminal;
        local_state.sequence = PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence();
        local_state.decision = Some(
            exact_new_decision_v2_for_test(
                &staged.descriptor,
                &fixture.committed_lease,
                &fixture.new_consensus,
            )
            .unwrap(),
        );
        local_state.remote_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            owners: Vec::new(),
        });
        local_state.local_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            owners: vec![v2_terminal_evidence(
                &staged.descriptor,
                &local_state,
                staged.descriptor.coordinator_peer_id,
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                241,
            )],
        });
        local_state =
            canonical_private_oram_mutation_state_v2_for_test(&staged.descriptor, &local_state)
                .unwrap();
        install_v2_state_for_test(&journal, &staged.descriptor, &local_state);

        let local = journal.validated_local_terminal_for_current_v2().unwrap();
        let receipt = point_resolution_receipt_for_local_state(
            &staged.descriptor,
            &local_state,
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
        );
        let foreign_collection = temp.path().join("foreign-collection");
        fs::create_dir(&foreign_collection).unwrap();
        let foreign_store = PrivateOramPointStagingStore::new(&foreign_collection);
        assert!(matches!(
            journal.mark_private_point_resolved_v2(
                &local,
                &foreign_store,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                receipt.clone(),
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut wrong = receipt.clone();
        wrong.observations[0] = PrivateOramPointReplicaObservationV2::Absent {
            shard_id: wrong.replicas[0].shard_id,
            peer_id: wrong.replicas[0].peer_id,
        };
        wrong.receipt_digest = private_oram_point_resolution_receipt_v2_digest(
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            &wrong,
        )
        .unwrap();
        assert!(matches!(
            journal.mark_private_point_resolved_v2(
                &local,
                &point_store,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                wrong,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let resolved = journal
            .mark_private_point_resolved_v2(
                &local,
                &point_store,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                receipt.clone(),
            )
            .unwrap();
        assert_eq!(
            resolved.state.phase,
            PrivateOramMutationJournalPhaseV2::PointResolved
        );
        fs::remove_dir_all(collection_path.join(
            crate::content_manager::private_oram_point_staging::PRIVATE_ORAM_POINT_STAGING_DIR,
        ))
        .unwrap();
        assert_eq!(
            journal
                .mark_private_point_resolved_v2(
                    &local,
                    &point_store,
                    PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                    receipt.clone(),
                )
                .unwrap(),
            resolved
        );
        let mut different_after_cleanup = receipt;
        different_after_cleanup.observations[0] = PrivateOramPointReplicaObservationV2::Absent {
            shard_id: different_after_cleanup.replicas[0].shard_id,
            peer_id: different_after_cleanup.replicas[0].peer_id,
        };
        different_after_cleanup.receipt_digest = private_oram_point_resolution_receipt_v2_digest(
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            &different_after_cleanup,
        )
        .unwrap();
        assert!(matches!(
            journal.mark_private_point_resolved_v2(
                &local,
                &point_store,
                PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
                different_after_cleanup,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let rendered = format!("{local:?} {resolved:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
    }

    #[test]
    fn v2_phase_tokens_reject_cross_descriptor_reuse_and_replay_exactly() {
        let first_temp = tempfile::tempdir().unwrap();
        let first_fixture = fixture(54, 20);
        let first_journal = journal(&first_temp, &first_fixture);
        let first_initial = begin_v2(&first_journal, &first_fixture, &[11]);
        first_journal
            .mark_owners_prepared_v2(owner_prepares_v2(&first_initial))
            .unwrap();
        let first_parent = first_journal.validated_point_stage_parent_v2().unwrap();
        first_journal
            .mark_no_server_point_stage_durable_v2(&first_parent)
            .unwrap();
        let first_decision = first_journal
            .validated_decision_for_v2_state(
                &reconcile_snapshot(
                    &first_fixture.new_consensus,
                    first_fixture.committed_lease.clone(),
                ),
                None,
            )
            .unwrap();
        let (_, first_decision_durable) = first_journal
            .mark_decision_durable_v2(&first_decision)
            .unwrap();

        let second_temp = tempfile::tempdir().unwrap();
        let second_fixture = fixture(55, 40);
        let second_journal = journal(&second_temp, &second_fixture);
        let second_initial = begin_v2(&second_journal, &second_fixture, &[11]);
        second_journal
            .mark_owners_prepared_v2(owner_prepares_v2(&second_initial))
            .unwrap();
        let second_parent = second_journal.validated_point_stage_parent_v2().unwrap();
        second_journal
            .mark_no_server_point_stage_durable_v2(&second_parent)
            .unwrap();
        let second_decision = second_journal
            .validated_decision_for_v2_state(
                &reconcile_snapshot(
                    &second_fixture.new_consensus,
                    second_fixture.committed_lease.clone(),
                ),
                None,
            )
            .unwrap();
        let (_, second_decision_durable) = second_journal
            .mark_decision_durable_v2(&second_decision)
            .unwrap();

        assert!(matches!(
            second_journal.mark_remotes_terminal_v2(&first_decision_durable, &[]),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let (first_remote, first_remote_token) = second_journal
            .mark_remotes_terminal_v2(&second_decision_durable, &[])
            .unwrap();
        let (replayed_remote, replayed_remote_token) = second_journal
            .mark_remotes_terminal_v2(&second_decision_durable, &[])
            .unwrap();
        assert_eq!(replayed_remote, first_remote);
        assert_eq!(
            replayed_remote_token.remotes_terminal_record_digest,
            first_remote_token.remotes_terminal_record_digest
        );
    }

    #[test]
    fn v2_writer_accepts_only_durable_visible_point_stage_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(51, 230, 0, true);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared_v2(owner_prepares_v2(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent_v2().unwrap();
        let point_store = PrivateOramPointStagingStore::new(&temp.path().join("collection"));
        let (_, durable) = point_store
            .prepare(fixture.staged_frame_bytes.as_deref().unwrap(), &parent)
            .unwrap();
        let staged = journal
            .mark_private_point_stage_durable_v2(&durable)
            .unwrap();
        let Some(PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
            point_semantic_digest,
            target_shard_ids,
            ..
        }) = staged.state.point_stage.as_ref()
        else {
            panic!("expected visible private point stage");
        };
        assert_eq!(point_semantic_digest, durable.point_semantic_digest());
        assert_eq!(target_shard_ids, durable.target_shard_ids());
        assert_eq!(journal.load_v2().unwrap().unwrap(), staged);
        let reconcile = reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone());
        assert!(
            journal
                .validated_decision_for_v2_state(&reconcile, None)
                .is_err()
        );
        let decision = journal
            .validated_decision_for_v2_state(&reconcile, Some(&durable))
            .unwrap();
        assert_eq!(decision.kind(), PrivateOramMutationDecisionKindV2::ExactNew);
    }

    #[test]
    fn v2_writer_rejects_legacy_and_mixed_active_layouts() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(45, 170);
        let journal = journal(&temp, &fixture);
        begin(&journal, &fixture, &[11]);
        assert!(matches!(
            journal.load_v2(),
            Err(PrivateOramMutationJournalError::LegacyV1State)
        ));
        assert!(matches!(
            journal.begin_v2(
                11,
                &[11],
                fixture.mutation_bundle.clone(),
                fixture.preparing_lease.clone(),
                fixture.old_consensus.clone(),
            ),
            Err(PrivateOramMutationJournalError::LegacyV1State)
        ));

        write_new_json_private(
            &journal.active_path().join("format.json"),
            &json!({
                "state_version": 2,
                "descriptor_digest": digest(250),
            }),
            1 << 12,
        )
        .unwrap();
        assert!(matches!(
            journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_writer_resumes_only_an_exact_pending_typed_transition() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(46, 180);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let prepares = owner_prepares_v2(&initial);
        let pending = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &initial.state,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            |next| {
                next.owner_prepares = prepares.clone();
                Ok(())
            },
        )
        .unwrap();
        write_new_json_private(
            &v2_record_path(&journal, pending.sequence),
            &pending,
            MAX_STATE_BYTES,
        )
        .unwrap();

        let observed = journal.load_v2().unwrap().unwrap();
        assert_eq!(observed.state, initial.state);
        assert_eq!(observed.pending_next_for_test(), Some(&pending));
        let resumed = journal.mark_owners_prepared_v2(prepares).unwrap();
        assert_eq!(resumed.state, pending);
        assert!(resumed.pending_next_for_test().is_none());
    }

    #[test]
    fn v2_writer_rejects_different_evidence_for_pending_record() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(47, 190);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let prepares = owner_prepares_v2(&initial);
        let pending = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &initial.state,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            |next| {
                next.owner_prepares = prepares.clone();
                Ok(())
            },
        )
        .unwrap();
        write_new_json_private(
            &v2_record_path(&journal, pending.sequence),
            &pending,
            MAX_STATE_BYTES,
        )
        .unwrap();

        let mut different = prepares;
        different[0].prepared_journal_digest = digest(249);
        assert!(matches!(
            journal.mark_owners_prepared_v2(different),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
        let observed = journal.load_v2().unwrap().unwrap();
        assert_eq!(observed.state, initial.state);
        assert_eq!(observed.pending_next_for_test(), Some(&pending));
    }

    #[test]
    fn v2_writer_rejects_structurally_invalid_pending_record() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(52, 240);
        let journal = journal(&temp, &fixture);
        let initial = begin_v2(&journal, &fixture, &[11]);
        let prepares = owner_prepares_v2(&initial);
        let mut pending = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &initial.state,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            |next| {
                next.owner_prepares = prepares;
                Ok(())
            },
        )
        .unwrap();
        pending.owner_prepares[0].prepared_journal_digest = digest(248);
        write_new_json_private(
            &v2_record_path(&journal, pending.sequence),
            &pending,
            MAX_STATE_BYTES,
        )
        .unwrap();

        assert!(matches!(
            journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_writer_bounds_history_directory_iteration() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(53, 250);
        let journal = journal(&temp, &fixture);
        begin_v2(&journal, &fixture, &[11]);
        let records = journal.active_path().join("state_records");
        for index in 0..7 {
            write_new_json_private(
                &records.join(format!("extra-{index}.json")),
                &json!({ "unexpected": index }),
                1024,
            )
            .unwrap();
        }

        assert!(matches!(
            journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_writer_rejects_history_gap_pointer_ahead_and_missing_format() {
        let gap_temp = tempfile::tempdir().unwrap();
        let gap_fixture = fixture(48, 200);
        let gap_journal = journal(&gap_temp, &gap_fixture);
        begin_v2(&gap_journal, &gap_fixture, &[11]);
        fs::remove_file(v2_record_path(&gap_journal, 1)).unwrap();
        assert!(matches!(
            gap_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let pointer_temp = tempfile::tempdir().unwrap();
        let pointer_fixture = fixture(49, 210);
        let pointer_journal = journal(&pointer_temp, &pointer_fixture);
        let initial = begin_v2(&pointer_journal, &pointer_fixture, &[11]);
        let prepares = owner_prepares_v2(&initial);
        let pointer_ahead = next_private_oram_mutation_state_v2(
            &initial.descriptor,
            &initial.state,
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            |next| {
                next.owner_prepares = prepares;
                Ok(())
            },
        )
        .unwrap();
        fs::write(
            pointer_journal.state_path(),
            serde_json::to_vec(&pointer_ahead).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            pointer_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let format_temp = tempfile::tempdir().unwrap();
        let format_fixture = fixture(50, 220);
        let format_journal = journal(&format_temp, &format_fixture);
        begin_v2(&format_journal, &format_fixture, &[11]);
        fs::remove_file(format_journal.active_path().join("format.json")).unwrap();
        assert!(matches!(
            format_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn v2_writer_classifies_missing_mandatory_artifacts_as_corrupt() {
        let descriptor_temp = tempfile::tempdir().unwrap();
        let descriptor_fixture = fixture(56, 60);
        let descriptor_journal = journal(&descriptor_temp, &descriptor_fixture);
        begin_v2(&descriptor_journal, &descriptor_fixture, &[11]);
        fs::remove_file(descriptor_journal.active_path().join(DESCRIPTOR_FILE)).unwrap();
        assert!(matches!(
            descriptor_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let state_temp = tempfile::tempdir().unwrap();
        let state_fixture = fixture(57, 80);
        let state_journal = journal(&state_temp, &state_fixture);
        begin_v2(&state_journal, &state_fixture, &[11]);
        fs::remove_file(state_journal.state_path()).unwrap();
        assert!(matches!(
            state_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let records_temp = tempfile::tempdir().unwrap();
        let records_fixture = fixture(58, 100);
        let records_journal = journal(&records_temp, &records_fixture);
        begin_v2(&records_journal, &records_fixture, &[11]);
        fs::remove_dir_all(records_journal.active_path().join("state_records")).unwrap();
        assert!(matches!(
            records_journal.load_v2(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn parent_journal_persists_exact_seven_phase_progression() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(17, 1);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        assert_eq!(
            initial.state.phase,
            PrivateOramMutationJournalPhaseV1::LeaseAcquired
        );
        assert!(matches!(
            journal.validated_point_stage_parent(),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let prepares = owner_prepares(&initial);
        assert!(matches!(
            journal.mark_owners_prepared(prepares[..1].to_vec()),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let prepared = journal.mark_owners_prepared(prepares.clone()).unwrap();
        assert_eq!(
            prepared.state.phase,
            PrivateOramMutationJournalPhaseV1::OwnersPrepared
        );
        assert_eq!(
            journal
                .mark_owners_prepared(prepares)
                .unwrap()
                .state
                .sequence,
            2
        );
        let point = mark_no_server_point_stage(&journal);
        assert_eq!(point.state.sequence, 3);
        let committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        assert_eq!(committed.state.sequence, 4);
        let remote = finalizations(&committed, false);
        let remotes = journal.mark_remotes_finalized(remote).unwrap();
        assert_eq!(remotes.state.sequence, 5);
        let local = finalizations(&remotes, true);
        let local = journal.mark_local_finalized(local).unwrap();
        assert_eq!(local.state.sequence, 6);
        let complete = journal.mark_complete().unwrap();
        assert_eq!(
            complete.state.phase,
            PrivateOramMutationJournalPhaseV1::Complete
        );
        assert_eq!(complete.state.sequence, 7);
        assert_eq!(journal.mark_complete().unwrap(), complete);

        let reopened = journal.load().unwrap().unwrap();
        assert_eq!(reopened, complete);
        let rendered = format!("{reopened:?}");
        assert!(!rendered.contains("collection-uuid-1"));
        assert!(!rendered.contains("secret-index"));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
    }

    #[test]
    fn v2_state_binds_both_decisions_and_empty_remote_terminal_batch() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(41, 31);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);

        for decision_kind in [
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationDecisionKindV2::ExactOldAbort,
        ] {
            let state = v2_no_server_terminal_state(
                &initial,
                &fixture,
                decision_kind,
                PrivateOramMutationJournalPhaseV2::PointResolved,
            );
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &state).unwrap();
            assert_eq!(state.sequence, 7);
            assert!(
                state
                    .remote_terminals
                    .as_ref()
                    .is_some_and(|batch| batch.owners.is_empty())
            );
            assert!(matches!(
                state.point_resolution,
                Some(PrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
                    decision_kind: recorded,
                    ..
                }) if recorded == decision_kind
            ));
            let rendered = format!("{state:?}");
            assert!(!rendered.contains("collection-uuid-1"));
            assert!(!rendered.contains("secret-index"));
            assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
        }
    }

    #[test]
    fn v2_state_rejects_terminal_kind_and_predecessor_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(42, 33);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let state = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );

        let mut wrong_terminal_kind = state.clone();
        wrong_terminal_kind.local_terminals.as_mut().unwrap().kind =
            PrivateOramMutationOwnerTerminalKindV2::AbortedOld;
        wrong_terminal_kind = canonical_private_oram_mutation_state_v2_for_test(
            &initial.descriptor,
            &wrong_terminal_kind,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_terminal_kind,
            )
            .is_err()
        );

        let mut wrong_predecessor = state;
        let PrivateOramMutationStatePredecessorV2::PreviousV2 { record_digest, .. } =
            &mut wrong_predecessor.predecessor
        else {
            panic!("expected V2 predecessor");
        };
        *record_digest = digest(249);
        wrong_predecessor.record_digest = state_record_digest_v2_for_test(
            &initial.descriptor.descriptor_digest,
            &wrong_predecessor,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_predecessor,
            )
            .is_err()
        );

        let mut wrong_authority = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        let batch = wrong_authority.local_terminals.as_mut().unwrap();
        batch.owners[0].reconciliation_authority_digest = digest(248);
        batch.owners[0].terminal_evidence_digest = private_oram_owner_terminal_evidence_v2_digest(
            &initial.descriptor.descriptor_digest,
            batch.kind,
            &batch.owners[0],
        )
        .unwrap();
        wrong_authority = canonical_private_oram_mutation_state_v2_for_test(
            &initial.descriptor,
            &wrong_authority,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_authority,
            )
            .is_err()
        );

        let mut unsupported_legacy_origin = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        unsupported_legacy_origin.origin = PrivateOramMutationStateOriginV2::MigratedV1 {
            legacy_phase: PrivateOramMutationJournalPhaseV1::Complete,
            legacy_record_digest: digest(247),
            legacy_state_file_sha256: digest(246),
        };
        unsupported_legacy_origin.record_digest = state_record_digest_v2_for_test(
            &initial.descriptor.descriptor_digest,
            &unsupported_legacy_origin,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &unsupported_legacy_origin,
            )
            .is_err()
        );

        let mut wrong_decided_lease = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        );
        let Some(PrivateOramMutationDecisionEvidenceV2::ExactNew {
            committed_lease, ..
        }) = wrong_decided_lease.decision.as_mut()
        else {
            unreachable!();
        };
        committed_lease.base_record_digest = digest(244);
        wrong_decided_lease = canonical_private_oram_mutation_state_v2_for_test(
            &initial.descriptor,
            &wrong_decided_lease,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_decided_lease,
            )
            .is_err()
        );
    }

    #[test]
    fn v2_point_resolution_receipts_bind_outcome_route_and_raw_replica_observations() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(45, 38, 0, true);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);

        for outcome in [
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld,
        ] {
            let state = v2_visible_point_resolved_state(&initial, &fixture, outcome);
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &state).unwrap();
        }

        let mut wrong_observation = v2_visible_point_resolved_state(
            &initial,
            &fixture,
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
        );
        let Some(PrivateOramMutationPointResolutionEvidenceV2::PublishedExactNew { receipt }) =
            wrong_observation.point_resolution.as_mut()
        else {
            unreachable!();
        };
        receipt.observations[0] = PrivateOramPointReplicaObservationV2::Exact {
            shard_id: 11,
            peer_id: 11,
            point_semantic_digest: digest(245),
        };
        receipt.receipt_digest = private_oram_point_resolution_receipt_v2_digest(
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew,
            receipt,
        )
        .unwrap();
        wrong_observation = canonical_private_oram_mutation_state_v2_for_test(
            &initial.descriptor,
            &wrong_observation,
        )
        .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(
                &initial.descriptor,
                &wrong_observation,
            )
            .is_err()
        );

        let mut wrong_route = v2_visible_point_resolved_state(
            &initial,
            &fixture,
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld,
        );
        let Some(PrivateOramMutationPointResolutionEvidenceV2::AbortedExactOld { receipt }) =
            wrong_route.point_resolution.as_mut()
        else {
            unreachable!();
        };
        receipt.target_shard_ids = vec![12];
        receipt.replicas = vec![PrivateOramPointReplicaTargetV2 {
            shard_id: 12,
            peer_id: 11,
        }];
        receipt.replica_set_digest =
            private_oram_point_replica_set_digest_v2(&receipt.replicas).unwrap();
        receipt.observations = vec![PrivateOramPointReplicaObservationV2::Absent {
            shard_id: 12,
            peer_id: 11,
        }];
        receipt.receipt_digest = private_oram_point_resolution_receipt_v2_digest(
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld,
            receipt,
        )
        .unwrap();
        wrong_route =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &wrong_route)
                .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &wrong_route,)
                .is_err()
        );
    }

    #[test]
    fn v2_terminal_batches_require_every_owner_once_in_canonical_order() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(46, 39);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12, 13]);
        let mut prepared = empty_v2_state(PrivateOramMutationJournalPhaseV2::OwnersPrepared);
        prepared.owner_prepares = owner_prepares(&initial);
        let prepared =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &prepared)
                .unwrap();
        let mut state = empty_v2_state(PrivateOramMutationJournalPhaseV2::LocalTerminal);
        state.owner_prepares = prepared.owner_prepares;
        state.point_stage = Some(
            PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
                parent_owners_prepared_record_digest: prepared.record_digest,
            },
        );
        state.decision = Some(
            exact_new_decision_v2_for_test(
                &initial.descriptor,
                &fixture.committed_lease,
                &fixture.new_consensus,
            )
            .unwrap(),
        );
        state.remote_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            owners: vec![
                v2_terminal_evidence(
                    &initial.descriptor,
                    &state,
                    12,
                    PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                    201,
                ),
                v2_terminal_evidence(
                    &initial.descriptor,
                    &state,
                    13,
                    PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                    211,
                ),
            ],
        });
        state.local_terminals = Some(PrivateOramMutationOwnerTerminalBatchV2 {
            kind: PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            owners: vec![v2_terminal_evidence(
                &initial.descriptor,
                &state,
                11,
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
                221,
            )],
        });
        let state =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &state).unwrap();
        validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &state).unwrap();

        let mut reversed = state.clone();
        reversed.remote_terminals.as_mut().unwrap().owners.reverse();
        reversed =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &reversed)
                .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &reversed)
                .is_err()
        );

        let mut missing = state.clone();
        missing.remote_terminals.as_mut().unwrap().owners.pop();
        missing = canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &missing)
            .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &missing)
                .is_err()
        );

        let mut duplicate = state;
        let duplicate_owner = duplicate.remote_terminals.as_ref().unwrap().owners[0].clone();
        duplicate.remote_terminals.as_mut().unwrap().owners[1] = duplicate_owner;
        duplicate =
            canonical_private_oram_mutation_state_v2_for_test(&initial.descriptor, &duplicate)
                .unwrap();
        assert!(
            validate_private_oram_mutation_state_v2_structure(&initial.descriptor, &duplicate)
                .is_err()
        );
    }

    #[test]
    fn dual_state_decoder_keeps_v1_complete_distinct_from_v2_point_resolved() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(43, 35);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let prepared = journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        journal
            .mark_remotes_finalized(finalizations(&committed, false))
            .unwrap();
        let remotes = journal.load().unwrap().unwrap();
        journal
            .mark_local_finalized(finalizations(&remotes, true))
            .unwrap();
        let complete = journal.mark_complete().unwrap();
        let v1_bytes = serde_json::to_vec(&complete.state).unwrap();
        let DecodedPrivateOramMutationStateUntrusted::V1(decoded_v1) =
            decode_untrusted_private_oram_mutation_state(&complete.descriptor, &v1_bytes).unwrap()
        else {
            panic!("expected V1 state");
        };
        assert_eq!(
            decoded_v1.phase,
            PrivateOramMutationJournalPhaseV1::Complete
        );
        assert!(serde_json::from_slice::<PrivateOramMutationJournalStateV2>(&v1_bytes).is_err());

        let v2 = v2_no_server_terminal_state(
            &prepared,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactNew,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        let v2_bytes = serde_json::to_vec(&v2).unwrap();
        let DecodedPrivateOramMutationStateUntrusted::UntrustedV2(decoded_v2) =
            decode_untrusted_private_oram_mutation_state(&prepared.descriptor, &v2_bytes).unwrap()
        else {
            panic!("expected V2 state");
        };
        assert_eq!(
            decoded_v2.phase,
            PrivateOramMutationJournalPhaseV2::PointResolved
        );

        let mut unknown_field = serde_json::to_value(&v2).unwrap();
        unknown_field
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), json!(true));
        assert!(
            decode_untrusted_private_oram_mutation_state(
                &prepared.descriptor,
                &serde_json::to_vec(&unknown_field).unwrap(),
            )
            .is_err()
        );

        let mut unknown_version = serde_json::to_value(&v2).unwrap();
        unknown_version["version"] = json!(99);
        assert!(
            decode_untrusted_private_oram_mutation_state(
                &prepared.descriptor,
                &serde_json::to_vec(&unknown_version).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn v1_state_wire_fixture_remains_frozen_for_dual_decoder() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(47, 40);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let encoded = String::from_utf8(serde_json::to_vec(&initial.state).unwrap()).unwrap();
        assert_eq!(
            encoded,
            "{\"version\":1,\"sequence\":1,\"phase\":\"lease_acquired\",\"previous_record_digest\":null,\"owner_prepares\":[],\"point_stage\":null,\"consensus\":null,\"remote_finalizations\":[],\"local_finalizations\":[],\"record_digest\":\"MO5QBbMU6zHpF1pO8lz6gmhWIz01QzVD7ro5mfditQw\"}"
        );
        assert!(matches!(
            decode_untrusted_private_oram_mutation_state(&initial.descriptor, encoded.as_bytes())
                .unwrap(),
            DecodedPrivateOramMutationStateUntrusted::V1(_)
        ));
    }

    #[test]
    fn v2_parent_state_digest_has_known_answer() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(44, 37);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let state = v2_no_server_terminal_state(
            &initial,
            &fixture,
            PrivateOramMutationDecisionKindV2::ExactOldAbort,
            PrivateOramMutationJournalPhaseV2::PointResolved,
        );
        assert_eq!(
            state.record_digest,
            "Y9aXbMKSjnqXwFLAwJOPhceori1M73yQBfk1X8d6PeQ"
        );
    }

    #[test]
    fn no_server_stage_binds_exact_owners_prepared_chain_tip() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(18, 10);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let prepared = journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent().unwrap();
        assert_eq!(
            parent.owners_prepared_record_digest(),
            prepared.state.record_digest
        );

        let staged = journal.mark_no_server_point_stage_durable(&parent).unwrap();
        let Some(PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        }) = staged.state.point_stage.as_ref()
        else {
            panic!("expected no-server point-stage evidence");
        };
        assert_eq!(
            parent_owners_prepared_record_digest,
            &prepared.state.record_digest
        );
        let replay_parent = journal.validated_point_stage_parent().unwrap();
        assert!(!replay_parent.permits_new_child_install());
        assert_eq!(replay_parent.expected_child_descriptor_digest(), None);
        assert_eq!(
            journal.mark_no_server_point_stage_durable(&parent).unwrap(),
            staged
        );

        let mut tampered = staged;
        let Some(PrivateOramMutationPointStageEvidenceV1::NoServerPointRecord {
            parent_owners_prepared_record_digest,
        }) = tampered.state.point_stage.as_mut()
        else {
            unreachable!();
        };
        *parent_owners_prepared_record_digest = digest(252);
        tampered.state.record_digest =
            state_record_digest(&tampered.descriptor.descriptor_digest, &tampered.state).unwrap();
        fs::write(
            journal.state_path(),
            serde_json::to_vec(&tampered.state).unwrap(),
        )
        .unwrap();
        assert!(journal.load().is_err());
    }

    #[test]
    fn reconciliation_context_classifies_only_valid_old_and_new_authority() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(19, 20);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);

        let mut renewed_preparing = fixture.preparing_lease.clone();
        renewed_preparing.expires_at_unix += 10;
        renewed_preparing.renewal_revision += 1;
        let old = journal
            .validated_reconcile_context(
                &fixture.old_consensus,
                &active_lease_slot(renewed_preparing.clone()),
            )
            .unwrap();
        assert_eq!(
            old.disposition(),
            PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision
        );
        assert_eq!(old.active_lease(), &renewed_preparing);
        assert!(old.validated_decision_evidence_v2().is_err());
        assert_eq!(
            old.snapshot().state.phase,
            PrivateOramMutationJournalPhaseV1::PointStageDurable
        );
        let rendered = format!("{old:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));

        let mut abort_decided = renewed_preparing.clone();
        abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
        let abort = journal
            .validated_reconcile_context(
                &fixture.old_consensus,
                &active_lease_slot(abort_decided.clone()),
            )
            .unwrap();
        assert_eq!(
            abort.disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided
        );
        assert_eq!(abort.active_lease(), &abort_decided);
        let abort_decision = abort.validated_decision_evidence_v2().unwrap();
        assert_eq!(
            abort_decision.kind(),
            PrivateOramMutationDecisionKindV2::ExactOldAbort
        );

        let new = journal
            .validated_reconcile_context(
                &fixture.new_consensus,
                &active_lease_slot(fixture.committed_lease.clone()),
            )
            .unwrap();
        assert_eq!(
            new.disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactNew
        );
        assert_eq!(new.active_lease(), &fixture.committed_lease);
        let new_decision = new.validated_decision_evidence_v2().unwrap();
        assert_eq!(
            new_decision.kind(),
            PrivateOramMutationDecisionKindV2::ExactNew
        );
        let rendered = format!("{new_decision:?}");
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&fixture.mutation_bundle.mutation.mutation_id));
        let mut renewed_committed = fixture.committed_lease.clone();
        renewed_committed.expires_at_unix += 20;
        renewed_committed.renewal_revision += 1;
        journal
            .mark_consensus_committed(&renewed_committed, &fixture.new_consensus)
            .unwrap();
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(fixture.committed_lease.clone()),
                )
                .is_err()
        );
        assert_eq!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(renewed_committed),
                )
                .unwrap()
                .disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactNew
        );
    }

    #[test]
    fn owner_recovery_authority_binds_owner_and_is_stable_across_parent_progress() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(44, 170);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        assert!(matches!(
            journal.validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.old_consensus, fixture.preparing_lease.clone()),
                12,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        let prepares = owner_prepares(&initial);
        journal.mark_owners_prepared(prepares.clone()).unwrap();
        mark_no_server_point_stage(&journal);

        let mut renewed_preparing = fixture.preparing_lease.clone();
        renewed_preparing.expires_at_unix += 10;
        renewed_preparing.renewal_revision += 1;
        let observed_snapshot =
            reconcile_snapshot(&fixture.old_consensus, renewed_preparing.clone());
        let snapshot_debug = format!("{observed_snapshot:?}");
        assert!(!snapshot_debug.contains(&fixture.mutation_bundle.mutation.collection_id));
        assert!(!snapshot_debug.contains(&fixture.preparing_lease.base_record_digest));
        let observed = journal
            .validated_owner_recovery_authority(&observed_snapshot, 12)
            .unwrap();
        assert_eq!(observed.owner_peer_id(), 12);
        assert_eq!(
            observed.disposition(),
            PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision
        );
        assert_eq!(
            observed.parent_descriptor_digest(),
            initial.descriptor.descriptor_digest
        );
        assert_eq!(
            observed.parent_lease_acquired_record_digest(),
            initial.state.record_digest
        );
        assert_eq!(
            observed.consensus_authority_record_digest(),
            fixture.preparing_lease.base_record_digest
        );
        assert_eq!(observed.mutation_bundle(), &fixture.mutation_bundle);
        assert_eq!(observed.indexes().len(), 1);
        assert_eq!(observed.indexes()[0].requirement().peer_id, 12);
        assert_eq!(observed.indexes()[0].prepared(), &prepares[1]);
        assert_eq!(observed.reconciliation_authority_digest().len(), 43);
        let coordinator_owner = journal
            .validated_owner_recovery_authority(&observed_snapshot, 11)
            .unwrap();
        assert_ne!(
            observed.reconciliation_authority_digest(),
            coordinator_owner.reconciliation_authority_digest()
        );
        assert!(matches!(
            journal.validated_owner_recovery_authority(&observed_snapshot, 13),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut abort_decided = renewed_preparing;
        abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
        let abort = journal
            .validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.old_consensus, abort_decided),
                12,
            )
            .unwrap();
        assert_eq!(
            abort.disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided
        );
        assert_eq!(
            abort.consensus_authority_record_digest(),
            observed.consensus_authority_record_digest()
        );
        assert_ne!(
            abort.reconciliation_authority_digest(),
            observed.reconciliation_authority_digest()
        );

        let before_parent_progress = journal
            .validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone()),
                12,
            )
            .unwrap();
        let mut renewed_committed = fixture.committed_lease.clone();
        renewed_committed.expires_at_unix += 20;
        renewed_committed.renewal_revision += 1;
        journal
            .mark_consensus_committed(&renewed_committed, &fixture.new_consensus)
            .unwrap();
        let after_parent_progress = journal
            .validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.new_consensus, renewed_committed),
                12,
            )
            .unwrap();
        assert_eq!(
            before_parent_progress.disposition(),
            PrivateOramMutationReconcileDispositionV1::ExactNew
        );
        assert_eq!(
            before_parent_progress.consensus_authority_record_digest(),
            canonical_private_oram_consensus_state_record_digest(&fixture.new_consensus).unwrap()
        );
        assert_eq!(
            before_parent_progress.parent_owners_prepared_record_digest(),
            after_parent_progress.parent_owners_prepared_record_digest()
        );
        assert_eq!(
            before_parent_progress.reconciliation_authority_digest(),
            after_parent_progress.reconciliation_authority_digest()
        );

        let rendered = format!("{after_parent_progress:?}");
        for secret in [
            fixture.mutation_bundle.mutation.collection_id.as_str(),
            fixture.mutation_bundle.mutation.mutation_id.as_str(),
            observed.indexes()[0].requirement().index_name.as_str(),
            after_parent_progress.reconciliation_authority_digest(),
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn owner_recovery_authority_digest_has_known_answer() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(45, 180);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let authority = journal
            .validated_owner_recovery_authority(
                &reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone()),
                12,
            )
            .unwrap();

        assert_eq!(
            authority.reconciliation_authority_digest(),
            "fSOEGuuAWS9SgVu_oDuC1fcBIaZ-OXguisfs6bnnVAY"
        );
    }

    #[test]
    fn live_owner_recovery_authority_holds_and_revalidates_parent_lock() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(47, 200);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let reconcile = reconcile_snapshot(&fixture.new_consensus, fixture.committed_lease.clone());

        let authority_digest = journal
            .with_live_owner_recovery_authority_v1(&reconcile, 12, |live| {
                assert_eq!(live.owner_peer_id(), 12);
                assert_eq!(
                    live.disposition(),
                    PrivateOramMutationReconcileDispositionV1::ExactNew
                );
                assert_eq!(
                    live.parent_descriptor_digest(),
                    initial.descriptor.descriptor_digest
                );
                assert_eq!(live.mutation_bundle(), &fixture.mutation_bundle);

                let second = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(journal.root.join(LOCK_FILE))
                    .unwrap();
                assert!(!FileExt::try_lock_exclusive(second.file()).unwrap());

                let rendered = format!("{live:?}");
                assert!(!rendered.contains(&fixture.mutation_bundle.mutation.collection_id));
                assert!(!rendered.contains(live.reconciliation_authority_digest()));
                live.reconciliation_authority_digest().to_string()
            })
            .unwrap();
        assert_eq!(authority_digest.len(), 43);

        let original_state = fs::read(journal.state_path()).unwrap();
        let error = journal
            .with_live_owner_recovery_authority_v1(&reconcile, 12, |_| {
                fs::write(journal.state_path(), b"{\"tampered\":true}").unwrap();
            })
            .unwrap_err();
        assert!(matches!(error, PrivateOramMutationJournalError::Corrupt));
        fs::write(journal.state_path(), original_state).unwrap();

        let displaced_root = temp.path().join("displaced-parent-journal");
        let error = journal
            .with_live_owner_recovery_authority_v1(&reconcile, 12, |_| {
                fs::rename(&journal.root, &displaced_root).unwrap();
                fs::create_dir(&journal.root).unwrap();
                set_private_directory_permissions(&journal.root).unwrap();
            })
            .unwrap_err();
        assert!(matches!(error, PrivateOramMutationJournalError::Corrupt));
        fs::remove_dir(&journal.root).unwrap();
        fs::rename(displaced_root, &journal.root).unwrap();
        assert!(journal.load().unwrap().is_some());
    }

    #[test]
    fn owner_recovery_pair_projection_requires_canonical_authenticated_pair() {
        let authority = pair_recovery_authority(46, 190);
        let projection = authority.pair_recovery_projection().unwrap();
        let rendered = format!("{projection:?}");
        assert!(!rendered.contains(&authority.mutation_bundle.mutation.collection_id));
        assert!(!rendered.contains(&authority.indexes[0].prepared.prepared_journal_digest));

        let mut hnsw_only = authority.clone();
        hnsw_only.indexes.pop();
        assert!(matches!(
            hnsw_only.pair_recovery_projection(),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut reordered = authority.clone();
        reordered.indexes.swap(0, 1);
        assert!(matches!(
            reordered.pair_recovery_projection(),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));

        let mut foreign_owner = authority;
        foreign_owner.indexes[1].prepared.peer_id = 12;
        assert!(matches!(
            foreign_owner.pair_recovery_projection(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[test]
    fn reconciliation_context_rejects_mixed_ambiguous_and_aba_state() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(20, 30);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(fixture.committed_lease.clone()),
                )
                .is_err()
        );
        mark_no_server_point_stage(&journal);

        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.old_consensus,
                    &active_lease_slot(fixture.committed_lease.clone()),
                )
                .is_err()
        );
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(fixture.preparing_lease.clone()),
                )
                .is_err()
        );
        let mut abort_decided = fixture.preparing_lease.clone();
        abort_decided.phase = PrivateOramMutationLeasePhase::AbortDecided;
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.new_consensus,
                    &active_lease_slot(abort_decided.clone()),
                )
                .is_err()
        );

        let mut ambiguous_state = fixture.old_consensus.clone();
        ambiguous_state.state_sequence += 10;
        assert!(
            journal
                .validated_reconcile_context(
                    &ambiguous_state,
                    &active_lease_slot(fixture.preparing_lease.clone()),
                )
                .is_err()
        );

        let mut aba_slot = active_lease_slot(fixture.preparing_lease.clone());
        aba_slot.generation += 1;
        aba_slot.max_writer_fence += 1;
        assert!(
            journal
                .validated_reconcile_context(&fixture.old_consensus, &aba_slot)
                .is_err()
        );

        let mut forged_renewal = fixture.preparing_lease.clone();
        forged_renewal.expires_at_unix += 1;
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.old_consensus,
                    &active_lease_slot(forged_renewal),
                )
                .is_err()
        );

        journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.old_consensus,
                    &active_lease_slot(fixture.preparing_lease.clone()),
                )
                .is_err()
        );
        assert!(
            journal
                .validated_reconcile_context(
                    &fixture.old_consensus,
                    &active_lease_slot(abort_decided),
                )
                .is_err()
        );
    }

    #[test]
    fn begin_is_exactly_idempotent_and_rejects_another_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let original = fixture(19, 20);
        let journal = journal(&temp, &original);
        let first = begin(&journal, &original, &[11, 12]);
        let replay = begin(&journal, &original, &[11, 12]);
        assert_eq!(first, replay);

        let conflicting = fixture(19, 40);
        assert!(matches!(
            journal.begin(
                11,
                &[11, 12],
                conflicting.mutation_bundle,
                conflicting.preparing_lease,
                conflicting.old_consensus,
            ),
            Err(PrivateOramMutationJournalError::ConcurrentMutation)
        ));
    }

    #[test]
    fn parent_journal_digest_format_has_known_answer() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(41, 130);
        let journal = journal(&temp, &fixture);
        let snapshot = begin(&journal, &fixture, &[11, 12]);

        assert_eq!(
            (
                snapshot.descriptor.descriptor_digest.as_str(),
                snapshot.state.record_digest.as_str(),
            ),
            (
                "9tpFN8mc5ErsCTDstFEb_mnGjN5_2RANiwIC5di0lgQ",
                "gi78kODdPKibnEKFRZhQEMYtQ6eN0ctSpVdGarg3dqE",
            )
        );
    }

    #[test]
    fn begin_rejects_noncanonical_consensus_transition_digest() {
        let temp = tempfile::tempdir().unwrap();
        let mut fixture = fixture(42, 140);
        fixture.preparing_lease.transition_digest = digest(250);
        let journal = journal(&temp, &fixture);

        assert!(matches!(
            journal.begin(
                11,
                &[11, 12],
                fixture.mutation_bundle,
                fixture.preparing_lease,
                fixture.old_consensus,
            ),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn single_owner_records_empty_remote_finalize_phase() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(23, 60);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let prepared = journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        let remote = journal.mark_remotes_finalized(Vec::new()).unwrap();
        assert_eq!(remote.state.sequence, 5);
        let local = finalizations(&prepared, true);
        journal.mark_local_finalized(local).unwrap();
        assert_eq!(journal.mark_complete().unwrap().state.sequence, 7);
        assert_eq!(committed.state.remote_finalizations, Vec::new());
    }

    #[test]
    fn parent_journal_binds_non_genesis_consensus_record() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(27, 70, 7, false);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        assert_eq!(
            initial
                .descriptor
                .expected_consensus_old_state
                .state_sequence,
            7
        );
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        assert_eq!(
            committed.state.consensus.unwrap().committed_state_sequence,
            8
        );
    }

    #[test]
    fn visible_point_phase_requires_private_staging_token() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture_at_sequence(28, 75, 0, true);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        let prepared = journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        let parent = journal.validated_point_stage_parent().unwrap();
        assert!(parent.permits_new_child_install());
        assert_eq!(
            parent.owners_prepared_record_digest(),
            prepared.state.record_digest
        );
        assert!(journal.mark_no_server_point_stage_durable(&parent).is_err());

        let point_store = PrivateOramPointStagingStore::new(&temp.path().join("collection"));
        let (point_stage, durable_token) = point_store
            .prepare(fixture.staged_frame_bytes.as_deref().unwrap(), &parent)
            .unwrap();
        let staged = journal
            .mark_private_point_stage_durable(&durable_token)
            .unwrap();
        assert_eq!(
            staged.state.phase,
            PrivateOramMutationJournalPhaseV1::PointStageDurable
        );
        let Some(PrivateOramMutationPointStageEvidenceV1::PrivateOramPointStaging {
            point_id,
            staged_insert_sha256,
            canonical_point_id_digest,
            child_descriptor_digest,
            parent_owners_prepared_record_digest,
        }) = staged.state.point_stage.as_ref()
        else {
            panic!("expected private point-staging evidence");
        };
        assert_eq!(point_id, durable_token.point_id());
        assert_eq!(staged_insert_sha256, durable_token.frame_sha256());
        assert_eq!(
            canonical_point_id_digest,
            durable_token.canonical_point_id_digest()
        );
        assert_eq!(
            durable_token.target_shard_ids(),
            point_stage.frame.target_shard_ids.as_slice()
        );
        assert_eq!(
            durable_token.point_semantic_digest(),
            private_oram_staged_point_semantic_v1_digest(&point_stage.frame.point).unwrap()
        );
        let PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
            point_semantic_digest,
            target_shard_ids,
            ..
        } = private_oram_point_stage_evidence_v2_from_durable_token(&durable_token)
        else {
            unreachable!();
        };
        assert_eq!(point_semantic_digest, durable_token.point_semantic_digest());
        assert_eq!(target_shard_ids, durable_token.target_shard_ids());
        assert_eq!(
            child_descriptor_digest,
            &point_stage.descriptor.descriptor_digest
        );
        assert_eq!(
            parent_owners_prepared_record_digest,
            &prepared.state.record_digest
        );

        let replay_parent = journal.validated_point_stage_parent().unwrap();
        assert!(!replay_parent.permits_new_child_install());
        assert_eq!(
            replay_parent.expected_child_descriptor_digest(),
            Some(point_stage.descriptor.descriptor_digest.as_str())
        );
        let (_, replay_token) = point_store.load(&replay_parent).unwrap().unwrap();
        assert_eq!(replay_token, durable_token);
        assert_eq!(
            journal
                .mark_private_point_stage_durable(&replay_token)
                .unwrap(),
            staged
        );
    }

    #[test]
    fn changed_consensus_receipt_or_owner_evidence_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(29, 80);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11, 12]);
        let mut prepares = owner_prepares(&initial);
        prepares[0].prepared_journal_digest = "not-a-digest".to_string();
        assert!(matches!(
            journal.mark_owners_prepared(prepares),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let mut changed = fixture.new_consensus.clone();
        let PrivateOramConsensusTransitionV2::Mutation(receipt) = &mut changed.last_transition
        else {
            unreachable!();
        };
        receipt.point_operation_digest = digest(250);
        assert!(matches!(
            journal.mark_consensus_committed(&fixture.committed_lease, &changed),
            Err(PrivateOramMutationJournalError::InvalidTransition)
        ));
    }

    #[test]
    fn recomputed_parent_digest_cannot_replace_consensus_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(30, 90);
        let journal = journal(&temp, &fixture);
        let initial = begin(&journal, &fixture, &[11]);
        journal
            .mark_owners_prepared(owner_prepares(&initial))
            .unwrap();
        mark_no_server_point_stage(&journal);
        let mut committed = journal
            .mark_consensus_committed(&fixture.committed_lease, &fixture.new_consensus)
            .unwrap();
        committed
            .state
            .consensus
            .as_mut()
            .unwrap()
            .committed_record_digest = digest(249);
        committed.state.record_digest =
            state_record_digest(&committed.descriptor.descriptor_digest, &committed.state).unwrap();
        fs::write(
            journal.state_path(),
            serde_json::to_vec(&committed.state).unwrap(),
        )
        .unwrap();
        assert!(journal.load().is_err());
    }

    #[test]
    fn on_disk_state_digest_and_signature_tampering_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(31, 100);
        let journal = journal(&temp, &fixture);
        begin(&journal, &fixture, &[11]);
        let mut state: serde_json::Value =
            serde_json::from_reader(File::open(journal.state_path()).unwrap()).unwrap();
        state["record_digest"] = json!(digest(251));
        fs::write(journal.state_path(), serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(matches!(
            journal.load(),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));

        let wrong_key = PrivateOramMutationJournal::new(
            temp.path().join("collection").as_path(),
            "tenant-a/private-oram-owner-v2",
            Ed25519KeyPair::from_seed_unchecked(&[99; 32])
                .unwrap()
                .public_key()
                .as_ref()
                .to_vec(),
        )
        .unwrap();
        assert!(matches!(
            wrong_key.load(),
            Err(PrivateOramMutationJournalError::Signature(_))
                | Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    struct FailBeforePublish;

    impl JournalSaveBackend for FailBeforePublish {
        fn publish(&self, _candidate: NamedTempFile, _destination: &Path) -> io::Result<()> {
            Err(io::Error::other("injected pre-publish failure"))
        }

        fn sync_parent(&self, _parent: &Path) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailAfterPublish;

    impl JournalSaveBackend for FailAfterPublish {
        fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.publish(candidate, destination)?;
            Err(io::Error::other("injected post-publish failure"))
        }

        fn sync_parent(&self, parent: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.sync_parent(parent)
        }
    }

    struct ExhaustParentSync {
        calls: AtomicUsize,
    }

    impl JournalSaveBackend for ExhaustParentSync {
        fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.publish(candidate, destination)
        }

        fn sync_parent(&self, _parent: &Path) -> io::Result<()> {
            self.calls.fetch_add(1, AtomicOrdering::Relaxed);
            Err(io::Error::other("injected parent sync failure"))
        }
    }

    struct RemoveAfterPublish;

    impl JournalSaveBackend for RemoveAfterPublish {
        fn publish(&self, candidate: NamedTempFile, destination: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.publish(candidate, destination)?;
            fs::remove_file(destination)
        }

        fn sync_parent(&self, parent: &Path) -> io::Result<()> {
            FilesystemJournalSaveBackend.sync_parent(parent)
        }
    }

    fn atomic_save_fixture() -> (TempDir, PathBuf, PathBuf, [u8; 32]) {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("active");
        create_private_directory(&parent).unwrap();
        let temp_dir = parent.join("temp");
        create_private_directory(&temp_dir).unwrap();
        let destination = parent.join("state.json");
        write_new_json_private(&destination, &json!({ "value": "old" }), 4096).unwrap();
        let old_sha = file_sha256(&destination, 4096).unwrap();
        (temp, destination, temp_dir, old_sha)
    }

    #[test]
    fn atomic_state_save_classifies_before_and_after_publish_failures() {
        let (_temp, destination, temp_dir, old_sha) = atomic_save_fixture();
        let definitive = write_json_atomic_classified(
            &destination,
            &temp_dir,
            &json!({ "value": "new" }),
            old_sha,
            &FailBeforePublish,
        );
        assert!(matches!(
            definitive,
            Err(PrivateOramMutationJournalError::Io(_))
        ));
        assert_eq!(
            read_json_private::<serde_json::Value>(&destination, 4096).unwrap(),
            json!({ "value": "old" })
        );

        write_json_atomic_classified(
            &destination,
            &temp_dir,
            &json!({ "value": "new" }),
            old_sha,
            &FailAfterPublish,
        )
        .unwrap();
        assert_eq!(
            read_json_private::<serde_json::Value>(&destination, 4096).unwrap(),
            json!({ "value": "new" })
        );
    }

    #[test]
    fn exhausted_parent_sync_is_indeterminate_after_publish() {
        let (_temp, destination, temp_dir, old_sha) = atomic_save_fixture();
        let backend = ExhaustParentSync {
            calls: AtomicUsize::new(0),
        };
        assert!(matches!(
            write_json_atomic_classified(
                &destination,
                &temp_dir,
                &json!({ "value": "new" }),
                old_sha,
                &backend,
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        assert_eq!(
            backend.calls.load(AtomicOrdering::Relaxed),
            PARENT_SYNC_ATTEMPTS
        );
        assert_eq!(
            read_json_private::<serde_json::Value>(&destination, 4096).unwrap(),
            json!({ "value": "new" })
        );
    }

    #[test]
    fn post_publish_read_failure_is_indeterminate() {
        let (_temp, destination, temp_dir, old_sha) = atomic_save_fixture();
        assert!(matches!(
            write_json_atomic_classified(
                &destination,
                &temp_dir,
                &json!({ "value": "new" }),
                old_sha,
                &RemoveAfterPublish,
            ),
            Err(PrivateOramMutationJournalError::Indeterminate)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn private_json_read_rejects_content_beyond_the_callers_bound() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bounded.json");
        write_new_json_private(&path, &json!({ "value": "too-large" }), 4096).unwrap();
        assert!(matches!(
            read_json_private::<serde_json::Value>(&path, 2),
            Err(PrivateOramMutationJournalError::Corrupt)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_file_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let fixture = fixture(37, 120);
        let journal = journal(&temp, &fixture);
        begin(&journal, &fixture, &[11]);
        fs::remove_file(journal.state_path()).unwrap();
        let target = temp.path().join("target");
        fs::write(&target, b"{}").unwrap();
        symlink(target, journal.state_path()).unwrap();
        assert!(journal.load().is_err());
    }
}
