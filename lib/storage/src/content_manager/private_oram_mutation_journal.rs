use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use collection::shards::shard::PeerId;
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
use super::private_oram_point_staging::PrivateOramDurablePointStageTokenV1;

pub const PRIVATE_ORAM_MUTATION_JOURNAL_DIR: &str = "private_oram_mutations";
pub const PRIVATE_ORAM_MUTATION_JOURNAL_VERSION: u16 = 1;

const ACTIVE_DIR: &str = "active";
const TEMP_DIR: &str = "temp";
const ACTIVE_TEMP_DIR: &str = "temp";
const LOCK_FILE: &str = "journal.lock";
const DESCRIPTOR_FILE: &str = "descriptor.json";
const STATE_FILE: &str = "state.json";
const MAX_DESCRIPTOR_BYTES: u64 = 512 * 1024 * 1024;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
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
    #[error("private ORAM mutation journal signature validation failed")]
    Signature(#[source] PrivateOramMutationError),
    #[error("private ORAM mutation journal I/O failed before publication")]
    Io(#[source] io::Error),
    #[error("private ORAM mutation journal publication outcome is indeterminate")]
    Indeterminate,
}

impl Debug for PrivateOramMutationJournalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => f.debug_tuple("InvalidInput").field(field).finish(),
            Self::Corrupt => f.write_str("Corrupt"),
            Self::ConcurrentMutation => f.write_str("ConcurrentMutation"),
            Self::InvalidTransition => f.write_str("InvalidTransition"),
            Self::Signature(_) => f.write_str("Signature([redacted])"),
            Self::Io(_) => f.write_str("Io([redacted])"),
            Self::Indeterminate => f.write_str("Indeterminate"),
        }
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
    const fn sequence(self) -> u64 {
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
}

impl Debug for PrivateOramMutationJournal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournal")
            .field("root", &"[redacted]")
            .field("expected_owner_signing_key_id", &"[redacted]")
            .field("owner_public_key", &"[redacted]")
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
        Ok(Self {
            root: collection_path.join(PRIVATE_ORAM_MUTATION_JOURNAL_DIR),
            expected_owner_signing_key_id,
            owner_public_key,
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
                    || recorded.committed_signed_state_digest
                        != derived.committed_signed_state_digest
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
        validate_private_directory(&self.active_path())?;
        validate_private_directory(&self.active_temp_path())?;
        let descriptor: PrivateOramMutationJournalDescriptorV1 =
            read_json_private(&self.descriptor_path(), MAX_DESCRIPTOR_BYTES)?;
        validate_descriptor(&descriptor, self.signature_verification())?;
        let state: PrivateOramMutationJournalStateV1 =
            read_json_private(&self.state_path(), MAX_STATE_BYTES)?;
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
        let path = self.root.join(LOCK_FILE);
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
        sync_directory(&self.root)?;
        Ok(PrivateOramMutationJournalLock { _file: file })
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

    fn descriptor_path(&self) -> PathBuf {
        self.active_path().join(DESCRIPTOR_FILE)
    }

    fn state_path(&self) -> PathBuf {
        self.active_path().join(STATE_FILE)
    }
}

struct PrivateOramMutationJournalLock {
    _file: File,
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

fn validate_state(
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

fn validate_owner_prepares(
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
    let reconciliation_authority_digest = owner_recovery_authority_digest(
        context,
        authenticated_owner_peer_id,
        &parent_lease_acquired_record_digest,
        &parent_owners_prepared_record_digest,
        &consensus_authority_record_digest,
        &indexes,
    )?;
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

fn owner_recovery_authority_digest(
    context: &PrivateOramValidatedMutationReconcileContextV1,
    authenticated_owner_peer_id: PeerId,
    parent_lease_acquired_record_digest: &str,
    parent_owners_prepared_record_digest: &str,
    consensus_authority_record_digest: &str,
    indexes: &[PrivateOramValidatedOwnerRecoveryIndexV1],
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(OWNER_RECOVERY_AUTHORITY_DIGEST_DOMAIN);
    hash_digest(&mut hasher, &context.snapshot.descriptor.descriptor_digest)?;
    hash_digest(&mut hasher, parent_lease_acquired_record_digest)?;
    hash_digest(&mut hasher, parent_owners_prepared_record_digest)?;
    hash_digest(&mut hasher, consensus_authority_record_digest)?;
    hasher.update(authenticated_owner_peer_id.to_be_bytes());
    hasher.update([match context.disposition {
        PrivateOramMutationReconcileDispositionV1::ObservedOldNeedsAbortDecision => 1,
        PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided => 2,
        PrivateOramMutationReconcileDispositionV1::ExactNew => 3,
    }]);

    let lease = &context.active_lease;
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
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
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

fn derive_consensus_evidence(
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

fn validate_consensus_evidence_shape(
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
    if file_sha256(destination, MAX_STATE_BYTES)? != candidate_sha256 {
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
            return if file_sha256(destination, MAX_STATE_BYTES)? == candidate_sha256 {
                Ok(())
            } else {
                Err(PrivateOramMutationJournalError::Indeterminate)
            };
        }
        if file_sha256(destination, MAX_STATE_BYTES)? != candidate_sha256 {
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
    let mut file = open_private_file(path, max_bytes)?;
    serde_json::from_reader(&mut file).map_err(|_| PrivateOramMutationJournalError::Corrupt)
}

pub(super) fn file_sha256(
    path: &Path,
    max_bytes: u64,
) -> Result<[u8; 32], PrivateOramMutationJournalError> {
    let mut file = open_private_file(path, max_bytes)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(PrivateOramMutationJournalError::Io)?;
        if read == 0 {
            break;
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
        snapshot
            .descriptor
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
