#![allow(
    dead_code,
    reason = "D3-B3-B2 is dormant until the private ORAM mutation coordinator is wired"
)]

//! Prepared-first durable owner journal for a paired private ORAM append mutation.
//!
//! The journal lives below the primary HNSW store's existing `temp` directory. A non-empty
//! journal therefore reuses the collection snapshot incomplete-write gate. Publication requires
//! Linux `renameat2(RENAME_NOREPLACE)` and an owner-only local filesystem with durable directory
//! fsync. No canonical HNSW/result bucket, Merkle, epoch, or point file is modified by prepare.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr};
use std::fmt::{self, Debug, Formatter};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use data_encoding::BASE64URL_NOPAD;
use fs_err as fs;
use fs_err::{File, OpenOptions};
use qdrant_sec::{
    PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS, PrivateHnswOramBucket, PrivateOramAppendBucketRefV1,
    PrivateOramAppendMutationBundleV1, PrivateOramIndexKindV2,
    PrivateOramValidatedOwnerFinalBucketsV1, PrivateOramValidatedOwnerPrepareV1,
    PrivateResultOramBucket, private_oram_append_mutation_v1_digest,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PRIVATE_ORAM_OWNER_JOURNAL_DIR: &str = "private-oram-owner-v2";
pub const PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION: u16 = 1;
pub const PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION: u16 = 1;
pub const PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION: u16 = 1;

const OWNER_STORE_TEMP_DIR: &str = "temp";
const ACTIVE_DIR: &str = "active";
const ACTIVE_TEMP_DIR: &str = "temp";
const DESCRIPTOR_FILE: &str = "descriptor.bin";
const FINAL_BUCKETS_FILE: &str = "final-buckets.bin";
const STATE_FILE: &str = "state.bin";
const TERMINAL_DIR: &str = "terminal";
const TERMINAL_RECORD_FILE: &str = "record.bin";
const CANDIDATE_PREFIX: &str = ".candidate-";
const TERMINAL_CANDIDATE_PREFIX: &str = ".terminal-candidate-";
const PREPARED_PHASE_TAG: u8 = 1;
const FINALIZED_PHASE_TAG: u8 = 2;
const ABORTED_OLD_PHASE_TAG: u8 = 3;
const HNSW_KIND_TAG: u8 = 1;
const RESULT_KIND_TAG: u8 = 2;
const MAX_DESCRIPTOR_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FINAL_BUCKET_FRAME_BYTES: u64 = 512 * 1024 * 1024;
const MAX_STATE_BYTES: u64 = 4 * 1024;
const MAX_TERMINAL_RECORD_BYTES: u64 = 4 * 1024;
const MAX_RESOURCE_ID_BYTES: usize = 256;
const DIGEST_BYTES: usize = 32;
const MAX_PAIRED_OWNER_INDEXES: usize = 2;

const DESCRIPTOR_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-journal-descriptor/v1";
const STATE_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-journal-state/v1";
const FINALIZED_STATE_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-finalized-state/v1";
const ABORTED_OLD_STATE_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-aborted-old-state/v1";
const FINAL_BUCKET_FRAME_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-final-bucket-frame/v1";
const INDEX_PREPARED_EVIDENCE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-index-prepared-evidence/v1";
const INDEX_FINALIZED_EVIDENCE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-index-finalized-evidence/v1";
const INDEX_ABORTED_OLD_EVIDENCE_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-index-aborted-old-evidence/v1";

#[derive(Error, Clone, Copy, PartialEq, Eq)]
pub enum PrivateOramOwnerJournalError {
    #[error("private ORAM owner journal is unsupported on this platform or filesystem")]
    Unsupported,
    #[error("private ORAM owner journal input is invalid")]
    InvalidInput(&'static str),
    #[error("another private ORAM owner journal is active")]
    ConcurrentMutation,
    #[error("private ORAM owner journal phase transition is invalid")]
    InvalidTransition,
    #[error("private ORAM owner journal contains corrupt or inconsistent state")]
    Corrupt,
    #[error("private ORAM owner journal I/O failed before publication")]
    Io,
    #[error("private ORAM owner journal publication outcome is indeterminate")]
    Indeterminate,
}

impl Debug for PrivateOramOwnerJournalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("Unsupported"),
            Self::InvalidInput(field) => f.debug_tuple("InvalidInput").field(field).finish(),
            Self::ConcurrentMutation => f.write_str("ConcurrentMutation"),
            Self::InvalidTransition => f.write_str("InvalidTransition"),
            Self::Corrupt => f.write_str("Corrupt([redacted])"),
            Self::Io => f.write_str("Io([redacted])"),
            Self::Indeterminate => f.write_str("Indeterminate([redacted])"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerJournalRequirementV1<'a> {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: &'a str,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub writeback_digest: &'a str,
}

impl Debug for PrivateOramOwnerJournalRequirementV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalRequirementV1")
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerJournalPrepareContextV1<'a> {
    pub(crate) parent_descriptor_digest: &'a str,
    pub(crate) parent_lease_acquired_record_digest: &'a str,
    pub(crate) owner_peer_id: u64,
    pub(crate) requirements: &'a [PrivateOramOwnerJournalRequirementV1<'a>],
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PrivateOramOwnerJournalFinalizeContextV1<'a> {
    expected_journal_descriptor_digest: &'a str,
    parent_descriptor_digest: &'a str,
    authenticated_owner_peer_id: u64,
    consensus_authority_record_digest: &'a str,
    reconciliation_authority_digest: &'a str,
    canonical_index_states: &'a [PrivateOramOwnerJournalTerminalIndexStateV1],
}

impl Debug for PrivateOramOwnerJournalFinalizeContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalFinalizeContextV1")
            .field("expected_journal_descriptor_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field(
                "authenticated_owner_peer_id",
                &self.authenticated_owner_peer_id,
            )
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field(
                "canonical_index_state_count",
                &self.canonical_index_states.len(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PrivateOramOwnerJournalAbortOldContextV1<'a> {
    expected_journal_descriptor_digest: &'a str,
    parent_descriptor_digest: &'a str,
    authenticated_owner_peer_id: u64,
    consensus_authority_record_digest: &'a str,
    reconciliation_authority_digest: &'a str,
    canonical_index_states: &'a [PrivateOramOwnerJournalTerminalIndexStateV1],
}

impl Debug for PrivateOramOwnerJournalAbortOldContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalAbortOldContextV1")
            .field("expected_journal_descriptor_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field(
                "authenticated_owner_peer_id",
                &self.authenticated_owner_peer_id,
            )
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field(
                "canonical_index_state_count",
                &self.canonical_index_states.len(),
            )
            .finish()
    }
}

impl Debug for PrivateOramOwnerJournalPrepareContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalPrepareContextV1")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("requirement_count", &self.requirements.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalIndexDescriptorV1 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub writeback_digest: String,
    pub read_path_count: u32,
    pub read_transcript_digest: String,
    pub ordered_bucket_refs: Vec<PrivateOramAppendBucketRefV1>,
    pub final_bucket_refs: Vec<PrivateOramAppendBucketRefV1>,
}

impl Debug for PrivateOramOwnerJournalIndexDescriptorV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalIndexDescriptorV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("read_path_count", &self.read_path_count)
            .field("read_transcript_digest", &"[redacted]")
            .field("ordered_bucket_count", &self.ordered_bucket_refs.len())
            .field("final_bucket_count", &self.final_bucket_refs.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalDescriptorV1 {
    pub version: u16,
    pub parent_descriptor_digest: String,
    pub parent_lease_acquired_record_digest: String,
    pub owner_peer_id: u64,
    pub collection_id: String,
    pub mutation_id: String,
    pub signed_mutation_digest: String,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub indexes: Vec<PrivateOramOwnerJournalIndexDescriptorV1>,
    pub final_bucket_frame_version: u16,
    pub final_bucket_frame_length: u64,
    pub final_bucket_frame_sha256: String,
    pub descriptor_digest: String,
}

impl Debug for PrivateOramOwnerJournalDescriptorV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalDescriptorV1")
            .field("version", &self.version)
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("signed_mutation_digest", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("indexes", &self.indexes)
            .field(
                "final_bucket_frame_version",
                &self.final_bucket_frame_version,
            )
            .field("final_bucket_frame_length", &self.final_bucket_frame_length)
            .field("final_bucket_frame_sha256", &"[redacted]")
            .field("descriptor_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramOwnerJournalPhaseV1 {
    Prepared,
    Finalized,
    AbortedOld,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalStateV1 {
    pub version: u16,
    pub sequence: u64,
    pub descriptor_digest: String,
    pub previous_record_digest: Option<String>,
    pub phase: PrivateOramOwnerJournalPhaseV1,
    pub state_digest: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalTerminalIndexStateV1 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub canonical_state_digest: String,
}

impl Debug for PrivateOramOwnerJournalTerminalIndexStateV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalTerminalIndexStateV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("canonical_state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalTerminalRecordV1 {
    pub version: u16,
    pub sequence: u64,
    pub descriptor_digest: String,
    pub previous_record_digest: String,
    pub phase: PrivateOramOwnerJournalPhaseV1,
    pub parent_descriptor_digest: String,
    pub authenticated_owner_peer_id: u64,
    pub consensus_authority_record_digest: String,
    pub reconciliation_authority_digest: String,
    pub canonical_index_states: Vec<PrivateOramOwnerJournalTerminalIndexStateV1>,
    pub record_digest: String,
}

impl Debug for PrivateOramOwnerJournalTerminalRecordV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalTerminalRecordV1")
            .field("version", &self.version)
            .field("sequence", &self.sequence)
            .field("descriptor_digest", &"[redacted]")
            .field("previous_record_digest", &"[redacted]")
            .field("phase", &self.phase)
            .field("parent_descriptor_digest", &"[redacted]")
            .field(
                "authenticated_owner_peer_id",
                &self.authenticated_owner_peer_id,
            )
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field(
                "canonical_index_state_count",
                &self.canonical_index_states.len(),
            )
            .field("record_digest", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramOwnerJournalStateV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalStateV1")
            .field("version", &self.version)
            .field("sequence", &self.sequence)
            .field("descriptor_digest", &"[redacted]")
            .field("previous_record_digest", &"[redacted]")
            .field("phase", &self.phase)
            .field("state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum PrivateOramOwnerFinalBucketBatchV1 {
    Hnsw(Vec<PrivateHnswOramBucket>),
    Result(Vec<PrivateResultOramBucket>),
}

impl PrivateOramOwnerFinalBucketBatchV1 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        match self {
            Self::Hnsw(_) => PrivateOramIndexKindV2::Hnsw,
            Self::Result(_) => PrivateOramIndexKindV2::Result,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Hnsw(buckets) => buckets.len(),
            Self::Result(buckets) => buckets.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Debug for PrivateOramOwnerFinalBucketBatchV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerFinalBucketBatchV1")
            .field("kind", &self.kind())
            .field("bucket_count", &self.len())
            .field("buckets", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerFinalBucketIndexV1 {
    pub index_name: String,
    pub buckets: PrivateOramOwnerFinalBucketBatchV1,
}

impl Debug for PrivateOramOwnerFinalBucketIndexV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerFinalBucketIndexV1")
            .field("index_name", &"[redacted]")
            .field("buckets", &self.buckets)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerJournalSnapshotV1 {
    pub descriptor: PrivateOramOwnerJournalDescriptorV1,
    pub state: PrivateOramOwnerJournalStateV1,
    pub terminal: Option<PrivateOramOwnerJournalTerminalRecordV1>,
    pub final_buckets: Vec<PrivateOramOwnerFinalBucketIndexV1>,
}

impl Debug for PrivateOramOwnerJournalSnapshotV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournalSnapshotV1")
            .field("descriptor", &self.descriptor)
            .field("state", &self.state)
            .field("terminal", &self.terminal)
            .field("final_bucket_index_count", &self.final_buckets.len())
            .field("final_buckets", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerPreparedIndexEvidenceV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    prepared_journal_digest: String,
}

impl Debug for PrivateOramOwnerPreparedIndexEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPreparedIndexEvidenceV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerPreparedIndexEvidenceV1 {
    pub(crate) const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.kind
    }

    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn prepared_journal_digest(&self) -> &str {
        &self.prepared_journal_digest
    }
}

/// Untrusted parent projection used to match one owner-journal index during restart recovery.
///
/// Construction validates shape only. This type does not carry parent consensus authority.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramOwnerRecoveryIndexProjectionInputV1<'a> {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: &'a str,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub writeback_digest: &'a str,
    pub prepared_journal_digest: &'a str,
}

impl Debug for PrivateOramOwnerRecoveryIndexProjectionInputV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryIndexProjectionInputV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerRecoveryIndexProjectionV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    new_root_hash: String,
    writeback_digest: String,
    prepared_journal_digest: String,
}

impl Debug for PrivateOramOwnerRecoveryIndexProjectionV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryIndexProjectionV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryIndexProjectionV1 {
    pub fn try_from_input(
        input: PrivateOramOwnerRecoveryIndexProjectionInputV1<'_>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_resource_id(input.index_name, "index_name")?;
        validate_digest(input.old_root_hash, "old_root_hash")?;
        validate_digest(input.new_root_hash, "new_root_hash")?;
        validate_digest(input.writeback_digest, "writeback_digest")?;
        validate_digest(input.prepared_journal_digest, "prepared_journal_digest")?;
        if input.new_epoch <= input.old_epoch {
            return Err(PrivateOramOwnerJournalError::InvalidInput("index_epoch"));
        }
        Ok(Self {
            kind: input.kind,
            index_name: input.index_name.to_string(),
            old_epoch: input.old_epoch,
            new_epoch: input.new_epoch,
            old_root_hash: input.old_root_hash.to_string(),
            new_root_hash: input.new_root_hash.to_string(),
            writeback_digest: input.writeback_digest.to_string(),
            prepared_journal_digest: input.prepared_journal_digest.to_string(),
        })
    }
}

/// Untrusted, immutable projection of typed parent recovery evidence.
///
/// The storage coordinator must build this from its validated parent authority. Reopening the
/// child journal below recomputes every Prepared digest; possession of this projection alone does
/// not authorize canonical writes or a terminal transition.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerRecoveryProjectionV1 {
    expected_owner_peer_id: u64,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    collection_id: String,
    mutation_id: String,
    signed_mutation_digest: String,
    writer_lease_digest: String,
    writer_fence: u64,
    indexes: Vec<PrivateOramOwnerRecoveryIndexProjectionV1>,
}

impl Debug for PrivateOramOwnerRecoveryProjectionV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryProjectionV1")
            .field("expected_owner_peer_id", &self.expected_owner_peer_id)
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("signed_mutation_digest", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl PrivateOramOwnerRecoveryProjectionV1 {
    pub fn try_new(
        expected_owner_peer_id: u64,
        parent_descriptor_digest: &str,
        parent_lease_acquired_record_digest: &str,
        mutation_bundle: &PrivateOramAppendMutationBundleV1,
        indexes: Vec<PrivateOramOwnerRecoveryIndexProjectionV1>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_digest(parent_descriptor_digest, "parent_descriptor_digest")?;
        validate_digest(
            parent_lease_acquired_record_digest,
            "parent_lease_acquired_record_digest",
        )?;
        if indexes.len() != MAX_PAIRED_OWNER_INDEXES
            || indexes[0].kind != PrivateOramIndexKindV2::Hnsw
            || indexes[1].kind != PrivateOramIndexKindV2::Result
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput("indexes"));
        }

        let mutation = &mutation_bundle.mutation;
        validate_resource_id(&mutation.collection_id, "collection_id")?;
        validate_digest(&mutation.mutation_id, "mutation_id")?;
        validate_digest(&mutation.writer_lease_digest, "writer_lease_digest")?;
        let signed_mutation_digest = private_oram_append_mutation_v1_digest(mutation)
            .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("mutation_bundle"))?;
        validate_digest(&signed_mutation_digest, "signed_mutation_digest")?;
        if mutation.old_state.state.indexes.len() != indexes.len()
            || mutation.new_state.state.indexes.len() != indexes.len()
            || mutation.writebacks.len() != indexes.len()
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "mutation_indexes",
            ));
        }
        for (((projection, old), new), writeback) in indexes
            .iter()
            .zip(&mutation.old_state.state.indexes)
            .zip(&mutation.new_state.state.indexes)
            .zip(&mutation.writebacks)
        {
            if projection.kind != old.kind
                || projection.kind != new.kind
                || projection.kind != writeback.kind
                || projection.index_name != old.index_name
                || projection.index_name != new.index_name
                || projection.index_name != writeback.index_name
                || projection.old_epoch != old.index_epoch
                || projection.new_epoch != new.index_epoch
                || projection.old_root_hash != old.root_hash
                || projection.new_root_hash != new.root_hash
                || projection.writeback_digest != new.last_writeback_digest
            {
                return Err(PrivateOramOwnerJournalError::InvalidInput(
                    "mutation_indexes",
                ));
            }
        }

        Ok(Self {
            expected_owner_peer_id,
            parent_descriptor_digest: parent_descriptor_digest.to_string(),
            parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.to_string(),
            collection_id: mutation.collection_id.clone(),
            mutation_id: mutation.mutation_id.clone(),
            signed_mutation_digest,
            writer_lease_digest: mutation.writer_lease_digest.clone(),
            writer_fence: mutation.writer_fence,
            indexes,
        })
    }
}

/// Opaque evidence that a live Prepared child matched an untrusted parent projection while the
/// child journal remained under a shared lock.
///
/// The value is exposed only by reference inside `with_revalidated_recovery_prepared_v1`, so safe
/// callers cannot retain it after the lock is released.
pub(crate) struct PrivateOramOwnerRecoveryPreparedBindingV1<'lock> {
    prepared: PrivateOramDurableOwnerPreparedTokenV1,
    store_binding: PrivateOramOwnerPreparedStoreBindingV1,
    lock_lifetime: PhantomData<&'lock mut ()>,
}

impl Debug for PrivateOramOwnerRecoveryPreparedBindingV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryPreparedBindingV1")
            .field("prepared", &"[redacted]")
            .field("store_binding", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryPreparedBindingV1<'_> {
    /// Returns structural data only. The snapshot is untrusted outside this lock-scoped rebind and
    /// cannot authorize a store write or terminal transition.
    pub(crate) fn untrusted_snapshot_view(&self) -> &PrivateOramOwnerJournalSnapshotV1 {
        self.store_binding.snapshot()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramDurableOwnerPreparedTokenV1 {
    owner_peer_id: u64,
    journal_descriptor_digest: String,
    parent_descriptor_digest: String,
    parent_lease_acquired_record_digest: String,
    indexes: Vec<PrivateOramOwnerPreparedIndexEvidenceV1>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerPreparedStoreBindingV1 {
    snapshot: PrivateOramOwnerJournalSnapshotV1,
}

impl Debug for PrivateOramOwnerPreparedStoreBindingV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerPreparedStoreBindingV1")
            .field("snapshot", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerPreparedStoreBindingV1 {
    pub(crate) fn snapshot(&self) -> &PrivateOramOwnerJournalSnapshotV1 {
        &self.snapshot
    }
}

impl Debug for PrivateOramDurableOwnerPreparedTokenV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramDurableOwnerPreparedTokenV1")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("journal_descriptor_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("parent_lease_acquired_record_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl PrivateOramDurableOwnerPreparedTokenV1 {
    pub(crate) const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub(crate) fn journal_descriptor_digest(&self) -> &str {
        &self.journal_descriptor_digest
    }

    pub(crate) fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub(crate) fn parent_lease_acquired_record_digest(&self) -> &str {
        &self.parent_lease_acquired_record_digest
    }

    pub(crate) fn indexes(&self) -> &[PrivateOramOwnerPreparedIndexEvidenceV1] {
        &self.indexes
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerFinalizedIndexEvidenceV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    prepared_journal_digest: String,
    finalized_state_digest: String,
}

impl Debug for PrivateOramOwnerFinalizedIndexEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerFinalizedIndexEvidenceV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("finalized_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerFinalizedIndexEvidenceV1 {
    pub(crate) const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.kind
    }

    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn prepared_journal_digest(&self) -> &str {
        &self.prepared_journal_digest
    }

    pub(crate) fn finalized_state_digest(&self) -> &str {
        &self.finalized_state_digest
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramDurableOwnerFinalizedTokenV1 {
    owner_peer_id: u64,
    journal_descriptor_digest: String,
    prepared_state_digest: String,
    terminal_record_digest: String,
    parent_descriptor_digest: String,
    consensus_authority_record_digest: String,
    reconciliation_authority_digest: String,
    indexes: Vec<PrivateOramOwnerFinalizedIndexEvidenceV1>,
}

impl Debug for PrivateOramDurableOwnerFinalizedTokenV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramDurableOwnerFinalizedTokenV1")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("journal_descriptor_digest", &"[redacted]")
            .field("prepared_state_digest", &"[redacted]")
            .field("terminal_record_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl PrivateOramDurableOwnerFinalizedTokenV1 {
    pub(crate) const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub(crate) fn journal_descriptor_digest(&self) -> &str {
        &self.journal_descriptor_digest
    }

    pub(crate) fn prepared_state_digest(&self) -> &str {
        &self.prepared_state_digest
    }

    pub(crate) fn terminal_record_digest(&self) -> &str {
        &self.terminal_record_digest
    }

    pub(crate) fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub(crate) fn consensus_authority_record_digest(&self) -> &str {
        &self.consensus_authority_record_digest
    }

    pub(crate) fn reconciliation_authority_digest(&self) -> &str {
        &self.reconciliation_authority_digest
    }

    pub(crate) fn indexes(&self) -> &[PrivateOramOwnerFinalizedIndexEvidenceV1] {
        &self.indexes
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramOwnerAbortedOldIndexEvidenceV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    prepared_journal_digest: String,
    aborted_old_state_digest: String,
}

impl Debug for PrivateOramOwnerAbortedOldIndexEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerAbortedOldIndexEvidenceV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("prepared_journal_digest", &"[redacted]")
            .field("aborted_old_state_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerAbortedOldIndexEvidenceV1 {
    pub(crate) const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.kind
    }

    pub(crate) fn index_name(&self) -> &str {
        &self.index_name
    }

    pub(crate) fn prepared_journal_digest(&self) -> &str {
        &self.prepared_journal_digest
    }

    pub(crate) fn aborted_old_state_digest(&self) -> &str {
        &self.aborted_old_state_digest
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PrivateOramDurableOwnerAbortedOldTokenV1 {
    owner_peer_id: u64,
    journal_descriptor_digest: String,
    prepared_state_digest: String,
    terminal_record_digest: String,
    parent_descriptor_digest: String,
    consensus_authority_record_digest: String,
    reconciliation_authority_digest: String,
    indexes: Vec<PrivateOramOwnerAbortedOldIndexEvidenceV1>,
}

impl Debug for PrivateOramDurableOwnerAbortedOldTokenV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramDurableOwnerAbortedOldTokenV1")
            .field("owner_peer_id", &self.owner_peer_id)
            .field("journal_descriptor_digest", &"[redacted]")
            .field("prepared_state_digest", &"[redacted]")
            .field("terminal_record_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("consensus_authority_record_digest", &"[redacted]")
            .field("reconciliation_authority_digest", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

impl PrivateOramDurableOwnerAbortedOldTokenV1 {
    pub(crate) const fn owner_peer_id(&self) -> u64 {
        self.owner_peer_id
    }

    pub(crate) fn journal_descriptor_digest(&self) -> &str {
        &self.journal_descriptor_digest
    }

    pub(crate) fn prepared_state_digest(&self) -> &str {
        &self.prepared_state_digest
    }

    pub(crate) fn terminal_record_digest(&self) -> &str {
        &self.terminal_record_digest
    }

    pub(crate) fn parent_descriptor_digest(&self) -> &str {
        &self.parent_descriptor_digest
    }

    pub(crate) fn consensus_authority_record_digest(&self) -> &str {
        &self.consensus_authority_record_digest
    }

    pub(crate) fn reconciliation_authority_digest(&self) -> &str {
        &self.reconciliation_authority_digest
    }

    pub(crate) fn indexes(&self) -> &[PrivateOramOwnerAbortedOldIndexEvidenceV1] {
        &self.indexes
    }
}

#[derive(Clone)]
pub struct PrivateOramOwnerJournal {
    root: PathBuf,
}

impl Debug for PrivateOramOwnerJournal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerJournal")
            .field("root", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerJournal {
    /// Creates a paired owner journal below the primary HNSW store root.
    pub fn new(primary_hnsw_store_root: impl AsRef<Path>) -> Self {
        Self {
            root: primary_hnsw_store_root
                .as_ref()
                .join(OWNER_STORE_TEMP_DIR)
                .join(PRIVATE_ORAM_OWNER_JOURNAL_DIR),
        }
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    pub(crate) fn prepare(
        &self,
        validated: &PrivateOramValidatedOwnerPrepareV1,
        context: PrivateOramOwnerJournalPrepareContextV1<'_>,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerPreparedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        let desired = ValidatedOwnerJournal::build(validated, context)?;
        self.prepare_validated(desired)
    }

    /// Loads a self-consistent but untrusted snapshot without minting durable owner evidence.
    ///
    /// The snapshot may contain only the Prepared record or an append-only terminal record.
    /// Recovery must bind it to typed parent state, the signed mutation, manifests, and canonical
    /// index state before it can produce new evidence.
    pub fn inspect_structural(
        &self,
    ) -> Result<Option<PrivateOramOwnerJournalSnapshotV1>, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        if !path_entry_exists(&self.root)? {
            return Ok(None);
        }
        let root_file = open_private_directory(&self.root)?;
        let _root_lock = lock_private_journal_root_shared(&root_file)?;
        let output = match Self::stable_root_entry_from(&root_file)? {
            StableRootEntry::Empty => None,
            StableRootEntry::Active => Some(
                self.load_active_structural_from(&root_file, false, None)?
                    .snapshot,
            ),
        };
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(output)
    }

    pub(crate) fn bind_live_prepared_store_adapter_v1(
        &self,
        prepared: &PrivateOramDurableOwnerPreparedTokenV1,
    ) -> Result<PrivateOramOwnerPreparedStoreBindingV1, PrivateOramOwnerJournalError> {
        let snapshot = self
            .inspect_structural()?
            .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
        prepared_store_binding(snapshot, prepared)
    }

    pub(crate) fn with_live_prepared_store_binding_v1<R>(
        &self,
        prepared: &PrivateOramDurableOwnerPreparedTokenV1,
        action: impl FnOnce(&PrivateOramOwnerPreparedStoreBindingV1) -> R,
    ) -> Result<R, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let root_file = open_private_directory(&self.root)?;
        let _root_lock = lock_private_journal_root_shared(&root_file)?;
        let snapshot = match Self::stable_root_entry_from(&root_file)? {
            StableRootEntry::Empty => {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            StableRootEntry::Active => {
                self.load_active_structural_from(&root_file, false, None)?
                    .snapshot
            }
        };
        let binding = prepared_store_binding(snapshot, prepared)?;
        let output = action(&binding);
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(output)
    }

    /// Reopens and revalidates the exact paired child Prepared evidence under one shared lock.
    ///
    /// The projection is deliberately not authority-bearing. A storage-layer caller must retain
    /// its typed parent recovery authority while consuming the callback-scoped binding.
    pub(crate) fn with_revalidated_recovery_prepared_v1<R>(
        &self,
        projection: &PrivateOramOwnerRecoveryProjectionV1,
        action: impl for<'lock> FnOnce(&PrivateOramOwnerRecoveryPreparedBindingV1<'lock>) -> R,
    ) -> Result<R, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        if !path_entry_exists(&self.root)? {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let root_file = open_private_directory(&self.root)?;
        let root_lock = lock_private_journal_root_shared(&root_file)?;
        let snapshot = match Self::stable_root_entry_from(&root_file)? {
            StableRootEntry::Empty => {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            StableRootEntry::Active => {
                self.load_active_structural_from(&root_file, false, None)?
                    .snapshot
            }
        };
        let binding = recovery_prepared_binding(snapshot, projection, &root_lock)?;
        let output = action(&binding);
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(output)
    }

    #[cfg(test)]
    pub(crate) fn with_exclusive_root_lock_test_v1<R>(
        &self,
        action: impl FnOnce() -> R,
    ) -> Result<R, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        let root_file = open_private_directory(&self.root)?;
        let _root_lock = lock_private_journal_root(&root_file)?;
        let output = action();
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(output)
    }

    #[cfg(test)]
    pub(crate) fn prepare_store_adapter_test_fixture_v1(
        &self,
        mutation_bundle: &qdrant_sec::PrivateOramAppendMutationBundleV1,
        owner_peer_id: u64,
        parent_descriptor_digest: &str,
        parent_lease_acquired_record_digest: &str,
        final_buckets: Vec<PrivateOramOwnerFinalBucketIndexV1>,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerPreparedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        let mutation = &mutation_bundle.mutation;
        let old = &mutation.old_state.state.indexes;
        let new = &mutation.new_state.state.indexes;
        if old.len() != new.len()
            || old.len() != mutation.writebacks.len()
            || old.len() != final_buckets.len()
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "test_fixture_indexes",
            ));
        }
        let indexes = old
            .iter()
            .zip(new)
            .zip(&mutation.writebacks)
            .zip(&final_buckets)
            .map(|(((old, new), writeback), final_buckets)| {
                if old.kind != new.kind
                    || old.kind != writeback.kind
                    || old.kind != final_buckets.buckets.kind()
                    || old.index_name != new.index_name
                    || old.index_name != writeback.index_name
                    || old.index_name != final_buckets.index_name
                {
                    return Err(PrivateOramOwnerJournalError::InvalidInput(
                        "test_fixture_index",
                    ));
                }
                let final_bucket_refs = match &final_buckets.buckets {
                    PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets) => buckets
                        .iter()
                        .map(|bucket| PrivateOramAppendBucketRefV1 {
                            bucket_id: bucket.bucket_id,
                            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                            bucket_commitment: bucket.bucket_commitment.clone(),
                        })
                        .collect(),
                    PrivateOramOwnerFinalBucketBatchV1::Result(buckets) => buckets
                        .iter()
                        .map(|bucket| PrivateOramAppendBucketRefV1 {
                            bucket_id: bucket.bucket_id,
                            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                            bucket_commitment: bucket.bucket_commitment.clone(),
                        })
                        .collect(),
                };
                Ok(PrivateOramOwnerJournalIndexDescriptorV1 {
                    kind: old.kind,
                    index_name: old.index_name.clone(),
                    old_epoch: old.index_epoch,
                    new_epoch: new.index_epoch,
                    old_root_hash: old.root_hash.clone(),
                    new_root_hash: new.root_hash.clone(),
                    writeback_digest: new.last_writeback_digest.clone(),
                    read_path_count: writeback.read_path_count,
                    read_transcript_digest: writeback.read_transcript_digest.clone(),
                    ordered_bucket_refs: writeback.updated_buckets.clone(),
                    final_bucket_refs,
                })
            })
            .collect::<Result<Vec<_>, PrivateOramOwnerJournalError>>()?;
        let final_bucket_bytes = encode_final_bucket_frame(&indexes, &final_buckets)?;
        let mut descriptor = PrivateOramOwnerJournalDescriptorV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION,
            parent_descriptor_digest: parent_descriptor_digest.to_string(),
            parent_lease_acquired_record_digest: parent_lease_acquired_record_digest.to_string(),
            owner_peer_id,
            collection_id: mutation.collection_id.clone(),
            mutation_id: mutation.mutation_id.clone(),
            signed_mutation_digest: qdrant_sec::private_oram_append_mutation_v1_digest(mutation)
                .map_err(|_| PrivateOramOwnerJournalError::InvalidInput("test_fixture_mutation"))?,
            writer_lease_digest: mutation.writer_lease_digest.clone(),
            writer_fence: mutation.writer_fence,
            indexes,
            final_bucket_frame_version: PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION,
            final_bucket_frame_length: final_bucket_bytes.len() as u64,
            final_bucket_frame_sha256: digest_string(&final_bucket_bytes),
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor_digest(&descriptor)?;
        let descriptor_bytes = encode_descriptor(&descriptor)?;
        let mut state = PrivateOramOwnerJournalStateV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION,
            sequence: 1,
            descriptor_digest: descriptor.descriptor_digest.clone(),
            previous_record_digest: None,
            phase: PrivateOramOwnerJournalPhaseV1::Prepared,
            state_digest: String::new(),
        };
        state.state_digest = state_digest(&state)?;
        let state_bytes = encode_state(&state)?;
        let snapshot = PrivateOramOwnerJournalSnapshotV1 {
            descriptor,
            state,
            terminal: None,
            final_buckets,
        };
        validate_snapshot(&snapshot, &final_bucket_bytes)?;
        self.prepare_validated(ValidatedOwnerJournal {
            snapshot,
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes: None,
        })
    }

    #[deprecated(note = "use inspect_structural, which also describes terminal snapshots")]
    pub fn inspect_prepared_structural(
        &self,
    ) -> Result<Option<PrivateOramOwnerJournalSnapshotV1>, PrivateOramOwnerJournalError> {
        self.inspect_structural()
    }

    /// Records a durable Finalized terminal state after a higher-level adapter has verified the
    /// canonical new index state and exact-new reconciliation authority.
    fn record_finalized(
        &self,
        context: PrivateOramOwnerJournalFinalizeContextV1<'_>,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerFinalizedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        let journal = self.record_terminal(TerminalTransition {
            phase: PrivateOramOwnerJournalPhaseV1::Finalized,
            expected_journal_descriptor_digest: context.expected_journal_descriptor_digest,
            parent_descriptor_digest: context.parent_descriptor_digest,
            authenticated_owner_peer_id: context.authenticated_owner_peer_id,
            consensus_authority_record_digest: context.consensus_authority_record_digest,
            reconciliation_authority_digest: context.reconciliation_authority_digest,
            canonical_index_states: context.canonical_index_states,
        })?;
        let token = finalized_token(&journal.snapshot)?;
        Ok((journal.snapshot, token))
    }

    /// Records a durable AbortedOld terminal state after a higher-level adapter has verified the
    /// canonical old index state and consensus-linearized abort authority.
    fn record_aborted_old(
        &self,
        context: PrivateOramOwnerJournalAbortOldContextV1<'_>,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerAbortedOldTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        let journal = self.record_terminal(TerminalTransition {
            phase: PrivateOramOwnerJournalPhaseV1::AbortedOld,
            expected_journal_descriptor_digest: context.expected_journal_descriptor_digest,
            parent_descriptor_digest: context.parent_descriptor_digest,
            authenticated_owner_peer_id: context.authenticated_owner_peer_id,
            consensus_authority_record_digest: context.consensus_authority_record_digest,
            reconciliation_authority_digest: context.reconciliation_authority_digest,
            canonical_index_states: context.canonical_index_states,
        })?;
        let token = aborted_old_token(&journal.snapshot)?;
        Ok((journal.snapshot, token))
    }

    fn prepare_validated(
        &self,
        desired: ValidatedOwnerJournal,
    ) -> Result<
        (
            PrivateOramOwnerJournalSnapshotV1,
            PrivateOramDurableOwnerPreparedTokenV1,
        ),
        PrivateOramOwnerJournalError,
    > {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        let root_file = self.ensure_root()?;
        let _root_lock = lock_private_journal_root(&root_file)?;
        if Self::stable_root_entry_from(&root_file)? == StableRootEntry::Active {
            let existing = self.load_active_structural_from(&root_file, true, None)?;
            if !existing.exactly_matches(&desired) {
                return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
            }
            sync_open_directory(&root_file)
                .and_then(|()| validate_open_directory_at_path(&root_file, &self.root))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            return Ok(existing.into_output());
        }

        let candidate = tempfile::Builder::new()
            .prefix(CANDIDATE_PREFIX)
            .tempdir_in(&self.root)
            .map_err(|_| PrivateOramOwnerJournalError::Io)?;
        set_private_directory_permissions(candidate.path())?;
        validate_private_directory_exact(candidate.path())?;
        write_new_private_file(
            &candidate.path().join(DESCRIPTOR_FILE),
            &desired.descriptor_bytes,
            MAX_DESCRIPTOR_BYTES,
        )?;
        write_new_private_file(
            &candidate.path().join(FINAL_BUCKETS_FILE),
            &desired.final_bucket_bytes,
            MAX_FINAL_BUCKET_FRAME_BYTES,
        )?;
        write_new_private_file(
            &candidate.path().join(STATE_FILE),
            &desired.state_bytes,
            MAX_STATE_BYTES,
        )?;
        let candidate_temp = candidate.path().join(ACTIVE_TEMP_DIR);
        create_private_directory(&candidate_temp)?;
        validate_directory_is_empty(&candidate_temp)?;
        validate_active_entry_set(candidate.path())?;
        sync_private_directory(&candidate_temp).map_err(|_| PrivateOramOwnerJournalError::Io)?;
        sync_private_directory(candidate.path()).map_err(|_| PrivateOramOwnerJournalError::Io)?;
        let candidate_file = open_private_directory(candidate.path())?;

        validate_open_directory_at_path(&root_file, &self.root)?;
        let candidate_name = candidate
            .path()
            .file_name()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        match rename_directory_noreplace(&root_file, candidate_name, OsStr::new(ACTIVE_DIR)) {
            Ok(()) => {
                validate_open_directory_at_path(&root_file, &self.root)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let installed = self
                    .load_active_structural_from(&root_file, true, Some(&candidate_file))
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                if !installed.exactly_matches(&desired) {
                    return Err(PrivateOramOwnerJournalError::Indeterminate);
                }
                Ok(installed.into_output())
            }
            Err(PrivateOramOwnerJournalError::ConcurrentMutation) => {
                validate_open_directory_at_path(&root_file, &self.root)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let existing = self.load_active_structural_from(&root_file, true, None)?;
                if !existing.exactly_matches(&desired) {
                    return Err(PrivateOramOwnerJournalError::ConcurrentMutation);
                }
                Ok(existing.into_output())
            }
            Err(error) => Err(error),
        }
    }

    fn record_terminal(
        &self,
        transition: TerminalTransition<'_>,
    ) -> Result<ValidatedOwnerJournal, PrivateOramOwnerJournalError> {
        #[cfg(not(target_os = "linux"))]
        ensure_supported_platform()?;
        validate_digest(
            transition.expected_journal_descriptor_digest,
            "expected_journal_descriptor_digest",
        )?;
        validate_digest(
            transition.parent_descriptor_digest,
            "parent_descriptor_digest",
        )?;
        validate_digest(
            transition.consensus_authority_record_digest,
            "consensus_authority_record_digest",
        )?;
        validate_digest(
            transition.reconciliation_authority_digest,
            "reconciliation_authority_digest",
        )?;
        if transition.phase == PrivateOramOwnerJournalPhaseV1::Prepared
            || !path_entry_exists(&self.root)?
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }

        let root = open_private_directory(&self.root)?;
        let _root_lock = lock_private_journal_root(&root)?;
        if Self::stable_root_entry_from(&root)? != StableRootEntry::Active {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let current = self.load_active_structural_from(&root, true, None)?;
        if current.snapshot.descriptor.descriptor_digest
            != transition.expected_journal_descriptor_digest
            || current.snapshot.descriptor.parent_descriptor_digest
                != transition.parent_descriptor_digest
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        let desired_terminal = build_terminal_record(&current.snapshot, transition)?;
        let desired_terminal_bytes = encode_terminal_record(&desired_terminal)?;
        if let Some(existing) = current.snapshot.terminal.as_ref() {
            if existing != &desired_terminal
                || current.terminal_bytes.as_deref() != Some(desired_terminal_bytes.as_slice())
            {
                return Err(PrivateOramOwnerJournalError::InvalidTransition);
            }
            sync_open_directory(&root)
                .and_then(|()| validate_open_directory_at_path(&root, &self.root))
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            return Ok(current);
        }

        let active_path = open_directory_entry_path(&root, OsStr::new(ACTIVE_DIR))?;
        let active = open_private_directory(&active_path)?;
        let temp_path = open_directory_entry_path(&active, OsStr::new(ACTIVE_TEMP_DIR))?;
        let temp = open_private_directory(&temp_path)?;
        validate_terminal_temp_entries_open(&temp)?;
        let candidate = tempfile::Builder::new()
            .prefix(TERMINAL_CANDIDATE_PREFIX)
            .tempdir_in(&temp_path)
            .map_err(|_| PrivateOramOwnerJournalError::Io)?;
        set_private_directory_permissions(candidate.path())?;
        validate_private_directory_exact(candidate.path())?;
        write_new_private_file(
            &candidate.path().join(TERMINAL_RECORD_FILE),
            &desired_terminal_bytes,
            MAX_TERMINAL_RECORD_BYTES,
        )?;
        validate_terminal_entry_set(candidate.path())?;
        sync_private_directory(candidate.path()).map_err(|_| PrivateOramOwnerJournalError::Io)?;
        let candidate_directory = open_private_directory(candidate.path())?;
        sync_open_directory(&temp).map_err(|_| PrivateOramOwnerJournalError::Io)?;

        validate_open_directory_at_path(&root, &self.root)?;
        validate_open_directory_at_path(&active, &active_path)?;
        validate_open_directory_at_path(&temp, &temp_path)?;
        let candidate_name = candidate
            .path()
            .file_name()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        match rename_entry_noreplace(&temp, candidate_name, &active, OsStr::new(TERMINAL_DIR)) {
            Ok(()) => {
                let installed_terminal_path =
                    open_directory_entry_path(&active, OsStr::new(TERMINAL_DIR))
                        .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let installed_terminal = open_private_directory(&installed_terminal_path)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                ensure_same_open_inode(&candidate_directory, &installed_terminal)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                let installed = self
                    .load_active_structural_from(&root, true, None)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                ensure_same_open_inode(&candidate_directory, &installed_terminal)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
                if installed.snapshot.terminal.as_ref() != Some(&desired_terminal)
                    || installed.terminal_bytes.as_deref()
                        != Some(desired_terminal_bytes.as_slice())
                {
                    return Err(PrivateOramOwnerJournalError::Indeterminate);
                }
                Ok(installed)
            }
            Err(PrivateOramOwnerJournalError::ConcurrentMutation) => {
                let existing = self.load_active_structural_from(&root, true, None)?;
                if existing.snapshot.terminal.as_ref() != Some(&desired_terminal)
                    || existing.terminal_bytes.as_deref() != Some(desired_terminal_bytes.as_slice())
                {
                    return Err(PrivateOramOwnerJournalError::InvalidTransition);
                }
                Ok(existing)
            }
            Err(error) => Err(error),
        }
    }

    fn ensure_root(&self) -> Result<File, PrivateOramOwnerJournalError> {
        let parent = self
            .root
            .parent()
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        let parent_file = open_private_directory(parent)?;
        let anchored_root =
            open_directory_entry_path(&parent_file, OsStr::new(PRIVATE_ORAM_OWNER_JOURNAL_DIR))?;
        create_private_directory(&anchored_root)?;
        sync_open_directory(&parent_file).map_err(|_| PrivateOramOwnerJournalError::Io)?;
        validate_open_directory_at_path(&parent_file, parent)?;
        let root_file = open_private_directory(&anchored_root)?;
        validate_open_directory_at_path(&root_file, &self.root)?;
        Ok(root_file)
    }

    fn stable_root_entry_from(
        root: &File,
    ) -> Result<StableRootEntry, PrivateOramOwnerJournalError> {
        let mut has_active = false;
        for name in directory_entry_names_open(root)? {
            if name == OsStr::new(ACTIVE_DIR) {
                has_active = true;
            } else if is_candidate_name(&name) {
                // Stranded candidates are preserved for operator inspection but are never
                // adopted as canonical state.
                validate_private_directory_exact(&open_directory_entry_path(root, &name)?)?;
            } else {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
        }
        Ok(if has_active {
            StableRootEntry::Active
        } else {
            StableRootEntry::Empty
        })
    }

    fn load_active_structural_from(
        &self,
        root: &File,
        durably_sync: bool,
        expected_active: Option<&File>,
    ) -> Result<ValidatedOwnerJournal, PrivateOramOwnerJournalError> {
        let active_path = open_directory_entry_path(root, OsStr::new(ACTIVE_DIR))?;
        let active = open_private_directory(&active_path)?;
        if let Some(expected_active) = expected_active {
            ensure_same_open_inode(expected_active, &active)?;
        }
        let has_terminal = validate_active_entry_set_open(&active)?;
        let temp_path = open_directory_entry_path(&active, OsStr::new(ACTIVE_TEMP_DIR))?;
        let temp = open_private_directory(&temp_path)?;
        validate_terminal_temp_entries_open(&temp)?;

        let (mut descriptor_file, descriptor_bytes) = read_private_file_pinned(
            &open_directory_entry_path(&active, OsStr::new(DESCRIPTOR_FILE))?,
            MAX_DESCRIPTOR_BYTES,
        )?;
        let (mut final_bucket_file, final_bucket_bytes) = read_private_file_pinned(
            &open_directory_entry_path(&active, OsStr::new(FINAL_BUCKETS_FILE))?,
            MAX_FINAL_BUCKET_FRAME_BYTES,
        )?;
        let (mut state_file, state_bytes) = read_private_file_pinned(
            &open_directory_entry_path(&active, OsStr::new(STATE_FILE))?,
            MAX_STATE_BYTES,
        )?;
        let (mut terminal_file, terminal_bytes, terminal_directory, terminal_path) = if has_terminal
        {
            let terminal_path = open_directory_entry_path(&active, OsStr::new(TERMINAL_DIR))?;
            let terminal_directory = open_private_directory(&terminal_path)?;
            validate_terminal_entry_set_open(&terminal_directory)?;
            let (terminal_file, terminal_bytes) = read_private_file_pinned(
                &open_directory_entry_path(&terminal_directory, OsStr::new(TERMINAL_RECORD_FILE))?,
                MAX_TERMINAL_RECORD_BYTES,
            )?;
            (
                Some(terminal_file),
                Some(terminal_bytes),
                Some(terminal_directory),
                Some(terminal_path),
            )
        } else {
            (None, None, None, None)
        };

        let validated = ValidatedOwnerJournal::decode(
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes,
        )?;
        if durably_sync {
            descriptor_file.sync()?;
            final_bucket_file.sync()?;
            state_file.sync()?;
            if let Some(terminal_file) = terminal_file.as_ref() {
                terminal_file.sync()?;
            }
            if let Some(terminal_directory) = terminal_directory.as_ref() {
                sync_open_directory(terminal_directory)
                    .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            }
            sync_open_directory(&temp).map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            sync_open_directory(&active)
                .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
            sync_open_directory(root).map_err(|_| PrivateOramOwnerJournalError::Indeterminate)?;
        }

        if validate_active_entry_set_open(&active)? != has_terminal {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        validate_terminal_temp_entries_open(&temp)?;
        descriptor_file.validate_exact_contents(&validated.descriptor_bytes)?;
        final_bucket_file.validate_exact_contents(&validated.final_bucket_bytes)?;
        state_file.validate_exact_contents(&validated.state_bytes)?;
        if let (Some(terminal_file), Some(terminal_bytes)) =
            (terminal_file.as_mut(), validated.terminal_bytes.as_deref())
        {
            terminal_file.validate_exact_contents(terminal_bytes)?;
        }
        descriptor_file.validate_at_path()?;
        final_bucket_file.validate_at_path()?;
        state_file.validate_at_path()?;
        if let Some(terminal_file) = terminal_file.as_ref() {
            terminal_file.validate_at_path()?;
        }
        validate_open_directory_at_path(&temp, &temp_path)?;
        if let (Some(terminal_directory), Some(terminal_path)) =
            (terminal_directory.as_ref(), terminal_path.as_ref())
        {
            validate_terminal_entry_set_open(terminal_directory)?;
            validate_open_directory_at_path(terminal_directory, terminal_path)?;
        }
        validate_open_directory_at_path(&active, &active_path)?;
        if let Some(expected_active) = expected_active {
            ensure_same_open_inode(expected_active, &active)?;
        }
        if Self::stable_root_entry_from(root)? != StableRootEntry::Active {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        validate_open_directory_at_path(root, &self.root)?;
        Ok(validated)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StableRootEntry {
    Empty,
    Active,
}

#[derive(Clone, Copy)]
struct TerminalTransition<'a> {
    phase: PrivateOramOwnerJournalPhaseV1,
    expected_journal_descriptor_digest: &'a str,
    parent_descriptor_digest: &'a str,
    authenticated_owner_peer_id: u64,
    consensus_authority_record_digest: &'a str,
    reconciliation_authority_digest: &'a str,
    canonical_index_states: &'a [PrivateOramOwnerJournalTerminalIndexStateV1],
}

#[derive(Clone)]
struct ValidatedOwnerJournal {
    snapshot: PrivateOramOwnerJournalSnapshotV1,
    descriptor_bytes: Vec<u8>,
    final_bucket_bytes: Vec<u8>,
    state_bytes: Vec<u8>,
    terminal_bytes: Option<Vec<u8>>,
}

impl ValidatedOwnerJournal {
    fn build(
        validated: &PrivateOramValidatedOwnerPrepareV1,
        context: PrivateOramOwnerJournalPrepareContextV1<'_>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        validate_digest(context.parent_descriptor_digest, "parent_descriptor_digest")?;
        validate_digest(
            context.parent_lease_acquired_record_digest,
            "parent_lease_acquired_record_digest",
        )?;
        let mutation = &validated.mutation_bundle().mutation;
        validate_digest(validated.mutation_digest(), "signed_mutation_digest")?;
        validate_digest(&mutation.mutation_id, "mutation_id")?;
        validate_digest(&mutation.writer_lease_digest, "writer_lease_digest")?;
        validate_resource_id(&mutation.collection_id, "collection_id")?;
        if validated.indexes().is_empty()
            || validated.indexes().len() > MAX_PAIRED_OWNER_INDEXES
            || validated.indexes().len() != context.requirements.len()
            || validated.indexes()[0].kind() != PrivateOramIndexKindV2::Hnsw
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput("indexes"));
        }

        let mut names = BTreeSet::new();
        let mut saw_result = false;
        let mut total_ordered_bucket_refs = 0usize;
        let mut indexes = Vec::with_capacity(validated.indexes().len());
        let mut final_buckets = Vec::with_capacity(validated.indexes().len());
        for (index, requirement) in validated.indexes().iter().zip(context.requirements) {
            validate_resource_id(index.index_name(), "index_name")?;
            if !names.insert(index.index_name().to_string())
                || index.kind() != requirement.kind
                || index.index_name() != requirement.index_name
                || index.old_epoch() != requirement.old_epoch
                || index.new_epoch() != requirement.new_epoch
                || index.old_root_hash() != requirement.old_root_hash
                || index.new_root_hash() != requirement.new_root_hash
                || index.writeback_digest() != requirement.writeback_digest
            {
                return Err(PrivateOramOwnerJournalError::InvalidInput("requirements"));
            }
            match index.kind() {
                PrivateOramIndexKindV2::Hnsw if indexes.is_empty() => {}
                PrivateOramIndexKindV2::Result if !saw_result => saw_result = true,
                _ => return Err(PrivateOramOwnerJournalError::InvalidInput("indexes")),
            }
            total_ordered_bucket_refs = total_ordered_bucket_refs
                .checked_add(index.ordered_bucket_refs().len())
                .ok_or(PrivateOramOwnerJournalError::InvalidInput(
                    "ordered_bucket_refs",
                ))?;
            if index.ordered_bucket_refs().is_empty()
                || index.final_bucket_refs().is_empty()
                || index.final_bucket_refs().len() > index.ordered_bucket_refs().len()
                || index
                    .final_bucket_refs()
                    .windows(2)
                    .any(|pair| pair[0].bucket_id >= pair[1].bucket_id)
            {
                return Err(PrivateOramOwnerJournalError::InvalidInput("bucket_refs"));
            }
            validate_digest(index.old_root_hash(), "old_root_hash")?;
            validate_digest(index.new_root_hash(), "new_root_hash")?;
            validate_digest(index.writeback_digest(), "writeback_digest")?;
            validate_digest(
                &index.read_transcript().transcript_digest,
                "read_transcript_digest",
            )?;
            for bucket in index
                .ordered_bucket_refs()
                .iter()
                .chain(index.final_bucket_refs())
            {
                validate_bucket_ref(bucket)?;
            }
            indexes.push(PrivateOramOwnerJournalIndexDescriptorV1 {
                kind: index.kind(),
                index_name: index.index_name().to_string(),
                old_epoch: index.old_epoch(),
                new_epoch: index.new_epoch(),
                old_root_hash: index.old_root_hash().to_string(),
                new_root_hash: index.new_root_hash().to_string(),
                writeback_digest: index.writeback_digest().to_string(),
                read_path_count: index.read_transcript().read_path_count,
                read_transcript_digest: index.read_transcript().transcript_digest.clone(),
                ordered_bucket_refs: index.ordered_bucket_refs().to_vec(),
                final_bucket_refs: index.final_bucket_refs().to_vec(),
            });
            final_buckets.push(PrivateOramOwnerFinalBucketIndexV1 {
                index_name: index.index_name().to_string(),
                buckets: match index.final_buckets() {
                    PrivateOramValidatedOwnerFinalBucketsV1::Hnsw(buckets) => {
                        PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets.clone())
                    }
                    PrivateOramValidatedOwnerFinalBucketsV1::Result(buckets) => {
                        PrivateOramOwnerFinalBucketBatchV1::Result(buckets.clone())
                    }
                },
            });
        }
        if total_ordered_bucket_refs == 0
            || total_ordered_bucket_refs > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS
        {
            return Err(PrivateOramOwnerJournalError::InvalidInput(
                "ordered_bucket_refs",
            ));
        }

        let final_bucket_bytes = encode_final_bucket_frame(&indexes, &final_buckets)?;
        let mut descriptor = PrivateOramOwnerJournalDescriptorV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION,
            parent_descriptor_digest: context.parent_descriptor_digest.to_string(),
            parent_lease_acquired_record_digest: context
                .parent_lease_acquired_record_digest
                .to_string(),
            owner_peer_id: context.owner_peer_id,
            collection_id: mutation.collection_id.clone(),
            mutation_id: mutation.mutation_id.clone(),
            signed_mutation_digest: validated.mutation_digest().to_string(),
            writer_lease_digest: mutation.writer_lease_digest.clone(),
            writer_fence: mutation.writer_fence,
            indexes,
            final_bucket_frame_version: PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION,
            final_bucket_frame_length: u64::try_from(final_bucket_bytes.len()).map_err(|_| {
                PrivateOramOwnerJournalError::InvalidInput("final_bucket_frame_length")
            })?,
            final_bucket_frame_sha256: digest_string(&final_bucket_bytes),
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor_digest(&descriptor)?;
        let descriptor_bytes = encode_descriptor(&descriptor)?;

        let mut state = PrivateOramOwnerJournalStateV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION,
            sequence: 1,
            descriptor_digest: descriptor.descriptor_digest.clone(),
            previous_record_digest: None,
            phase: PrivateOramOwnerJournalPhaseV1::Prepared,
            state_digest: String::new(),
        };
        state.state_digest = state_digest(&state)?;
        let state_bytes = encode_state(&state)?;

        let snapshot = PrivateOramOwnerJournalSnapshotV1 {
            descriptor,
            state,
            terminal: None,
            final_buckets,
        };
        validate_snapshot(&snapshot, &final_bucket_bytes)?;
        Ok(Self {
            snapshot,
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes: None,
        })
    }

    fn decode(
        descriptor_bytes: Vec<u8>,
        final_bucket_bytes: Vec<u8>,
        state_bytes: Vec<u8>,
        terminal_bytes: Option<Vec<u8>>,
    ) -> Result<Self, PrivateOramOwnerJournalError> {
        let descriptor = decode_descriptor(&descriptor_bytes)?;
        let final_buckets = decode_final_bucket_frame(&descriptor.indexes, &final_bucket_bytes)?;
        let state = decode_state(&state_bytes)?;
        let terminal = terminal_bytes
            .as_deref()
            .map(decode_terminal_record)
            .transpose()?;
        let snapshot = PrivateOramOwnerJournalSnapshotV1 {
            descriptor,
            state,
            terminal,
            final_buckets,
        };
        validate_snapshot(&snapshot, &final_bucket_bytes)?;
        Ok(Self {
            snapshot,
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes,
        })
    }

    fn exactly_matches(&self, other: &Self) -> bool {
        self.descriptor_bytes == other.descriptor_bytes
            && self.final_bucket_bytes == other.final_bucket_bytes
            && self.state_bytes == other.state_bytes
            && self.terminal_bytes == other.terminal_bytes
    }

    fn into_output(
        self,
    ) -> (
        PrivateOramOwnerJournalSnapshotV1,
        PrivateOramDurableOwnerPreparedTokenV1,
    ) {
        assert!(self.snapshot.terminal.is_none());
        let token = prepared_token(&self.snapshot.descriptor)
            .expect("decoded owner journal descriptor must produce prepared evidence");
        (self.snapshot, token)
    }
}

fn validate_snapshot(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
    final_bucket_bytes: &[u8],
) -> Result<(), PrivateOramOwnerJournalError> {
    if snapshot.state.version != PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION
        || snapshot.state.sequence != 1
        || snapshot.state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || snapshot.state.previous_record_digest.is_some()
        || snapshot.state.descriptor_digest != snapshot.descriptor.descriptor_digest
        || snapshot.descriptor.final_bucket_frame_version
            != PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION
        || snapshot.descriptor.final_bucket_frame_length
            != u64::try_from(final_bucket_bytes.len())
                .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?
        || snapshot.descriptor.final_bucket_frame_sha256 != digest_string(final_bucket_bytes)
        || snapshot.descriptor.indexes.len() != snapshot.final_buckets.len()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    for (index, final_index) in snapshot
        .descriptor
        .indexes
        .iter()
        .zip(&snapshot.final_buckets)
    {
        if index.kind != final_index.buckets.kind()
            || index.index_name != final_index.index_name
            || index.final_bucket_refs != final_bucket_refs(&final_index.buckets)
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    if let Some(terminal) = snapshot.terminal.as_ref() {
        if terminal.version != PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION
            || terminal.sequence != 2
            || terminal.phase == PrivateOramOwnerJournalPhaseV1::Prepared
            || terminal.descriptor_digest != snapshot.descriptor.descriptor_digest
            || terminal.previous_record_digest != snapshot.state.state_digest
            || terminal.parent_descriptor_digest != snapshot.descriptor.parent_descriptor_digest
            || terminal.authenticated_owner_peer_id != snapshot.descriptor.owner_peer_id
            || terminal.canonical_index_states.len() != snapshot.descriptor.indexes.len()
            || terminal_record_digest(terminal)? != terminal.record_digest
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        for (index, canonical) in snapshot
            .descriptor
            .indexes
            .iter()
            .zip(&terminal.canonical_index_states)
        {
            if index.kind != canonical.kind
                || index.index_name != canonical.index_name
                || validate_digest(&canonical.canonical_state_digest, "canonical_state_digest")
                    .is_err()
            {
                return Err(PrivateOramOwnerJournalError::Corrupt);
            }
        }
    }
    Ok(())
}

fn prepared_token(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
) -> Result<PrivateOramDurableOwnerPreparedTokenV1, PrivateOramOwnerJournalError> {
    let indexes = descriptor
        .indexes
        .iter()
        .map(|index| {
            Ok(PrivateOramOwnerPreparedIndexEvidenceV1 {
                kind: index.kind,
                index_name: index.index_name.clone(),
                prepared_journal_digest: index_prepared_evidence_digest(descriptor, index)?,
            })
        })
        .collect::<Result<Vec<_>, PrivateOramOwnerJournalError>>()?;
    Ok(PrivateOramDurableOwnerPreparedTokenV1 {
        owner_peer_id: descriptor.owner_peer_id,
        journal_descriptor_digest: descriptor.descriptor_digest.clone(),
        parent_descriptor_digest: descriptor.parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: descriptor.parent_lease_acquired_record_digest.clone(),
        indexes,
    })
}

fn prepared_store_binding(
    snapshot: PrivateOramOwnerJournalSnapshotV1,
    prepared: &PrivateOramDurableOwnerPreparedTokenV1,
) -> Result<PrivateOramOwnerPreparedStoreBindingV1, PrivateOramOwnerJournalError> {
    if snapshot.terminal.is_some()
        || snapshot.state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || prepared_token(&snapshot.descriptor)? != *prepared
    {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }
    Ok(PrivateOramOwnerPreparedStoreBindingV1 { snapshot })
}

fn recovery_prepared_binding<'lock>(
    snapshot: PrivateOramOwnerJournalSnapshotV1,
    projection: &PrivateOramOwnerRecoveryProjectionV1,
    _root_lock: &'lock PrivateJournalRootLock<'_>,
) -> Result<PrivateOramOwnerRecoveryPreparedBindingV1<'lock>, PrivateOramOwnerJournalError> {
    let descriptor = &snapshot.descriptor;
    if snapshot.terminal.is_some()
        || snapshot.state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || descriptor.indexes.len() != MAX_PAIRED_OWNER_INDEXES
        || descriptor.indexes[0].kind != PrivateOramIndexKindV2::Hnsw
        || descriptor.indexes[1].kind != PrivateOramIndexKindV2::Result
        || descriptor.owner_peer_id != projection.expected_owner_peer_id
        || descriptor.parent_descriptor_digest != projection.parent_descriptor_digest
        || descriptor.parent_lease_acquired_record_digest
            != projection.parent_lease_acquired_record_digest
        || descriptor.collection_id != projection.collection_id
        || descriptor.mutation_id != projection.mutation_id
        || descriptor.signed_mutation_digest != projection.signed_mutation_digest
        || descriptor.writer_lease_digest != projection.writer_lease_digest
        || descriptor.writer_fence != projection.writer_fence
        || descriptor.indexes.len() != projection.indexes.len()
    {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }

    let prepared = prepared_token(descriptor)?;
    for ((descriptor_index, prepared_index), projected_index) in descriptor
        .indexes
        .iter()
        .zip(prepared.indexes())
        .zip(&projection.indexes)
    {
        if descriptor_index.kind != projected_index.kind
            || descriptor_index.index_name != projected_index.index_name
            || descriptor_index.old_epoch != projected_index.old_epoch
            || descriptor_index.new_epoch != projected_index.new_epoch
            || descriptor_index.old_root_hash != projected_index.old_root_hash
            || descriptor_index.new_root_hash != projected_index.new_root_hash
            || descriptor_index.writeback_digest != projected_index.writeback_digest
            || prepared_index.kind != projected_index.kind
            || prepared_index.index_name != projected_index.index_name
            || prepared_index.prepared_journal_digest != projected_index.prepared_journal_digest
        {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
    }

    let store_binding = prepared_store_binding(snapshot, &prepared)?;
    Ok(PrivateOramOwnerRecoveryPreparedBindingV1 {
        prepared,
        store_binding,
        lock_lifetime: PhantomData,
    })
}

fn index_prepared_evidence_digest(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
    index: &PrivateOramOwnerJournalIndexDescriptorV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    let mut bytes = Vec::with_capacity(512);
    push_domain(&mut bytes, INDEX_PREPARED_EVIDENCE_DOMAIN)?;
    push_digest(
        &mut bytes,
        &descriptor.descriptor_digest,
        "descriptor_digest",
    )?;
    bytes.extend_from_slice(&descriptor.owner_peer_id.to_be_bytes());
    bytes.push(kind_tag(index.kind));
    push_resource_id(&mut bytes, &index.index_name, "index_name")?;
    bytes.extend_from_slice(&index.old_epoch.to_be_bytes());
    bytes.extend_from_slice(&index.new_epoch.to_be_bytes());
    push_digest(&mut bytes, &index.old_root_hash, "old_root_hash")?;
    push_digest(&mut bytes, &index.new_root_hash, "new_root_hash")?;
    push_digest(&mut bytes, &index.writeback_digest, "writeback_digest")?;
    Ok(digest_string(&bytes))
}

fn build_terminal_record(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
    transition: TerminalTransition<'_>,
) -> Result<PrivateOramOwnerJournalTerminalRecordV1, PrivateOramOwnerJournalError> {
    if snapshot.state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || transition.phase == PrivateOramOwnerJournalPhaseV1::Prepared
        || snapshot.descriptor.descriptor_digest != transition.expected_journal_descriptor_digest
        || snapshot.descriptor.parent_descriptor_digest != transition.parent_descriptor_digest
        || snapshot.descriptor.owner_peer_id != transition.authenticated_owner_peer_id
        || snapshot.descriptor.indexes.len() != transition.canonical_index_states.len()
    {
        return Err(PrivateOramOwnerJournalError::InvalidTransition);
    }
    for (index, canonical) in snapshot
        .descriptor
        .indexes
        .iter()
        .zip(transition.canonical_index_states)
    {
        if index.kind != canonical.kind || index.index_name != canonical.index_name {
            return Err(PrivateOramOwnerJournalError::InvalidTransition);
        }
        validate_digest(&canonical.canonical_state_digest, "canonical_state_digest")?;
    }
    let mut record = PrivateOramOwnerJournalTerminalRecordV1 {
        version: PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION,
        sequence: 2,
        descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        previous_record_digest: snapshot.state.state_digest.clone(),
        phase: transition.phase,
        parent_descriptor_digest: transition.parent_descriptor_digest.to_string(),
        authenticated_owner_peer_id: transition.authenticated_owner_peer_id,
        consensus_authority_record_digest: transition.consensus_authority_record_digest.to_string(),
        reconciliation_authority_digest: transition.reconciliation_authority_digest.to_string(),
        canonical_index_states: transition.canonical_index_states.to_vec(),
        record_digest: String::new(),
    };
    record.record_digest = terminal_record_digest(&record)?;
    Ok(record)
}

fn finalized_token(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
) -> Result<PrivateOramDurableOwnerFinalizedTokenV1, PrivateOramOwnerJournalError> {
    let terminal = snapshot
        .terminal
        .as_ref()
        .filter(|terminal| terminal.phase == PrivateOramOwnerJournalPhaseV1::Finalized)
        .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
    let indexes = snapshot
        .descriptor
        .indexes
        .iter()
        .map(|index| {
            Ok(PrivateOramOwnerFinalizedIndexEvidenceV1 {
                kind: index.kind,
                index_name: index.index_name.clone(),
                prepared_journal_digest: index_prepared_evidence_digest(
                    &snapshot.descriptor,
                    index,
                )?,
                finalized_state_digest: index_terminal_evidence_digest(snapshot, terminal, index)?,
            })
        })
        .collect::<Result<Vec<_>, PrivateOramOwnerJournalError>>()?;
    Ok(PrivateOramDurableOwnerFinalizedTokenV1 {
        owner_peer_id: snapshot.descriptor.owner_peer_id,
        journal_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        prepared_state_digest: snapshot.state.state_digest.clone(),
        terminal_record_digest: terminal.record_digest.clone(),
        parent_descriptor_digest: terminal.parent_descriptor_digest.clone(),
        consensus_authority_record_digest: terminal.consensus_authority_record_digest.clone(),
        reconciliation_authority_digest: terminal.reconciliation_authority_digest.clone(),
        indexes,
    })
}

fn aborted_old_token(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
) -> Result<PrivateOramDurableOwnerAbortedOldTokenV1, PrivateOramOwnerJournalError> {
    let terminal = snapshot
        .terminal
        .as_ref()
        .filter(|terminal| terminal.phase == PrivateOramOwnerJournalPhaseV1::AbortedOld)
        .ok_or(PrivateOramOwnerJournalError::InvalidTransition)?;
    let indexes = snapshot
        .descriptor
        .indexes
        .iter()
        .map(|index| {
            Ok(PrivateOramOwnerAbortedOldIndexEvidenceV1 {
                kind: index.kind,
                index_name: index.index_name.clone(),
                prepared_journal_digest: index_prepared_evidence_digest(
                    &snapshot.descriptor,
                    index,
                )?,
                aborted_old_state_digest: index_terminal_evidence_digest(
                    snapshot, terminal, index,
                )?,
            })
        })
        .collect::<Result<Vec<_>, PrivateOramOwnerJournalError>>()?;
    Ok(PrivateOramDurableOwnerAbortedOldTokenV1 {
        owner_peer_id: snapshot.descriptor.owner_peer_id,
        journal_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        prepared_state_digest: snapshot.state.state_digest.clone(),
        terminal_record_digest: terminal.record_digest.clone(),
        parent_descriptor_digest: terminal.parent_descriptor_digest.clone(),
        consensus_authority_record_digest: terminal.consensus_authority_record_digest.clone(),
        reconciliation_authority_digest: terminal.reconciliation_authority_digest.clone(),
        indexes,
    })
}

fn index_terminal_evidence_digest(
    snapshot: &PrivateOramOwnerJournalSnapshotV1,
    terminal: &PrivateOramOwnerJournalTerminalRecordV1,
    index: &PrivateOramOwnerJournalIndexDescriptorV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    let domain = match terminal.phase {
        PrivateOramOwnerJournalPhaseV1::Finalized => INDEX_FINALIZED_EVIDENCE_DOMAIN,
        PrivateOramOwnerJournalPhaseV1::AbortedOld => INDEX_ABORTED_OLD_EVIDENCE_DOMAIN,
        PrivateOramOwnerJournalPhaseV1::Prepared => {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    };
    let canonical = terminal
        .canonical_index_states
        .iter()
        .find(|canonical| canonical.kind == index.kind && canonical.index_name == index.index_name)
        .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
    let mut bytes = Vec::with_capacity(1024);
    push_domain(&mut bytes, domain)?;
    push_digest(
        &mut bytes,
        &snapshot.descriptor.descriptor_digest,
        "descriptor_digest",
    )?;
    push_digest(
        &mut bytes,
        &snapshot.state.state_digest,
        "prepared_state_digest",
    )?;
    push_digest(
        &mut bytes,
        &terminal.record_digest,
        "terminal_record_digest",
    )?;
    bytes.extend_from_slice(&snapshot.descriptor.owner_peer_id.to_be_bytes());
    bytes.push(kind_tag(index.kind));
    push_resource_id(&mut bytes, &index.index_name, "index_name")?;
    bytes.extend_from_slice(&index.old_epoch.to_be_bytes());
    bytes.extend_from_slice(&index.new_epoch.to_be_bytes());
    push_digest(&mut bytes, &index.old_root_hash, "old_root_hash")?;
    push_digest(&mut bytes, &index.new_root_hash, "new_root_hash")?;
    push_digest(&mut bytes, &index.writeback_digest, "writeback_digest")?;
    push_bucket_refs(&mut bytes, &index.final_bucket_refs)?;
    push_digest(
        &mut bytes,
        &canonical.canonical_state_digest,
        "canonical_state_digest",
    )?;
    Ok(digest_string(&bytes))
}

fn descriptor_digest(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    Ok(digest_string(&descriptor_body(descriptor)?))
}

fn encode_descriptor(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    let mut bytes = descriptor_body(descriptor)?;
    if descriptor.descriptor_digest != digest_string(&bytes) {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    push_digest(
        &mut bytes,
        &descriptor.descriptor_digest,
        "descriptor_digest",
    )?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn descriptor_body(
    descriptor: &PrivateOramOwnerJournalDescriptorV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    if descriptor.version != PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION
        || descriptor.indexes.is_empty()
        || descriptor.indexes.len() > MAX_PAIRED_OWNER_INDEXES
        || descriptor.final_bucket_frame_version != PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION
        || descriptor.final_bucket_frame_length == 0
        || descriptor.final_bucket_frame_length > MAX_FINAL_BUCKET_FRAME_BYTES
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(4096);
    push_domain(&mut bytes, DESCRIPTOR_DOMAIN)?;
    bytes.extend_from_slice(&descriptor.version.to_be_bytes());
    push_digest(
        &mut bytes,
        &descriptor.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    push_digest(
        &mut bytes,
        &descriptor.parent_lease_acquired_record_digest,
        "parent_lease_acquired_record_digest",
    )?;
    bytes.extend_from_slice(&descriptor.owner_peer_id.to_be_bytes());
    push_resource_id(&mut bytes, &descriptor.collection_id, "collection_id")?;
    push_digest(&mut bytes, &descriptor.mutation_id, "mutation_id")?;
    push_digest(
        &mut bytes,
        &descriptor.signed_mutation_digest,
        "signed_mutation_digest",
    )?;
    push_digest(
        &mut bytes,
        &descriptor.writer_lease_digest,
        "writer_lease_digest",
    )?;
    bytes.extend_from_slice(&descriptor.writer_fence.to_be_bytes());
    push_len(&mut bytes, descriptor.indexes.len(), "indexes")?;
    let mut names = BTreeSet::new();
    let mut total_ordered = 0usize;
    for (ordinal, index) in descriptor.indexes.iter().enumerate() {
        if !names.insert(index.index_name.as_str())
            || (ordinal == 0 && index.kind != PrivateOramIndexKindV2::Hnsw)
            || (ordinal > 0 && index.kind != PrivateOramIndexKindV2::Result)
            || index.old_epoch.checked_add(1) != Some(index.new_epoch)
            || index.old_root_hash == index.new_root_hash
            || index.read_path_count == 0
            || index.ordered_bucket_refs.is_empty()
            || index.final_bucket_refs.is_empty()
            || index.final_bucket_refs.len() > index.ordered_bucket_refs.len()
            || index
                .final_bucket_refs
                .windows(2)
                .any(|pair| pair[0].bucket_id >= pair[1].bucket_id)
            || collapse_ordered_bucket_refs(&index.ordered_bucket_refs) != index.final_bucket_refs
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        total_ordered = total_ordered
            .checked_add(index.ordered_bucket_refs.len())
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        bytes.push(kind_tag(index.kind));
        push_resource_id(&mut bytes, &index.index_name, "index_name")?;
        bytes.extend_from_slice(&index.old_epoch.to_be_bytes());
        bytes.extend_from_slice(&index.new_epoch.to_be_bytes());
        push_digest(&mut bytes, &index.old_root_hash, "old_root_hash")?;
        push_digest(&mut bytes, &index.new_root_hash, "new_root_hash")?;
        push_digest(&mut bytes, &index.writeback_digest, "writeback_digest")?;
        bytes.extend_from_slice(&index.read_path_count.to_be_bytes());
        push_digest(
            &mut bytes,
            &index.read_transcript_digest,
            "read_transcript_digest",
        )?;
        push_bucket_refs(&mut bytes, &index.ordered_bucket_refs)?;
        push_bucket_refs(&mut bytes, &index.final_bucket_refs)?;
    }
    if total_ordered == 0 || total_ordered > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    bytes.extend_from_slice(&descriptor.final_bucket_frame_version.to_be_bytes());
    bytes.extend_from_slice(&descriptor.final_bucket_frame_length.to_be_bytes());
    push_digest(
        &mut bytes,
        &descriptor.final_bucket_frame_sha256,
        "final_bucket_frame_sha256",
    )?;
    Ok(bytes)
}

fn decode_descriptor(
    bytes: &[u8],
) -> Result<PrivateOramOwnerJournalDescriptorV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    decoder.read_domain(DESCRIPTOR_DOMAIN)?;
    let version = decoder.read_u16()?;
    let parent_descriptor_digest = decoder.read_digest()?;
    let parent_lease_acquired_record_digest = decoder.read_digest()?;
    let owner_peer_id = decoder.read_u64()?;
    let collection_id = decoder.read_resource_id()?;
    let mutation_id = decoder.read_digest()?;
    let signed_mutation_digest = decoder.read_digest()?;
    let writer_lease_digest = decoder.read_digest()?;
    let writer_fence = decoder.read_u64()?;
    let index_count = decoder.read_len(MAX_PAIRED_OWNER_INDEXES)?;
    let mut indexes = Vec::with_capacity(index_count);
    for _ in 0..index_count {
        indexes.push(PrivateOramOwnerJournalIndexDescriptorV1 {
            kind: decoder.read_kind()?,
            index_name: decoder.read_resource_id()?,
            old_epoch: decoder.read_u64()?,
            new_epoch: decoder.read_u64()?,
            old_root_hash: decoder.read_digest()?,
            new_root_hash: decoder.read_digest()?,
            writeback_digest: decoder.read_digest()?,
            read_path_count: decoder.read_u32()?,
            read_transcript_digest: decoder.read_digest()?,
            ordered_bucket_refs: decoder
                .read_bucket_refs(PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS)?,
            final_bucket_refs: decoder
                .read_bucket_refs(PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS)?,
        });
    }
    let final_bucket_frame_version = decoder.read_u16()?;
    let final_bucket_frame_length = decoder.read_u64()?;
    let final_bucket_frame_sha256 = decoder.read_digest()?;
    let descriptor_digest = decoder.read_digest()?;
    if !decoder.is_finished() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let descriptor = PrivateOramOwnerJournalDescriptorV1 {
        version,
        parent_descriptor_digest,
        parent_lease_acquired_record_digest,
        owner_peer_id,
        collection_id,
        mutation_id,
        signed_mutation_digest,
        writer_lease_digest,
        writer_fence,
        indexes,
        final_bucket_frame_version,
        final_bucket_frame_length,
        final_bucket_frame_sha256,
        descriptor_digest,
    };
    if encode_descriptor(&descriptor)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(descriptor)
}

fn state_digest(
    state: &PrivateOramOwnerJournalStateV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    Ok(digest_string(&state_body(state)?))
}

fn encode_state(
    state: &PrivateOramOwnerJournalStateV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    let mut bytes = state_body(state)?;
    if state.state_digest != digest_string(&bytes) {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    push_digest(&mut bytes, &state.state_digest, "state_digest")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn state_body(
    state: &PrivateOramOwnerJournalStateV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    if state.version != PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION
        || state.sequence != 1
        || state.phase != PrivateOramOwnerJournalPhaseV1::Prepared
        || state.previous_record_digest.is_some()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(160);
    push_domain(&mut bytes, STATE_DOMAIN)?;
    bytes.extend_from_slice(&state.version.to_be_bytes());
    bytes.extend_from_slice(&state.sequence.to_be_bytes());
    bytes.push(PREPARED_PHASE_TAG);
    push_digest(&mut bytes, &state.descriptor_digest, "descriptor_digest")?;
    bytes.push(0);
    Ok(bytes)
}

fn decode_state(
    bytes: &[u8],
) -> Result<PrivateOramOwnerJournalStateV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    decoder.read_domain(STATE_DOMAIN)?;
    let version = decoder.read_u16()?;
    let sequence = decoder.read_u64()?;
    let phase = match decoder.read_u8()? {
        PREPARED_PHASE_TAG => PrivateOramOwnerJournalPhaseV1::Prepared,
        _ => return Err(PrivateOramOwnerJournalError::Corrupt),
    };
    let descriptor_digest = decoder.read_digest()?;
    let previous_record_digest = match decoder.read_u8()? {
        0 => None,
        1 => Some(decoder.read_digest()?),
        _ => return Err(PrivateOramOwnerJournalError::Corrupt),
    };
    let state_digest = decoder.read_digest()?;
    if !decoder.is_finished() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let state = PrivateOramOwnerJournalStateV1 {
        version,
        sequence,
        descriptor_digest,
        previous_record_digest,
        phase,
        state_digest,
    };
    if encode_state(&state)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(state)
}

fn terminal_record_digest(
    record: &PrivateOramOwnerJournalTerminalRecordV1,
) -> Result<String, PrivateOramOwnerJournalError> {
    Ok(digest_string(&terminal_record_body(record)?))
}

fn encode_terminal_record(
    record: &PrivateOramOwnerJournalTerminalRecordV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    let mut bytes = terminal_record_body(record)?;
    if record.record_digest != digest_string(&bytes) {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    push_digest(&mut bytes, &record.record_digest, "terminal_record_digest")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_TERMINAL_RECORD_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

fn terminal_record_body(
    record: &PrivateOramOwnerJournalTerminalRecordV1,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    if record.version != PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION || record.sequence != 2 {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    validate_digest(&record.descriptor_digest, "descriptor_digest")?;
    validate_digest(&record.previous_record_digest, "previous_record_digest")?;
    validate_digest(&record.parent_descriptor_digest, "parent_descriptor_digest")?;
    validate_digest(
        &record.consensus_authority_record_digest,
        "consensus_authority_record_digest",
    )?;
    validate_digest(
        &record.reconciliation_authority_digest,
        "reconciliation_authority_digest",
    )?;
    if record.canonical_index_states.is_empty()
        || record.canonical_index_states.len() > MAX_PAIRED_OWNER_INDEXES
        || record.canonical_index_states[0].kind != PrivateOramIndexKindV2::Hnsw
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut names = BTreeSet::new();
    for (position, canonical) in record.canonical_index_states.iter().enumerate() {
        validate_resource_id(&canonical.index_name, "index_name")?;
        validate_digest(&canonical.canonical_state_digest, "canonical_state_digest")?;
        if !names.insert(canonical.index_name.clone()) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        match (position, canonical.kind) {
            (0, PrivateOramIndexKindV2::Hnsw) | (1, PrivateOramIndexKindV2::Result) => {}
            _ => return Err(PrivateOramOwnerJournalError::Corrupt),
        }
    }
    let mut bytes = Vec::with_capacity(512);
    push_domain(&mut bytes, terminal_record_domain(record.phase)?)?;
    bytes.extend_from_slice(&record.version.to_be_bytes());
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    bytes.push(terminal_phase_tag(record.phase)?);
    push_digest(&mut bytes, &record.descriptor_digest, "descriptor_digest")?;
    push_digest(
        &mut bytes,
        &record.previous_record_digest,
        "previous_record_digest",
    )?;
    push_digest(
        &mut bytes,
        &record.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    push_digest(
        &mut bytes,
        &record.consensus_authority_record_digest,
        "consensus_authority_record_digest",
    )?;
    push_digest(
        &mut bytes,
        &record.reconciliation_authority_digest,
        "reconciliation_authority_digest",
    )?;
    bytes.extend_from_slice(&record.authenticated_owner_peer_id.to_be_bytes());
    push_len(
        &mut bytes,
        record.canonical_index_states.len(),
        "canonical_index_states",
    )?;
    for canonical in &record.canonical_index_states {
        bytes.push(kind_tag(canonical.kind));
        push_resource_id(&mut bytes, &canonical.index_name, "index_name")?;
        push_digest(
            &mut bytes,
            &canonical.canonical_state_digest,
            "canonical_state_digest",
        )?;
    }
    Ok(bytes)
}

fn decode_terminal_record(
    bytes: &[u8],
) -> Result<PrivateOramOwnerJournalTerminalRecordV1, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_TERMINAL_RECORD_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    let domain_index =
        decoder.read_domain_choice(&[FINALIZED_STATE_DOMAIN, ABORTED_OLD_STATE_DOMAIN])?;
    let domain_phase = match domain_index {
        0 => PrivateOramOwnerJournalPhaseV1::Finalized,
        1 => PrivateOramOwnerJournalPhaseV1::AbortedOld,
        _ => return Err(PrivateOramOwnerJournalError::Corrupt),
    };
    let version = decoder.read_u16()?;
    let sequence = decoder.read_u64()?;
    let phase = match decoder.read_u8()? {
        FINALIZED_PHASE_TAG => PrivateOramOwnerJournalPhaseV1::Finalized,
        ABORTED_OLD_PHASE_TAG => PrivateOramOwnerJournalPhaseV1::AbortedOld,
        _ => return Err(PrivateOramOwnerJournalError::Corrupt),
    };
    if phase != domain_phase {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let descriptor_digest = decoder.read_digest()?;
    let previous_record_digest = decoder.read_digest()?;
    let parent_descriptor_digest = decoder.read_digest()?;
    let consensus_authority_record_digest = decoder.read_digest()?;
    let reconciliation_authority_digest = decoder.read_digest()?;
    let authenticated_owner_peer_id = decoder.read_u64()?;
    let canonical_index_count = decoder.read_len(MAX_PAIRED_OWNER_INDEXES)?;
    let mut canonical_index_states = Vec::with_capacity(canonical_index_count);
    for _ in 0..canonical_index_count {
        let kind = match decoder.read_u8()? {
            HNSW_KIND_TAG => PrivateOramIndexKindV2::Hnsw,
            RESULT_KIND_TAG => PrivateOramIndexKindV2::Result,
            _ => return Err(PrivateOramOwnerJournalError::Corrupt),
        };
        canonical_index_states.push(PrivateOramOwnerJournalTerminalIndexStateV1 {
            kind,
            index_name: decoder.read_resource_id()?,
            canonical_state_digest: decoder.read_digest()?,
        });
    }
    let record_digest = decoder.read_digest()?;
    if !decoder.is_finished() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let record = PrivateOramOwnerJournalTerminalRecordV1 {
        version,
        sequence,
        descriptor_digest,
        previous_record_digest,
        phase,
        parent_descriptor_digest,
        authenticated_owner_peer_id,
        consensus_authority_record_digest,
        reconciliation_authority_digest,
        canonical_index_states,
        record_digest,
    };
    if encode_terminal_record(&record)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(record)
}

fn terminal_record_domain(
    phase: PrivateOramOwnerJournalPhaseV1,
) -> Result<&'static [u8], PrivateOramOwnerJournalError> {
    match phase {
        PrivateOramOwnerJournalPhaseV1::Finalized => Ok(FINALIZED_STATE_DOMAIN),
        PrivateOramOwnerJournalPhaseV1::AbortedOld => Ok(ABORTED_OLD_STATE_DOMAIN),
        PrivateOramOwnerJournalPhaseV1::Prepared => Err(PrivateOramOwnerJournalError::Corrupt),
    }
}

fn terminal_phase_tag(
    phase: PrivateOramOwnerJournalPhaseV1,
) -> Result<u8, PrivateOramOwnerJournalError> {
    match phase {
        PrivateOramOwnerJournalPhaseV1::Finalized => Ok(FINALIZED_PHASE_TAG),
        PrivateOramOwnerJournalPhaseV1::AbortedOld => Ok(ABORTED_OLD_PHASE_TAG),
        PrivateOramOwnerJournalPhaseV1::Prepared => Err(PrivateOramOwnerJournalError::Corrupt),
    }
}

fn encode_final_bucket_frame(
    indexes: &[PrivateOramOwnerJournalIndexDescriptorV1],
    final_buckets: &[PrivateOramOwnerFinalBucketIndexV1],
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    if indexes.is_empty()
        || indexes.len() > MAX_PAIRED_OWNER_INDEXES
        || indexes.len() != final_buckets.len()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut bytes = Vec::new();
    push_domain(&mut bytes, FINAL_BUCKET_FRAME_DOMAIN)?;
    bytes.extend_from_slice(&PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION.to_be_bytes());
    push_len(&mut bytes, indexes.len(), "indexes")?;
    let mut total_buckets = 0usize;
    for (index, final_index) in indexes.iter().zip(final_buckets) {
        if index.kind != final_index.buckets.kind()
            || index.index_name != final_index.index_name
            || index.final_bucket_refs != final_bucket_refs(&final_index.buckets)
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        bytes.push(kind_tag(index.kind));
        push_resource_id(&mut bytes, &index.index_name, "index_name")?;
        push_len(&mut bytes, final_index.buckets.len(), "final_buckets")?;
        total_buckets = total_buckets
            .checked_add(final_index.buckets.len())
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        match &final_index.buckets {
            PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets) => {
                for bucket in buckets {
                    encode_final_bucket(
                        &mut bytes,
                        bucket.version,
                        bucket.bucket_id,
                        bucket.index_epoch,
                        &bucket.ciphertext,
                        &bucket.ciphertext_sha256,
                        &bucket.bucket_commitment,
                        index.new_epoch,
                    )?;
                }
            }
            PrivateOramOwnerFinalBucketBatchV1::Result(buckets) => {
                for bucket in buckets {
                    encode_final_bucket(
                        &mut bytes,
                        bucket.version,
                        bucket.bucket_id,
                        bucket.index_epoch,
                        &bucket.ciphertext,
                        &bucket.ciphertext_sha256,
                        &bucket.bucket_commitment,
                        index.new_epoch,
                    )?;
                }
            }
        }
    }
    if total_buckets == 0 || total_buckets > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    if bytes.is_empty() || bytes.len() as u64 > MAX_FINAL_BUCKET_FRAME_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn encode_final_bucket(
    bytes: &mut Vec<u8>,
    version: u16,
    bucket_id: u64,
    index_epoch: u64,
    ciphertext: &str,
    ciphertext_sha256: &str,
    bucket_commitment: &str,
    expected_epoch: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    if version != 1 || index_epoch != expected_epoch {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let ciphertext_bytes = decode_base64url_canonical(ciphertext, "ciphertext")?;
    if ciphertext_bytes.is_empty()
        || ciphertext_bytes.len() as u64 > MAX_FINAL_BUCKET_FRAME_BYTES
        || digest_string(&ciphertext_bytes) != ciphertext_sha256
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    validate_digest(ciphertext_sha256, "ciphertext_sha256")?;
    validate_digest(bucket_commitment, "bucket_commitment")?;
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&bucket_id.to_be_bytes());
    bytes.extend_from_slice(&index_epoch.to_be_bytes());
    push_len(bytes, ciphertext_bytes.len(), "ciphertext")?;
    bytes.extend_from_slice(&ciphertext_bytes);
    push_digest(bytes, ciphertext_sha256, "ciphertext_sha256")?;
    push_digest(bytes, bucket_commitment, "bucket_commitment")?;
    Ok(())
}

fn decode_final_bucket_frame(
    indexes: &[PrivateOramOwnerJournalIndexDescriptorV1],
    bytes: &[u8],
) -> Result<Vec<PrivateOramOwnerFinalBucketIndexV1>, PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_FINAL_BUCKET_FRAME_BYTES {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut decoder = BinaryDecoder::new(bytes);
    decoder.read_domain(FINAL_BUCKET_FRAME_DOMAIN)?;
    if decoder.read_u16()? != PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION
        || decoder.read_len(MAX_PAIRED_OWNER_INDEXES)? != indexes.len()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let mut final_indexes = Vec::with_capacity(indexes.len());
    let mut total_buckets = 0usize;
    for index in indexes {
        if decoder.read_kind()? != index.kind || decoder.read_resource_id()? != index.index_name {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let bucket_count = decoder.read_len(PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS)?;
        if bucket_count == 0 {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        total_buckets = total_buckets
            .checked_add(bucket_count)
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        if total_buckets > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let buckets = match index.kind {
            PrivateOramIndexKindV2::Hnsw => {
                let mut buckets = Vec::with_capacity(bucket_count);
                for _ in 0..bucket_count {
                    let bucket = decoder.read_final_bucket(index.new_epoch)?;
                    buckets.push(PrivateHnswOramBucket {
                        version: bucket.version,
                        bucket_id: bucket.bucket_id,
                        index_epoch: bucket.index_epoch,
                        ciphertext: bucket.ciphertext,
                        ciphertext_sha256: bucket.ciphertext_sha256,
                        bucket_commitment: bucket.bucket_commitment,
                    });
                }
                PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets)
            }
            PrivateOramIndexKindV2::Result => {
                let mut buckets = Vec::with_capacity(bucket_count);
                for _ in 0..bucket_count {
                    let bucket = decoder.read_final_bucket(index.new_epoch)?;
                    buckets.push(PrivateResultOramBucket {
                        version: bucket.version,
                        bucket_id: bucket.bucket_id,
                        index_epoch: bucket.index_epoch,
                        ciphertext: bucket.ciphertext,
                        ciphertext_sha256: bucket.ciphertext_sha256,
                        bucket_commitment: bucket.bucket_commitment,
                    });
                }
                PrivateOramOwnerFinalBucketBatchV1::Result(buckets)
            }
        };
        final_indexes.push(PrivateOramOwnerFinalBucketIndexV1 {
            index_name: index.index_name.clone(),
            buckets,
        });
    }
    if total_buckets == 0 || !decoder.is_finished() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    if encode_final_bucket_frame(indexes, &final_indexes)? != bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(final_indexes)
}

fn final_bucket_refs(
    buckets: &PrivateOramOwnerFinalBucketBatchV1,
) -> Vec<PrivateOramAppendBucketRefV1> {
    match buckets {
        PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets) => buckets
            .iter()
            .map(|bucket| PrivateOramAppendBucketRefV1 {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                bucket_commitment: bucket.bucket_commitment.clone(),
            })
            .collect(),
        PrivateOramOwnerFinalBucketBatchV1::Result(buckets) => buckets
            .iter()
            .map(|bucket| PrivateOramAppendBucketRefV1 {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                bucket_commitment: bucket.bucket_commitment.clone(),
            })
            .collect(),
    }
}

fn collapse_ordered_bucket_refs(
    ordered: &[PrivateOramAppendBucketRefV1],
) -> Vec<PrivateOramAppendBucketRefV1> {
    let mut final_refs = BTreeMap::new();
    for bucket in ordered {
        final_refs.insert(bucket.bucket_id, bucket.clone());
    }
    final_refs.into_values().collect()
}

fn validate_bucket_ref(
    bucket: &PrivateOramAppendBucketRefV1,
) -> Result<(), PrivateOramOwnerJournalError> {
    validate_digest(&bucket.ciphertext_sha256, "ciphertext_sha256")?;
    validate_digest(&bucket.bucket_commitment, "bucket_commitment")
}

fn kind_tag(kind: PrivateOramIndexKindV2) -> u8 {
    match kind {
        PrivateOramIndexKindV2::Hnsw => HNSW_KIND_TAG,
        PrivateOramIndexKindV2::Result => RESULT_KIND_TAG,
    }
}

fn push_domain(bytes: &mut Vec<u8>, domain: &[u8]) -> Result<(), PrivateOramOwnerJournalError> {
    push_len(bytes, domain.len(), "domain")?;
    bytes.extend_from_slice(domain);
    Ok(())
}

fn push_digest(
    bytes: &mut Vec<u8>,
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerJournalError> {
    bytes.extend_from_slice(&decode_digest(value, field)?);
    Ok(())
}

fn push_resource_id(
    bytes: &mut Vec<u8>,
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerJournalError> {
    validate_resource_id(value, field)?;
    push_len(bytes, value.len(), field)?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_len(
    bytes: &mut Vec<u8>,
    length: usize,
    field: &'static str,
) -> Result<(), PrivateOramOwnerJournalError> {
    let length =
        u32::try_from(length).map_err(|_| PrivateOramOwnerJournalError::InvalidInput(field))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn push_bucket_refs(
    bytes: &mut Vec<u8>,
    buckets: &[PrivateOramAppendBucketRefV1],
) -> Result<(), PrivateOramOwnerJournalError> {
    push_len(bytes, buckets.len(), "bucket_refs")?;
    for bucket in buckets {
        validate_bucket_ref(bucket)?;
        bytes.extend_from_slice(&bucket.bucket_id.to_be_bytes());
        push_digest(bytes, &bucket.ciphertext_sha256, "ciphertext_sha256")?;
        push_digest(bytes, &bucket.bucket_commitment, "bucket_commitment")?;
    }
    Ok(())
}

fn validate_resource_id(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerJournalError> {
    if value.is_empty()
        || value.len() > MAX_RESOURCE_ID_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(PrivateOramOwnerJournalError::InvalidInput(field));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), PrivateOramOwnerJournalError> {
    decode_digest(value, field).map(drop)
}

fn decode_digest(
    value: &str,
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], PrivateOramOwnerJournalError> {
    let decoded = decode_base64url_canonical(value, field)?;
    decoded
        .try_into()
        .map_err(|_| PrivateOramOwnerJournalError::InvalidInput(field))
}

fn decode_base64url_canonical(
    value: &str,
    field: &'static str,
) -> Result<Vec<u8>, PrivateOramOwnerJournalError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramOwnerJournalError::InvalidInput(field))?;
    if BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramOwnerJournalError::InvalidInput(field));
    }
    Ok(decoded)
}

fn digest_string(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(bytes))
}

struct DecodedFinalBucket {
    version: u16,
    bucket_id: u64,
    index_epoch: u64,
    ciphertext: String,
    ciphertext_sha256: String,
    bucket_commitment: String,
}

struct BinaryDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_domain(&mut self, expected: &[u8]) -> Result<(), PrivateOramOwnerJournalError> {
        let length = self.read_len(expected.len())?;
        if length != expected.len() || self.read_exact(length)? != expected {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(())
    }

    fn read_domain_choice(
        &mut self,
        expected: &[&[u8]],
    ) -> Result<usize, PrivateOramOwnerJournalError> {
        let max_length = expected.iter().map(|value| value.len()).max().unwrap_or(0);
        let length = self.read_len(max_length)?;
        let actual = self.read_exact(length)?;
        expected
            .iter()
            .position(|candidate| *candidate == actual)
            .ok_or(PrivateOramOwnerJournalError::Corrupt)
    }

    fn read_u8(&mut self) -> Result<u8, PrivateOramOwnerJournalError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, PrivateOramOwnerJournalError> {
        let value: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        Ok(u16::from_be_bytes(value))
    }

    fn read_u32(&mut self) -> Result<u32, PrivateOramOwnerJournalError> {
        let value: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        Ok(u32::from_be_bytes(value))
    }

    fn read_u64(&mut self) -> Result<u64, PrivateOramOwnerJournalError> {
        let value: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        Ok(u64::from_be_bytes(value))
    }

    fn read_len(&mut self, max: usize) -> Result<usize, PrivateOramOwnerJournalError> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        if length > max {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(length)
    }

    fn read_kind(&mut self) -> Result<PrivateOramIndexKindV2, PrivateOramOwnerJournalError> {
        match self.read_u8()? {
            HNSW_KIND_TAG => Ok(PrivateOramIndexKindV2::Hnsw),
            RESULT_KIND_TAG => Ok(PrivateOramIndexKindV2::Result),
            _ => Err(PrivateOramOwnerJournalError::Corrupt),
        }
    }

    fn read_digest(&mut self) -> Result<String, PrivateOramOwnerJournalError> {
        Ok(BASE64URL_NOPAD.encode(self.read_exact(DIGEST_BYTES)?))
    }

    fn read_resource_id(&mut self) -> Result<String, PrivateOramOwnerJournalError> {
        let length = self.read_len(MAX_RESOURCE_ID_BYTES)?;
        let value = std::str::from_utf8(self.read_exact(length)?)
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_resource_id(value, "resource_id")
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        Ok(value.to_string())
    }

    fn read_bucket_refs(
        &mut self,
        max: usize,
    ) -> Result<Vec<PrivateOramAppendBucketRefV1>, PrivateOramOwnerJournalError> {
        let count = self.read_len(max)?;
        let mut buckets = Vec::with_capacity(count);
        for _ in 0..count {
            buckets.push(PrivateOramAppendBucketRefV1 {
                bucket_id: self.read_u64()?,
                ciphertext_sha256: self.read_digest()?,
                bucket_commitment: self.read_digest()?,
            });
        }
        Ok(buckets)
    }

    fn read_final_bucket(
        &mut self,
        expected_epoch: u64,
    ) -> Result<DecodedFinalBucket, PrivateOramOwnerJournalError> {
        let version = self.read_u16()?;
        let bucket_id = self.read_u64()?;
        let index_epoch = self.read_u64()?;
        if version != 1 || index_epoch != expected_epoch {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let max_ciphertext = usize::try_from(MAX_FINAL_BUCKET_FRAME_BYTES)
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let ciphertext_bytes = self.read_blob(max_ciphertext)?;
        if ciphertext_bytes.is_empty() {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let ciphertext = BASE64URL_NOPAD.encode(ciphertext_bytes);
        let ciphertext_sha256 = self.read_digest()?;
        let bucket_commitment = self.read_digest()?;
        if digest_string(ciphertext_bytes) != ciphertext_sha256 {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        Ok(DecodedFinalBucket {
            version,
            bucket_id,
            index_epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment,
        })
    }

    fn read_blob(&mut self, max: usize) -> Result<&'a [u8], PrivateOramOwnerJournalError> {
        let length = self.read_len(max)?;
        self.read_exact(length)
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], PrivateOramOwnerJournalError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PrivateOramOwnerJournalError::Corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    length: u64,
}

fn path_entry_exists(path: &Path) -> Result<bool, PrivateOramOwnerJournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PrivateOramOwnerJournalError::Io),
    }
}

fn create_private_directory(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_private_directory_exact(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(PrivateOramOwnerJournalError::Io),
    }
    match fs::create_dir(path) {
        Ok(()) => {
            set_private_directory_permissions(path)?;
            validate_private_directory_exact(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_private_directory_exact(path)
        }
        Err(_) => Err(PrivateOramOwnerJournalError::Io),
    }
}

fn set_private_directory_permissions(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| PrivateOramOwnerJournalError::Io)?;
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    Ok(())
}

fn private_directory_identity(
    path: &Path,
) -> Result<DirectoryIdentity, PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&before)?;
    let opened = open_private_directory(path)?;
    let after = opened
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&after)?;
    ensure_same_inode(&before, &after)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(DirectoryIdentity {
            device: after.dev(),
            inode: after.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(DirectoryIdentity {
            length: after.len(),
        })
    }
}

fn validate_private_directory_exact(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    private_directory_identity(path).map(drop)
}

fn validate_directory_metadata(
    metadata: &std::fs::Metadata,
) -> Result<(), PrivateOramOwnerJournalError> {
    if !metadata.file_type().is_dir() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || metadata.nlink() < 2
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn validate_file_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn validate_stranded_candidate_file(
    path: &Path,
    max_bytes: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_stranded_candidate_file_metadata(&before, max_bytes)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let after = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_stranded_candidate_file_metadata(&after, max_bytes)?;
    ensure_same_inode(&before, &after)
}

fn validate_stranded_candidate_file_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn ensure_same_inode(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), PrivateOramOwnerJournalError> {
    if before.file_type().is_file() != after.file_type().is_file()
        || before.file_type().is_dir() != after.file_type().is_dir()
        || before.len() != after.len()
    {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(())
}

fn ensure_same_open_inode(first: &File, second: &File) -> Result<(), PrivateOramOwnerJournalError> {
    let first_metadata = first
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let second_metadata = second
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    ensure_same_inode(&first_metadata, &second_metadata)
}

fn open_private_directory(path: &Path) -> Result<File, PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let after = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&after)?;
    ensure_same_inode(&before, &after)?;
    Ok(file)
}

fn write_new_private_file(
    path: &Path,
    bytes: &[u8],
    max_bytes: u64,
) -> Result<(), PrivateOramOwnerJournalError> {
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(PrivateOramOwnerJournalError::InvalidInput("file_bytes"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let mut file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Io)?;
    file.write_all(bytes)
        .map_err(|_| PrivateOramOwnerJournalError::Io)?;
    file.flush().map_err(|_| PrivateOramOwnerJournalError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Io)?;
    validate_file_metadata(&metadata, max_bytes)?;
    if metadata.len() != bytes.len() as u64 {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    file.sync_all()
        .map_err(|_| PrivateOramOwnerJournalError::Io)
}

struct PinnedPrivateFile {
    file: File,
    path: PathBuf,
    max_bytes: u64,
}

impl PinnedPrivateFile {
    fn sync(&self) -> Result<(), PrivateOramOwnerJournalError> {
        self.file
            .sync_all()
            .map_err(|_| PrivateOramOwnerJournalError::Indeterminate)
    }

    fn validate_at_path(&self) -> Result<(), PrivateOramOwnerJournalError> {
        let opened = self
            .file
            .metadata()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_file_metadata(&opened, self.max_bytes)?;
        let current =
            fs::symlink_metadata(&self.path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_file_metadata(&current, self.max_bytes)?;
        ensure_same_inode(&opened, &current)
    }

    fn validate_exact_contents(
        &mut self,
        expected: &[u8],
    ) -> Result<(), PrivateOramOwnerJournalError> {
        let before = self
            .file
            .metadata()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_file_metadata(&before, self.max_bytes)?;
        if before.len() != expected.len() as u64 {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let mut actual = Vec::new();
        actual
            .try_reserve_exact(expected.len())
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        (&mut self.file)
            .take(self.max_bytes.saturating_add(1))
            .read_to_end(&mut actual)
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        let after = self
            .file
            .metadata()
            .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        validate_file_metadata(&after, self.max_bytes)?;
        ensure_same_inode(&before, &after)?;
        if actual != expected {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        self.validate_at_path()
    }
}

struct PrivateJournalRootLock<'a> {
    root: &'a File,
}

#[cfg(target_os = "linux")]
impl Drop for PrivateJournalRootLock<'_> {
    fn drop(&mut self) {
        // SAFETY: the guard retains the live directory fd for the full lock lifetime.
        let _ = unsafe { nix::libc::flock(self.root.as_raw_fd(), nix::libc::LOCK_UN) };
    }
}

#[cfg(target_os = "linux")]
fn lock_private_journal_root(
    root: &File,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    lock_private_journal_root_with_operation(root, nix::libc::LOCK_EX)
}

#[cfg(target_os = "linux")]
fn lock_private_journal_root_shared(
    root: &File,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    lock_private_journal_root_with_operation(root, nix::libc::LOCK_SH)
}

#[cfg(target_os = "linux")]
fn lock_private_journal_root_with_operation(
    root: &File,
    operation: nix::libc::c_int,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    // SAFETY: root is a validated, live directory fd retained by the returned guard.
    let result = unsafe { nix::libc::flock(root.as_raw_fd(), operation | nix::libc::LOCK_NB) };
    if result == 0 {
        return Ok(PrivateJournalRootLock { root });
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(nix::libc::EWOULDBLOCK) {
        Err(PrivateOramOwnerJournalError::ConcurrentMutation)
    } else {
        Err(PrivateOramOwnerJournalError::Unsupported)
    }
}

#[cfg(not(target_os = "linux"))]
fn lock_private_journal_root(
    _root: &File,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(not(target_os = "linux"))]
fn lock_private_journal_root_shared(
    _root: &File,
) -> Result<PrivateJournalRootLock<'_>, PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

fn read_private_file_pinned(
    path: &Path,
    max_bytes: u64,
) -> Result<(PinnedPrivateFile, Vec<u8>), PrivateOramOwnerJournalError> {
    let before = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_file_metadata(&before, max_bytes)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let mut file = options
        .open(path)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let opened = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_file_metadata(&opened, max_bytes)?;
    ensure_same_inode(&before, &opened)?;

    let expected_length =
        usize::try_from(opened.len()).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    if bytes.len() != expected_length {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    let after = file
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_file_metadata(&after, max_bytes)?;
    ensure_same_inode(&opened, &after)?;
    let pinned = PinnedPrivateFile {
        file,
        path: path.to_path_buf(),
        max_bytes,
    };
    pinned.validate_at_path()?;
    Ok((pinned, bytes))
}

fn sync_private_directory(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    sync_open_directory(&open_private_directory(path)?)
}

fn sync_open_directory(directory: &File) -> Result<(), PrivateOramOwnerJournalError> {
    directory
        .sync_all()
        .map_err(|_| PrivateOramOwnerJournalError::Io)
}

fn validate_open_directory_at_path(
    directory: &File,
    path: &Path,
) -> Result<(), PrivateOramOwnerJournalError> {
    let opened = directory
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&opened)?;
    let current = fs::symlink_metadata(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&current)?;
    ensure_same_inode(&opened, &current)
}

fn directory_entry_names(
    path: &Path,
) -> Result<BTreeSet<std::ffi::OsString>, PrivateOramOwnerJournalError> {
    let mut names = BTreeSet::new();
    let entries = fs::read_dir(path).map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    for entry in entries {
        let entry = entry.map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
        if !names.insert(entry.file_name()) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn open_directory_entry_path(
    directory: &File,
    name: &OsStr,
) -> Result<PathBuf, PrivateOramOwnerJournalError> {
    checked_single_component_cstring(name)?;
    let metadata = directory
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&metadata)?;
    Ok(PathBuf::from("/proc/self/fd")
        .join(directory.as_raw_fd().to_string())
        .join(name))
}

#[cfg(not(target_os = "linux"))]
fn open_directory_entry_path(
    _directory: &File,
    _name: &OsStr,
) -> Result<PathBuf, PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

fn directory_entry_names_open(
    directory: &File,
) -> Result<BTreeSet<std::ffi::OsString>, PrivateOramOwnerJournalError> {
    let before = directory
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&before)?;
    #[cfg(target_os = "linux")]
    let path = PathBuf::from("/proc/self/fd").join(directory.as_raw_fd().to_string());
    #[cfg(not(target_os = "linux"))]
    return Err(PrivateOramOwnerJournalError::Unsupported);
    #[allow(unreachable_code)]
    let names = directory_entry_names(&path)?;
    let after = directory
        .metadata()
        .map_err(|_| PrivateOramOwnerJournalError::Corrupt)?;
    validate_directory_metadata(&after)?;
    ensure_same_inode(&before, &after)?;
    Ok(names)
}

fn validate_active_entry_set(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    validate_private_directory_exact(path)?;
    let actual = directory_entry_names(path)?;
    let expected = [
        DESCRIPTOR_FILE,
        FINAL_BUCKETS_FILE,
        STATE_FILE,
        ACTIVE_TEMP_DIR,
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_active_entry_set_open(directory: &File) -> Result<bool, PrivateOramOwnerJournalError> {
    let actual = directory_entry_names_open(directory)?;
    let mut expected = [
        DESCRIPTOR_FILE,
        FINAL_BUCKETS_FILE,
        STATE_FILE,
        ACTIVE_TEMP_DIR,
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<BTreeSet<_>>();
    let has_terminal = actual.contains(OsStr::new(TERMINAL_DIR));
    if has_terminal {
        expected.insert(std::ffi::OsString::from(TERMINAL_DIR));
    }
    if actual != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(has_terminal)
}

fn validate_directory_is_empty(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    validate_private_directory_exact(path)?;
    if !directory_entry_names(path)?.is_empty() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_directory_is_empty_open(directory: &File) -> Result<(), PrivateOramOwnerJournalError> {
    if !directory_entry_names_open(directory)?.is_empty() {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_terminal_entry_set(path: &Path) -> Result<(), PrivateOramOwnerJournalError> {
    validate_private_directory_exact(path)?;
    let expected = [std::ffi::OsString::from(TERMINAL_RECORD_FILE)]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if directory_entry_names(path)? != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_terminal_entry_set_open(directory: &File) -> Result<(), PrivateOramOwnerJournalError> {
    let expected = [std::ffi::OsString::from(TERMINAL_RECORD_FILE)]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if directory_entry_names_open(directory)? != expected {
        return Err(PrivateOramOwnerJournalError::Corrupt);
    }
    Ok(())
}

fn validate_terminal_temp_entries_open(
    directory: &File,
) -> Result<(), PrivateOramOwnerJournalError> {
    for name in directory_entry_names_open(directory)? {
        if !is_terminal_candidate_name(&name) {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let candidate_path = open_directory_entry_path(directory, &name)?;
        let candidate = open_private_directory(&candidate_path)?;
        let entries = directory_entry_names_open(&candidate)?;
        if entries.is_empty() {
            continue;
        }
        let expected = [std::ffi::OsString::from(TERMINAL_RECORD_FILE)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        if entries != expected {
            return Err(PrivateOramOwnerJournalError::Corrupt);
        }
        let record_path = open_directory_entry_path(&candidate, OsStr::new(TERMINAL_RECORD_FILE))?;
        validate_stranded_candidate_file(&record_path, MAX_TERMINAL_RECORD_BYTES)?;
    }
    Ok(())
}

fn is_candidate_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.len() > CANDIDATE_PREFIX.len() && name.starts_with(CANDIDATE_PREFIX)
    })
}

fn is_terminal_candidate_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.len() > TERMINAL_CANDIDATE_PREFIX.len() && name.starts_with(TERMINAL_CANDIDATE_PREFIX)
    })
}

#[cfg(target_os = "linux")]
fn rename_directory_noreplace(
    root: &File,
    source_name: &OsStr,
    destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    rename_entry_noreplace(root, source_name, root, destination_name)
}

#[cfg(target_os = "linux")]
fn rename_entry_noreplace(
    source_directory: &File,
    source_name: &OsStr,
    destination_directory: &File,
    destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    let source = checked_single_component_cstring(source_name)?;
    let destination = checked_single_component_cstring(destination_name)?;
    // SAFETY: both names are validated single-component C strings and both directory descriptors
    // are pinned, live, no-follow handles retained across the non-replacing rename.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_renameat2,
            source_directory.as_raw_fd(),
            source.as_ptr(),
            destination_directory.as_raw_fd(),
            destination.as_ptr(),
            nix::libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(nix::libc::EEXIST) => Err(PrivateOramOwnerJournalError::ConcurrentMutation),
        Some(nix::libc::ENOSYS | nix::libc::EINVAL | nix::libc::EOPNOTSUPP | nix::libc::EXDEV) => {
            Err(PrivateOramOwnerJournalError::Unsupported)
        }
        _ => Err(PrivateOramOwnerJournalError::Indeterminate),
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_directory_noreplace(
    _root: &File,
    _source_name: &OsStr,
    _destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(not(target_os = "linux"))]
fn rename_entry_noreplace(
    _source_directory: &File,
    _source_name: &OsStr,
    _destination_directory: &File,
    _destination_name: &OsStr,
) -> Result<(), PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(target_os = "linux")]
fn checked_single_component_cstring(name: &OsStr) -> Result<CString, PrivateOramOwnerJournalError> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(PrivateOramOwnerJournalError::InvalidInput(
            "rename_component",
        ));
    }
    CString::new(bytes).map_err(|_| PrivateOramOwnerJournalError::InvalidInput("rename_component"))
}

#[cfg(not(target_os = "linux"))]
const fn ensure_supported_platform() -> Result<(), PrivateOramOwnerJournalError> {
    Err(PrivateOramOwnerJournalError::Unsupported)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    struct JournalFixture {
        _temp: TempDir,
        hnsw_root: PathBuf,
        journal: PrivateOramOwnerJournal,
    }

    fn digest(fill: u8) -> String {
        BASE64URL_NOPAD.encode(&[fill; DIGEST_BYTES])
    }

    fn canonical_index_states(
        desired: &ValidatedOwnerJournal,
        marker: u8,
    ) -> Vec<PrivateOramOwnerJournalTerminalIndexStateV1> {
        desired
            .snapshot
            .descriptor
            .indexes
            .iter()
            .enumerate()
            .map(
                |(position, index)| PrivateOramOwnerJournalTerminalIndexStateV1 {
                    kind: index.kind,
                    index_name: index.index_name.clone(),
                    canonical_state_digest: digest(marker.wrapping_add(position as u8)),
                },
            )
            .collect()
    }

    fn recovery_projection(
        desired: &ValidatedOwnerJournal,
    ) -> PrivateOramOwnerRecoveryProjectionV1 {
        let descriptor = &desired.snapshot.descriptor;
        let prepared = prepared_token(descriptor).unwrap();
        PrivateOramOwnerRecoveryProjectionV1 {
            expected_owner_peer_id: descriptor.owner_peer_id,
            parent_descriptor_digest: descriptor.parent_descriptor_digest.clone(),
            parent_lease_acquired_record_digest: descriptor
                .parent_lease_acquired_record_digest
                .clone(),
            collection_id: descriptor.collection_id.clone(),
            mutation_id: descriptor.mutation_id.clone(),
            signed_mutation_digest: descriptor.signed_mutation_digest.clone(),
            writer_lease_digest: descriptor.writer_lease_digest.clone(),
            writer_fence: descriptor.writer_fence,
            indexes: descriptor
                .indexes
                .iter()
                .zip(prepared.indexes())
                .map(
                    |(index, evidence)| PrivateOramOwnerRecoveryIndexProjectionV1 {
                        kind: index.kind,
                        index_name: index.index_name.clone(),
                        old_epoch: index.old_epoch,
                        new_epoch: index.new_epoch,
                        old_root_hash: index.old_root_hash.clone(),
                        new_root_hash: index.new_root_hash.clone(),
                        writeback_digest: index.writeback_digest.clone(),
                        prepared_journal_digest: evidence.prepared_journal_digest.clone(),
                    },
                )
                .collect(),
        }
    }

    fn bucket_ref(
        bucket_id: u64,
        ciphertext_sha256: String,
        bucket_commitment: String,
    ) -> PrivateOramAppendBucketRefV1 {
        PrivateOramAppendBucketRefV1 {
            bucket_id,
            ciphertext_sha256,
            bucket_commitment,
        }
    }

    fn ciphertext(marker: u8, bucket_id: u64) -> String {
        let mut bytes = vec![marker; 48];
        bytes.extend_from_slice(&bucket_id.to_be_bytes());
        BASE64URL_NOPAD.encode(&bytes)
    }

    fn hnsw_bucket(marker: u8, bucket_id: u64, epoch: u64) -> PrivateHnswOramBucket {
        let ciphertext = ciphertext(marker, bucket_id);
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext_sha256: digest_string(
                &BASE64URL_NOPAD.decode(ciphertext.as_bytes()).unwrap(),
            ),
            bucket_commitment: digest(marker.wrapping_add(80).wrapping_add(bucket_id as u8)),
            ciphertext,
        }
    }

    fn result_bucket(marker: u8, bucket_id: u64, epoch: u64) -> PrivateResultOramBucket {
        let ciphertext = ciphertext(marker, bucket_id);
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext_sha256: digest_string(
                &BASE64URL_NOPAD.decode(ciphertext.as_bytes()).unwrap(),
            ),
            bucket_commitment: digest(marker.wrapping_add(90).wrapping_add(bucket_id as u8)),
            ciphertext,
        }
    }

    fn validated_fixture(marker: u8, include_result: bool) -> ValidatedOwnerJournal {
        let hnsw_epoch = 12;
        let hnsw_buckets = vec![
            hnsw_bucket(marker.wrapping_add(1), 0, hnsw_epoch),
            hnsw_bucket(marker.wrapping_add(2), 1, hnsw_epoch),
        ];
        let hnsw_final_refs = hnsw_buckets
            .iter()
            .map(|bucket| {
                bucket_ref(
                    bucket.bucket_id,
                    bucket.ciphertext_sha256.clone(),
                    bucket.bucket_commitment.clone(),
                )
            })
            .collect::<Vec<_>>();
        let hnsw_ordered_refs = vec![
            bucket_ref(
                1,
                digest(marker.wrapping_add(30)),
                digest(marker.wrapping_add(31)),
            ),
            hnsw_final_refs[0].clone(),
            hnsw_final_refs[1].clone(),
        ];
        let mut indexes = vec![PrivateOramOwnerJournalIndexDescriptorV1 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: "text".to_string(),
            old_epoch: 11,
            new_epoch: hnsw_epoch,
            old_root_hash: digest(marker.wrapping_add(3)),
            new_root_hash: digest(marker.wrapping_add(4)),
            writeback_digest: digest(marker.wrapping_add(5)),
            read_path_count: 8,
            read_transcript_digest: digest(marker.wrapping_add(6)),
            ordered_bucket_refs: hnsw_ordered_refs,
            final_bucket_refs: hnsw_final_refs,
        }];
        let mut final_buckets = vec![PrivateOramOwnerFinalBucketIndexV1 {
            index_name: "text".to_string(),
            buckets: PrivateOramOwnerFinalBucketBatchV1::Hnsw(hnsw_buckets),
        }];
        if include_result {
            let result_epoch = 22;
            let result_buckets = vec![result_bucket(marker.wrapping_add(7), 2, result_epoch)];
            let result_refs = result_buckets
                .iter()
                .map(|bucket| {
                    bucket_ref(
                        bucket.bucket_id,
                        bucket.ciphertext_sha256.clone(),
                        bucket.bucket_commitment.clone(),
                    )
                })
                .collect::<Vec<_>>();
            indexes.push(PrivateOramOwnerJournalIndexDescriptorV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: "private-result".to_string(),
                old_epoch: 21,
                new_epoch: result_epoch,
                old_root_hash: digest(marker.wrapping_add(8)),
                new_root_hash: digest(marker.wrapping_add(9)),
                writeback_digest: digest(marker.wrapping_add(10)),
                read_path_count: 4,
                read_transcript_digest: digest(marker.wrapping_add(11)),
                ordered_bucket_refs: result_refs.clone(),
                final_bucket_refs: result_refs,
            });
            final_buckets.push(PrivateOramOwnerFinalBucketIndexV1 {
                index_name: "private-result".to_string(),
                buckets: PrivateOramOwnerFinalBucketBatchV1::Result(result_buckets),
            });
        }
        validated_from_parts(marker, indexes, final_buckets)
    }

    fn validated_from_parts(
        marker: u8,
        indexes: Vec<PrivateOramOwnerJournalIndexDescriptorV1>,
        final_buckets: Vec<PrivateOramOwnerFinalBucketIndexV1>,
    ) -> ValidatedOwnerJournal {
        let final_bucket_bytes = encode_final_bucket_frame(&indexes, &final_buckets).unwrap();
        let mut descriptor = PrivateOramOwnerJournalDescriptorV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_DESCRIPTOR_VERSION,
            parent_descriptor_digest: digest(marker.wrapping_add(12)),
            parent_lease_acquired_record_digest: digest(marker.wrapping_add(13)),
            owner_peer_id: 7,
            collection_id: format!("collection-{marker}"),
            mutation_id: digest(marker.wrapping_add(14)),
            signed_mutation_digest: digest(marker.wrapping_add(15)),
            writer_lease_digest: digest(marker.wrapping_add(16)),
            writer_fence: 9,
            indexes,
            final_bucket_frame_version: PRIVATE_ORAM_OWNER_FINAL_BUCKET_FRAME_VERSION,
            final_bucket_frame_length: final_bucket_bytes.len() as u64,
            final_bucket_frame_sha256: digest_string(&final_bucket_bytes),
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor_digest(&descriptor).unwrap();
        let descriptor_bytes = encode_descriptor(&descriptor).unwrap();
        let mut state = PrivateOramOwnerJournalStateV1 {
            version: PRIVATE_ORAM_OWNER_JOURNAL_STATE_VERSION,
            sequence: 1,
            descriptor_digest: descriptor.descriptor_digest.clone(),
            previous_record_digest: None,
            phase: PrivateOramOwnerJournalPhaseV1::Prepared,
            state_digest: String::new(),
        };
        state.state_digest = state_digest(&state).unwrap();
        let state_bytes = encode_state(&state).unwrap();
        let snapshot = PrivateOramOwnerJournalSnapshotV1 {
            descriptor,
            state,
            terminal: None,
            final_buckets,
        };
        validate_snapshot(&snapshot, &final_bucket_bytes).unwrap();
        ValidatedOwnerJournal {
            snapshot,
            descriptor_bytes,
            final_bucket_bytes,
            state_bytes,
            terminal_bytes: None,
        }
    }

    fn fixture() -> JournalFixture {
        let temp = TempDir::new().unwrap();
        let hnsw_root = temp.path().join("private-hnsw-root");
        create_private_directory(&hnsw_root).unwrap();
        create_private_directory(&hnsw_root.join(OWNER_STORE_TEMP_DIR)).unwrap();
        let journal = PrivateOramOwnerJournal::new(&hnsw_root);
        JournalFixture {
            _temp: temp,
            hnsw_root,
            journal,
        }
    }

    fn active_path(fixture: &JournalFixture) -> PathBuf {
        fixture.journal.root.join(ACTIVE_DIR)
    }

    fn terminal_path(fixture: &JournalFixture) -> PathBuf {
        active_path(fixture).join(TERMINAL_DIR)
    }

    fn prepare_and_finalize(fixture: &JournalFixture, marker: u8) {
        let desired = validated_fixture(marker, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(marker.wrapping_add(120));
        let reconciliation_authority_digest = digest(marker.wrapping_add(121));
        let canonical_index_states = canonical_index_states(&desired, marker.wrapping_add(122));
        fixture.journal.prepare_validated(desired).unwrap();
        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &reconciliation_authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();
    }

    #[test]
    fn canonical_codecs_round_trip() {
        let desired = validated_fixture(1, true);
        let decoded = ValidatedOwnerJournal::decode(
            desired.descriptor_bytes.clone(),
            desired.final_bucket_bytes.clone(),
            desired.state_bytes.clone(),
            None,
        )
        .unwrap();

        assert!(decoded.exactly_matches(&desired));
        assert_eq!(decoded.snapshot.descriptor.indexes.len(), 2);
        assert_eq!(
            decoded.snapshot.descriptor.indexes[0]
                .ordered_bucket_refs
                .len(),
            3
        );
        assert_eq!(
            decoded.snapshot.descriptor.indexes[0]
                .final_bucket_refs
                .len(),
            2
        );
        assert_eq!(
            (
                desired.snapshot.descriptor.descriptor_digest.as_str(),
                desired
                    .snapshot
                    .descriptor
                    .final_bucket_frame_sha256
                    .as_str(),
                desired.snapshot.state.state_digest.as_str(),
            ),
            (
                "roOyXeChO0guhChkl6yBmv9_TsfQo4nK7lrsXt1VWZY",
                "h_xkYfrPQjXyBnKbMSgp4ZfEkB4xog6HaVht2CGCoM0",
                "-ji2rNgkMAUaRNGwJsrrUuGPk35jHqh4W5bouJgNTpo",
            )
        );
    }

    #[test]
    fn terminal_codecs_round_trip_with_distinct_known_answers() {
        let desired = validated_fixture(19, true);
        let consensus_authority_record_digest = digest(90);
        let finalize_authority_digest = digest(91);
        let abort_authority_digest = digest(92);
        let finalized_index_states = canonical_index_states(&desired, 105);
        let aborted_index_states = canonical_index_states(&desired, 107);
        let finalized = build_terminal_record(
            &desired.snapshot,
            TerminalTransition {
                phase: PrivateOramOwnerJournalPhaseV1::Finalized,
                expected_journal_descriptor_digest: &desired.snapshot.descriptor.descriptor_digest,
                parent_descriptor_digest: &desired.snapshot.descriptor.parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &finalize_authority_digest,
                canonical_index_states: &finalized_index_states,
            },
        )
        .unwrap();
        let aborted = build_terminal_record(
            &desired.snapshot,
            TerminalTransition {
                phase: PrivateOramOwnerJournalPhaseV1::AbortedOld,
                expected_journal_descriptor_digest: &desired.snapshot.descriptor.descriptor_digest,
                parent_descriptor_digest: &desired.snapshot.descriptor.parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &abort_authority_digest,
                canonical_index_states: &aborted_index_states,
            },
        )
        .unwrap();
        let finalized_bytes = encode_terminal_record(&finalized).unwrap();
        let aborted_bytes = encode_terminal_record(&aborted).unwrap();
        let mut finalized_snapshot = desired.snapshot.clone();
        finalized_snapshot.terminal = Some(finalized.clone());
        let mut aborted_snapshot = desired.snapshot;
        aborted_snapshot.terminal = Some(aborted.clone());

        assert_eq!(decode_terminal_record(&finalized_bytes).unwrap(), finalized);
        assert_eq!(decode_terminal_record(&aborted_bytes).unwrap(), aborted);
        assert_ne!(finalized_bytes, aborted_bytes);
        assert_eq!(
            (
                finalized.record_digest.as_str(),
                aborted.record_digest.as_str(),
                index_terminal_evidence_digest(
                    &finalized_snapshot,
                    finalized_snapshot.terminal.as_ref().unwrap(),
                    &finalized_snapshot.descriptor.indexes[0],
                )
                .unwrap(),
                index_terminal_evidence_digest(
                    &aborted_snapshot,
                    aborted_snapshot.terminal.as_ref().unwrap(),
                    &aborted_snapshot.descriptor.indexes[0],
                )
                .unwrap(),
            ),
            (
                "jZhaXH4MRgJwDEN_Y6-OZWStljvlUMGJKPcnAJQxh-w",
                "9-LWfFY2Nz1jzF24JDe5-zXrfm22cbldScGIvVZDJGo",
                "YCC1KyQTJvinV6YCB149WrgesDcLVRCwwfFpnwx95Xk".to_string(),
                "JfZ28r4ATcFOFUuPIcBhDcgEFkySkUQywfEOHZfTKZY".to_string()
            )
        );
    }

    #[test]
    fn descriptor_rejects_invalid_epoch_and_non_last_final_ref() {
        let desired = validated_fixture(14, false);
        let mut invalid_epoch = desired.snapshot.descriptor.clone();
        invalid_epoch.indexes[0].new_epoch = invalid_epoch.indexes[0].old_epoch;
        invalid_epoch.descriptor_digest.clear();
        assert_eq!(
            descriptor_digest(&invalid_epoch).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let mut invalid_root = desired.snapshot.descriptor.clone();
        invalid_root.indexes[0].new_root_hash = invalid_root.indexes[0].old_root_hash.clone();
        invalid_root.descriptor_digest.clear();
        assert_eq!(
            descriptor_digest(&invalid_root).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let mut invalid_final = desired.snapshot.descriptor;
        invalid_final.indexes[0].ordered_bucket_refs[2].ciphertext_sha256 = digest(230);
        invalid_final.descriptor_digest.clear();
        assert_eq!(
            descriptor_digest(&invalid_final).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let paired = validated_fixture(15, true);
        let mut too_many = paired.snapshot.descriptor;
        let mut extra_result = too_many.indexes[1].clone();
        extra_result.index_name = "private-result-2".to_string();
        too_many.indexes.push(extra_result);
        too_many.descriptor_digest.clear();
        assert_eq!(
            descriptor_digest(&too_many).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn prepare_reopen_and_exact_replay_return_same_token() {
        let fixture = fixture();
        let desired = validated_fixture(2, true);

        let (prepared, token) = fixture.journal.prepare_validated(desired.clone()).unwrap();
        let (replayed, replay_token) = fixture.journal.prepare_validated(desired).unwrap();
        let reopened = fixture.journal.inspect_structural().unwrap().unwrap();

        assert_eq!(prepared, replayed);
        assert_eq!(prepared, reopened);
        assert_eq!(token, replay_token);
        assert_eq!(token.indexes().len(), 2);
        assert_eq!(
            directory_entry_names(&fixture.journal.root).unwrap().len(),
            1
        );
    }

    #[test]
    fn conflicting_prepare_never_replaces_active() {
        let fixture = fixture();
        let first = validated_fixture(3, false);
        let second = validated_fixture(4, false);
        let (_, first_token) = fixture.journal.prepare_validated(first).unwrap();

        assert_eq!(
            fixture.journal.prepare_validated(second).unwrap_err(),
            PrivateOramOwnerJournalError::ConcurrentMutation
        );
        let current = fixture.journal.inspect_structural().unwrap().unwrap();
        assert_eq!(
            current.descriptor.descriptor_digest,
            first_token.journal_descriptor_digest()
        );
    }

    #[test]
    fn paired_indexes_publish_as_one_active_artifact() {
        let fixture = fixture();
        let (snapshot, token) = fixture
            .journal
            .prepare_validated(validated_fixture(5, true))
            .unwrap();

        assert_eq!(snapshot.descriptor.indexes.len(), 2);
        assert_eq!(snapshot.final_buckets.len(), 2);
        assert_eq!(token.indexes().len(), 2);
        assert_eq!(
            directory_entry_names(&active_path(&fixture)).unwrap(),
            [
                DESCRIPTOR_FILE,
                FINAL_BUCKETS_FILE,
                STATE_FILE,
                ACTIVE_TEMP_DIR
            ]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect()
        );
    }

    #[test]
    fn earlier_duplicate_changes_descriptor_but_not_final_image() {
        let first = validated_fixture(6, false);
        let mut indexes = first.snapshot.descriptor.indexes.clone();
        indexes[0].ordered_bucket_refs[0].ciphertext_sha256 = digest(201);
        indexes[0].ordered_bucket_refs[0].bucket_commitment = digest(202);
        let second = validated_from_parts(6, indexes, first.snapshot.final_buckets.clone());

        assert_eq!(first.final_bucket_bytes, second.final_bucket_bytes);
        assert_ne!(
            first.snapshot.descriptor.descriptor_digest,
            second.snapshot.descriptor.descriptor_digest
        );
        assert_eq!(
            second.snapshot.descriptor.indexes[0]
                .ordered_bucket_refs
                .len(),
            3
        );
        assert_eq!(
            second.snapshot.descriptor.indexes[0]
                .final_bucket_refs
                .len(),
            2
        );
    }

    #[test]
    fn stranded_candidate_is_never_adopted() {
        let fixture = fixture();
        fixture.journal.ensure_root().unwrap();
        let stranded = fixture.journal.root.join(".candidate-stranded");
        create_private_directory(&stranded).unwrap();

        assert!(fixture.journal.inspect_structural().unwrap().is_none());
        fixture
            .journal
            .prepare_validated(validated_fixture(7, false))
            .unwrap();

        assert!(stranded.exists());
        assert!(active_path(&fixture).exists());
    }

    #[test]
    fn prepare_does_not_modify_canonical_store_files() {
        let fixture = fixture();
        let bucket_sentinel = fixture.hnsw_root.join("canonical-buckets.sentinel");
        let merkle_sentinel = fixture.hnsw_root.join("canonical-merkle.sentinel");
        let epoch_sentinel = fixture.hnsw_root.join("canonical-epoch.sentinel");
        fs::write(&bucket_sentinel, b"old-buckets").unwrap();
        fs::write(&merkle_sentinel, b"old-merkle").unwrap();
        fs::write(&epoch_sentinel, b"old-epoch").unwrap();

        fixture
            .journal
            .prepare_validated(validated_fixture(8, true))
            .unwrap();

        assert_eq!(fs::read(bucket_sentinel).unwrap(), b"old-buckets");
        assert_eq!(fs::read(merkle_sentinel).unwrap(), b"old-merkle");
        assert_eq!(fs::read(epoch_sentinel).unwrap(), b"old-epoch");
    }

    #[test]
    fn active_file_tamper_fails_closed() {
        let fixture = fixture();
        fixture
            .journal
            .prepare_validated(validated_fixture(9, false))
            .unwrap();
        let state = active_path(&fixture).join(STATE_FILE);
        let mut bytes = fs::read(&state).unwrap();
        bytes[0] ^= 1;
        fs::write(state, bytes).unwrap();

        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn pinned_file_detects_same_inode_content_rewrite() {
        let fixture = fixture();
        fixture
            .journal
            .prepare_validated(validated_fixture(17, false))
            .unwrap();
        let state_path = active_path(&fixture).join(STATE_FILE);
        let (mut pinned, expected) =
            read_private_file_pinned(&state_path, MAX_STATE_BYTES).unwrap();
        let mut changed = expected.clone();
        changed[0] ^= 1;
        fs::write(state_path, changed).unwrap();

        assert_eq!(
            pinned.validate_exact_contents(&expected).unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn live_prepared_store_binding_requires_exact_token_and_holds_shared_lock() {
        let fixture = fixture();
        let desired = validated_fixture(18, true);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(91);
        let reconciliation_authority_digest = digest(92);
        let canonical_index_states = canonical_index_states(&desired, 107);
        let (_, prepared) = fixture.journal.prepare_validated(desired.clone()).unwrap();

        let binding = fixture
            .journal
            .bind_live_prepared_store_adapter_v1(&prepared)
            .unwrap();
        assert_eq!(binding.snapshot(), &desired.snapshot);

        let mut forged = prepared.clone();
        forged.owner_peer_id += 1;
        assert_eq!(
            fixture
                .journal
                .bind_live_prepared_store_adapter_v1(&forged)
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );

        let concurrent_terminal = fixture
            .journal
            .with_live_prepared_store_binding_v1(&prepared, |live_binding| {
                assert_eq!(live_binding, &binding);
                fixture
                    .journal
                    .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                        expected_journal_descriptor_digest: &descriptor_digest,
                        parent_descriptor_digest: &parent_descriptor_digest,
                        authenticated_owner_peer_id: 7,
                        consensus_authority_record_digest: &consensus_authority_record_digest,
                        reconciliation_authority_digest: &reconciliation_authority_digest,
                        canonical_index_states: &canonical_index_states,
                    })
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(
            concurrent_terminal,
            PrivateOramOwnerJournalError::ConcurrentMutation
        );

        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &reconciliation_authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();
        assert_eq!(
            fixture
                .journal
                .bind_live_prepared_store_adapter_v1(&prepared)
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn recovery_rebind_recomputes_exact_pair_and_holds_shared_lock() {
        let fixture = fixture();
        let desired = validated_fixture(119, true);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(120);
        let reconciliation_authority_digest = digest(121);
        let canonical_index_states = canonical_index_states(&desired, 122);
        let expected_snapshot = desired.snapshot.clone();
        let expected_prepared = prepared_token(&expected_snapshot.descriptor).unwrap();
        let projection = recovery_projection(&desired);
        fixture.journal.prepare_validated(desired).unwrap();

        let concurrent_terminal = fixture
            .journal
            .with_revalidated_recovery_prepared_v1(&projection, |binding| {
                assert_eq!(&binding.prepared, &expected_prepared);
                assert_eq!(binding.store_binding.snapshot(), &expected_snapshot);
                let rendered = format!("{binding:?}");
                assert!(!rendered.contains(&descriptor_digest));
                assert!(!rendered.contains("collection-119"));
                fixture
                    .journal
                    .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                        expected_journal_descriptor_digest: &descriptor_digest,
                        parent_descriptor_digest: &parent_descriptor_digest,
                        authenticated_owner_peer_id: 7,
                        consensus_authority_record_digest: &consensus_authority_record_digest,
                        reconciliation_authority_digest: &reconciliation_authority_digest,
                        canonical_index_states: &canonical_index_states,
                    })
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(
            concurrent_terminal,
            PrivateOramOwnerJournalError::ConcurrentMutation
        );

        let mut substitutions = Vec::new();
        let mut forged = projection.clone();
        forged.expected_owner_peer_id += 1;
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.parent_descriptor_digest = digest(123);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.parent_lease_acquired_record_digest = digest(124);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.mutation_id = digest(125);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.writer_fence += 1;
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.indexes.swap(0, 1);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.indexes[0].prepared_journal_digest = digest(126);
        substitutions.push(forged);
        let mut forged = projection.clone();
        forged.indexes[1].new_root_hash = digest(127);
        substitutions.push(forged);

        for forged in substitutions {
            let mut called = false;
            assert_eq!(
                fixture
                    .journal
                    .with_revalidated_recovery_prepared_v1(&forged, |_| called = true)
                    .unwrap_err(),
                PrivateOramOwnerJournalError::InvalidTransition
            );
            assert!(!called);
        }

        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &reconciliation_authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();
        assert_eq!(
            fixture
                .journal
                .with_revalidated_recovery_prepared_v1(&projection, |_| ())
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn recovery_rebind_requires_hnsw_result_pair() {
        let fixture = fixture();
        let desired = validated_fixture(120, false);
        let projection = recovery_projection(&desired);
        fixture.journal.prepare_validated(desired).unwrap();

        assert_eq!(
            fixture
                .journal
                .with_revalidated_recovery_prepared_v1(&projection, |_| ())
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn finalized_terminal_reopens_and_exact_replay_returns_same_token() {
        let fixture = fixture();
        let desired = validated_fixture(20, true);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(93);
        let reconciliation_authority_digest = digest(94);
        let canonical_index_states = canonical_index_states(&desired, 109);
        fixture.journal.prepare_validated(desired.clone()).unwrap();
        let context = PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &reconciliation_authority_digest,
            canonical_index_states: &canonical_index_states,
        };

        let (finalized, token) = fixture.journal.record_finalized(context).unwrap();
        let (replayed, replay_token) = fixture.journal.record_finalized(context).unwrap();
        let reopened = fixture.journal.inspect_structural().unwrap().unwrap();

        assert_eq!(finalized, replayed);
        assert_eq!(finalized, reopened);
        assert_eq!(token, replay_token);
        assert_eq!(
            finalized.terminal.as_ref().unwrap().phase,
            PrivateOramOwnerJournalPhaseV1::Finalized
        );
        assert_eq!(token.owner_peer_id(), 7);
        assert_eq!(token.journal_descriptor_digest(), descriptor_digest);
        assert_eq!(token.indexes().len(), 2);
        assert_eq!(
            token.indexes()[0].prepared_journal_digest(),
            prepared_token(&finalized.descriptor).unwrap().indexes()[0].prepared_journal_digest()
        );
        assert!(terminal_path(&fixture).join(TERMINAL_RECORD_FILE).exists());
        assert_eq!(
            fixture.journal.prepare_validated(desired).unwrap_err(),
            PrivateOramOwnerJournalError::ConcurrentMutation
        );
    }

    #[test]
    fn aborted_old_terminal_replays_and_rejects_finalize_substitution() {
        let fixture = fixture();
        let desired = validated_fixture(21, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(95);
        let abort_authority_digest = digest(96);
        let finalize_authority_digest = digest(97);
        let aborted_index_states = canonical_index_states(&desired, 111);
        let finalized_index_states = canonical_index_states(&desired, 112);
        fixture.journal.prepare_validated(desired).unwrap();
        let abort_context = PrivateOramOwnerJournalAbortOldContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &abort_authority_digest,
            canonical_index_states: &aborted_index_states,
        };

        let (aborted, token) = fixture.journal.record_aborted_old(abort_context).unwrap();
        let (replayed, replay_token) = fixture.journal.record_aborted_old(abort_context).unwrap();
        let finalize_context = PrivateOramOwnerJournalFinalizeContextV1 {
            expected_journal_descriptor_digest: &descriptor_digest,
            parent_descriptor_digest: &parent_descriptor_digest,
            authenticated_owner_peer_id: 7,
            consensus_authority_record_digest: &consensus_authority_record_digest,
            reconciliation_authority_digest: &finalize_authority_digest,
            canonical_index_states: &finalized_index_states,
        };

        assert_eq!(aborted, replayed);
        assert_eq!(token, replay_token);
        assert_eq!(
            aborted.terminal.as_ref().unwrap().phase,
            PrivateOramOwnerJournalPhaseV1::AbortedOld
        );
        assert_eq!(token.owner_peer_id(), 7);
        assert_eq!(token.indexes().len(), 1);
        assert_eq!(
            fixture
                .journal
                .record_finalized(finalize_context)
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn terminal_requires_exact_descriptor_parent_and_authenticated_owner() {
        let fixture = fixture();
        let desired = validated_fixture(22, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let wrong_digest = digest(98);
        let consensus_authority_record_digest = digest(99);
        let authority_digest = digest(100);
        let canonical_index_states = canonical_index_states(&desired, 113);
        fixture.journal.prepare_validated(desired).unwrap();

        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &wrong_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &authority_digest,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &wrong_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &authority_digest,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 8,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &authority_digest,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        assert!(!terminal_path(&fixture).exists());
    }

    #[test]
    fn terminal_requires_exact_authorities_and_canonical_index_states() {
        let fixture = fixture();
        let desired = validated_fixture(25, true);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(116);
        let reconciliation_authority_digest = digest(117);
        let canonical_index_states = canonical_index_states(&desired, 118);
        fixture.journal.prepare_validated(desired).unwrap();

        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &reconciliation_authority_digest,
                    canonical_index_states: &canonical_index_states[..1],
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        let mut wrong_identity = canonical_index_states.clone();
        wrong_identity[1].index_name.push_str("-wrong");
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &reconciliation_authority_digest,
                    canonical_index_states: &wrong_identity,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        assert!(!terminal_path(&fixture).exists());

        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &reconciliation_authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();

        let changed_consensus_authority = digest(119);
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &changed_consensus_authority,
                    reconciliation_authority_digest: &reconciliation_authority_digest,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        let changed_reconciliation_authority = digest(120);
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &changed_reconciliation_authority,
                    canonical_index_states: &canonical_index_states,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
        let mut changed_canonical_state = canonical_index_states;
        changed_canonical_state[0].canonical_state_digest = digest(121);
        assert_eq!(
            fixture
                .journal
                .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                    expected_journal_descriptor_digest: &descriptor_digest,
                    parent_descriptor_digest: &parent_descriptor_digest,
                    authenticated_owner_peer_id: 7,
                    consensus_authority_record_digest: &consensus_authority_record_digest,
                    reconciliation_authority_digest: &reconciliation_authority_digest,
                    canonical_index_states: &changed_canonical_state,
                })
                .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidTransition
        );
    }

    #[test]
    fn stranded_terminal_candidate_is_preserved_but_never_adopted() {
        let fixture = fixture();
        let desired = validated_fixture(23, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(101);
        let authority_digest = digest(102);
        let canonical_index_states = canonical_index_states(&desired, 114);
        fixture.journal.prepare_validated(desired).unwrap();
        let stranded = active_path(&fixture)
            .join(ACTIVE_TEMP_DIR)
            .join(".terminal-candidate-stranded");
        create_private_directory(&stranded).unwrap();

        let structural = fixture.journal.inspect_structural().unwrap().unwrap();
        assert!(structural.terminal.is_none());
        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();

        assert!(stranded.exists());
        assert!(terminal_path(&fixture).exists());
    }

    #[test]
    fn terminal_record_tamper_fails_closed() {
        let fixture = fixture();
        let desired = validated_fixture(24, false);
        let descriptor_digest = desired.snapshot.descriptor.descriptor_digest.clone();
        let parent_descriptor_digest = desired.snapshot.descriptor.parent_descriptor_digest.clone();
        let consensus_authority_record_digest = digest(103);
        let authority_digest = digest(104);
        let canonical_index_states = canonical_index_states(&desired, 115);
        fixture.journal.prepare_validated(desired).unwrap();
        fixture
            .journal
            .record_finalized(PrivateOramOwnerJournalFinalizeContextV1 {
                expected_journal_descriptor_digest: &descriptor_digest,
                parent_descriptor_digest: &parent_descriptor_digest,
                authenticated_owner_peer_id: 7,
                consensus_authority_record_digest: &consensus_authority_record_digest,
                reconciliation_authority_digest: &authority_digest,
                canonical_index_states: &canonical_index_states,
            })
            .unwrap();
        let record_path = terminal_path(&fixture).join(TERMINAL_RECORD_FILE);
        let mut bytes = fs::read(&record_path).unwrap();
        bytes[0] ^= 1;
        fs::write(record_path, bytes).unwrap();

        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exclusive_root_lock_rejects_concurrent_prepare() {
        let fixture = fixture();
        let root = fixture.journal.ensure_root().unwrap();
        let _lock = lock_private_journal_root(&root).unwrap();

        assert_eq!(
            fixture
                .journal
                .prepare_validated(validated_fixture(18, false))
                .unwrap_err(),
            PrivateOramOwnerJournalError::ConcurrentMutation
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn structural_read_rejects_concurrent_terminal_writer() {
        let fixture = fixture();
        fixture
            .journal
            .prepare_validated(validated_fixture(26, false))
            .unwrap();
        let root = open_private_directory(&fixture.journal.root).unwrap();
        let _lock = lock_private_journal_root(&root).unwrap();

        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::ConcurrentMutation
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_hardlink_and_bad_mode_fail_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let symlink_fixture = fixture();
        symlink_fixture
            .journal
            .prepare_validated(validated_fixture(10, false))
            .unwrap();
        let symlink_state = active_path(&symlink_fixture).join(STATE_FILE);
        let outside = symlink_fixture.hnsw_root.join("outside-state");
        fs::rename(&symlink_state, &outside).unwrap();
        symlink(&outside, &symlink_state).unwrap();
        assert_eq!(
            symlink_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let hardlink_fixture = fixture();
        hardlink_fixture
            .journal
            .prepare_validated(validated_fixture(11, false))
            .unwrap();
        let hardlink_state = active_path(&hardlink_fixture).join(STATE_FILE);
        fs::hard_link(
            &hardlink_state,
            hardlink_fixture.hnsw_root.join("state-hardlink"),
        )
        .unwrap();
        assert_eq!(
            hardlink_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let mode_fixture = fixture();
        mode_fixture
            .journal
            .prepare_validated(validated_fixture(12, false))
            .unwrap();
        let mode_state = active_path(&mode_fixture).join(STATE_FILE);
        fs::set_permissions(&mode_state, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            mode_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminal_symlink_hardlink_bad_mode_and_oversize_fail_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let symlink_fixture = fixture();
        prepare_and_finalize(&symlink_fixture, 27);
        let symlink_record = terminal_path(&symlink_fixture).join(TERMINAL_RECORD_FILE);
        let outside = symlink_fixture.hnsw_root.join("outside-terminal-record");
        fs::rename(&symlink_record, &outside).unwrap();
        symlink(&outside, &symlink_record).unwrap();
        assert_eq!(
            symlink_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let hardlink_fixture = fixture();
        prepare_and_finalize(&hardlink_fixture, 28);
        let hardlink_record = terminal_path(&hardlink_fixture).join(TERMINAL_RECORD_FILE);
        fs::hard_link(
            &hardlink_record,
            hardlink_fixture.hnsw_root.join("terminal-record-hardlink"),
        )
        .unwrap();
        assert_eq!(
            hardlink_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let mode_fixture = fixture();
        prepare_and_finalize(&mode_fixture, 29);
        let mode_record = terminal_path(&mode_fixture).join(TERMINAL_RECORD_FILE);
        fs::set_permissions(&mode_record, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            mode_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );

        let oversized_fixture = fixture();
        prepare_and_finalize(&oversized_fixture, 30);
        let oversized_record = terminal_path(&oversized_fixture).join(TERMINAL_RECORD_FILE);
        OpenOptions::new()
            .write(true)
            .open(&oversized_record)
            .unwrap()
            .set_len(MAX_TERMINAL_RECORD_BYTES + 1)
            .unwrap();
        assert_eq!(
            oversized_fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminal_candidate_allows_partial_record_but_rejects_unknown_entry() {
        use fs_err::os::unix::fs::OpenOptionsExt as _;

        let fixture = fixture();
        fixture
            .journal
            .prepare_validated(validated_fixture(31, false))
            .unwrap();
        let temp = active_path(&fixture).join(ACTIVE_TEMP_DIR);
        let partial = temp.join(".terminal-candidate-partial");
        create_private_directory(&partial).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(partial.join(TERMINAL_RECORD_FILE))
            .unwrap();
        assert!(
            fixture
                .journal
                .inspect_structural()
                .unwrap()
                .unwrap()
                .terminal
                .is_none()
        );

        let unknown = temp.join(".terminal-candidate-unknown");
        create_private_directory(&unknown).unwrap();
        fs::write(unknown.join("unexpected"), b"x").unwrap();
        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn unknown_root_entry_fails_closed() {
        let fixture = fixture();
        fixture.journal.ensure_root().unwrap();
        fs::write(fixture.journal.root.join("unexpected"), b"x").unwrap();

        assert_eq!(
            fixture.journal.inspect_structural().unwrap_err(),
            PrivateOramOwnerJournalError::Corrupt
        );
    }

    #[test]
    fn debug_and_errors_redact_sensitive_values() {
        let desired = validated_fixture(13, true);
        let debug = format!("{:?}", desired.snapshot);
        let error_debug = format!("{:?}", PrivateOramOwnerJournalError::Corrupt);
        let error_display = PrivateOramOwnerJournalError::Corrupt.to_string();

        assert!(!debug.contains(&desired.snapshot.descriptor.collection_id));
        assert!(!debug.contains(&desired.snapshot.descriptor.mutation_id));
        assert!(!debug.contains(
            &desired.snapshot.descriptor.indexes[0].ordered_bucket_refs[0].ciphertext_sha256
        ));
        assert!(!error_debug.contains("collection-13"));
        assert!(!error_display.contains("collection-13"));
    }
}
