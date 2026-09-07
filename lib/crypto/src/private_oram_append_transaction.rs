use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::private_hnsw_client::{
    PrivateHnswBucketAeadBaseContext, PrivateHnswClientError, PrivateHnswClientKeys,
    PrivateHnswEncryptedPathBatch, PrivateHnswNodeBlockPlaintext, PrivateHnswOramClientConfig,
    PrivateHnswOramClientState, PrivateHnswOramClientStateSnapshot, PrivateHnswOramMerkleProof,
    PrivateHnswOramPlaintextBucket, PrivateHnswVectorEncoding, decode_private_hnsw_oram_leaf_label,
    encode_private_hnsw_node_block, encode_private_hnsw_oram_leaf_label,
    evict_private_hnsw_oram_loaded_path, load_private_hnsw_oram_path_for_append,
    open_private_hnsw_oram_verified_path_batch, private_hnsw_oram_bucket_count,
    private_hnsw_oram_bucket_ids_for_leaf, remap_private_hnsw_oram_stash_block,
    rewrite_private_hnsw_oram_stash_block, seal_private_hnsw_oram_plaintext_bucket,
    validate_private_hnsw_upload_bucket,
};
use crate::private_hnsw_oram::{PrivateHnswOramBucket, private_hnsw_oram_bucket_ciphertext_bytes};
use crate::private_oram_append_client::{
    PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION, PrivateOramAppendClientCheckpointV2,
    PrivateOramAppendClientError, PrivateOramAppendClientIndexCheckpointV2,
    PrivateOramAppendLevel0HnswGraphDeltaV2, PrivateOramAppendLevel0PointV2,
    PrivateOramAppendMerklePatchLeafV1, PrivateOramAppendMerklePatchProofV1,
    apply_private_oram_append_sparse_merkle_patch_v1, plan_private_oram_level0_hnsw_graph_delta_v2,
    private_oram_append_client_checkpoint_plaintext_v3_digest,
    private_oram_append_hnsw_client_state_v3_digest, push_hnsw_node_block_v3,
    validate_private_oram_append_client_checkpoint_v2,
};
use crate::private_oram_mutation::{
    PrivateOramAppendBucketRefV1, PrivateOramAppendIndexWritebackV1,
    PrivateOramAppendReadTranscriptDigestInput, PrivateOramAppendReadWindowV1,
    PrivateOramAppendWritebackDigestInput, PrivateOramImmutableIndexParamsV2,
    PrivateOramImmutableManifestV2, PrivateOramIndexKindV2, PrivateOramMutationError,
    PrivateOramObservedReadTranscriptV1, PrivateOramSignedStateV2,
    private_oram_append_read_transcript_v1, private_oram_append_writeback_v1_digest,
    private_oram_immutable_manifest_v2_digest, private_oram_signed_state_v2_digest,
};
use crate::private_result_oram::PrivateResultOramError;

pub const PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V2_VERSION: u16 = 2;
pub const PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION: u16 = 3;
pub const PRIVATE_ORAM_APPEND_HNSW_ATTEMPT_V2_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-hnsw-attempt/v2";
pub const PRIVATE_ORAM_APPEND_HNSW_ATTEMPT_V3_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-hnsw-attempt/v3";
pub const PRIVATE_ORAM_APPEND_HNSW_PREPARED_COMMIT_V2_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-hnsw-prepared-commit/v2";
pub const PRIVATE_ORAM_APPEND_HNSW_PREPARED_COMMIT_V3_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-hnsw-prepared-commit/v3";
pub const PRIVATE_ORAM_APPEND_HNSW_PREPARED_COMMIT_V4_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-hnsw-prepared-commit/v4";
pub const PRIVATE_ORAM_APPEND_HNSW_GRAPH_DELTA_V3_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-hnsw-graph-delta-digest/v3";

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramAppendTransactionError {
    #[error("private ORAM append transaction client operation failed")]
    Client(#[source] PrivateOramAppendClientError),
    #[error("private ORAM append transaction HNSW operation failed")]
    Hnsw(#[source] PrivateHnswClientError),
    #[error("private ORAM append transaction result operation failed")]
    Result(#[source] PrivateResultOramError),
    #[error("private ORAM append transaction contract operation failed")]
    Mutation(#[source] PrivateOramMutationError),
    #[error("private ORAM append transaction input is invalid")]
    InvalidInput(&'static str),
    #[error("private ORAM append transaction topology is unsupported")]
    UnsupportedTopology,
    #[error("private ORAM append transaction already has a pending read window")]
    WindowPending,
    #[error("private ORAM append transaction has no pending read window")]
    WindowNotPending,
    #[error("private ORAM append transaction read window sequence does not match")]
    WindowSequenceMismatch,
    #[error("private ORAM append transaction recovery marker does not match")]
    RecoveryMarkerMismatch,
    #[error(
        "private ORAM append transaction response bucket sequence does not match the read window"
    )]
    ResponseBucketSequenceMismatch,
    #[error("private ORAM append transaction proof set is inconsistent")]
    ProofSetMismatch,
    #[error("private ORAM append transaction exceeds the client stash bound")]
    StashBoundExceeded,
    #[error("private ORAM append transaction is incomplete")]
    Incomplete,
    #[error("private ORAM append transaction is poisoned and requires recovery")]
    RecoveryRequired,
}

impl Debug for PrivateOramAppendTransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(_) => f.write_str("Client([redacted])"),
            Self::Hnsw(_) => f.write_str("Hnsw([redacted])"),
            Self::Result(_) => f.write_str("Result([redacted])"),
            Self::Mutation(_) => f.write_str("Mutation([redacted])"),
            Self::InvalidInput(field) => f.debug_tuple("InvalidInput").field(field).finish(),
            Self::UnsupportedTopology => f.write_str("UnsupportedTopology"),
            Self::WindowPending => f.write_str("WindowPending"),
            Self::WindowNotPending => f.write_str("WindowNotPending"),
            Self::WindowSequenceMismatch => f.write_str("WindowSequenceMismatch"),
            Self::RecoveryMarkerMismatch => f.write_str("RecoveryMarkerMismatch"),
            Self::ResponseBucketSequenceMismatch => f.write_str("ResponseBucketSequenceMismatch"),
            Self::ProofSetMismatch => f.write_str("ProofSetMismatch"),
            Self::StashBoundExceeded => f.write_str("StashBoundExceeded"),
            Self::Incomplete => f.write_str("Incomplete"),
            Self::RecoveryRequired => f.write_str("RecoveryRequired"),
        }
    }
}

impl From<PrivateOramAppendClientError> for PrivateOramAppendTransactionError {
    fn from(error: PrivateOramAppendClientError) -> Self {
        Self::Client(error)
    }
}

impl From<PrivateHnswClientError> for PrivateOramAppendTransactionError {
    fn from(error: PrivateHnswClientError) -> Self {
        Self::Hnsw(error)
    }
}

impl From<PrivateResultOramError> for PrivateOramAppendTransactionError {
    fn from(error: PrivateResultOramError) -> Self {
        Self::Result(error)
    }
}

impl From<PrivateOramMutationError> for PrivateOramAppendTransactionError {
    fn from(error: PrivateOramMutationError) -> Self {
        Self::Mutation(error)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramAppendHnswTransactionPlanV2 {
    pub index_name: String,
    pub mutation_id: String,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub paths_per_window: u32,
    pub candidate_node_ids: Vec<[u8; 32]>,
    pub candidate_remap_leaves: Vec<u64>,
    pub rewrite_remap_leaves: Vec<u64>,
    pub padding_leaves: Vec<u64>,
}

impl Debug for PrivateOramAppendHnswTransactionPlanV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswTransactionPlanV2")
            .field("index_name", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("paths_per_window", &self.paths_per_window)
            .field("candidate_count", &self.candidate_node_ids.len())
            .field("candidate_remap_count", &self.candidate_remap_leaves.len())
            .field("rewrite_remap_count", &self.rewrite_remap_leaves.len())
            .field("padding_leaf_count", &self.padding_leaves.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramAppendHnswAttemptDigestInput<'a> {
    pub manifest_digest: &'a str,
    pub old_state_digest: &'a str,
    pub checkpoint: &'a PrivateOramAppendClientCheckpointV2,
    pub point: &'a PrivateOramAppendLevel0PointV2,
    pub plan: &'a PrivateOramAppendHnswTransactionPlanV2,
}

impl Debug for PrivateOramAppendHnswAttemptDigestInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswAttemptDigestInput")
            .field("manifest_digest", &"[redacted]")
            .field("old_state_digest", &"[redacted]")
            .field("checkpoint", &"[redacted]")
            .field("point", &"[redacted]")
            .field("plan", &self.plan)
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramAppendHnswAttemptDigestInputV3<'a> {
    pub manifest_digest: &'a str,
    pub old_state_digest: &'a str,
    pub checkpoint: &'a PrivateOramAppendClientCheckpointV2,
    pub point: &'a PrivateOramAppendLevel0PointV2,
    pub plan: &'a PrivateOramAppendHnswTransactionPlanV2,
}

impl Debug for PrivateOramAppendHnswAttemptDigestInputV3<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswAttemptDigestInputV3")
            .field("manifest_digest", &"[redacted]")
            .field("old_state_digest", &"[redacted]")
            .field("checkpoint", &"[redacted]")
            .field("point", &"[redacted]")
            .field("plan", &self.plan)
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramAppendHnswPreparedCommitDigestInput<'a> {
    pub attempt_digest: &'a str,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub read_transcript_digest: &'a str,
    pub writeback_digest: &'a str,
    pub next_client_state: &'a PrivateHnswOramClientStateSnapshot,
}

impl Debug for PrivateOramAppendHnswPreparedCommitDigestInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswPreparedCommitDigestInput")
            .field("attempt_digest", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("read_transcript_digest", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("next_client_state", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramAppendHnswPreparedCommitDigestInputV3<'a> {
    pub attempt_digest: &'a str,
    pub graph_delta: &'a PrivateOramAppendLevel0HnswGraphDeltaV2,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub read_transcript_digest: &'a str,
    pub writeback_digest: &'a str,
    pub next_client_state: &'a PrivateHnswOramClientStateSnapshot,
}

impl Debug for PrivateOramAppendHnswPreparedCommitDigestInputV3<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswPreparedCommitDigestInputV3")
            .field("attempt_digest", &"[redacted]")
            .field("graph_delta", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("read_transcript_digest", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("next_client_state", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramAppendHnswPreparedCommitDigestInputV4<'a> {
    pub attempt_digest: &'a str,
    pub source_checkpoint_digest: &'a str,
    pub graph_delta: &'a PrivateOramAppendLevel0HnswGraphDeltaV2,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub read_transcript_digest: &'a str,
    pub writeback_digest: &'a str,
    pub next_client_state: &'a PrivateHnswOramClientStateSnapshot,
}

impl Debug for PrivateOramAppendHnswPreparedCommitDigestInputV4<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswPreparedCommitDigestInputV4")
            .field("attempt_digest", &"[redacted]")
            .field("source_checkpoint_digest", &"[redacted]")
            .field("graph_delta", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("read_transcript_digest", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("next_client_state", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendRecoveryMarkerV2 {
    pub version: u16,
    pub collection_id: String,
    pub manifest_digest: String,
    pub mutation_id: String,
    pub old_state_digest: String,
    pub attempt_digest: String,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub requested_window_count: u32,
    pub accepted_window_count: u32,
    pub observed_read_path_count: u32,
    pub phase: PrivateOramAppendRecoveryPhaseV2,
    pub prepared_commit_digest: Option<String>,
}

impl Debug for PrivateOramAppendRecoveryMarkerV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendRecoveryMarkerV2")
            .field("version", &self.version)
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("old_state_digest", &"[redacted]")
            .field("attempt_digest", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("requested_window_count", &self.requested_window_count)
            .field("accepted_window_count", &self.accepted_window_count)
            .field("observed_read_path_count", &self.observed_read_path_count)
            .field("phase", &self.phase)
            .field("prepared_commit_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendRecoveryMarkerV3 {
    pub version: u16,
    pub collection_id: String,
    pub manifest_digest: String,
    pub mutation_id: String,
    pub old_state_digest: String,
    pub attempt_digest: String,
    pub index_kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub requested_window_count: u32,
    pub accepted_window_count: u32,
    pub observed_read_path_count: u32,
    pub phase: PrivateOramAppendRecoveryPhaseV2,
    pub prepared_commit_digest: Option<String>,
}

impl Debug for PrivateOramAppendRecoveryMarkerV3 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendRecoveryMarkerV3")
            .field("version", &self.version)
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("old_state_digest", &"[redacted]")
            .field("attempt_digest", &"[redacted]")
            .field("index_kind", &self.index_kind)
            .field("index_name", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("requested_window_count", &self.requested_window_count)
            .field("accepted_window_count", &self.accepted_window_count)
            .field("observed_read_path_count", &self.observed_read_path_count)
            .field("phase", &self.phase)
            .field("prepared_commit_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramAppendRecoveryPhaseV2 {
    WindowIssued,
    Poisoned,
    PreparedCommit,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramAppendHnswReadRequestV2 {
    pub window: PrivateOramAppendReadWindowV1,
    pub recovery_marker: PrivateOramAppendRecoveryMarkerV3,
}

impl Debug for PrivateOramAppendHnswReadRequestV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswReadRequestV2")
            .field("window", &self.window)
            .field("recovery_marker", &self.recovery_marker)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateOramAppendHnswTransactionOutputV2 {
    pub source_checkpoint_digest: String,
    pub graph_delta: PrivateOramAppendLevel0HnswGraphDeltaV2,
    pub read_transcript: PrivateOramObservedReadTranscriptV1,
    pub writeback: PrivateOramAppendIndexWritebackV1,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub next_client_state: PrivateHnswOramClientStateSnapshot,
    pub ordered_encrypted_buckets: Vec<PrivateHnswOramBucket>,
    pub final_encrypted_buckets: Vec<PrivateHnswOramBucket>,
    pub merkle_patch_proof: PrivateOramAppendMerklePatchProofV1,
    pub recovery_marker: PrivateOramAppendRecoveryMarkerV3,
}

impl Debug for PrivateOramAppendHnswTransactionOutputV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswTransactionOutputV2")
            .field("source_checkpoint_digest", &"[redacted]")
            .field("graph_delta", &"[redacted]")
            .field("read_transcript", &self.read_transcript)
            .field("writeback", &self.writeback)
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("next_client_state", &self.next_client_state)
            .field(
                "ordered_encrypted_bucket_count",
                &self.ordered_encrypted_buckets.len(),
            )
            .field(
                "final_encrypted_bucket_count",
                &self.final_encrypted_buckets.len(),
            )
            .field("merkle_patch_proof", &"[redacted]")
            .field("recovery_marker", &self.recovery_marker)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateOramAppendHnswTransactionProgressV2 {
    pub accepted_read_path_count: u32,
    pub accepted_window_count: u32,
    pub prepared_write_bucket_count: usize,
    pub plaintext_overlay_bucket_count: usize,
    pub client_stash_block_count: usize,
}

#[derive(Clone)]
enum PrivateOramAppendHnswPathActionV2 {
    Candidate {
        node_id: [u8; 32],
        remap_leaf: u64,
    },
    Rewrite {
        node_id: [u8; 32],
        remap_leaf: u64,
        previous: Box<PrivateHnswNodeBlockPlaintext>,
        replacement: Box<PrivateHnswNodeBlockPlaintext>,
    },
    /// Reads and evicts the independent padding path `leaf` while the new block enters the
    /// stash under the point's own `initial_leaf` position.
    Insert {
        leaf: u64,
    },
    Padding {
        leaf: u64,
    },
}

impl PrivateOramAppendHnswPathActionV2 {
    fn leaf(
        &self,
        state: &PrivateHnswOramClientState,
    ) -> Result<u64, PrivateOramAppendTransactionError> {
        match self {
            Self::Candidate { node_id, .. } | Self::Rewrite { node_id, .. } => state
                .position(node_id)
                .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                    "position_map",
                )),
            Self::Insert { leaf } | Self::Padding { leaf } => Ok(*leaf),
        }
    }
}

/// One served path of a read window and the actions applied on its single load/evict cycle.
///
/// Actions whose current leaf coincides within a window share one path read: every member's
/// block is on that path (or already stashed), so one load and one eviction serve all of them.
/// The slot a merged action would have used reads an independent padding leaf instead, so a
/// window always carries `paths_per_window` distinct paths and the server never learns whether
/// two secret positions collided.
#[derive(Clone)]
struct PrivateOramAppendHnswWindowSlotV2 {
    leaf: u64,
    actions: Vec<PrivateOramAppendHnswPathActionV2>,
}

enum PrivateOramAppendHnswTransactionStatusV2 {
    Ready,
    MarkerPrepared {
        marker: Box<PrivateOramAppendRecoveryMarkerV3>,
        window: PrivateOramAppendReadWindowV1,
        slots: Vec<PrivateOramAppendHnswWindowSlotV2>,
    },
    Awaiting {
        window: PrivateOramAppendReadWindowV1,
        slots: Vec<PrivateOramAppendHnswWindowSlotV2>,
    },
    Poisoned,
}

pub struct PrivateOramAppendHnswTransactionV2 {
    manifest: PrivateOramImmutableManifestV2,
    old_state: PrivateOramSignedStateV2,
    checkpoint: PrivateOramAppendClientCheckpointV2,
    point: PrivateOramAppendLevel0PointV2,
    plan: PrivateOramAppendHnswTransactionPlanV2,
    manifest_digest: String,
    old_state_digest: String,
    source_checkpoint_digest: String,
    legacy_attempt_digest: String,
    attempt_digest: String,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    bucket_count: u64,
    fixed_read_path_count: u32,
    fixed_write_bucket_count: usize,
    max_client_stash_blocks: usize,
    config: PrivateHnswOramClientConfig,
    key_id: String,
    rk_id: String,
    rk_epoch: u64,
    working_state: PrivateHnswOramClientState,
    status: PrivateOramAppendHnswTransactionStatusV2,
    actions: VecDeque<PrivateOramAppendHnswPathActionV2>,
    candidate_phase_path_count: u32,
    candidate_action_count: usize,
    candidate_blocks: Vec<PrivateHnswNodeBlockPlaintext>,
    graph_delta: Option<PrivateOramAppendLevel0HnswGraphDeltaV2>,
    accepted_windows: Vec<PrivateOramAppendReadWindowV1>,
    requested_window_count: u32,
    accepted_path_count: u32,
    padding_leaf_offset: usize,
    inserted: bool,
    plaintext_overlay: BTreeMap<u64, PrivateHnswOramPlaintextBucket>,
    proof_leaves: BTreeMap<u64, PrivateOramAppendMerklePatchLeafV1>,
    ordered_refs: Vec<PrivateOramAppendBucketRefV1>,
    ordered_encrypted_buckets: Vec<PrivateHnswOramBucket>,
    final_encrypted_buckets: BTreeMap<u64, PrivateHnswOramBucket>,
}

#[derive(Clone)]
struct PrivateOramAppendHnswWindowSnapshotV2 {
    working_state: PrivateHnswOramClientState,
    actions: VecDeque<PrivateOramAppendHnswPathActionV2>,
    candidate_blocks: Vec<PrivateHnswNodeBlockPlaintext>,
    graph_delta: Option<PrivateOramAppendLevel0HnswGraphDeltaV2>,
    accepted_windows: Vec<PrivateOramAppendReadWindowV1>,
    accepted_path_count: u32,
    padding_leaf_offset: usize,
    inserted: bool,
    plaintext_overlay: BTreeMap<u64, PrivateHnswOramPlaintextBucket>,
    proof_leaves: BTreeMap<u64, PrivateOramAppendMerklePatchLeafV1>,
    ordered_refs: Vec<PrivateOramAppendBucketRefV1>,
    ordered_encrypted_buckets: Vec<PrivateHnswOramBucket>,
    final_encrypted_buckets: BTreeMap<u64, PrivateHnswOramBucket>,
}

impl Debug for PrivateOramAppendHnswTransactionV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswTransactionV2")
            .field("collection_id", &"[redacted]")
            .field("index_name", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("fixed_read_path_count", &self.fixed_read_path_count)
            .field("accepted_path_count", &self.accepted_path_count)
            .field("requested_window_count", &self.requested_window_count)
            .field("accepted_window_count", &self.accepted_windows.len())
            .field("pending_action_count", &self.actions.len())
            .field("has_graph_delta", &self.graph_delta.is_some())
            .field("inserted", &self.inserted)
            .field("requires_recovery", &self.requires_recovery())
            .field("poisoned", &self.is_poisoned())
            .finish()
    }
}

impl PrivateOramAppendHnswTransactionV2 {
    pub fn begin(
        manifest: &PrivateOramImmutableManifestV2,
        old_state: &PrivateOramSignedStateV2,
        checkpoint: &PrivateOramAppendClientCheckpointV2,
        point: PrivateOramAppendLevel0PointV2,
        plan: PrivateOramAppendHnswTransactionPlanV2,
    ) -> Result<Self, PrivateOramAppendTransactionError> {
        validate_private_oram_append_client_checkpoint_v2(checkpoint, manifest, old_state)?;
        validate_base64url_32(&plan.mutation_id, "mutation_id")?;
        validate_base64url_32(&plan.writer_lease_digest, "writer_lease_digest")?;
        if plan.writer_fence == 0
            || plan.paths_per_window == 0
            || plan.candidate_node_ids.len() != plan.candidate_remap_leaves.len()
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput("plan"));
        }

        let hnsw_offsets = manifest
            .indexes
            .iter()
            .enumerate()
            .filter_map(|(offset, index)| {
                (index.kind() == PrivateOramIndexKindV2::Hnsw).then_some(offset)
            })
            .collect::<Vec<_>>();
        let result_count = manifest
            .indexes
            .iter()
            .filter(|index| index.kind() == PrivateOramIndexKindV2::Result)
            .count();
        if hnsw_offsets.len() != 1 || result_count > 1 || manifest.indexes.len() > 2 {
            return Err(PrivateOramAppendTransactionError::UnsupportedTopology);
        }
        let index_offset = hnsw_offsets[0];
        let manifest_index = &manifest.indexes[index_offset];
        if manifest_index.index_name != plan.index_name {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "index_name",
            ));
        }
        let (
            key_id,
            rk_id,
            rk_epoch,
            hnsw,
            oram,
            max_neighbor_rewrites,
            checkpoint_state,
            checkpoint_records_empty,
        ) = match (&manifest_index.params, &checkpoint.indexes[index_offset]) {
            (
                PrivateOramImmutableIndexParamsV2::Hnsw {
                    key_id,
                    rk_id,
                    rk_epoch,
                    hnsw,
                    oram,
                    max_neighbor_rewrites,
                    ..
                },
                PrivateOramAppendClientIndexCheckpointV2::Hnsw {
                    index_name,
                    state,
                    records,
                    ..
                },
            ) if index_name == &plan.index_name => (
                key_id.clone(),
                rk_id.clone(),
                *rk_epoch,
                hnsw,
                oram,
                *max_neighbor_rewrites,
                state,
                records.is_empty(),
            ),
            _ => return Err(PrivateOramAppendTransactionError::UnsupportedTopology),
        };
        let state_index = &old_state.indexes[index_offset];
        let old_epoch = state_index.index_epoch;
        let new_epoch =
            old_epoch
                .checked_add(1)
                .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                    "index_epoch",
                ))?;
        let bucket_count = private_hnsw_oram_bucket_count(oram.tree_height)?;
        if bucket_count != manifest_index.capacity.bucket_count {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "bucket_count",
            ));
        }
        let fixed_read_path_count = manifest_index.capacity.fixed_append_read_path_count;
        let paths_per_window = plan.paths_per_window;
        if fixed_read_path_count == 0
            || !fixed_read_path_count.is_multiple_of(paths_per_window)
            || paths_per_window > fixed_read_path_count
            || paths_per_window != oram.path_batch_size
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "paths_per_window",
            ));
        }
        let expected_write_count = usize::try_from(fixed_read_path_count)
            .ok()
            .and_then(|count| {
                usize::try_from(oram.tree_height)
                    .ok()
                    .and_then(|height| count.checked_mul(height + 1))
            })
            .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                "fixed_write_bucket_count",
            ))?;
        let fixed_write_bucket_count = usize::try_from(
            manifest_index.capacity.fixed_append_write_bucket_count,
        )
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("fixed_write_bucket_count"))?;
        if fixed_write_bucket_count != expected_write_count {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "fixed_write_bucket_count",
            ));
        }
        let max_neighbor_rewrites = usize::try_from(max_neighbor_rewrites).map_err(|_| {
            PrivateOramAppendTransactionError::InvalidInput("max_neighbor_rewrites")
        })?;
        if plan.rewrite_remap_leaves.len() != max_neighbor_rewrites
            || plan.padding_leaves.len()
                != usize::try_from(fixed_read_path_count).map_err(|_| {
                    PrivateOramAppendTransactionError::InvalidInput("padding_leaves")
                })?
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "fixed_leaf_schedule",
            ));
        }

        let config = PrivateHnswOramClientConfig {
            tree_height: oram.tree_height,
            bucket_size: usize::try_from(oram.bucket_size)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("oram"))?,
            block_size_bytes: usize::try_from(oram.block_size_bytes)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("oram"))?,
            fixed_neighbor_slots: usize::try_from(hnsw.fixed_neighbor_slots)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("hnsw"))?,
        };
        let mut unique_candidates = BTreeSet::new();
        for node_id in &plan.candidate_node_ids {
            if *node_id == [0; 32] || !unique_candidates.insert(*node_id) {
                return Err(PrivateOramAppendTransactionError::InvalidInput(
                    "candidate_node_ids",
                ));
            }
        }
        for leaf in plan
            .candidate_remap_leaves
            .iter()
            .chain(&plan.rewrite_remap_leaves)
            .chain(&plan.padding_leaves)
            .chain(std::iter::once(&point.initial_leaf))
        {
            encode_private_hnsw_oram_leaf_label(*leaf, config.tree_height)?;
        }
        if checkpoint_records_empty != plan.candidate_node_ids.is_empty() {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "candidate_node_ids",
            ));
        }
        match plan_private_oram_level0_hnsw_graph_delta_v2(
            manifest,
            old_state,
            checkpoint,
            &plan.index_name,
            &point,
            &[],
            0,
        ) {
            Ok(_) if checkpoint_records_empty => {}
            Err(PrivateOramAppendClientError::AppendCandidateMismatch)
                if !checkpoint_records_empty => {}
            Ok(_) | Err(PrivateOramAppendClientError::AppendCandidateMismatch) => {
                return Err(PrivateOramAppendTransactionError::InvalidInput(
                    "candidate_node_ids",
                ));
            }
            Err(error) => return Err(error.into()),
        }

        let working_state = PrivateHnswOramClientState::from_snapshot(checkpoint_state)?;
        if plan
            .candidate_node_ids
            .iter()
            .any(|node_id| working_state.position(node_id).is_none())
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "candidate_node_ids",
            ));
        }
        let max_client_stash_blocks =
            usize::try_from(manifest_index.capacity.max_client_stash_blocks).map_err(|_| {
                PrivateOramAppendTransactionError::InvalidInput("max_client_stash_blocks")
            })?;
        if working_state.stash_len() > max_client_stash_blocks {
            return Err(PrivateOramAppendTransactionError::StashBoundExceeded);
        }

        let candidate_count = u32::try_from(plan.candidate_node_ids.len())
            .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("candidate_node_ids"))?;
        let candidate_phase_path_count = if candidate_count == 0 {
            0
        } else {
            candidate_count
                .checked_add(paths_per_window - 1)
                .and_then(|count| count.checked_div(paths_per_window))
                .and_then(|windows| windows.checked_mul(paths_per_window))
                .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                    "candidate_path_count",
                ))?
        };
        let candidate_budget = fixed_read_path_count
            .checked_sub(
                u32::try_from(max_neighbor_rewrites)
                    .ok()
                    .and_then(|count| count.checked_add(1))
                    .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                        "fixed_read_path_count",
                    ))?,
            )
            .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                "fixed_read_path_count",
            ))?;
        if candidate_phase_path_count > candidate_budget {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "candidate_path_count",
            ));
        }

        let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
        let old_state_digest = private_oram_signed_state_v2_digest(old_state)?;
        let source_checkpoint_digest =
            private_oram_append_client_checkpoint_plaintext_v3_digest(checkpoint)?;
        let legacy_attempt_digest =
            private_oram_append_hnsw_attempt_v2_digest(PrivateOramAppendHnswAttemptDigestInput {
                manifest_digest: &manifest_digest,
                old_state_digest: &old_state_digest,
                checkpoint,
                point: &point,
                plan: &plan,
            })?;
        let attempt_digest = private_oram_append_hnsw_attempt_v3_digest(
            PrivateOramAppendHnswAttemptDigestInputV3 {
                manifest_digest: &manifest_digest,
                old_state_digest: &old_state_digest,
                checkpoint,
                point: &point,
                plan: &plan,
            },
        )?;
        let mut transaction = Self {
            manifest: manifest.clone(),
            old_state: old_state.clone(),
            checkpoint: checkpoint.clone(),
            point,
            plan,
            manifest_digest,
            old_state_digest,
            source_checkpoint_digest,
            legacy_attempt_digest,
            attempt_digest,
            old_epoch,
            new_epoch,
            old_root_hash: state_index.root_hash.clone(),
            bucket_count,
            fixed_read_path_count,
            fixed_write_bucket_count,
            max_client_stash_blocks,
            config,
            key_id,
            rk_id,
            rk_epoch,
            working_state,
            status: PrivateOramAppendHnswTransactionStatusV2::Ready,
            actions: VecDeque::new(),
            candidate_phase_path_count,
            candidate_action_count: 0,
            candidate_blocks: Vec::new(),
            graph_delta: None,
            accepted_windows: Vec::new(),
            requested_window_count: 0,
            accepted_path_count: 0,
            padding_leaf_offset: 0,
            inserted: false,
            plaintext_overlay: BTreeMap::new(),
            proof_leaves: BTreeMap::new(),
            ordered_refs: Vec::new(),
            ordered_encrypted_buckets: Vec::new(),
            final_encrypted_buckets: BTreeMap::new(),
        };
        transaction.schedule_candidate_phase()?;
        if candidate_phase_path_count == 0 {
            transaction.plan_graph_and_schedule_remaining()?;
        }
        Ok(transaction)
    }

    /// Prepares only the durable recovery marker. No path label is returned at
    /// this boundary, so the attempt can still be discarded safely.
    pub fn prepare_next_read_window(
        &mut self,
    ) -> Result<Option<PrivateOramAppendRecoveryMarkerV3>, PrivateOramAppendTransactionError> {
        match self.status {
            PrivateOramAppendHnswTransactionStatusV2::MarkerPrepared { .. }
            | PrivateOramAppendHnswTransactionStatusV2::Awaiting { .. } => {
                return Err(PrivateOramAppendTransactionError::WindowPending);
            }
            PrivateOramAppendHnswTransactionStatusV2::Poisoned => {
                return Err(PrivateOramAppendTransactionError::RecoveryRequired);
            }
            PrivateOramAppendHnswTransactionStatusV2::Ready => {}
        }
        if self.actions.is_empty() {
            if self.graph_delta.is_some()
                && self.accepted_path_count == self.fixed_read_path_count
                && self.inserted
            {
                return Ok(None);
            }
            if self.requires_recovery() {
                self.status = PrivateOramAppendHnswTransactionStatusV2::Poisoned;
            }
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        let paths_per_window = usize::try_from(self.plan.paths_per_window)
            .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("paths_per_window"))?;
        if self.actions.len() < paths_per_window {
            self.status = PrivateOramAppendHnswTransactionStatusV2::Poisoned;
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        let actions = self
            .actions
            .iter()
            .take(paths_per_window)
            .cloned()
            .collect::<Vec<_>>();
        let slots = match self.group_window_slots(actions) {
            Ok(slots) => slots,
            Err(error) => return self.fail_prepare(error),
        };
        let paths = match slots
            .iter()
            .map(|slot| {
                encode_private_hnsw_oram_leaf_label(slot.leaf, self.config.tree_height)
                    .map_err(Into::into)
            })
            .collect::<Result<Vec<_>, PrivateOramAppendTransactionError>>()
        {
            Ok(paths) => paths,
            Err(error) => return self.fail_prepare(error),
        };
        if paths.iter().collect::<BTreeSet<_>>().len() != paths.len() {
            return self.fail_prepare(PrivateOramAppendTransactionError::InvalidInput(
                "duplicate_window_path",
            ));
        }
        let sequence = self.requested_window_count;
        let window = PrivateOramAppendReadWindowV1 { sequence, paths };
        let requested_window_count = self.requested_window_count.checked_add(1).ok_or(
            PrivateOramAppendTransactionError::InvalidInput("requested_window_count"),
        )?;
        let marker = self.build_recovery_marker(
            requested_window_count,
            PrivateOramAppendRecoveryPhaseV2::WindowIssued,
        );
        self.status = PrivateOramAppendHnswTransactionStatusV2::MarkerPrepared {
            marker: Box::new(marker.clone()),
            window: window.clone(),
            slots,
        };
        Ok(Some(marker))
    }

    /// Turns the next window's actions into one slot per served path.
    ///
    /// Actions that resolve to the same leaf join the slot of the first one; each merged
    /// action frees a slot, which reads the next padding leaf of the plan that is distinct
    /// from every other path of the window. The window shape therefore never depends on
    /// whether secret positions collided, and the plan's spare padding leaves (it carries
    /// one per fixed read path, more than the schedule consumes) pay for the substitutes.
    fn group_window_slots(
        &mut self,
        actions: Vec<PrivateOramAppendHnswPathActionV2>,
    ) -> Result<Vec<PrivateOramAppendHnswWindowSlotV2>, PrivateOramAppendTransactionError> {
        let mut slots: Vec<PrivateOramAppendHnswWindowSlotV2> = Vec::with_capacity(actions.len());
        let mut substitute_count = 0usize;
        for action in actions {
            let leaf = action.leaf(&self.working_state)?;
            match slots.iter_mut().find(|slot| slot.leaf == leaf) {
                Some(slot) => {
                    slot.actions.push(action);
                    substitute_count += 1;
                }
                None => slots.push(PrivateOramAppendHnswWindowSlotV2 {
                    leaf,
                    actions: vec![action],
                }),
            }
        }
        for _ in 0..substitute_count {
            let leaf = loop {
                let leaf = self.next_padding_leaf()?;
                if slots.iter().all(|slot| slot.leaf != leaf) {
                    break leaf;
                }
            };
            slots.push(PrivateOramAppendHnswWindowSlotV2 {
                leaf,
                actions: vec![PrivateOramAppendHnswPathActionV2::Padding { leaf }],
            });
        }
        Ok(slots)
    }

    /// Reveals the prepared path window only after the caller supplies the
    /// exact marker it has durably persisted.
    pub fn next_read_window_v2(
        &mut self,
        persisted_marker: &PrivateOramAppendRecoveryMarkerV2,
    ) -> Result<PrivateOramAppendHnswReadRequestV2, PrivateOramAppendTransactionError> {
        let current_marker = match &self.status {
            PrivateOramAppendHnswTransactionStatusV2::MarkerPrepared { marker, .. } => {
                marker.as_ref().clone()
            }
            PrivateOramAppendHnswTransactionStatusV2::Poisoned => {
                return Err(PrivateOramAppendTransactionError::RecoveryRequired);
            }
            PrivateOramAppendHnswTransactionStatusV2::Awaiting { .. } => {
                return Err(PrivateOramAppendTransactionError::WindowPending);
            }
            PrivateOramAppendHnswTransactionStatusV2::Ready => {
                return Err(PrivateOramAppendTransactionError::WindowNotPending);
            }
        };
        let expected = self.build_legacy_recovery_marker(
            current_marker.requested_window_count,
            current_marker.phase,
        );
        if &expected != persisted_marker {
            return Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch);
        }
        self.next_read_window(&current_marker)
    }

    /// Reveals the prepared path window only after the caller supplies the
    /// exact V3 marker it has durably persisted.
    pub fn next_read_window(
        &mut self,
        persisted_marker: &PrivateOramAppendRecoveryMarkerV3,
    ) -> Result<PrivateOramAppendHnswReadRequestV2, PrivateOramAppendTransactionError> {
        let pending = std::mem::replace(
            &mut self.status,
            PrivateOramAppendHnswTransactionStatusV2::Ready,
        );
        let PrivateOramAppendHnswTransactionStatusV2::MarkerPrepared {
            marker,
            window,
            slots,
        } = pending
        else {
            let error = match pending {
                PrivateOramAppendHnswTransactionStatusV2::Poisoned => {
                    PrivateOramAppendTransactionError::RecoveryRequired
                }
                PrivateOramAppendHnswTransactionStatusV2::Awaiting { .. } => {
                    PrivateOramAppendTransactionError::WindowPending
                }
                PrivateOramAppendHnswTransactionStatusV2::Ready => {
                    PrivateOramAppendTransactionError::WindowNotPending
                }
                PrivateOramAppendHnswTransactionStatusV2::MarkerPrepared { .. } => unreachable!(),
            };
            self.status = pending;
            return Err(error);
        };
        if marker.as_ref() != persisted_marker {
            self.status = PrivateOramAppendHnswTransactionStatusV2::MarkerPrepared {
                marker,
                window,
                slots,
            };
            return Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch);
        }
        // Every window consumes exactly `paths_per_window` queued actions; merged actions are
        // replaced by substitute padding slots, so the slot count equals the action count.
        let action_count = slots.len();
        self.actions.drain(..action_count);
        self.requested_window_count = marker.requested_window_count;
        self.status = PrivateOramAppendHnswTransactionStatusV2::Awaiting {
            window: window.clone(),
            slots,
        };
        Ok(PrivateOramAppendHnswReadRequestV2 {
            window,
            recovery_marker: *marker,
        })
    }

    pub fn accept_verified_window(
        &mut self,
        sequence: u32,
        keys: &PrivateHnswClientKeys,
        encrypted_batch: &PrivateHnswEncryptedPathBatch,
    ) -> Result<(), PrivateOramAppendTransactionError> {
        if matches!(
            self.status,
            PrivateOramAppendHnswTransactionStatusV2::Poisoned
        ) {
            return Err(PrivateOramAppendTransactionError::RecoveryRequired);
        }
        let pending = std::mem::replace(
            &mut self.status,
            PrivateOramAppendHnswTransactionStatusV2::Poisoned,
        );
        let PrivateOramAppendHnswTransactionStatusV2::Awaiting { window, slots } = pending else {
            self.status = pending;
            return Err(PrivateOramAppendTransactionError::WindowNotPending);
        };
        if window.sequence != sequence {
            // Nothing has been consumed yet: keep waiting for the right response instead of
            // poisoning the attempt on a caller or server sequencing slip.
            self.status = PrivateOramAppendHnswTransactionStatusV2::Awaiting { window, slots };
            return Err(PrivateOramAppendTransactionError::WindowSequenceMismatch);
        }
        let snapshot = self.window_snapshot();
        if let Err(error) =
            self.accept_verified_window_inner(&window, &slots, keys, encrypted_batch)
        {
            self.restore_window_snapshot(snapshot);
            return Err(error);
        }
        self.status = PrivateOramAppendHnswTransactionStatusV2::Ready;
        Ok(())
    }

    /// Produces a prepared-commit artifact. The returned recovery marker must
    /// remain durable until the server CAS and the new encrypted checkpoint
    /// are both confirmed.
    pub fn finalize(
        self,
    ) -> Result<PrivateOramAppendHnswTransactionOutputV2, PrivateOramAppendTransactionError> {
        if matches!(
            self.status,
            PrivateOramAppendHnswTransactionStatusV2::Poisoned
        ) {
            return Err(PrivateOramAppendTransactionError::RecoveryRequired);
        }
        if !matches!(self.status, PrivateOramAppendHnswTransactionStatusV2::Ready)
            || !self.actions.is_empty()
            || self.accepted_path_count != self.fixed_read_path_count
            || self.ordered_refs.len() != self.fixed_write_bucket_count
            || self.ordered_encrypted_buckets.len() != self.fixed_write_bucket_count
            || !self.inserted
        {
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        let mut recovery_marker = self.build_recovery_marker(
            self.requested_window_count,
            PrivateOramAppendRecoveryPhaseV2::PreparedCommit,
        );
        let graph_delta = self
            .graph_delta
            .ok_or(PrivateOramAppendTransactionError::Incomplete)?;
        let proof = PrivateOramAppendMerklePatchProofV1 {
            version: PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION,
            index_epoch: self.old_epoch,
            old_root_hash: self.old_root_hash.clone(),
            bucket_count: self.bucket_count,
            leaves: self.proof_leaves.into_values().collect(),
        };
        let patch = apply_private_oram_append_sparse_merkle_patch_v1(
            self.old_epoch,
            &self.old_root_hash,
            self.bucket_count,
            &proof,
            &self.ordered_refs,
        )?;
        let final_encrypted_buckets = self
            .final_encrypted_buckets
            .into_values()
            .collect::<Vec<_>>();
        let final_refs = final_encrypted_buckets
            .iter()
            .map(bucket_ref)
            .collect::<Vec<_>>();
        if final_refs != patch.final_buckets {
            return Err(PrivateOramAppendTransactionError::ProofSetMismatch);
        }
        let read_transcript =
            private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
                collection_id: &self.manifest.collection_id,
                manifest_digest: &self.manifest_digest,
                mutation_id: &self.plan.mutation_id,
                old_state_digest: &self.old_state_digest,
                writer_lease_digest: &self.plan.writer_lease_digest,
                writer_fence: self.plan.writer_fence,
                paths_per_window: self.plan.paths_per_window,
                tree_height: self.config.tree_height,
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: &self.plan.index_name,
                windows: &self.accepted_windows,
            })?;
        if read_transcript.read_path_count != self.fixed_read_path_count {
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        let writeback = PrivateOramAppendIndexWritebackV1 {
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: self.plan.index_name.clone(),
            read_path_count: read_transcript.read_path_count,
            read_transcript_digest: read_transcript.transcript_digest.clone(),
            updated_buckets: self.ordered_refs,
        };
        let next_client_state = self.working_state.to_snapshot(self.config.tree_height)?;
        let writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &self.manifest.collection_id,
                manifest_digest: &self.manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: self.old_epoch,
                new_epoch: self.new_epoch,
                old_root_hash: &self.old_root_hash,
                new_root_hash: &patch.new_root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            })?;
        recovery_marker.prepared_commit_digest =
            Some(private_oram_append_hnsw_prepared_commit_v4_digest(
                PrivateOramAppendHnswPreparedCommitDigestInputV4 {
                    attempt_digest: &self.attempt_digest,
                    source_checkpoint_digest: &self.source_checkpoint_digest,
                    graph_delta: &graph_delta,
                    old_epoch: self.old_epoch,
                    new_epoch: self.new_epoch,
                    old_root_hash: &self.old_root_hash,
                    new_root_hash: &patch.new_root_hash,
                    read_transcript_digest: &read_transcript.transcript_digest,
                    writeback_digest: &writeback_digest,
                    next_client_state: &next_client_state,
                },
            )?);
        let manifest = self.manifest.clone();
        let output = PrivateOramAppendHnswTransactionOutputV2 {
            source_checkpoint_digest: self.source_checkpoint_digest,
            graph_delta,
            read_transcript,
            writeback,
            old_epoch: self.old_epoch,
            new_epoch: self.new_epoch,
            old_root_hash: self.old_root_hash,
            new_root_hash: patch.new_root_hash,
            next_client_state,
            ordered_encrypted_buckets: self.ordered_encrypted_buckets,
            final_encrypted_buckets,
            merkle_patch_proof: proof,
            recovery_marker,
        };
        validate_private_oram_append_hnsw_transaction_output_v2(&manifest, &output)?;
        Ok(output)
    }

    pub fn requires_recovery(&self) -> bool {
        self.requested_window_count != 0
    }

    pub fn is_poisoned(&self) -> bool {
        matches!(
            self.status,
            PrivateOramAppendHnswTransactionStatusV2::Poisoned
        )
    }

    pub fn progress(&self) -> PrivateOramAppendHnswTransactionProgressV2 {
        PrivateOramAppendHnswTransactionProgressV2 {
            accepted_read_path_count: self.accepted_path_count,
            accepted_window_count: u32::try_from(self.accepted_windows.len()).unwrap_or(u32::MAX),
            prepared_write_bucket_count: self.ordered_refs.len(),
            plaintext_overlay_bucket_count: self.plaintext_overlay.len(),
            client_stash_block_count: self.working_state.stash_len(),
        }
    }

    pub fn recovery_marker(&self) -> Option<PrivateOramAppendRecoveryMarkerV3> {
        self.requires_recovery().then(|| {
            let phase = if self.is_poisoned() {
                PrivateOramAppendRecoveryPhaseV2::Poisoned
            } else {
                PrivateOramAppendRecoveryPhaseV2::WindowIssued
            };
            self.build_recovery_marker(self.requested_window_count, phase)
        })
    }

    fn build_recovery_marker(
        &self,
        requested_window_count: u32,
        phase: PrivateOramAppendRecoveryPhaseV2,
    ) -> PrivateOramAppendRecoveryMarkerV3 {
        PrivateOramAppendRecoveryMarkerV3 {
            version: PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION,
            collection_id: self.manifest.collection_id.clone(),
            manifest_digest: self.manifest_digest.clone(),
            mutation_id: self.plan.mutation_id.clone(),
            old_state_digest: self.old_state_digest.clone(),
            attempt_digest: self.attempt_digest.clone(),
            index_kind: PrivateOramIndexKindV2::Hnsw,
            index_name: self.plan.index_name.clone(),
            writer_lease_digest: self.plan.writer_lease_digest.clone(),
            writer_fence: self.plan.writer_fence,
            requested_window_count,
            accepted_window_count: u32::try_from(self.accepted_windows.len()).unwrap_or(u32::MAX),
            observed_read_path_count: requested_window_count
                .saturating_mul(self.plan.paths_per_window),
            phase,
            prepared_commit_digest: None,
        }
    }

    fn build_legacy_recovery_marker(
        &self,
        requested_window_count: u32,
        phase: PrivateOramAppendRecoveryPhaseV2,
    ) -> PrivateOramAppendRecoveryMarkerV2 {
        PrivateOramAppendRecoveryMarkerV2 {
            version: PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V2_VERSION,
            collection_id: self.manifest.collection_id.clone(),
            manifest_digest: self.manifest_digest.clone(),
            mutation_id: self.plan.mutation_id.clone(),
            old_state_digest: self.old_state_digest.clone(),
            attempt_digest: self.legacy_attempt_digest.clone(),
            writer_lease_digest: self.plan.writer_lease_digest.clone(),
            writer_fence: self.plan.writer_fence,
            requested_window_count,
            accepted_window_count: u32::try_from(self.accepted_windows.len()).unwrap_or(u32::MAX),
            observed_read_path_count: requested_window_count
                .saturating_mul(self.plan.paths_per_window),
            phase,
            prepared_commit_digest: None,
        }
    }

    fn fail_prepare<T>(
        &mut self,
        error: PrivateOramAppendTransactionError,
    ) -> Result<T, PrivateOramAppendTransactionError> {
        if self.requires_recovery() {
            self.status = PrivateOramAppendHnswTransactionStatusV2::Poisoned;
        }
        Err(error)
    }

    fn window_snapshot(&self) -> PrivateOramAppendHnswWindowSnapshotV2 {
        PrivateOramAppendHnswWindowSnapshotV2 {
            working_state: self.working_state.clone(),
            actions: self.actions.clone(),
            candidate_blocks: self.candidate_blocks.clone(),
            graph_delta: self.graph_delta.clone(),
            accepted_windows: self.accepted_windows.clone(),
            accepted_path_count: self.accepted_path_count,
            padding_leaf_offset: self.padding_leaf_offset,
            inserted: self.inserted,
            plaintext_overlay: self.plaintext_overlay.clone(),
            proof_leaves: self.proof_leaves.clone(),
            ordered_refs: self.ordered_refs.clone(),
            ordered_encrypted_buckets: self.ordered_encrypted_buckets.clone(),
            final_encrypted_buckets: self.final_encrypted_buckets.clone(),
        }
    }

    fn restore_window_snapshot(&mut self, snapshot: PrivateOramAppendHnswWindowSnapshotV2) {
        self.working_state = snapshot.working_state;
        self.actions = snapshot.actions;
        self.candidate_blocks = snapshot.candidate_blocks;
        self.graph_delta = snapshot.graph_delta;
        self.accepted_windows = snapshot.accepted_windows;
        self.accepted_path_count = snapshot.accepted_path_count;
        self.padding_leaf_offset = snapshot.padding_leaf_offset;
        self.inserted = snapshot.inserted;
        self.plaintext_overlay = snapshot.plaintext_overlay;
        self.proof_leaves = snapshot.proof_leaves;
        self.ordered_refs = snapshot.ordered_refs;
        self.ordered_encrypted_buckets = snapshot.ordered_encrypted_buckets;
        self.final_encrypted_buckets = snapshot.final_encrypted_buckets;
    }

    fn schedule_candidate_phase(&mut self) -> Result<(), PrivateOramAppendTransactionError> {
        for (node_id, remap_leaf) in self
            .plan
            .candidate_node_ids
            .iter()
            .copied()
            .zip(self.plan.candidate_remap_leaves.iter().copied())
        {
            self.actions
                .push_back(PrivateOramAppendHnswPathActionV2::Candidate {
                    node_id,
                    remap_leaf,
                });
            self.candidate_action_count += 1;
        }
        let candidate_padding_count = self
            .candidate_phase_path_count
            .checked_sub(u32::try_from(self.candidate_action_count).map_err(|_| {
                PrivateOramAppendTransactionError::InvalidInput("candidate_path_count")
            })?)
            .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                "candidate_path_count",
            ))?;
        for _ in 0..candidate_padding_count {
            let leaf = self.next_padding_leaf()?;
            self.actions
                .push_back(PrivateOramAppendHnswPathActionV2::Padding { leaf });
        }
        Ok(())
    }

    fn plan_graph_and_schedule_remaining(
        &mut self,
    ) -> Result<(), PrivateOramAppendTransactionError> {
        if self.graph_delta.is_some() {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "graph_delta",
            ));
        }
        let delta = plan_private_oram_level0_hnsw_graph_delta_v2(
            &self.manifest,
            &self.old_state,
            &self.checkpoint,
            &self.plan.index_name,
            &self.point,
            &self.candidate_blocks,
            self.candidate_phase_path_count,
        )?;
        for (offset, rewrite) in delta.neighbor_rewrites.iter().enumerate() {
            let remap_leaf = *self.plan.rewrite_remap_leaves.get(offset).ok_or(
                PrivateOramAppendTransactionError::InvalidInput("rewrite_remap_leaves"),
            )?;
            if self
                .working_state
                .position(&rewrite.previous.node_id)
                .is_none()
            {
                return Err(PrivateOramAppendTransactionError::InvalidInput(
                    "rewrite_position",
                ));
            }
            self.actions
                .push_back(PrivateOramAppendHnswPathActionV2::Rewrite {
                    node_id: rewrite.previous.node_id,
                    remap_leaf,
                    previous: Box::new(rewrite.previous.clone()),
                    replacement: Box::new(rewrite.replacement.clone()),
                });
        }
        // The inserted block keeps `point.initial_leaf` as its secret position. The path that is
        // read and evicted together with the insert is an independent padding leaf, so the
        // server never sees the position of the new block until an unrelated later access
        // remaps it again.
        let insert_eviction_leaf = self.next_padding_leaf()?;
        self.actions
            .push_back(PrivateOramAppendHnswPathActionV2::Insert {
                leaf: insert_eviction_leaf,
            });
        for _ in 0..delta.padding_read_path_count {
            let leaf = self.next_padding_leaf()?;
            self.actions
                .push_back(PrivateOramAppendHnswPathActionV2::Padding { leaf });
        }
        let remaining_path_count = self
            .fixed_read_path_count
            .checked_sub(self.accepted_path_count)
            .ok_or(PrivateOramAppendTransactionError::Incomplete)?;
        if self.actions.len()
            != usize::try_from(remaining_path_count)
                .map_err(|_| PrivateOramAppendTransactionError::Incomplete)?
            || !self.actions.len().is_multiple_of(
                usize::try_from(self.plan.paths_per_window)
                    .map_err(|_| PrivateOramAppendTransactionError::Incomplete)?,
            )
        {
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        self.graph_delta = Some(delta);
        Ok(())
    }

    fn next_padding_leaf(&mut self) -> Result<u64, PrivateOramAppendTransactionError> {
        let leaf = self
            .plan
            .padding_leaves
            .get(self.padding_leaf_offset)
            .copied()
            .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                "padding_leaves",
            ))?;
        self.padding_leaf_offset += 1;
        Ok(leaf)
    }

    fn accept_verified_window_inner(
        &mut self,
        window: &PrivateOramAppendReadWindowV1,
        slots: &[PrivateOramAppendHnswWindowSlotV2],
        keys: &PrivateHnswClientKeys,
        encrypted_batch: &PrivateHnswEncryptedPathBatch,
    ) -> Result<(), PrivateOramAppendTransactionError> {
        if slots.len() != window.paths.len()
            || window.paths.len()
                != usize::try_from(self.plan.paths_per_window)
                    .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("window"))?
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput("window"));
        }
        let expected_bucket_ids = slots
            .iter()
            .map(|slot| private_hnsw_oram_bucket_ids_for_leaf(slot.leaf, self.config.tree_height))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let returned_bucket_ids = encrypted_batch
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_id)
            .collect::<Vec<_>>();
        if returned_bucket_ids != expected_bucket_ids
            || encrypted_batch.index_epoch != self.old_epoch
            || encrypted_batch.root_hash != self.old_root_hash
            || encrypted_batch.bucket_count != self.bucket_count
        {
            return Err(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch);
        }
        let collection_id = self.manifest.collection_id.clone();
        let index_name = self.plan.index_name.clone();
        let key_id = self.key_id.clone();
        let rk_id = self.rk_id.clone();
        let base_context = PrivateHnswBucketAeadBaseContext {
            collection_id: &collection_id,
            vector_name: &index_name,
            key_id: &key_id,
            rk_id: &rk_id,
            rk_epoch: self.rk_epoch,
        };
        let opened = open_private_hnsw_oram_verified_path_batch(
            keys,
            base_context,
            self.config,
            self.old_epoch,
            &self.old_root_hash,
            self.bucket_count,
            &encrypted_batch.proof_value,
            &encrypted_batch.buckets,
        )?;
        let old_plaintext_by_id = opened
            .into_iter()
            .map(|bucket| (bucket.bucket_id, bucket))
            .collect::<BTreeMap<_, _>>();
        let expected_unique_bucket_ids =
            expected_bucket_ids.iter().copied().collect::<BTreeSet<_>>();
        if old_plaintext_by_id.len() != expected_unique_bucket_ids.len()
            || !expected_unique_bucket_ids
                .iter()
                .all(|bucket_id| old_plaintext_by_id.contains_key(bucket_id))
        {
            return Err(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch);
        }
        let proof =
            serde_json::from_str::<PrivateHnswOramMerkleProof>(&encrypted_batch.proof_value)
                .map_err(|_| PrivateOramAppendTransactionError::ProofSetMismatch)?;
        self.merge_proof(&PrivateOramAppendMerklePatchProofV1::from(&proof))?;

        for slot in slots {
            let path_buckets =
                private_hnsw_oram_bucket_ids_for_leaf(slot.leaf, self.config.tree_height)?
                    .iter()
                    .map(|bucket_id| {
                        self.plaintext_overlay
                            .get(bucket_id)
                            .or_else(|| old_plaintext_by_id.get(bucket_id))
                            .cloned()
                            .ok_or(
                                PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch,
                            )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            // Every access of the slot needs its block on this path (or already stashed); the
            // loader checks all of them before it moves a single block, so a served path that
            // lacks one leaves the working state untouched.
            let required_node_ids = slot
                .actions
                .iter()
                .filter_map(|action| match action {
                    PrivateOramAppendHnswPathActionV2::Candidate { node_id, .. }
                    | PrivateOramAppendHnswPathActionV2::Rewrite { node_id, .. } => Some(*node_id),
                    PrivateOramAppendHnswPathActionV2::Insert { .. }
                    | PrivateOramAppendHnswPathActionV2::Padding { .. } => None,
                })
                .collect::<Vec<_>>();
            let path_bucket_ids = load_private_hnsw_oram_path_for_append(
                &mut self.working_state,
                self.config,
                slot.leaf,
                &path_buckets,
                &required_node_ids,
            )?;
            for action in &slot.actions {
                match action {
                    PrivateOramAppendHnswPathActionV2::Candidate {
                        node_id,
                        remap_leaf,
                    } => {
                        let block = remap_private_hnsw_oram_stash_block(
                            &mut self.working_state,
                            self.config,
                            *node_id,
                            *remap_leaf,
                        )?;
                        self.candidate_blocks.push(block);
                    }
                    PrivateOramAppendHnswPathActionV2::Rewrite {
                        node_id,
                        remap_leaf,
                        previous,
                        replacement,
                    } => {
                        rewrite_private_hnsw_oram_stash_block(
                            &mut self.working_state,
                            self.config,
                            *node_id,
                            *remap_leaf,
                            |observed| {
                                if observed != previous.as_ref() {
                                    return Err(PrivateHnswClientError::InvalidAppendRewrite);
                                }
                                Ok(replacement.as_ref().clone())
                            },
                        )?;
                    }
                    PrivateOramAppendHnswPathActionV2::Insert { .. } => {
                        if self.inserted {
                            return Err(PrivateOramAppendTransactionError::InvalidInput("insert"));
                        }
                        let new_block = self
                            .graph_delta
                            .as_ref()
                            .ok_or(PrivateOramAppendTransactionError::Incomplete)?
                            .new_block
                            .clone();
                        self.working_state.insert_new_stash_block(
                            new_block,
                            self.point.initial_leaf,
                            self.config,
                        )?;
                        self.inserted = true;
                    }
                    PrivateOramAppendHnswPathActionV2::Padding { .. } => {}
                }
            }
            let writeback_buckets = evict_private_hnsw_oram_loaded_path(
                &mut self.working_state,
                self.config,
                &path_bucket_ids,
            )?;
            if self.working_state.stash_len() > self.max_client_stash_blocks {
                return Err(PrivateOramAppendTransactionError::StashBoundExceeded);
            }
            self.seal_ordered_writeback(keys, base_context, &path_bucket_ids, writeback_buckets)?;
        }
        self.accepted_path_count = self
            .accepted_path_count
            .checked_add(
                u32::try_from(slots.len())
                    .map_err(|_| PrivateOramAppendTransactionError::Incomplete)?,
            )
            .ok_or(PrivateOramAppendTransactionError::Incomplete)?;
        self.accepted_windows.push(window.clone());
        if self.graph_delta.is_none() && self.accepted_path_count == self.candidate_phase_path_count
        {
            if self.candidate_blocks.len() != self.candidate_action_count {
                return Err(PrivateOramAppendTransactionError::Incomplete);
            }
            self.plan_graph_and_schedule_remaining()?;
        }
        Ok(())
    }

    fn seal_ordered_writeback(
        &mut self,
        keys: &PrivateHnswClientKeys,
        base_context: PrivateHnswBucketAeadBaseContext<'_>,
        expected_bucket_ids: &[u64],
        writeback_buckets: Vec<PrivateHnswOramPlaintextBucket>,
    ) -> Result<(), PrivateOramAppendTransactionError> {
        if writeback_buckets.len() != expected_bucket_ids.len()
            || writeback_buckets
                .iter()
                .zip(expected_bucket_ids)
                .any(|(bucket, expected_id)| bucket.bucket_id != *expected_id)
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "writeback_buckets",
            ));
        }
        for plaintext_bucket in writeback_buckets {
            let encrypted_bucket = seal_private_hnsw_oram_plaintext_bucket(
                keys,
                base_context,
                self.new_epoch,
                &plaintext_bucket,
                self.config,
            )?;
            self.plaintext_overlay
                .insert(plaintext_bucket.bucket_id, plaintext_bucket);
            self.ordered_refs.push(bucket_ref(&encrypted_bucket));
            self.final_encrypted_buckets
                .insert(encrypted_bucket.bucket_id, encrypted_bucket.clone());
            self.ordered_encrypted_buckets.push(encrypted_bucket);
        }
        if self.ordered_refs.len() > self.fixed_write_bucket_count {
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        Ok(())
    }

    fn merge_proof(
        &mut self,
        proof: &PrivateOramAppendMerklePatchProofV1,
    ) -> Result<(), PrivateOramAppendTransactionError> {
        if proof.version != PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION
            || proof.index_epoch != self.old_epoch
            || proof.old_root_hash != self.old_root_hash
            || proof.bucket_count != self.bucket_count
        {
            return Err(PrivateOramAppendTransactionError::ProofSetMismatch);
        }
        for leaf in &proof.leaves {
            if let Some(existing) = self.proof_leaves.get(&leaf.bucket_id) {
                if existing != leaf {
                    return Err(PrivateOramAppendTransactionError::ProofSetMismatch);
                }
            } else {
                self.proof_leaves.insert(leaf.bucket_id, leaf.clone());
            }
        }
        Ok(())
    }
}

pub fn validate_private_oram_append_hnsw_transaction_output_v2(
    manifest: &PrivateOramImmutableManifestV2,
    output: &PrivateOramAppendHnswTransactionOutputV2,
) -> Result<(), PrivateOramAppendTransactionError> {
    let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
    let hnsw_indexes = manifest
        .indexes
        .iter()
        .filter(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
        .collect::<Vec<_>>();
    if hnsw_indexes.len() != 1 || !(1..=2).contains(&manifest.indexes.len()) {
        return Err(PrivateOramAppendTransactionError::UnsupportedTopology);
    }
    let manifest_index = hnsw_indexes[0];
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        key_id,
        rk_id,
        rk_epoch,
        dim,
        vector_encoding,
        hnsw,
        oram,
        max_neighbor_rewrites,
        ..
    } = &manifest_index.params
    else {
        return Err(PrivateOramAppendTransactionError::UnsupportedTopology);
    };
    let marker = &output.recovery_marker;
    let window_count = output
        .read_transcript
        .read_path_count
        .checked_div(oram.path_batch_size)
        .ok_or(PrivateOramAppendTransactionError::InvalidInput(
            "read_transcript",
        ))?;
    if marker.version != PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION
        || marker.collection_id != manifest.collection_id
        || marker.manifest_digest != manifest_digest
        || marker.index_kind != PrivateOramIndexKindV2::Hnsw
        || marker.index_name != manifest_index.index_name
        || marker.phase != PrivateOramAppendRecoveryPhaseV2::PreparedCommit
        || marker.requested_window_count != window_count
        || marker.accepted_window_count != window_count
        || marker.observed_read_path_count != output.read_transcript.read_path_count
        || marker.prepared_commit_digest.is_none()
        || output.new_epoch
            != output.old_epoch.checked_add(1).ok_or(
                PrivateOramAppendTransactionError::InvalidInput("index_epoch"),
            )?
        || output.old_root_hash == output.new_root_hash
        || output.graph_delta.index_name != manifest_index.index_name
        || output.graph_delta.fixed_read_path_count
            != manifest_index.capacity.fixed_append_read_path_count
        || output.writeback.kind != PrivateOramIndexKindV2::Hnsw
        || output.writeback.index_name != manifest_index.index_name
        || output.writeback.read_path_count != manifest_index.capacity.fixed_append_read_path_count
        || output.writeback.read_path_count != output.read_transcript.read_path_count
        || output.writeback.read_transcript_digest != output.read_transcript.transcript_digest
        || output.writeback.updated_buckets.len()
            != usize::try_from(manifest_index.capacity.fixed_append_write_bucket_count).map_err(
                |_| PrivateOramAppendTransactionError::InvalidInput("fixed_write_bucket_count"),
            )?
        || output.ordered_encrypted_buckets.len() != output.writeback.updated_buckets.len()
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "prepared_output",
        ));
    }
    validate_base64url_32(&marker.mutation_id, "mutation_id")?;
    validate_base64url_32(&marker.old_state_digest, "old_state_digest")?;
    validate_base64url_32(&marker.attempt_digest, "attempt_digest")?;
    validate_base64url_32(&marker.writer_lease_digest, "writer_lease_digest")?;
    validate_base64url_32(&output.source_checkpoint_digest, "source_checkpoint_digest")?;
    validate_base64url_32(&output.old_root_hash, "old_root_hash")?;
    validate_base64url_32(&output.new_root_hash, "new_root_hash")?;

    let paths_per_window = oram.path_batch_size;
    let paths_per_window_usize = usize::try_from(paths_per_window)
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("paths_per_window"))?;
    if output.read_transcript.collection_id != manifest.collection_id
        || output.read_transcript.manifest_digest != manifest_digest
        || output.read_transcript.mutation_id != marker.mutation_id
        || output.read_transcript.old_state_digest != marker.old_state_digest
        || output.read_transcript.writer_lease_digest != marker.writer_lease_digest
        || output.read_transcript.writer_fence != marker.writer_fence
        || output.read_transcript.kind != PrivateOramIndexKindV2::Hnsw
        || output.read_transcript.index_name != manifest_index.index_name
        || output.read_transcript.paths_per_window != paths_per_window
        || output.read_transcript.tree_height != oram.tree_height
        || output.read_transcript.ordered_leaf_labels.len()
            != usize::try_from(output.read_transcript.read_path_count)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("read_path_count"))?
        || !output
            .read_transcript
            .ordered_leaf_labels
            .len()
            .is_multiple_of(paths_per_window_usize)
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "read_transcript",
        ));
    }
    let windows = output
        .read_transcript
        .ordered_leaf_labels
        .chunks(paths_per_window_usize)
        .enumerate()
        .map(|(sequence, paths)| {
            Ok(PrivateOramAppendReadWindowV1 {
                sequence: u32::try_from(sequence).map_err(|_| {
                    PrivateOramAppendTransactionError::InvalidInput("read_transcript")
                })?,
                paths: paths.to_vec(),
            })
        })
        .collect::<Result<Vec<_>, PrivateOramAppendTransactionError>>()?;
    let expected_transcript =
        private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
            collection_id: &manifest.collection_id,
            manifest_digest: &manifest_digest,
            mutation_id: &marker.mutation_id,
            old_state_digest: &marker.old_state_digest,
            writer_lease_digest: &marker.writer_lease_digest,
            writer_fence: marker.writer_fence,
            paths_per_window,
            tree_height: oram.tree_height,
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: &manifest_index.index_name,
            windows: &windows,
        })?;
    if expected_transcript != output.read_transcript {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "read_transcript",
        ));
    }
    let expected_ordered_bucket_ids = output
        .read_transcript
        .ordered_leaf_labels
        .iter()
        .map(|leaf_label| {
            decode_private_hnsw_oram_leaf_label(leaf_label, oram.tree_height)
                .map_err(PrivateOramAppendTransactionError::from)
        })
        .map(|leaf| {
            leaf.and_then(|leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, oram.tree_height)
                    .map_err(PrivateOramAppendTransactionError::from)
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if expected_ordered_bucket_ids.len() != output.writeback.updated_buckets.len()
        || output
            .writeback
            .updated_buckets
            .iter()
            .zip(&expected_ordered_bucket_ids)
            .any(|(bucket, expected_bucket_id)| bucket.bucket_id != *expected_bucket_id)
        || output
            .ordered_encrypted_buckets
            .iter()
            .zip(&expected_ordered_bucket_ids)
            .any(|(bucket, expected_bucket_id)| bucket.bucket_id != *expected_bucket_id)
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "ordered_bucket_frames",
        ));
    }

    let bucket_count = private_hnsw_oram_bucket_count(oram.tree_height)?;
    if bucket_count != manifest_index.capacity.bucket_count {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "bucket_count",
        ));
    }
    let expected_ciphertext_bytes = private_hnsw_oram_bucket_ciphertext_bytes(oram)
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("encrypted_buckets"))?;
    let base_context = PrivateHnswBucketAeadBaseContext {
        collection_id: &manifest.collection_id,
        vector_name: &manifest_index.index_name,
        key_id,
        rk_id,
        rk_epoch: *rk_epoch,
    };
    let mut expected_final = BTreeMap::new();
    for (bucket, expected_ref) in output
        .ordered_encrypted_buckets
        .iter()
        .zip(&output.writeback.updated_buckets)
    {
        validate_private_hnsw_upload_bucket(
            base_context,
            bucket,
            output.new_epoch,
            bucket_count,
            expected_ciphertext_bytes,
        )?;
        if bucket_ref(bucket) != *expected_ref {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "encrypted_buckets",
            ));
        }
        expected_final.insert(bucket.bucket_id, bucket.clone());
    }
    if output
        .final_encrypted_buckets
        .windows(2)
        .any(|pair| pair[0].bucket_id >= pair[1].bucket_id)
        || output.final_encrypted_buckets != expected_final.into_values().collect::<Vec<_>>()
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "final_encrypted_buckets",
        ));
    }
    let patch = apply_private_oram_append_sparse_merkle_patch_v1(
        output.old_epoch,
        &output.old_root_hash,
        bucket_count,
        &output.merkle_patch_proof,
        &output.writeback.updated_buckets,
    )?;
    let final_refs = output
        .final_encrypted_buckets
        .iter()
        .map(bucket_ref)
        .collect::<Vec<_>>();
    if patch.new_root_hash != output.new_root_hash || patch.final_buckets != final_refs {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "merkle_patch_proof",
        ));
    }

    let graph_delta = &output.graph_delta;
    let expected_node_id = BASE64URL_NOPAD.encode(&graph_delta.new_block.node_id);
    let expected_point_token = BASE64URL_NOPAD.encode(&graph_delta.new_block.point_token);
    let expected_payload_fetch_token = graph_delta
        .new_block
        .payload_fetch_token
        .map(|value| BASE64URL_NOPAD.encode(&value));
    let expected_vector_bytes = usize::try_from(*dim)
        .ok()
        .and_then(|dim| dim.checked_mul(std::mem::size_of::<f32>()))
        .ok_or(PrivateOramAppendTransactionError::InvalidInput(
            "graph_delta",
        ))?;
    let block_size_bytes = usize::try_from(oram.block_size_bytes)
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("graph_delta"))?;
    let fixed_neighbor_slots = usize::try_from(hnsw.fixed_neighbor_slots)
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("graph_delta"))?;
    let expected_candidate_budget = graph_delta
        .fixed_read_path_count
        .checked_sub(max_neighbor_rewrites.checked_add(1).ok_or(
            PrivateOramAppendTransactionError::InvalidInput("graph_delta"),
        )?)
        .ok_or(PrivateOramAppendTransactionError::InvalidInput(
            "graph_delta",
        ))?;
    let expected_real_count = graph_delta
        .candidate_read_path_count
        .checked_add(graph_delta.rewrite_read_path_count)
        .and_then(|count| count.checked_add(1))
        .ok_or(PrivateOramAppendTransactionError::InvalidInput(
            "graph_delta",
        ))?;
    if graph_delta.new_block.version != crate::private_hnsw_client::PRIVATE_HNSW_NODE_BLOCK_VERSION
        || graph_delta.new_block.node_id == [0; 32]
        || graph_delta.new_block.point_token == [0; 32]
        || graph_delta
            .new_block
            .payload_fetch_token
            .is_some_and(|value| value == [0; 32])
        || graph_delta.new_block.level_mask != 1
        || graph_delta.new_block.vector_encoding != *vector_encoding
        || *vector_encoding != PrivateHnswVectorEncoding::F32Le
        || graph_delta.new_block.vector.len() != expected_vector_bytes
        || graph_delta.new_block.deleted
        || graph_delta.new_block.generation != 1
        || graph_delta.hnsw_record.node_id != expected_node_id
        || graph_delta.hnsw_record.point_token != expected_point_token
        || graph_delta.hnsw_record.level_mask != graph_delta.new_block.level_mask
        || graph_delta.hnsw_record.generation != graph_delta.new_block.generation
        || graph_delta.point_record.point_token != expected_point_token
        || graph_delta.point_record.payload_fetch_token != expected_payload_fetch_token
        || graph_delta.next_entry_node_id == [0; 32]
        || graph_delta.selected_neighbor_ids != graph_delta.new_block.neighbors
        || graph_delta
            .new_block
            .neighbor_levels
            .iter()
            .any(|level| *level != 0)
        || graph_delta.selected_neighbor_ids.len()
            > usize::try_from(hnsw.m)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("graph_delta"))?
        || graph_delta.candidate_read_path_budget != expected_candidate_budget
        || graph_delta.candidate_read_path_count > graph_delta.candidate_read_path_budget
        || graph_delta.rewrite_read_path_budget != *max_neighbor_rewrites
        || graph_delta.rewrite_read_path_count
            != u32::try_from(graph_delta.neighbor_rewrites.len())
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("graph_delta"))?
        || graph_delta.rewrite_read_path_count > graph_delta.rewrite_read_path_budget
        || graph_delta.real_read_path_count != expected_real_count
        || graph_delta
            .real_read_path_count
            .checked_add(graph_delta.padding_read_path_count)
            != Some(graph_delta.fixed_read_path_count)
        || match manifest.result_privacy {
            crate::private_hnsw_oram::ResultPrivacyMode::IdsVisible => {
                graph_delta
                    .point_record
                    .visible_point_id
                    .as_ref()
                    .is_none_or(String::is_empty)
                    || graph_delta.point_record.payload_fetch_token.is_some()
                    || graph_delta.new_block.payload_fetch_token.is_some()
            }
            crate::private_hnsw_oram::ResultPrivacyMode::PrivatePayloadOramRequired => {
                graph_delta.point_record.visible_point_id.is_some()
                    || graph_delta.point_record.payload_fetch_token.is_none()
                    || graph_delta.new_block.payload_fetch_token.is_none()
            }
        }
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "graph_delta",
        ));
    }
    encode_private_hnsw_node_block(
        &graph_delta.new_block,
        block_size_bytes,
        fixed_neighbor_slots,
    )?;
    let selected_neighbor_ids = graph_delta
        .selected_neighbor_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if selected_neighbor_ids.len() != graph_delta.selected_neighbor_ids.len()
        || selected_neighbor_ids.contains(&[0; 32])
        || selected_neighbor_ids.contains(&graph_delta.new_block.node_id)
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "graph_delta",
        ));
    }
    let mut rewritten_node_ids = BTreeSet::new();
    let mut replacement_level_zero_neighbor_ids = BTreeSet::new();
    for rewrite in &graph_delta.neighbor_rewrites {
        let previous = &rewrite.previous;
        let replacement = &rewrite.replacement;
        encode_private_hnsw_node_block(previous, block_size_bytes, fixed_neighbor_slots)?;
        encode_private_hnsw_node_block(replacement, block_size_bytes, fixed_neighbor_slots)?;
        let previous_upper_neighbors = previous
            .neighbors
            .iter()
            .zip(&previous.neighbor_levels)
            .filter(|(_, level)| **level > 0)
            .collect::<Vec<_>>();
        let replacement_upper_neighbors = replacement
            .neighbors
            .iter()
            .zip(&replacement.neighbor_levels)
            .filter(|(_, level)| **level > 0)
            .collect::<Vec<_>>();
        let previous_level_zero_neighbor_ids = previous
            .neighbors
            .iter()
            .zip(&previous.neighbor_levels)
            .filter_map(|(node_id, level)| (*level == 0).then_some(*node_id))
            .collect::<BTreeSet<_>>();
        let replacement_level_zero_ids = replacement
            .neighbors
            .iter()
            .zip(&replacement.neighbor_levels)
            .filter_map(|(node_id, level)| (*level == 0).then_some(*node_id))
            .collect::<BTreeSet<_>>();
        if previous.version != crate::private_hnsw_client::PRIVATE_HNSW_NODE_BLOCK_VERSION
            || replacement.version != previous.version
            || previous.node_id == [0; 32]
            || !rewritten_node_ids.insert(previous.node_id)
            || !selected_neighbor_ids.contains(&previous.node_id)
            || previous.node_id != replacement.node_id
            || previous.point_token == [0; 32]
            || previous.point_token != replacement.point_token
            || previous.level_mask != replacement.level_mask
            || previous.vector_encoding != *vector_encoding
            || previous.vector_encoding != replacement.vector_encoding
            || previous.vector.len() != expected_vector_bytes
            || previous.vector != replacement.vector
            || previous.deleted
            || replacement.deleted
            || previous
                .payload_fetch_token
                .is_some_and(|value| value == [0; 32])
            || previous.payload_fetch_token != replacement.payload_fetch_token
            || replacement.generation
                != previous.generation.checked_add(1).ok_or(
                    PrivateOramAppendTransactionError::InvalidInput("graph_delta"),
                )?
            || previous_upper_neighbors != replacement_upper_neighbors
            || replacement
                .neighbors
                .iter()
                .zip(&replacement.neighbor_levels)
                .filter(|(node_id, level)| {
                    **node_id == graph_delta.new_block.node_id && **level == 0
                })
                .count()
                != 1
            || replacement_level_zero_ids.iter().any(|node_id| {
                *node_id != graph_delta.new_block.node_id
                    && !previous_level_zero_neighbor_ids.contains(node_id)
            })
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "graph_delta",
            ));
        }
        replacement_level_zero_neighbor_ids.extend(replacement_level_zero_ids);
    }
    let next_state = PrivateHnswOramClientState::from_snapshot(&output.next_client_state)?;
    if output.next_client_state.tree_height != oram.tree_height
        || output.next_client_state.stash.len()
            > usize::try_from(manifest_index.capacity.max_client_stash_blocks)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("next_client_state"))?
        || next_state
            .position(&graph_delta.new_block.node_id)
            .is_none()
        || next_state
            .position(&graph_delta.next_entry_node_id)
            .is_none()
        || selected_neighbor_ids
            .iter()
            .any(|node_id| next_state.position(node_id).is_none())
        || rewritten_node_ids
            .iter()
            .any(|node_id| next_state.position(node_id).is_none())
        || replacement_level_zero_neighbor_ids
            .iter()
            .any(|node_id| next_state.position(node_id).is_none())
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "next_client_state",
        ));
    }
    for block in &output.next_client_state.stash {
        if block.version != crate::private_hnsw_client::PRIVATE_HNSW_NODE_BLOCK_VERSION
            || block.vector_encoding != *vector_encoding
            || block.vector.len() != expected_vector_bytes
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "next_client_state",
            ));
        }
        encode_private_hnsw_node_block(block, block_size_bytes, fixed_neighbor_slots)?;
    }
    for block in std::iter::once(&graph_delta.new_block).chain(
        graph_delta
            .neighbor_rewrites
            .iter()
            .map(|rewrite| &rewrite.replacement),
    ) {
        if next_state.position(&block.node_id).is_none()
            || output
                .next_client_state
                .stash
                .iter()
                .any(|stash_block| stash_block.node_id == block.node_id && stash_block != block)
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "next_client_state",
            ));
        }
    }

    let writeback_digest =
        private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
            collection_id: &manifest.collection_id,
            manifest_digest: &manifest_digest,
            kind: output.writeback.kind,
            index_name: &output.writeback.index_name,
            old_epoch: output.old_epoch,
            new_epoch: output.new_epoch,
            old_root_hash: &output.old_root_hash,
            new_root_hash: &output.new_root_hash,
            read_path_count: output.writeback.read_path_count,
            read_transcript_digest: &output.writeback.read_transcript_digest,
            updated_buckets: &output.writeback.updated_buckets,
        })?;
    let prepared_digest = private_oram_append_hnsw_prepared_commit_v4_digest(
        PrivateOramAppendHnswPreparedCommitDigestInputV4 {
            attempt_digest: &marker.attempt_digest,
            source_checkpoint_digest: &output.source_checkpoint_digest,
            graph_delta,
            old_epoch: output.old_epoch,
            new_epoch: output.new_epoch,
            old_root_hash: &output.old_root_hash,
            new_root_hash: &output.new_root_hash,
            read_transcript_digest: &output.read_transcript.transcript_digest,
            writeback_digest: &writeback_digest,
            next_client_state: &output.next_client_state,
        },
    )?;
    if marker.prepared_commit_digest.as_deref() != Some(prepared_digest.as_str()) {
        return Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch);
    }
    Ok(())
}

pub fn private_oram_append_hnsw_attempt_v2_digest(
    input: PrivateOramAppendHnswAttemptDigestInput<'_>,
) -> Result<String, PrivateOramAppendTransactionError> {
    let checkpoint = serde_json::to_vec(input.checkpoint)
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("checkpoint"))?;
    private_oram_append_hnsw_attempt_digest(
        PRIVATE_ORAM_APPEND_HNSW_ATTEMPT_V2_DIGEST_DOMAIN,
        PrivateOramAppendDigestDomainEncoding::LegacyV2,
        input.manifest_digest,
        input.old_state_digest,
        &checkpoint,
        input.point,
        input.plan,
    )
}

pub fn private_oram_append_hnsw_attempt_v3_digest(
    input: PrivateOramAppendHnswAttemptDigestInputV3<'_>,
) -> Result<String, PrivateOramAppendTransactionError> {
    let checkpoint_digest =
        private_oram_append_client_checkpoint_plaintext_v3_digest(input.checkpoint)?;
    private_oram_append_hnsw_attempt_digest(
        PRIVATE_ORAM_APPEND_HNSW_ATTEMPT_V3_DIGEST_DOMAIN,
        PrivateOramAppendDigestDomainEncoding::CanonicalV3,
        input.manifest_digest,
        input.old_state_digest,
        checkpoint_digest.as_bytes(),
        input.point,
        input.plan,
    )
}

#[derive(Clone, Copy)]
enum PrivateOramAppendDigestDomainEncoding {
    LegacyV2,
    CanonicalV3,
}

fn private_oram_append_hnsw_attempt_digest(
    domain: &str,
    domain_encoding: PrivateOramAppendDigestDomainEncoding,
    manifest_digest: &str,
    old_state_digest: &str,
    checkpoint_binding: &[u8],
    point: &PrivateOramAppendLevel0PointV2,
    plan: &PrivateOramAppendHnswTransactionPlanV2,
) -> Result<String, PrivateOramAppendTransactionError> {
    let mut hasher = Sha256::new();
    match domain_encoding {
        PrivateOramAppendDigestDomainEncoding::LegacyV2 => {
            update_digest_bytes(&mut hasher, domain.as_bytes())?;
        }
        PrivateOramAppendDigestDomainEncoding::CanonicalV3 => {
            update_digest_domain_v3(&mut hasher, domain.as_bytes())?;
        }
    }
    update_digest_bytes(&mut hasher, manifest_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, old_state_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, checkpoint_binding)?;
    update_digest_bytes(&mut hasher, plan.index_name.as_bytes())?;
    update_digest_bytes(&mut hasher, plan.mutation_id.as_bytes())?;
    update_digest_bytes(&mut hasher, plan.writer_lease_digest.as_bytes())?;
    hasher.update(plan.writer_fence.to_be_bytes());
    hasher.update(plan.paths_per_window.to_be_bytes());
    update_digest_bytes(&mut hasher, &point.node_id)?;
    update_digest_bytes(&mut hasher, &point.point_token)?;
    for value in [
        point.visible_point_id.as_deref().map(str::as_bytes),
        point.payload_fetch_token.as_ref().map(<[u8; 32]>::as_slice),
    ] {
        if let Some(value) = value {
            hasher.update([1]);
            update_digest_bytes(&mut hasher, value)?;
        } else {
            hasher.update([0]);
        }
    }
    update_digest_len(&mut hasher, point.vector.len())?;
    for value in &point.vector {
        hasher.update(value.to_bits().to_be_bytes());
    }
    hasher.update(point.initial_leaf.to_be_bytes());
    update_digest_len(&mut hasher, plan.candidate_node_ids.len())?;
    for node_id in &plan.candidate_node_ids {
        update_digest_bytes(&mut hasher, node_id)?;
    }
    for values in [
        plan.candidate_remap_leaves.as_slice(),
        plan.rewrite_remap_leaves.as_slice(),
        plan.padding_leaves.as_slice(),
    ] {
        update_digest_len(&mut hasher, values.len())?;
        for value in values {
            hasher.update(value.to_be_bytes());
        }
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_append_hnsw_prepared_commit_v2_digest(
    input: PrivateOramAppendHnswPreparedCommitDigestInput<'_>,
) -> Result<String, PrivateOramAppendTransactionError> {
    let next_client_state = serde_json::to_vec(input.next_client_state)
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("next_client_state"))?;
    let mut hasher = Sha256::new();
    update_digest_bytes(
        &mut hasher,
        PRIVATE_ORAM_APPEND_HNSW_PREPARED_COMMIT_V2_DIGEST_DOMAIN.as_bytes(),
    )?;
    update_digest_bytes(&mut hasher, input.attempt_digest.as_bytes())?;
    hasher.update(input.old_epoch.to_be_bytes());
    hasher.update(input.new_epoch.to_be_bytes());
    update_digest_bytes(&mut hasher, input.old_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.new_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.read_transcript_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, input.writeback_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, &next_client_state)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_append_hnsw_prepared_commit_v3_digest(
    input: PrivateOramAppendHnswPreparedCommitDigestInputV3<'_>,
) -> Result<String, PrivateOramAppendTransactionError> {
    let graph_delta_digest = private_oram_append_hnsw_graph_delta_v3_digest(input.graph_delta)?;
    let next_client_state_digest =
        private_oram_append_hnsw_client_state_v3_digest(input.next_client_state)?;
    let mut hasher = Sha256::new();
    update_digest_domain_v3(
        &mut hasher,
        PRIVATE_ORAM_APPEND_HNSW_PREPARED_COMMIT_V3_DIGEST_DOMAIN.as_bytes(),
    )?;
    update_digest_bytes(&mut hasher, input.attempt_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, graph_delta_digest.as_bytes())?;
    hasher.update(input.old_epoch.to_be_bytes());
    hasher.update(input.new_epoch.to_be_bytes());
    update_digest_bytes(&mut hasher, input.old_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.new_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.read_transcript_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, input.writeback_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, next_client_state_digest.as_bytes())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_append_hnsw_prepared_commit_v4_digest(
    input: PrivateOramAppendHnswPreparedCommitDigestInputV4<'_>,
) -> Result<String, PrivateOramAppendTransactionError> {
    validate_base64url_32(input.source_checkpoint_digest, "source_checkpoint_digest")?;
    let graph_delta_digest = private_oram_append_hnsw_graph_delta_v3_digest(input.graph_delta)?;
    let next_client_state_digest =
        private_oram_append_hnsw_client_state_v3_digest(input.next_client_state)?;
    let mut hasher = Sha256::new();
    update_digest_domain_v3(
        &mut hasher,
        PRIVATE_ORAM_APPEND_HNSW_PREPARED_COMMIT_V4_DIGEST_DOMAIN.as_bytes(),
    )?;
    update_digest_bytes(&mut hasher, input.attempt_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, input.source_checkpoint_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, graph_delta_digest.as_bytes())?;
    hasher.update(input.old_epoch.to_be_bytes());
    hasher.update(input.new_epoch.to_be_bytes());
    update_digest_bytes(&mut hasher, input.old_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.new_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.read_transcript_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, input.writeback_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, next_client_state_digest.as_bytes())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_append_hnsw_graph_delta_v3_digest(
    graph_delta: &PrivateOramAppendLevel0HnswGraphDeltaV2,
) -> Result<String, PrivateOramAppendTransactionError> {
    let mut hasher = Sha256::new();
    update_digest_domain_v3(
        &mut hasher,
        PRIVATE_ORAM_APPEND_HNSW_GRAPH_DELTA_V3_DIGEST_DOMAIN.as_bytes(),
    )?;
    update_digest_bytes(&mut hasher, graph_delta.index_name.as_bytes())?;
    update_digest_bytes(&mut hasher, graph_delta.point_record.point_token.as_bytes())?;
    update_optional_digest_bytes(
        &mut hasher,
        graph_delta
            .point_record
            .visible_point_id
            .as_deref()
            .map(str::as_bytes),
    )?;
    update_optional_digest_bytes(
        &mut hasher,
        graph_delta
            .point_record
            .payload_fetch_token
            .as_deref()
            .map(str::as_bytes),
    )?;
    update_digest_bytes(&mut hasher, graph_delta.hnsw_record.node_id.as_bytes())?;
    update_digest_bytes(&mut hasher, graph_delta.hnsw_record.point_token.as_bytes())?;
    hasher.update(graph_delta.hnsw_record.level_mask.to_be_bytes());
    hasher.update(graph_delta.hnsw_record.generation.to_be_bytes());
    update_hnsw_node_block_digest(&mut hasher, &graph_delta.new_block)?;
    update_digest_bytes(&mut hasher, &graph_delta.next_entry_node_id)?;
    update_digest_len(&mut hasher, graph_delta.selected_neighbor_ids.len())?;
    for node_id in &graph_delta.selected_neighbor_ids {
        update_digest_bytes(&mut hasher, node_id)?;
    }
    update_digest_len(&mut hasher, graph_delta.neighbor_rewrites.len())?;
    for rewrite in &graph_delta.neighbor_rewrites {
        update_hnsw_node_block_digest(&mut hasher, &rewrite.previous)?;
        update_hnsw_node_block_digest(&mut hasher, &rewrite.replacement)?;
    }
    for value in [
        graph_delta.fixed_read_path_count,
        graph_delta.candidate_read_path_budget,
        graph_delta.candidate_read_path_count,
        graph_delta.rewrite_read_path_budget,
        graph_delta.rewrite_read_path_count,
        graph_delta.real_read_path_count,
        graph_delta.padding_read_path_count,
    ] {
        hasher.update(value.to_be_bytes());
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn update_hnsw_node_block_digest(
    hasher: &mut Sha256,
    block: &PrivateHnswNodeBlockPlaintext,
) -> Result<(), PrivateOramAppendTransactionError> {
    let mut encoded = Vec::new();
    push_hnsw_node_block_v3(&mut encoded, block)?;
    update_digest_bytes(hasher, &encoded)
}

fn update_optional_digest_bytes(
    hasher: &mut Sha256,
    value: Option<&[u8]>,
) -> Result<(), PrivateOramAppendTransactionError> {
    match value {
        Some(value) => {
            hasher.update([1]);
            update_digest_bytes(hasher, value)
        }
        None => {
            hasher.update([0]);
            Ok(())
        }
    }
}

fn update_digest_bytes(
    hasher: &mut Sha256,
    value: &[u8],
) -> Result<(), PrivateOramAppendTransactionError> {
    update_digest_len(hasher, value.len())?;
    hasher.update(value);
    Ok(())
}

pub(crate) fn update_digest_domain_v3(
    hasher: &mut Sha256,
    domain: &[u8],
) -> Result<(), PrivateOramAppendTransactionError> {
    let len = u32::try_from(domain.len())
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("digest_domain"))?;
    hasher.update(len.to_be_bytes());
    hasher.update(domain);
    Ok(())
}

fn update_digest_len(
    hasher: &mut Sha256,
    len: usize,
) -> Result<(), PrivateOramAppendTransactionError> {
    let len = u64::try_from(len)
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("digest_input"))?;
    hasher.update(len.to_be_bytes());
    Ok(())
}

fn bucket_ref(bucket: &PrivateHnswOramBucket) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id: bucket.bucket_id,
        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        bucket_commitment: bucket.bucket_commitment.clone(),
    }
}

fn validate_base64url_32(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramAppendTransactionError> {
    if value.len() != 43 {
        return Err(PrivateOramAppendTransactionError::InvalidInput(field));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput(field))?;
    if decoded.len() != 32 {
        return Err(PrivateOramAppendTransactionError::InvalidInput(field));
    }
    Ok(())
}
