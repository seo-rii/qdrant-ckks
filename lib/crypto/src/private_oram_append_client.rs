use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::aead::{EncryptionError, SecretKey};
use crate::private_hnsw_client::{
    PRIVATE_HNSW_NODE_BLOCK_VERSION, PrivateHnswClientError, PrivateHnswMerkleSiblingPosition,
    PrivateHnswNodeBlockPlaintext, PrivateHnswOramClientConfig, PrivateHnswOramClientState,
    PrivateHnswOramClientStateSnapshot, PrivateHnswOramMerkleProof, PrivateHnswVectorEncoding,
    decode_private_hnsw_f32_vector, encode_private_hnsw_node_block, private_hnsw_f32_distance,
};
use crate::private_hnsw_oram::ResultPrivacyMode;
use crate::private_oram_mutation::{
    PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS, PrivateOramAppendBucketRefV1,
    PrivateOramImmutableIndexParamsV2, PrivateOramImmutableManifestV2, PrivateOramIndexKindV2,
    PrivateOramMutationError, PrivateOramSignedStateV2, private_oram_immutable_manifest_v2_digest,
    private_oram_signed_state_v2_digest,
};
use crate::private_result_oram::{
    PrivateResultOramClientState, PrivateResultOramClientStateSnapshot, PrivateResultOramError,
    PrivateResultOramMerkleProof, PrivateResultOramMerkleSiblingPosition,
};

pub const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_V2_VERSION: u16 = 2;
pub const PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION: u16 = 1;
pub const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AEAD_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-append-client-checkpoint-aead/v2";
pub const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-client-checkpoint-digest/v2";
pub const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_PLAINTEXT_V3_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-client-checkpoint-plaintext-digest/v3";
pub const PRIVATE_ORAM_APPEND_HNSW_CLIENT_STATE_V3_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-hnsw-client-state-digest/v3";
pub const PRIVATE_ORAM_APPEND_RESULT_CLIENT_STATE_V3_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-result-client-state-digest/v3";

const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_KDF_CONTEXT_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-append-client-checkpoint-kdf-context/v2";
const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AAD_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-append-client-checkpoint-aad/v2";
const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AEAD_VERSION: u8 = 1;
const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN: usize = 12;
const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_TAG_LEN: usize = 16;
const PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_MAX_BYTES: usize = 256 * 1024 * 1024;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramAppendClientError {
    #[error("private ORAM append checkpoint encryption failed")]
    Encryption(#[source] EncryptionError),
    #[error("private ORAM append HNSW client operation failed")]
    Hnsw(#[source] PrivateHnswClientError),
    #[error("private ORAM append result client operation failed")]
    Result(#[source] PrivateResultOramError),
    #[error("private ORAM append mutation contract failed")]
    Mutation(#[source] PrivateOramMutationError),
    #[error("private ORAM append checkpoint uses an unsupported version")]
    UnsupportedCheckpointVersion(u16),
    #[error("private ORAM append checkpoint field is invalid")]
    InvalidCheckpointField(&'static str),
    #[error("private ORAM append checkpoint index set is invalid")]
    InvalidCheckpointIndexes,
    #[error("private ORAM append checkpoint record is duplicated")]
    DuplicateCheckpointRecord,
    #[error("private ORAM append checkpoint does not match the signed state")]
    CheckpointStateMismatch,
    #[error("private ORAM append checkpoint ciphertext is malformed")]
    InvalidCheckpointCiphertext,
    #[error("private ORAM append checkpoint ciphertext hash is invalid")]
    InvalidCheckpointCiphertextHash,
    #[error("private ORAM append checkpoint authentication failed")]
    CheckpointOpenFailed,
    #[error("private ORAM append Merkle patch proof is malformed")]
    InvalidMerklePatch,
    #[error("private ORAM append Merkle patch proof does not match the old root")]
    MerklePatchMismatch,
    #[error("private ORAM append planner input is invalid")]
    InvalidAppendInput(&'static str),
    #[error("private ORAM append planner candidate evidence is incomplete or stale")]
    AppendCandidateMismatch,
    #[error("private ORAM append planner exceeds the fixed read-path budget")]
    AppendBudgetExceeded,
    #[error("private ORAM append planner has exhausted logical capacity")]
    AppendCapacityExhausted,
}

impl Debug for PrivateOramAppendClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encryption(_) => f.write_str("Encryption([redacted])"),
            Self::Hnsw(_) => f.write_str("Hnsw([redacted])"),
            Self::Result(_) => f.write_str("Result([redacted])"),
            Self::Mutation(_) => f.write_str("Mutation([redacted])"),
            Self::UnsupportedCheckpointVersion(version) => f
                .debug_tuple("UnsupportedCheckpointVersion")
                .field(version)
                .finish(),
            Self::InvalidCheckpointField(field) => f
                .debug_tuple("InvalidCheckpointField")
                .field(field)
                .finish(),
            Self::InvalidCheckpointIndexes => f.write_str("InvalidCheckpointIndexes"),
            Self::DuplicateCheckpointRecord => f.write_str("DuplicateCheckpointRecord"),
            Self::CheckpointStateMismatch => f.write_str("CheckpointStateMismatch"),
            Self::InvalidCheckpointCiphertext => f.write_str("InvalidCheckpointCiphertext"),
            Self::InvalidCheckpointCiphertextHash => f.write_str("InvalidCheckpointCiphertextHash"),
            Self::CheckpointOpenFailed => f.write_str("CheckpointOpenFailed"),
            Self::InvalidMerklePatch => f.write_str("InvalidMerklePatch"),
            Self::MerklePatchMismatch => f.write_str("MerklePatchMismatch"),
            Self::InvalidAppendInput(field) => {
                f.debug_tuple("InvalidAppendInput").field(field).finish()
            }
            Self::AppendCandidateMismatch => f.write_str("AppendCandidateMismatch"),
            Self::AppendBudgetExceeded => f.write_str("AppendBudgetExceeded"),
            Self::AppendCapacityExhausted => f.write_str("AppendCapacityExhausted"),
        }
    }
}

impl From<EncryptionError> for PrivateOramAppendClientError {
    fn from(error: EncryptionError) -> Self {
        Self::Encryption(error)
    }
}

impl From<PrivateHnswClientError> for PrivateOramAppendClientError {
    fn from(error: PrivateHnswClientError) -> Self {
        Self::Hnsw(error)
    }
}

impl From<PrivateResultOramError> for PrivateOramAppendClientError {
    fn from(error: PrivateResultOramError) -> Self {
        Self::Result(error)
    }
}

impl From<PrivateOramMutationError> for PrivateOramAppendClientError {
    fn from(error: PrivateOramMutationError) -> Self {
        Self::Mutation(error)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendHnswRecordV2 {
    pub node_id: String,
    pub point_token: String,
    pub level_mask: u64,
    pub generation: u64,
}

impl Debug for PrivateOramAppendHnswRecordV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswRecordV2")
            .field("node_id", &"[redacted]")
            .field("point_token", &"[redacted]")
            .field("level_mask", &"[redacted]")
            .field("generation", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendPointRecordV2 {
    pub point_token: String,
    pub visible_point_id: Option<String>,
    pub payload_fetch_token: Option<String>,
}

impl Debug for PrivateOramAppendPointRecordV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendPointRecordV2")
            .field("point_token", &"[redacted]")
            .field("visible_point_id", &"[redacted]")
            .field("payload_fetch_token", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendResultRecordV2 {
    pub payload_fetch_token: String,
    pub point_token: String,
    pub generation: u64,
}

impl Debug for PrivateOramAppendResultRecordV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendResultRecordV2")
            .field("payload_fetch_token", &"[redacted]")
            .field("point_token", &"[redacted]")
            .field("generation", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateOramAppendLevel0PointV2 {
    pub node_id: [u8; 32],
    pub point_token: [u8; 32],
    pub visible_point_id: Option<String>,
    pub payload_fetch_token: Option<[u8; 32]>,
    pub vector: Vec<f32>,
    pub initial_leaf: u64,
}

impl Debug for PrivateOramAppendLevel0PointV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendLevel0PointV2")
            .field("node_id", &"[redacted]")
            .field("point_token", &"[redacted]")
            .field("visible_point_id", &"[redacted]")
            .field("payload_fetch_token", &"[redacted]")
            .field("vector_len", &self.vector.len())
            .field("initial_leaf", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateOramAppendHnswNeighborRewriteV2 {
    pub previous: PrivateHnswNodeBlockPlaintext,
    pub replacement: PrivateHnswNodeBlockPlaintext,
}

impl Debug for PrivateOramAppendHnswNeighborRewriteV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendHnswNeighborRewriteV2")
            .field("node_id", &"[redacted]")
            .field("previous_generation", &"[redacted]")
            .field("replacement_generation", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateOramAppendLevel0HnswGraphDeltaV2 {
    pub index_name: String,
    pub point_record: PrivateOramAppendPointRecordV2,
    pub hnsw_record: PrivateOramAppendHnswRecordV2,
    pub new_block: PrivateHnswNodeBlockPlaintext,
    pub next_entry_node_id: [u8; 32],
    pub selected_neighbor_ids: Vec<[u8; 32]>,
    pub neighbor_rewrites: Vec<PrivateOramAppendHnswNeighborRewriteV2>,
    pub fixed_read_path_count: u32,
    pub candidate_read_path_budget: u32,
    pub candidate_read_path_count: u32,
    pub rewrite_read_path_budget: u32,
    pub rewrite_read_path_count: u32,
    pub real_read_path_count: u32,
    pub padding_read_path_count: u32,
}

impl Debug for PrivateOramAppendLevel0HnswGraphDeltaV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendLevel0HnswGraphDeltaV2")
            .field("index_name", &"[redacted]")
            .field("point_record", &"[redacted]")
            .field("hnsw_record", &"[redacted]")
            .field("new_block", &"[redacted]")
            .field("next_entry_node_id", &"[redacted]")
            .field("selected_neighbor_count", &self.selected_neighbor_ids.len())
            .field("neighbor_rewrite_count", &self.neighbor_rewrites.len())
            .field("fixed_read_path_count", &self.fixed_read_path_count)
            .field(
                "candidate_read_path_budget",
                &self.candidate_read_path_budget,
            )
            .field("candidate_read_path_count", &self.candidate_read_path_count)
            .field("rewrite_read_path_budget", &self.rewrite_read_path_budget)
            .field("rewrite_read_path_count", &self.rewrite_read_path_count)
            .field("real_read_path_count", &self.real_read_path_count)
            .field("padding_read_path_count", &self.padding_read_path_count)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateOramAppendClientIndexCheckpointV2 {
    Hnsw {
        index_name: String,
        index_epoch: u64,
        root_hash: String,
        entry_node_id: Option<String>,
        state: PrivateHnswOramClientStateSnapshot,
        records: Vec<PrivateOramAppendHnswRecordV2>,
    },
    Result {
        index_name: String,
        index_epoch: u64,
        root_hash: String,
        state: PrivateResultOramClientStateSnapshot,
        records: Vec<PrivateOramAppendResultRecordV2>,
    },
}

impl Debug for PrivateOramAppendClientIndexCheckpointV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hnsw {
                entry_node_id,
                index_epoch,
                state,
                records,
                ..
            } => f
                .debug_struct("Hnsw")
                .field("index_name", &"[redacted]")
                .field("index_epoch", index_epoch)
                .field("root_hash", &"[redacted]")
                .field("has_entry_node_id", &entry_node_id.is_some())
                .field("state", state)
                .field("record_count", &records.len())
                .finish(),
            Self::Result {
                index_epoch,
                state,
                records,
                ..
            } => f
                .debug_struct("Result")
                .field("index_name", &"[redacted]")
                .field("index_epoch", index_epoch)
                .field("root_hash", &"[redacted]")
                .field("state", state)
                .field("record_count", &records.len())
                .finish(),
        }
    }
}

impl PrivateOramAppendClientIndexCheckpointV2 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        match self {
            Self::Hnsw { .. } => PrivateOramIndexKindV2::Hnsw,
            Self::Result { .. } => PrivateOramIndexKindV2::Result,
        }
    }

    pub fn index_name(&self) -> &str {
        match self {
            Self::Hnsw { index_name, .. } | Self::Result { index_name, .. } => index_name,
        }
    }

    pub const fn index_epoch(&self) -> u64 {
        match self {
            Self::Hnsw { index_epoch, .. } | Self::Result { index_epoch, .. } => *index_epoch,
        }
    }

    pub fn root_hash(&self) -> &str {
        match self {
            Self::Hnsw { root_hash, .. } | Self::Result { root_hash, .. } => root_hash,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendClientCheckpointV2 {
    pub version: u16,
    pub collection_id: String,
    pub manifest_digest: String,
    pub layout_generation: u64,
    pub state_sequence: u64,
    pub points: Vec<PrivateOramAppendPointRecordV2>,
    pub indexes: Vec<PrivateOramAppendClientIndexCheckpointV2>,
}

impl Debug for PrivateOramAppendClientCheckpointV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendClientCheckpointV2")
            .field("version", &self.version)
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("layout_generation", &self.layout_generation)
            .field("state_sequence", &self.state_sequence)
            .field("point_count", &self.points.len())
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramSealedAppendClientCheckpointV2 {
    pub version: u16,
    pub collection_id: String,
    pub manifest_digest: String,
    pub layout_generation: u64,
    pub state_sequence: u64,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
}

impl Debug for PrivateOramSealedAppendClientCheckpointV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramSealedAppendClientCheckpointV2")
            .field("version", &self.version)
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("layout_generation", &self.layout_generation)
            .field("state_sequence", &self.state_sequence)
            .field("ciphertext_len", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramEncryptedAppendClientCheckpointV2 {
    pub sealed: PrivateOramSealedAppendClientCheckpointV2,
    pub state_digest: String,
}

impl Debug for PrivateOramEncryptedAppendClientCheckpointV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramEncryptedAppendClientCheckpointV2")
            .field("sealed", &"[redacted]")
            .field("state_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramAppendMerkleSiblingPositionV1 {
    Left,
    Right,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendMerkleSiblingV1 {
    pub level: u32,
    pub position: PrivateOramAppendMerkleSiblingPositionV1,
    pub hash: String,
}

impl Debug for PrivateOramAppendMerkleSiblingV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendMerkleSiblingV1")
            .field("level", &self.level)
            .field("position", &self.position)
            .field("hash", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendMerklePatchLeafV1 {
    pub bucket_id: u64,
    pub old_commitment: String,
    pub siblings: Vec<PrivateOramAppendMerkleSiblingV1>,
}

impl Debug for PrivateOramAppendMerklePatchLeafV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendMerklePatchLeafV1")
            .field("bucket_id", &"[redacted]")
            .field("old_commitment", &"[redacted]")
            .field("sibling_count", &self.siblings.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendMerklePatchProofV1 {
    pub version: u16,
    pub index_epoch: u64,
    pub old_root_hash: String,
    pub bucket_count: u64,
    pub leaves: Vec<PrivateOramAppendMerklePatchLeafV1>,
}

impl Debug for PrivateOramAppendMerklePatchProofV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendMerklePatchProofV1")
            .field("version", &self.version)
            .field("index_epoch", &self.index_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("bucket_count", &self.bucket_count)
            .field("leaf_count", &self.leaves.len())
            .finish()
    }
}

impl From<&PrivateHnswOramMerkleProof> for PrivateOramAppendMerklePatchProofV1 {
    fn from(proof: &PrivateHnswOramMerkleProof) -> Self {
        Self {
            version: PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION,
            index_epoch: proof.index_epoch,
            old_root_hash: proof.root_hash.clone(),
            bucket_count: proof.bucket_count,
            leaves: proof
                .leaves
                .iter()
                .map(|leaf| PrivateOramAppendMerklePatchLeafV1 {
                    bucket_id: leaf.bucket_id,
                    old_commitment: leaf.leaf_hash.clone(),
                    siblings: leaf
                        .siblings
                        .iter()
                        .map(|sibling| PrivateOramAppendMerkleSiblingV1 {
                            level: sibling.level,
                            position: match sibling.position {
                                PrivateHnswMerkleSiblingPosition::Left => {
                                    PrivateOramAppendMerkleSiblingPositionV1::Left
                                }
                                PrivateHnswMerkleSiblingPosition::Right => {
                                    PrivateOramAppendMerkleSiblingPositionV1::Right
                                }
                            },
                            hash: sibling.hash.clone(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

impl From<&PrivateResultOramMerkleProof> for PrivateOramAppendMerklePatchProofV1 {
    fn from(proof: &PrivateResultOramMerkleProof) -> Self {
        Self {
            version: PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION,
            index_epoch: proof.index_epoch,
            old_root_hash: proof.root_hash.clone(),
            bucket_count: proof.bucket_count,
            leaves: proof
                .leaves
                .iter()
                .map(|leaf| PrivateOramAppendMerklePatchLeafV1 {
                    bucket_id: leaf.bucket_id,
                    old_commitment: leaf.leaf_hash.clone(),
                    siblings: leaf
                        .siblings
                        .iter()
                        .map(|sibling| PrivateOramAppendMerkleSiblingV1 {
                            level: sibling.level,
                            position: match sibling.position {
                                PrivateResultOramMerkleSiblingPosition::Left => {
                                    PrivateOramAppendMerkleSiblingPositionV1::Left
                                }
                                PrivateResultOramMerkleSiblingPosition::Right => {
                                    PrivateOramAppendMerkleSiblingPositionV1::Right
                                }
                            },
                            hash: sibling.hash.clone(),
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramAppendSparseMerklePatchV1 {
    pub new_root_hash: String,
    pub final_buckets: Vec<PrivateOramAppendBucketRefV1>,
}

impl Debug for PrivateOramAppendSparseMerklePatchV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendSparseMerklePatchV1")
            .field("new_root_hash", &"[redacted]")
            .field("final_bucket_count", &self.final_buckets.len())
            .finish()
    }
}

pub fn apply_private_oram_append_sparse_merkle_patch_v1(
    expected_old_epoch: u64,
    expected_old_root_hash: &str,
    expected_bucket_count: u64,
    proof: &PrivateOramAppendMerklePatchProofV1,
    ordered_updates: &[PrivateOramAppendBucketRefV1],
) -> Result<PrivateOramAppendSparseMerklePatchV1, PrivateOramAppendClientError> {
    if proof.version != PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION
        || expected_bucket_count == 0
        || proof.index_epoch != expected_old_epoch
        || proof.old_root_hash != expected_old_root_hash
        || proof.bucket_count != expected_bucket_count
        || proof.leaves.is_empty()
        || proof.leaves.len() > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS
        || ordered_updates.is_empty()
        || ordered_updates.len() > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS
    {
        return Err(PrivateOramAppendClientError::InvalidMerklePatch);
    }

    let old_root = decode_merkle_patch_hash(expected_old_root_hash)?;
    let padded_bucket_count = expected_bucket_count
        .checked_next_power_of_two()
        .ok_or(PrivateOramAppendClientError::InvalidMerklePatch)?;
    let depth = padded_bucket_count.trailing_zeros();
    let depth_usize =
        usize::try_from(depth).map_err(|_| PrivateOramAppendClientError::InvalidMerklePatch)?;
    let mut old_nodes = BTreeMap::<(u32, u64), [u8; 32]>::new();
    let mut proven_bucket_ids = BTreeSet::new();

    for leaf in &proof.leaves {
        if leaf.bucket_id >= expected_bucket_count || leaf.siblings.len() != depth_usize {
            return Err(PrivateOramAppendClientError::InvalidMerklePatch);
        }
        let mut index = leaf.bucket_id;
        let mut node_hash = decode_merkle_patch_hash(&leaf.old_commitment)?;
        insert_consistent_merkle_node(&mut old_nodes, (0, index), node_hash)?;
        proven_bucket_ids.insert(leaf.bucket_id);

        for (expected_level, sibling) in leaf.siblings.iter().enumerate() {
            let expected_level = u32::try_from(expected_level)
                .map_err(|_| PrivateOramAppendClientError::InvalidMerklePatch)?;
            let expected_position = if index % 2 == 0 {
                PrivateOramAppendMerkleSiblingPositionV1::Right
            } else {
                PrivateOramAppendMerkleSiblingPositionV1::Left
            };
            if sibling.level != expected_level || sibling.position != expected_position {
                return Err(PrivateOramAppendClientError::InvalidMerklePatch);
            }
            let sibling_hash = decode_merkle_patch_hash(&sibling.hash)?;
            insert_consistent_merkle_node(
                &mut old_nodes,
                (expected_level, index ^ 1),
                sibling_hash,
            )?;
            node_hash = match sibling.position {
                PrivateOramAppendMerkleSiblingPositionV1::Left => {
                    private_oram_append_merkle_parent_hash(&sibling_hash, &node_hash)
                }
                PrivateOramAppendMerkleSiblingPositionV1::Right => {
                    private_oram_append_merkle_parent_hash(&node_hash, &sibling_hash)
                }
            };
            index /= 2;
            insert_consistent_merkle_node(
                &mut old_nodes,
                (
                    expected_level
                        .checked_add(1)
                        .ok_or(PrivateOramAppendClientError::InvalidMerklePatch)?,
                    index,
                ),
                node_hash,
            )?;
        }
        if node_hash != old_root {
            return Err(PrivateOramAppendClientError::MerklePatchMismatch);
        }
    }

    let mut final_buckets_by_id = BTreeMap::new();
    for bucket in ordered_updates {
        if bucket.bucket_id >= expected_bucket_count
            || !proven_bucket_ids.contains(&bucket.bucket_id)
        {
            return Err(PrivateOramAppendClientError::MerklePatchMismatch);
        }
        decode_merkle_patch_hash(&bucket.ciphertext_sha256)?;
        decode_merkle_patch_hash(&bucket.bucket_commitment)?;
        final_buckets_by_id.insert(bucket.bucket_id, bucket.clone());
    }

    let mut changed_nodes = final_buckets_by_id
        .iter()
        .map(|(bucket_id, bucket)| {
            Ok((
                *bucket_id,
                decode_merkle_patch_hash(&bucket.bucket_commitment)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, PrivateOramAppendClientError>>()?;

    for level in 0..depth {
        let parent_indexes = changed_nodes
            .keys()
            .map(|index| index / 2)
            .collect::<BTreeSet<_>>();
        let mut next_changed_nodes = BTreeMap::new();
        for parent_index in parent_indexes {
            let left_index = parent_index
                .checked_mul(2)
                .ok_or(PrivateOramAppendClientError::InvalidMerklePatch)?;
            let right_index = left_index
                .checked_add(1)
                .ok_or(PrivateOramAppendClientError::InvalidMerklePatch)?;
            let left_hash = changed_nodes
                .get(&left_index)
                .copied()
                .or_else(|| old_nodes.get(&(level, left_index)).copied())
                .ok_or(PrivateOramAppendClientError::InvalidMerklePatch)?;
            let right_hash = changed_nodes
                .get(&right_index)
                .copied()
                .or_else(|| old_nodes.get(&(level, right_index)).copied())
                .ok_or(PrivateOramAppendClientError::InvalidMerklePatch)?;
            next_changed_nodes.insert(
                parent_index,
                private_oram_append_merkle_parent_hash(&left_hash, &right_hash),
            );
        }
        changed_nodes = next_changed_nodes;
    }

    let new_root = changed_nodes
        .get(&0)
        .ok_or(PrivateOramAppendClientError::InvalidMerklePatch)?;
    Ok(PrivateOramAppendSparseMerklePatchV1 {
        new_root_hash: BASE64URL_NOPAD.encode(new_root),
        final_buckets: final_buckets_by_id.into_values().collect(),
    })
}

pub fn plan_private_oram_level0_hnsw_graph_delta_v2(
    manifest: &PrivateOramImmutableManifestV2,
    state: &PrivateOramSignedStateV2,
    checkpoint: &PrivateOramAppendClientCheckpointV2,
    index_name: &str,
    point: &PrivateOramAppendLevel0PointV2,
    candidate_blocks: &[PrivateHnswNodeBlockPlaintext],
    consumed_candidate_read_path_count: u32,
) -> Result<PrivateOramAppendLevel0HnswGraphDeltaV2, PrivateOramAppendClientError> {
    validate_private_oram_append_client_checkpoint_v2(checkpoint, manifest, state)?;
    validate_checkpoint_id(index_name, "index_name")?;
    if manifest
        .indexes
        .iter()
        .filter(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
        .count()
        != 1
    {
        return Err(PrivateOramAppendClientError::InvalidAppendInput(
            "index_topology",
        ));
    }

    let index_offset = manifest
        .indexes
        .iter()
        .position(|index| {
            index.kind() == PrivateOramIndexKindV2::Hnsw && index.index_name == index_name
        })
        .ok_or(PrivateOramAppendClientError::InvalidAppendInput(
            "index_name",
        ))?;
    let manifest_index = &manifest.indexes[index_offset];
    let state_index = &state.indexes[index_offset];
    let checkpoint_index = &checkpoint.indexes[index_offset];
    let (dim, distance, hnsw, oram, max_neighbor_rewrites, entry_node_id, hnsw_records) =
        match (&manifest_index.params, checkpoint_index) {
            (
                PrivateOramImmutableIndexParamsV2::Hnsw {
                    dim,
                    vector_encoding,
                    distance,
                    hnsw,
                    oram,
                    max_neighbor_rewrites,
                    ..
                },
                PrivateOramAppendClientIndexCheckpointV2::Hnsw {
                    entry_node_id,
                    records,
                    ..
                },
            ) if *vector_encoding == PrivateHnswVectorEncoding::F32Le => (
                *dim,
                *distance,
                hnsw,
                oram,
                *max_neighbor_rewrites,
                entry_node_id,
                records,
            ),
            _ => {
                return Err(PrivateOramAppendClientError::InvalidAppendInput("index"));
            }
        };
    if state_index.logical_count >= manifest_index.capacity.logical_capacity
        || state_index.dummy_count == 0
    {
        return Err(PrivateOramAppendClientError::AppendCapacityExhausted);
    }

    let expected_dim = usize::try_from(dim)
        .map_err(|_| PrivateOramAppendClientError::InvalidAppendInput("vector"))?;
    if point.node_id == [0; 32]
        || point.point_token == [0; 32]
        || point.vector.len() != expected_dim
        || point.vector.iter().any(|value| !value.is_finite())
    {
        return Err(PrivateOramAppendClientError::InvalidAppendInput("point"));
    }
    match manifest.result_privacy {
        ResultPrivacyMode::IdsVisible => {
            let visible_point_id = point.visible_point_id.as_deref().ok_or(
                PrivateOramAppendClientError::InvalidAppendInput("visible_point_id"),
            )?;
            validate_visible_point_id(visible_point_id).map_err(|_| {
                PrivateOramAppendClientError::InvalidAppendInput("visible_point_id")
            })?;
            if point.payload_fetch_token.is_some() {
                return Err(PrivateOramAppendClientError::InvalidAppendInput(
                    "payload_fetch_token",
                ));
            }
        }
        ResultPrivacyMode::PrivatePayloadOramRequired => {
            if point.visible_point_id.is_some()
                || point
                    .payload_fetch_token
                    .is_none_or(|payload_fetch_token| payload_fetch_token == [0; 32])
            {
                return Err(PrivateOramAppendClientError::InvalidAppendInput(
                    "payload_fetch_token",
                ));
            }
        }
    }

    let node_id = BASE64URL_NOPAD.encode(&point.node_id);
    let point_token = BASE64URL_NOPAD.encode(&point.point_token);
    let payload_fetch_token = point
        .payload_fetch_token
        .map(|token| BASE64URL_NOPAD.encode(&token));
    if hnsw_records
        .iter()
        .any(|record| record.node_id == node_id || record.point_token == point_token)
        || checkpoint.points.iter().any(|record| {
            record.point_token == point_token
                || point
                    .visible_point_id
                    .as_ref()
                    .is_some_and(|point_id| record.visible_point_id.as_ref() == Some(point_id))
                || payload_fetch_token
                    .as_ref()
                    .is_some_and(|token| record.payload_fetch_token.as_ref() == Some(token))
        })
    {
        return Err(PrivateOramAppendClientError::DuplicateCheckpointRecord);
    }

    let leaf_count = 1u64.checked_shl(oram.tree_height).ok_or(
        PrivateOramAppendClientError::InvalidAppendInput("initial_leaf"),
    )?;
    if point.initial_leaf >= leaf_count {
        return Err(PrivateOramAppendClientError::InvalidAppendInput(
            "initial_leaf",
        ));
    }
    let fixed_read_path_count = manifest_index.capacity.fixed_append_read_path_count;
    let rewrite_read_path_budget = max_neighbor_rewrites;
    let candidate_read_path_budget = fixed_read_path_count
        .checked_sub(
            rewrite_read_path_budget
                .checked_add(1)
                .ok_or(PrivateOramAppendClientError::AppendBudgetExceeded)?,
        )
        .ok_or(PrivateOramAppendClientError::AppendBudgetExceeded)?;
    if candidate_blocks.len()
        > usize::try_from(consumed_candidate_read_path_count)
            .map_err(|_| PrivateOramAppendClientError::AppendBudgetExceeded)?
        || consumed_candidate_read_path_count > candidate_read_path_budget
    {
        return Err(PrivateOramAppendClientError::AppendBudgetExceeded);
    }
    if hnsw_records.is_empty() {
        if entry_node_id.is_some()
            || !candidate_blocks.is_empty()
            || consumed_candidate_read_path_count != 0
        {
            return Err(PrivateOramAppendClientError::AppendCandidateMismatch);
        }
    } else if entry_node_id.is_none() || candidate_blocks.is_empty() {
        return Err(PrivateOramAppendClientError::AppendCandidateMismatch);
    }

    let config = PrivateHnswOramClientConfig {
        tree_height: oram.tree_height,
        bucket_size: usize::try_from(oram.bucket_size)
            .map_err(|_| PrivateOramAppendClientError::InvalidAppendInput("oram"))?,
        block_size_bytes: usize::try_from(oram.block_size_bytes)
            .map_err(|_| PrivateOramAppendClientError::InvalidAppendInput("oram"))?,
        fixed_neighbor_slots: usize::try_from(hnsw.fixed_neighbor_slots)
            .map_err(|_| PrivateOramAppendClientError::InvalidAppendInput("hnsw"))?,
    };
    let records_by_node = hnsw_records
        .iter()
        .map(|record| {
            Ok((
                decode_base64url_32(&record.node_id, "records.node_id")?,
                record,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, PrivateOramAppendClientError>>()?;
    let points_by_token = checkpoint
        .points
        .iter()
        .map(|record| {
            Ok((
                decode_base64url_32(&record.point_token, "points.point_token")?,
                record,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, PrivateOramAppendClientError>>()?;
    let mut evidence = BTreeMap::<[u8; 32], (&PrivateHnswNodeBlockPlaintext, Vec<f32>)>::new();
    for block in candidate_blocks {
        encode_private_hnsw_node_block(
            block,
            config.block_size_bytes,
            config.fixed_neighbor_slots,
        )?;
        let record = records_by_node
            .get(&block.node_id)
            .ok_or(PrivateOramAppendClientError::AppendCandidateMismatch)?;
        let point_record = points_by_token
            .get(&block.point_token)
            .ok_or(PrivateOramAppendClientError::AppendCandidateMismatch)?;
        if block.deleted
            || record.point_token != BASE64URL_NOPAD.encode(&block.point_token)
            || record.level_mask != block.level_mask
            || record.generation != block.generation
            || point_record.payload_fetch_token
                != block
                    .payload_fetch_token
                    .map(|token| BASE64URL_NOPAD.encode(&token))
            || block.neighbors.iter().any(|neighbor| {
                !records_by_node.contains_key(neighbor) || *neighbor == point.node_id
            })
        {
            return Err(PrivateOramAppendClientError::AppendCandidateMismatch);
        }
        let vector = decode_private_hnsw_f32_vector(block)?;
        if vector.len() != expected_dim
            || vector.iter().any(|value| !value.is_finite())
            || evidence.insert(block.node_id, (block, vector)).is_some()
        {
            return Err(PrivateOramAppendClientError::AppendCandidateMismatch);
        }
    }

    let max_neighbors = usize::try_from(hnsw.m)
        .map_err(|_| PrivateOramAppendClientError::InvalidAppendInput("hnsw.m"))?
        .min(config.fixed_neighbor_slots)
        .min(evidence.len());
    let candidate_vectors = evidence
        .iter()
        .map(|(candidate_id, (_, vector))| (*candidate_id, vector.clone()))
        .collect::<Vec<_>>();
    let mut selected_neighbor_ids = select_private_oram_append_neighbors(
        &point.vector,
        &candidate_vectors,
        distance,
        max_neighbors,
    )?;
    if !hnsw_records.is_empty() && selected_neighbor_ids.is_empty() {
        return Err(PrivateOramAppendClientError::AppendCandidateMismatch);
    }

    let mut neighbor_rewrites = Vec::new();
    let rewrite_limit = usize::try_from(max_neighbor_rewrites)
        .map_err(|_| PrivateOramAppendClientError::InvalidAppendInput("max_neighbor_rewrites"))?;
    for neighbor_id in &selected_neighbor_ids {
        if neighbor_rewrites.len() == rewrite_limit {
            break;
        }
        let Some(rewrite) = plan_private_oram_append_reverse_edge(
            *neighbor_id,
            point.node_id,
            &point.vector,
            &evidence,
            config,
            distance,
        )?
        else {
            continue;
        };
        neighbor_rewrites.push(rewrite);
    }
    let old_entry_node_id = entry_node_id
        .as_deref()
        .map(|entry| decode_base64url_32(entry, "entry_node_id"))
        .transpose()?;
    let next_entry_node_id = if hnsw_records.is_empty() {
        point.node_id
    } else if neighbor_rewrites.is_empty() {
        let old_entry_node_id =
            old_entry_node_id.ok_or(PrivateOramAppendClientError::AppendCandidateMismatch)?;
        if !evidence.contains_key(&old_entry_node_id) {
            return Err(PrivateOramAppendClientError::AppendCandidateMismatch);
        }
        if !selected_neighbor_ids.contains(&old_entry_node_id) {
            if selected_neighbor_ids.len() < max_neighbors {
                selected_neighbor_ids.push(old_entry_node_id);
            } else {
                let last = selected_neighbor_ids
                    .last_mut()
                    .ok_or(PrivateOramAppendClientError::AppendCandidateMismatch)?;
                *last = old_entry_node_id;
            }
        }
        point.node_id
    } else {
        old_entry_node_id.ok_or(PrivateOramAppendClientError::AppendCandidateMismatch)?
    };

    let vector = point
        .vector
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let new_block = PrivateHnswNodeBlockPlaintext {
        version: PRIVATE_HNSW_NODE_BLOCK_VERSION,
        node_id: point.node_id,
        point_token: point.point_token,
        level_mask: 1,
        vector_encoding: PrivateHnswVectorEncoding::F32Le,
        vector,
        neighbors: selected_neighbor_ids.clone(),
        neighbor_levels: vec![0; selected_neighbor_ids.len()],
        deleted: false,
        generation: 1,
        payload_fetch_token: point.payload_fetch_token,
    };
    encode_private_hnsw_node_block(
        &new_block,
        config.block_size_bytes,
        config.fixed_neighbor_slots,
    )?;
    let rewrite_read_path_count = u32::try_from(neighbor_rewrites.len())
        .map_err(|_| PrivateOramAppendClientError::AppendBudgetExceeded)?;
    let real_read_path_count = consumed_candidate_read_path_count
        .checked_add(rewrite_read_path_count)
        .and_then(|count| count.checked_add(1))
        .ok_or(PrivateOramAppendClientError::AppendBudgetExceeded)?;

    Ok(PrivateOramAppendLevel0HnswGraphDeltaV2 {
        index_name: index_name.to_string(),
        point_record: PrivateOramAppendPointRecordV2 {
            point_token,
            visible_point_id: point.visible_point_id.clone(),
            payload_fetch_token,
        },
        hnsw_record: PrivateOramAppendHnswRecordV2 {
            node_id,
            point_token: BASE64URL_NOPAD.encode(&point.point_token),
            level_mask: 1,
            generation: 1,
        },
        new_block,
        next_entry_node_id,
        selected_neighbor_ids,
        neighbor_rewrites,
        fixed_read_path_count,
        candidate_read_path_budget,
        candidate_read_path_count: consumed_candidate_read_path_count,
        rewrite_read_path_budget,
        rewrite_read_path_count,
        real_read_path_count,
        padding_read_path_count: fixed_read_path_count - real_read_path_count,
    })
}

pub fn validate_private_oram_append_client_checkpoint_v2_shape(
    checkpoint: &PrivateOramAppendClientCheckpointV2,
) -> Result<(), PrivateOramAppendClientError> {
    if checkpoint.version != PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_V2_VERSION {
        return Err(PrivateOramAppendClientError::UnsupportedCheckpointVersion(
            checkpoint.version,
        ));
    }
    validate_checkpoint_id(&checkpoint.collection_id, "collection_id")?;
    decode_base64url_32(&checkpoint.manifest_digest, "manifest_digest")?;
    if checkpoint.layout_generation == 0 {
        return Err(PrivateOramAppendClientError::InvalidCheckpointField(
            "layout_generation",
        ));
    }
    if checkpoint.indexes.is_empty() {
        return Err(PrivateOramAppendClientError::InvalidCheckpointIndexes);
    }

    let point_records = validate_point_records(&checkpoint.points)?;
    let mut previous_index = None;
    for index in &checkpoint.indexes {
        validate_checkpoint_id(index.index_name(), "indexes.index_name")?;
        decode_base64url_32(index.root_hash(), "indexes.root_hash")?;
        let key = (checkpoint_index_tag(index.kind()), index.index_name());
        if previous_index.is_some_and(|previous| previous >= key) {
            return Err(PrivateOramAppendClientError::InvalidCheckpointIndexes);
        }
        previous_index = Some(key);

        match index {
            PrivateOramAppendClientIndexCheckpointV2::Hnsw {
                entry_node_id,
                state,
                records,
                ..
            } => validate_hnsw_checkpoint_index(entry_node_id, state, records, &point_records)?,
            PrivateOramAppendClientIndexCheckpointV2::Result { state, records, .. } => {
                validate_result_checkpoint_index(state, records, &point_records)?
            }
        }
    }
    Ok(())
}

pub fn validate_private_oram_append_client_checkpoint_v2(
    checkpoint: &PrivateOramAppendClientCheckpointV2,
    manifest: &PrivateOramImmutableManifestV2,
    state: &PrivateOramSignedStateV2,
) -> Result<(), PrivateOramAppendClientError> {
    validate_private_oram_append_client_checkpoint_v2_shape(checkpoint)?;
    let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
    if checkpoint.collection_id != manifest.collection_id
        || checkpoint.collection_id != state.collection_id
        || checkpoint.manifest_digest != manifest_digest
        || checkpoint.manifest_digest != state.manifest_digest
        || checkpoint.layout_generation != state.layout_generation
        || checkpoint.state_sequence != state.state_sequence
        || checkpoint.indexes.len() != manifest.indexes.len()
        || checkpoint.indexes.len() != state.indexes.len()
    {
        return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
    }

    let expected_logical_count = state
        .indexes
        .first()
        .and_then(|index| usize::try_from(index.logical_count).ok())
        .ok_or(PrivateOramAppendClientError::CheckpointStateMismatch)?;
    if checkpoint.points.len() != expected_logical_count {
        return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
    }
    match manifest.result_privacy {
        ResultPrivacyMode::IdsVisible => {
            if checkpoint.points.iter().any(|record| {
                record.visible_point_id.is_none() || record.payload_fetch_token.is_some()
            }) {
                return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
            }
        }
        ResultPrivacyMode::PrivatePayloadOramRequired => {
            if checkpoint.points.iter().any(|record| {
                record.visible_point_id.is_some() || record.payload_fetch_token.is_none()
            }) {
                return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
            }
        }
    }

    for ((checkpoint_index, manifest_index), state_index) in checkpoint
        .indexes
        .iter()
        .zip(&manifest.indexes)
        .zip(&state.indexes)
    {
        if checkpoint_index.kind() != manifest_index.kind()
            || checkpoint_index.kind() != state_index.kind
            || checkpoint_index.index_name() != manifest_index.index_name
            || checkpoint_index.index_name() != state_index.index_name
            || checkpoint_index.index_epoch() != state_index.index_epoch
            || checkpoint_index.root_hash() != state_index.root_hash
        {
            return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
        }
        let expected_logical_count = usize::try_from(state_index.logical_count)
            .map_err(|_| PrivateOramAppendClientError::CheckpointStateMismatch)?;
        let max_stash = usize::try_from(manifest_index.capacity.max_client_stash_blocks)
            .map_err(|_| PrivateOramAppendClientError::CheckpointStateMismatch)?;
        let expected_tree_height = match &manifest_index.params {
            PrivateOramImmutableIndexParamsV2::Hnsw { oram, .. }
            | PrivateOramImmutableIndexParamsV2::Result { oram, .. } => oram.tree_height,
        };

        match checkpoint_index {
            PrivateOramAppendClientIndexCheckpointV2::Hnsw { state, records, .. } => {
                if state.tree_height != expected_tree_height
                    || records.len() != expected_logical_count
                    || state.stash.len() > max_stash
                {
                    return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
                }
            }
            PrivateOramAppendClientIndexCheckpointV2::Result { state, records, .. } => {
                if state.tree_height != expected_tree_height
                    || records.len() != expected_logical_count
                    || state.stash.len() > max_stash
                {
                    return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
                }
            }
        }
    }
    Ok(())
}

pub fn try_private_oram_append_client_checkpoint_plaintext_v3_digest_message(
    checkpoint: &PrivateOramAppendClientCheckpointV2,
) -> Result<Vec<u8>, PrivateOramAppendClientError> {
    validate_private_oram_append_client_checkpoint_v2_shape(checkpoint)?;
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_PLAINTEXT_V3_DIGEST_DOMAIN.as_bytes(),
    )?;
    message.extend_from_slice(&checkpoint.version.to_be_bytes());
    push_str(&mut message, &checkpoint.collection_id)?;
    push_str(&mut message, &checkpoint.manifest_digest)?;
    message.extend_from_slice(&checkpoint.layout_generation.to_be_bytes());
    message.extend_from_slice(&checkpoint.state_sequence.to_be_bytes());
    push_len(&mut message, checkpoint.points.len())?;
    for point in &checkpoint.points {
        push_point_record_v3(&mut message, point)?;
    }
    push_len(&mut message, checkpoint.indexes.len())?;
    for index in &checkpoint.indexes {
        match index {
            PrivateOramAppendClientIndexCheckpointV2::Hnsw {
                index_name,
                index_epoch,
                root_hash,
                entry_node_id,
                state,
                records,
            } => {
                message.push(1);
                push_str(&mut message, index_name)?;
                message.extend_from_slice(&index_epoch.to_be_bytes());
                push_str(&mut message, root_hash)?;
                push_optional_str(&mut message, entry_node_id.as_deref())?;
                push_hnsw_client_state_v3(&mut message, state)?;
                push_len(&mut message, records.len())?;
                for record in records {
                    push_hnsw_record_v3(&mut message, record)?;
                }
            }
            PrivateOramAppendClientIndexCheckpointV2::Result {
                index_name,
                index_epoch,
                root_hash,
                state,
                records,
            } => {
                message.push(2);
                push_str(&mut message, index_name)?;
                message.extend_from_slice(&index_epoch.to_be_bytes());
                push_str(&mut message, root_hash)?;
                push_result_client_state_v3(&mut message, state)?;
                push_len(&mut message, records.len())?;
                for record in records {
                    push_result_record_v3(&mut message, record)?;
                }
            }
        }
    }
    Ok(message)
}

pub fn private_oram_append_client_checkpoint_plaintext_v3_digest(
    checkpoint: &PrivateOramAppendClientCheckpointV2,
) -> Result<String, PrivateOramAppendClientError> {
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(
        try_private_oram_append_client_checkpoint_plaintext_v3_digest_message(checkpoint)?,
    )))
}

pub fn try_private_oram_append_hnsw_client_state_v3_digest_message(
    state: &PrivateHnswOramClientStateSnapshot,
) -> Result<Vec<u8>, PrivateOramAppendClientError> {
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_APPEND_HNSW_CLIENT_STATE_V3_DIGEST_DOMAIN.as_bytes(),
    )?;
    push_hnsw_client_state_v3(&mut message, state)?;
    Ok(message)
}

pub fn private_oram_append_hnsw_client_state_v3_digest(
    state: &PrivateHnswOramClientStateSnapshot,
) -> Result<String, PrivateOramAppendClientError> {
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(
        try_private_oram_append_hnsw_client_state_v3_digest_message(state)?,
    )))
}

pub fn try_private_oram_append_result_client_state_v3_digest_message(
    state: &PrivateResultOramClientStateSnapshot,
) -> Result<Vec<u8>, PrivateOramAppendClientError> {
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_APPEND_RESULT_CLIENT_STATE_V3_DIGEST_DOMAIN.as_bytes(),
    )?;
    push_result_client_state_v3(&mut message, state)?;
    Ok(message)
}

pub fn private_oram_append_result_client_state_v3_digest(
    state: &PrivateResultOramClientStateSnapshot,
) -> Result<String, PrivateOramAppendClientError> {
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(
        try_private_oram_append_result_client_state_v3_digest_message(state)?,
    )))
}

pub fn seal_private_oram_append_client_checkpoint_v2(
    checkpoint_key: &SecretKey,
    checkpoint: &PrivateOramAppendClientCheckpointV2,
) -> Result<PrivateOramSealedAppendClientCheckpointV2, PrivateOramAppendClientError> {
    validate_private_oram_append_client_checkpoint_v2_shape(checkpoint)?;
    // The checkpoint carries the position maps and stashes; the working buffer is zeroized.
    let plaintext = Zeroizing::new(
        serde_json::to_vec(checkpoint)
            .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointField("checkpoint"))?,
    );
    if plaintext.len() > PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_MAX_BYTES {
        return Err(PrivateOramAppendClientError::InvalidCheckpointField(
            "checkpoint_size",
        ));
    }

    let key = derive_checkpoint_key(
        checkpoint_key,
        &checkpoint.collection_id,
        &checkpoint.manifest_digest,
    )?;
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| EncryptionError::RandomFailure)?;
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key.as_bytes()).map_err(|_| EncryptionError::SealFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = checkpoint_aad(
        checkpoint.version,
        &checkpoint.collection_id,
        &checkpoint.manifest_digest,
        checkpoint.layout_generation,
        checkpoint.state_sequence,
    )?;
    let mut ciphertext = plaintext;
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad.as_slice()), &mut ciphertext[..])
        .map_err(|_| EncryptionError::SealFailed)?;

    let mut encoded = Vec::with_capacity(
        1 + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN
            + ciphertext.len()
            + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_TAG_LEN,
    );
    encoded.push(PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AEAD_VERSION);
    encoded.extend_from_slice(&nonce_bytes);
    encoded.extend_from_slice(&ciphertext[..]);
    encoded.extend_from_slice(tag.as_ref());
    let ciphertext_sha256 = base64url_sha256(&encoded);

    Ok(PrivateOramSealedAppendClientCheckpointV2 {
        version: checkpoint.version,
        collection_id: checkpoint.collection_id.clone(),
        manifest_digest: checkpoint.manifest_digest.clone(),
        layout_generation: checkpoint.layout_generation,
        state_sequence: checkpoint.state_sequence,
        ciphertext: BASE64URL_NOPAD.encode(&encoded),
        ciphertext_sha256,
    })
}

pub fn try_private_oram_append_client_checkpoint_v2_digest_message(
    sealed: &PrivateOramSealedAppendClientCheckpointV2,
) -> Result<Vec<u8>, PrivateOramAppendClientError> {
    validate_sealed_checkpoint_shape(sealed)?;
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_DIGEST_DOMAIN.as_bytes(),
    )?;
    message.extend_from_slice(&sealed.version.to_be_bytes());
    push_str(&mut message, &sealed.collection_id)?;
    push_str(&mut message, &sealed.manifest_digest)?;
    message.extend_from_slice(&sealed.layout_generation.to_be_bytes());
    message.extend_from_slice(&sealed.state_sequence.to_be_bytes());
    push_str(&mut message, &sealed.ciphertext_sha256)?;
    Ok(message)
}

pub fn private_oram_append_client_checkpoint_v2_digest(
    sealed: &PrivateOramSealedAppendClientCheckpointV2,
) -> Result<String, PrivateOramAppendClientError> {
    Ok(base64url_sha256(
        &try_private_oram_append_client_checkpoint_v2_digest_message(sealed)?,
    ))
}

pub fn bind_private_oram_append_client_checkpoint_v2(
    sealed: PrivateOramSealedAppendClientCheckpointV2,
    state: &PrivateOramSignedStateV2,
) -> Result<PrivateOramEncryptedAppendClientCheckpointV2, PrivateOramAppendClientError> {
    validate_sealed_checkpoint_shape(&sealed)?;
    if sealed.collection_id != state.collection_id
        || sealed.manifest_digest != state.manifest_digest
        || sealed.layout_generation != state.layout_generation
        || sealed.state_sequence != state.state_sequence
        || private_oram_append_client_checkpoint_v2_digest(&sealed)? != state.client_state_digest
    {
        return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
    }
    Ok(PrivateOramEncryptedAppendClientCheckpointV2 {
        sealed,
        state_digest: private_oram_signed_state_v2_digest(state)?,
    })
}

pub fn open_private_oram_append_client_checkpoint_v2(
    checkpoint_key: &SecretKey,
    encrypted: &PrivateOramEncryptedAppendClientCheckpointV2,
    manifest: &PrivateOramImmutableManifestV2,
    state: &PrivateOramSignedStateV2,
) -> Result<PrivateOramAppendClientCheckpointV2, PrivateOramAppendClientError> {
    validate_sealed_checkpoint_shape(&encrypted.sealed)?;
    decode_base64url_32(&encrypted.state_digest, "state_digest")?;
    if encrypted.state_digest != private_oram_signed_state_v2_digest(state)?
        || encrypted.sealed.collection_id != state.collection_id
        || encrypted.sealed.manifest_digest != state.manifest_digest
        || encrypted.sealed.layout_generation != state.layout_generation
        || encrypted.sealed.state_sequence != state.state_sequence
        || private_oram_append_client_checkpoint_v2_digest(&encrypted.sealed)?
            != state.client_state_digest
    {
        return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
    }

    let raw = BASE64URL_NOPAD
        .decode(encrypted.sealed.ciphertext.as_bytes())
        .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointCiphertext)?;
    if raw.len()
        > PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_MAX_BYTES
            + 1
            + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN
            + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_TAG_LEN
        || base64url_sha256(&raw) != encrypted.sealed.ciphertext_sha256
    {
        return Err(PrivateOramAppendClientError::InvalidCheckpointCiphertextHash);
    }
    let min_len = 1
        + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN
        + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_TAG_LEN;
    if raw.len() < min_len || raw[0] != PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AEAD_VERSION {
        return Err(PrivateOramAppendClientError::InvalidCheckpointCiphertext);
    }
    let nonce_bytes: [u8; PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN] = raw
        [1..1 + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN]
        .try_into()
        .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointCiphertext)?;
    let mut ciphertext =
        Zeroizing::new(raw[1 + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN..].to_vec());
    let key = derive_checkpoint_key(
        checkpoint_key,
        &encrypted.sealed.collection_id,
        &encrypted.sealed.manifest_digest,
    )?;
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key.as_bytes()).map_err(|_| EncryptionError::OpenFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = checkpoint_aad(
        encrypted.sealed.version,
        &encrypted.sealed.collection_id,
        &encrypted.sealed.manifest_digest,
        encrypted.sealed.layout_generation,
        encrypted.sealed.state_sequence,
    )?;
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext[..])
        .map_err(|_| PrivateOramAppendClientError::CheckpointOpenFailed)?;
    let checkpoint: PrivateOramAppendClientCheckpointV2 = serde_json::from_slice(plaintext)
        .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointCiphertext)?;
    if checkpoint.version != encrypted.sealed.version
        || checkpoint.collection_id != encrypted.sealed.collection_id
        || checkpoint.manifest_digest != encrypted.sealed.manifest_digest
        || checkpoint.layout_generation != encrypted.sealed.layout_generation
        || checkpoint.state_sequence != encrypted.sealed.state_sequence
    {
        return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
    }
    validate_private_oram_append_client_checkpoint_v2(&checkpoint, manifest, state)?;
    Ok(checkpoint)
}

fn select_private_oram_append_neighbors(
    source_vector: &[f32],
    candidates: &[([u8; 32], Vec<f32>)],
    distance: crate::private_hnsw_oram::DistanceKind,
    max_neighbors: usize,
) -> Result<Vec<[u8; 32]>, PrivateOramAppendClientError> {
    if max_neighbors == 0 {
        return Ok(Vec::new());
    }
    let mut seen = BTreeSet::new();
    let mut ranked = Vec::with_capacity(candidates.len());
    for (candidate_id, vector) in candidates {
        if !seen.insert(*candidate_id)
            || vector.len() != source_vector.len()
            || vector.iter().any(|value| !value.is_finite())
        {
            return Err(PrivateOramAppendClientError::AppendCandidateMismatch);
        }
        ranked.push((
            private_hnsw_f32_distance(source_vector, vector, distance)?,
            *candidate_id,
            vector,
        ));
    }
    ranked.sort_by(|lhs, rhs| lhs.0.total_cmp(&rhs.0).then_with(|| lhs.1.cmp(&rhs.1)));

    let mut selected = Vec::new();
    let mut selected_vectors = Vec::<&Vec<f32>>::new();
    for (source_distance, candidate_id, candidate_vector) in ranked {
        let mut redundant = false;
        for selected_vector in &selected_vectors {
            if private_hnsw_f32_distance(candidate_vector, selected_vector, distance)?
                < source_distance
            {
                redundant = true;
                break;
            }
        }
        if redundant {
            continue;
        }
        selected.push(candidate_id);
        selected_vectors.push(candidate_vector);
        if selected.len() == max_neighbors {
            break;
        }
    }
    Ok(selected)
}

fn plan_private_oram_append_reverse_edge(
    source_node_id: [u8; 32],
    new_node_id: [u8; 32],
    new_vector: &[f32],
    evidence: &BTreeMap<[u8; 32], (&PrivateHnswNodeBlockPlaintext, Vec<f32>)>,
    config: PrivateHnswOramClientConfig,
    distance: crate::private_hnsw_oram::DistanceKind,
) -> Result<Option<PrivateOramAppendHnswNeighborRewriteV2>, PrivateOramAppendClientError> {
    let (previous, source_vector) = evidence
        .get(&source_node_id)
        .map(|(block, vector)| (*block, vector))
        .ok_or(PrivateOramAppendClientError::AppendCandidateMismatch)?;
    let upper_neighbors = previous
        .neighbors
        .iter()
        .copied()
        .zip(previous.neighbor_levels.iter().copied())
        .filter(|(_, level)| *level > 0)
        .collect::<Vec<_>>();
    let level0_capacity = config
        .fixed_neighbor_slots
        .checked_sub(upper_neighbors.len())
        .ok_or(PrivateOramAppendClientError::AppendCandidateMismatch)?;
    if level0_capacity == 0 {
        return Ok(None);
    }

    let mut candidate_vectors = Vec::new();
    for (neighbor_id, level) in previous.neighbors.iter().zip(&previous.neighbor_levels) {
        if *level != 0 {
            continue;
        }
        let (_, vector) = evidence
            .get(neighbor_id)
            .ok_or(PrivateOramAppendClientError::AppendCandidateMismatch)?;
        candidate_vectors.push((*neighbor_id, vector.clone()));
    }
    candidate_vectors.push((new_node_id, new_vector.to_vec()));
    let selected_level0 = select_private_oram_append_neighbors(
        source_vector,
        &candidate_vectors,
        distance,
        level0_capacity,
    )?;
    if !selected_level0.contains(&new_node_id) {
        return Ok(None);
    }

    let mut replacement = previous.clone();
    replacement.neighbors = upper_neighbors
        .iter()
        .map(|(neighbor_id, _)| *neighbor_id)
        .chain(selected_level0.iter().copied())
        .collect();
    replacement.neighbor_levels = upper_neighbors
        .iter()
        .map(|(_, level)| *level)
        .chain(std::iter::repeat(0).take(selected_level0.len()))
        .collect();
    replacement.generation = replacement.generation.checked_add(1).ok_or(
        PrivateOramAppendClientError::InvalidAppendInput("generation"),
    )?;
    encode_private_hnsw_node_block(
        &replacement,
        config.block_size_bytes,
        config.fixed_neighbor_slots,
    )?;
    Ok(Some(PrivateOramAppendHnswNeighborRewriteV2 {
        previous: previous.clone(),
        replacement,
    }))
}

fn validate_hnsw_checkpoint_index(
    entry_node_id: &Option<String>,
    state: &PrivateHnswOramClientStateSnapshot,
    records: &[PrivateOramAppendHnswRecordV2],
    point_records: &BTreeMap<[u8; 32], &PrivateOramAppendPointRecordV2>,
) -> Result<(), PrivateOramAppendClientError> {
    PrivateHnswOramClientState::from_snapshot(state)?;
    let entry_node_id = entry_node_id
        .as_deref()
        .map(|entry_node_id| decode_base64url_32(entry_node_id, "entry_node_id"))
        .transpose()?;
    let mut previous_node_id = None;
    let mut node_ids = BTreeSet::new();
    let mut point_tokens = BTreeSet::new();
    let mut records_by_node = BTreeMap::new();
    for record in records {
        let node_id = decode_base64url_32(&record.node_id, "records.node_id")?;
        let point_token = decode_base64url_32(&record.point_token, "records.point_token")?;
        if previous_node_id.is_some_and(|previous| previous >= node_id)
            || !node_ids.insert(node_id)
            || !point_tokens.insert(point_token)
            || record.level_mask == 0
        {
            return Err(PrivateOramAppendClientError::DuplicateCheckpointRecord);
        }
        if !point_records.contains_key(&point_token) {
            return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
        }
        previous_node_id = Some(node_id);
        records_by_node.insert(node_id, record);
    }
    if point_tokens.len() != point_records.len() {
        return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
    }
    if (node_ids.is_empty() && entry_node_id.is_some())
        || (!node_ids.is_empty() && entry_node_id.is_none())
        || entry_node_id.is_some_and(|entry_node_id| !node_ids.contains(&entry_node_id))
    {
        return Err(PrivateOramAppendClientError::InvalidCheckpointField(
            "entry_node_id",
        ));
    }

    let snapshot_node_ids = state
        .positions
        .iter()
        .map(|position| decode_base64url_32(&position.node_id, "positions.node_id"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if snapshot_node_ids != node_ids || state.positions.len() != node_ids.len() {
        return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
    }
    for block in &state.stash {
        let Some(record) = records_by_node.get(&block.node_id) else {
            return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
        };
        if block.deleted
            || BASE64URL_NOPAD.encode(&block.point_token) != record.point_token
            || block.level_mask != record.level_mask
            || block.generation != record.generation
        {
            return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
        }
        let point_record = point_records
            .get(&block.point_token)
            .ok_or(PrivateOramAppendClientError::CheckpointStateMismatch)?;
        if block
            .payload_fetch_token
            .map(|token| BASE64URL_NOPAD.encode(&token))
            != point_record.payload_fetch_token
        {
            return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
        }
    }
    Ok(())
}

fn validate_result_checkpoint_index(
    state: &PrivateResultOramClientStateSnapshot,
    records: &[PrivateOramAppendResultRecordV2],
    point_records: &BTreeMap<[u8; 32], &PrivateOramAppendPointRecordV2>,
) -> Result<(), PrivateOramAppendClientError> {
    PrivateResultOramClientState::from_snapshot(state)?;
    let mut previous_payload_fetch_token = None;
    let mut payload_fetch_tokens = BTreeSet::new();
    let mut point_tokens = BTreeSet::new();
    let mut records_by_token = BTreeMap::new();
    for record in records {
        let payload_fetch_token =
            decode_base64url_32(&record.payload_fetch_token, "records.payload_fetch_token")?;
        let point_token = decode_base64url_32(&record.point_token, "records.point_token")?;
        if previous_payload_fetch_token.is_some_and(|previous| previous >= payload_fetch_token)
            || !payload_fetch_tokens.insert(payload_fetch_token)
            || !point_tokens.insert(point_token)
        {
            return Err(PrivateOramAppendClientError::DuplicateCheckpointRecord);
        }
        if point_records
            .get(&point_token)
            .and_then(|point| point.payload_fetch_token.as_deref())
            .is_none_or(|expected| expected != record.payload_fetch_token)
        {
            return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
        }
        previous_payload_fetch_token = Some(payload_fetch_token);
        records_by_token.insert(payload_fetch_token, record);
    }
    if point_tokens.len() != point_records.len() {
        return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
    }
    let snapshot_tokens = state
        .positions
        .iter()
        .map(|position| {
            decode_base64url_32(
                &position.payload_fetch_token,
                "positions.payload_fetch_token",
            )
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if snapshot_tokens != payload_fetch_tokens
        || state.positions.len() != payload_fetch_tokens.len()
    {
        return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
    }
    for block in &state.stash {
        let Some(record) = records_by_token.get(&block.payload_fetch_token) else {
            return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
        };
        if block.deleted
            || BASE64URL_NOPAD.encode(&block.point_token) != record.point_token
            || block.generation != record.generation
        {
            return Err(PrivateOramAppendClientError::CheckpointStateMismatch);
        }
    }
    Ok(())
}

fn validate_point_records(
    records: &[PrivateOramAppendPointRecordV2],
) -> Result<BTreeMap<[u8; 32], &PrivateOramAppendPointRecordV2>, PrivateOramAppendClientError> {
    let mut previous_point_token = None;
    let mut visible_point_ids = BTreeSet::new();
    let mut payload_fetch_tokens = BTreeSet::new();
    let mut records_by_point_token = BTreeMap::new();
    for record in records {
        let point_token = decode_base64url_32(&record.point_token, "points.point_token")?;
        if previous_point_token.is_some_and(|previous| previous >= point_token)
            || records_by_point_token.insert(point_token, record).is_some()
        {
            return Err(PrivateOramAppendClientError::DuplicateCheckpointRecord);
        }
        previous_point_token = Some(point_token);
        if let Some(point_id) = record.visible_point_id.as_deref() {
            validate_visible_point_id(point_id)?;
            if !visible_point_ids.insert(point_id) {
                return Err(PrivateOramAppendClientError::DuplicateCheckpointRecord);
            }
        }
        if let Some(payload_fetch_token) = record.payload_fetch_token.as_deref() {
            let payload_fetch_token =
                decode_base64url_32(payload_fetch_token, "points.payload_fetch_token")?;
            if !payload_fetch_tokens.insert(payload_fetch_token) {
                return Err(PrivateOramAppendClientError::DuplicateCheckpointRecord);
            }
        }
    }
    Ok(records_by_point_token)
}

fn validate_sealed_checkpoint_shape(
    sealed: &PrivateOramSealedAppendClientCheckpointV2,
) -> Result<(), PrivateOramAppendClientError> {
    if sealed.version != PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_V2_VERSION {
        return Err(PrivateOramAppendClientError::UnsupportedCheckpointVersion(
            sealed.version,
        ));
    }
    validate_checkpoint_id(&sealed.collection_id, "collection_id")?;
    decode_base64url_32(&sealed.manifest_digest, "manifest_digest")?;
    decode_base64url_32(&sealed.ciphertext_sha256, "ciphertext_sha256")?;
    if sealed.layout_generation == 0 || sealed.ciphertext.is_empty() {
        return Err(PrivateOramAppendClientError::InvalidCheckpointField(
            "sealed",
        ));
    }
    let max_encoded_len = base64url_nopad_encoded_len(
        PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_MAX_BYTES
            + 1
            + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN
            + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_TAG_LEN,
    )
    .ok_or(PrivateOramAppendClientError::InvalidCheckpointCiphertext)?;
    if sealed.ciphertext.len() > max_encoded_len {
        return Err(PrivateOramAppendClientError::InvalidCheckpointCiphertext);
    }
    let raw = BASE64URL_NOPAD
        .decode(sealed.ciphertext.as_bytes())
        .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointCiphertext)?;
    let minimum_len = 1
        + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN
        + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_TAG_LEN;
    if raw.len() < minimum_len
        || raw.len()
            > PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_MAX_BYTES
                + 1
                + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_NONCE_LEN
                + PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_TAG_LEN
        || raw[0] != PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AEAD_VERSION
    {
        return Err(PrivateOramAppendClientError::InvalidCheckpointCiphertext);
    }
    if base64url_sha256(&raw) != sealed.ciphertext_sha256 {
        return Err(PrivateOramAppendClientError::InvalidCheckpointCiphertextHash);
    }
    Ok(())
}

fn derive_checkpoint_key(
    checkpoint_key: &SecretKey,
    collection_id: &str,
    manifest_digest: &str,
) -> Result<SecretKey, PrivateOramAppendClientError> {
    checkpoint_key
        .derive_subkey_with_context(
            PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AEAD_DOMAIN,
            PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_KDF_CONTEXT_DOMAIN,
            &[collection_id.as_bytes(), manifest_digest.as_bytes()],
        )
        .map_err(PrivateOramAppendClientError::Encryption)
}

fn checkpoint_aad(
    version: u16,
    collection_id: &str,
    manifest_digest: &str,
    layout_generation: u64,
    state_sequence: u64,
) -> Result<Vec<u8>, PrivateOramAppendClientError> {
    let mut aad = Vec::new();
    push_domain(&mut aad, PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_AAD_DOMAIN)?;
    aad.extend_from_slice(&version.to_be_bytes());
    push_str(&mut aad, collection_id)?;
    push_str(&mut aad, manifest_digest)?;
    aad.extend_from_slice(&layout_generation.to_be_bytes());
    aad.extend_from_slice(&state_sequence.to_be_bytes());
    Ok(aad)
}

fn validate_checkpoint_id(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramAppendClientError> {
    if value.is_empty()
        || value.len() > 255
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(PrivateOramAppendClientError::InvalidCheckpointField(field));
    }
    Ok(())
}

fn validate_visible_point_id(value: &str) -> Result<(), PrivateOramAppendClientError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(PrivateOramAppendClientError::InvalidCheckpointField(
            "points.visible_point_id",
        ));
    }
    Ok(())
}

fn decode_merkle_patch_hash(value: &str) -> Result<[u8; 32], PrivateOramAppendClientError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateOramAppendClientError::InvalidMerklePatch);
    }
    BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramAppendClientError::InvalidMerklePatch)?
        .try_into()
        .map_err(|_| PrivateOramAppendClientError::InvalidMerklePatch)
}

fn insert_consistent_merkle_node(
    nodes: &mut BTreeMap<(u32, u64), [u8; 32]>,
    position: (u32, u64),
    hash: [u8; 32],
) -> Result<(), PrivateOramAppendClientError> {
    if nodes
        .insert(position, hash)
        .is_some_and(|existing| existing != hash)
    {
        return Err(PrivateOramAppendClientError::MerklePatchMismatch);
    }
    Ok(())
}

fn private_oram_append_merkle_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn decode_base64url_32(
    value: &str,
    field: &'static str,
) -> Result<[u8; 32], PrivateOramAppendClientError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateOramAppendClientError::InvalidCheckpointField(field));
    }
    BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointField(field))?
        .try_into()
        .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointField(field))
}

fn push_point_record_v3(
    output: &mut Vec<u8>,
    record: &PrivateOramAppendPointRecordV2,
) -> Result<(), PrivateOramAppendClientError> {
    push_str(output, &record.point_token)?;
    push_optional_str(output, record.visible_point_id.as_deref())?;
    push_optional_str(output, record.payload_fetch_token.as_deref())
}

fn push_hnsw_record_v3(
    output: &mut Vec<u8>,
    record: &PrivateOramAppendHnswRecordV2,
) -> Result<(), PrivateOramAppendClientError> {
    push_str(output, &record.node_id)?;
    push_str(output, &record.point_token)?;
    output.extend_from_slice(&record.level_mask.to_be_bytes());
    output.extend_from_slice(&record.generation.to_be_bytes());
    Ok(())
}

fn push_result_record_v3(
    output: &mut Vec<u8>,
    record: &PrivateOramAppendResultRecordV2,
) -> Result<(), PrivateOramAppendClientError> {
    push_str(output, &record.payload_fetch_token)?;
    push_str(output, &record.point_token)?;
    output.extend_from_slice(&record.generation.to_be_bytes());
    Ok(())
}

fn push_hnsw_client_state_v3(
    output: &mut Vec<u8>,
    state: &PrivateHnswOramClientStateSnapshot,
) -> Result<(), PrivateOramAppendClientError> {
    let state = PrivateHnswOramClientState::from_snapshot(state)?.to_snapshot(state.tree_height)?;
    output.extend_from_slice(&state.version.to_be_bytes());
    output.extend_from_slice(&state.tree_height.to_be_bytes());
    push_len(output, state.positions.len())?;
    for position in &state.positions {
        push_str(output, &position.node_id)?;
        push_str(output, &position.leaf_label)?;
    }
    push_len(output, state.stash.len())?;
    for block in &state.stash {
        push_hnsw_node_block_v3(output, block)?;
    }
    Ok(())
}

fn push_result_client_state_v3(
    output: &mut Vec<u8>,
    state: &PrivateResultOramClientStateSnapshot,
) -> Result<(), PrivateOramAppendClientError> {
    let state =
        PrivateResultOramClientState::from_snapshot(state)?.to_snapshot(state.tree_height)?;
    output.extend_from_slice(&state.version.to_be_bytes());
    output.extend_from_slice(&state.tree_height.to_be_bytes());
    push_len(output, state.positions.len())?;
    for position in &state.positions {
        push_str(output, &position.payload_fetch_token)?;
        push_str(output, &position.leaf_label)?;
    }
    push_len(output, state.stash.len())?;
    for block in &state.stash {
        push_result_payload_block_v3(output, block)?;
    }
    Ok(())
}

pub(crate) fn push_hnsw_node_block_v3(
    output: &mut Vec<u8>,
    block: &PrivateHnswNodeBlockPlaintext,
) -> Result<(), PrivateOramAppendClientError> {
    output.extend_from_slice(&block.version.to_be_bytes());
    output.extend_from_slice(&block.node_id);
    output.extend_from_slice(&block.point_token);
    output.extend_from_slice(&block.level_mask.to_be_bytes());
    output.push(match block.vector_encoding {
        PrivateHnswVectorEncoding::F32Le => 1,
        PrivateHnswVectorEncoding::I8Quantized => 2,
        PrivateHnswVectorEncoding::PqCode => 3,
        PrivateHnswVectorEncoding::BinaryQuantized => 4,
    });
    push_bytes(output, &block.vector)?;
    push_len(output, block.neighbors.len())?;
    for neighbor in &block.neighbors {
        output.extend_from_slice(neighbor);
    }
    push_bytes(output, &block.neighbor_levels)?;
    output.push(u8::from(block.deleted));
    output.extend_from_slice(&block.generation.to_be_bytes());
    match block.payload_fetch_token {
        Some(payload_fetch_token) => {
            output.push(1);
            output.extend_from_slice(&payload_fetch_token);
        }
        None => output.push(0),
    }
    Ok(())
}

fn push_result_payload_block_v3(
    output: &mut Vec<u8>,
    block: &crate::private_result_oram::PrivateResultOramPayloadBlockPlaintext,
) -> Result<(), PrivateOramAppendClientError> {
    output.extend_from_slice(&block.version.to_be_bytes());
    output.extend_from_slice(&block.payload_fetch_token);
    output.extend_from_slice(&block.point_token);
    push_bytes(output, &block.payload)?;
    output.push(u8::from(block.deleted));
    output.extend_from_slice(&block.generation.to_be_bytes());
    Ok(())
}

const fn checkpoint_index_tag(kind: PrivateOramIndexKindV2) -> u8 {
    match kind {
        PrivateOramIndexKindV2::Hnsw => 1,
        PrivateOramIndexKindV2::Result => 2,
    }
}

fn push_domain(output: &mut Vec<u8>, domain: &[u8]) -> Result<(), PrivateOramAppendClientError> {
    let len = u32::try_from(domain.len())
        .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointField("domain"))?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(domain);
    Ok(())
}

fn push_str(output: &mut Vec<u8>, value: &str) -> Result<(), PrivateOramAppendClientError> {
    let len = u64::try_from(value.len())
        .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointField("string"))?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_optional_str(
    output: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), PrivateOramAppendClientError> {
    match value {
        Some(value) => {
            output.push(1);
            push_str(output, value)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

pub(crate) fn push_len(
    output: &mut Vec<u8>,
    len: usize,
) -> Result<(), PrivateOramAppendClientError> {
    let len = u64::try_from(len)
        .map_err(|_| PrivateOramAppendClientError::InvalidCheckpointField("length"))?;
    output.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

pub(crate) fn push_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), PrivateOramAppendClientError> {
    push_len(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn base64url_sha256(value: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(value))
}

fn base64url_nopad_encoded_len(byte_len: usize) -> Option<usize> {
    let full_chunks = byte_len / 3;
    let tail_len = match byte_len % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => return None,
    };
    full_chunks
        .checked_mul(4)
        .and_then(|len| len.checked_add(tail_len))
}
