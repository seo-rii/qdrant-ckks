use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::private_hnsw_client::PrivateHnswVectorEncoding;
use crate::private_hnsw_oram::{
    DistanceKind, FixedBudgetParams, OramParams, PrivateHnswParams, ResultPrivacyMode,
    private_hnsw_min_f32_node_block_bytes,
};

pub const VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER: &str = "vector/private-hnsw-oram@v2";
pub const PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER: &str = "payload/private-result-oram@v2";
pub const PRIVATE_HNSW_ORAM_V2_BINDING: &str = "private-hnsw-oram/v2";
pub const PRIVATE_RESULT_ORAM_V2_BINDING: &str = "private-result-oram/v2";

pub const PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION: u16 = 2;
pub const PRIVATE_ORAM_SIGNED_STATE_V2_VERSION: u16 = 2;
pub const PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION: u16 = 1;

pub const PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-oram-v2-manifest-signature/v1";
pub const PRIVATE_ORAM_SIGNED_STATE_V2_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-oram-signed-state/v2";
pub const PRIVATE_ORAM_APPEND_MUTATION_V1_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-oram-mutation/v1";
pub const PRIVATE_ORAM_APPEND_WRITEBACK_V1_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-writeback/v1";
pub const PRIVATE_ORAM_APPEND_READ_TRANSCRIPT_V1_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-read-transcript/v1";
pub const PRIVATE_ORAM_NO_SERVER_POINT_RECORD_V1_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-no-server-point-record/v1";
pub const PRIVATE_ORAM_VISIBLE_POINT_RECORD_V1_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-visible-point-record/v1";
pub const PRIVATE_ORAM_APPEND_MAX_INDEXES: usize = 1_024;
pub const PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS: usize = 65_536;
pub const PRIVATE_ORAM_APPEND_MAX_MUTATION_TTL_SECS: u64 = 86_400;

const PRIVATE_ORAM_SIGNATURE_ALGORITHM: &str = "ed25519";
const BASE64URL_NOPAD_8_BYTE_LEN: usize = 11;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;
const PRIVATE_ORAM_MAX_UPDATED_BUCKETS_U64: u64 = 65_536;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramMutationError {
    #[error("private ORAM immutable manifest uses unsupported version")]
    UnsupportedManifestVersion(u16),
    #[error("private ORAM signed state uses unsupported version")]
    UnsupportedStateVersion(u16),
    #[error("private ORAM append mutation uses unsupported version")]
    UnsupportedMutationVersion(u16),
    #[error("private ORAM immutable manifest field is invalid")]
    InvalidManifestField(&'static str),
    #[error("private ORAM signed state field is invalid")]
    InvalidStateField(&'static str),
    #[error("private ORAM append mutation field is invalid")]
    InvalidMutationField(&'static str),
    #[error("private ORAM append mutation does not match runtime context")]
    MutationContextMismatch(&'static str),
    #[error("private ORAM signature is missing")]
    MissingSignature,
    #[error("private ORAM signature uses unsupported algorithm")]
    UnsupportedSignatureAlgorithm(String),
    #[error("private ORAM signature key id does not match")]
    SignatureKeyIdMismatch,
    #[error("private ORAM signature is malformed")]
    MalformedSignature,
    #[error("private ORAM immutable manifest signature verification failed")]
    InvalidManifestSignature,
    #[error("private ORAM signed state signature verification failed")]
    InvalidStateSignature,
    #[error("private ORAM append mutation signature verification failed")]
    InvalidMutationSignature,
    #[error("private ORAM index set is not canonical")]
    NonCanonicalIndexes,
    #[error("private ORAM writeback bucket set is not canonical")]
    NonCanonicalBuckets,
    #[error("private ORAM append mutation state is stale")]
    StaleState,
    #[error("private ORAM append mutation state transition is invalid")]
    InvalidStateTransition(&'static str),
    #[error("private ORAM append mutation has exhausted logical capacity")]
    CapacityExhausted,
    #[error("private ORAM append mutation writeback does not match the fixed budget")]
    FixedBudgetMismatch,
    #[error("private ORAM append mutation point operation does not match")]
    PointOperationMismatch,
    #[error("private ORAM append mutation writeback digest does not match")]
    WritebackDigestMismatch,
    #[error("private ORAM append mutation is not valid yet")]
    MutationNotYetValid,
    #[error("private ORAM append mutation is expired")]
    MutationExpired,
    #[error("private ORAM append mutation lifetime exceeds policy")]
    MutationTtlExceeded,
}

impl Debug for PrivateOramMutationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateOramMutationError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramIndexKindV2 {
    Hnsw,
    Result,
}

impl PrivateOramIndexKindV2 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hnsw => "hnsw",
            Self::Result => "result",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Hnsw => 1,
            Self::Result => 2,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramIndexCapacityV2 {
    pub bucket_count: u64,
    pub logical_capacity: u64,
    pub reserved_physical_slots: u64,
    pub max_client_stash_blocks: u32,
    pub fixed_append_read_path_count: u32,
    pub fixed_append_write_bucket_count: u32,
}

impl Debug for PrivateOramIndexCapacityV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramIndexCapacityV2")
            .field("bucket_count", &self.bucket_count)
            .field("logical_capacity", &self.logical_capacity)
            .field("reserved_physical_slots", &self.reserved_physical_slots)
            .field("max_client_stash_blocks", &self.max_client_stash_blocks)
            .field(
                "fixed_append_read_path_count",
                &self.fixed_append_read_path_count,
            )
            .field(
                "fixed_append_write_bucket_count",
                &self.fixed_append_write_bucket_count,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateOramImmutableIndexParamsV2 {
    Hnsw {
        provider: String,
        binding: String,
        key_id: String,
        rk_id: String,
        rk_epoch: u64,
        dim: u32,
        vector_encoding: PrivateHnswVectorEncoding,
        distance: DistanceKind,
        hnsw: PrivateHnswParams,
        oram: OramParams,
        fixed_search_budget: FixedBudgetParams,
        max_neighbor_rewrites: u32,
    },
    Result {
        provider: String,
        binding: String,
        key_id: String,
        rk_id: String,
        rk_epoch: u64,
        oram: OramParams,
    },
}

impl Debug for PrivateOramImmutableIndexParamsV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hnsw {
                provider,
                binding,
                rk_epoch,
                dim,
                vector_encoding,
                distance,
                hnsw,
                oram,
                fixed_search_budget,
                max_neighbor_rewrites,
                ..
            } => f
                .debug_struct("Hnsw")
                .field("provider", provider)
                .field("binding", binding)
                .field("key_id", &"[redacted]")
                .field("rk_id", &"[redacted]")
                .field("rk_epoch", rk_epoch)
                .field("dim", dim)
                .field("vector_encoding", vector_encoding)
                .field("distance", distance)
                .field("hnsw", hnsw)
                .field("oram", oram)
                .field("fixed_search_budget", fixed_search_budget)
                .field("max_neighbor_rewrites", max_neighbor_rewrites)
                .finish(),
            Self::Result {
                provider,
                binding,
                rk_epoch,
                oram,
                ..
            } => f
                .debug_struct("Result")
                .field("provider", provider)
                .field("binding", binding)
                .field("key_id", &"[redacted]")
                .field("rk_id", &"[redacted]")
                .field("rk_epoch", rk_epoch)
                .field("oram", oram)
                .finish(),
        }
    }
}

impl PrivateOramImmutableIndexParamsV2 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        match self {
            Self::Hnsw { .. } => PrivateOramIndexKindV2::Hnsw,
            Self::Result { .. } => PrivateOramIndexKindV2::Result,
        }
    }

    fn oram(&self) -> &OramParams {
        match self {
            Self::Hnsw { oram, .. } | Self::Result { oram, .. } => oram,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramImmutableIndexV2 {
    pub index_name: String,
    pub params: PrivateOramImmutableIndexParamsV2,
    pub capacity: PrivateOramIndexCapacityV2,
}

impl Debug for PrivateOramImmutableIndexV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramImmutableIndexV2")
            .field("index_name", &"[redacted]")
            .field("params", &self.params)
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl PrivateOramImmutableIndexV2 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.params.kind()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramImmutableManifestV2 {
    pub version: u16,
    pub collection_id: String,
    pub manifest_nonce: String,
    pub indexes: Vec<PrivateOramImmutableIndexV2>,
    pub result_privacy: ResultPrivacyMode,
    pub owner_signing_key_id: String,
    pub created_at_unix: u64,
}

impl Debug for PrivateOramImmutableManifestV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramImmutableManifestV2")
            .field("version", &self.version)
            .field("collection_id", &"[redacted]")
            .field("manifest_nonce", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .field("result_privacy", &self.result_privacy)
            .field("owner_signing_key_id", &"[redacted]")
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateOramSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramSignature")
            .field("alg", &self.alg)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramImmutableManifestBundleV2 {
    pub manifest: PrivateOramImmutableManifestV2,
    pub signature: PrivateOramSignature,
}

impl Debug for PrivateOramImmutableManifestBundleV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramImmutableManifestBundleV2")
            .field("manifest", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramIndexStateV2 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub logical_count: u64,
    pub dummy_count: u64,
    pub last_writeback_digest: String,
}

impl Debug for PrivateOramIndexStateV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramIndexStateV2")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("logical_count", &self.logical_count)
            .field("dummy_count", &self.dummy_count)
            .field("last_writeback_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramSignedStateV2 {
    pub version: u16,
    pub collection_id: String,
    pub manifest_digest: String,
    pub layout_generation: u64,
    pub layout_digest: String,
    pub state_sequence: u64,
    pub indexes: Vec<PrivateOramIndexStateV2>,
    pub client_state_digest: String,
    pub last_mutation_id: Option<String>,
    pub owner_signing_key_id: String,
    pub signed_at_unix: u64,
}

impl Debug for PrivateOramSignedStateV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramSignedStateV2")
            .field("version", &self.version)
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("layout_generation", &self.layout_generation)
            .field("layout_digest", &"[redacted]")
            .field("state_sequence", &self.state_sequence)
            .field("index_count", &self.indexes.len())
            .field("client_state_digest", &"[redacted]")
            .field("last_mutation_id", &"[redacted]")
            .field("owner_signing_key_id", &"[redacted]")
            .field("signed_at_unix", &self.signed_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramSignedStateBundleV2 {
    pub state: PrivateOramSignedStateV2,
    pub signature: PrivateOramSignature,
}

impl Debug for PrivateOramSignedStateBundleV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramSignedStateBundleV2")
            .field("state", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramPointOperationKindV1 {
    VisiblePointRecord,
    NoServerPointRecord,
}

impl PrivateOramPointOperationKindV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VisiblePointRecord => "visible_point_record",
            Self::NoServerPointRecord => "no_server_point_record",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::VisiblePointRecord => 1,
            Self::NoServerPointRecord => 2,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendBucketRefV1 {
    pub bucket_id: u64,
    pub ciphertext_sha256: String,
    pub bucket_commitment: String,
}

impl Debug for PrivateOramAppendBucketRefV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendBucketRefV1")
            .field("bucket_id", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .field("bucket_commitment", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendIndexWritebackV1 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub read_path_count: u32,
    pub read_transcript_digest: String,
    pub updated_buckets: Vec<PrivateOramAppendBucketRefV1>,
}

impl Debug for PrivateOramAppendIndexWritebackV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendIndexWritebackV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("read_path_count", &self.read_path_count)
            .field("read_transcript_digest", &"[redacted]")
            .field("updated_bucket_count", &self.updated_buckets.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendMutationV1 {
    pub version: u16,
    pub mutation_id: String,
    pub collection_id: String,
    pub manifest_digest: String,
    pub layout_generation: u64,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub old_state: PrivateOramSignedStateBundleV2,
    pub new_state: PrivateOramSignedStateBundleV2,
    pub point_operation_kind: PrivateOramPointOperationKindV1,
    pub point_operation_digest: String,
    pub writebacks: Vec<PrivateOramAppendIndexWritebackV1>,
    pub owner_signing_key_id: String,
}

impl Debug for PrivateOramAppendMutationV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendMutationV1")
            .field("version", &self.version)
            .field("mutation_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("layout_generation", &self.layout_generation)
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("old_state", &"[redacted]")
            .field("new_state", &"[redacted]")
            .field("point_operation_kind", &self.point_operation_kind)
            .field("point_operation_digest", &"[redacted]")
            .field("writeback_count", &self.writebacks.len())
            .field("owner_signing_key_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendMutationBundleV1 {
    pub mutation: PrivateOramAppendMutationV1,
    pub signature: PrivateOramSignature,
}

impl Debug for PrivateOramAppendMutationBundleV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendMutationBundleV1")
            .field("mutation", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramSignatureVerification<'a> {
    pub expected_key_id: &'a str,
    pub public_key: &'a [u8],
}

impl Debug for PrivateOramSignatureVerification<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramSignatureVerification")
            .field("expected_key_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramAppendWritebackDigestInput<'a> {
    pub collection_id: &'a str,
    pub manifest_digest: &'a str,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: &'a str,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub read_path_count: u32,
    pub read_transcript_digest: &'a str,
    pub updated_buckets: &'a [PrivateOramAppendBucketRefV1],
}

impl Debug for PrivateOramAppendWritebackDigestInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendWritebackDigestInput")
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("read_path_count", &self.read_path_count)
            .field("read_transcript_digest", &"[redacted]")
            .field("updated_bucket_count", &self.updated_buckets.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramObservedReadTranscriptV1 {
    pub collection_id: String,
    pub manifest_digest: String,
    pub mutation_id: String,
    pub old_state_digest: String,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub read_path_count: u32,
    pub paths_per_window: u32,
    pub tree_height: u32,
    pub ordered_leaf_labels: Vec<String>,
    pub transcript_digest: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramVisiblePointRecordV1<'a> {
    pub point_id: &'a str,
    pub staged_insert_sha256: &'a str,
}

impl Debug for PrivateOramVisiblePointRecordV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramVisiblePointRecordV1")
            .field("point_id", &"[redacted]")
            .field("staged_insert_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendReadWindowV1 {
    pub sequence: u32,
    pub paths: Vec<String>,
}

impl Debug for PrivateOramAppendReadWindowV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendReadWindowV1")
            .field("sequence", &self.sequence)
            .field("path_count", &self.paths.len())
            .field("paths", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramAppendReadTranscriptDigestInput<'a> {
    pub collection_id: &'a str,
    pub manifest_digest: &'a str,
    pub mutation_id: &'a str,
    pub old_state_digest: &'a str,
    pub writer_lease_digest: &'a str,
    pub writer_fence: u64,
    pub paths_per_window: u32,
    pub tree_height: u32,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: &'a str,
    pub windows: &'a [PrivateOramAppendReadWindowV1],
}

impl Debug for PrivateOramAppendReadTranscriptDigestInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendReadTranscriptDigestInput")
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("old_state_digest", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("paths_per_window", &self.paths_per_window)
            .field("tree_height", &self.tree_height)
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("window_count", &self.windows.len())
            .finish()
    }
}

impl Debug for PrivateOramObservedReadTranscriptV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramObservedReadTranscriptV1")
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("old_state_digest", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("read_path_count", &self.read_path_count)
            .field("paths_per_window", &self.paths_per_window)
            .field("tree_height", &self.tree_height)
            .field("ordered_leaf_label_count", &self.ordered_leaf_labels.len())
            .field("ordered_leaf_labels", &"[redacted]")
            .field("transcript_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramAppendValidationContext<'a> {
    pub expected_collection_id: &'a str,
    pub expected_manifest_digest: &'a str,
    pub expected_owner_signing_key_id: &'a str,
    pub expected_layout_generation: u64,
    pub expected_layout_digest: &'a str,
    pub expected_writer_lease_digest: &'a str,
    pub expected_writer_fence: u64,
    pub expected_state_sequence: u64,
    pub expected_old_state_digest: &'a str,
    pub expected_visible_point_record: Option<PrivateOramVisiblePointRecordV1<'a>>,
    pub observed_read_transcripts: &'a [PrivateOramObservedReadTranscriptV1],
    pub now_unix: u64,
    pub max_mutation_ttl_secs: u64,
    pub public_key: &'a [u8],
}

impl Debug for PrivateOramAppendValidationContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendValidationContext")
            .field("expected_collection_id", &"[redacted]")
            .field("expected_manifest_digest", &"[redacted]")
            .field("expected_owner_signing_key_id", &"[redacted]")
            .field(
                "expected_layout_generation",
                &self.expected_layout_generation,
            )
            .field("expected_layout_digest", &"[redacted]")
            .field("expected_writer_lease_digest", &"[redacted]")
            .field("expected_writer_fence", &self.expected_writer_fence)
            .field("expected_state_sequence", &self.expected_state_sequence)
            .field("expected_old_state_digest", &"[redacted]")
            .field(
                "has_expected_visible_point_record",
                &self.expected_visible_point_record.is_some(),
            )
            .field(
                "observed_read_transcript_count",
                &self.observed_read_transcripts.len(),
            )
            .field("now_unix", &self.now_unix)
            .field("max_mutation_ttl_secs", &self.max_mutation_ttl_secs)
            .field("public_key", &"[redacted]")
            .finish()
    }
}

pub fn validate_private_oram_immutable_manifest_v2_shape(
    manifest: &PrivateOramImmutableManifestV2,
) -> Result<(), PrivateOramMutationError> {
    if manifest.version != PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION {
        return Err(PrivateOramMutationError::UnsupportedManifestVersion(
            manifest.version,
        ));
    }
    validate_resource_id(
        &manifest.collection_id,
        "collection_id",
        PrivateOramMutationError::InvalidManifestField,
    )?;
    decode_base64url_32(
        &manifest.manifest_nonce,
        "manifest_nonce",
        PrivateOramMutationError::InvalidManifestField,
    )?;
    validate_resource_id(
        &manifest.owner_signing_key_id,
        "owner_signing_key_id",
        PrivateOramMutationError::InvalidManifestField,
    )?;
    if manifest.created_at_unix == 0 {
        return Err(PrivateOramMutationError::InvalidManifestField(
            "created_at_unix",
        ));
    }
    validate_canonical_manifest_indexes(&manifest.indexes)?;

    let mut hnsw_count = 0usize;
    let mut result_count = 0usize;
    let mut logical_capacity = None;
    let mut total_read_bucket_responses = 0u64;
    let mut total_write_buckets = 0u64;
    for index in &manifest.indexes {
        validate_index_name(
            &index.index_name,
            "indexes.index_name",
            PrivateOramMutationError::InvalidManifestField,
        )?;
        validate_immutable_index_params(&index.params)?;
        validate_index_capacity(&index.params, &index.capacity)?;
        let read_bucket_responses = u64::from(index.capacity.fixed_append_read_path_count)
            .checked_mul(u64::from(index.params.oram().tree_height) + 1)
            .ok_or(PrivateOramMutationError::InvalidManifestField(
                "indexes.capacity",
            ))?;
        total_read_bucket_responses = total_read_bucket_responses
            .checked_add(read_bucket_responses)
            .ok_or(PrivateOramMutationError::InvalidManifestField(
                "indexes.capacity",
            ))?;
        total_write_buckets = total_write_buckets
            .checked_add(u64::from(index.capacity.fixed_append_write_bucket_count))
            .ok_or(PrivateOramMutationError::InvalidManifestField(
                "indexes.capacity",
            ))?;
        if logical_capacity
            .replace(index.capacity.logical_capacity)
            .is_some_and(|capacity| capacity != index.capacity.logical_capacity)
        {
            return Err(PrivateOramMutationError::InvalidManifestField(
                "indexes.logical_capacity",
            ));
        }
        match index.kind() {
            PrivateOramIndexKindV2::Hnsw => hnsw_count += 1,
            PrivateOramIndexKindV2::Result => result_count += 1,
        }
    }
    if total_read_bucket_responses > PRIVATE_ORAM_MAX_UPDATED_BUCKETS_U64
        || total_write_buckets > PRIVATE_ORAM_MAX_UPDATED_BUCKETS_U64
    {
        return Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.capacity",
        ));
    }
    if hnsw_count == 0 || result_count > 1 {
        return Err(PrivateOramMutationError::InvalidManifestField("indexes"));
    }
    match manifest.result_privacy {
        ResultPrivacyMode::IdsVisible if result_count != 0 => {
            return Err(PrivateOramMutationError::InvalidManifestField(
                "result_privacy",
            ));
        }
        ResultPrivacyMode::PrivatePayloadOramRequired if result_count != 1 => {
            return Err(PrivateOramMutationError::InvalidManifestField(
                "result_privacy",
            ));
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_private_oram_signed_state_v2_shape(
    state: &PrivateOramSignedStateV2,
) -> Result<(), PrivateOramMutationError> {
    if state.version != PRIVATE_ORAM_SIGNED_STATE_V2_VERSION {
        return Err(PrivateOramMutationError::UnsupportedStateVersion(
            state.version,
        ));
    }
    validate_resource_id(
        &state.collection_id,
        "collection_id",
        PrivateOramMutationError::InvalidStateField,
    )?;
    decode_base64url_32(
        &state.manifest_digest,
        "manifest_digest",
        PrivateOramMutationError::InvalidStateField,
    )?;
    if state.layout_generation == 0 {
        return Err(PrivateOramMutationError::InvalidStateField(
            "layout_generation",
        ));
    }
    decode_base64url_32(
        &state.layout_digest,
        "layout_digest",
        PrivateOramMutationError::InvalidStateField,
    )?;
    validate_canonical_state_indexes(&state.indexes)?;
    let mut occupancy = None;
    for index in &state.indexes {
        validate_index_name(
            &index.index_name,
            "indexes.index_name",
            PrivateOramMutationError::InvalidStateField,
        )?;
        decode_base64url_32(
            &index.root_hash,
            "indexes.root_hash",
            PrivateOramMutationError::InvalidStateField,
        )?;
        decode_base64url_32(
            &index.last_writeback_digest,
            "indexes.last_writeback_digest",
            PrivateOramMutationError::InvalidStateField,
        )?;
        let index_occupancy = (index.logical_count, index.dummy_count);
        if occupancy
            .replace(index_occupancy)
            .is_some_and(|occupancy| occupancy != index_occupancy)
        {
            return Err(PrivateOramMutationError::InvalidStateField(
                "indexes.occupancy",
            ));
        }
    }
    decode_base64url_32(
        &state.client_state_digest,
        "client_state_digest",
        PrivateOramMutationError::InvalidStateField,
    )?;
    match (state.state_sequence, &state.last_mutation_id) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => {
            return Err(PrivateOramMutationError::InvalidStateField(
                "last_mutation_id",
            ));
        }
        (_, Some(mutation_id)) => validate_mutation_id(
            mutation_id,
            "last_mutation_id",
            PrivateOramMutationError::InvalidStateField,
        )?,
    }
    validate_resource_id(
        &state.owner_signing_key_id,
        "owner_signing_key_id",
        PrivateOramMutationError::InvalidStateField,
    )?;
    if state.signed_at_unix == 0 {
        return Err(PrivateOramMutationError::InvalidStateField(
            "signed_at_unix",
        ));
    }
    Ok(())
}

pub fn validate_private_oram_append_mutation_v1_shape(
    mutation: &PrivateOramAppendMutationV1,
) -> Result<(), PrivateOramMutationError> {
    if mutation.version != PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION {
        return Err(PrivateOramMutationError::UnsupportedMutationVersion(
            mutation.version,
        ));
    }
    validate_mutation_id(
        &mutation.mutation_id,
        "mutation_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    validate_resource_id(
        &mutation.collection_id,
        "collection_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        &mutation.manifest_digest,
        "manifest_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    if mutation.layout_generation == 0 {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "layout_generation",
        ));
    }
    decode_base64url_32(
        &mutation.writer_lease_digest,
        "writer_lease_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    if mutation.writer_fence == 0 {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "writer_fence",
        ));
    }
    if mutation.issued_at_unix == 0 || mutation.expires_at_unix <= mutation.issued_at_unix {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "mutation_lifetime",
        ));
    }
    validate_private_oram_signed_state_v2_shape(&mutation.old_state.state)?;
    validate_private_oram_signed_state_v2_shape(&mutation.new_state.state)?;
    validate_private_oram_signature_shape(&mutation.old_state.signature)?;
    validate_private_oram_signature_shape(&mutation.new_state.signature)?;
    decode_base64url_32(
        &mutation.point_operation_digest,
        "point_operation_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    validate_canonical_writebacks(&mutation.writebacks)?;
    validate_resource_id(
        &mutation.owner_signing_key_id,
        "owner_signing_key_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    Ok(())
}

pub fn validate_private_oram_signature_shape(
    signature: &PrivateOramSignature,
) -> Result<(), PrivateOramMutationError> {
    if signature.alg != PRIVATE_ORAM_SIGNATURE_ALGORITHM {
        return Err(PrivateOramMutationError::UnsupportedSignatureAlgorithm(
            signature.alg.clone(),
        ));
    }
    validate_resource_id(
        &signature.key_id,
        "signature.key_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_64(&signature.sig)?;
    Ok(())
}

pub fn try_private_oram_immutable_manifest_v2_signature_message(
    manifest: &PrivateOramImmutableManifestV2,
) -> Result<Vec<u8>, PrivateOramMutationError> {
    validate_private_oram_immutable_manifest_v2_shape(manifest)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_SIGNATURE_DOMAIN.as_bytes(),
    )?;
    push_u16(&mut message, manifest.version);
    try_push_str(&mut message, &manifest.collection_id)?;
    try_push_str(&mut message, &manifest.manifest_nonce)?;
    push_len(&mut message, manifest.indexes.len())?;
    for index in &manifest.indexes {
        push_u8(&mut message, index.kind().tag());
        try_push_str(&mut message, &index.index_name)?;
        push_immutable_index_params(&mut message, &index.params)?;
        push_index_capacity(&mut message, &index.capacity);
    }
    push_u8(
        &mut message,
        match manifest.result_privacy {
            ResultPrivacyMode::IdsVisible => 1,
            ResultPrivacyMode::PrivatePayloadOramRequired => 2,
        },
    );
    try_push_str(&mut message, &manifest.owner_signing_key_id)?;
    push_u64(&mut message, manifest.created_at_unix);
    Ok(message)
}

pub fn private_oram_immutable_manifest_v2_digest(
    manifest: &PrivateOramImmutableManifestV2,
) -> Result<String, PrivateOramMutationError> {
    Ok(digest_message(
        try_private_oram_immutable_manifest_v2_signature_message(manifest)?,
    ))
}

pub fn try_private_oram_signed_state_v2_signature_message(
    state: &PrivateOramSignedStateV2,
) -> Result<Vec<u8>, PrivateOramMutationError> {
    validate_private_oram_signed_state_v2_shape(state)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_SIGNED_STATE_V2_SIGNATURE_DOMAIN.as_bytes(),
    )?;
    push_u16(&mut message, state.version);
    try_push_str(&mut message, &state.collection_id)?;
    try_push_str(&mut message, &state.manifest_digest)?;
    push_u64(&mut message, state.layout_generation);
    try_push_str(&mut message, &state.layout_digest)?;
    push_u64(&mut message, state.state_sequence);
    push_len(&mut message, state.indexes.len())?;
    for index in &state.indexes {
        push_u8(&mut message, index.kind.tag());
        try_push_str(&mut message, &index.index_name)?;
        push_u64(&mut message, index.index_epoch);
        try_push_str(&mut message, &index.root_hash)?;
        push_u64(&mut message, index.logical_count);
        push_u64(&mut message, index.dummy_count);
        try_push_str(&mut message, &index.last_writeback_digest)?;
    }
    try_push_str(&mut message, &state.client_state_digest)?;
    push_optional_str(&mut message, state.last_mutation_id.as_deref())?;
    try_push_str(&mut message, &state.owner_signing_key_id)?;
    push_u64(&mut message, state.signed_at_unix);
    Ok(message)
}

pub fn private_oram_signed_state_v2_digest(
    state: &PrivateOramSignedStateV2,
) -> Result<String, PrivateOramMutationError> {
    Ok(digest_message(
        try_private_oram_signed_state_v2_signature_message(state)?,
    ))
}

pub fn try_private_oram_append_read_transcript_v1_digest_message(
    input: PrivateOramAppendReadTranscriptDigestInput<'_>,
) -> Result<Vec<u8>, PrivateOramMutationError> {
    validate_resource_id(
        input.collection_id,
        "collection_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        input.manifest_digest,
        "manifest_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    validate_mutation_id(
        input.mutation_id,
        "mutation_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        input.old_state_digest,
        "old_state_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        input.writer_lease_digest,
        "writer_lease_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    if input.writer_fence == 0 {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "writer_fence",
        ));
    }
    validate_index_name(
        input.index_name,
        "index_name",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    let paths_per_window = usize::try_from(input.paths_per_window).map_err(|_| {
        PrivateOramMutationError::InvalidMutationField("read_windows.paths_per_window")
    })?;
    let leaf_count = 1u64.checked_shl(input.tree_height).ok_or(
        PrivateOramMutationError::InvalidMutationField("read_windows.tree_height"),
    )?;
    if paths_per_window == 0
        || input.tree_height == 0
        || input.tree_height >= 63
        || input.windows.is_empty()
        || input.windows.len() > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS
    {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "read_windows",
        ));
    }

    let mut total_path_count = 0usize;
    for (offset, window) in input.windows.iter().enumerate() {
        let expected_sequence = u32::try_from(offset)
            .map_err(|_| PrivateOramMutationError::InvalidMutationField("read_windows.sequence"))?;
        if window.sequence != expected_sequence || window.paths.len() != paths_per_window {
            return Err(PrivateOramMutationError::InvalidMutationField(
                "read_windows",
            ));
        }
        total_path_count = total_path_count.checked_add(window.paths.len()).ok_or(
            PrivateOramMutationError::InvalidMutationField("read_windows"),
        )?;
        if total_path_count > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS {
            return Err(PrivateOramMutationError::InvalidMutationField(
                "read_windows",
            ));
        }
        // A window reads `paths_per_window` distinct paths (a collision is padded with a fresh
        // leaf), which is also what the server-side read validator enforces.
        let mut window_leaves = BTreeSet::new();
        for path in &window.paths {
            let leaf = u64::from_be_bytes(decode_base64url_8(path)?);
            if leaf >= leaf_count || !window_leaves.insert(leaf) {
                return Err(PrivateOramMutationError::InvalidMutationField(
                    "read_windows.paths",
                ));
            }
        }
    }

    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_APPEND_READ_TRANSCRIPT_V1_DIGEST_DOMAIN.as_bytes(),
    )?;
    try_push_str(&mut message, input.collection_id)?;
    try_push_str(&mut message, input.manifest_digest)?;
    try_push_str(&mut message, input.mutation_id)?;
    try_push_str(&mut message, input.old_state_digest)?;
    try_push_str(&mut message, input.writer_lease_digest)?;
    push_u64(&mut message, input.writer_fence);
    push_u32(&mut message, input.paths_per_window);
    push_u32(&mut message, input.tree_height);
    push_u8(&mut message, input.kind.tag());
    try_push_str(&mut message, input.index_name)?;
    push_len(&mut message, input.windows.len())?;
    for window in input.windows {
        push_u32(&mut message, window.sequence);
        push_len(&mut message, window.paths.len())?;
        for path in &window.paths {
            try_push_str(&mut message, path)?;
        }
    }
    Ok(message)
}

pub fn private_oram_append_read_transcript_v1(
    input: PrivateOramAppendReadTranscriptDigestInput<'_>,
) -> Result<PrivateOramObservedReadTranscriptV1, PrivateOramMutationError> {
    let path_count = input
        .windows
        .iter()
        .try_fold(0usize, |count, window| {
            count.checked_add(window.paths.len())
        })
        .and_then(|count| u32::try_from(count).ok())
        .ok_or(PrivateOramMutationError::InvalidMutationField(
            "read_windows",
        ))?;
    let transcript_digest = digest_message(
        try_private_oram_append_read_transcript_v1_digest_message(input)?,
    );
    let ordered_leaf_labels = input
        .windows
        .iter()
        .flat_map(|window| window.paths.iter().cloned())
        .collect();
    Ok(PrivateOramObservedReadTranscriptV1 {
        collection_id: input.collection_id.to_string(),
        manifest_digest: input.manifest_digest.to_string(),
        mutation_id: input.mutation_id.to_string(),
        old_state_digest: input.old_state_digest.to_string(),
        writer_lease_digest: input.writer_lease_digest.to_string(),
        writer_fence: input.writer_fence,
        kind: input.kind,
        index_name: input.index_name.to_string(),
        read_path_count: path_count,
        paths_per_window: input.paths_per_window,
        tree_height: input.tree_height,
        ordered_leaf_labels,
        transcript_digest,
    })
}

pub fn try_private_oram_append_writeback_v1_digest_message(
    input: PrivateOramAppendWritebackDigestInput<'_>,
) -> Result<Vec<u8>, PrivateOramMutationError> {
    validate_resource_id(
        input.collection_id,
        "collection_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        input.manifest_digest,
        "manifest_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    validate_index_name(
        input.index_name,
        "writebacks.index_name",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    let expected_new_epoch =
        input
            .old_epoch
            .checked_add(1)
            .ok_or(PrivateOramMutationError::InvalidStateTransition(
                "index_epoch",
            ))?;
    if input.new_epoch != expected_new_epoch {
        return Err(PrivateOramMutationError::InvalidStateTransition(
            "index_epoch",
        ));
    }
    decode_base64url_32(
        input.old_root_hash,
        "old_root_hash",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        input.new_root_hash,
        "new_root_hash",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    if input.read_path_count == 0 {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "read_path_count",
        ));
    }
    decode_base64url_32(
        input.read_transcript_digest,
        "read_transcript_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    validate_ordered_bucket_occurrences(input.updated_buckets)?;

    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_APPEND_WRITEBACK_V1_DIGEST_DOMAIN.as_bytes(),
    )?;
    try_push_str(&mut message, input.collection_id)?;
    try_push_str(&mut message, input.manifest_digest)?;
    push_u8(&mut message, input.kind.tag());
    try_push_str(&mut message, input.index_name)?;
    push_u64(&mut message, input.old_epoch);
    push_u64(&mut message, input.new_epoch);
    try_push_str(&mut message, input.old_root_hash)?;
    try_push_str(&mut message, input.new_root_hash)?;
    push_u32(&mut message, input.read_path_count);
    try_push_str(&mut message, input.read_transcript_digest)?;
    push_bucket_refs(&mut message, input.updated_buckets)?;
    Ok(message)
}

pub fn private_oram_append_writeback_v1_digest(
    input: PrivateOramAppendWritebackDigestInput<'_>,
) -> Result<String, PrivateOramMutationError> {
    Ok(digest_message(
        try_private_oram_append_writeback_v1_digest_message(input)?,
    ))
}

pub fn try_private_oram_visible_point_record_v1_digest_message(
    collection_id: &str,
    manifest_digest: &str,
    mutation_id: &str,
    record: PrivateOramVisiblePointRecordV1<'_>,
) -> Result<Vec<u8>, PrivateOramMutationError> {
    validate_resource_id(
        collection_id,
        "collection_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        manifest_digest,
        "manifest_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    validate_mutation_id(
        mutation_id,
        "mutation_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    validate_resource_id(
        record.point_id,
        "point_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        record.staged_insert_sha256,
        "staged_insert_sha256",
        PrivateOramMutationError::InvalidMutationField,
    )?;

    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_VISIBLE_POINT_RECORD_V1_DIGEST_DOMAIN.as_bytes(),
    )?;
    try_push_str(&mut message, collection_id)?;
    try_push_str(&mut message, manifest_digest)?;
    try_push_str(&mut message, mutation_id)?;
    try_push_str(&mut message, record.point_id)?;
    try_push_str(&mut message, record.staged_insert_sha256)?;
    Ok(message)
}

pub fn private_oram_visible_point_record_v1_digest(
    collection_id: &str,
    manifest_digest: &str,
    mutation_id: &str,
    record: PrivateOramVisiblePointRecordV1<'_>,
) -> Result<String, PrivateOramMutationError> {
    Ok(digest_message(
        try_private_oram_visible_point_record_v1_digest_message(
            collection_id,
            manifest_digest,
            mutation_id,
            record,
        )?,
    ))
}

pub fn try_private_oram_no_server_point_record_v1_digest_message(
    collection_id: &str,
    manifest_digest: &str,
    mutation_id: &str,
) -> Result<Vec<u8>, PrivateOramMutationError> {
    validate_resource_id(
        collection_id,
        "collection_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        manifest_digest,
        "manifest_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    validate_mutation_id(
        mutation_id,
        "mutation_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_NO_SERVER_POINT_RECORD_V1_DIGEST_DOMAIN.as_bytes(),
    )?;
    try_push_str(&mut message, collection_id)?;
    try_push_str(&mut message, manifest_digest)?;
    try_push_str(&mut message, mutation_id)?;
    Ok(message)
}

pub fn private_oram_no_server_point_record_v1_digest(
    collection_id: &str,
    manifest_digest: &str,
    mutation_id: &str,
) -> Result<String, PrivateOramMutationError> {
    Ok(digest_message(
        try_private_oram_no_server_point_record_v1_digest_message(
            collection_id,
            manifest_digest,
            mutation_id,
        )?,
    ))
}

pub fn try_private_oram_append_mutation_v1_signature_message(
    mutation: &PrivateOramAppendMutationV1,
) -> Result<Vec<u8>, PrivateOramMutationError> {
    validate_private_oram_append_mutation_v1_shape(mutation)?;
    let old_state_digest = private_oram_signed_state_v2_digest(&mutation.old_state.state)?;
    let new_state_digest = private_oram_signed_state_v2_digest(&mutation.new_state.state)?;

    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_APPEND_MUTATION_V1_SIGNATURE_DOMAIN.as_bytes(),
    )?;
    push_u16(&mut message, mutation.version);
    try_push_str(&mut message, &mutation.mutation_id)?;
    try_push_str(&mut message, &mutation.collection_id)?;
    try_push_str(&mut message, &mutation.manifest_digest)?;
    push_u64(&mut message, mutation.layout_generation);
    try_push_str(&mut message, &mutation.writer_lease_digest)?;
    push_u64(&mut message, mutation.writer_fence);
    push_u64(&mut message, mutation.issued_at_unix);
    push_u64(&mut message, mutation.expires_at_unix);
    try_push_str(&mut message, &old_state_digest)?;
    try_push_str(&mut message, &new_state_digest)?;
    push_u8(&mut message, mutation.point_operation_kind.tag());
    try_push_str(&mut message, &mutation.point_operation_digest)?;
    push_len(&mut message, mutation.writebacks.len())?;
    for writeback in &mutation.writebacks {
        push_u8(&mut message, writeback.kind.tag());
        try_push_str(&mut message, &writeback.index_name)?;
        push_u32(&mut message, writeback.read_path_count);
        try_push_str(&mut message, &writeback.read_transcript_digest)?;
        push_bucket_refs(&mut message, &writeback.updated_buckets)?;
    }
    try_push_str(&mut message, &mutation.owner_signing_key_id)?;
    Ok(message)
}

pub fn private_oram_append_mutation_v1_digest(
    mutation: &PrivateOramAppendMutationV1,
) -> Result<String, PrivateOramMutationError> {
    Ok(digest_message(
        try_private_oram_append_mutation_v1_signature_message(mutation)?,
    ))
}

pub fn sign_private_oram_immutable_manifest_v2(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateOramImmutableManifestV2,
) -> Result<PrivateOramSignature, PrivateOramMutationError> {
    sign_message(
        key_pair,
        &manifest.owner_signing_key_id,
        try_private_oram_immutable_manifest_v2_signature_message(manifest)?,
    )
}

pub fn package_private_oram_immutable_manifest_v2(
    key_pair: &Ed25519KeyPair,
    manifest: PrivateOramImmutableManifestV2,
) -> Result<PrivateOramImmutableManifestBundleV2, PrivateOramMutationError> {
    let signature = sign_private_oram_immutable_manifest_v2(key_pair, &manifest)?;
    Ok(PrivateOramImmutableManifestBundleV2 {
        manifest,
        signature,
    })
}

pub fn sign_private_oram_signed_state_v2(
    key_pair: &Ed25519KeyPair,
    state: &PrivateOramSignedStateV2,
) -> Result<PrivateOramSignature, PrivateOramMutationError> {
    sign_message(
        key_pair,
        &state.owner_signing_key_id,
        try_private_oram_signed_state_v2_signature_message(state)?,
    )
}

pub fn package_private_oram_signed_state_v2(
    key_pair: &Ed25519KeyPair,
    state: PrivateOramSignedStateV2,
) -> Result<PrivateOramSignedStateBundleV2, PrivateOramMutationError> {
    let signature = sign_private_oram_signed_state_v2(key_pair, &state)?;
    Ok(PrivateOramSignedStateBundleV2 { state, signature })
}

pub fn sign_private_oram_append_mutation_v1(
    key_pair: &Ed25519KeyPair,
    mutation: &PrivateOramAppendMutationV1,
) -> Result<PrivateOramSignature, PrivateOramMutationError> {
    sign_message(
        key_pair,
        &mutation.owner_signing_key_id,
        try_private_oram_append_mutation_v1_signature_message(mutation)?,
    )
}

pub fn package_private_oram_append_mutation_v1(
    key_pair: &Ed25519KeyPair,
    mutation: PrivateOramAppendMutationV1,
) -> Result<PrivateOramAppendMutationBundleV1, PrivateOramMutationError> {
    let signature = sign_private_oram_append_mutation_v1(key_pair, &mutation)?;
    Ok(PrivateOramAppendMutationBundleV1 {
        mutation,
        signature,
    })
}

pub fn validate_private_oram_immutable_manifest_v2_signature(
    manifest: &PrivateOramImmutableManifestV2,
    signature: Option<&PrivateOramSignature>,
    verification: PrivateOramSignatureVerification<'_>,
) -> Result<(), PrivateOramMutationError> {
    verify_signature(
        signature,
        &manifest.owner_signing_key_id,
        verification,
        try_private_oram_immutable_manifest_v2_signature_message(manifest)?,
        PrivateOramMutationError::InvalidManifestSignature,
    )
}

pub fn validate_private_oram_signed_state_v2_signature(
    state: &PrivateOramSignedStateV2,
    signature: Option<&PrivateOramSignature>,
    verification: PrivateOramSignatureVerification<'_>,
) -> Result<(), PrivateOramMutationError> {
    verify_signature(
        signature,
        &state.owner_signing_key_id,
        verification,
        try_private_oram_signed_state_v2_signature_message(state)?,
        PrivateOramMutationError::InvalidStateSignature,
    )
}

pub fn validate_private_oram_append_mutation_v1_signature(
    mutation: &PrivateOramAppendMutationV1,
    signature: Option<&PrivateOramSignature>,
    verification: PrivateOramSignatureVerification<'_>,
) -> Result<(), PrivateOramMutationError> {
    verify_signature(
        signature,
        &mutation.owner_signing_key_id,
        verification,
        try_private_oram_append_mutation_v1_signature_message(mutation)?,
        PrivateOramMutationError::InvalidMutationSignature,
    )
}

pub fn validate_private_oram_append_mutation_v1(
    manifest_bundle: &PrivateOramImmutableManifestBundleV2,
    mutation_bundle: &PrivateOramAppendMutationBundleV1,
    context: PrivateOramAppendValidationContext<'_>,
) -> Result<(), PrivateOramMutationError> {
    validate_append_validation_context(context)?;
    let manifest = &manifest_bundle.manifest;
    let mutation = &mutation_bundle.mutation;
    let verification = PrivateOramSignatureVerification {
        expected_key_id: context.expected_owner_signing_key_id,
        public_key: context.public_key,
    };

    validate_private_oram_immutable_manifest_v2_signature(
        manifest,
        Some(&manifest_bundle.signature),
        verification,
    )?;
    let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
    if manifest.collection_id != context.expected_collection_id {
        return Err(PrivateOramMutationError::MutationContextMismatch(
            "collection_id",
        ));
    }
    if manifest.owner_signing_key_id != context.expected_owner_signing_key_id {
        return Err(PrivateOramMutationError::SignatureKeyIdMismatch);
    }
    if manifest_digest != context.expected_manifest_digest {
        return Err(PrivateOramMutationError::MutationContextMismatch(
            "manifest_digest",
        ));
    }

    validate_private_oram_append_mutation_v1_shape(mutation)?;
    validate_private_oram_signed_state_v2_signature(
        &mutation.old_state.state,
        Some(&mutation.old_state.signature),
        verification,
    )?;
    validate_private_oram_signed_state_v2_signature(
        &mutation.new_state.state,
        Some(&mutation.new_state.signature),
        verification,
    )?;
    validate_private_oram_append_mutation_v1_signature(
        mutation,
        Some(&mutation_bundle.signature),
        verification,
    )?;

    validate_mutation_context_fields(mutation, context)?;
    validate_mutation_lifetime(mutation, context)?;
    validate_state_transition(manifest, mutation, context)?;
    validate_point_operation(manifest, mutation, context)?;
    validate_writeback_transition(manifest, mutation, context)?;
    Ok(())
}

fn validate_append_validation_context(
    context: PrivateOramAppendValidationContext<'_>,
) -> Result<(), PrivateOramMutationError> {
    validate_resource_id(
        context.expected_collection_id,
        "expected_collection_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        context.expected_manifest_digest,
        "expected_manifest_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    validate_resource_id(
        context.expected_owner_signing_key_id,
        "expected_owner_signing_key_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    if context.expected_layout_generation == 0 {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "expected_layout_generation",
        ));
    }
    decode_base64url_32(
        context.expected_layout_digest,
        "expected_layout_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    decode_base64url_32(
        context.expected_writer_lease_digest,
        "expected_writer_lease_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    if context.expected_writer_fence == 0 {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "expected_writer_fence",
        ));
    }
    decode_base64url_32(
        context.expected_old_state_digest,
        "expected_old_state_digest",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    if let Some(record) = context.expected_visible_point_record {
        validate_resource_id(
            record.point_id,
            "expected_visible_point_record.point_id",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        decode_base64url_32(
            record.staged_insert_sha256,
            "expected_visible_point_record.staged_insert_sha256",
            PrivateOramMutationError::InvalidMutationField,
        )?;
    }
    validate_observed_read_transcripts(context.observed_read_transcripts)?;
    if context.now_unix == 0
        || context.max_mutation_ttl_secs == 0
        || context.max_mutation_ttl_secs > PRIVATE_ORAM_APPEND_MAX_MUTATION_TTL_SECS
        || context.public_key.len() != 32
    {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "validation_context",
        ));
    }
    Ok(())
}

fn validate_mutation_context_fields(
    mutation: &PrivateOramAppendMutationV1,
    context: PrivateOramAppendValidationContext<'_>,
) -> Result<(), PrivateOramMutationError> {
    if mutation.collection_id != context.expected_collection_id {
        return Err(PrivateOramMutationError::MutationContextMismatch(
            "collection_id",
        ));
    }
    if mutation.manifest_digest != context.expected_manifest_digest {
        return Err(PrivateOramMutationError::MutationContextMismatch(
            "manifest_digest",
        ));
    }
    if mutation.layout_generation != context.expected_layout_generation {
        return Err(PrivateOramMutationError::MutationContextMismatch(
            "layout_generation",
        ));
    }
    if mutation.writer_lease_digest != context.expected_writer_lease_digest
        || mutation.writer_fence != context.expected_writer_fence
    {
        return Err(PrivateOramMutationError::MutationContextMismatch(
            "writer_lease",
        ));
    }
    if mutation.owner_signing_key_id != context.expected_owner_signing_key_id {
        return Err(PrivateOramMutationError::SignatureKeyIdMismatch);
    }
    let old_state_digest = private_oram_signed_state_v2_digest(&mutation.old_state.state)?;
    if mutation.old_state.state.state_sequence != context.expected_state_sequence
        || old_state_digest != context.expected_old_state_digest
    {
        return Err(PrivateOramMutationError::StaleState);
    }
    Ok(())
}

fn validate_mutation_lifetime(
    mutation: &PrivateOramAppendMutationV1,
    context: PrivateOramAppendValidationContext<'_>,
) -> Result<(), PrivateOramMutationError> {
    let ttl = mutation
        .expires_at_unix
        .checked_sub(mutation.issued_at_unix)
        .ok_or(PrivateOramMutationError::InvalidMutationField(
            "mutation_lifetime",
        ))?;
    if ttl > context.max_mutation_ttl_secs {
        return Err(PrivateOramMutationError::MutationTtlExceeded);
    }
    if context.now_unix < mutation.issued_at_unix {
        return Err(PrivateOramMutationError::MutationNotYetValid);
    }
    if context.now_unix > mutation.expires_at_unix {
        return Err(PrivateOramMutationError::MutationExpired);
    }
    Ok(())
}

fn validate_state_transition(
    manifest: &PrivateOramImmutableManifestV2,
    mutation: &PrivateOramAppendMutationV1,
    context: PrivateOramAppendValidationContext<'_>,
) -> Result<(), PrivateOramMutationError> {
    let old = &mutation.old_state.state;
    let new = &mutation.new_state.state;
    for state in [old, new] {
        if state.collection_id != mutation.collection_id {
            return Err(PrivateOramMutationError::MutationContextMismatch(
                "state.collection_id",
            ));
        }
        if state.manifest_digest != mutation.manifest_digest {
            return Err(PrivateOramMutationError::MutationContextMismatch(
                "state.manifest_digest",
            ));
        }
        if state.layout_generation != mutation.layout_generation
            || state.layout_generation != context.expected_layout_generation
            || state.layout_digest != context.expected_layout_digest
        {
            return Err(PrivateOramMutationError::MutationContextMismatch(
                "state.layout",
            ));
        }
        if state.owner_signing_key_id != mutation.owner_signing_key_id {
            return Err(PrivateOramMutationError::SignatureKeyIdMismatch);
        }
    }
    validate_state_against_manifest(manifest, old)?;

    let expected_state_sequence = old.state_sequence.checked_add(1).ok_or(
        PrivateOramMutationError::InvalidStateTransition("state_sequence"),
    )?;
    if new.state_sequence != expected_state_sequence {
        return Err(PrivateOramMutationError::InvalidStateTransition(
            "state_sequence",
        ));
    }
    if new.last_mutation_id.as_deref() != Some(mutation.mutation_id.as_str()) {
        return Err(PrivateOramMutationError::InvalidStateTransition(
            "last_mutation_id",
        ));
    }
    if old.last_mutation_id.as_deref() == Some(mutation.mutation_id.as_str()) {
        return Err(PrivateOramMutationError::InvalidStateTransition(
            "mutation_id",
        ));
    }
    if new.client_state_digest == old.client_state_digest {
        return Err(PrivateOramMutationError::InvalidStateTransition(
            "client_state_digest",
        ));
    }
    if mutation.issued_at_unix < old.signed_at_unix
        || new.signed_at_unix < mutation.issued_at_unix
        || new.signed_at_unix > mutation.expires_at_unix
        || new.signed_at_unix < old.signed_at_unix
        || new.signed_at_unix > context.now_unix
    {
        return Err(PrivateOramMutationError::InvalidStateTransition(
            "signed_at_unix",
        ));
    }
    if old.indexes.len() != new.indexes.len() {
        return Err(PrivateOramMutationError::InvalidStateTransition("indexes"));
    }
    for (old_index, new_index) in old.indexes.iter().zip(&new.indexes) {
        if old_index.kind != new_index.kind || old_index.index_name != new_index.index_name {
            return Err(PrivateOramMutationError::InvalidStateTransition("indexes"));
        }
        let expected_index_epoch = old_index.index_epoch.checked_add(1).ok_or(
            PrivateOramMutationError::InvalidStateTransition("index_epoch"),
        )?;
        if new_index.index_epoch != expected_index_epoch {
            return Err(PrivateOramMutationError::InvalidStateTransition(
                "index_epoch",
            ));
        }
        if new_index.root_hash == old_index.root_hash {
            return Err(PrivateOramMutationError::InvalidStateTransition(
                "root_hash",
            ));
        }
        let expected_logical_count = old_index.logical_count.checked_add(1).ok_or(
            PrivateOramMutationError::InvalidStateTransition("logical_count"),
        )?;
        if new_index.logical_count != expected_logical_count {
            return Err(PrivateOramMutationError::InvalidStateTransition(
                "logical_count",
            ));
        }
        if old_index.dummy_count == 0 {
            return Err(PrivateOramMutationError::CapacityExhausted);
        }
        if new_index.dummy_count != old_index.dummy_count - 1 {
            return Err(PrivateOramMutationError::InvalidStateTransition(
                "dummy_count",
            ));
        }
        if new_index.last_writeback_digest == old_index.last_writeback_digest {
            return Err(PrivateOramMutationError::InvalidStateTransition(
                "last_writeback_digest",
            ));
        }
    }
    validate_state_against_manifest(manifest, new)?;
    Ok(())
}

fn validate_state_against_manifest(
    manifest: &PrivateOramImmutableManifestV2,
    state: &PrivateOramSignedStateV2,
) -> Result<(), PrivateOramMutationError> {
    if state.signed_at_unix < manifest.created_at_unix {
        return Err(PrivateOramMutationError::InvalidStateTransition(
            "signed_at_unix",
        ));
    }
    if state.indexes.len() != manifest.indexes.len() {
        return Err(PrivateOramMutationError::InvalidStateTransition("indexes"));
    }
    for (manifest_index, state_index) in manifest.indexes.iter().zip(&state.indexes) {
        if manifest_index.kind() != state_index.kind
            || manifest_index.index_name != state_index.index_name
        {
            return Err(PrivateOramMutationError::InvalidStateTransition("indexes"));
        }
        let occupancy = state_index
            .logical_count
            .checked_add(state_index.dummy_count)
            .ok_or(PrivateOramMutationError::InvalidStateTransition(
                "occupancy",
            ))?;
        if occupancy != manifest_index.capacity.logical_capacity {
            return Err(PrivateOramMutationError::InvalidStateTransition(
                "occupancy",
            ));
        }
    }
    Ok(())
}

fn validate_point_operation(
    manifest: &PrivateOramImmutableManifestV2,
    mutation: &PrivateOramAppendMutationV1,
    context: PrivateOramAppendValidationContext<'_>,
) -> Result<(), PrivateOramMutationError> {
    let (expected_kind, expected_digest) = match manifest.result_privacy {
        ResultPrivacyMode::IdsVisible => {
            let record = context
                .expected_visible_point_record
                .ok_or(PrivateOramMutationError::PointOperationMismatch)?;
            (
                PrivateOramPointOperationKindV1::VisiblePointRecord,
                private_oram_visible_point_record_v1_digest(
                    &mutation.collection_id,
                    &mutation.manifest_digest,
                    &mutation.mutation_id,
                    record,
                )?,
            )
        }
        ResultPrivacyMode::PrivatePayloadOramRequired => {
            if context.expected_visible_point_record.is_some() {
                return Err(PrivateOramMutationError::PointOperationMismatch);
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
    if mutation.point_operation_kind != expected_kind
        || mutation.point_operation_digest != expected_digest
    {
        return Err(PrivateOramMutationError::PointOperationMismatch);
    }
    Ok(())
}

fn validate_writeback_transition(
    manifest: &PrivateOramImmutableManifestV2,
    mutation: &PrivateOramAppendMutationV1,
    context: PrivateOramAppendValidationContext<'_>,
) -> Result<(), PrivateOramMutationError> {
    if mutation.writebacks.len() != manifest.indexes.len()
        || context.observed_read_transcripts.len() != manifest.indexes.len()
    {
        return Err(PrivateOramMutationError::FixedBudgetMismatch);
    }
    for (offset, (((manifest_index, old_index), new_index), writeback)) in manifest
        .indexes
        .iter()
        .zip(&mutation.old_state.state.indexes)
        .zip(&mutation.new_state.state.indexes)
        .zip(&mutation.writebacks)
        .enumerate()
    {
        let observed_read = &context.observed_read_transcripts[offset];
        let oram = manifest_index.params.oram();
        if writeback.kind != manifest_index.kind()
            || writeback.index_name != manifest_index.index_name
        {
            return Err(PrivateOramMutationError::InvalidStateTransition(
                "writebacks",
            ));
        }
        if writeback.read_path_count != manifest_index.capacity.fixed_append_read_path_count
            || observed_read.collection_id != mutation.collection_id
            || observed_read.manifest_digest != mutation.manifest_digest
            || observed_read.mutation_id != mutation.mutation_id
            || observed_read.old_state_digest != context.expected_old_state_digest
            || observed_read.writer_lease_digest != mutation.writer_lease_digest
            || observed_read.writer_fence != mutation.writer_fence
            || observed_read.kind != writeback.kind
            || observed_read.index_name != writeback.index_name
            || observed_read.read_path_count != writeback.read_path_count
            || observed_read.paths_per_window != oram.path_batch_size
            || observed_read.tree_height != oram.tree_height
            || observed_read.transcript_digest != writeback.read_transcript_digest
        {
            return Err(PrivateOramMutationError::FixedBudgetMismatch);
        }
        if writeback.updated_buckets.len()
            != usize::try_from(manifest_index.capacity.fixed_append_write_bucket_count)
                .map_err(|_| PrivateOramMutationError::FixedBudgetMismatch)?
        {
            return Err(PrivateOramMutationError::FixedBudgetMismatch);
        }
        let path_bucket_count = usize::try_from(oram.tree_height)
            .ok()
            .and_then(|tree_height| tree_height.checked_add(1))
            .ok_or(PrivateOramMutationError::FixedBudgetMismatch)?;
        if observed_read.ordered_leaf_labels.len()
            != usize::try_from(writeback.read_path_count)
                .map_err(|_| PrivateOramMutationError::FixedBudgetMismatch)?
            || writeback.updated_buckets.len()
                != observed_read
                    .ordered_leaf_labels
                    .len()
                    .checked_mul(path_bucket_count)
                    .ok_or(PrivateOramMutationError::FixedBudgetMismatch)?
        {
            return Err(PrivateOramMutationError::FixedBudgetMismatch);
        }
        for (leaf_label, bucket_frame) in observed_read
            .ordered_leaf_labels
            .iter()
            .zip(writeback.updated_buckets.chunks_exact(path_bucket_count))
        {
            let expected_bucket_ids =
                private_oram_path_bucket_ids_for_leaf_label(leaf_label, oram.tree_height)?;
            if bucket_frame
                .iter()
                .zip(expected_bucket_ids)
                .any(|(bucket, expected_bucket_id)| bucket.bucket_id != expected_bucket_id)
            {
                return Err(PrivateOramMutationError::FixedBudgetMismatch);
            }
        }
        let digest =
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
        if digest != new_index.last_writeback_digest {
            return Err(PrivateOramMutationError::WritebackDigestMismatch);
        }
    }
    Ok(())
}

fn validate_immutable_index_params(
    params: &PrivateOramImmutableIndexParamsV2,
) -> Result<(), PrivateOramMutationError> {
    match params {
        PrivateOramImmutableIndexParamsV2::Hnsw {
            provider,
            binding,
            key_id,
            rk_id,
            rk_epoch,
            dim,
            vector_encoding,
            distance: _,
            hnsw,
            oram,
            fixed_search_budget,
            max_neighbor_rewrites,
        } => {
            if provider != VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER {
                return Err(PrivateOramMutationError::InvalidManifestField(
                    "indexes.provider",
                ));
            }
            if binding != PRIVATE_HNSW_ORAM_V2_BINDING {
                return Err(PrivateOramMutationError::InvalidManifestField(
                    "indexes.binding",
                ));
            }
            validate_resource_key_fields(key_id, rk_id, *rk_epoch)?;
            if *dim == 0
                || hnsw.m == 0
                || hnsw.ef_construction == 0
                || hnsw.max_layers == 0
                || hnsw.max_layers > 64
                || hnsw.fixed_neighbor_slots < hnsw.m
                || *vector_encoding != PrivateHnswVectorEncoding::F32Le
                || *max_neighbor_rewrites == 0
            {
                return Err(PrivateOramMutationError::InvalidManifestField(
                    "indexes.hnsw",
                ));
            }
            validate_oram_params(oram)?;
            let min_block_size =
                private_hnsw_min_f32_node_block_bytes(*dim, hnsw.fixed_neighbor_slots).ok_or(
                    PrivateOramMutationError::InvalidManifestField("indexes.oram.block_size_bytes"),
                )?;
            if u64::from(oram.block_size_bytes) < min_block_size {
                return Err(PrivateOramMutationError::InvalidManifestField(
                    "indexes.oram.block_size_bytes",
                ));
            }
            if !fixed_search_budget.enabled
                || fixed_search_budget.upper_layer_steps == 0
                || fixed_search_budget.base_layer_steps == 0
                || fixed_search_budget.paths_per_round == 0
                || fixed_search_budget.fixed_result_k == 0
                || fixed_search_budget.paths_per_round != oram.path_batch_size
            {
                return Err(PrivateOramMutationError::InvalidManifestField(
                    "indexes.fixed_search_budget",
                ));
            }
        }
        PrivateOramImmutableIndexParamsV2::Result {
            provider,
            binding,
            key_id,
            rk_id,
            rk_epoch,
            oram,
        } => {
            if provider != PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER {
                return Err(PrivateOramMutationError::InvalidManifestField(
                    "indexes.provider",
                ));
            }
            if binding != PRIVATE_RESULT_ORAM_V2_BINDING {
                return Err(PrivateOramMutationError::InvalidManifestField(
                    "indexes.binding",
                ));
            }
            validate_resource_key_fields(key_id, rk_id, *rk_epoch)?;
            validate_oram_params(oram)?;
        }
    }
    Ok(())
}

fn validate_resource_key_fields(
    key_id: &str,
    rk_id: &str,
    rk_epoch: u64,
) -> Result<(), PrivateOramMutationError> {
    validate_resource_id(
        key_id,
        "indexes.key_id",
        PrivateOramMutationError::InvalidManifestField,
    )?;
    validate_resource_id(
        rk_id,
        "indexes.rk_id",
        PrivateOramMutationError::InvalidManifestField,
    )?;
    if rk_epoch == 0 {
        return Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.rk_epoch",
        ));
    }
    Ok(())
}

fn validate_oram_params(oram: &OramParams) -> Result<(), PrivateOramMutationError> {
    if oram.bucket_size == 0
        || oram.block_size_bytes == 0
        || oram.tree_height == 0
        || oram.tree_height >= 63
        || oram.path_batch_size == 0
        || u64::from(oram.path_batch_size) > (1u64 << oram.tree_height)
    {
        return Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.oram",
        ));
    }
    Ok(())
}

fn validate_index_capacity(
    params: &PrivateOramImmutableIndexParamsV2,
    capacity: &PrivateOramIndexCapacityV2,
) -> Result<(), PrivateOramMutationError> {
    let oram = params.oram();
    let expected_bucket_count = (1u64 << oram.tree_height)
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .ok_or(PrivateOramMutationError::InvalidManifestField(
            "indexes.capacity.bucket_count",
        ))?;
    if capacity.bucket_count != expected_bucket_count {
        return Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.capacity.bucket_count",
        ));
    }
    let physical_slots = capacity
        .bucket_count
        .checked_mul(u64::from(oram.bucket_size))
        .ok_or(PrivateOramMutationError::InvalidManifestField(
            "indexes.capacity",
        ))?;
    let minimum_path_bucket_count = u64::from(oram.tree_height) + 1;
    let read_bucket_responses = u64::from(capacity.fixed_append_read_path_count)
        .checked_mul(minimum_path_bucket_count)
        .ok_or(PrivateOramMutationError::InvalidManifestField(
            "indexes.capacity",
        ))?;
    if capacity.logical_capacity == 0
        || capacity.reserved_physical_slots == 0
        || capacity
            .logical_capacity
            .checked_add(capacity.reserved_physical_slots)
            .is_none_or(|required| required > physical_slots)
        || capacity.max_client_stash_blocks == 0
        || u64::from(capacity.max_client_stash_blocks) > physical_slots
        || capacity.fixed_append_read_path_count == 0
        || !capacity
            .fixed_append_read_path_count
            .is_multiple_of(oram.path_batch_size)
        || read_bucket_responses > PRIVATE_ORAM_MAX_UPDATED_BUCKETS_U64
        || u64::from(capacity.fixed_append_write_bucket_count) != read_bucket_responses
        || u64::from(capacity.fixed_append_write_bucket_count)
            > PRIVATE_ORAM_MAX_UPDATED_BUCKETS_U64
    {
        return Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.capacity",
        ));
    }
    if let PrivateOramImmutableIndexParamsV2::Hnsw {
        max_neighbor_rewrites,
        ..
    } = params
    {
        // Candidate reads are consumed in whole windows of `path_batch_size` paths, and an
        // append into a non-empty graph needs at least one candidate window on top of the
        // rewrites and the insert. A budget below one window would admit the first point and
        // then reject every later append of an immutable manifest for good.
        let reserved_paths = u64::from(*max_neighbor_rewrites).saturating_add(1);
        let candidate_budget =
            u64::from(capacity.fixed_append_read_path_count).saturating_sub(reserved_paths);
        if u64::from(*max_neighbor_rewrites) > capacity.logical_capacity
            || u64::from(capacity.fixed_append_read_path_count) < reserved_paths.saturating_add(1)
            || candidate_budget < u64::from(oram.path_batch_size)
        {
            return Err(PrivateOramMutationError::InvalidManifestField(
                "indexes.max_neighbor_rewrites",
            ));
        }
    }
    Ok(())
}

fn validate_canonical_manifest_indexes(
    indexes: &[PrivateOramImmutableIndexV2],
) -> Result<(), PrivateOramMutationError> {
    if indexes.is_empty() || indexes.len() > PRIVATE_ORAM_APPEND_MAX_INDEXES {
        return Err(PrivateOramMutationError::NonCanonicalIndexes);
    }
    if indexes.windows(2).any(|indexes| {
        index_sort_key(indexes[0].kind(), &indexes[0].index_name)
            >= index_sort_key(indexes[1].kind(), &indexes[1].index_name)
    }) {
        return Err(PrivateOramMutationError::NonCanonicalIndexes);
    }
    Ok(())
}

fn validate_canonical_state_indexes(
    indexes: &[PrivateOramIndexStateV2],
) -> Result<(), PrivateOramMutationError> {
    if indexes.is_empty() || indexes.len() > PRIVATE_ORAM_APPEND_MAX_INDEXES {
        return Err(PrivateOramMutationError::NonCanonicalIndexes);
    }
    if indexes.windows(2).any(|indexes| {
        index_sort_key(indexes[0].kind, &indexes[0].index_name)
            >= index_sort_key(indexes[1].kind, &indexes[1].index_name)
    }) {
        return Err(PrivateOramMutationError::NonCanonicalIndexes);
    }
    Ok(())
}

fn validate_canonical_writebacks(
    writebacks: &[PrivateOramAppendIndexWritebackV1],
) -> Result<(), PrivateOramMutationError> {
    if writebacks.is_empty() || writebacks.len() > PRIVATE_ORAM_APPEND_MAX_INDEXES {
        return Err(PrivateOramMutationError::NonCanonicalIndexes);
    }
    if writebacks.windows(2).any(|writebacks| {
        index_sort_key(writebacks[0].kind, &writebacks[0].index_name)
            >= index_sort_key(writebacks[1].kind, &writebacks[1].index_name)
    }) {
        return Err(PrivateOramMutationError::NonCanonicalIndexes);
    }
    let mut total_updated_buckets = 0usize;
    for writeback in writebacks {
        validate_index_name(
            &writeback.index_name,
            "writebacks.index_name",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        if writeback.read_path_count == 0 {
            return Err(PrivateOramMutationError::InvalidMutationField(
                "writebacks.read_path_count",
            ));
        }
        decode_base64url_32(
            &writeback.read_transcript_digest,
            "writebacks.read_transcript_digest",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        validate_ordered_bucket_occurrences(&writeback.updated_buckets)?;
        total_updated_buckets = total_updated_buckets
            .checked_add(writeback.updated_buckets.len())
            .ok_or(PrivateOramMutationError::NonCanonicalBuckets)?;
        if total_updated_buckets > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS {
            return Err(PrivateOramMutationError::NonCanonicalBuckets);
        }
    }
    Ok(())
}

fn validate_observed_read_transcripts(
    transcripts: &[PrivateOramObservedReadTranscriptV1],
) -> Result<(), PrivateOramMutationError> {
    if transcripts.is_empty() || transcripts.len() > PRIVATE_ORAM_APPEND_MAX_INDEXES {
        return Err(PrivateOramMutationError::NonCanonicalIndexes);
    }
    if transcripts.windows(2).any(|transcripts| {
        index_sort_key(transcripts[0].kind, &transcripts[0].index_name)
            >= index_sort_key(transcripts[1].kind, &transcripts[1].index_name)
    }) {
        return Err(PrivateOramMutationError::NonCanonicalIndexes);
    }
    for transcript in transcripts {
        validate_resource_id(
            &transcript.collection_id,
            "observed_read_transcripts.collection_id",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        decode_base64url_32(
            &transcript.manifest_digest,
            "observed_read_transcripts.manifest_digest",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        validate_mutation_id(
            &transcript.mutation_id,
            "observed_read_transcripts.mutation_id",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        decode_base64url_32(
            &transcript.writer_lease_digest,
            "observed_read_transcripts.writer_lease_digest",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        decode_base64url_32(
            &transcript.old_state_digest,
            "observed_read_transcripts.old_state_digest",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        validate_index_name(
            &transcript.index_name,
            "observed_read_transcripts.index_name",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        if transcript.read_path_count == 0
            || transcript.writer_fence == 0
            || transcript.paths_per_window == 0
            || transcript.tree_height == 0
            || transcript.tree_height >= 63
            || transcript.ordered_leaf_labels.len()
                != usize::try_from(transcript.read_path_count)
                    .map_err(|_| PrivateOramMutationError::FixedBudgetMismatch)?
        {
            return Err(PrivateOramMutationError::InvalidMutationField(
                "observed_read_transcripts.geometry",
            ));
        }
        decode_base64url_32(
            &transcript.transcript_digest,
            "observed_read_transcripts.transcript_digest",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        let leaf_count = 1u64.checked_shl(transcript.tree_height).ok_or(
            PrivateOramMutationError::InvalidMutationField("observed_read_transcripts.tree_height"),
        )?;
        for leaf_label in &transcript.ordered_leaf_labels {
            if u64::from_be_bytes(decode_base64url_8(leaf_label)?) >= leaf_count {
                return Err(PrivateOramMutationError::InvalidMutationField(
                    "observed_read_transcripts.ordered_leaf_labels",
                ));
            }
        }
        // The digest is recomputed from the labels rather than trusted. A transcript that was
        // deserialized from storage could otherwise carry any digest, which would make the later
        // `transcript_digest == writeback.read_transcript_digest` check tautological.
        let paths_per_window = usize::try_from(transcript.paths_per_window).map_err(|_| {
            PrivateOramMutationError::InvalidMutationField("observed_read_transcripts.geometry")
        })?;
        if !transcript
            .ordered_leaf_labels
            .len()
            .is_multiple_of(paths_per_window)
        {
            return Err(PrivateOramMutationError::InvalidMutationField(
                "observed_read_transcripts.geometry",
            ));
        }
        let windows = transcript
            .ordered_leaf_labels
            .chunks(paths_per_window)
            .enumerate()
            .map(|(sequence, paths)| {
                Ok(PrivateOramAppendReadWindowV1 {
                    sequence: u32::try_from(sequence).map_err(|_| {
                        PrivateOramMutationError::InvalidMutationField(
                            "observed_read_transcripts.geometry",
                        )
                    })?,
                    paths: paths.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, PrivateOramMutationError>>()?;
        let expected_digest =
            digest_message(try_private_oram_append_read_transcript_v1_digest_message(
                PrivateOramAppendReadTranscriptDigestInput {
                    collection_id: &transcript.collection_id,
                    manifest_digest: &transcript.manifest_digest,
                    mutation_id: &transcript.mutation_id,
                    old_state_digest: &transcript.old_state_digest,
                    writer_lease_digest: &transcript.writer_lease_digest,
                    writer_fence: transcript.writer_fence,
                    paths_per_window: transcript.paths_per_window,
                    tree_height: transcript.tree_height,
                    kind: transcript.kind,
                    index_name: &transcript.index_name,
                    windows: &windows,
                },
            )?);
        if expected_digest != transcript.transcript_digest {
            return Err(PrivateOramMutationError::InvalidMutationField(
                "observed_read_transcripts.transcript_digest",
            ));
        }
    }
    Ok(())
}

fn validate_ordered_bucket_occurrences(
    buckets: &[PrivateOramAppendBucketRefV1],
) -> Result<(), PrivateOramMutationError> {
    if buckets.is_empty() || buckets.len() > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS {
        return Err(PrivateOramMutationError::NonCanonicalBuckets);
    }
    for bucket in buckets {
        decode_base64url_32(
            &bucket.ciphertext_sha256,
            "writebacks.ciphertext_sha256",
            PrivateOramMutationError::InvalidMutationField,
        )?;
        decode_base64url_32(
            &bucket.bucket_commitment,
            "writebacks.bucket_commitment",
            PrivateOramMutationError::InvalidMutationField,
        )?;
    }
    Ok(())
}

fn index_sort_key(kind: PrivateOramIndexKindV2, name: &str) -> (u8, &str) {
    (kind.tag(), name)
}

fn push_immutable_index_params(
    message: &mut Vec<u8>,
    params: &PrivateOramImmutableIndexParamsV2,
) -> Result<(), PrivateOramMutationError> {
    match params {
        PrivateOramImmutableIndexParamsV2::Hnsw {
            provider,
            binding,
            key_id,
            rk_id,
            rk_epoch,
            dim,
            vector_encoding,
            distance,
            hnsw,
            oram,
            fixed_search_budget,
            max_neighbor_rewrites,
        } => {
            try_push_str(message, provider)?;
            try_push_str(message, binding)?;
            try_push_str(message, key_id)?;
            try_push_str(message, rk_id)?;
            push_u64(message, *rk_epoch);
            push_u32(message, *dim);
            push_u8(
                message,
                match vector_encoding {
                    PrivateHnswVectorEncoding::F32Le => 1,
                    PrivateHnswVectorEncoding::I8Quantized => 2,
                    PrivateHnswVectorEncoding::PqCode => 3,
                    PrivateHnswVectorEncoding::BinaryQuantized => 4,
                },
            );
            push_u8(
                message,
                match distance {
                    DistanceKind::Cosine => 1,
                    DistanceKind::Dot => 2,
                    DistanceKind::Euclid => 3,
                    DistanceKind::Manhattan => 4,
                },
            );
            push_u32(message, hnsw.m);
            push_u32(message, hnsw.ef_construction);
            push_u32(message, hnsw.max_layers);
            push_u32(message, hnsw.fixed_neighbor_slots);
            push_oram_params(message, oram);
            push_bool(message, fixed_search_budget.enabled);
            push_u32(message, fixed_search_budget.upper_layer_steps);
            push_u32(message, fixed_search_budget.base_layer_steps);
            push_u32(message, fixed_search_budget.paths_per_round);
            push_u32(message, fixed_search_budget.fixed_result_k);
            push_u32(message, *max_neighbor_rewrites);
        }
        PrivateOramImmutableIndexParamsV2::Result {
            provider,
            binding,
            key_id,
            rk_id,
            rk_epoch,
            oram,
        } => {
            try_push_str(message, provider)?;
            try_push_str(message, binding)?;
            try_push_str(message, key_id)?;
            try_push_str(message, rk_id)?;
            push_u64(message, *rk_epoch);
            push_oram_params(message, oram);
        }
    }
    Ok(())
}

fn push_oram_params(message: &mut Vec<u8>, oram: &OramParams) {
    push_u8(message, 1);
    push_u32(message, oram.bucket_size);
    push_u32(message, oram.block_size_bytes);
    push_u32(message, oram.tree_height);
    push_u32(message, oram.path_batch_size);
}

fn push_index_capacity(message: &mut Vec<u8>, capacity: &PrivateOramIndexCapacityV2) {
    push_u64(message, capacity.bucket_count);
    push_u64(message, capacity.logical_capacity);
    push_u64(message, capacity.reserved_physical_slots);
    push_u32(message, capacity.max_client_stash_blocks);
    push_u32(message, capacity.fixed_append_read_path_count);
    push_u32(message, capacity.fixed_append_write_bucket_count);
}

fn push_bucket_refs(
    message: &mut Vec<u8>,
    buckets: &[PrivateOramAppendBucketRefV1],
) -> Result<(), PrivateOramMutationError> {
    push_len(message, buckets.len())?;
    for bucket in buckets {
        push_u64(message, bucket.bucket_id);
        try_push_str(message, &bucket.ciphertext_sha256)?;
        try_push_str(message, &bucket.bucket_commitment)?;
    }
    Ok(())
}

fn sign_message(
    key_pair: &Ed25519KeyPair,
    key_id: &str,
    message: Vec<u8>,
) -> Result<PrivateOramSignature, PrivateOramMutationError> {
    validate_resource_id(
        key_id,
        "owner_signing_key_id",
        PrivateOramMutationError::InvalidMutationField,
    )?;
    Ok(PrivateOramSignature {
        alg: PRIVATE_ORAM_SIGNATURE_ALGORITHM.to_string(),
        key_id: key_id.to_string(),
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    })
}

fn verify_signature(
    signature: Option<&PrivateOramSignature>,
    signed_key_id: &str,
    verification: PrivateOramSignatureVerification<'_>,
    message: Vec<u8>,
    invalid_signature_error: PrivateOramMutationError,
) -> Result<(), PrivateOramMutationError> {
    let signature = signature.ok_or(PrivateOramMutationError::MissingSignature)?;
    validate_private_oram_signature_shape(signature)?;
    if signed_key_id != verification.expected_key_id
        || signature.key_id != signed_key_id
        || signature.key_id != verification.expected_key_id
    {
        return Err(PrivateOramMutationError::SignatureKeyIdMismatch);
    }
    if verification.public_key.len() != 32 {
        return Err(PrivateOramMutationError::MalformedSignature);
    }
    let signature_bytes = decode_base64url_64(&signature.sig)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| invalid_signature_error)
}

fn validate_resource_id(
    value: &str,
    field: &'static str,
    error: fn(&'static str) -> PrivateOramMutationError,
) -> Result<(), PrivateOramMutationError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(error(field));
    }
    Ok(())
}

fn validate_index_name(
    value: &str,
    field: &'static str,
    error: fn(&'static str) -> PrivateOramMutationError,
) -> Result<(), PrivateOramMutationError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(error(field));
    }
    Ok(())
}

fn validate_mutation_id(
    value: &str,
    field: &'static str,
    error: fn(&'static str) -> PrivateOramMutationError,
) -> Result<(), PrivateOramMutationError> {
    decode_base64url_32(value, field, error).map(|_| ())
}

fn decode_base64url_8(value: &str) -> Result<[u8; 8], PrivateOramMutationError> {
    if value.len() != BASE64URL_NOPAD_8_BYTE_LEN {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "read_windows.paths",
        ));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMutationError::InvalidMutationField("read_windows.paths"))?;
    decoded
        .try_into()
        .map_err(|_| PrivateOramMutationError::InvalidMutationField("read_windows.paths"))
}

fn private_oram_path_bucket_ids_for_leaf_label(
    leaf_label: &str,
    tree_height: u32,
) -> Result<Vec<u64>, PrivateOramMutationError> {
    let leaf = u64::from_be_bytes(decode_base64url_8(leaf_label)?);
    let leaf_count =
        1u64.checked_shl(tree_height)
            .ok_or(PrivateOramMutationError::InvalidMutationField(
                "read_windows.tree_height",
            ))?;
    if tree_height == 0 || tree_height >= 63 || leaf >= leaf_count {
        return Err(PrivateOramMutationError::InvalidMutationField(
            "read_windows.paths",
        ));
    }
    let path_capacity = usize::try_from(tree_height)
        .ok()
        .and_then(|tree_height| tree_height.checked_add(1))
        .ok_or(PrivateOramMutationError::FixedBudgetMismatch)?;
    let mut bucket_ids = Vec::with_capacity(path_capacity);
    for level in 0..=tree_height {
        let level_start = (1u64 << level) - 1;
        let prefix = if level == 0 {
            0
        } else {
            leaf >> (tree_height - level)
        };
        bucket_ids.push(level_start + prefix);
    }
    Ok(bucket_ids)
}

fn decode_base64url_32(
    value: &str,
    field: &'static str,
    error: fn(&'static str) -> PrivateOramMutationError,
) -> Result<[u8; 32], PrivateOramMutationError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(error(field));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| error(field))?;
    decoded.try_into().map_err(|_| error(field))
}

fn decode_base64url_64(value: &str) -> Result<[u8; 64], PrivateOramMutationError> {
    if value.len() != BASE64URL_NOPAD_64_BYTE_LEN {
        return Err(PrivateOramMutationError::MalformedSignature);
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMutationError::MalformedSignature)?;
    decoded
        .try_into()
        .map_err(|_| PrivateOramMutationError::MalformedSignature)
}

fn digest_message(message: Vec<u8>) -> String {
    BASE64URL_NOPAD.encode(Sha256::digest(message).as_ref())
}

fn try_push_domain(message: &mut Vec<u8>, domain: &[u8]) -> Result<(), PrivateOramMutationError> {
    let len = u32::try_from(domain.len())
        .map_err(|_| PrivateOramMutationError::InvalidMutationField("canonical_message"))?;
    push_u32(message, len);
    message.extend_from_slice(domain);
    Ok(())
}

fn try_push_str(message: &mut Vec<u8>, value: &str) -> Result<(), PrivateOramMutationError> {
    let len = u64::try_from(value.len())
        .map_err(|_| PrivateOramMutationError::InvalidMutationField("canonical_message"))?;
    push_u64(message, len);
    message.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_optional_str(
    message: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), PrivateOramMutationError> {
    match value {
        Some(value) => {
            push_u8(message, 1);
            try_push_str(message, value)?;
        }
        None => push_u8(message, 0),
    }
    Ok(())
}

fn push_len(message: &mut Vec<u8>, len: usize) -> Result<(), PrivateOramMutationError> {
    push_u32(
        message,
        u32::try_from(len)
            .map_err(|_| PrivateOramMutationError::InvalidMutationField("canonical_message"))?,
    );
    Ok(())
}

fn push_bool(message: &mut Vec<u8>, value: bool) {
    push_u8(message, u8::from(value));
}

fn push_u8(message: &mut Vec<u8>, value: u8) {
    message.push(value);
}

fn push_u16(message: &mut Vec<u8>, value: u16) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(message: &mut Vec<u8>, value: u32) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(message: &mut Vec<u8>, value: u64) {
    message.extend_from_slice(&value.to_be_bytes());
}
