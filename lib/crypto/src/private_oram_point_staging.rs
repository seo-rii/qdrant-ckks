use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::private_oram_mutation::{
    PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION, PrivateOramAppendMutationBundleV1,
    PrivateOramAppendMutationV1, PrivateOramPointOperationKindV1, PrivateOramVisiblePointRecordV1,
    private_oram_signed_state_v2_digest, private_oram_visible_point_record_v1_digest,
};

pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION: u16 = 1;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_DOMAIN: &str =
    "qdrant-sec/private-oram-staged-insert-frame/v1";
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES: usize = 64 * 1024 * 1024;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_NAME_BYTES: usize = 256;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_SHARD_KEYWORD_BYTES: usize = 1_024;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_TARGET_SHARDS: usize = 65_536;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_NAMED_VECTORS: usize = 1_024;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_DIMENSION: usize = 1_048_576;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_MULTI_DENSE_VECTORS: usize = 65_536;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_TOTAL_VECTOR_VALUES: usize = 8_388_608;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_DEPTH: usize = 64;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_VALUES: usize = 1_000_000;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_CONTAINER_ENTRIES: usize = 1_000_000;
pub const PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_STRING_BYTES: usize = 8 * 1024 * 1024;

const PRIVATE_ORAM_RESOURCE_ID_MAX_BYTES: usize = 256;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;

const POINT_ID_NUMERIC_TAG: u8 = 1;
const POINT_ID_UUID_TAG: u8 = 2;
const OPTIONAL_NONE_TAG: u8 = 0;
const OPTIONAL_SOME_TAG: u8 = 1;
const SHARD_KEY_KEYWORD_TAG: u8 = 1;
const SHARD_KEY_NUMBER_TAG: u8 = 2;
const VECTOR_DENSE_TAG: u8 = 1;
const VECTOR_SPARSE_TAG: u8 = 2;
const VECTOR_MULTI_DENSE_TAG: u8 = 3;
const JSON_NULL_TAG: u8 = 0;
const JSON_BOOL_TAG: u8 = 1;
const JSON_I64_TAG: u8 = 2;
const JSON_U64_TAG: u8 = 3;
const JSON_F64_TAG: u8 = 4;
const JSON_STRING_TAG: u8 = 5;
const JSON_ARRAY_TAG: u8 = 6;
const JSON_OBJECT_TAG: u8 = 7;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramStagingError {
    #[error("private ORAM staged insert frame uses an unsupported version")]
    UnsupportedVersion,
    #[error("private ORAM staged insert frame field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM staged insert frame digest is malformed")]
    MalformedDigest(&'static str),
    #[error("private ORAM staged insert frame point UUID is not canonical")]
    NonCanonicalPointUuid,
    #[error("private ORAM staged insert frame contains a non-finite number")]
    NonFiniteNumber(&'static str),
    #[error("private ORAM staged insert frame contains duplicate vector names")]
    DuplicateVectorName,
    #[error("private ORAM staged insert frame contains duplicate sparse indices")]
    DuplicateSparseIndex,
    #[error("private ORAM staged insert frame sparse vector is invalid")]
    InvalidSparseVector,
    #[error("private ORAM staged insert frame multi-dense vector is invalid")]
    InvalidMultiDenseVector,
    #[error("private ORAM staged insert frame exceeds its hard size bound")]
    FrameTooLarge,
    #[error("private ORAM staged insert frame exceeds a resource bound")]
    LimitExceeded(&'static str),
    #[error("private ORAM staged insert frame encoding is truncated")]
    UnexpectedEnd,
    #[error("private ORAM staged insert frame encoding is malformed")]
    MalformedEncoding(&'static str),
    #[error("private ORAM staged insert frame has trailing bytes")]
    TrailingBytes,
    #[error("private ORAM staged insert frame encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("private ORAM staged insert frame allocation failed")]
    AllocationFailed,
    #[error("private ORAM staged insert requires a visible point mutation")]
    VisiblePointRecordRequired,
    #[error("private ORAM staged insert frame does not match the mutation")]
    MutationBindingMismatch(&'static str),
    #[error("private ORAM staged insert mutation state digest is invalid")]
    InvalidMutationStateDigest,
    #[error("private ORAM staged insert point operation digest does not match")]
    PointOperationDigestMismatch,
}

impl Debug for PrivateOramStagingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateOramStagingError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateOramStagedPointIdV1 {
    Numeric { value: u64 },
    Uuid { value: String },
}

impl Debug for PrivateOramStagedPointIdV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Numeric { .. } => "numeric",
            Self::Uuid { .. } => "uuid",
        };
        f.debug_struct("PrivateOramStagedPointIdV1")
            .field("kind", &kind)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateOramStagedShardKeyV1 {
    Keyword { value: String },
    Number { value: u64 },
}

impl Debug for PrivateOramStagedShardKeyV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Keyword { .. } => "keyword",
            Self::Number { .. } => "number",
        };
        f.debug_struct("PrivateOramStagedShardKeyV1")
            .field("kind", &kind)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrivateOramStagedVectorV1 {
    Dense { values: Vec<f32> },
    Sparse { indices: Vec<u32>, values: Vec<f32> },
    MultiDense { vectors: Vec<Vec<f32>> },
}

impl Debug for PrivateOramStagedVectorV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dense { values } => f
                .debug_struct("PrivateOramStagedVectorV1")
                .field("kind", &"dense")
                .field("value_count", &values.len())
                .field("values", &"[redacted]")
                .finish(),
            Self::Sparse { indices, .. } => f
                .debug_struct("PrivateOramStagedVectorV1")
                .field("kind", &"sparse")
                .field("value_count", &indices.len())
                .field("values", &"[redacted]")
                .finish(),
            Self::MultiDense { vectors } => f
                .debug_struct("PrivateOramStagedVectorV1")
                .field("kind", &"multi_dense")
                .field("vector_count", &vectors.len())
                .field("values", &"[redacted]")
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramStagedNamedVectorV1 {
    pub name: String,
    pub vector: PrivateOramStagedVectorV1,
}

impl Debug for PrivateOramStagedNamedVectorV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramStagedNamedVectorV1")
            .field("name", &"[redacted]")
            .field("vector", &self.vector)
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramStagedPointV1 {
    pub id: PrivateOramStagedPointIdV1,
    pub vectors: Vec<PrivateOramStagedNamedVectorV1>,
    pub payload: Option<Map<String, Value>>,
}

impl Debug for PrivateOramStagedPointV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramStagedPointV1")
            .field("id", &"[redacted]")
            .field("vector_count", &self.vectors.len())
            .field("vectors", &"[redacted]")
            .field("payload", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramStagedInsertFrameV1 {
    pub version: u16,
    pub collection_id: String,
    pub manifest_digest: String,
    pub mutation_id: String,
    pub old_state_digest: String,
    pub new_state_digest: String,
    pub layout_generation: u64,
    pub layout_digest: String,
    pub old_state_sequence: u64,
    pub new_state_sequence: u64,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub target_shard_ids: Vec<u32>,
    pub shard_key: Option<PrivateOramStagedShardKeyV1>,
    pub point: PrivateOramStagedPointV1,
}

impl Debug for PrivateOramStagedInsertFrameV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramStagedInsertFrameV1")
            .field("version", &self.version)
            .field("collection_id", &"[redacted]")
            .field("manifest_digest", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("old_state_digest", &"[redacted]")
            .field("new_state_digest", &"[redacted]")
            .field("layout_generation", &self.layout_generation)
            .field("layout_digest", &"[redacted]")
            .field("old_state_sequence", &self.old_state_sequence)
            .field("new_state_sequence", &self.new_state_sequence)
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("target_shard_count", &self.target_shard_ids.len())
            .field("target_shard_ids", &"[redacted]")
            .field("shard_key", &"[redacted]")
            .field("point", &"[redacted]")
            .finish()
    }
}

pub fn encode_private_oram_staged_insert_frame_v1(
    frame: &PrivateOramStagedInsertFrameV1,
) -> Result<Vec<u8>, PrivateOramStagingError> {
    validate_frame_header(frame)?;

    let mut encoder = CanonicalEncoder::new();
    encoder.push_domain(PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_DOMAIN)?;
    encoder.push_u16(frame.version)?;
    encoder.push_string(&frame.collection_id)?;
    encoder.push_digest(&frame.manifest_digest, "manifest_digest")?;
    encoder.push_digest(&frame.mutation_id, "mutation_id")?;
    encoder.push_digest(&frame.old_state_digest, "old_state_digest")?;
    encoder.push_digest(&frame.new_state_digest, "new_state_digest")?;
    encoder.push_u64(frame.layout_generation)?;
    encoder.push_digest(&frame.layout_digest, "layout_digest")?;
    encoder.push_u64(frame.old_state_sequence)?;
    encoder.push_u64(frame.new_state_sequence)?;
    encoder.push_digest(&frame.writer_lease_digest, "writer_lease_digest")?;
    encoder.push_u64(frame.writer_fence)?;
    encoder.push_len(frame.target_shard_ids.len(), "target_shard_ids")?;
    for target_shard_id in &frame.target_shard_ids {
        encoder.push_u32(*target_shard_id)?;
    }
    encode_shard_key(&mut encoder, frame.shard_key.as_ref())?;
    encode_point(&mut encoder, &frame.point)?;
    Ok(encoder.finish())
}

pub fn decode_private_oram_staged_insert_frame_v1(
    bytes: &[u8],
) -> Result<PrivateOramStagedInsertFrameV1, PrivateOramStagingError> {
    if bytes.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES {
        return Err(PrivateOramStagingError::FrameTooLarge);
    }

    let mut decoder = CanonicalDecoder::new(bytes);
    decoder.read_domain(PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_DOMAIN)?;
    let version = decoder.read_u16()?;
    let collection_id = decoder.read_string(PRIVATE_ORAM_RESOURCE_ID_MAX_BYTES, "collection_id")?;
    let manifest_digest = decoder.read_digest()?;
    let mutation_id = decoder.read_digest()?;
    let old_state_digest = decoder.read_digest()?;
    let new_state_digest = decoder.read_digest()?;
    let layout_generation = decoder.read_u64()?;
    let layout_digest = decoder.read_digest()?;
    let old_state_sequence = decoder.read_u64()?;
    let new_state_sequence = decoder.read_u64()?;
    let writer_lease_digest = decoder.read_digest()?;
    let writer_fence = decoder.read_u64()?;
    let target_shard_count = decoder.read_bounded_count(
        PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_TARGET_SHARDS,
        "target_shard_ids",
    )?;
    if target_shard_count == 0 || target_shard_count > decoder.remaining() / 4 {
        return Err(PrivateOramStagingError::InvalidField("target_shard_ids"));
    }
    let mut target_shard_ids = try_vec_with_capacity(target_shard_count)?;
    let mut previous_target_shard_id = None;
    for _ in 0..target_shard_count {
        let target_shard_id = decoder.read_u32()?;
        if previous_target_shard_id.is_some_and(|previous| previous >= target_shard_id) {
            return Err(PrivateOramStagingError::NonCanonicalEncoding);
        }
        previous_target_shard_id = Some(target_shard_id);
        target_shard_ids.push(target_shard_id);
    }
    let shard_key = decode_shard_key(&mut decoder)?;
    let point = decode_point(&mut decoder)?;

    if !decoder.is_finished() {
        return Err(PrivateOramStagingError::TrailingBytes);
    }

    let frame = PrivateOramStagedInsertFrameV1 {
        version,
        collection_id,
        manifest_digest,
        mutation_id,
        old_state_digest,
        new_state_digest,
        layout_generation,
        layout_digest,
        old_state_sequence,
        new_state_sequence,
        writer_lease_digest,
        writer_fence,
        target_shard_ids,
        shard_key,
        point,
    };
    let canonical = encode_private_oram_staged_insert_frame_v1(&frame)?;
    if canonical.as_slice() != bytes {
        return Err(PrivateOramStagingError::NonCanonicalEncoding);
    }
    Ok(frame)
}

pub fn private_oram_staged_insert_frame_v1_digest(
    frame: &PrivateOramStagedInsertFrameV1,
) -> Result<String, PrivateOramStagingError> {
    let bytes = encode_private_oram_staged_insert_frame_v1(frame)?;
    Ok(digest_bytes(&bytes))
}

pub fn private_oram_staged_point_id_canonical_string(
    point_id: &PrivateOramStagedPointIdV1,
) -> Result<String, PrivateOramStagingError> {
    match point_id {
        PrivateOramStagedPointIdV1::Numeric { value } => Ok(value.to_string()),
        PrivateOramStagedPointIdV1::Uuid { value } => {
            let parsed = Uuid::parse_str(value)
                .map_err(|_| PrivateOramStagingError::NonCanonicalPointUuid)?;
            let canonical = parsed.hyphenated().to_string();
            if canonical != *value {
                return Err(PrivateOramStagingError::NonCanonicalPointUuid);
            }
            Ok(canonical)
        }
    }
}

pub fn validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
    frame: &PrivateOramStagedInsertFrameV1,
    bundle: &PrivateOramAppendMutationBundleV1,
) -> Result<(), PrivateOramStagingError> {
    // The caller must validate the mutation and state signatures before using this binding check.
    validate_private_oram_staged_insert_frame_v1_against_mutation(frame, &bundle.mutation)
}

pub fn validate_private_oram_staged_insert_frame_v1_against_mutation(
    frame: &PrivateOramStagedInsertFrameV1,
    mutation: &PrivateOramAppendMutationV1,
) -> Result<(), PrivateOramStagingError> {
    let frame_bytes = encode_private_oram_staged_insert_frame_v1(frame)?;
    if mutation.version != PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION {
        return Err(PrivateOramStagingError::MutationBindingMismatch("version"));
    }
    if mutation.point_operation_kind != PrivateOramPointOperationKindV1::VisiblePointRecord {
        return Err(PrivateOramStagingError::VisiblePointRecordRequired);
    }
    require_equal(
        &frame.collection_id,
        &mutation.collection_id,
        "collection_id",
    )?;
    require_equal(
        &frame.manifest_digest,
        &mutation.manifest_digest,
        "manifest_digest",
    )?;
    require_equal(&frame.mutation_id, &mutation.mutation_id, "mutation_id")?;
    if frame.layout_generation != mutation.layout_generation {
        return Err(PrivateOramStagingError::MutationBindingMismatch(
            "layout_generation",
        ));
    }
    require_equal(
        &frame.layout_digest,
        &mutation.old_state.state.layout_digest,
        "layout_digest",
    )?;
    require_equal(
        &frame.layout_digest,
        &mutation.new_state.state.layout_digest,
        "layout_digest",
    )?;
    if frame.old_state_sequence != mutation.old_state.state.state_sequence {
        return Err(PrivateOramStagingError::MutationBindingMismatch(
            "old_state_sequence",
        ));
    }
    if frame.new_state_sequence != mutation.new_state.state.state_sequence {
        return Err(PrivateOramStagingError::MutationBindingMismatch(
            "new_state_sequence",
        ));
    }
    require_equal(
        &frame.writer_lease_digest,
        &mutation.writer_lease_digest,
        "writer_lease_digest",
    )?;
    if frame.writer_fence != mutation.writer_fence {
        return Err(PrivateOramStagingError::MutationBindingMismatch(
            "writer_fence",
        ));
    }

    let old_state_digest = private_oram_signed_state_v2_digest(&mutation.old_state.state)
        .map_err(|_| PrivateOramStagingError::InvalidMutationStateDigest)?;
    let new_state_digest = private_oram_signed_state_v2_digest(&mutation.new_state.state)
        .map_err(|_| PrivateOramStagingError::InvalidMutationStateDigest)?;
    require_equal(
        &frame.old_state_digest,
        &old_state_digest,
        "old_state_digest",
    )?;
    require_equal(
        &frame.new_state_digest,
        &new_state_digest,
        "new_state_digest",
    )?;

    let canonical_point_id = private_oram_staged_point_id_canonical_string(&frame.point.id)?;
    let staged_insert_sha256 = digest_bytes(&frame_bytes);
    let expected_point_operation_digest = private_oram_visible_point_record_v1_digest(
        &frame.collection_id,
        &frame.manifest_digest,
        &frame.mutation_id,
        PrivateOramVisiblePointRecordV1 {
            point_id: &canonical_point_id,
            staged_insert_sha256: &staged_insert_sha256,
        },
    )
    .map_err(|_| PrivateOramStagingError::PointOperationDigestMismatch)?;
    if mutation.point_operation_digest != expected_point_operation_digest {
        return Err(PrivateOramStagingError::PointOperationDigestMismatch);
    }
    Ok(())
}

fn validate_frame_header(
    frame: &PrivateOramStagedInsertFrameV1,
) -> Result<(), PrivateOramStagingError> {
    if frame.version != PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION {
        return Err(PrivateOramStagingError::UnsupportedVersion);
    }
    validate_resource_id(&frame.collection_id, "collection_id")?;
    decode_digest(&frame.manifest_digest, "manifest_digest")?;
    decode_digest(&frame.mutation_id, "mutation_id")?;
    decode_digest(&frame.old_state_digest, "old_state_digest")?;
    decode_digest(&frame.new_state_digest, "new_state_digest")?;
    decode_digest(&frame.layout_digest, "layout_digest")?;
    decode_digest(&frame.writer_lease_digest, "writer_lease_digest")?;
    if frame.old_state_digest == frame.new_state_digest {
        return Err(PrivateOramStagingError::InvalidField("state_digests"));
    }
    if frame.layout_generation == 0 {
        return Err(PrivateOramStagingError::InvalidField("layout_generation"));
    }
    if frame.old_state_sequence.checked_add(1) != Some(frame.new_state_sequence) {
        return Err(PrivateOramStagingError::InvalidField("state_sequence"));
    }
    if frame.writer_fence == 0 {
        return Err(PrivateOramStagingError::InvalidField("writer_fence"));
    }
    if frame.target_shard_ids.is_empty()
        || frame.target_shard_ids.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_TARGET_SHARDS
        || frame
            .target_shard_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(PrivateOramStagingError::InvalidField("target_shard_ids"));
    }
    Ok(())
}

fn encode_shard_key(
    encoder: &mut CanonicalEncoder,
    shard_key: Option<&PrivateOramStagedShardKeyV1>,
) -> Result<(), PrivateOramStagingError> {
    match shard_key {
        None => encoder.push_u8(OPTIONAL_NONE_TAG),
        Some(PrivateOramStagedShardKeyV1::Keyword { value }) => {
            validate_shard_keyword(value)?;
            encoder.push_u8(OPTIONAL_SOME_TAG)?;
            encoder.push_u8(SHARD_KEY_KEYWORD_TAG)?;
            encoder.push_string(value)
        }
        Some(PrivateOramStagedShardKeyV1::Number { value }) => {
            encoder.push_u8(OPTIONAL_SOME_TAG)?;
            encoder.push_u8(SHARD_KEY_NUMBER_TAG)?;
            encoder.push_u64(*value)
        }
    }
}

fn decode_shard_key(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<Option<PrivateOramStagedShardKeyV1>, PrivateOramStagingError> {
    match decoder.read_u8()? {
        OPTIONAL_NONE_TAG => Ok(None),
        OPTIONAL_SOME_TAG => match decoder.read_u8()? {
            SHARD_KEY_KEYWORD_TAG => {
                let value = decoder.read_string(
                    PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_SHARD_KEYWORD_BYTES,
                    "shard_key",
                )?;
                validate_shard_keyword(&value)?;
                Ok(Some(PrivateOramStagedShardKeyV1::Keyword { value }))
            }
            SHARD_KEY_NUMBER_TAG => Ok(Some(PrivateOramStagedShardKeyV1::Number {
                value: decoder.read_u64()?,
            })),
            _ => Err(PrivateOramStagingError::MalformedEncoding("shard_key_kind")),
        },
        _ => Err(PrivateOramStagingError::MalformedEncoding(
            "optional_shard_key",
        )),
    }
}

fn encode_point(
    encoder: &mut CanonicalEncoder,
    point: &PrivateOramStagedPointV1,
) -> Result<(), PrivateOramStagingError> {
    encode_point_id(encoder, &point.id)?;
    if point.vectors.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_NAMED_VECTORS {
        return Err(PrivateOramStagingError::LimitExceeded("vectors"));
    }

    let mut vectors = Vec::new();
    vectors
        .try_reserve_exact(point.vectors.len())
        .map_err(|_| PrivateOramStagingError::AllocationFailed)?;
    vectors.extend(point.vectors.iter());
    for vector in &vectors {
        validate_vector_name(&vector.name)?;
    }
    vectors.sort_unstable_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    if vectors.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(PrivateOramStagingError::DuplicateVectorName);
    }

    encoder.push_len(vectors.len(), "vectors")?;
    let mut total_vector_values = 0usize;
    for named_vector in vectors {
        encoder.push_string(&named_vector.name)?;
        encode_vector(encoder, &named_vector.vector, &mut total_vector_values)?;
    }

    match &point.payload {
        None => encoder.push_u8(OPTIONAL_NONE_TAG),
        Some(payload) => {
            encoder.push_u8(OPTIONAL_SOME_TAG)?;
            let mut json_context = JsonEncodeContext { value_count: 0 };
            validate_json_position(0, &mut json_context.value_count)?;
            encode_json_object(encoder, payload, 0, &mut json_context)
        }
    }
}

fn decode_point(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<PrivateOramStagedPointV1, PrivateOramStagingError> {
    let id = decode_point_id(decoder)?;
    let vector_count = decoder.read_bounded_count(
        PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_NAMED_VECTORS,
        "vectors",
    )?;
    if vector_count > decoder.remaining() {
        return Err(PrivateOramStagingError::LimitExceeded("vectors"));
    }
    let mut vectors = try_vec_with_capacity(vector_count)?;
    let mut previous_name: Option<String> = None;
    let mut total_vector_values = 0usize;
    for _ in 0..vector_count {
        let name = decoder.read_string(
            PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_NAME_BYTES,
            "vector_name",
        )?;
        validate_vector_name(&name)?;
        if previous_name
            .as_ref()
            .is_some_and(|previous| previous.as_bytes() >= name.as_bytes())
        {
            return Err(PrivateOramStagingError::NonCanonicalEncoding);
        }
        previous_name = Some(name.clone());
        let vector = decode_vector(decoder, &mut total_vector_values)?;
        vectors.push(PrivateOramStagedNamedVectorV1 { name, vector });
    }

    let payload = match decoder.read_u8()? {
        OPTIONAL_NONE_TAG => None,
        OPTIONAL_SOME_TAG => {
            let mut json_context = JsonDecodeContext { value_count: 0 };
            match decode_json_value(decoder, 0, &mut json_context)? {
                Value::Object(payload) => Some(payload),
                _ => {
                    return Err(PrivateOramStagingError::MalformedEncoding("payload"));
                }
            }
        }
        _ => {
            return Err(PrivateOramStagingError::MalformedEncoding(
                "optional_payload",
            ));
        }
    };
    Ok(PrivateOramStagedPointV1 {
        id,
        vectors,
        payload,
    })
}

fn encode_point_id(
    encoder: &mut CanonicalEncoder,
    point_id: &PrivateOramStagedPointIdV1,
) -> Result<(), PrivateOramStagingError> {
    match point_id {
        PrivateOramStagedPointIdV1::Numeric { value } => {
            encoder.push_u8(POINT_ID_NUMERIC_TAG)?;
            encoder.push_u64(*value)
        }
        PrivateOramStagedPointIdV1::Uuid { value } => {
            let canonical = private_oram_staged_point_id_canonical_string(point_id)?;
            encoder.push_u8(POINT_ID_UUID_TAG)?;
            debug_assert_eq!(&canonical, value);
            encoder.push_string(&canonical)
        }
    }
}

fn decode_point_id(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<PrivateOramStagedPointIdV1, PrivateOramStagingError> {
    let point_id = match decoder.read_u8()? {
        POINT_ID_NUMERIC_TAG => PrivateOramStagedPointIdV1::Numeric {
            value: decoder.read_u64()?,
        },
        POINT_ID_UUID_TAG => PrivateOramStagedPointIdV1::Uuid {
            value: decoder.read_string(36, "point_id")?,
        },
        _ => {
            return Err(PrivateOramStagingError::MalformedEncoding("point_id_kind"));
        }
    };
    private_oram_staged_point_id_canonical_string(&point_id)?;
    Ok(point_id)
}

fn encode_vector(
    encoder: &mut CanonicalEncoder,
    vector: &PrivateOramStagedVectorV1,
    total_vector_values: &mut usize,
) -> Result<(), PrivateOramStagingError> {
    match vector {
        PrivateOramStagedVectorV1::Dense { values } => {
            validate_vector_value_count(values.len(), total_vector_values)?;
            encoder.push_u8(VECTOR_DENSE_TAG)?;
            encoder.push_len(values.len(), "dense_values")?;
            for value in values {
                encoder.push_u32(canonical_f32_bits(*value, "dense_values")?)?;
            }
        }
        PrivateOramStagedVectorV1::Sparse { indices, values } => {
            if indices.is_empty() || indices.len() != values.len() {
                return Err(PrivateOramStagingError::InvalidSparseVector);
            }
            validate_vector_value_count(values.len(), total_vector_values)?;
            let mut entries = Vec::new();
            entries
                .try_reserve_exact(indices.len())
                .map_err(|_| PrivateOramStagingError::AllocationFailed)?;
            entries.extend(indices.iter().copied().zip(values.iter().copied()));
            entries.sort_unstable_by_key(|entry| entry.0);
            if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(PrivateOramStagingError::DuplicateSparseIndex);
            }
            encoder.push_u8(VECTOR_SPARSE_TAG)?;
            encoder.push_len(entries.len(), "sparse_values")?;
            for (index, value) in entries {
                encoder.push_u32(index)?;
                encoder.push_u32(canonical_f32_bits(value, "sparse_values")?)?;
            }
        }
        PrivateOramStagedVectorV1::MultiDense { vectors } => {
            if vectors.is_empty()
                || vectors.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_MULTI_DENSE_VECTORS
            {
                return Err(PrivateOramStagingError::InvalidMultiDenseVector);
            }
            let dimension = vectors[0].len();
            if dimension == 0
                || dimension > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_DIMENSION
                || vectors.iter().any(|vector| vector.len() != dimension)
            {
                return Err(PrivateOramStagingError::InvalidMultiDenseVector);
            }
            let value_count = vectors
                .len()
                .checked_mul(dimension)
                .ok_or(PrivateOramStagingError::LimitExceeded("multi_dense_values"))?;
            validate_vector_value_count(value_count, total_vector_values)?;
            encoder.push_u8(VECTOR_MULTI_DENSE_TAG)?;
            encoder.push_len(vectors.len(), "multi_dense_vectors")?;
            encoder.push_len(dimension, "multi_dense_dimension")?;
            for dense in vectors {
                for value in dense {
                    encoder.push_u32(canonical_f32_bits(*value, "multi_dense_values")?)?;
                }
            }
        }
    }
    Ok(())
}

fn decode_vector(
    decoder: &mut CanonicalDecoder<'_>,
    total_vector_values: &mut usize,
) -> Result<PrivateOramStagedVectorV1, PrivateOramStagingError> {
    match decoder.read_u8()? {
        VECTOR_DENSE_TAG => {
            let count = decoder.read_bounded_count(
                PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_DIMENSION,
                "dense_values",
            )?;
            if count == 0 || count > decoder.remaining() / 4 {
                return Err(PrivateOramStagingError::LimitExceeded("dense_values"));
            }
            validate_vector_value_count(count, total_vector_values)?;
            let mut values = try_vec_with_capacity(count)?;
            for _ in 0..count {
                values.push(decoder.read_f32("dense_values")?);
            }
            Ok(PrivateOramStagedVectorV1::Dense { values })
        }
        VECTOR_SPARSE_TAG => {
            let count = decoder.read_bounded_count(
                PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_DIMENSION,
                "sparse_values",
            )?;
            if count == 0 || count > decoder.remaining() / 8 {
                return Err(PrivateOramStagingError::InvalidSparseVector);
            }
            validate_vector_value_count(count, total_vector_values)?;
            let mut indices = try_vec_with_capacity(count)?;
            let mut values = try_vec_with_capacity(count)?;
            let mut previous_index = None;
            for _ in 0..count {
                let index = decoder.read_u32()?;
                if previous_index.is_some_and(|previous| previous >= index) {
                    return Err(PrivateOramStagingError::NonCanonicalEncoding);
                }
                previous_index = Some(index);
                indices.push(index);
                values.push(decoder.read_f32("sparse_values")?);
            }
            Ok(PrivateOramStagedVectorV1::Sparse { indices, values })
        }
        VECTOR_MULTI_DENSE_TAG => {
            let vector_count = decoder.read_bounded_count(
                PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_MULTI_DENSE_VECTORS,
                "multi_dense_vectors",
            )?;
            let dimension = decoder.read_bounded_count(
                PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_DIMENSION,
                "multi_dense_dimension",
            )?;
            if vector_count == 0 || dimension == 0 {
                return Err(PrivateOramStagingError::InvalidMultiDenseVector);
            }
            let value_count = vector_count
                .checked_mul(dimension)
                .ok_or(PrivateOramStagingError::LimitExceeded("multi_dense_values"))?;
            if value_count > decoder.remaining() / 4 {
                return Err(PrivateOramStagingError::InvalidMultiDenseVector);
            }
            validate_vector_value_count(value_count, total_vector_values)?;
            let mut vectors = try_vec_with_capacity(vector_count)?;
            for _ in 0..vector_count {
                let mut values = try_vec_with_capacity(dimension)?;
                for _ in 0..dimension {
                    values.push(decoder.read_f32("multi_dense_values")?);
                }
                vectors.push(values);
            }
            Ok(PrivateOramStagedVectorV1::MultiDense { vectors })
        }
        _ => Err(PrivateOramStagingError::MalformedEncoding("vector_kind")),
    }
}

fn encode_json_value(
    encoder: &mut CanonicalEncoder,
    value: &Value,
    depth: usize,
    context: &mut JsonEncodeContext,
) -> Result<(), PrivateOramStagingError> {
    validate_json_position(depth, &mut context.value_count)?;
    match value {
        Value::Null => encoder.push_u8(JSON_NULL_TAG),
        Value::Bool(value) => {
            encoder.push_u8(JSON_BOOL_TAG)?;
            encoder.push_u8(u8::from(*value))
        }
        Value::Number(value) => encode_json_number(encoder, value),
        Value::String(value) => {
            validate_json_string(value, "json_string")?;
            encoder.push_u8(JSON_STRING_TAG)?;
            encoder.push_string(value)
        }
        Value::Array(values) => {
            if values.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_CONTAINER_ENTRIES {
                return Err(PrivateOramStagingError::LimitExceeded("json_array"));
            }
            encoder.push_u8(JSON_ARRAY_TAG)?;
            encoder.push_len(values.len(), "json_array")?;
            let child_depth = depth
                .checked_add(1)
                .ok_or(PrivateOramStagingError::LimitExceeded("json_depth"))?;
            for value in values {
                encode_json_value(encoder, value, child_depth, context)?;
            }
            Ok(())
        }
        Value::Object(values) => encode_json_object(encoder, values, depth, context),
    }
}

fn encode_json_object(
    encoder: &mut CanonicalEncoder,
    values: &Map<String, Value>,
    depth: usize,
    context: &mut JsonEncodeContext,
) -> Result<(), PrivateOramStagingError> {
    if values.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_CONTAINER_ENTRIES {
        return Err(PrivateOramStagingError::LimitExceeded("json_object"));
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(values.len())
        .map_err(|_| PrivateOramStagingError::AllocationFailed)?;
    entries.extend(values.iter());
    entries.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    encoder.push_u8(JSON_OBJECT_TAG)?;
    encoder.push_len(entries.len(), "json_object")?;
    let child_depth = depth
        .checked_add(1)
        .ok_or(PrivateOramStagingError::LimitExceeded("json_depth"))?;
    for (key, value) in entries {
        validate_json_string(key, "json_object_key")?;
        encoder.push_string(key)?;
        encode_json_value(encoder, value, child_depth, context)?;
    }
    Ok(())
}

fn decode_json_value(
    decoder: &mut CanonicalDecoder<'_>,
    depth: usize,
    context: &mut JsonDecodeContext,
) -> Result<Value, PrivateOramStagingError> {
    validate_json_position(depth, &mut context.value_count)?;
    match decoder.read_u8()? {
        JSON_NULL_TAG => Ok(Value::Null),
        JSON_BOOL_TAG => match decoder.read_u8()? {
            0 => Ok(Value::Bool(false)),
            1 => Ok(Value::Bool(true)),
            _ => Err(PrivateOramStagingError::MalformedEncoding("json_bool")),
        },
        JSON_I64_TAG => Ok(Value::Number(Number::from(decoder.read_i64()?))),
        JSON_U64_TAG => Ok(Value::Number(Number::from(decoder.read_u64()?))),
        JSON_F64_TAG => {
            let value = f64::from_bits(decoder.read_u64()?);
            if !value.is_finite() {
                return Err(PrivateOramStagingError::NonFiniteNumber("json_f64"));
            }
            Number::from_f64(value)
                .map(Value::Number)
                .ok_or(PrivateOramStagingError::NonFiniteNumber("json_f64"))
        }
        JSON_STRING_TAG => {
            let value = decoder.read_string(
                PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_STRING_BYTES,
                "json_string",
            )?;
            validate_json_string(&value, "json_string")?;
            Ok(Value::String(value))
        }
        JSON_ARRAY_TAG => {
            let count = decoder.read_bounded_count(
                PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_CONTAINER_ENTRIES,
                "json_array",
            )?;
            if count > decoder.remaining() {
                return Err(PrivateOramStagingError::LimitExceeded("json_array"));
            }
            let child_depth = depth
                .checked_add(1)
                .ok_or(PrivateOramStagingError::LimitExceeded("json_depth"))?;
            let mut values = try_vec_with_capacity(count)?;
            for _ in 0..count {
                values.push(decode_json_value(decoder, child_depth, context)?);
            }
            Ok(Value::Array(values))
        }
        JSON_OBJECT_TAG => {
            let count = decoder.read_bounded_count(
                PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_CONTAINER_ENTRIES,
                "json_object",
            )?;
            if count > decoder.remaining() {
                return Err(PrivateOramStagingError::LimitExceeded("json_object"));
            }
            let child_depth = depth
                .checked_add(1)
                .ok_or(PrivateOramStagingError::LimitExceeded("json_depth"))?;
            let mut values = Map::new();
            let mut previous_key: Option<String> = None;
            for _ in 0..count {
                let key = decoder.read_string(
                    PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_STRING_BYTES,
                    "json_object_key",
                )?;
                validate_json_string(&key, "json_object_key")?;
                if previous_key
                    .as_ref()
                    .is_some_and(|previous| previous.as_bytes() >= key.as_bytes())
                {
                    return Err(PrivateOramStagingError::NonCanonicalEncoding);
                }
                previous_key = Some(key.clone());
                let value = decode_json_value(decoder, child_depth, context)?;
                if values.insert(key, value).is_some() {
                    return Err(PrivateOramStagingError::NonCanonicalEncoding);
                }
            }
            Ok(Value::Object(values))
        }
        _ => Err(PrivateOramStagingError::MalformedEncoding("json_kind")),
    }
}

fn encode_json_number(
    encoder: &mut CanonicalEncoder,
    value: &Number,
) -> Result<(), PrivateOramStagingError> {
    if value.is_u64() {
        encoder.push_u8(JSON_U64_TAG)?;
        encoder.push_u64(
            value
                .as_u64()
                .ok_or(PrivateOramStagingError::InvalidField("json_number"))?,
        )
    } else if value.is_i64() {
        encoder.push_u8(JSON_I64_TAG)?;
        encoder.push_i64(
            value
                .as_i64()
                .ok_or(PrivateOramStagingError::InvalidField("json_number"))?,
        )
    } else {
        let value = value
            .as_f64()
            .ok_or(PrivateOramStagingError::InvalidField("json_number"))?;
        if !value.is_finite() {
            return Err(PrivateOramStagingError::NonFiniteNumber("json_f64"));
        }
        encoder.push_u8(JSON_F64_TAG)?;
        encoder.push_u64(if value == 0.0 { 0 } else { value.to_bits() })
    }
}

fn validate_resource_id(value: &str, field: &'static str) -> Result<(), PrivateOramStagingError> {
    if value.is_empty()
        || value.len() > PRIVATE_ORAM_RESOURCE_ID_MAX_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(PrivateOramStagingError::InvalidField(field));
    }
    Ok(())
}

fn validate_vector_name(value: &str) -> Result<(), PrivateOramStagingError> {
    if value.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_NAME_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(PrivateOramStagingError::InvalidField("vector_name"));
    }
    Ok(())
}

fn validate_shard_keyword(value: &str) -> Result<(), PrivateOramStagingError> {
    if value.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_SHARD_KEYWORD_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(PrivateOramStagingError::InvalidField("shard_key"));
    }
    Ok(())
}

fn validate_json_string(value: &str, field: &'static str) -> Result<(), PrivateOramStagingError> {
    if value.len() > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_STRING_BYTES {
        return Err(PrivateOramStagingError::LimitExceeded(field));
    }
    Ok(())
}

fn validate_json_position(
    depth: usize,
    value_count: &mut usize,
) -> Result<(), PrivateOramStagingError> {
    if depth > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_DEPTH {
        return Err(PrivateOramStagingError::LimitExceeded("json_depth"));
    }
    *value_count = value_count
        .checked_add(1)
        .ok_or(PrivateOramStagingError::LimitExceeded("json_values"))?;
    if *value_count > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_VALUES {
        return Err(PrivateOramStagingError::LimitExceeded("json_values"));
    }
    Ok(())
}

fn validate_vector_value_count(
    count: usize,
    total: &mut usize,
) -> Result<(), PrivateOramStagingError> {
    if count == 0 || count > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_DIMENSION {
        return Err(PrivateOramStagingError::LimitExceeded("vector_values"));
    }
    *total = total
        .checked_add(count)
        .ok_or(PrivateOramStagingError::LimitExceeded("vector_values"))?;
    if *total > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_TOTAL_VECTOR_VALUES {
        return Err(PrivateOramStagingError::LimitExceeded("vector_values"));
    }
    Ok(())
}

fn canonical_f32_bits(value: f32, field: &'static str) -> Result<u32, PrivateOramStagingError> {
    if !value.is_finite() {
        return Err(PrivateOramStagingError::NonFiniteNumber(field));
    }
    Ok(if value == 0.0 { 0 } else { value.to_bits() })
}

fn decode_digest(value: &str, field: &'static str) -> Result<[u8; 32], PrivateOramStagingError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateOramStagingError::MalformedDigest(field));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramStagingError::MalformedDigest(field))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| PrivateOramStagingError::MalformedDigest(field))?;
    if BASE64URL_NOPAD.encode(&bytes) != value {
        return Err(PrivateOramStagingError::MalformedDigest(field));
    }
    Ok(bytes)
}

fn require_equal(
    frame_value: &str,
    mutation_value: &str,
    field: &'static str,
) -> Result<(), PrivateOramStagingError> {
    if frame_value != mutation_value {
        return Err(PrivateOramStagingError::MutationBindingMismatch(field));
    }
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(Sha256::digest(bytes).as_ref())
}

fn try_vec_with_capacity<T>(capacity: usize) -> Result<Vec<T>, PrivateOramStagingError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| PrivateOramStagingError::AllocationFailed)?;
    Ok(values)
}

struct JsonEncodeContext {
    value_count: usize,
}

struct JsonDecodeContext {
    value_count: usize,
}

struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn push_domain(&mut self, domain: &str) -> Result<(), PrivateOramStagingError> {
        let len = u32::try_from(domain.len())
            .map_err(|_| PrivateOramStagingError::LimitExceeded("domain"))?;
        self.push_u32(len)?;
        self.push_bytes(domain.as_bytes())
    }

    fn push_string(&mut self, value: &str) -> Result<(), PrivateOramStagingError> {
        let len = u64::try_from(value.len())
            .map_err(|_| PrivateOramStagingError::LimitExceeded("string"))?;
        self.push_u64(len)?;
        self.push_bytes(value.as_bytes())
    }

    fn push_digest(
        &mut self,
        value: &str,
        field: &'static str,
    ) -> Result<(), PrivateOramStagingError> {
        self.push_bytes(&decode_digest(value, field)?)
    }

    fn push_len(&mut self, len: usize, field: &'static str) -> Result<(), PrivateOramStagingError> {
        self.push_u32(
            u32::try_from(len).map_err(|_| PrivateOramStagingError::LimitExceeded(field))?,
        )
    }

    fn push_u8(&mut self, value: u8) -> Result<(), PrivateOramStagingError> {
        self.push_bytes(&[value])
    }

    fn push_u16(&mut self, value: u16) -> Result<(), PrivateOramStagingError> {
        self.push_bytes(&value.to_be_bytes())
    }

    fn push_u32(&mut self, value: u32) -> Result<(), PrivateOramStagingError> {
        self.push_bytes(&value.to_be_bytes())
    }

    fn push_u64(&mut self, value: u64) -> Result<(), PrivateOramStagingError> {
        self.push_bytes(&value.to_be_bytes())
    }

    fn push_i64(&mut self, value: i64) -> Result<(), PrivateOramStagingError> {
        self.push_bytes(&value.to_be_bytes())
    }

    fn push_bytes(&mut self, value: &[u8]) -> Result<(), PrivateOramStagingError> {
        let new_len = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(PrivateOramStagingError::FrameTooLarge)?;
        if new_len > PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES {
            return Err(PrivateOramStagingError::FrameTooLarge);
        }
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| PrivateOramStagingError::AllocationFailed)?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}

struct CanonicalDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> CanonicalDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn is_finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    fn read_domain(&mut self, expected: &str) -> Result<(), PrivateOramStagingError> {
        let len = usize::try_from(self.read_u32()?)
            .map_err(|_| PrivateOramStagingError::MalformedEncoding("domain"))?;
        if len != expected.len() || self.read_exact(len)? != expected.as_bytes() {
            return Err(PrivateOramStagingError::MalformedEncoding("domain"));
        }
        Ok(())
    }

    fn read_string(
        &mut self,
        max_len: usize,
        field: &'static str,
    ) -> Result<String, PrivateOramStagingError> {
        let len = usize::try_from(self.read_u64()?)
            .map_err(|_| PrivateOramStagingError::LimitExceeded(field))?;
        if len > max_len {
            return Err(PrivateOramStagingError::LimitExceeded(field));
        }
        let bytes = self.read_exact(len)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| PrivateOramStagingError::MalformedEncoding(field))?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(len)
            .map_err(|_| PrivateOramStagingError::AllocationFailed)?;
        owned.push_str(value);
        Ok(owned)
    }

    fn read_digest(&mut self) -> Result<String, PrivateOramStagingError> {
        Ok(BASE64URL_NOPAD.encode(self.read_exact(32)?))
    }

    fn read_bounded_count(
        &mut self,
        max: usize,
        field: &'static str,
    ) -> Result<usize, PrivateOramStagingError> {
        let count = usize::try_from(self.read_u32()?)
            .map_err(|_| PrivateOramStagingError::LimitExceeded(field))?;
        if count > max {
            return Err(PrivateOramStagingError::LimitExceeded(field));
        }
        Ok(count)
    }

    fn read_f32(&mut self, field: &'static str) -> Result<f32, PrivateOramStagingError> {
        let bits = self.read_u32()?;
        let value = f32::from_bits(bits);
        let canonical = canonical_f32_bits(value, field)?;
        if bits != canonical {
            return Err(PrivateOramStagingError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, PrivateOramStagingError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, PrivateOramStagingError> {
        let bytes: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| PrivateOramStagingError::UnexpectedEnd)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, PrivateOramStagingError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| PrivateOramStagingError::UnexpectedEnd)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, PrivateOramStagingError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| PrivateOramStagingError::UnexpectedEnd)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_i64(&mut self) -> Result<i64, PrivateOramStagingError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| PrivateOramStagingError::UnexpectedEnd)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], PrivateOramStagingError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(PrivateOramStagingError::UnexpectedEnd)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(PrivateOramStagingError::UnexpectedEnd)?;
        self.cursor = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
    use serde_json::{Map, Number, Value};

    use super::*;
    use crate::private_oram_mutation::{
        PRIVATE_ORAM_SIGNED_STATE_V2_VERSION, PrivateOramAppendMutationBundleV1,
        PrivateOramAppendMutationV1, PrivateOramIndexKindV2, PrivateOramIndexStateV2,
        PrivateOramPointOperationKindV1, PrivateOramSignature, PrivateOramSignedStateBundleV2,
        PrivateOramSignedStateV2, PrivateOramVisiblePointRecordV1,
        private_oram_signed_state_v2_digest, private_oram_visible_point_record_v1_digest,
    };

    fn digest(seed: u8) -> String {
        BASE64URL_NOPAD.encode(&[seed; 32])
    }

    fn signature() -> PrivateOramSignature {
        PrivateOramSignature {
            alg: "ed25519".to_string(),
            key_id: "owner-key".to_string(),
            sig: BASE64URL_NOPAD.encode(&[91; 64]),
        }
    }

    fn payload() -> Map<String, Value> {
        let mut nested = Map::new();
        nested.insert("z".to_string(), Value::Null);
        nested.insert("a".to_string(), Value::Bool(true));

        let mut payload = Map::new();
        payload.insert(
            "secret".to_string(),
            Value::String("payload-secret".to_string()),
        );
        payload.insert("negative".to_string(), Value::Number(Number::from(-7)));
        payload.insert("positive".to_string(), Value::Number(Number::from(9_u64)));
        payload.insert(
            "float".to_string(),
            Value::Number(Number::from_f64(-0.0).unwrap()),
        );
        payload.insert("nested".to_string(), Value::Object(nested));
        payload
    }

    fn sample_frame() -> PrivateOramStagedInsertFrameV1 {
        PrivateOramStagedInsertFrameV1 {
            version: PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION,
            collection_id: "secret-collection".to_string(),
            manifest_digest: digest(1),
            mutation_id: digest(2),
            old_state_digest: digest(3),
            new_state_digest: digest(4),
            layout_generation: 7,
            layout_digest: digest(6),
            old_state_sequence: 41,
            new_state_sequence: 42,
            writer_lease_digest: digest(5),
            writer_fence: 11,
            target_shard_ids: vec![13, 21],
            shard_key: Some(PrivateOramStagedShardKeyV1::Keyword {
                value: "secret-shard-key".to_string(),
            }),
            point: PrivateOramStagedPointV1 {
                id: PrivateOramStagedPointIdV1::Uuid {
                    value: "123e4567-e89b-12d3-a456-426614174000".to_string(),
                },
                vectors: vec![
                    PrivateOramStagedNamedVectorV1 {
                        name: "z-vector".to_string(),
                        vector: PrivateOramStagedVectorV1::Dense {
                            values: vec![-0.0, 1.5],
                        },
                    },
                    PrivateOramStagedNamedVectorV1 {
                        name: "a-vector".to_string(),
                        vector: PrivateOramStagedVectorV1::Sparse {
                            indices: vec![9, 2],
                            values: vec![4.0, -0.0],
                        },
                    },
                    PrivateOramStagedNamedVectorV1 {
                        name: "m-vector".to_string(),
                        vector: PrivateOramStagedVectorV1::MultiDense {
                            vectors: vec![vec![1.0, 2.0], vec![3.0, 4.0]],
                        },
                    },
                ],
                payload: Some(payload()),
            },
        }
    }

    fn known_answer_frame() -> PrivateOramStagedInsertFrameV1 {
        let mut payload = Map::new();
        payload.insert("a".to_string(), Value::Null);
        PrivateOramStagedInsertFrameV1 {
            version: PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION,
            collection_id: "c".to_string(),
            manifest_digest: digest(1),
            mutation_id: digest(2),
            old_state_digest: digest(3),
            new_state_digest: digest(4),
            layout_generation: 7,
            layout_digest: digest(6),
            old_state_sequence: 0,
            new_state_sequence: 1,
            writer_lease_digest: digest(5),
            writer_fence: 9,
            target_shard_ids: vec![11, 12],
            shard_key: Some(PrivateOramStagedShardKeyV1::Number { value: 13 }),
            point: PrivateOramStagedPointV1 {
                id: PrivateOramStagedPointIdV1::Numeric { value: 17 },
                vectors: vec![PrivateOramStagedNamedVectorV1 {
                    name: "v".to_string(),
                    vector: PrivateOramStagedVectorV1::Dense {
                        values: vec![1.0, -0.0],
                    },
                }],
                payload: Some(payload),
            },
        }
    }

    fn state_bundle(
        frame: &PrivateOramStagedInsertFrameV1,
        state_sequence: u64,
        last_mutation_id: Option<String>,
        seed: u8,
    ) -> PrivateOramSignedStateBundleV2 {
        PrivateOramSignedStateBundleV2 {
            state: PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: frame.collection_id.clone(),
                manifest_digest: frame.manifest_digest.clone(),
                layout_generation: frame.layout_generation,
                layout_digest: frame.layout_digest.clone(),
                state_sequence,
                indexes: vec![PrivateOramIndexStateV2 {
                    kind: PrivateOramIndexKindV2::Hnsw,
                    index_name: "text".to_string(),
                    index_epoch: state_sequence,
                    root_hash: digest(seed.wrapping_add(1)),
                    logical_count: state_sequence,
                    dummy_count: 64_u64.saturating_sub(state_sequence),
                    last_writeback_digest: digest(seed.wrapping_add(2)),
                }],
                client_state_digest: digest(seed.wrapping_add(3)),
                last_mutation_id,
                owner_signing_key_id: "owner-key".to_string(),
                signed_at_unix: 1_700_000_000 + state_sequence,
            },
            signature: signature(),
        }
    }

    fn bound_frame_and_mutation() -> (
        PrivateOramStagedInsertFrameV1,
        PrivateOramAppendMutationBundleV1,
    ) {
        let mut frame = known_answer_frame();
        let old_state = state_bundle(&frame, 0, None, 20);
        let new_state = state_bundle(&frame, 1, Some(frame.mutation_id.clone()), 30);
        frame.old_state_digest = private_oram_signed_state_v2_digest(&old_state.state).unwrap();
        frame.new_state_digest = private_oram_signed_state_v2_digest(&new_state.state).unwrap();

        let staged_insert_sha256 = private_oram_staged_insert_frame_v1_digest(&frame).unwrap();
        let point_id = private_oram_staged_point_id_canonical_string(&frame.point.id).unwrap();
        let point_operation_digest = private_oram_visible_point_record_v1_digest(
            &frame.collection_id,
            &frame.manifest_digest,
            &frame.mutation_id,
            PrivateOramVisiblePointRecordV1 {
                point_id: &point_id,
                staged_insert_sha256: &staged_insert_sha256,
            },
        )
        .unwrap();

        let bundle = PrivateOramAppendMutationBundleV1 {
            mutation: PrivateOramAppendMutationV1 {
                version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
                mutation_id: frame.mutation_id.clone(),
                collection_id: frame.collection_id.clone(),
                manifest_digest: frame.manifest_digest.clone(),
                layout_generation: frame.layout_generation,
                writer_lease_digest: frame.writer_lease_digest.clone(),
                writer_fence: frame.writer_fence,
                issued_at_unix: 1_700_000_000,
                expires_at_unix: 1_700_000_600,
                old_state,
                new_state,
                point_operation_kind: PrivateOramPointOperationKindV1::VisiblePointRecord,
                point_operation_digest,
                writebacks: Vec::new(),
                owner_signing_key_id: "owner-key".to_string(),
            },
            signature: signature(),
        };
        (frame, bundle)
    }

    #[test]
    fn canonical_encoding_sorts_vectors_and_sparse_indices_and_normalizes_zero() {
        let frame = sample_frame();
        let encoded = encode_private_oram_staged_insert_frame_v1(&frame).unwrap();
        let decoded = decode_private_oram_staged_insert_frame_v1(&encoded).unwrap();

        let names: Vec<&str> = decoded
            .point
            .vectors
            .iter()
            .map(|vector| vector.name.as_str())
            .collect();
        assert_eq!(names, vec!["a-vector", "m-vector", "z-vector"]);
        let PrivateOramStagedVectorV1::Sparse { indices, values } =
            &decoded.point.vectors[0].vector
        else {
            panic!("expected sparse vector");
        };
        assert_eq!(indices, &vec![2, 9]);
        assert_eq!(values[0].to_bits(), 0.0_f32.to_bits());
        let PrivateOramStagedVectorV1::Dense { values } = &decoded.point.vectors[2].vector else {
            panic!("expected dense vector");
        };
        assert_eq!(values[0].to_bits(), 0.0_f32.to_bits());

        let mut reordered = frame.clone();
        reordered.point.vectors.reverse();
        let PrivateOramStagedVectorV1::Sparse { indices, values } = &mut reordered
            .point
            .vectors
            .iter_mut()
            .find(|vector| vector.name == "a-vector")
            .unwrap()
            .vector
        else {
            panic!("expected sparse vector");
        };
        indices.reverse();
        values.reverse();
        assert_eq!(
            encoded,
            encode_private_oram_staged_insert_frame_v1(&reordered).unwrap()
        );
    }

    #[test]
    fn canonical_bytes_and_digest_match_known_answer() {
        let frame = known_answer_frame();
        let encoded = encode_private_oram_staged_insert_frame_v1(&frame).unwrap();
        assert_eq!(
            HEXLOWER.encode(&encoded),
            "0000002e716472616e742d7365632f707269766174652d6f72616d2d7374616765642d696e736572742d6672616d652f763100010000000000000001630101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404000000000000000706060606060606060606060606060606060606060606060606060606060606060000000000000000000000000000000105050505050505050505050505050505050505050505050505050505050505050000000000000009000000020000000b0000000c0102000000000000000d0100000000000000110000000100000000000000017601000000023f8000000000000001070000000100000000000000016100"
        );
        assert_eq!(
            private_oram_staged_insert_frame_v1_digest(&frame).unwrap(),
            "fveBL9G6uk4GFHv2MqgxCeVuPHSssmU91or_dtp-auQ"
        );
    }

    #[test]
    fn strict_decode_roundtrips_canonical_frame() {
        let encoded = encode_private_oram_staged_insert_frame_v1(&sample_frame()).unwrap();
        let decoded = decode_private_oram_staged_insert_frame_v1(&encoded).unwrap();
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&decoded).unwrap(),
            encoded
        );
    }

    #[test]
    fn strict_serde_rejects_unknown_fields() {
        let mut value = serde_json::to_value(known_answer_frame()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), Value::Bool(true));
        assert!(serde_json::from_value::<PrivateOramStagedInsertFrameV1>(value).is_err());

        let point_id = serde_json::json!({
            "kind": "numeric",
            "value": 7,
            "unexpected": true
        });
        assert!(serde_json::from_value::<PrivateOramStagedPointIdV1>(point_id).is_err());
    }

    #[test]
    fn decode_rejects_malformed_trailing_oversized_and_tampered_frames() {
        let encoded = encode_private_oram_staged_insert_frame_v1(&known_answer_frame()).unwrap();

        assert_eq!(
            decode_private_oram_staged_insert_frame_v1(&encoded[..encoded.len() - 1]),
            Err(PrivateOramStagingError::UnexpectedEnd)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_private_oram_staged_insert_frame_v1(&trailing),
            Err(PrivateOramStagingError::TrailingBytes)
        );
        let oversized = vec![0; PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_BYTES + 1];
        assert_eq!(
            decode_private_oram_staged_insert_frame_v1(&oversized),
            Err(PrivateOramStagingError::FrameTooLarge)
        );
        let mut tampered = encoded;
        tampered[4] ^= 1;
        assert_eq!(
            decode_private_oram_staged_insert_frame_v1(&tampered),
            Err(PrivateOramStagingError::MalformedEncoding("domain"))
        );
    }

    #[test]
    fn encode_rejects_invalid_header_and_point_identity() {
        let mut frame = known_answer_frame();
        frame.layout_generation = 0;
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::InvalidField("layout_generation"))
        );

        let mut frame = known_answer_frame();
        frame.writer_fence = 0;
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::InvalidField("writer_fence"))
        );

        let mut frame = known_answer_frame();
        frame.new_state_digest = frame.old_state_digest.clone();
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::InvalidField("state_digests"))
        );

        let mut frame = known_answer_frame();
        frame.manifest_digest = "not-base64url".to_string();
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::MalformedDigest("manifest_digest"))
        );

        let mut frame = known_answer_frame();
        frame.point.id = PrivateOramStagedPointIdV1::Uuid {
            value: "123E4567-E89B-12D3-A456-426614174000".to_string(),
        };
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::NonCanonicalPointUuid)
        );
    }

    #[test]
    fn target_shards_are_nonempty_strictly_increasing_and_vectors_may_be_empty() {
        let mut frame = known_answer_frame();
        frame.point.vectors.clear();
        let encoded = encode_private_oram_staged_insert_frame_v1(&frame).unwrap();
        let decoded = decode_private_oram_staged_insert_frame_v1(&encoded).unwrap();
        assert!(decoded.point.vectors.is_empty());
        assert_eq!(decoded.target_shard_ids, vec![11, 12]);

        let mut empty_targets = known_answer_frame();
        empty_targets.target_shard_ids.clear();
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&empty_targets),
            Err(PrivateOramStagingError::InvalidField("target_shard_ids"))
        );

        let mut duplicate_targets = known_answer_frame();
        duplicate_targets.target_shard_ids = vec![11, 11];
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&duplicate_targets),
            Err(PrivateOramStagingError::InvalidField("target_shard_ids"))
        );

        let mut unordered_targets = known_answer_frame();
        unordered_targets.target_shard_ids = vec![12, 11];
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&unordered_targets),
            Err(PrivateOramStagingError::InvalidField("target_shard_ids"))
        );
    }

    #[test]
    fn encode_rejects_vector_duplicates_nonfinite_values_and_bad_dimensions() {
        let mut frame = known_answer_frame();
        frame.point.vectors.push(frame.point.vectors[0].clone());
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::DuplicateVectorName)
        );

        let mut frame = known_answer_frame();
        frame.point.vectors[0].vector = PrivateOramStagedVectorV1::Sparse {
            indices: vec![2, 2],
            values: vec![1.0, 2.0],
        };
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::DuplicateSparseIndex)
        );

        let mut frame = known_answer_frame();
        frame.point.vectors[0].vector = PrivateOramStagedVectorV1::Dense {
            values: vec![f32::INFINITY],
        };
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::NonFiniteNumber("dense_values"))
        );

        let mut frame = known_answer_frame();
        frame.point.vectors[0].vector = PrivateOramStagedVectorV1::MultiDense {
            vectors: vec![vec![1.0], vec![2.0, 3.0]],
        };
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::InvalidMultiDenseVector)
        );
    }

    #[test]
    fn encode_rejects_bounded_strings_and_json_depth() {
        let mut frame = known_answer_frame();
        frame.point.vectors[0].name =
            "x".repeat(PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_VECTOR_NAME_BYTES + 1);
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::InvalidField("vector_name"))
        );

        let mut nested = Value::Null;
        for _ in 0..=PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_MAX_JSON_DEPTH {
            nested = Value::Array(vec![nested]);
        }
        let mut payload = Map::new();
        payload.insert("deep".to_string(), nested);
        let mut frame = known_answer_frame();
        frame.point.payload = Some(payload);
        assert_eq!(
            encode_private_oram_staged_insert_frame_v1(&frame),
            Err(PrivateOramStagingError::LimitExceeded("json_depth"))
        );
    }

    #[test]
    fn canonical_point_id_helper_covers_numeric_and_uuid_ids() {
        assert_eq!(
            private_oram_staged_point_id_canonical_string(&PrivateOramStagedPointIdV1::Numeric {
                value: 42
            })
            .unwrap(),
            "42"
        );
        assert_eq!(
            private_oram_staged_point_id_canonical_string(&PrivateOramStagedPointIdV1::Uuid {
                value: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            })
            .unwrap(),
            "123e4567-e89b-12d3-a456-426614174000"
        );
    }

    #[test]
    fn mutation_validator_binds_exact_frame_and_visible_point_digest() {
        let (frame, bundle) = bound_frame_and_mutation();
        validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(&frame, &bundle)
            .unwrap();

        let mut mismatch = frame.clone();
        mismatch.collection_id = "other-collection".to_string();
        assert_eq!(
            validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
                &mismatch, &bundle
            ),
            Err(PrivateOramStagingError::MutationBindingMismatch(
                "collection_id"
            ))
        );

        let mut mismatch = frame.clone();
        mismatch.writer_lease_digest = digest(99);
        assert_eq!(
            validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
                &mismatch, &bundle
            ),
            Err(PrivateOramStagingError::MutationBindingMismatch(
                "writer_lease_digest"
            ))
        );

        let mut mismatch = frame.clone();
        mismatch.old_state_digest = digest(98);
        assert_eq!(
            validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
                &mismatch, &bundle
            ),
            Err(PrivateOramStagingError::MutationBindingMismatch(
                "old_state_digest"
            ))
        );

        let mut mismatch = frame.clone();
        mismatch.layout_digest = digest(97);
        assert_eq!(
            validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
                &mismatch, &bundle
            ),
            Err(PrivateOramStagingError::MutationBindingMismatch(
                "layout_digest"
            ))
        );

        let mut mismatch = frame.clone();
        mismatch.old_state_sequence = 2;
        mismatch.new_state_sequence = 3;
        assert_eq!(
            validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
                &mismatch, &bundle
            ),
            Err(PrivateOramStagingError::MutationBindingMismatch(
                "old_state_sequence"
            ))
        );

        let mut rerouted = frame.clone();
        rerouted.target_shard_ids = vec![11, 13];
        assert_eq!(
            validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
                &rerouted, &bundle
            ),
            Err(PrivateOramStagingError::PointOperationDigestMismatch)
        );

        let mut changed_point = frame.clone();
        changed_point.point.id = PrivateOramStagedPointIdV1::Numeric { value: 18 };
        assert_eq!(
            validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(
                &changed_point,
                &bundle
            ),
            Err(PrivateOramStagingError::PointOperationDigestMismatch)
        );
    }

    #[test]
    fn mutation_validator_rejects_no_server_record_and_digest_mismatch() {
        let (frame, mut bundle) = bound_frame_and_mutation();
        bundle.mutation.point_operation_kind = PrivateOramPointOperationKindV1::NoServerPointRecord;
        assert_eq!(
            validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(&frame, &bundle),
            Err(PrivateOramStagingError::VisiblePointRecordRequired)
        );

        bundle.mutation.point_operation_kind = PrivateOramPointOperationKindV1::VisiblePointRecord;
        bundle.mutation.point_operation_digest = digest(77);
        assert_eq!(
            validate_private_oram_staged_insert_frame_v1_against_mutation_bundle(&frame, &bundle),
            Err(PrivateOramStagingError::PointOperationDigestMismatch)
        );
    }

    #[test]
    fn debug_and_error_output_redacts_sensitive_content() {
        let frame = sample_frame();
        let debug = format!("{frame:?}");
        for secret in [
            frame.collection_id.as_str(),
            frame.manifest_digest.as_str(),
            "123e4567-e89b-12d3-a456-426614174000",
            "secret-shard-key",
            "payload-secret",
        ] {
            assert!(!debug.contains(secret));
        }

        let point_debug = format!("{:?}", frame.point.id);
        assert!(!point_debug.contains("123e4567-e89b-12d3-a456-426614174000"));
        let error = PrivateOramStagingError::MutationBindingMismatch("manifest_digest");
        let error_debug = format!("{error:?}");
        let error_display = error.to_string();
        assert!(!error_debug.contains(frame.manifest_digest.as_str()));
        assert!(!error_display.contains(frame.manifest_digest.as_str()));
    }
}
