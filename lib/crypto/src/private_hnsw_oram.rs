use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::aead::{EncryptionError, validate_resource_key_id};
use crate::control_plane::{PRIVATE_HNSW_ORAM_BINDING, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER};

pub const PRIVATE_HNSW_ORAM_MANIFEST_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-manifest-signature/v1";
pub const PRIVATE_HNSW_ORAM_COMMIT_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-commit-signature/v1";
pub const PRIVATE_HNSW_ORAM_READ_PATHS_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-read-paths-signature/v1";

const PRIVATE_HNSW_ORAM_SIGNATURE_ALGORITHM: &str = "ed25519";
const BASE64URL_NOPAD_8_BYTE_LEN: usize = 11;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;
const PRIVATE_HNSW_ORAM_MANIFEST_VERSION: u16 = 1;
const PRIVATE_HNSW_NODE_BLOCK_FIXED_BYTES: u64 = 133;
const PRIVATE_HNSW_NODE_BLOCK_F32_ELEMENT_BYTES: u64 = 4;
const PRIVATE_HNSW_NODE_BLOCK_NEIGHBOR_SLOT_BYTES: u64 = 33;
const PRIVATE_HNSW_ORAM_BUCKET_PLAINTEXT_HEADER_BYTES: usize = 4 + 2 + 4 + 4;
const PRIVATE_HNSW_ORAM_BUCKET_AEAD_OVERHEAD_BYTES: usize = 1 + 12 + 16;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PrivateHnswOramError {
    #[error("private HNSW ORAM manifest uses unsupported version")]
    UnsupportedManifestVersion(u16),
    #[error("private HNSW ORAM manifest provider is invalid")]
    InvalidProvider,
    #[error("private HNSW ORAM manifest binding is invalid")]
    InvalidBinding,
    #[error("private HNSW ORAM manifest field is invalid")]
    InvalidManifestField(&'static str),
    #[error("private HNSW ORAM manifest field does not match runtime context")]
    ManifestContextMismatch(&'static str),
    #[error("private HNSW ORAM manifest signature is missing")]
    MissingManifestSignature,
    #[error("private HNSW ORAM manifest signature uses unsupported algorithm")]
    UnsupportedSignatureAlgorithm(String),
    #[error("private HNSW ORAM manifest signature key id does not match runtime context")]
    SignatureKeyIdMismatch,
    #[error("private HNSW ORAM manifest signature is malformed")]
    MalformedSignature,
    #[error("private HNSW ORAM manifest signature verification failed")]
    InvalidManifestSignature,
    #[error("private HNSW ORAM commit signature verification failed")]
    InvalidCommitSignature,
    #[error("private HNSW ORAM commit must update at least one bucket")]
    EmptyCommit,
    #[error("private HNSW ORAM read_paths signature verification failed")]
    InvalidReadPathsSignature,
    #[error("private HNSW ORAM resource key id is invalid")]
    InvalidResourceKeyId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistanceKind {
    Cosine,
    Dot,
    Euclid,
    Manhattan,
}

impl DistanceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cosine => "cosine",
            Self::Dot => "dot",
            Self::Euclid => "euclid",
            Self::Manhattan => "manhattan",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultPrivacyMode {
    IdsVisible,
    PrivatePayloadOramRequired,
}

impl ResultPrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdsVisible => "ids_visible",
            Self::PrivatePayloadOramRequired => "private_payload_oram_required",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OramKind {
    PathOram,
}

impl OramKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PathOram => "path_oram",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswParams {
    pub m: u32,
    pub ef_construction: u32,
    pub max_layers: u32,
    pub fixed_neighbor_slots: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OramParams {
    pub kind: OramKind,
    pub bucket_size: u32,
    pub block_size_bytes: u32,
    pub tree_height: u32,
    pub path_batch_size: u32,
}

pub fn private_hnsw_oram_bucket_ciphertext_bytes(
    oram: &OramParams,
) -> Result<usize, PrivateHnswOramError> {
    let bucket_size = usize::try_from(oram.bucket_size)
        .map_err(|_| PrivateHnswOramError::InvalidManifestField("oram.bucket_size"))?;
    let block_size_bytes = usize::try_from(oram.block_size_bytes)
        .map_err(|_| PrivateHnswOramError::InvalidManifestField("oram.block_size_bytes"))?;
    let slot_bytes =
        1usize
            .checked_add(block_size_bytes)
            .ok_or(PrivateHnswOramError::InvalidManifestField(
                "oram.block_size_bytes",
            ))?;
    let bucket_payload_bytes =
        bucket_size
            .checked_mul(slot_bytes)
            .ok_or(PrivateHnswOramError::InvalidManifestField(
                "oram.bucket_size",
            ))?;
    let plaintext_bytes = PRIVATE_HNSW_ORAM_BUCKET_PLAINTEXT_HEADER_BYTES
        .checked_add(bucket_payload_bytes)
        .ok_or(PrivateHnswOramError::InvalidManifestField("oram"))?;
    PRIVATE_HNSW_ORAM_BUCKET_AEAD_OVERHEAD_BYTES
        .checked_add(plaintext_bytes)
        .ok_or(PrivateHnswOramError::InvalidManifestField("oram"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedBudgetParams {
    pub enabled: bool,
    pub upper_layer_steps: u32,
    pub base_layer_steps: u32,
    pub paths_per_round: u32,
    pub fixed_result_k: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramManifest {
    pub version: u16,
    pub provider: String,
    pub binding: String,
    pub collection_id: String,
    pub vector_name: String,
    pub key_id: String,
    pub rk_id: String,
    pub rk_epoch: u64,
    pub dim: u32,
    pub distance: DistanceKind,
    pub hnsw: PrivateHnswParams,
    pub oram: OramParams,
    pub fixed_budget: FixedBudgetParams,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub logical_node_count: u64,
    pub dummy_node_count: u64,
    pub result_privacy: ResultPrivacyMode,
    pub owner_signing_key_id: String,
    pub created_at_unix: u64,
}

impl Debug for PrivateHnswOramManifest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramManifest")
            .field("version", &self.version)
            .field("provider", &self.provider)
            .field("binding", &self.binding)
            .field("collection_id", &self.collection_id)
            .field("vector_name", &self.vector_name)
            .field("key_id", &self.key_id)
            .field("rk_id", &self.rk_id)
            .field("rk_epoch", &self.rk_epoch)
            .field("dim", &self.dim)
            .field("distance", &self.distance)
            .field("hnsw", &self.hnsw)
            .field("oram", &self.oram)
            .field("fixed_budget", &self.fixed_budget)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &self.bucket_count)
            .field("logical_node_count", &self.logical_node_count)
            .field("dummy_node_count", &self.dummy_node_count)
            .field("result_privacy", &self.result_privacy)
            .field("owner_signing_key_id", &self.owner_signing_key_id)
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramBucket {
    pub version: u16,
    pub bucket_id: u64,
    pub index_epoch: u64,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub bucket_commitment: String,
}

impl Debug for PrivateHnswOramBucket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramBucket")
            .field("version", &self.version)
            .field("bucket_id", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("ciphertext_sha256", &"[redacted]")
            .field("bucket_commitment", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateHnswOramSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramSignature")
            .field("alg", &self.alg)
            .field("key_id", &self.key_id)
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateHnswSignatureVerification<'a> {
    pub expected_key_id: &'a str,
    pub public_key: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateHnswManifestValidationContext<'a> {
    pub expected_collection_id: &'a str,
    pub expected_vector_name: &'a str,
    pub expected_key_id: &'a str,
    pub expected_rk_id: &'a str,
    pub min_rk_epoch: u64,
    pub max_rk_epoch: u64,
    pub expected_dim: u32,
    pub expected_distance: DistanceKind,
    pub signature_verification: PrivateHnswSignatureVerification<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateHnswEpoch {
    pub epoch: u64,
    pub root_hash: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswOramCommitBucketRef<'a> {
    pub bucket_id: u64,
    pub ciphertext_sha256: &'a str,
}

impl Debug for PrivateHnswOramCommitBucketRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramCommitBucketRef")
            .field("bucket_id", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswOramCommitSignatureInput<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub updated_buckets: &'a [PrivateHnswOramCommitBucketRef<'a>],
    pub signature_alg: &'a str,
    pub signature_key_id: &'a str,
}

impl Debug for PrivateHnswOramCommitSignatureInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramCommitSignatureInput")
            .field("collection_id", &self.collection_id)
            .field("vector_name", &self.vector_name)
            .field("key_id", &self.key_id)
            .field("rk_id", &self.rk_id)
            .field("rk_epoch", &self.rk_epoch)
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("updated_bucket_count", &self.updated_buckets.len())
            .field("signature_alg", &self.signature_alg)
            .field("signature_key_id", &self.signature_key_id)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateHnswOramReadPathsSignatureInput<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub index_epoch: u64,
    pub root_hash: &'a str,
    pub paths: &'a [&'a str],
    pub requested_paths: u32,
    pub dummy_paths_included: bool,
    pub signature_alg: &'a str,
    pub signature_key_id: &'a str,
}

impl Debug for PrivateHnswOramReadPathsSignatureInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramReadPathsSignatureInput")
            .field("collection_id", &self.collection_id)
            .field("vector_name", &self.vector_name)
            .field("key_id", &self.key_id)
            .field("rk_id", &self.rk_id)
            .field("rk_epoch", &self.rk_epoch)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("path_count", &self.paths.len())
            .field("requested_paths", &self.requested_paths)
            .field("dummy_paths_included", &self.dummy_paths_included)
            .field("signature_alg", &self.signature_alg)
            .field("signature_key_id", &self.signature_key_id)
            .finish()
    }
}

pub fn validate_private_hnsw_oram_manifest(
    manifest: &PrivateHnswOramManifest,
    signature: Option<&PrivateHnswOramSignature>,
    context: PrivateHnswManifestValidationContext<'_>,
) -> Result<PrivateHnswEpoch, PrivateHnswOramError> {
    validate_manifest_shape(manifest)?;
    validate_manifest_context(manifest, context)?;
    validate_private_hnsw_oram_manifest_signature(
        manifest,
        signature,
        context.signature_verification,
    )?;

    let root_hash = decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(PrivateHnswEpoch {
        epoch: manifest.index_epoch,
        root_hash,
    })
}

pub fn validate_private_hnsw_oram_manifest_shape(
    manifest: &PrivateHnswOramManifest,
) -> Result<(), PrivateHnswOramError> {
    validate_manifest_shape(manifest)
}

pub fn validate_private_hnsw_oram_manifest_signature_shape(
    signature: &PrivateHnswOramSignature,
) -> Result<(), PrivateHnswOramError> {
    if signature.alg != PRIVATE_HNSW_ORAM_SIGNATURE_ALGORITHM {
        return Err(PrivateHnswOramError::UnsupportedSignatureAlgorithm(
            signature.alg.clone(),
        ));
    }
    validate_resource_id(&signature.key_id)?;
    decode_base64url_64(&signature.sig)?;
    Ok(())
}

pub fn validate_private_hnsw_oram_manifest_signature(
    manifest: &PrivateHnswOramManifest,
    signature: Option<&PrivateHnswOramSignature>,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    let signature = signature.ok_or(PrivateHnswOramError::MissingManifestSignature)?;
    validate_manifest_shape(manifest)?;
    validate_signature_header(
        signature,
        manifest.owner_signing_key_id.as_str(),
        verification,
    )?;
    let signature_bytes = decode_base64url_64(&signature.sig)?;
    let message = try_private_hnsw_oram_manifest_signature_message(manifest)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateHnswOramError::InvalidManifestSignature)
}

pub fn validate_private_hnsw_oram_commit_signature(
    input: PrivateHnswOramCommitSignatureInput<'_>,
    signature: &str,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    validate_signature_fields(input.signature_alg, input.signature_key_id, verification)?;
    validate_signature_input_context(
        input.collection_id,
        Some(input.vector_name),
        input.key_id,
        input.rk_id,
    )?;
    if input.updated_buckets.is_empty() {
        return Err(PrivateHnswOramError::EmptyCommit);
    }
    if u32::try_from(input.updated_buckets.len()).is_err() {
        return Err(PrivateHnswOramError::InvalidCommitSignature);
    }
    if input.new_epoch <= input.old_epoch {
        return Err(PrivateHnswOramError::InvalidManifestField("new_epoch"));
    }
    decode_base64url_32(input.old_root_hash, "old_root_hash")?;
    decode_base64url_32(input.new_root_hash, "new_root_hash")?;
    let mut seen_bucket_ids = BTreeSet::new();
    for bucket in input.updated_buckets {
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateHnswOramError::InvalidCommitSignature);
        }
        decode_base64url_32(bucket.ciphertext_sha256, "ciphertext_sha256")?;
    }
    let signature_bytes = decode_base64url_64(signature)?;
    let message = try_private_hnsw_oram_commit_signature_message(input)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateHnswOramError::InvalidCommitSignature)
}

pub fn validate_private_hnsw_oram_read_paths_signature(
    input: PrivateHnswOramReadPathsSignatureInput<'_>,
    signature: &str,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    validate_signature_fields(input.signature_alg, input.signature_key_id, verification)?;
    validate_signature_input_context(
        input.collection_id,
        Some(input.vector_name),
        input.key_id,
        input.rk_id,
    )?;
    decode_base64url_32(input.root_hash, "root_hash")?;
    let requested_paths_len: usize = input
        .requested_paths
        .try_into()
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)?;
    if input.paths.is_empty()
        || input.requested_paths == 0
        || u32::try_from(input.paths.len()).is_err()
        || requested_paths_len != input.paths.len()
        || !input.dummy_paths_included
    {
        return Err(PrivateHnswOramError::InvalidReadPathsSignature);
    }
    for path in input.paths {
        decode_base64url_8(path).map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)?;
    }
    let signature_bytes = decode_base64url_64(signature)?;
    let message = try_private_hnsw_oram_read_paths_signature_message(input)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)
}

pub fn private_hnsw_min_f32_node_block_bytes(dim: u32, fixed_neighbor_slots: u32) -> Option<u64> {
    let vector_bytes = u64::from(dim).checked_mul(PRIVATE_HNSW_NODE_BLOCK_F32_ELEMENT_BYTES)?;
    let neighbor_bytes =
        u64::from(fixed_neighbor_slots).checked_mul(PRIVATE_HNSW_NODE_BLOCK_NEIGHBOR_SLOT_BYTES)?;
    PRIVATE_HNSW_NODE_BLOCK_FIXED_BYTES
        .checked_add(vector_bytes)?
        .checked_add(neighbor_bytes)
}

pub fn try_private_hnsw_oram_manifest_signature_message(
    manifest: &PrivateHnswOramManifest,
) -> Result<Vec<u8>, PrivateHnswOramError> {
    validate_manifest_shape(manifest)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_HNSW_ORAM_MANIFEST_SIGNATURE_DOMAIN.as_bytes(),
        || PrivateHnswOramError::InvalidManifestField("signature_message"),
    )?;
    push_u16(&mut message, manifest.version);
    try_push_str(&mut message, &manifest.provider, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.binding, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.collection_id, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.vector_name, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.key_id, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.rk_id, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    push_u64(&mut message, manifest.rk_epoch);
    push_u32(&mut message, manifest.dim);
    try_push_str(&mut message, manifest.distance.as_str(), || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    push_u32(&mut message, manifest.hnsw.m);
    push_u32(&mut message, manifest.hnsw.ef_construction);
    push_u32(&mut message, manifest.hnsw.max_layers);
    push_u32(&mut message, manifest.hnsw.fixed_neighbor_slots);
    try_push_str(&mut message, manifest.oram.kind.as_str(), || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    push_u32(&mut message, manifest.oram.bucket_size);
    push_u32(&mut message, manifest.oram.block_size_bytes);
    push_u32(&mut message, manifest.oram.tree_height);
    push_u32(&mut message, manifest.oram.path_batch_size);
    push_bool(&mut message, manifest.fixed_budget.enabled);
    push_u32(&mut message, manifest.fixed_budget.upper_layer_steps);
    push_u32(&mut message, manifest.fixed_budget.base_layer_steps);
    push_u32(&mut message, manifest.fixed_budget.paths_per_round);
    push_u32(&mut message, manifest.fixed_budget.fixed_result_k);
    push_u64(&mut message, manifest.index_epoch);
    try_push_str(&mut message, &manifest.root_hash, || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    push_u64(&mut message, manifest.bucket_count);
    push_u64(&mut message, manifest.logical_node_count);
    push_u64(&mut message, manifest.dummy_node_count);
    try_push_str(&mut message, manifest.result_privacy.as_str(), || {
        PrivateHnswOramError::InvalidManifestField("signature_message")
    })?;
    Ok(message)
}

pub fn try_private_hnsw_oram_read_paths_signature_message(
    input: PrivateHnswOramReadPathsSignatureInput<'_>,
) -> Result<Vec<u8>, PrivateHnswOramError> {
    validate_signature_input_context(
        input.collection_id,
        Some(input.vector_name),
        input.key_id,
        input.rk_id,
    )?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_HNSW_ORAM_READ_PATHS_SIGNATURE_DOMAIN.as_bytes(),
        || PrivateHnswOramError::InvalidReadPathsSignature,
    )?;
    try_push_str(&mut message, input.collection_id, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    try_push_str(&mut message, input.vector_name, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    try_push_str(&mut message, input.key_id, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    try_push_str(&mut message, input.rk_id, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    push_u64(&mut message, input.rk_epoch);
    push_u64(&mut message, input.index_epoch);
    try_push_str(&mut message, input.root_hash, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    let path_count = u32::try_from(input.paths.len())
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)?;
    push_u32(&mut message, path_count);
    for path in input.paths {
        try_push_str(&mut message, path, || {
            PrivateHnswOramError::InvalidReadPathsSignature
        })?;
    }
    push_u32(&mut message, input.requested_paths);
    push_bool(&mut message, input.dummy_paths_included);
    try_push_str(&mut message, input.signature_alg, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    try_push_str(&mut message, input.signature_key_id, || {
        PrivateHnswOramError::InvalidReadPathsSignature
    })?;
    Ok(message)
}

pub fn try_private_hnsw_oram_commit_signature_message(
    input: PrivateHnswOramCommitSignatureInput<'_>,
) -> Result<Vec<u8>, PrivateHnswOramError> {
    validate_signature_input_context(
        input.collection_id,
        Some(input.vector_name),
        input.key_id,
        input.rk_id,
    )?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_HNSW_ORAM_COMMIT_SIGNATURE_DOMAIN.as_bytes(),
        || PrivateHnswOramError::InvalidCommitSignature,
    )?;
    try_push_str(&mut message, input.collection_id, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.vector_name, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.key_id, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.rk_id, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    push_u64(&mut message, input.rk_epoch);
    push_u64(&mut message, input.old_epoch);
    push_u64(&mut message, input.new_epoch);
    try_push_str(&mut message, input.old_root_hash, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.new_root_hash, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    let updated_bucket_count = u32::try_from(input.updated_buckets.len())
        .map_err(|_| PrivateHnswOramError::InvalidCommitSignature)?;
    push_u32(&mut message, updated_bucket_count);
    for bucket in input.updated_buckets {
        push_u64(&mut message, bucket.bucket_id);
        try_push_str(&mut message, bucket.ciphertext_sha256, || {
            PrivateHnswOramError::InvalidCommitSignature
        })?;
    }
    try_push_str(&mut message, input.signature_alg, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.signature_key_id, || {
        PrivateHnswOramError::InvalidCommitSignature
    })?;
    Ok(message)
}

fn validate_manifest_shape(manifest: &PrivateHnswOramManifest) -> Result<(), PrivateHnswOramError> {
    if manifest.version != PRIVATE_HNSW_ORAM_MANIFEST_VERSION {
        return Err(PrivateHnswOramError::UnsupportedManifestVersion(
            manifest.version,
        ));
    }
    if manifest.provider != VECTOR_PRIVATE_HNSW_ORAM_PROVIDER {
        return Err(PrivateHnswOramError::InvalidProvider);
    }
    if manifest.binding != PRIVATE_HNSW_ORAM_BINDING {
        return Err(PrivateHnswOramError::InvalidBinding);
    }
    validate_id(&manifest.collection_id, "collection_id")?;
    validate_vector_name(&manifest.vector_name)?;
    validate_resource_id(&manifest.key_id)?;
    validate_resource_id(&manifest.rk_id)?;
    validate_resource_id(&manifest.owner_signing_key_id)?;
    if manifest.dim == 0 {
        return Err(PrivateHnswOramError::InvalidManifestField("dim"));
    }
    if manifest.hnsw.m == 0
        || manifest.hnsw.ef_construction == 0
        || manifest.hnsw.max_layers == 0
        || manifest.hnsw.fixed_neighbor_slots < manifest.hnsw.m
    {
        return Err(PrivateHnswOramError::InvalidManifestField("hnsw"));
    }
    if manifest.oram.bucket_size == 0
        || manifest.oram.block_size_bytes == 0
        || manifest.oram.tree_height == 0
        || manifest.oram.path_batch_size == 0
    {
        return Err(PrivateHnswOramError::InvalidManifestField("oram"));
    }
    let min_node_block_bytes =
        private_hnsw_min_f32_node_block_bytes(manifest.dim, manifest.hnsw.fixed_neighbor_slots)
            .ok_or(PrivateHnswOramError::InvalidManifestField(
                "oram.block_size_bytes",
            ))?;
    if u64::from(manifest.oram.block_size_bytes) < min_node_block_bytes {
        return Err(PrivateHnswOramError::InvalidManifestField(
            "oram.block_size_bytes",
        ));
    }
    if !manifest.fixed_budget.enabled
        || manifest.fixed_budget.upper_layer_steps == 0
        || manifest.fixed_budget.base_layer_steps == 0
        || manifest.fixed_budget.paths_per_round == 0
        || manifest.fixed_budget.fixed_result_k == 0
    {
        return Err(PrivateHnswOramError::InvalidManifestField("fixed_budget"));
    }
    if manifest.bucket_count == 0 {
        return Err(PrivateHnswOramError::InvalidManifestField("bucket_count"));
    }
    let leaf_count = path_oram_leaf_count(manifest.oram.tree_height)
        .ok_or(PrivateHnswOramError::InvalidManifestField("oram"))?;
    if u64::from(manifest.oram.path_batch_size) > leaf_count {
        return Err(PrivateHnswOramError::InvalidManifestField(
            "oram.path_batch_size",
        ));
    }
    if manifest.fixed_budget.paths_per_round != manifest.oram.path_batch_size {
        return Err(PrivateHnswOramError::InvalidManifestField(
            "fixed_budget.paths_per_round",
        ));
    }
    let expected_bucket_count = path_oram_bucket_count(manifest.oram.tree_height)
        .ok_or(PrivateHnswOramError::InvalidManifestField("oram"))?;
    if manifest.bucket_count != expected_bucket_count {
        return Err(PrivateHnswOramError::InvalidManifestField("bucket_count"));
    }
    let capacity = manifest
        .bucket_count
        .checked_mul(u64::from(manifest.oram.bucket_size))
        .ok_or(PrivateHnswOramError::InvalidManifestField("bucket_count"))?;
    let node_count = manifest
        .logical_node_count
        .checked_add(manifest.dummy_node_count)
        .ok_or(PrivateHnswOramError::InvalidManifestField("node_count"))?;
    if node_count > capacity {
        return Err(PrivateHnswOramError::InvalidManifestField("node_count"));
    }
    decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(())
}

fn path_oram_bucket_count(tree_height: u32) -> Option<u64> {
    path_oram_leaf_count(tree_height)?
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
}

fn path_oram_leaf_count(tree_height: u32) -> Option<u64> {
    if tree_height >= 63 {
        return None;
    }
    Some(1u64 << tree_height)
}

fn validate_manifest_context(
    manifest: &PrivateHnswOramManifest,
    context: PrivateHnswManifestValidationContext<'_>,
) -> Result<(), PrivateHnswOramError> {
    if manifest.collection_id != context.expected_collection_id {
        return Err(PrivateHnswOramError::ManifestContextMismatch(
            "collection_id",
        ));
    }
    if manifest.vector_name != context.expected_vector_name {
        return Err(PrivateHnswOramError::ManifestContextMismatch("vector_name"));
    }
    if manifest.key_id != context.expected_key_id {
        return Err(PrivateHnswOramError::ManifestContextMismatch("key_id"));
    }
    if manifest.rk_id != context.expected_rk_id {
        return Err(PrivateHnswOramError::ManifestContextMismatch("rk_id"));
    }
    if manifest.rk_epoch < context.min_rk_epoch || manifest.rk_epoch > context.max_rk_epoch {
        return Err(PrivateHnswOramError::ManifestContextMismatch("rk_epoch"));
    }
    if manifest.dim != context.expected_dim {
        return Err(PrivateHnswOramError::ManifestContextMismatch("dim"));
    }
    if manifest.distance != context.expected_distance {
        return Err(PrivateHnswOramError::ManifestContextMismatch("distance"));
    }
    Ok(())
}

fn validate_signature_header(
    signature: &PrivateHnswOramSignature,
    expected_owner_key_id: &str,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    validate_signature_fields(&signature.alg, &signature.key_id, verification)?;
    if signature.key_id != expected_owner_key_id {
        return Err(PrivateHnswOramError::SignatureKeyIdMismatch);
    }
    Ok(())
}

fn validate_signature_fields(
    alg: &str,
    key_id: &str,
    verification: PrivateHnswSignatureVerification<'_>,
) -> Result<(), PrivateHnswOramError> {
    if alg != PRIVATE_HNSW_ORAM_SIGNATURE_ALGORITHM {
        return Err(PrivateHnswOramError::UnsupportedSignatureAlgorithm(
            alg.to_string(),
        ));
    }
    validate_resource_id(key_id)?;
    if key_id != verification.expected_key_id {
        return Err(PrivateHnswOramError::SignatureKeyIdMismatch);
    }
    if verification.public_key.len() != 32 {
        return Err(PrivateHnswOramError::MalformedSignature);
    }
    Ok(())
}

fn validate_signature_input_context(
    collection_id: &str,
    vector_name: Option<&str>,
    key_id: &str,
    rk_id: &str,
) -> Result<(), PrivateHnswOramError> {
    validate_id(collection_id, "collection_id")?;
    if let Some(vector_name) = vector_name {
        validate_vector_name(vector_name)?;
    }
    validate_resource_id(key_id)?;
    validate_resource_id(rk_id)?;
    Ok(())
}

fn validate_id(value: &str, field: &'static str) -> Result<(), PrivateHnswOramError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(PrivateHnswOramError::InvalidManifestField(field));
    }
    Ok(())
}

fn validate_vector_name(value: &str) -> Result<(), PrivateHnswOramError> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || vector_name_is_client_owned_oram_state_alias(value)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        return Err(PrivateHnswOramError::InvalidManifestField("vector_name"));
    }
    Ok(())
}

fn vector_name_is_client_owned_oram_state_alias(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let compact_value = value.replace(['_', '-', '.'], "");
    if compact_vector_name_is_client_owned_oram_state_alias(&compact_value) {
        return true;
    }
    let Some((stem, _extension)) = value.rsplit_once('.') else {
        return false;
    };
    compact_vector_name_is_client_owned_oram_state_alias(&stem.replace(['_', '-', '.'], ""))
}

fn compact_vector_name_is_client_owned_oram_state_alias(value: &str) -> bool {
    matches!(
        value,
        "clientstate"
            | "clientstatesnapshot"
            | "clientstatesnapshots"
            | "encryptedclientstatesnapshot"
            | "encryptedclientstatesnapshots"
            | "positionmap"
            | "positionmaps"
            | "positionmapsnapshot"
            | "positionmapsnapshots"
            | "orampositionmap"
            | "orampositionmaps"
            | "orampositionmapsnapshot"
            | "orampositionmapsnapshots"
            | "tokenpositionmap"
            | "tokenpositionmaps"
            | "tokenpositionmapsnapshot"
            | "tokenpositionmapsnapshots"
            | "stash"
            | "stashsnapshot"
            | "stashsnapshots"
    )
}

fn validate_resource_id(value: &str) -> Result<(), PrivateHnswOramError> {
    validate_resource_key_id(value).map_err(|err| match err {
        EncryptionError::InvalidResourceKeyId => PrivateHnswOramError::InvalidResourceKeyId,
        _ => PrivateHnswOramError::InvalidResourceKeyId,
    })
}

fn decode_base64url_32(value: &str, field: &'static str) -> Result<[u8; 32], PrivateHnswOramError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateHnswOramError::InvalidManifestField(field));
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswOramError::InvalidManifestField(field))?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswOramError::InvalidManifestField(field))
}

fn decode_base64url_8(value: &str) -> Result<[u8; 8], PrivateHnswOramError> {
    if value.len() != BASE64URL_NOPAD_8_BYTE_LEN {
        return Err(PrivateHnswOramError::InvalidReadPathsSignature);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswOramError::InvalidReadPathsSignature)
}

fn decode_base64url_64(value: &str) -> Result<[u8; 64], PrivateHnswOramError> {
    if value.len() != BASE64URL_NOPAD_64_BYTE_LEN {
        return Err(PrivateHnswOramError::MalformedSignature);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswOramError::MalformedSignature)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswOramError::MalformedSignature)
}

fn try_push_domain(
    message: &mut Vec<u8>,
    value: &[u8],
    error: impl FnOnce() -> PrivateHnswOramError,
) -> Result<(), PrivateHnswOramError> {
    let len: u32 = value.len().try_into().map_err(|_| error())?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value);
    Ok(())
}

fn try_push_str(
    message: &mut Vec<u8>,
    value: &str,
    error: impl FnOnce() -> PrivateHnswOramError,
) -> Result<(), PrivateHnswOramError> {
    let len: u64 = value.len().try_into().map_err(|_| error())?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_bool(message: &mut Vec<u8>, value: bool) {
    message.push(u8::from(value));
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

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn private_hnsw_oram_error_display_does_not_reflect_structured_values() {
        let cases = [
            PrivateHnswOramError::UnsupportedManifestVersion(99).to_string(),
            PrivateHnswOramError::InvalidManifestField("manifest-field-sentinel").to_string(),
            PrivateHnswOramError::ManifestContextMismatch("manifest-context-sentinel").to_string(),
            PrivateHnswOramError::UnsupportedSignatureAlgorithm("rsa-pss-sentinel".to_string())
                .to_string(),
        ];

        for rendered in cases {
            assert!(!rendered.contains("rsa-pss-sentinel"), "{rendered}");
            assert!(!rendered.contains("manifest-field-sentinel"), "{rendered}");
            assert!(
                !rendered.contains("manifest-context-sentinel"),
                "{rendered}"
            );
            assert!(!rendered.contains("99"), "{rendered}");
        }
    }

    #[test]
    fn private_hnsw_debug_redacts_ciphertext_and_access_pattern_values() {
        let encrypted_bucket = PrivateHnswOramBucket {
            version: 1,
            bucket_id: 987_654,
            index_epoch: 42,
            ciphertext: "HNSW-CIPHERTEXT-SENTINEL".to_string(),
            ciphertext_sha256: "HNSW-SHA-SENTINEL".to_string(),
            bucket_commitment: "HNSW-COMMITMENT-SENTINEL".to_string(),
        };
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: "HNSW-SIGNATURE-SENTINEL".to_string(),
        };
        let mut manifest = fixture_manifest();
        manifest.root_hash = "HNSW-MANIFEST-ROOT-SENTINEL".to_string();
        let commit_refs = [PrivateHnswOramCommitBucketRef {
            bucket_id: 987_654,
            ciphertext_sha256: "HNSW-SHA-SENTINEL",
        }];
        let commit_signature_input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: "HNSW-OLD-ROOT-SENTINEL",
            new_root_hash: "HNSW-NEW-ROOT-SENTINEL",
            updated_buckets: &commit_refs,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let paths = ["HNSW-PATH-LABEL-SENTINEL"];
        let read_paths_signature_input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: "HNSW-ROOT-SENTINEL",
            paths: &paths,
            requested_paths: 1,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };

        let rendered = [
            format!("{encrypted_bucket:?}"),
            format!("{signature:?}"),
            format!("{manifest:?}"),
            format!("{:?}", commit_refs[0]),
            format!("{commit_signature_input:?}"),
            format!("{read_paths_signature_input:?}"),
        ]
        .join("\n");
        for leaked in [
            "987654",
            "HNSW-CIPHERTEXT-SENTINEL",
            "HNSW-SHA-SENTINEL",
            "HNSW-COMMITMENT-SENTINEL",
            "HNSW-SIGNATURE-SENTINEL",
            "HNSW-MANIFEST-ROOT-SENTINEL",
            "HNSW-OLD-ROOT-SENTINEL",
            "HNSW-NEW-ROOT-SENTINEL",
            "HNSW-ROOT-SENTINEL",
            "HNSW-PATH-LABEL-SENTINEL",
        ] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
    }

    fn fixture_manifest() -> PrivateHnswOramManifest {
        PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            vector_name: "text".to_string(),
            key_id: "tenant-a/vector-private-rk".to_string(),
            rk_id: "tenant-a/vector-private-rk".to_string(),
            rk_epoch: 7,
            dim: 1536,
            distance: DistanceKind::Cosine,
            hnsw: PrivateHnswParams {
                m: 32,
                ef_construction: 128,
                max_layers: 16,
                fixed_neighbor_slots: 64,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 16384,
                tree_height: 24,
                path_batch_size: 8,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 32,
                base_layer_steps: 256,
                paths_per_round: 8,
                fixed_result_k: 10,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: (1 << 25) - 1,
            logical_node_count: 500_000,
            dummy_node_count: 24_288,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    #[test]
    fn bucket_ciphertext_size_matches_path_oram_encoding_contract() {
        let mut manifest = fixture_manifest();
        manifest.oram.bucket_size = 4;
        manifest.oram.block_size_bytes = 8192;

        assert_eq!(
            private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
            1 + 12 + 16 + 4 + 2 + 4 + 4 + 4 * (1 + 8192)
        );
    }

    fn fixture_context<'a>(
        public_key: &'a [u8],
        key_id: &'a str,
    ) -> PrivateHnswManifestValidationContext<'a> {
        PrivateHnswManifestValidationContext {
            expected_collection_id: "collection-uuid-1",
            expected_vector_name: "text",
            expected_key_id: "tenant-a/vector-private-rk",
            expected_rk_id: "tenant-a/vector-private-rk",
            min_rk_epoch: 7,
            max_rk_epoch: 7,
            expected_dim: 1536,
            expected_distance: DistanceKind::Cosine,
            signature_verification: PrivateHnswSignatureVerification {
                expected_key_id: key_id,
                public_key,
            },
        }
    }

    fn deterministic_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
    }

    fn sign_b64(key_pair: &Ed25519KeyPair, message: &[u8]) -> String {
        BASE64URL_NOPAD.encode(key_pair.sign(message).as_ref())
    }

    fn checked_manifest_signature_message(manifest: &PrivateHnswOramManifest) -> Vec<u8> {
        try_private_hnsw_oram_manifest_signature_message(manifest).unwrap()
    }

    fn checked_commit_signature_message(input: PrivateHnswOramCommitSignatureInput<'_>) -> Vec<u8> {
        try_private_hnsw_oram_commit_signature_message(input).unwrap()
    }

    fn checked_read_paths_signature_message(
        input: PrivateHnswOramReadPathsSignatureInput<'_>,
    ) -> Vec<u8> {
        try_private_hnsw_oram_read_paths_signature_message(input).unwrap()
    }

    #[test]
    fn manifest_signature_message_is_stable() {
        let manifest = fixture_manifest();
        let digest = Sha256::digest(checked_manifest_signature_message(&manifest));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "1hzG6sGJ3RkYa_N_fB91X83CT5gF19sXnVxGdo2hiOQ"
        );
    }

    #[test]
    fn commit_signature_message_is_stable() {
        let buckets = [
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateHnswOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };

        let digest = Sha256::digest(checked_commit_signature_message(input));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "K7D-QZtqOp7EBdqB0idlNYPSzjPMcg_Uripj067shYQ"
        );
    }

    #[test]
    fn read_paths_signature_message_is_stable() {
        let paths = ["AAAAAAAAAAA", "AAAAAAAAAAE"];
        let input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 2,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };

        let digest = Sha256::digest(checked_read_paths_signature_message(input));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "n_ChN7eT7j4hxnccWt9L4u65CYHUnOMr5K3f80SJTaA"
        );
    }

    #[test]
    fn signature_known_answer_vectors_are_stable() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        assert_eq!(
            sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
            "L9Q5eSm8eDGxINlvhFUYSsBiRrhqkc0eEcqbyqv9rnsAuqYCEv9k4ZWUL0RiWi-ft49oq-JBu9yX_xrtkXG_Bw"
        );

        let buckets = [
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateHnswOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let commit_input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        assert_eq!(
            sign_b64(&key_pair, &checked_commit_signature_message(commit_input)),
            "wRomyqNMlHx22E4hNCitBRnqk06QhZ2Y_SwWnCrKhteedbtrxIslkFfUTiPWgl03hfFiKWJbzhi8jZVVb9u_Ag"
        );

        let paths = ["AAAAAAAAAAA", "AAAAAAAAAAE"];
        let read_input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 2,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        assert_eq!(
            sign_b64(&key_pair, &checked_read_paths_signature_message(read_input)),
            "xoxnYq-yulLq8ufkyv_wLANeEpsC2lYdbwWPr8KvjRgPc-3st2HrbKDwE_wQZTPiByEp_W5F3lVS84TWgbVcCw"
        );
    }

    fn assert_signature_fixture(
        fixture: &serde_json::Value,
        case_name: &str,
        message: &[u8],
        signature: &str,
    ) {
        let case = fixture["cases"]
            .as_array()
            .and_then(|cases| {
                cases
                    .iter()
                    .find(|case| case["name"].as_str() == Some(case_name))
            })
            .unwrap_or_else(|| panic!("test vector case {case_name} must exist"));
        let get = |key: &str| {
            case[key]
                .as_str()
                .unwrap_or_else(|| panic!("test vector case {case_name} must define {key}"))
        };

        assert_eq!(get("signature_alg"), "ed25519");
        assert_eq!(
            message.len() as u64,
            case["signature_message_len"]
                .as_u64()
                .unwrap_or_else(|| panic!("test vector case {case_name} must define message len"))
        );
        assert_eq!(
            BASE64URL_NOPAD.encode(message),
            get("signature_message_b64")
        );
        assert_eq!(
            BASE64URL_NOPAD.encode(Sha256::digest(message).as_ref()),
            get("signature_message_sha256_b64")
        );
        assert_eq!(signature, get("signature_b64"));
    }

    #[test]
    fn signature_messages_match_sdk_test_vector() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/qdrant-sec-private-hnsw-oram-signature-test-vector.json"
        ))
        .expect("private HNSW ORAM signature test vector must be valid JSON");
        assert_eq!(
            fixture["provider"].as_str(),
            Some(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER)
        );
        assert_eq!(fixture["binding"].as_str(), Some(PRIVATE_HNSW_ORAM_BINDING));

        let key_pair = deterministic_key_pair();
        let manifest_message = checked_manifest_signature_message(&fixture_manifest());
        let manifest_signature = sign_b64(&key_pair, &manifest_message);
        assert_signature_fixture(&fixture, "manifest", &manifest_message, &manifest_signature);

        let buckets = [
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateHnswOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let commit_input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let commit_message = checked_commit_signature_message(commit_input);
        let commit_signature = sign_b64(&key_pair, &commit_message);
        assert_signature_fixture(&fixture, "commit", &commit_message, &commit_signature);

        let paths = ["AAAAAAAAAAA", "AAAAAAAAAAE"];
        let read_input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 2,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let read_message = checked_read_paths_signature_message(read_input);
        let read_signature = sign_b64(&key_pair, &read_message);
        assert_signature_fixture(&fixture, "read_paths", &read_message, &read_signature);
    }

    #[test]
    fn signature_message_builders_reject_client_state_vector_aliases() {
        let mut manifest = fixture_manifest();
        manifest.vector_name = "client.state".to_string();
        assert_eq!(
            try_private_hnsw_oram_manifest_signature_message(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let paths = ["AAAAAAAAAAA"];
        let read_paths_input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "client.state",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 1,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        assert_eq!(
            try_private_hnsw_oram_read_paths_signature_message(read_paths_input),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let buckets = [PrivateHnswOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
        }];
        let commit_input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "client.state",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        assert_eq!(
            try_private_hnsw_oram_commit_signature_message(commit_input),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );
    }

    #[test]
    fn read_paths_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let paths = ["AAAAAAAAAAA"];
        let input = PrivateHnswOramReadPathsSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            paths: &paths,
            requested_paths: 1,
            dummy_paths_included: true,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let signature = sign_b64(&key_pair, &checked_read_paths_signature_message(input));
        let verification = PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/private-hnsw-signing-v1",
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_hnsw_oram_read_paths_signature(input, &signature, verification).unwrap();

        let invalid_context = PrivateHnswOramReadPathsSignatureInput {
            vector_name: "",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                invalid_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let unsafe_vector_context = PrivateHnswOramReadPathsSignatureInput {
            vector_name: "text/private",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                unsafe_vector_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let client_state_alias_context = PrivateHnswOramReadPathsSignatureInput {
            vector_name: "client.state",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                client_state_alias_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let malformed_root = PrivateHnswOramReadPathsSignatureInput {
            root_hash: "AAAA",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                malformed_root,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("root_hash"))
        );

        let empty_paths = PrivateHnswOramReadPathsSignatureInput {
            paths: &[],
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                empty_paths,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let malformed_paths = ["AAAA"];
        let malformed_path = PrivateHnswOramReadPathsSignatureInput {
            paths: &malformed_paths,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                malformed_path,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let tampered = PrivateHnswOramReadPathsSignatureInput {
            requested_paths: 2,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(tampered, &signature, verification),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let tampered_padding = PrivateHnswOramReadPathsSignatureInput {
            dummy_paths_included: false,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                tampered_padding,
                &signature,
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );
        let tampered_padding_signature = sign_b64(
            &key_pair,
            &checked_read_paths_signature_message(tampered_padding),
        );
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                tampered_padding,
                &tampered_padding_signature,
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );

        let mismatched = PrivateHnswOramReadPathsSignatureInput {
            requested_paths: 2,
            ..input
        };
        let mismatched_signature =
            sign_b64(&key_pair, &checked_read_paths_signature_message(mismatched));
        assert_eq!(
            validate_private_hnsw_oram_read_paths_signature(
                mismatched,
                &mismatched_signature,
                verification,
            ),
            Err(PrivateHnswOramError::InvalidReadPathsSignature)
        );
    }

    #[test]
    fn manifest_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };
        let context = fixture_context(key_pair.public_key().as_ref(), &signature.key_id);

        let epoch =
            validate_private_hnsw_oram_manifest(&manifest, Some(&signature), context).unwrap();
        assert_eq!(epoch.epoch, 42);
        assert_eq!(epoch.root_hash, [42; 32]);

        let mut tampered = manifest;
        tampered.root_hash = BASE64URL_NOPAD.encode(&[43; 32]);
        assert_eq!(
            validate_private_hnsw_oram_manifest(&tampered, Some(&signature), context),
            Err(PrivateHnswOramError::InvalidManifestSignature)
        );

        let mut malformed = fixture_manifest();
        malformed.root_hash = "AAAA".to_string();
        assert_eq!(
            validate_private_hnsw_oram_manifest_signature(
                &malformed,
                Some(&signature),
                context.signature_verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("root_hash"))
        );
    }

    #[test]
    fn manifest_signature_requires_owner_and_runtime_key_id_match() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };

        let mut wrong_owner_signature = signature.clone();
        wrong_owner_signature.key_id = "tenant-a/private-hnsw-signing-v2".to_string();
        assert_eq!(
            validate_private_hnsw_oram_manifest(
                &manifest,
                Some(&wrong_owner_signature),
                fixture_context(
                    key_pair.public_key().as_ref(),
                    &wrong_owner_signature.key_id
                ),
            ),
            Err(PrivateHnswOramError::SignatureKeyIdMismatch)
        );

        assert_eq!(
            validate_private_hnsw_oram_manifest(
                &manifest,
                Some(&signature),
                fixture_context(
                    key_pair.public_key().as_ref(),
                    "tenant-a/private-hnsw-wrong"
                ),
            ),
            Err(PrivateHnswOramError::SignatureKeyIdMismatch)
        );
    }

    #[test]
    fn manifest_shape_rejects_node_count_over_capacity() {
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.bucket_count = 3;
        manifest.oram.bucket_size = 1;
        manifest.oram.path_batch_size = 2;
        manifest.fixed_budget.paths_per_round = 2;
        manifest.logical_node_count = 4;
        manifest.dummy_node_count = 0;

        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField("node_count"))
        );
    }

    #[test]
    fn manifest_shape_rejects_path_oram_bucket_count_mismatch() {
        let mut manifest = fixture_manifest();
        manifest.bucket_count -= 1;

        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField("bucket_count"))
        );
    }

    #[test]
    fn manifest_shape_rejects_vector_name_not_safe_for_store_path() {
        for vector_name in [
            "text/private",
            "text:private",
            ".",
            "stash",
            "stash.snapshot",
            "client.state",
            "client_state.json",
            "position-map",
            "position.map",
            "oram.position.map",
            "token.position-map",
        ] {
            let mut manifest = fixture_manifest();
            manifest.vector_name = vector_name.to_string();
            assert_eq!(
                validate_private_hnsw_oram_manifest_shape(&manifest),
                Err(PrivateHnswOramError::InvalidManifestField("vector_name")),
                "vector_name {vector_name:?} should be rejected",
            );
        }
    }

    #[test]
    fn manifest_shape_rejects_impossible_path_batch_budget() {
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.bucket_count = 3;
        manifest.oram.path_batch_size = 3;
        manifest.fixed_budget.paths_per_round = 3;

        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField(
                "oram.path_batch_size"
            ))
        );

        manifest = fixture_manifest();
        manifest.fixed_budget.paths_per_round = manifest.oram.path_batch_size + 1;
        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField(
                "fixed_budget.paths_per_round"
            ))
        );
    }

    #[test]
    fn manifest_shape_rejects_impossible_node_block_budget() {
        let mut manifest = fixture_manifest();
        manifest.oram.block_size_bytes = 8192;

        assert_eq!(
            validate_private_hnsw_oram_manifest_shape(&manifest),
            Err(PrivateHnswOramError::InvalidManifestField(
                "oram.block_size_bytes"
            ))
        );
    }

    #[test]
    fn manifest_context_mismatch_and_malformed_signature_reject() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };
        let mut wrong_context = fixture_context(key_pair.public_key().as_ref(), &signature.key_id);
        wrong_context.expected_vector_name = "body";
        assert_eq!(
            validate_private_hnsw_oram_manifest(&manifest, Some(&signature), wrong_context),
            Err(PrivateHnswOramError::ManifestContextMismatch("vector_name"))
        );
        validate_private_hnsw_oram_manifest_shape(&manifest).unwrap();

        let bad_signature = PrivateHnswOramSignature {
            sig: "not-base64url".to_string(),
            ..signature
        };
        assert_eq!(
            validate_private_hnsw_oram_manifest_signature_shape(&bad_signature),
            Err(PrivateHnswOramError::MalformedSignature)
        );
        assert_eq!(
            validate_private_hnsw_oram_manifest(
                &manifest,
                Some(&bad_signature),
                fixture_context(key_pair.public_key().as_ref(), &bad_signature.key_id)
            ),
            Err(PrivateHnswOramError::MalformedSignature)
        );
    }

    #[test]
    fn commit_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let buckets = [PrivateHnswOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
        }];
        let input = PrivateHnswOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-hnsw-signing-v1",
        };
        let signature = sign_b64(&key_pair, &checked_commit_signature_message(input));
        let verification = PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/private-hnsw-signing-v1",
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_hnsw_oram_commit_signature(input, &signature, verification).unwrap();

        let stale_epoch_input = PrivateHnswOramCommitSignatureInput {
            new_epoch: input.old_epoch,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                stale_epoch_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("new_epoch"))
        );

        let invalid_context = PrivateHnswOramCommitSignatureInput {
            collection_id: "",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                invalid_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("collection_id"))
        );

        let invalid_vector_context = PrivateHnswOramCommitSignatureInput {
            vector_name: "text:private",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                invalid_vector_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let client_state_alias_context = PrivateHnswOramCommitSignatureInput {
            vector_name: "client.state",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                client_state_alias_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("vector_name"))
        );

        let invalid_key_context = PrivateHnswOramCommitSignatureInput {
            key_id: "bad key id",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                invalid_key_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidResourceKeyId)
        );

        let empty_input = PrivateHnswOramCommitSignatureInput {
            updated_buckets: &[],
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                empty_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::EmptyCommit)
        );

        let malformed_root_input = PrivateHnswOramCommitSignatureInput {
            old_root_hash: "AAAA",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                malformed_root_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField("old_root_hash"))
        );

        let malformed_hash_buckets = [PrivateHnswOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: "AAAA",
        }];
        let malformed_hash_input = PrivateHnswOramCommitSignatureInput {
            updated_buckets: &malformed_hash_buckets,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                malformed_hash_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateHnswOramError::InvalidManifestField(
                "ciphertext_sha256"
            ))
        );

        let duplicate_buckets = [
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateHnswOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[10; 32]),
            },
        ];
        let duplicate_input = PrivateHnswOramCommitSignatureInput {
            updated_buckets: &duplicate_buckets,
            ..input
        };
        let duplicate_signature = sign_b64(
            &key_pair,
            &checked_commit_signature_message(duplicate_input),
        );
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                duplicate_input,
                &duplicate_signature,
                verification,
            ),
            Err(PrivateHnswOramError::InvalidCommitSignature)
        );

        let wrong_signature_key_input = PrivateHnswOramCommitSignatureInput {
            signature_key_id: "tenant-a/private-hnsw-signing-v2",
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(
                wrong_signature_key_input,
                &signature,
                verification,
            ),
            Err(PrivateHnswOramError::SignatureKeyIdMismatch)
        );

        let tampered = PrivateHnswOramCommitSignatureInput {
            new_epoch: 44,
            ..input
        };
        assert_eq!(
            validate_private_hnsw_oram_commit_signature(tampered, &signature, verification),
            Err(PrivateHnswOramError::InvalidCommitSignature)
        );
    }

    #[test]
    fn generated_key_pair_manifest_signature_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };

        validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            fixture_context(key_pair.public_key().as_ref(), &signature.key_id),
        )
        .unwrap();
    }
}
