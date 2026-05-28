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

const PRIVATE_HNSW_ORAM_SIGNATURE_ALGORITHM: &str = "ed25519";
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;
const PRIVATE_HNSW_ORAM_MANIFEST_VERSION: u16 = 1;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PrivateHnswOramError {
    #[error("private HNSW ORAM manifest uses unsupported version {0}")]
    UnsupportedManifestVersion(u16),
    #[error("private HNSW ORAM manifest provider is invalid")]
    InvalidProvider,
    #[error("private HNSW ORAM manifest binding is invalid")]
    InvalidBinding,
    #[error("private HNSW ORAM manifest field {0} is invalid")]
    InvalidManifestField(&'static str),
    #[error("private HNSW ORAM manifest field {0} does not match runtime context")]
    ManifestContextMismatch(&'static str),
    #[error("private HNSW ORAM manifest signature is missing")]
    MissingManifestSignature,
    #[error("private HNSW ORAM manifest signature uses unsupported algorithm {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("private HNSW ORAM manifest signature key id does not match runtime context")]
    SignatureKeyIdMismatch,
    #[error("private HNSW ORAM manifest signature is malformed")]
    MalformedSignature,
    #[error("private HNSW ORAM manifest signature verification failed")]
    InvalidManifestSignature,
    #[error("private HNSW ORAM commit signature verification failed")]
    InvalidCommitSignature,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedBudgetParams {
    pub enabled: bool,
    pub upper_layer_steps: u32,
    pub base_layer_steps: u32,
    pub paths_per_round: u32,
    pub fixed_result_k: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramBucket {
    pub version: u16,
    pub bucket_id: u64,
    pub index_epoch: u64,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub bucket_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateHnswOramCommitBucketRef<'a> {
    pub bucket_id: u64,
    pub ciphertext_sha256: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    validate_signature_header(
        signature,
        manifest.owner_signing_key_id.as_str(),
        verification,
    )?;
    let signature_bytes = decode_base64url_64(&signature.sig)?;
    let message = private_hnsw_oram_manifest_signature_message(manifest);
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
    let signature_bytes = decode_base64url_64(signature)?;
    let message = private_hnsw_oram_commit_signature_message(input);
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateHnswOramError::InvalidCommitSignature)
}

pub fn private_hnsw_oram_manifest_signature_message(manifest: &PrivateHnswOramManifest) -> Vec<u8> {
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_HNSW_ORAM_MANIFEST_SIGNATURE_DOMAIN.as_bytes(),
    );
    push_u16(&mut message, manifest.version);
    push_str(&mut message, &manifest.provider);
    push_str(&mut message, &manifest.binding);
    push_str(&mut message, &manifest.collection_id);
    push_str(&mut message, &manifest.vector_name);
    push_str(&mut message, &manifest.key_id);
    push_str(&mut message, &manifest.rk_id);
    push_u64(&mut message, manifest.rk_epoch);
    push_u32(&mut message, manifest.dim);
    push_str(&mut message, manifest.distance.as_str());
    push_u32(&mut message, manifest.hnsw.m);
    push_u32(&mut message, manifest.hnsw.ef_construction);
    push_u32(&mut message, manifest.hnsw.max_layers);
    push_u32(&mut message, manifest.hnsw.fixed_neighbor_slots);
    push_str(&mut message, manifest.oram.kind.as_str());
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
    push_str(&mut message, &manifest.root_hash);
    push_u64(&mut message, manifest.bucket_count);
    push_u64(&mut message, manifest.logical_node_count);
    push_u64(&mut message, manifest.dummy_node_count);
    push_str(&mut message, manifest.result_privacy.as_str());
    message
}

pub fn private_hnsw_oram_commit_signature_message(
    input: PrivateHnswOramCommitSignatureInput<'_>,
) -> Vec<u8> {
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_HNSW_ORAM_COMMIT_SIGNATURE_DOMAIN.as_bytes(),
    );
    push_str(&mut message, input.collection_id);
    push_str(&mut message, input.vector_name);
    push_str(&mut message, input.key_id);
    push_str(&mut message, input.rk_id);
    push_u64(&mut message, input.rk_epoch);
    push_u64(&mut message, input.old_epoch);
    push_u64(&mut message, input.new_epoch);
    push_str(&mut message, input.old_root_hash);
    push_str(&mut message, input.new_root_hash);
    push_u32(&mut message, input.updated_buckets.len() as u32);
    for bucket in input.updated_buckets {
        push_u64(&mut message, bucket.bucket_id);
        push_str(&mut message, bucket.ciphertext_sha256);
    }
    push_str(&mut message, input.signature_alg);
    push_str(&mut message, input.signature_key_id);
    message
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
    validate_id(&manifest.vector_name, "vector_name")?;
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
    decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(())
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

fn push_domain(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u32).to_be_bytes());
    message.extend_from_slice(value);
}

fn push_str(message: &mut Vec<u8>, value: &str) {
    message.extend_from_slice(&(value.len() as u64).to_be_bytes());
    message.extend_from_slice(value.as_bytes());
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
                block_size_bytes: 8192,
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
            bucket_count: 1 << 20,
            logical_node_count: 500_000,
            dummy_node_count: 24_288,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
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

    #[test]
    fn manifest_signature_message_is_stable() {
        let manifest = fixture_manifest();
        let digest = Sha256::digest(private_hnsw_oram_manifest_signature_message(&manifest));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "NysgLtDq-ZNT2yCs8hECga8BSo_6hH2NrievkTY0fuw"
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

        let digest = Sha256::digest(private_hnsw_oram_commit_signature_message(input));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "K7D-QZtqOp7EBdqB0idlNYPSzjPMcg_Uripj067shYQ"
        );
    }

    #[test]
    fn manifest_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(
                &key_pair,
                &private_hnsw_oram_manifest_signature_message(&manifest),
            ),
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
    }

    #[test]
    fn manifest_context_mismatch_and_malformed_signature_reject() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(
                &key_pair,
                &private_hnsw_oram_manifest_signature_message(&manifest),
            ),
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
        let signature = sign_b64(
            &key_pair,
            &private_hnsw_oram_commit_signature_message(input),
        );
        let verification = PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/private-hnsw-signing-v1",
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_hnsw_oram_commit_signature(input, &signature, verification).unwrap();

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
            sig: sign_b64(
                &key_pair,
                &private_hnsw_oram_manifest_signature_message(&manifest),
            ),
        };

        validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            fixture_context(key_pair.public_key().as_ref(), &signature.key_id),
        )
        .unwrap();
    }
}
