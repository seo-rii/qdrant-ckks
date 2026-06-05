use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::aead::validate_resource_key_id;
use crate::control_plane::{PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING};
use crate::private_hnsw_oram::OramParams;

pub const PRIVATE_RESULT_ORAM_MANIFEST_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-result-oram-manifest-signature/v1";
pub const PRIVATE_RESULT_ORAM_COMMIT_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-result-oram-commit-signature/v1";
pub const PRIVATE_RESULT_ORAM_BUCKET_COMMITMENT_DOMAIN: &str =
    "qdrant-sec/private-result-oram-bucket-commitment/v1";

const PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM: &str = "ed25519";
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;
const PRIVATE_RESULT_ORAM_MERKLE_PROOF_JSON_MAX_BYTES: usize = 4 * 1024 * 1024;
const PRIVATE_RESULT_ORAM_MANIFEST_VERSION: u16 = 1;
const PRIVATE_RESULT_ORAM_BUCKET_VERSION: u16 = 1;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PrivateResultOramError {
    #[error("private result ORAM manifest uses unsupported version {0}")]
    UnsupportedManifestVersion(u16),
    #[error("private result ORAM manifest provider is invalid")]
    InvalidProvider,
    #[error("private result ORAM manifest binding is invalid")]
    InvalidBinding,
    #[error("private result ORAM manifest field {0} is invalid")]
    InvalidManifestField(&'static str),
    #[error("private result ORAM manifest field {0} does not match runtime context")]
    ManifestContextMismatch(&'static str),
    #[error("private result ORAM manifest signature is missing")]
    MissingManifestSignature,
    #[error("private result ORAM signature uses unsupported algorithm {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("private result ORAM signature key id does not match runtime context")]
    SignatureKeyIdMismatch,
    #[error("private result ORAM signature is malformed")]
    MalformedSignature,
    #[error("private result ORAM manifest signature verification failed")]
    InvalidManifestSignature,
    #[error("private result ORAM commit signature verification failed")]
    InvalidCommitSignature,
    #[error("private result ORAM resource key id is invalid")]
    InvalidResourceKeyId,
    #[error("private result ORAM bucket uses unsupported version {0}")]
    UnsupportedBucketVersion(u16),
    #[error(
        "private result ORAM bucket {bucket_id} is out of range for bucket_count {bucket_count}"
    )]
    BucketOutOfRange { bucket_id: u64, bucket_count: u64 },
    #[error("private result ORAM bucket field {0} is invalid")]
    InvalidBucketField(&'static str),
    #[error("private result ORAM bucket ciphertext exceeds maximum size")]
    BucketOversized,
    #[error("private result ORAM bucket ciphertext_sha256 mismatch")]
    InvalidBucketHash,
    #[error("private result ORAM bucket commitment context mismatch")]
    InvalidBucketCommitment,
    #[error("private result ORAM Merkle tree is empty")]
    EmptyMerkleTree,
    #[error("private result ORAM Merkle root does not match current commitments")]
    MerkleRootMismatch,
    #[error("private result ORAM manifest epoch/root does not match commit old epoch/root")]
    ManifestCommitMismatch,
    #[error(
        "private result ORAM bucket {bucket_id} has stale epoch {actual_epoch}; expected {expected_epoch}"
    )]
    StaleBucketEpoch {
        bucket_id: u64,
        expected_epoch: u64,
        actual_epoch: u64,
    },
    #[error("private result ORAM commit repeats bucket {bucket_id}")]
    DuplicateUpdatedBucket { bucket_id: u64 },
    #[error("private result ORAM commit must update at least one bucket")]
    EmptyCommit,
    #[error("private result ORAM Merkle proof is malformed")]
    InvalidMerkleProof,
    #[error("private result ORAM Merkle proof JSON is malformed")]
    InvalidMerkleProofJson,
    #[error("private result ORAM Merkle proof does not match bucket commitments")]
    MerkleProofMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramManifest {
    pub version: u16,
    pub provider: String,
    pub binding: String,
    pub collection_id: String,
    pub key_id: String,
    pub rk_id: String,
    pub rk_epoch: u64,
    pub oram: OramParams,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub logical_result_count: u64,
    pub dummy_result_count: u64,
    pub owner_signing_key_id: String,
    pub created_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramBucket {
    pub version: u16,
    pub bucket_id: u64,
    pub index_epoch: u64,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub bucket_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

pub const PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND: &str = "merkle_path_batch/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramMerkleProof {
    pub kind: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub leaves: Vec<PrivateResultOramMerkleProofLeaf>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramMerkleProofLeaf {
    pub bucket_id: u64,
    pub leaf_hash: String,
    pub siblings: Vec<PrivateResultOramMerkleSibling>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramMerkleSibling {
    pub level: u32,
    pub position: PrivateResultOramMerkleSiblingPosition,
    pub hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateResultOramMerkleSiblingPosition {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramUploadBundle {
    pub manifest: PrivateResultOramManifest,
    pub manifest_signature: PrivateResultOramSignature,
    pub buckets: Vec<PrivateResultOramBucket>,
}

impl PrivateResultOramUploadBundle {
    pub fn index_epoch(&self) -> u64 {
        self.manifest.index_epoch
    }

    pub fn root_hash(&self) -> &str {
        &self.manifest.root_hash
    }

    pub fn bucket_count(&self) -> u64 {
        self.manifest.bucket_count
    }

    pub fn bucket_commitments(&self) -> Vec<String> {
        self.buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect()
    }

    pub fn validate_initial_upload_contract(&self) -> Result<Vec<String>, PrivateResultOramError> {
        validate_private_result_oram_upload_bundle(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateResultOramEpoch {
    pub epoch: u64,
    pub root_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateResultOramSignatureVerification<'a> {
    pub expected_key_id: &'a str,
    pub public_key: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateResultOramManifestValidationContext<'a> {
    pub expected_collection_id: &'a str,
    pub expected_key_id: &'a str,
    pub expected_rk_id: &'a str,
    pub min_rk_epoch: u64,
    pub max_rk_epoch: u64,
    pub signature_verification: PrivateResultOramSignatureVerification<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateResultOramCommitSignatureContext<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub signing_key_id: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateResultOramBucketValidationContext {
    pub expected_index_epoch: u64,
    pub bucket_count: u64,
    pub max_ciphertext_bytes: usize,
}

impl PrivateResultOramBucketValidationContext {
    pub fn from_manifest(
        manifest: &PrivateResultOramManifest,
        max_ciphertext_bytes: usize,
    ) -> Self {
        Self {
            expected_index_epoch: manifest.index_epoch,
            bucket_count: manifest.bucket_count,
            max_ciphertext_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateResultOramBucketCommitmentContext<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub bucket_id: u64,
    pub index_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateResultOramClientCommitBucketRef {
    pub bucket_id: u64,
    pub ciphertext_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateResultOramCommitPlan {
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub leaf_commitments: Vec<String>,
    pub updated_buckets: Vec<PrivateResultOramClientCommitBucketRef>,
}

impl PrivateResultOramCommitPlan {
    pub fn signature_bucket_refs(&self) -> Vec<PrivateResultOramCommitBucketRef<'_>> {
        self.updated_buckets
            .iter()
            .map(|bucket| PrivateResultOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateResultOramCommitBucketRef<'a> {
    pub bucket_id: u64,
    pub ciphertext_sha256: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateResultOramCommitSignatureInput<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub updated_buckets: &'a [PrivateResultOramCommitBucketRef<'a>],
    pub signature_alg: &'a str,
    pub signature_key_id: &'a str,
}

pub fn validate_private_result_oram_manifest(
    manifest: &PrivateResultOramManifest,
    signature: Option<&PrivateResultOramSignature>,
    context: PrivateResultOramManifestValidationContext<'_>,
) -> Result<PrivateResultOramEpoch, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    validate_manifest_context(manifest, context)?;
    validate_private_result_oram_manifest_signature(
        manifest,
        signature,
        context.signature_verification,
    )?;

    let root_hash = decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(PrivateResultOramEpoch {
        epoch: manifest.index_epoch,
        root_hash,
    })
}

pub fn validate_private_result_oram_manifest_shape(
    manifest: &PrivateResultOramManifest,
) -> Result<(), PrivateResultOramError> {
    if manifest.version != PRIVATE_RESULT_ORAM_MANIFEST_VERSION {
        return Err(PrivateResultOramError::UnsupportedManifestVersion(
            manifest.version,
        ));
    }
    if manifest.provider != PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER {
        return Err(PrivateResultOramError::InvalidProvider);
    }
    if manifest.binding != PRIVATE_RESULT_ORAM_BINDING {
        return Err(PrivateResultOramError::InvalidBinding);
    }
    validate_id(&manifest.collection_id, "collection_id")?;
    validate_resource_id(&manifest.key_id)?;
    validate_resource_id(&manifest.rk_id)?;
    validate_resource_id(&manifest.owner_signing_key_id)?;
    if manifest.oram.bucket_size == 0
        || manifest.oram.block_size_bytes == 0
        || manifest.oram.tree_height == 0
        || manifest.oram.path_batch_size == 0
    {
        return Err(PrivateResultOramError::InvalidManifestField("oram"));
    }
    if manifest.bucket_count == 0 {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }
    let expected_bucket_count = path_oram_bucket_count(manifest.oram.tree_height)
        .ok_or(PrivateResultOramError::InvalidManifestField("oram"))?;
    if manifest.bucket_count != expected_bucket_count {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }
    let capacity = manifest
        .bucket_count
        .checked_mul(u64::from(manifest.oram.bucket_size))
        .ok_or(PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    let result_count = manifest
        .logical_result_count
        .checked_add(manifest.dummy_result_count)
        .ok_or(PrivateResultOramError::InvalidManifestField("result_count"))?;
    if result_count > capacity {
        return Err(PrivateResultOramError::InvalidManifestField("result_count"));
    }
    decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(())
}

fn path_oram_bucket_count(tree_height: u32) -> Option<u64> {
    if tree_height >= 63 {
        return None;
    }
    (1u64 << tree_height)
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
}

pub fn validate_private_result_oram_bucket_shape(
    bucket: &PrivateResultOramBucket,
    context: PrivateResultOramBucketValidationContext,
) -> Result<(), PrivateResultOramError> {
    if bucket.version != PRIVATE_RESULT_ORAM_BUCKET_VERSION {
        return Err(PrivateResultOramError::UnsupportedBucketVersion(
            bucket.version,
        ));
    }
    if bucket.bucket_id >= context.bucket_count {
        return Err(PrivateResultOramError::BucketOutOfRange {
            bucket_id: bucket.bucket_id,
            bucket_count: context.bucket_count,
        });
    }
    if bucket.index_epoch != context.expected_index_epoch {
        return Err(PrivateResultOramError::InvalidBucketField("index_epoch"));
    }
    let max_ciphertext_b64_len = max_base64url_nopad_encoded_len(context.max_ciphertext_bytes)
        .ok_or(PrivateResultOramError::InvalidBucketField(
            "max_ciphertext_bytes",
        ))?;
    if bucket.ciphertext.len() > max_ciphertext_b64_len {
        return Err(PrivateResultOramError::BucketOversized);
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext"))?;
    if ciphertext.len() > context.max_ciphertext_bytes {
        return Err(PrivateResultOramError::BucketOversized);
    }
    let ciphertext_hash = decode_base64url_32(&bucket.ciphertext_sha256, "ciphertext_sha256")
        .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext_sha256"))?;
    let computed_hash: [u8; 32] = Sha256::digest(&ciphertext).into();
    if computed_hash != ciphertext_hash {
        return Err(PrivateResultOramError::InvalidBucketHash);
    }
    decode_base64url_32(&bucket.bucket_commitment, "bucket_commitment")
        .map_err(|_| PrivateResultOramError::InvalidBucketField("bucket_commitment"))?;
    Ok(())
}

fn max_base64url_nopad_encoded_len(byte_len: usize) -> Option<usize> {
    let full_chunks = byte_len / 3;
    let remainder = byte_len % 3;
    full_chunks.checked_mul(4).and_then(|len| {
        len.checked_add(match remainder {
            0 => 0,
            1 => 2,
            2 => 3,
            _ => unreachable!("remainder modulo 3"),
        })
    })
}

pub fn validate_private_result_oram_manifest_signature_shape(
    signature: &PrivateResultOramSignature,
) -> Result<(), PrivateResultOramError> {
    if signature.alg != PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM {
        return Err(PrivateResultOramError::UnsupportedSignatureAlgorithm(
            signature.alg.clone(),
        ));
    }
    validate_resource_id(&signature.key_id)?;
    decode_base64url_64(&signature.sig)?;
    Ok(())
}

pub fn validate_private_result_oram_manifest_signature(
    manifest: &PrivateResultOramManifest,
    signature: Option<&PrivateResultOramSignature>,
    verification: PrivateResultOramSignatureVerification<'_>,
) -> Result<(), PrivateResultOramError> {
    let signature = signature.ok_or(PrivateResultOramError::MissingManifestSignature)?;
    validate_signature_header(
        signature,
        manifest.owner_signing_key_id.as_str(),
        verification,
    )?;
    let signature_bytes = decode_base64url_64(&signature.sig)?;
    let message = private_result_oram_manifest_signature_message(manifest);
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateResultOramError::InvalidManifestSignature)
}

pub fn validate_private_result_oram_commit_signature(
    input: PrivateResultOramCommitSignatureInput<'_>,
    signature: &str,
    verification: PrivateResultOramSignatureVerification<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_signature_fields(input.signature_alg, input.signature_key_id, verification)?;
    if input.updated_buckets.is_empty() {
        return Err(PrivateResultOramError::EmptyCommit);
    }
    for bucket in input.updated_buckets {
        decode_base64url_32(bucket.ciphertext_sha256, "ciphertext_sha256")
            .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext_sha256"))?;
    }
    let signature_bytes = decode_base64url_64(signature)?;
    let message = private_result_oram_commit_signature_message(input);
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateResultOramError::InvalidCommitSignature)
}

pub fn sign_private_result_oram_manifest(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateResultOramManifest,
) -> Result<PrivateResultOramSignature, PrivateResultOramError> {
    validate_resource_id(&manifest.owner_signing_key_id)?;
    let message = private_result_oram_manifest_signature_message(manifest);
    let signature = key_pair.sign(&message);
    Ok(PrivateResultOramSignature {
        alg: PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM.to_string(),
        key_id: manifest.owner_signing_key_id.clone(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn sign_private_result_oram_commit(
    key_pair: &Ed25519KeyPair,
    context: PrivateResultOramCommitSignatureContext<'_>,
    plan: &PrivateResultOramCommitPlan,
) -> Result<PrivateResultOramSignature, PrivateResultOramError> {
    validate_commit_signature_context(context)?;
    if plan.updated_buckets.is_empty() {
        return Err(PrivateResultOramError::EmptyCommit);
    }
    let bucket_refs = plan.signature_bucket_refs();
    let input = PrivateResultOramCommitSignatureInput {
        collection_id: context.collection_id,
        key_id: context.key_id,
        rk_id: context.rk_id,
        rk_epoch: context.rk_epoch,
        old_epoch: plan.old_epoch,
        new_epoch: plan.new_epoch,
        old_root_hash: &plan.old_root_hash,
        new_root_hash: &plan.new_root_hash,
        updated_buckets: &bucket_refs,
        signature_alg: PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM,
        signature_key_id: context.signing_key_id,
    };
    let message = private_result_oram_commit_signature_message(input);
    let signature = key_pair.sign(&message);
    Ok(PrivateResultOramSignature {
        alg: PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM.to_string(),
        key_id: context.signing_key_id.to_string(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn package_private_result_oram_upload_bundle(
    key_pair: &Ed25519KeyPair,
    manifest: PrivateResultOramManifest,
    buckets: Vec<PrivateResultOramBucket>,
) -> Result<PrivateResultOramUploadBundle, PrivateResultOramError> {
    let manifest_signature = sign_private_result_oram_manifest(key_pair, &manifest)?;
    let bundle = PrivateResultOramUploadBundle {
        manifest,
        manifest_signature,
        buckets,
    };
    validate_private_result_oram_upload_bundle(&bundle)?;
    Ok(bundle)
}

pub fn validate_private_result_oram_upload_bundle(
    bundle: &PrivateResultOramUploadBundle,
) -> Result<Vec<String>, PrivateResultOramError> {
    let manifest = &bundle.manifest;
    validate_private_result_oram_manifest_shape(manifest)?;
    let bucket_count = usize::try_from(manifest.bucket_count)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    if bundle.buckets.len() != bucket_count {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }

    let max_ciphertext_bytes = private_result_oram_upload_max_ciphertext_bytes(manifest)?;
    let validation_context =
        PrivateResultOramBucketValidationContext::from_manifest(manifest, max_ciphertext_bytes);
    let mut commitments = Vec::with_capacity(bundle.buckets.len());
    for (expected_bucket_id, bucket) in bundle.buckets.iter().enumerate() {
        if bucket.bucket_id != expected_bucket_id as u64 {
            return Err(PrivateResultOramError::InvalidBucketField("bucket_id"));
        }
        validate_private_result_oram_bucket_shape(bucket, validation_context)?;
        let expected_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch: manifest.index_epoch,
            },
            &bucket.ciphertext_sha256,
        )?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(PrivateResultOramError::InvalidBucketCommitment);
        }
        commitments.push(bucket.bucket_commitment.clone());
    }
    if private_result_oram_merkle_root_for_commitments(&commitments)? != manifest.root_hash {
        return Err(PrivateResultOramError::MerkleRootMismatch);
    }
    Ok(commitments)
}

fn private_result_oram_upload_max_ciphertext_bytes(
    manifest: &PrivateResultOramManifest,
) -> Result<usize, PrivateResultOramError> {
    let block_size = usize::try_from(manifest.oram.block_size_bytes)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("block_size_bytes"))?;
    let bucket_size = usize::try_from(manifest.oram.bucket_size)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_size"))?;
    block_size
        .checked_mul(bucket_size)
        .and_then(|size| size.checked_add(4096))
        .ok_or(PrivateResultOramError::InvalidManifestField("oram"))
}

pub fn refresh_private_result_oram_manifest_for_commit(
    manifest: &PrivateResultOramManifest,
    plan: &PrivateResultOramCommitPlan,
) -> Result<PrivateResultOramManifest, PrivateResultOramError> {
    if manifest.index_epoch != plan.old_epoch || manifest.root_hash != plan.old_root_hash {
        return Err(PrivateResultOramError::ManifestCommitMismatch);
    }
    if plan.new_epoch <= plan.old_epoch {
        return Err(PrivateResultOramError::InvalidManifestField("new_epoch"));
    }
    decode_base64url_32(&plan.new_root_hash, "root_hash")?;

    let mut refreshed = manifest.clone();
    refreshed.index_epoch = plan.new_epoch;
    refreshed.root_hash = plan.new_root_hash.clone();
    Ok(refreshed)
}

pub fn sign_private_result_oram_manifest_refresh(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateResultOramManifest,
    plan: &PrivateResultOramCommitPlan,
) -> Result<(PrivateResultOramManifest, PrivateResultOramSignature), PrivateResultOramError> {
    let refreshed = refresh_private_result_oram_manifest_for_commit(manifest, plan)?;
    let signature = sign_private_result_oram_manifest(key_pair, &refreshed)?;
    Ok((refreshed, signature))
}

pub fn private_result_oram_manifest_signature_message(
    manifest: &PrivateResultOramManifest,
) -> Vec<u8> {
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_RESULT_ORAM_MANIFEST_SIGNATURE_DOMAIN.as_bytes(),
    );
    push_u16(&mut message, manifest.version);
    push_str(&mut message, &manifest.provider);
    push_str(&mut message, &manifest.binding);
    push_str(&mut message, &manifest.collection_id);
    push_str(&mut message, &manifest.key_id);
    push_str(&mut message, &manifest.rk_id);
    push_u64(&mut message, manifest.rk_epoch);
    push_str(&mut message, manifest.oram.kind.as_str());
    push_u32(&mut message, manifest.oram.bucket_size);
    push_u32(&mut message, manifest.oram.block_size_bytes);
    push_u32(&mut message, manifest.oram.tree_height);
    push_u32(&mut message, manifest.oram.path_batch_size);
    push_u64(&mut message, manifest.index_epoch);
    push_str(&mut message, &manifest.root_hash);
    push_u64(&mut message, manifest.bucket_count);
    push_u64(&mut message, manifest.logical_result_count);
    push_u64(&mut message, manifest.dummy_result_count);
    push_str(&mut message, &manifest.owner_signing_key_id);
    message
}

pub fn private_result_oram_commit_signature_message(
    input: PrivateResultOramCommitSignatureInput<'_>,
) -> Vec<u8> {
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_RESULT_ORAM_COMMIT_SIGNATURE_DOMAIN.as_bytes(),
    );
    push_str(&mut message, input.collection_id);
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

pub fn private_result_oram_bucket_commitment(
    context: PrivateResultOramBucketCommitmentContext<'_>,
    ciphertext_sha256: &str,
) -> Result<String, PrivateResultOramError> {
    validate_id(context.collection_id, "collection_id")?;
    validate_resource_id(context.key_id)?;
    validate_resource_id(context.rk_id)?;
    let ciphertext_sha256 = decode_base64url_32(ciphertext_sha256, "ciphertext_sha256")
        .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext_sha256"))?;

    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_RESULT_ORAM_BUCKET_COMMITMENT_DOMAIN.as_bytes(),
    );
    push_str(&mut message, context.collection_id);
    push_str(&mut message, context.key_id);
    push_str(&mut message, context.rk_id);
    push_u64(&mut message, context.rk_epoch);
    push_u64(&mut message, context.bucket_id);
    push_u64(&mut message, context.index_epoch);
    message.extend_from_slice(&ciphertext_sha256);
    Ok(BASE64URL_NOPAD.encode(Sha256::digest(&message).as_ref()))
}

pub fn private_result_oram_merkle_root_for_commitments(
    commitments: &[String],
) -> Result<String, PrivateResultOramError> {
    let levels = private_result_oram_merkle_levels(commitments)?;
    let root = levels
        .last()
        .and_then(|level| level.first())
        .ok_or(PrivateResultOramError::EmptyMerkleTree)?;
    Ok(BASE64URL_NOPAD.encode(root))
}

pub fn verify_private_result_oram_merkle_proof_json(
    proof_value: &str,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    buckets: &[PrivateResultOramBucket],
) -> Result<(), PrivateResultOramError> {
    if proof_value.len() > PRIVATE_RESULT_ORAM_MERKLE_PROOF_JSON_MAX_BYTES {
        return Err(PrivateResultOramError::InvalidMerkleProofJson);
    }
    let proof: PrivateResultOramMerkleProof = serde_json::from_str(proof_value)
        .map_err(|_| PrivateResultOramError::InvalidMerkleProofJson)?;
    verify_private_result_oram_merkle_proof(
        &proof,
        expected_epoch,
        expected_root_hash,
        expected_bucket_count,
        buckets,
    )
}

pub fn verify_private_result_oram_merkle_proof(
    proof: &PrivateResultOramMerkleProof,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    buckets: &[PrivateResultOramBucket],
) -> Result<(), PrivateResultOramError> {
    if expected_bucket_count == 0
        || proof.kind != PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND
        || proof.index_epoch != expected_epoch
        || proof.bucket_count != expected_bucket_count
        || proof.leaves.len() != buckets.len()
    {
        return Err(PrivateResultOramError::InvalidMerkleProof);
    }

    let expected_root = decode_merkle_proof_hash(expected_root_hash)?;
    let proof_root = decode_merkle_proof_hash(&proof.root_hash)?;
    if proof_root != expected_root {
        return Err(PrivateResultOramError::MerkleProofMismatch);
    }

    let mut buckets_by_id = std::collections::BTreeMap::new();
    for bucket in buckets {
        if bucket.version != PRIVATE_RESULT_ORAM_BUCKET_VERSION
            || bucket.index_epoch > expected_epoch
            || bucket.bucket_id >= expected_bucket_count
        {
            return Err(PrivateResultOramError::InvalidMerkleProof);
        }
        decode_bucket_commitment(&bucket.bucket_commitment)?;
        if let Some(existing) = buckets_by_id.insert(bucket.bucket_id, bucket) {
            if existing != bucket {
                return Err(PrivateResultOramError::InvalidMerkleProof);
            }
        }
    }

    let mut leaves_by_id = std::collections::BTreeMap::new();
    for leaf in &proof.leaves {
        if leaf.bucket_id >= expected_bucket_count {
            return Err(PrivateResultOramError::InvalidMerkleProof);
        }
        if let Some(existing) = leaves_by_id.insert(leaf.bucket_id, leaf) {
            if existing != leaf {
                return Err(PrivateResultOramError::InvalidMerkleProof);
            }
            continue;
        }
        let Some(bucket) = buckets_by_id.get(&leaf.bucket_id) else {
            return Err(PrivateResultOramError::MerkleProofMismatch);
        };
        if bucket.bucket_commitment != leaf.leaf_hash {
            return Err(PrivateResultOramError::MerkleProofMismatch);
        }

        let mut node_hash = decode_merkle_proof_hash(&leaf.leaf_hash)?;
        let mut index = leaf.bucket_id;
        for (expected_level, sibling) in leaf.siblings.iter().enumerate() {
            if sibling.level != expected_level as u32 {
                return Err(PrivateResultOramError::InvalidMerkleProof);
            }
            let sibling_hash = decode_merkle_proof_hash(&sibling.hash)?;
            let expected_position = if index % 2 == 0 {
                PrivateResultOramMerkleSiblingPosition::Right
            } else {
                PrivateResultOramMerkleSiblingPosition::Left
            };
            if sibling.position != expected_position {
                return Err(PrivateResultOramError::InvalidMerkleProof);
            }
            node_hash = match sibling.position {
                PrivateResultOramMerkleSiblingPosition::Left => {
                    private_result_oram_merkle_parent_hash(&sibling_hash, &node_hash)
                }
                PrivateResultOramMerkleSiblingPosition::Right => {
                    private_result_oram_merkle_parent_hash(&node_hash, &sibling_hash)
                }
            };
            index /= 2;
        }
        if node_hash != expected_root {
            return Err(PrivateResultOramError::MerkleProofMismatch);
        }
    }
    for bucket_id in buckets_by_id.keys() {
        if !leaves_by_id.contains_key(bucket_id) {
            return Err(PrivateResultOramError::MerkleProofMismatch);
        }
    }

    Ok(())
}

pub fn plan_private_result_oram_commit(
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateResultOramBucket],
) -> Result<PrivateResultOramCommitPlan, PrivateResultOramError> {
    if new_epoch <= old_epoch {
        return Err(PrivateResultOramError::InvalidManifestField("new_epoch"));
    }
    if updated_buckets.is_empty() {
        return Err(PrivateResultOramError::EmptyCommit);
    }
    let computed_old_root =
        private_result_oram_merkle_root_for_commitments(current_leaf_commitments)?;
    if computed_old_root != old_root_hash {
        return Err(PrivateResultOramError::MerkleRootMismatch);
    }

    let bucket_count = u64::try_from(current_leaf_commitments.len())
        .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    let mut next_leaf_commitments = current_leaf_commitments.to_vec();
    let mut seen_bucket_ids = std::collections::BTreeSet::new();
    let mut commit_bucket_refs = Vec::with_capacity(updated_buckets.len());

    for bucket in updated_buckets {
        if bucket.version != PRIVATE_RESULT_ORAM_BUCKET_VERSION {
            return Err(PrivateResultOramError::UnsupportedBucketVersion(
                bucket.version,
            ));
        }
        if bucket.index_epoch != new_epoch {
            return Err(PrivateResultOramError::StaleBucketEpoch {
                bucket_id: bucket.bucket_id,
                expected_epoch: new_epoch,
                actual_epoch: bucket.index_epoch,
            });
        }
        if bucket.bucket_id >= bucket_count {
            return Err(PrivateResultOramError::BucketOutOfRange {
                bucket_id: bucket.bucket_id,
                bucket_count,
            });
        }
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateResultOramError::DuplicateUpdatedBucket {
                bucket_id: bucket.bucket_id,
            });
        }
        decode_base64url_32(&bucket.ciphertext_sha256, "ciphertext_sha256")
            .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext_sha256"))?;
        decode_bucket_commitment(&bucket.bucket_commitment)?;

        let bucket_index = usize::try_from(bucket.bucket_id)
            .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_count"))?;
        next_leaf_commitments[bucket_index] = bucket.bucket_commitment.clone();
        commit_bucket_refs.push(PrivateResultOramClientCommitBucketRef {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        });
    }

    let new_root_hash = private_result_oram_merkle_root_for_commitments(&next_leaf_commitments)?;
    Ok(PrivateResultOramCommitPlan {
        old_epoch,
        new_epoch,
        old_root_hash: old_root_hash.to_string(),
        new_root_hash,
        leaf_commitments: next_leaf_commitments,
        updated_buckets: commit_bucket_refs,
    })
}

pub fn plan_private_result_oram_commit_for_manifest(
    manifest: &PrivateResultOramManifest,
    new_epoch: u64,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateResultOramBucket],
) -> Result<PrivateResultOramCommitPlan, PrivateResultOramError> {
    let manifest_bucket_count = usize::try_from(manifest.bucket_count)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    if current_leaf_commitments.len() != manifest_bucket_count {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }
    let plan = plan_private_result_oram_commit(
        manifest.index_epoch,
        new_epoch,
        &manifest.root_hash,
        current_leaf_commitments,
        updated_buckets,
    )?;
    for bucket in updated_buckets {
        let expected_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch: new_epoch,
            },
            &bucket.ciphertext_sha256,
        )?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(PrivateResultOramError::InvalidBucketCommitment);
        }
    }
    Ok(plan)
}

fn validate_id(value: &str, field: &'static str) -> Result<(), PrivateResultOramError> {
    if value.is_empty()
        || value.len() > 255
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(PrivateResultOramError::InvalidManifestField(field));
    }
    Ok(())
}

fn validate_resource_id(value: &str) -> Result<(), PrivateResultOramError> {
    validate_resource_key_id(value).map_err(|_| PrivateResultOramError::InvalidResourceKeyId)
}

fn validate_manifest_context(
    manifest: &PrivateResultOramManifest,
    context: PrivateResultOramManifestValidationContext<'_>,
) -> Result<(), PrivateResultOramError> {
    if manifest.collection_id != context.expected_collection_id {
        return Err(PrivateResultOramError::ManifestContextMismatch(
            "collection_id",
        ));
    }
    if manifest.key_id != context.expected_key_id {
        return Err(PrivateResultOramError::ManifestContextMismatch("key_id"));
    }
    if manifest.rk_id != context.expected_rk_id {
        return Err(PrivateResultOramError::ManifestContextMismatch("rk_id"));
    }
    if manifest.rk_epoch < context.min_rk_epoch || manifest.rk_epoch > context.max_rk_epoch {
        return Err(PrivateResultOramError::ManifestContextMismatch("rk_epoch"));
    }
    Ok(())
}

fn validate_commit_signature_context(
    context: PrivateResultOramCommitSignatureContext<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_id(context.collection_id, "collection_id")?;
    validate_resource_id(context.key_id)?;
    validate_resource_id(context.rk_id)?;
    validate_resource_id(context.signing_key_id)?;
    Ok(())
}

fn validate_signature_header(
    signature: &PrivateResultOramSignature,
    expected_owner_key_id: &str,
    verification: PrivateResultOramSignatureVerification<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_signature_fields(&signature.alg, &signature.key_id, verification)?;
    decode_base64url_64(&signature.sig)?;
    if signature.key_id != expected_owner_key_id {
        return Err(PrivateResultOramError::SignatureKeyIdMismatch);
    }
    Ok(())
}

fn validate_signature_fields(
    alg: &str,
    key_id: &str,
    verification: PrivateResultOramSignatureVerification<'_>,
) -> Result<(), PrivateResultOramError> {
    if alg != PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM {
        return Err(PrivateResultOramError::UnsupportedSignatureAlgorithm(
            alg.to_string(),
        ));
    }
    validate_resource_id(key_id)?;
    if key_id != verification.expected_key_id {
        return Err(PrivateResultOramError::SignatureKeyIdMismatch);
    }
    Ok(())
}

fn decode_base64url_32(
    value: &str,
    field: &'static str,
) -> Result<[u8; 32], PrivateResultOramError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateResultOramError::InvalidManifestField(field));
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidManifestField(field))?;
    bytes
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidManifestField(field))
}

fn decode_base64url_64(value: &str) -> Result<[u8; 64], PrivateResultOramError> {
    if value.len() != BASE64URL_NOPAD_64_BYTE_LEN {
        return Err(PrivateResultOramError::MalformedSignature);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateResultOramError::MalformedSignature)?;
    bytes
        .try_into()
        .map_err(|_| PrivateResultOramError::MalformedSignature)
}

fn decode_bucket_commitment(value: &str) -> Result<[u8; 32], PrivateResultOramError> {
    decode_base64url_32(value, "bucket_commitment")
        .map_err(|_| PrivateResultOramError::InvalidBucketField("bucket_commitment"))
}

fn decode_merkle_proof_hash(value: &str) -> Result<[u8; 32], PrivateResultOramError> {
    decode_base64url_32(value, "merkle_proof_hash")
        .map_err(|_| PrivateResultOramError::InvalidMerkleProof)
}

fn private_result_oram_merkle_levels(
    commitments: &[String],
) -> Result<Vec<Vec<[u8; 32]>>, PrivateResultOramError> {
    if commitments.is_empty() {
        return Err(PrivateResultOramError::EmptyMerkleTree);
    }
    let mut leaves = commitments
        .iter()
        .map(|commitment| decode_bucket_commitment(commitment))
        .collect::<Result<Vec<_>, _>>()?;
    let padded_len = leaves
        .len()
        .checked_next_power_of_two()
        .ok_or(PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    leaves.resize(padded_len, [0; 32]);

    let mut levels = vec![leaves];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let previous = levels.last().expect("checked above");
        let mut next = Vec::with_capacity(previous.len() / 2);
        for pair in previous.chunks_exact(2) {
            next.push(private_result_oram_merkle_parent_hash(&pair[0], &pair[1]));
        }
        levels.push(next);
    }
    Ok(levels)
}

fn private_result_oram_merkle_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn push_domain(message: &mut Vec<u8>, domain: &[u8]) {
    message.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    message.extend_from_slice(domain);
}

fn push_str(message: &mut Vec<u8>, value: &str) {
    message.extend_from_slice(&(value.len() as u64).to_be_bytes());
    message.extend_from_slice(value.as_bytes());
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
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;
    use crate::private_hnsw_oram::OramKind;

    fn fixture_manifest() -> PrivateResultOramManifest {
        PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            key_id: "tenant-a/payload-private-rk".to_string(),
            rk_id: "tenant-a/payload-private-rk".to_string(),
            rk_epoch: 7,
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 8192,
                tree_height: 24,
                path_batch_size: 8,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: (1 << 25) - 1,
            logical_result_count: 700,
            dummy_result_count: 324,
            owner_signing_key_id: "tenant-a/private-result-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn deterministic_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap()
    }

    fn fixture_context<'a>(
        public_key: &'a [u8],
        key_id: &'a str,
    ) -> PrivateResultOramManifestValidationContext<'a> {
        PrivateResultOramManifestValidationContext {
            expected_collection_id: "collection-uuid-1",
            expected_key_id: "tenant-a/payload-private-rk",
            expected_rk_id: "tenant-a/payload-private-rk",
            min_rk_epoch: 7,
            max_rk_epoch: 7,
            signature_verification: PrivateResultOramSignatureVerification {
                expected_key_id: key_id,
                public_key,
            },
        }
    }

    fn sign_b64(key_pair: &Ed25519KeyPair, message: &[u8]) -> String {
        BASE64URL_NOPAD.encode(key_pair.sign(message).as_ref())
    }

    fn bucket_validation_context() -> PrivateResultOramBucketValidationContext {
        let manifest = PrivateResultOramManifest {
            bucket_count: 16,
            ..fixture_manifest()
        };
        PrivateResultOramBucketValidationContext::from_manifest(&manifest, 128)
    }

    fn fixture_bucket() -> PrivateResultOramBucket {
        let ciphertext = [3; 32];
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(ciphertext).as_ref());
        PrivateResultOramBucket {
            version: 1,
            bucket_id: 9,
            index_epoch: 42,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256: ciphertext_sha256.clone(),
            bucket_commitment: fixture_bucket_commitment(9, 42, &ciphertext_sha256),
        }
    }

    fn fixture_commit_bucket(
        bucket_id: u64,
        epoch: u64,
        commitment_byte: u8,
    ) -> PrivateResultOramBucket {
        let ciphertext = [commitment_byte; 32];
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(ciphertext).as_ref());
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256: ciphertext_sha256.clone(),
            bucket_commitment: fixture_bucket_commitment(bucket_id, epoch, &ciphertext_sha256),
        }
    }

    fn commitment(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn fixture_bucket_commitment(bucket_id: u64, epoch: u64, ciphertext_sha256: &str) -> String {
        private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/payload-private-rk",
                rk_id: "tenant-a/payload-private-rk",
                rk_epoch: 7,
                bucket_id,
                index_epoch: epoch,
            },
            ciphertext_sha256,
        )
        .unwrap()
    }

    fn fixture_bucket_set() -> Vec<PrivateResultOramBucket> {
        (0..3)
            .map(|bucket_id| fixture_commit_bucket(bucket_id, 42, bucket_id as u8 + 1))
            .collect()
    }

    #[test]
    fn manifest_signature_message_is_stable() {
        let digest = Sha256::digest(private_result_oram_manifest_signature_message(
            &fixture_manifest(),
        ));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "mOy8vej616osyutILgm6MwoTDwZhq7tau_9wyHgaYGA"
        );
    }

    #[test]
    fn commit_signature_message_is_stable() {
        let buckets = [
            PrivateResultOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateResultOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let input = PrivateResultOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };

        let digest = Sha256::digest(private_result_oram_commit_signature_message(input));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "Dsso6H8kYZbPZHYG49vdmgVaLa02M2fP47VCQH4wPtM"
        );
    }

    #[test]
    fn manifest_shape_rejects_wrong_provider_and_root() {
        let mut manifest = fixture_manifest();
        validate_private_result_oram_manifest_shape(&manifest).unwrap();

        manifest.provider = "payload/client-aead@v1".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_shape(&manifest),
            Err(PrivateResultOramError::InvalidProvider)
        );

        manifest = fixture_manifest();
        manifest.root_hash = "not-base64url".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_shape(&manifest),
            Err(PrivateResultOramError::InvalidManifestField("root_hash"))
        );

        manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.bucket_count = 3;
        manifest.oram.bucket_size = 1;
        manifest.logical_result_count = 4;
        manifest.dummy_result_count = 0;
        assert_eq!(
            validate_private_result_oram_manifest_shape(&manifest),
            Err(PrivateResultOramError::InvalidManifestField("result_count"))
        );

        manifest = fixture_manifest();
        manifest.bucket_count -= 1;
        assert_eq!(
            validate_private_result_oram_manifest_shape(&manifest),
            Err(PrivateResultOramError::InvalidManifestField("bucket_count"))
        );
    }

    #[test]
    fn signature_shape_rejects_wrong_alg_and_malformed_signature() {
        let mut signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-result-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[9; 64]),
        };
        validate_private_result_oram_manifest_signature_shape(&signature).unwrap();

        signature.alg = "rsa-pss".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_signature_shape(&signature),
            Err(PrivateResultOramError::UnsupportedSignatureAlgorithm(
                "rsa-pss".to_string()
            ))
        );

        signature.alg = "ed25519".to_string();
        signature.sig = "short".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_signature_shape(&signature),
            Err(PrivateResultOramError::MalformedSignature)
        );
    }

    #[test]
    fn bucket_shape_validates_hash_range_and_size() {
        let bucket = fixture_bucket();
        validate_private_result_oram_bucket_shape(&bucket, bucket_validation_context()).unwrap();

        let mut out_of_range = bucket.clone();
        out_of_range.bucket_id = 16;
        assert_eq!(
            validate_private_result_oram_bucket_shape(&out_of_range, bucket_validation_context()),
            Err(PrivateResultOramError::BucketOutOfRange {
                bucket_id: 16,
                bucket_count: 16,
            })
        );

        let mut hash_mismatch = bucket.clone();
        hash_mismatch.ciphertext_sha256 = BASE64URL_NOPAD.encode(&[5; 32]);
        assert_eq!(
            validate_private_result_oram_bucket_shape(&hash_mismatch, bucket_validation_context()),
            Err(PrivateResultOramError::InvalidBucketHash)
        );

        let mut oversized = bucket;
        oversized.ciphertext = BASE64URL_NOPAD.encode(&[7; 129]);
        oversized.ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest([7; 129]).as_ref());
        assert_eq!(
            validate_private_result_oram_bucket_shape(&oversized, bucket_validation_context()),
            Err(PrivateResultOramError::BucketOversized)
        );

        let mut encoded_oversized = fixture_bucket();
        encoded_oversized.ciphertext =
            "A".repeat(max_base64url_nopad_encoded_len(128).unwrap() + 1);
        encoded_oversized.ciphertext_sha256 = BASE64URL_NOPAD.encode(&[9; 32]);
        assert_eq!(
            validate_private_result_oram_bucket_shape(
                &encoded_oversized,
                bucket_validation_context()
            ),
            Err(PrivateResultOramError::BucketOversized)
        );
    }

    #[test]
    fn merkle_root_for_commitments_is_stable_and_rejects_bad_leaves() {
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&[
                commitment(1),
                commitment(2),
                commitment(3),
            ])
            .unwrap(),
            "WaBpZZL4P-1d3PL6tJFGletAnWPATB_KlpiiL9p5U5E"
        );
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&[]),
            Err(PrivateResultOramError::EmptyMerkleTree)
        );
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&["bad".to_string()]),
            Err(PrivateResultOramError::InvalidBucketField(
                "bucket_commitment"
            ))
        );
    }

    #[test]
    fn merkle_proof_verifies_bucket_commitments_and_json() {
        let bucket0 = fixture_commit_bucket(0, 42, 1);
        let bucket1 = fixture_commit_bucket(1, 42, 2);
        let root = private_result_oram_merkle_root_for_commitments(&[
            bucket0.bucket_commitment.clone(),
            bucket1.bucket_commitment.clone(),
        ])
        .unwrap();
        let proof = PrivateResultOramMerkleProof {
            kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root.clone(),
            bucket_count: 2,
            leaves: vec![
                PrivateResultOramMerkleProofLeaf {
                    bucket_id: 0,
                    leaf_hash: bucket0.bucket_commitment.clone(),
                    siblings: vec![PrivateResultOramMerkleSibling {
                        level: 0,
                        position: PrivateResultOramMerkleSiblingPosition::Right,
                        hash: bucket1.bucket_commitment.clone(),
                    }],
                },
                PrivateResultOramMerkleProofLeaf {
                    bucket_id: 1,
                    leaf_hash: bucket1.bucket_commitment.clone(),
                    siblings: vec![PrivateResultOramMerkleSibling {
                        level: 0,
                        position: PrivateResultOramMerkleSiblingPosition::Left,
                        hash: bucket0.bucket_commitment.clone(),
                    }],
                },
            ],
        };

        verify_private_result_oram_merkle_proof(
            &proof,
            42,
            &root,
            2,
            &[bucket0.clone(), bucket1.clone()],
        )
        .unwrap();
        verify_private_result_oram_merkle_proof_json(
            &serde_json::to_string(&proof).unwrap(),
            42,
            &root,
            2,
            &[bucket0.clone(), bucket1.clone()],
        )
        .unwrap();

        let duplicate_proof = PrivateResultOramMerkleProof {
            leaves: vec![proof.leaves[0].clone(), proof.leaves[0].clone()],
            ..proof.clone()
        };
        verify_private_result_oram_merkle_proof(
            &duplicate_proof,
            42,
            &root,
            2,
            &[bucket0.clone(), bucket0.clone()],
        )
        .unwrap();

        let mut conflicting_duplicate_bucket = bucket0.clone();
        conflicting_duplicate_bucket.ciphertext =
            BASE64URL_NOPAD.encode(b"conflicting duplicate bucket");
        assert_eq!(
            verify_private_result_oram_merkle_proof(
                &duplicate_proof,
                42,
                &root,
                2,
                &[bucket0.clone(), conflicting_duplicate_bucket],
            ),
            Err(PrivateResultOramError::InvalidMerkleProof)
        );

        let mut conflicting_duplicate_proof = duplicate_proof.clone();
        conflicting_duplicate_proof.leaves[1].leaf_hash = bucket1.bucket_commitment.clone();
        assert_eq!(
            verify_private_result_oram_merkle_proof(
                &conflicting_duplicate_proof,
                42,
                &root,
                2,
                &[bucket0.clone(), bucket0.clone()],
            ),
            Err(PrivateResultOramError::InvalidMerkleProof)
        );

        let mut tampered = proof.clone();
        tampered.leaves[0].leaf_hash = bucket1.bucket_commitment.clone();
        assert_eq!(
            verify_private_result_oram_merkle_proof(&tampered, 42, &root, 2, &[bucket0, bucket1]),
            Err(PrivateResultOramError::MerkleProofMismatch)
        );
        assert_eq!(
            verify_private_result_oram_merkle_proof_json("not-json", 42, &root, 2, &[]),
            Err(PrivateResultOramError::InvalidMerkleProofJson)
        );
        let oversized_proof_json = " ".repeat(PRIVATE_RESULT_ORAM_MERKLE_PROOF_JSON_MAX_BYTES + 1);
        assert_eq!(
            verify_private_result_oram_merkle_proof_json(&oversized_proof_json, 42, &root, 2, &[]),
            Err(PrivateResultOramError::InvalidMerkleProofJson)
        );
    }

    #[test]
    fn commit_plan_updates_merkle_root_and_signature_refs() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9);

        let plan = plan_private_result_oram_commit(
            42,
            43,
            &old_root,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        assert_eq!(plan.old_epoch, 42);
        assert_eq!(plan.new_epoch, 43);
        assert_eq!(plan.old_root_hash, old_root);
        assert_ne!(plan.new_root_hash, plan.old_root_hash);
        assert_eq!(plan.leaf_commitments[2], updated_bucket.bucket_commitment);
        assert_eq!(
            plan.updated_buckets,
            vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }]
        );
        assert_eq!(
            plan.signature_bucket_refs(),
            vec![PrivateResultOramCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.as_str(),
            }]
        );
    }

    #[test]
    fn commit_plan_for_manifest_rejects_bucket_commitment_context_mismatch() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let manifest = PrivateResultOramManifest {
            root_hash: old_root.clone(),
            bucket_count: leaf_commitments.len() as u64,
            ..fixture_manifest()
        };
        let updated_bucket = fixture_commit_bucket(2, 43, 9);

        let plan = plan_private_result_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();
        assert_eq!(plan.old_epoch, manifest.index_epoch);
        assert_eq!(plan.old_root_hash, old_root);
        assert_eq!(plan.leaf_commitments[2], updated_bucket.bucket_commitment);

        let mut wrong_commitment = updated_bucket;
        wrong_commitment.bucket_commitment = commitment(99);
        assert_eq!(
            plan_private_result_oram_commit_for_manifest(
                &manifest,
                43,
                &leaf_commitments,
                std::slice::from_ref(&wrong_commitment),
            ),
            Err(PrivateResultOramError::InvalidBucketCommitment)
        );

        let wrong_bucket_count = PrivateResultOramManifest {
            bucket_count: 3,
            ..manifest
        };
        assert_eq!(
            plan_private_result_oram_commit_for_manifest(
                &wrong_bucket_count,
                43,
                &leaf_commitments,
                std::slice::from_ref(&wrong_commitment),
            ),
            Err(PrivateResultOramError::InvalidManifestField("bucket_count",))
        );
    }

    #[test]
    fn commit_plan_rejects_stale_duplicate_out_of_range_and_root_mismatch() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9);

        assert_eq!(
            plan_private_result_oram_commit(42, 43, &old_root, &leaf_commitments, &[]),
            Err(PrivateResultOramError::EmptyCommit)
        );

        assert_eq!(
            plan_private_result_oram_commit(
                42,
                43,
                &commitment(99),
                &leaf_commitments,
                std::slice::from_ref(&updated_bucket),
            ),
            Err(PrivateResultOramError::MerkleRootMismatch)
        );

        let stale_bucket = fixture_commit_bucket(2, 42, 9);
        assert_eq!(
            plan_private_result_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&stale_bucket),
            ),
            Err(PrivateResultOramError::StaleBucketEpoch {
                bucket_id: 2,
                expected_epoch: 43,
                actual_epoch: 42,
            })
        );

        assert_eq!(
            plan_private_result_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                &[updated_bucket.clone(), updated_bucket.clone()],
            ),
            Err(PrivateResultOramError::DuplicateUpdatedBucket { bucket_id: 2 })
        );

        let out_of_range = fixture_commit_bucket(4, 43, 9);
        assert_eq!(
            plan_private_result_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&out_of_range),
            ),
            Err(PrivateResultOramError::BucketOutOfRange {
                bucket_id: 4,
                bucket_count: 4,
            })
        );
    }

    #[test]
    fn commit_plan_can_be_signed_and_verified_by_server_validator() {
        let key_pair = deterministic_key_pair();
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9);
        let plan = plan_private_result_oram_commit(
            42,
            43,
            &old_root,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        let signature = sign_private_result_oram_commit(
            &key_pair,
            PrivateResultOramCommitSignatureContext {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/payload-private-rk",
                rk_id: "tenant-a/payload-private-rk",
                rk_epoch: 7,
                signing_key_id: "tenant-a/private-result-signing-v1",
            },
            &plan,
        )
        .unwrap();

        let bucket_refs = plan.signature_bucket_refs();
        validate_private_result_oram_commit_signature(
            PrivateResultOramCommitSignatureInput {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/payload-private-rk",
                rk_id: "tenant-a/payload-private-rk",
                rk_epoch: 7,
                old_epoch: plan.old_epoch,
                new_epoch: plan.new_epoch,
                old_root_hash: &plan.old_root_hash,
                new_root_hash: &plan.new_root_hash,
                updated_buckets: &bucket_refs,
                signature_alg: &signature.alg,
                signature_key_id: &signature.key_id,
            },
            &signature.sig,
            PrivateResultOramSignatureVerification {
                expected_key_id: "tenant-a/private-result-signing-v1",
                public_key: key_pair.public_key().as_ref(),
            },
        )
        .unwrap();

        let empty_plan = PrivateResultOramCommitPlan {
            old_epoch: plan.old_epoch,
            new_epoch: plan.new_epoch,
            old_root_hash: plan.old_root_hash.clone(),
            new_root_hash: plan.old_root_hash.clone(),
            leaf_commitments: plan.leaf_commitments.clone(),
            updated_buckets: Vec::new(),
        };
        assert_eq!(
            sign_private_result_oram_commit(
                &key_pair,
                PrivateResultOramCommitSignatureContext {
                    collection_id: "collection-uuid-1",
                    key_id: "tenant-a/payload-private-rk",
                    rk_id: "tenant-a/payload-private-rk",
                    rk_epoch: 7,
                    signing_key_id: "tenant-a/private-result-signing-v1",
                },
                &empty_plan,
            ),
            Err(PrivateResultOramError::EmptyCommit)
        );
    }

    #[test]
    fn manifest_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let mut manifest = fixture_manifest();
        let signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(
                &key_pair,
                &private_result_oram_manifest_signature_message(&manifest),
            ),
        };
        let verification = PrivateResultOramSignatureVerification {
            expected_key_id: signature.key_id.as_str(),
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_result_oram_manifest_signature(&manifest, Some(&signature), verification)
            .unwrap();

        manifest.index_epoch += 1;
        assert_eq!(
            validate_private_result_oram_manifest_signature(
                &manifest,
                Some(&signature),
                verification,
            ),
            Err(PrivateResultOramError::InvalidManifestSignature)
        );
        assert_eq!(
            validate_private_result_oram_manifest_signature(&manifest, None, verification),
            Err(PrivateResultOramError::MissingManifestSignature)
        );
    }

    #[test]
    fn manifest_can_be_signed_and_verified_by_server_validator() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = sign_private_result_oram_manifest(&key_pair, &manifest).unwrap();

        let epoch = validate_private_result_oram_manifest(
            &manifest,
            Some(&signature),
            fixture_context(key_pair.public_key().as_ref(), &signature.key_id),
        )
        .unwrap();

        assert_eq!(epoch.epoch, 42);
        assert_eq!(epoch.root_hash, [42; 32]);
    }

    #[test]
    fn manifest_refresh_for_commit_advances_epoch_root_and_resigns() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let plan = PrivateResultOramCommitPlan {
            old_epoch: manifest.index_epoch,
            new_epoch: manifest.index_epoch + 1,
            old_root_hash: manifest.root_hash.clone(),
            new_root_hash: commitment(43),
            leaf_commitments: vec![commitment(1), commitment(2)],
            updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: 1,
                ciphertext_sha256: commitment(9),
            }],
        };

        let refreshed = refresh_private_result_oram_manifest_for_commit(&manifest, &plan).unwrap();
        assert_eq!(refreshed.index_epoch, plan.new_epoch);
        assert_eq!(refreshed.root_hash, plan.new_root_hash);
        assert_eq!(refreshed.collection_id, manifest.collection_id);
        assert_eq!(refreshed.bucket_count, manifest.bucket_count);
        assert_eq!(
            refreshed.logical_result_count,
            manifest.logical_result_count
        );
        assert_eq!(refreshed.dummy_result_count, manifest.dummy_result_count);

        let (signed_manifest, signature) =
            sign_private_result_oram_manifest_refresh(&key_pair, &manifest, &plan).unwrap();
        assert_eq!(signed_manifest, refreshed);
        assert_eq!(signature.key_id, signed_manifest.owner_signing_key_id);
        let epoch = validate_private_result_oram_manifest(
            &signed_manifest,
            Some(&signature),
            fixture_context(key_pair.public_key().as_ref(), &signature.key_id),
        )
        .unwrap();
        assert_eq!(epoch.epoch, 43);
        assert_eq!(epoch.root_hash, [43; 32]);

        let mut stale_plan = plan.clone();
        stale_plan.old_root_hash = commitment(99);
        assert_eq!(
            refresh_private_result_oram_manifest_for_commit(&manifest, &stale_plan),
            Err(PrivateResultOramError::ManifestCommitMismatch)
        );
    }

    #[test]
    fn upload_bundle_packages_signed_manifest_and_buckets() {
        let key_pair = deterministic_key_pair();
        let buckets = fixture_bucket_set();
        let root_hash = private_result_oram_merkle_root_for_commitments(
            &buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let manifest = PrivateResultOramManifest {
            root_hash: root_hash.clone(),
            bucket_count: buckets.len() as u64,
            logical_result_count: 3,
            dummy_result_count: 0,
            oram: OramParams {
                tree_height: 1,
                ..fixture_manifest().oram
            },
            ..fixture_manifest()
        };

        let bundle =
            package_private_result_oram_upload_bundle(&key_pair, manifest.clone(), buckets.clone())
                .unwrap();

        assert_eq!(bundle.index_epoch(), 42);
        assert_eq!(bundle.root_hash(), root_hash);
        assert_eq!(bundle.bucket_count(), 3);
        assert_eq!(bundle.buckets, buckets);
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&bundle.bucket_commitments()).unwrap(),
            root_hash
        );
        let ordered_commitments = bundle.validate_initial_upload_contract().unwrap();
        assert_eq!(ordered_commitments, bundle.bucket_commitments());

        let encoded = serde_json::to_string(&bundle).unwrap();
        let decoded: PrivateResultOramUploadBundle = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, bundle);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&decoded).unwrap(),
            ordered_commitments
        );

        validate_private_result_oram_manifest(
            &decoded.manifest,
            Some(&decoded.manifest_signature),
            fixture_context(
                key_pair.public_key().as_ref(),
                &decoded.manifest_signature.key_id,
            ),
        )
        .unwrap();

        let mut incomplete = decoded.clone();
        incomplete.buckets.pop();
        assert_eq!(
            validate_private_result_oram_upload_bundle(&incomplete),
            Err(PrivateResultOramError::InvalidManifestField("bucket_count"))
        );

        let mut unordered = decoded.clone();
        unordered.buckets.swap(0, 1);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&unordered),
            Err(PrivateResultOramError::InvalidBucketField("bucket_id"))
        );

        let mut wrong_hash = decoded.clone();
        wrong_hash.buckets[0].ciphertext_sha256 = commitment(99);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&wrong_hash),
            Err(PrivateResultOramError::InvalidBucketHash)
        );

        let mut wrong_commitment = decoded.clone();
        wrong_commitment.buckets[0].bucket_commitment = commitment(99);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&wrong_commitment),
            Err(PrivateResultOramError::InvalidBucketCommitment)
        );

        let mut wrong_root = manifest;
        wrong_root.root_hash = commitment(99);
        assert_eq!(
            package_private_result_oram_upload_bundle(&key_pair, wrong_root, buckets),
            Err(PrivateResultOramError::MerkleRootMismatch)
        );
    }

    #[test]
    fn commit_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let buckets = [PrivateResultOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
        }];
        let input = PrivateResultOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };
        let signature = sign_b64(
            &key_pair,
            &private_result_oram_commit_signature_message(input),
        );
        let verification = PrivateResultOramSignatureVerification {
            expected_key_id: "tenant-a/private-result-signing-v1",
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_result_oram_commit_signature(input, &signature, verification).unwrap();

        let empty_input = PrivateResultOramCommitSignatureInput {
            updated_buckets: &[],
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                empty_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::EmptyCommit)
        );

        let malformed_hash_buckets = [PrivateResultOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: "AAAA",
        }];
        let malformed_hash_input = PrivateResultOramCommitSignatureInput {
            updated_buckets: &malformed_hash_buckets,
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                malformed_hash_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidBucketField(
                "ciphertext_sha256"
            ))
        );

        let tampered = PrivateResultOramCommitSignatureInput {
            new_epoch: 44,
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(tampered, &signature, verification),
            Err(PrivateResultOramError::InvalidCommitSignature)
        );
    }

    #[test]
    fn manifest_validation_binds_context_and_returns_epoch() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(
                &key_pair,
                &private_result_oram_manifest_signature_message(&manifest),
            ),
        };
        let context = fixture_context(key_pair.public_key().as_ref(), &signature.key_id);

        assert_eq!(
            validate_private_result_oram_manifest(&manifest, Some(&signature), context),
            Ok(PrivateResultOramEpoch {
                epoch: 42,
                root_hash: [42; 32],
            })
        );

        let bad_context = PrivateResultOramManifestValidationContext {
            expected_collection_id: "other-collection",
            ..context
        };
        assert_eq!(
            validate_private_result_oram_manifest(&manifest, Some(&signature), bad_context),
            Err(PrivateResultOramError::ManifestContextMismatch(
                "collection_id"
            ))
        );

        let bad_signature_context = PrivateResultOramManifestValidationContext {
            signature_verification: PrivateResultOramSignatureVerification {
                expected_key_id: "tenant-a/other-signing-v1",
                public_key: key_pair.public_key().as_ref(),
            },
            ..context
        };
        assert_eq!(
            validate_private_result_oram_manifest(
                &manifest,
                Some(&signature),
                bad_signature_context,
            ),
            Err(PrivateResultOramError::SignatureKeyIdMismatch)
        );
    }
}
