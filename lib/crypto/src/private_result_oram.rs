use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, UnparsedPublicKey};
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

const PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM: &str = "ed25519";
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;
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
pub struct PrivateResultOramBucketValidationContext {
    pub expected_index_epoch: u64,
    pub bucket_count: u64,
    pub max_ciphertext_bytes: usize,
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
    decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(())
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
    let signature_bytes = decode_base64url_64(signature)?;
    let message = private_result_oram_commit_signature_message(input);
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateResultOramError::InvalidCommitSignature)
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
            bucket_count: 1024,
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
        PrivateResultOramBucketValidationContext {
            expected_index_epoch: 42,
            bucket_count: 16,
            max_ciphertext_bytes: 128,
        }
    }

    fn fixture_bucket() -> PrivateResultOramBucket {
        let ciphertext = [3; 32];
        PrivateResultOramBucket {
            version: 1,
            bucket_id: 9,
            index_epoch: 42,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256: BASE64URL_NOPAD.encode(Sha256::digest(ciphertext).as_ref()),
            bucket_commitment: BASE64URL_NOPAD.encode(&[4; 32]),
        }
    }

    #[test]
    fn manifest_signature_message_is_stable() {
        let digest = Sha256::digest(private_result_oram_manifest_signature_message(
            &fixture_manifest(),
        ));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "nqKPgk8p_NH8xwO78a9YnTapaKCdqFK8Lqhe18Rg9Oc"
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
