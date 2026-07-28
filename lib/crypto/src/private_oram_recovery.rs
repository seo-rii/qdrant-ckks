use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-oram-external-recovery-checkpoint-signature/v1";

pub const PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_VERSION: u16 = 1;
const PRIVATE_ORAM_RECOVERY_SIGNATURE_ALGORITHM: &str = "ed25519";
const PRIVATE_ORAM_RECOVERY_MAX_OWNER_PEERS: usize = 10_000;
const PRIVATE_ORAM_RECOVERY_MAX_SHARDS: usize = 1_000_000;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramRecoveryError {
    #[error("private ORAM recovery checkpoint uses unsupported version")]
    UnsupportedCheckpointVersion(u16),
    #[error("private ORAM recovery checkpoint field is invalid")]
    InvalidCheckpointField(&'static str),
    #[error("private ORAM recovery checkpoint does not match the restore context")]
    CheckpointContextMismatch(&'static str),
    #[error("private ORAM recovery checkpoint signature is missing")]
    MissingCheckpointSignature,
    #[error("private ORAM recovery checkpoint signature uses unsupported algorithm")]
    UnsupportedSignatureAlgorithm(String),
    #[error("private ORAM recovery checkpoint signature key id does not match")]
    SignatureKeyIdMismatch,
    #[error("private ORAM recovery checkpoint signature is malformed")]
    MalformedSignature,
    #[error("private ORAM recovery checkpoint signature verification failed")]
    InvalidCheckpointSignature,
}

impl Debug for PrivateOramRecoveryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateOramRecoveryError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramExternalRecoveryCheckpoint {
    pub version: u16,
    pub collection_id: String,
    pub backup_generation: u64,
    pub source_peer_id: u64,
    pub source_shard_ids: Vec<u32>,
    pub layout_generation: u64,
    pub owner_peer_ids: Vec<u64>,
    pub layout_digest: String,
    pub index_state_digest: String,
    pub snapshot_size_bytes: u64,
    /// Lowercase hexadecimal SHA-256 used by the existing Qdrant snapshot contract.
    pub snapshot_sha256: String,
    /// Base64url SHA-256 of the complete encrypted client recovery-state set.
    pub client_recovery_state_digest: String,
    pub owner_signing_key_id: String,
    pub created_at_unix: u64,
}

impl Debug for PrivateOramExternalRecoveryCheckpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryCheckpoint")
            .field("version", &self.version)
            .field("collection_id", &"[redacted]")
            .field("backup_generation", &"[redacted]")
            .field("source_peer_id", &"[redacted]")
            .field("source_shard_count", &"[redacted]")
            .field("layout_generation", &"[redacted]")
            .field("owner_peer_count", &"[redacted]")
            .field("layout_digest", &"[redacted]")
            .field("index_state_digest", &"[redacted]")
            .field("snapshot_size_bytes", &"[redacted]")
            .field("snapshot_sha256", &"[redacted]")
            .field("client_recovery_state_digest", &"[redacted]")
            .field("owner_signing_key_id", &"[redacted]")
            .field("created_at_unix", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramRecoverySignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateOramRecoverySignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramRecoverySignature")
            .field("alg", &self.alg)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramExternalRecoveryCheckpointBundle {
    pub checkpoint: PrivateOramExternalRecoveryCheckpoint,
    pub signature: PrivateOramRecoverySignature,
}

impl Debug for PrivateOramExternalRecoveryCheckpointBundle {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryCheckpointBundle")
            .field("checkpoint", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramRecoveryValidationContext<'a> {
    pub expected_collection_id: &'a str,
    pub expected_backup_generation: u64,
    pub expected_source_peer_id: u64,
    pub expected_source_shard_ids: &'a [u32],
    pub expected_layout_generation: u64,
    pub expected_owner_peer_ids: &'a [u64],
    pub expected_layout_digest: &'a str,
    pub expected_index_state_digest: &'a str,
    pub expected_snapshot_size_bytes: u64,
    pub expected_snapshot_sha256: &'a str,
    pub expected_client_recovery_state_digest: &'a str,
    pub expected_owner_signing_key_id: &'a str,
    pub public_key: &'a [u8],
}

impl Debug for PrivateOramRecoveryValidationContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramRecoveryValidationContext")
            .field("expected_collection_id", &"[redacted]")
            .field("expected_backup_generation", &"[redacted]")
            .field("expected_source_peer_id", &"[redacted]")
            .field("expected_source_shard_count", &"[redacted]")
            .field("expected_layout_generation", &"[redacted]")
            .field("expected_owner_peer_count", &"[redacted]")
            .field("expected_layout_digest", &"[redacted]")
            .field("expected_index_state_digest", &"[redacted]")
            .field("expected_snapshot_size_bytes", &"[redacted]")
            .field("expected_snapshot_sha256", &"[redacted]")
            .field("expected_client_recovery_state_digest", &"[redacted]")
            .field("expected_owner_signing_key_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .finish()
    }
}

pub fn validate_private_oram_external_recovery_checkpoint_shape(
    checkpoint: &PrivateOramExternalRecoveryCheckpoint,
) -> Result<(), PrivateOramRecoveryError> {
    if checkpoint.version != PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_VERSION {
        return Err(PrivateOramRecoveryError::UnsupportedCheckpointVersion(
            checkpoint.version,
        ));
    }
    validate_resource_id(&checkpoint.collection_id, "collection_id")?;
    if checkpoint.backup_generation == 0 {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(
            "backup_generation",
        ));
    }
    validate_strictly_increasing_u32(
        &checkpoint.source_shard_ids,
        PRIVATE_ORAM_RECOVERY_MAX_SHARDS,
        "source_shard_ids",
    )?;
    if checkpoint.layout_generation == 0 {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(
            "layout_generation",
        ));
    }
    validate_strictly_increasing_u64(
        &checkpoint.owner_peer_ids,
        PRIVATE_ORAM_RECOVERY_MAX_OWNER_PEERS,
        "owner_peer_ids",
    )?;
    if checkpoint
        .owner_peer_ids
        .binary_search(&checkpoint.source_peer_id)
        .is_err()
    {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(
            "source_peer_id",
        ));
    }
    decode_base64url_32(&checkpoint.layout_digest, "layout_digest")?;
    decode_base64url_32(&checkpoint.index_state_digest, "index_state_digest")?;
    if checkpoint.snapshot_size_bytes == 0 {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(
            "snapshot_size_bytes",
        ));
    }
    validate_lower_hex_sha256(&checkpoint.snapshot_sha256, "snapshot_sha256")?;
    decode_base64url_32(
        &checkpoint.client_recovery_state_digest,
        "client_recovery_state_digest",
    )?;
    validate_resource_id(&checkpoint.owner_signing_key_id, "owner_signing_key_id")?;
    if checkpoint.created_at_unix == 0 {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(
            "created_at_unix",
        ));
    }
    Ok(())
}

pub fn validate_private_oram_recovery_signature_shape(
    signature: &PrivateOramRecoverySignature,
) -> Result<(), PrivateOramRecoveryError> {
    if signature.alg != PRIVATE_ORAM_RECOVERY_SIGNATURE_ALGORITHM {
        return Err(PrivateOramRecoveryError::UnsupportedSignatureAlgorithm(
            signature.alg.clone(),
        ));
    }
    validate_resource_id(&signature.key_id, "signature.key_id")?;
    decode_base64url_64(&signature.sig)?;
    Ok(())
}

pub fn try_private_oram_external_recovery_checkpoint_signature_message(
    checkpoint: &PrivateOramExternalRecoveryCheckpoint,
) -> Result<Vec<u8>, PrivateOramRecoveryError> {
    validate_private_oram_external_recovery_checkpoint_shape(checkpoint)?;

    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_SIGNATURE_DOMAIN.as_bytes(),
    )?;
    push_u16(&mut message, checkpoint.version);
    try_push_str(&mut message, &checkpoint.collection_id)?;
    push_u64(&mut message, checkpoint.backup_generation);
    push_u64(&mut message, checkpoint.source_peer_id);
    push_u32(
        &mut message,
        u32::try_from(checkpoint.source_shard_ids.len())
            .map_err(|_| PrivateOramRecoveryError::InvalidCheckpointField("source_shard_ids"))?,
    );
    for shard_id in &checkpoint.source_shard_ids {
        push_u32(&mut message, *shard_id);
    }
    push_u64(&mut message, checkpoint.layout_generation);
    push_u32(
        &mut message,
        u32::try_from(checkpoint.owner_peer_ids.len())
            .map_err(|_| PrivateOramRecoveryError::InvalidCheckpointField("owner_peer_ids"))?,
    );
    for peer_id in &checkpoint.owner_peer_ids {
        push_u64(&mut message, *peer_id);
    }
    try_push_str(&mut message, &checkpoint.layout_digest)?;
    try_push_str(&mut message, &checkpoint.index_state_digest)?;
    push_u64(&mut message, checkpoint.snapshot_size_bytes);
    try_push_str(&mut message, &checkpoint.snapshot_sha256)?;
    try_push_str(&mut message, &checkpoint.client_recovery_state_digest)?;
    try_push_str(&mut message, &checkpoint.owner_signing_key_id)?;
    push_u64(&mut message, checkpoint.created_at_unix);
    Ok(message)
}

pub fn sign_private_oram_external_recovery_checkpoint(
    key_pair: &Ed25519KeyPair,
    checkpoint: &PrivateOramExternalRecoveryCheckpoint,
) -> Result<PrivateOramRecoverySignature, PrivateOramRecoveryError> {
    let message = try_private_oram_external_recovery_checkpoint_signature_message(checkpoint)?;
    Ok(PrivateOramRecoverySignature {
        alg: PRIVATE_ORAM_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
        key_id: checkpoint.owner_signing_key_id.clone(),
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    })
}

pub fn package_private_oram_external_recovery_checkpoint(
    key_pair: &Ed25519KeyPair,
    checkpoint: PrivateOramExternalRecoveryCheckpoint,
) -> Result<PrivateOramExternalRecoveryCheckpointBundle, PrivateOramRecoveryError> {
    let signature = sign_private_oram_external_recovery_checkpoint(key_pair, &checkpoint)?;
    Ok(PrivateOramExternalRecoveryCheckpointBundle {
        checkpoint,
        signature,
    })
}

pub fn validate_private_oram_external_recovery_checkpoint(
    checkpoint: &PrivateOramExternalRecoveryCheckpoint,
    signature: Option<&PrivateOramRecoverySignature>,
    context: PrivateOramRecoveryValidationContext<'_>,
) -> Result<(), PrivateOramRecoveryError> {
    validate_private_oram_external_recovery_checkpoint_shape(checkpoint)?;
    if checkpoint.collection_id != context.expected_collection_id {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "collection_id",
        ));
    }
    if checkpoint.backup_generation != context.expected_backup_generation {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "backup_generation",
        ));
    }
    if checkpoint.source_peer_id != context.expected_source_peer_id {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "source_peer_id",
        ));
    }
    if checkpoint.source_shard_ids != context.expected_source_shard_ids {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "source_shard_ids",
        ));
    }
    if checkpoint.layout_generation != context.expected_layout_generation {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "layout_generation",
        ));
    }
    if checkpoint.owner_peer_ids != context.expected_owner_peer_ids {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "owner_peer_ids",
        ));
    }
    if checkpoint.layout_digest != context.expected_layout_digest {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "layout_digest",
        ));
    }
    if checkpoint.index_state_digest != context.expected_index_state_digest {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "index_state_digest",
        ));
    }
    if checkpoint.snapshot_size_bytes != context.expected_snapshot_size_bytes {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "snapshot_size_bytes",
        ));
    }
    if checkpoint.snapshot_sha256 != context.expected_snapshot_sha256 {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "snapshot_sha256",
        ));
    }
    if checkpoint.client_recovery_state_digest != context.expected_client_recovery_state_digest {
        return Err(PrivateOramRecoveryError::CheckpointContextMismatch(
            "client_recovery_state_digest",
        ));
    }
    if checkpoint.owner_signing_key_id != context.expected_owner_signing_key_id {
        return Err(PrivateOramRecoveryError::SignatureKeyIdMismatch);
    }

    let signature = signature.ok_or(PrivateOramRecoveryError::MissingCheckpointSignature)?;
    validate_private_oram_recovery_signature_shape(signature)?;
    if signature.key_id != checkpoint.owner_signing_key_id
        || signature.key_id != context.expected_owner_signing_key_id
    {
        return Err(PrivateOramRecoveryError::SignatureKeyIdMismatch);
    }
    if context.public_key.len() != 32 {
        return Err(PrivateOramRecoveryError::MalformedSignature);
    }

    let signature_bytes = decode_base64url_64(&signature.sig)?;
    let message = try_private_oram_external_recovery_checkpoint_signature_message(checkpoint)?;
    UnparsedPublicKey::new(&ED25519, context.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateOramRecoveryError::InvalidCheckpointSignature)
}

fn validate_resource_id(value: &str, field: &'static str) -> Result<(), PrivateOramRecoveryError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(field));
    }
    Ok(())
}

fn validate_strictly_increasing_u32(
    values: &[u32],
    max_len: usize,
    field: &'static str,
) -> Result<(), PrivateOramRecoveryError> {
    if values.is_empty()
        || values.len() > max_len
        || values.windows(2).any(|values| values[0] >= values[1])
    {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(field));
    }
    Ok(())
}

fn validate_strictly_increasing_u64(
    values: &[u64],
    max_len: usize,
    field: &'static str,
) -> Result<(), PrivateOramRecoveryError> {
    if values.is_empty()
        || values.len() > max_len
        || values.windows(2).any(|values| values[0] >= values[1])
    {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(field));
    }
    Ok(())
}

fn decode_base64url_32(
    value: &str,
    field: &'static str,
) -> Result<[u8; 32], PrivateOramRecoveryError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(field));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramRecoveryError::InvalidCheckpointField(field))?;
    decoded
        .try_into()
        .map_err(|_| PrivateOramRecoveryError::InvalidCheckpointField(field))
}

fn validate_lower_hex_sha256(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramRecoveryError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(PrivateOramRecoveryError::InvalidCheckpointField(field));
    }
    Ok(())
}

fn decode_base64url_64(value: &str) -> Result<[u8; 64], PrivateOramRecoveryError> {
    if value.len() != BASE64URL_NOPAD_64_BYTE_LEN {
        return Err(PrivateOramRecoveryError::MalformedSignature);
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramRecoveryError::MalformedSignature)?;
    decoded
        .try_into()
        .map_err(|_| PrivateOramRecoveryError::MalformedSignature)
}

fn try_push_domain(message: &mut Vec<u8>, domain: &[u8]) -> Result<(), PrivateOramRecoveryError> {
    let len = u32::try_from(domain.len())
        .map_err(|_| PrivateOramRecoveryError::InvalidCheckpointField("signature_message"))?;
    push_u32(message, len);
    message.extend_from_slice(domain);
    Ok(())
}

fn try_push_str(message: &mut Vec<u8>, value: &str) -> Result<(), PrivateOramRecoveryError> {
    let len = u64::try_from(value.len())
        .map_err(|_| PrivateOramRecoveryError::InvalidCheckpointField("signature_message"))?;
    push_u64(message, len);
    message.extend_from_slice(value.as_bytes());
    Ok(())
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
    use sha2::{Digest, Sha256};

    use super::*;

    fn deterministic_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[19; 32]).unwrap()
    }

    fn fixture_checkpoint() -> PrivateOramExternalRecoveryCheckpoint {
        PrivateOramExternalRecoveryCheckpoint {
            version: 1,
            collection_id: "collection-uuid-1".to_string(),
            backup_generation: 31,
            source_peer_id: 17,
            source_shard_ids: vec![1, 4, 9],
            layout_generation: 23,
            owner_peer_ids: vec![11, 17, 29],
            layout_digest: BASE64URL_NOPAD.encode(&[41; 32]),
            index_state_digest: BASE64URL_NOPAD.encode(&[42; 32]),
            snapshot_size_bytes: 1_048_576,
            snapshot_sha256: "2b".repeat(32),
            client_recovery_state_digest: BASE64URL_NOPAD.encode(&[44; 32]),
            owner_signing_key_id: "tenant-a/private-oram-recovery-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn fixture_validation_context<'a>(
        checkpoint: &'a PrivateOramExternalRecoveryCheckpoint,
        public_key: &'a [u8],
    ) -> PrivateOramRecoveryValidationContext<'a> {
        PrivateOramRecoveryValidationContext {
            expected_collection_id: &checkpoint.collection_id,
            expected_backup_generation: checkpoint.backup_generation,
            expected_source_peer_id: checkpoint.source_peer_id,
            expected_source_shard_ids: &checkpoint.source_shard_ids,
            expected_layout_generation: checkpoint.layout_generation,
            expected_owner_peer_ids: &checkpoint.owner_peer_ids,
            expected_layout_digest: &checkpoint.layout_digest,
            expected_index_state_digest: &checkpoint.index_state_digest,
            expected_snapshot_size_bytes: checkpoint.snapshot_size_bytes,
            expected_snapshot_sha256: &checkpoint.snapshot_sha256,
            expected_client_recovery_state_digest: &checkpoint.client_recovery_state_digest,
            expected_owner_signing_key_id: &checkpoint.owner_signing_key_id,
            public_key,
        }
    }

    #[test]
    fn recovery_checkpoint_signature_known_answer_is_stable() {
        let checkpoint = fixture_checkpoint();
        let message =
            try_private_oram_external_recovery_checkpoint_signature_message(&checkpoint).unwrap();
        assert_eq!(
            BASE64URL_NOPAD.encode(Sha256::digest(&message).as_ref()),
            "hxUQN8i56xcpwMnx47J2sw4J_yzxydt8GILYr_wF_IU"
        );

        let signature =
            sign_private_oram_external_recovery_checkpoint(&deterministic_key_pair(), &checkpoint)
                .unwrap();
        assert_eq!(
            signature.sig,
            "_gbHSa_lGRZlSCU96G5ZJMdsyZWJNVF0HVEU0VB-q9Wv5TktItp3mx3a8xiYBz6tCOsIlLZcxGzNZF26lF8pBg"
        );
    }

    #[test]
    fn recovery_checkpoint_sign_and_verify_round_trip() {
        let key_pair = deterministic_key_pair();
        let bundle =
            package_private_oram_external_recovery_checkpoint(&key_pair, fixture_checkpoint())
                .unwrap();
        validate_private_oram_external_recovery_checkpoint(
            &bundle.checkpoint,
            Some(&bundle.signature),
            fixture_validation_context(&bundle.checkpoint, key_pair.public_key().as_ref()),
        )
        .unwrap();
    }

    #[test]
    fn recovery_checkpoint_rejects_noncanonical_owner_and_shard_sets() {
        let mut checkpoint = fixture_checkpoint();
        checkpoint.source_shard_ids = vec![1, 1];
        assert!(matches!(
            validate_private_oram_external_recovery_checkpoint_shape(&checkpoint),
            Err(PrivateOramRecoveryError::InvalidCheckpointField(
                "source_shard_ids"
            ))
        ));

        let mut checkpoint = fixture_checkpoint();
        checkpoint.owner_peer_ids = vec![17, 11];
        assert!(matches!(
            validate_private_oram_external_recovery_checkpoint_shape(&checkpoint),
            Err(PrivateOramRecoveryError::InvalidCheckpointField(
                "owner_peer_ids"
            ))
        ));

        let mut checkpoint = fixture_checkpoint();
        checkpoint.owner_peer_ids = vec![11, 29];
        assert!(matches!(
            validate_private_oram_external_recovery_checkpoint_shape(&checkpoint),
            Err(PrivateOramRecoveryError::InvalidCheckpointField(
                "source_peer_id"
            ))
        ));
    }

    #[test]
    fn recovery_checkpoint_rejects_malformed_shape_before_signing() {
        let mut checkpoint = fixture_checkpoint();
        checkpoint.layout_generation = 0;
        assert!(matches!(
            sign_private_oram_external_recovery_checkpoint(&deterministic_key_pair(), &checkpoint),
            Err(PrivateOramRecoveryError::InvalidCheckpointField(
                "layout_generation"
            ))
        ));

        let mut checkpoint = fixture_checkpoint();
        checkpoint.backup_generation = 0;
        assert!(matches!(
            sign_private_oram_external_recovery_checkpoint(&deterministic_key_pair(), &checkpoint),
            Err(PrivateOramRecoveryError::InvalidCheckpointField(
                "backup_generation"
            ))
        ));

        let mut checkpoint = fixture_checkpoint();
        checkpoint.snapshot_size_bytes = 0;
        assert!(matches!(
            sign_private_oram_external_recovery_checkpoint(&deterministic_key_pair(), &checkpoint),
            Err(PrivateOramRecoveryError::InvalidCheckpointField(
                "snapshot_size_bytes"
            ))
        ));

        let mut checkpoint = fixture_checkpoint();
        checkpoint.snapshot_sha256 = "snapshot-digest-sentinel".to_string();
        assert!(matches!(
            sign_private_oram_external_recovery_checkpoint(&deterministic_key_pair(), &checkpoint),
            Err(PrivateOramRecoveryError::InvalidCheckpointField(
                "snapshot_sha256"
            ))
        ));

        let mut checkpoint = fixture_checkpoint();
        checkpoint.snapshot_sha256 = "AB".repeat(32);
        assert!(matches!(
            sign_private_oram_external_recovery_checkpoint(&deterministic_key_pair(), &checkpoint),
            Err(PrivateOramRecoveryError::InvalidCheckpointField(
                "snapshot_sha256"
            ))
        ));

        let mut checkpoint = fixture_checkpoint();
        checkpoint.client_recovery_state_digest = "client-state-digest-sentinel".to_string();
        assert!(matches!(
            sign_private_oram_external_recovery_checkpoint(&deterministic_key_pair(), &checkpoint),
            Err(PrivateOramRecoveryError::InvalidCheckpointField(
                "client_recovery_state_digest"
            ))
        ));
    }

    #[test]
    fn recovery_checkpoint_rejects_context_drift_and_tampering() {
        let key_pair = deterministic_key_pair();
        let bundle =
            package_private_oram_external_recovery_checkpoint(&key_pair, fixture_checkpoint())
                .unwrap();

        let mut context =
            fixture_validation_context(&bundle.checkpoint, key_pair.public_key().as_ref());
        context.expected_layout_generation += 1;
        assert!(matches!(
            validate_private_oram_external_recovery_checkpoint(
                &bundle.checkpoint,
                Some(&bundle.signature),
                context,
            ),
            Err(PrivateOramRecoveryError::CheckpointContextMismatch(
                "layout_generation"
            ))
        ));

        let mut tampered = bundle.checkpoint.clone();
        tampered.snapshot_sha256 = "2c".repeat(32);
        assert_eq!(
            validate_private_oram_external_recovery_checkpoint(
                &tampered,
                Some(&bundle.signature),
                fixture_validation_context(&tampered, key_pair.public_key().as_ref()),
            ),
            Err(PrivateOramRecoveryError::InvalidCheckpointSignature)
        );
    }

    #[test]
    fn recovery_checkpoint_rejects_wrong_owner_key_before_verification() {
        let key_pair = deterministic_key_pair();
        let bundle =
            package_private_oram_external_recovery_checkpoint(&key_pair, fixture_checkpoint())
                .unwrap();
        let mut signature = bundle.signature.clone();
        signature.key_id = "tenant-a/other-recovery-key".to_string();
        assert_eq!(
            validate_private_oram_external_recovery_checkpoint(
                &bundle.checkpoint,
                Some(&signature),
                fixture_validation_context(&bundle.checkpoint, key_pair.public_key().as_ref()),
            ),
            Err(PrivateOramRecoveryError::SignatureKeyIdMismatch)
        );
    }

    #[test]
    fn recovery_checkpoint_rejects_malformed_signature_shape() {
        let key_pair = deterministic_key_pair();
        let bundle =
            package_private_oram_external_recovery_checkpoint(&key_pair, fixture_checkpoint())
                .unwrap();

        let mut signature = bundle.signature.clone();
        signature.alg = "rsa-pss-sentinel".to_string();
        assert!(matches!(
            validate_private_oram_external_recovery_checkpoint(
                &bundle.checkpoint,
                Some(&signature),
                fixture_validation_context(&bundle.checkpoint, key_pair.public_key().as_ref()),
            ),
            Err(PrivateOramRecoveryError::UnsupportedSignatureAlgorithm(_))
        ));

        let mut signature = bundle.signature.clone();
        signature.sig = "signature-body-sentinel".to_string();
        assert_eq!(
            validate_private_oram_external_recovery_checkpoint(
                &bundle.checkpoint,
                Some(&signature),
                fixture_validation_context(&bundle.checkpoint, key_pair.public_key().as_ref()),
            ),
            Err(PrivateOramRecoveryError::MalformedSignature)
        );
    }

    #[test]
    fn recovery_checkpoint_serde_rejects_unknown_fields() {
        let mut value = serde_json::to_value(fixture_checkpoint()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("client_state".to_string(), serde_json::json!("sentinel"));
        assert!(serde_json::from_value::<PrivateOramExternalRecoveryCheckpoint>(value).is_err());
    }

    #[test]
    fn recovery_checkpoint_debug_and_errors_redact_sensitive_values() {
        let checkpoint = fixture_checkpoint();
        let checkpoint_debug = format!("{checkpoint:?}");
        let context_debug = format!("{:?}", fixture_validation_context(&checkpoint, &[77; 32]));
        for sentinel in [
            checkpoint.collection_id.as_str(),
            checkpoint.layout_digest.as_str(),
            checkpoint.index_state_digest.as_str(),
            checkpoint.snapshot_sha256.as_str(),
            checkpoint.client_recovery_state_digest.as_str(),
            checkpoint.owner_signing_key_id.as_str(),
            "17",
            "23",
            "31",
        ] {
            assert!(!checkpoint_debug.contains(sentinel), "{checkpoint_debug}");
            assert!(!context_debug.contains(sentinel), "{context_debug}");
        }

        let errors = [
            PrivateOramRecoveryError::UnsupportedCheckpointVersion(99).to_string(),
            PrivateOramRecoveryError::InvalidCheckpointField("field-sentinel").to_string(),
            PrivateOramRecoveryError::CheckpointContextMismatch("context-sentinel").to_string(),
            PrivateOramRecoveryError::UnsupportedSignatureAlgorithm(
                "algorithm-sentinel".to_string(),
            )
            .to_string(),
        ];
        for error in errors {
            assert!(!error.contains("99"), "{error}");
            assert!(!error.contains("field-sentinel"), "{error}");
            assert!(!error.contains("context-sentinel"), "{error}");
            assert!(!error.contains("algorithm-sentinel"), "{error}");
        }
    }
}
