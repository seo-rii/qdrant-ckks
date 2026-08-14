//! Owner-signed proof that an exact committed reservation challenge was durably fenced.

use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM, PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
    PrivateOramOwnerCleanupSignatureV1, PrivateOramOwnerCleanupSignerV1,
    PrivateOramOwnerLifecycleStateV1,
};

pub const PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_SIGNATURE_DOMAIN_V1: &str =
    "qdrant-sec/private-oram-owner-reservation-prepare-signature/v1";

const PREPARE_DIGEST_DOMAIN_V1: &[u8] = b"qdrant-sec/private-oram-owner-reservation-prepare/v1";
const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const CHALLENGE_NONCE_BYTES: usize = 16;
const MAX_IDENTIFIER_BYTES: usize = 1_024;
const MAX_CANONICAL_BYTES: usize = 128 * 1024;

mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let value = encoded.parse::<u64>().map_err(serde::de::Error::custom)?;
        if encoded != value.to_string() {
            return Err(serde::de::Error::custom("non-canonical integer"));
        }
        Ok(value)
    }
}

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramOwnerReservationPrepareError {
    #[error("private ORAM owner reservation prepare field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM owner reservation prepare context does not match")]
    ContextMismatch,
    #[error("private ORAM owner reservation prepare signer does not match")]
    SignerMismatch,
    #[error("private ORAM owner reservation prepare signature is invalid")]
    InvalidSignature,
    #[error("private ORAM owner reservation prepare encoding is not canonical")]
    NonCanonicalEncoding,
}

impl Debug for PrivateOramOwnerReservationPrepareError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramOwnerReservationPrepareError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerReservationPrepareChallengeV1 {
    pub version: u16,
    pub consensus_history_id_digest: String,
    pub raft_group_id_digest: String,
    pub collection_id: String,
    pub collection_lifetime_id_digest: String,
    pub collection_incarnation_digest: String,
    pub activation_anchor_digest: String,
    #[serde(with = "decimal_u64")]
    pub capability_epoch: u64,
    pub protocol_capability_digest: String,
    #[serde(with = "decimal_u64")]
    pub membership_epoch: u64,
    pub reservation_intent_digest: String,
    pub checkpoint_context_digest: String,
    pub committed_challenge_digest: String,
    #[serde(with = "decimal_u64")]
    pub challenge_applied_term: u64,
    #[serde(with = "decimal_u64")]
    pub challenge_applied_index: u64,
    pub attempt_id: String,
    pub challenge_nonce: String,
    pub expected_checkpoint_record_digest: String,
    #[serde(with = "decimal_u64")]
    pub expected_checkpoint_sequence: u64,
    pub expected_owner_target_digest: String,
    pub reserved_terminal_intent_key: String,
    pub owner_index: u32,
    pub owner_count: u32,
    pub owner_enrollment_id: String,
    pub owner_peer_id: u64,
    pub owner_store_incarnation_digest: String,
    pub authority_registry_digest: String,
    pub owner_registry_digest: String,
}

impl Debug for PrivateOramOwnerReservationPrepareChallengeV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerReservationPrepareChallengeV1")
            .field("version", &self.version)
            .field("capability_epoch", &self.capability_epoch)
            .field("membership_epoch", &self.membership_epoch)
            .field("challenge_applied_term", &self.challenge_applied_term)
            .field("challenge_applied_index", &self.challenge_applied_index)
            .field(
                "expected_checkpoint_sequence",
                &self.expected_checkpoint_sequence,
            )
            .field("owner_index", &self.owner_index)
            .field("owner_count", &self.owner_count)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("reservation_intent_digest", &"[redacted]")
            .field("checkpoint_context_digest", &"[redacted]")
            .field("committed_challenge_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("expected_owner_target_digest", &"[redacted]")
            .field("reserved_terminal_intent_key", &"[redacted]")
            .field("owner_enrollment_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerReservationPrepareStatusV1 {
    ReadyExact,
    ConflictingFence,
    RepairPending,
    CorruptOrForked,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerReservationPrepareV1 {
    pub version: u16,
    pub challenge: PrivateOramOwnerReservationPrepareChallengeV1,
    pub observed_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    #[serde(with = "decimal_u64")]
    pub local_terminal_generation: u64,
    pub reserved_terminal_slot: bool,
    pub durable_fence_record_digest: String,
    pub status: PrivateOramOwnerReservationPrepareStatusV1,
    pub owner_signer: PrivateOramOwnerCleanupSignerV1,
    pub prepare_digest: String,
    pub signature: PrivateOramOwnerCleanupSignatureV1,
}

impl Debug for PrivateOramOwnerReservationPrepareV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerReservationPrepareV1")
            .field("version", &self.version)
            .field("challenge", &self.challenge)
            .field("observed_lifecycle_state", &self.observed_lifecycle_state)
            .field("local_terminal_generation", &self.local_terminal_generation)
            .field("reserved_terminal_slot", &self.reserved_terminal_slot)
            .field("status", &self.status)
            .field("durable_fence_record_digest", &"[redacted]")
            .field("owner_signer", &"[redacted]")
            .field("prepare_digest", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerReservationPrepareV1 {
    prepare: PrivateOramOwnerReservationPrepareV1,
}

impl VerifiedPrivateOramOwnerReservationPrepareV1 {
    pub fn prepare(&self) -> &PrivateOramOwnerReservationPrepareV1 {
        &self.prepare
    }
}

impl Debug for VerifiedPrivateOramOwnerReservationPrepareV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramOwnerReservationPrepareV1")
            .field("prepare", &"[verified]")
            .finish()
    }
}

pub fn sign_private_oram_owner_reservation_prepare_v1(
    owner_key: &Ed25519KeyPair,
    challenge: PrivateOramOwnerReservationPrepareChallengeV1,
    observed_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    local_terminal_generation: u64,
    durable_fence_record_digest: String,
    owner_signer: PrivateOramOwnerCleanupSignerV1,
) -> Result<PrivateOramOwnerReservationPrepareV1, PrivateOramOwnerReservationPrepareError> {
    validate_challenge(&challenge)?;
    validate_signer(&owner_signer)?;
    validate_lifecycle_state(&observed_lifecycle_state)?;
    if owner_key.public_key().as_ref()
        != BASE64URL_NOPAD
            .decode(owner_signer.public_key.as_bytes())
            .map_err(|_| PrivateOramOwnerReservationPrepareError::InvalidField("public_key"))?
            .as_slice()
    {
        return Err(PrivateOramOwnerReservationPrepareError::SignerMismatch);
    }
    validate_digest(&durable_fence_record_digest, "durable_fence_record_digest")?;
    let mut prepare = PrivateOramOwnerReservationPrepareV1 {
        version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
        challenge,
        observed_lifecycle_state,
        local_terminal_generation,
        reserved_terminal_slot: true,
        durable_fence_record_digest,
        status: PrivateOramOwnerReservationPrepareStatusV1::ReadyExact,
        owner_signer: owner_signer.clone(),
        prepare_digest: String::new(),
        signature: empty_signature(&owner_signer),
    };
    prepare.prepare_digest = prepare_digest(&prepare)?;
    let signature = owner_key.sign(&signature_message(&prepare.prepare_digest)?);
    prepare.signature.sig = BASE64URL_NOPAD.encode(signature.as_ref());
    validate_prepare_shape(&prepare)?;
    Ok(prepare)
}

pub fn validate_private_oram_owner_reservation_prepare_v1(
    prepare: &PrivateOramOwnerReservationPrepareV1,
    expected_challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
    expected_signer: &PrivateOramOwnerCleanupSignerV1,
    expected_lifecycle_state: &PrivateOramOwnerLifecycleStateV1,
) -> Result<VerifiedPrivateOramOwnerReservationPrepareV1, PrivateOramOwnerReservationPrepareError> {
    validate_prepare_shape(prepare)?;
    if &prepare.challenge != expected_challenge
        || &prepare.owner_signer != expected_signer
        || &prepare.observed_lifecycle_state != expected_lifecycle_state
        || prepare.local_terminal_generation != expected_lifecycle_state.generation
        || !prepare.reserved_terminal_slot
        || prepare.status != PrivateOramOwnerReservationPrepareStatusV1::ReadyExact
    {
        return Err(PrivateOramOwnerReservationPrepareError::ContextMismatch);
    }
    verify_signature(expected_signer, &prepare.signature, &prepare.prepare_digest)?;
    Ok(VerifiedPrivateOramOwnerReservationPrepareV1 {
        prepare: prepare.clone(),
    })
}

pub fn encode_private_oram_owner_reservation_prepare_v1(
    prepare: &PrivateOramOwnerReservationPrepareV1,
) -> Result<Vec<u8>, PrivateOramOwnerReservationPrepareError> {
    validate_prepare_shape(prepare)?;
    canonical_json(prepare)
}

pub fn decode_private_oram_owner_reservation_prepare_v1(
    bytes: &[u8],
) -> Result<PrivateOramOwnerReservationPrepareV1, PrivateOramOwnerReservationPrepareError> {
    canonical_decode(bytes)
}

pub fn validate_private_oram_owner_reservation_prepare_challenge_v1(
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    validate_challenge(challenge)
}

fn validate_challenge(
    challenge: &PrivateOramOwnerReservationPrepareChallengeV1,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    if challenge.version != PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1
        || challenge.capability_epoch == 0
        || challenge.membership_epoch == 0
        || challenge.challenge_applied_term == 0
        || challenge.challenge_applied_index == 0
        || challenge.expected_checkpoint_sequence == 0
        || challenge.owner_peer_id == 0
        || challenge.owner_count == 0
        || challenge.owner_index >= challenge.owner_count
    {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(
            "challenge",
        ));
    }
    for digest in [
        &challenge.consensus_history_id_digest,
        &challenge.raft_group_id_digest,
        &challenge.collection_lifetime_id_digest,
        &challenge.collection_incarnation_digest,
        &challenge.activation_anchor_digest,
        &challenge.protocol_capability_digest,
        &challenge.reservation_intent_digest,
        &challenge.checkpoint_context_digest,
        &challenge.committed_challenge_digest,
        &challenge.attempt_id,
        &challenge.expected_checkpoint_record_digest,
        &challenge.expected_owner_target_digest,
        &challenge.reserved_terminal_intent_key,
        &challenge.owner_enrollment_id,
        &challenge.owner_store_incarnation_digest,
        &challenge.authority_registry_digest,
        &challenge.owner_registry_digest,
    ] {
        validate_digest(digest, "challenge")?;
    }
    validate_identifier(&challenge.collection_id, "collection_id")?;
    validate_base64_exact(
        &challenge.challenge_nonce,
        CHALLENGE_NONCE_BYTES,
        "challenge_nonce",
    )
}

fn validate_prepare_shape(
    prepare: &PrivateOramOwnerReservationPrepareV1,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    if prepare.version != PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1
        || prepare
            .observed_lifecycle_state
            .owner_store_incarnation_digest
            != prepare.challenge.owner_store_incarnation_digest
    {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(
            "prepare",
        ));
    }
    validate_challenge(&prepare.challenge)?;
    validate_lifecycle_state(&prepare.observed_lifecycle_state)?;
    validate_signer(&prepare.owner_signer)?;
    validate_signature_shape(&prepare.signature, &prepare.owner_signer)?;
    validate_digest(
        &prepare.durable_fence_record_digest,
        "durable_fence_record_digest",
    )?;
    validate_digest(&prepare.prepare_digest, "prepare_digest")?;
    if prepare.prepare_digest != prepare_digest(prepare)? {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(
            "prepare_digest",
        ));
    }
    ensure_canonical_size(prepare)
}

fn prepare_digest(
    prepare: &PrivateOramOwnerReservationPrepareV1,
) -> Result<String, PrivateOramOwnerReservationPrepareError> {
    #[derive(Serialize)]
    struct Core<'a> {
        version: u16,
        challenge: &'a PrivateOramOwnerReservationPrepareChallengeV1,
        observed_lifecycle_state: &'a PrivateOramOwnerLifecycleStateV1,
        local_terminal_generation: u64,
        reserved_terminal_slot: bool,
        durable_fence_record_digest: &'a str,
        status: PrivateOramOwnerReservationPrepareStatusV1,
        owner_signer: &'a PrivateOramOwnerCleanupSignerV1,
    }
    let encoded = canonical_json(&Core {
        version: prepare.version,
        challenge: &prepare.challenge,
        observed_lifecycle_state: &prepare.observed_lifecycle_state,
        local_terminal_generation: prepare.local_terminal_generation,
        reserved_terminal_slot: prepare.reserved_terminal_slot,
        durable_fence_record_digest: &prepare.durable_fence_record_digest,
        status: prepare.status,
        owner_signer: &prepare.owner_signer,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(PREPARE_DIGEST_DOMAIN_V1);
    hasher.update(
        u64::try_from(encoded.len())
            .map_err(|_| PrivateOramOwnerReservationPrepareError::NonCanonicalEncoding)?
            .to_be_bytes(),
    );
    hasher.update(encoded);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn signature_message(digest: &str) -> Result<Vec<u8>, PrivateOramOwnerReservationPrepareError> {
    let digest = BASE64URL_NOPAD
        .decode(digest.as_bytes())
        .map_err(|_| PrivateOramOwnerReservationPrepareError::InvalidField("prepare_digest"))?;
    if digest.len() != DIGEST_BYTES {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(
            "prepare_digest",
        ));
    }
    let domain = PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_SIGNATURE_DOMAIN_V1.as_bytes();
    let mut message = Vec::with_capacity(4 + domain.len() + digest.len());
    message.extend_from_slice(
        &u32::try_from(domain.len())
            .map_err(|_| PrivateOramOwnerReservationPrepareError::InvalidField("domain"))?
            .to_be_bytes(),
    );
    message.extend_from_slice(domain);
    message.extend_from_slice(&digest);
    Ok(message)
}

fn empty_signature(signer: &PrivateOramOwnerCleanupSignerV1) -> PrivateOramOwnerCleanupSignatureV1 {
    PrivateOramOwnerCleanupSignatureV1 {
        version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
        alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch: signer.key_epoch,
        key_id: signer.key_id.clone(),
        sig: String::new(),
    }
}

fn verify_signature(
    signer: &PrivateOramOwnerCleanupSignerV1,
    signature: &PrivateOramOwnerCleanupSignatureV1,
    digest: &str,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    let public_key = BASE64URL_NOPAD
        .decode(signer.public_key.as_bytes())
        .map_err(|_| PrivateOramOwnerReservationPrepareError::InvalidField("public_key"))?;
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| PrivateOramOwnerReservationPrepareError::InvalidField("signature"))?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signature_message(digest)?, &signature_bytes)
        .map_err(|_| PrivateOramOwnerReservationPrepareError::InvalidSignature)
}

fn validate_signer(
    signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    if signer.version != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION
        || signer.alg != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM
        || signer.key_epoch == 0
    {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(
            "signer",
        ));
    }
    validate_identifier(&signer.key_id, "key_id")?;
    validate_base64_exact(&signer.public_key, DIGEST_BYTES, "public_key")
}

fn validate_signature_shape(
    signature: &PrivateOramOwnerCleanupSignatureV1,
    signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    if signature.version != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION
        || signature.alg != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM
        || signature.key_epoch != signer.key_epoch
        || signature.key_id != signer.key_id
    {
        return Err(PrivateOramOwnerReservationPrepareError::SignerMismatch);
    }
    validate_base64_exact(&signature.sig, SIGNATURE_BYTES, "signature")
}

fn validate_lifecycle_state(
    state: &PrivateOramOwnerLifecycleStateV1,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    if state.minimum_reader_version == 0 || state.capability.is_empty() {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(
            "lifecycle_state",
        ));
    }
    validate_digest(
        &state.owner_store_incarnation_digest,
        "owner_store_incarnation_digest",
    )?;
    validate_digest(&state.state_root, "state_root")?;
    validate_identifier(&state.capability, "capability")
}

fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    validate_base64_exact(value, DIGEST_BYTES, field)
}

fn validate_base64_exact(
    value: &str,
    expected_len: usize,
    field: &'static str,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramOwnerReservationPrepareError::InvalidField(field))?;
    if decoded.len() != expected_len || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(field));
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(field));
    }
    Ok(())
}

fn canonical_json<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, PrivateOramOwnerReservationPrepareError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| PrivateOramOwnerReservationPrepareError::NonCanonicalEncoding)?;
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_BYTES {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(
            "canonical_bytes",
        ));
    }
    Ok(bytes)
}

fn canonical_decode<T>(bytes: &[u8]) -> Result<T, PrivateOramOwnerReservationPrepareError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_BYTES {
        return Err(PrivateOramOwnerReservationPrepareError::InvalidField(
            "canonical_bytes",
        ));
    }
    let value = serde_json::from_slice(bytes)
        .map_err(|_| PrivateOramOwnerReservationPrepareError::NonCanonicalEncoding)?;
    if canonical_json(&value)? != bytes {
        return Err(PrivateOramOwnerReservationPrepareError::NonCanonicalEncoding);
    }
    Ok(value)
}

fn ensure_canonical_size<T: Serialize>(
    value: &T,
) -> Result<(), PrivateOramOwnerReservationPrepareError> {
    canonical_json(value).map(|_| ())
}

#[cfg(test)]
mod tests {
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::{
        private_oram_owner_cleanup_signer_v1, private_oram_owner_lifecycle_genesis_state_v1,
    };

    fn digest(seed: u8) -> String {
        BASE64URL_NOPAD.encode(&[seed; 32])
    }

    fn challenge() -> PrivateOramOwnerReservationPrepareChallengeV1 {
        PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-a".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: digest(4),
            activation_anchor_digest: digest(5),
            capability_epoch: 7,
            protocol_capability_digest: digest(6),
            membership_epoch: 9,
            reservation_intent_digest: digest(7),
            checkpoint_context_digest: digest(8),
            committed_challenge_digest: digest(9),
            challenge_applied_term: 3,
            challenge_applied_index: 41,
            attempt_id: digest(10),
            challenge_nonce: BASE64URL_NOPAD.encode(&[11; 16]),
            expected_checkpoint_record_digest: digest(12),
            expected_checkpoint_sequence: 2,
            expected_owner_target_digest: digest(13),
            reserved_terminal_intent_key: digest(14),
            owner_index: 0,
            owner_count: 1,
            owner_enrollment_id: digest(15),
            owner_peer_id: 11,
            owner_store_incarnation_digest: digest(16),
            authority_registry_digest: digest(17),
            owner_registry_digest: digest(18),
        }
    }

    #[test]
    fn reservation_prepare_binds_committed_challenge_target_and_durable_fence() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let signer = private_oram_owner_cleanup_signer_v1(&key, 4).unwrap();
        let challenge = challenge();
        let state = private_oram_owner_lifecycle_genesis_state_v1(
            challenge.owner_store_incarnation_digest.clone(),
        )
        .unwrap();
        let prepare = sign_private_oram_owner_reservation_prepare_v1(
            &key,
            challenge.clone(),
            state.clone(),
            state.generation,
            digest(19),
            signer.clone(),
        )
        .unwrap();
        let _verified = validate_private_oram_owner_reservation_prepare_v1(
            &prepare, &challenge, &signer, &state,
        )
        .unwrap();
        let encoded = encode_private_oram_owner_reservation_prepare_v1(&prepare).unwrap();
        assert_eq!(
            decode_private_oram_owner_reservation_prepare_v1(&encoded).unwrap(),
            prepare
        );

        let mut transplanted = prepare.clone();
        transplanted.challenge.expected_owner_target_digest = digest(20);
        transplanted.prepare_digest = prepare_digest(&transplanted).unwrap();
        assert_eq!(
            validate_private_oram_owner_reservation_prepare_v1(
                &transplanted,
                &transplanted.challenge,
                &signer,
                &state,
            ),
            Err(PrivateOramOwnerReservationPrepareError::InvalidSignature)
        );
    }
}
