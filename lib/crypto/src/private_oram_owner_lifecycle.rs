//! Owner lifecycle enrollment and read-only status attestations.
//!
//! These wire artifacts report local durable state. They are not retained authority by
//! themselves: consensus must compare a verified value with its exact enrollment or checkpoint
//! record before it can create a reservation or advance a lifecycle floor.

use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM, PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
    PrivateOramOwnerCleanupSignatureV1, PrivateOramOwnerCleanupSignerV1,
    PrivateOramOwnerLifecycleStateV1, PrivateOramPeerRecoveryPublicKeyV1,
    private_oram_owner_lifecycle_genesis_state_v1,
    validate_private_oram_peer_recovery_public_key_v1,
};

pub const PRIVATE_ORAM_OWNER_ENROLLMENT_PROTOCOL_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_OWNER_STATUS_PROTOCOL_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_OWNER_ENROLLMENT_GENESIS_SIGNATURE_DOMAIN_V1: &str =
    "qdrant-sec/private-oram-owner-enrollment-genesis-signature/v1";
pub const PRIVATE_ORAM_OWNER_STATUS_SIGNATURE_DOMAIN_V1: &str =
    "qdrant-sec/private-oram-owner-lifecycle-status-signature/v1";

const ENROLLMENT_PREPARED_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-enrollment-prepared/v1";
const ENROLLMENT_COMMITMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-enrollment-genesis-commitment/v1";
const OWNER_STATUS_DIGEST_DOMAIN_V1: &[u8] = b"qdrant-sec/private-oram-owner-lifecycle-status/v1";
const CHALLENGE_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 1_024;
const MAX_CANONICAL_BYTES: usize = 64 * 1024;

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
pub enum PrivateOramOwnerLifecycleError {
    #[error("private ORAM owner lifecycle version is unsupported")]
    UnsupportedVersion,
    #[error("private ORAM owner lifecycle field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM owner lifecycle context does not match")]
    ContextMismatch,
    #[error("private ORAM owner lifecycle signer does not match")]
    SignerMismatch,
    #[error("private ORAM owner lifecycle signature is invalid")]
    InvalidSignature,
    #[error("private ORAM owner lifecycle encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("private ORAM owner lifecycle secure randomness is unavailable")]
    RandomnessUnavailable,
}

impl Debug for PrivateOramOwnerLifecycleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramOwnerLifecycleError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerEnrollmentPreparedV1 {
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
    pub owner_enrollment_id: String,
    pub owner_peer_id: u64,
    pub owner_signer: PrivateOramOwnerCleanupSignerV1,
    pub owner_store_incarnation_digest: String,
    pub expected_genesis_state: PrivateOramOwnerLifecycleStateV1,
    pub authority_registry_digest: String,
    pub owner_registry_digest: String,
    pub enrollment_operation_id: String,
    pub prepared_record_digest: String,
}

impl Debug for PrivateOramOwnerEnrollmentPreparedV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerEnrollmentPreparedV1")
            .field("version", &self.version)
            .field("capability_epoch", &self.capability_epoch)
            .field("membership_epoch", &self.membership_epoch)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("consensus_history_id_digest", &"[redacted]")
            .field("raft_group_id_digest", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("owner_enrollment_id", &"[redacted]")
            .field("owner_store_incarnation_digest", &"[redacted]")
            .field("expected_genesis_state", &self.expected_genesis_state)
            .field("prepared_record_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerEnrollmentGenesisCommitmentV1 {
    pub version: u16,
    pub prepared_record_digest: String,
    pub enrollment_operation_id: String,
    pub collection_id: String,
    pub collection_incarnation_digest: String,
    pub owner_enrollment_id: String,
    pub owner_peer_id: u64,
    pub owner_store_incarnation_digest: String,
    pub lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    pub owner_signer: PrivateOramOwnerCleanupSignerV1,
    pub commitment_digest: String,
    pub signature: PrivateOramOwnerCleanupSignatureV1,
}

impl Debug for PrivateOramOwnerEnrollmentGenesisCommitmentV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerEnrollmentGenesisCommitmentV1")
            .field("version", &self.version)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("lifecycle_state", &self.lifecycle_state)
            .field("prepared_record_digest", &"[redacted]")
            .field("owner_enrollment_id", &"[redacted]")
            .field("owner_store_incarnation_digest", &"[redacted]")
            .field("owner_signer", &"[redacted]")
            .field("commitment_digest", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerEnrollmentGenesisCommitmentV1 {
    commitment: PrivateOramOwnerEnrollmentGenesisCommitmentV1,
}

impl VerifiedPrivateOramOwnerEnrollmentGenesisCommitmentV1 {
    pub fn commitment(&self) -> &PrivateOramOwnerEnrollmentGenesisCommitmentV1 {
        &self.commitment
    }
}

impl Debug for VerifiedPrivateOramOwnerEnrollmentGenesisCommitmentV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramOwnerEnrollmentGenesisCommitmentV1")
            .field("commitment", &self.commitment)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerLifecycleStatusModeV1 {
    ReadyExact,
    UnreconciledTerminal,
    RepairPending,
    CorruptOrForked,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerLifecycleStatusChallengeV1 {
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
    pub attempt_id: String,
    pub attempt_context_digest: String,
    pub challenge_nonce: String,
    pub expected_checkpoint_record_digest: String,
    #[serde(with = "decimal_u64")]
    pub expected_checkpoint_sequence: u64,
    pub owner_index: u32,
    pub owner_enrollment_id: String,
    pub owner_peer_id: u64,
    pub owner_store_incarnation_digest: String,
    pub authority_registry_digest: String,
    pub owner_registry_digest: String,
}

impl Debug for PrivateOramOwnerLifecycleStatusChallengeV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerLifecycleStatusChallengeV1")
            .field("version", &self.version)
            .field("capability_epoch", &self.capability_epoch)
            .field("membership_epoch", &self.membership_epoch)
            .field(
                "expected_checkpoint_sequence",
                &self.expected_checkpoint_sequence,
            )
            .field("owner_index", &self.owner_index)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("attempt_id", &"[redacted]")
            .field("challenge_nonce", &"[redacted]")
            .field("expected_checkpoint_record_digest", &"[redacted]")
            .field("owner_enrollment_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerLifecycleStatusAttestationV1 {
    pub version: u16,
    pub challenge: PrivateOramOwnerLifecycleStatusChallengeV1,
    pub observed_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    pub status_mode: PrivateOramOwnerLifecycleStatusModeV1,
    pub terminal_capacity_ready: bool,
    pub owner_signer: PrivateOramOwnerCleanupSignerV1,
    pub attestation_digest: String,
    pub signature: PrivateOramOwnerCleanupSignatureV1,
}

impl Debug for PrivateOramOwnerLifecycleStatusAttestationV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerLifecycleStatusAttestationV1")
            .field("version", &self.version)
            .field("challenge", &self.challenge)
            .field("observed_lifecycle_state", &self.observed_lifecycle_state)
            .field("status_mode", &self.status_mode)
            .field("terminal_capacity_ready", &self.terminal_capacity_ready)
            .field("owner_signer", &"[redacted]")
            .field("attestation_digest", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerLifecycleStatusAttestationV1 {
    attestation: PrivateOramOwnerLifecycleStatusAttestationV1,
}

impl VerifiedPrivateOramOwnerLifecycleStatusAttestationV1 {
    pub fn attestation(&self) -> &PrivateOramOwnerLifecycleStatusAttestationV1 {
        &self.attestation
    }
}

impl Debug for VerifiedPrivateOramOwnerLifecycleStatusAttestationV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramOwnerLifecycleStatusAttestationV1")
            .field("attestation", &self.attestation)
            .finish()
    }
}

pub fn new_private_oram_owner_lifecycle_challenge_nonce_v1()
-> Result<String, PrivateOramOwnerLifecycleError> {
    let mut nonce = [0u8; CHALLENGE_BYTES];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| PrivateOramOwnerLifecycleError::RandomnessUnavailable)?;
    Ok(BASE64URL_NOPAD.encode(&nonce))
}

pub fn prepare_private_oram_owner_enrollment_v1(
    mut prepared: PrivateOramOwnerEnrollmentPreparedV1,
) -> Result<PrivateOramOwnerEnrollmentPreparedV1, PrivateOramOwnerLifecycleError> {
    prepared.version = PRIVATE_ORAM_OWNER_ENROLLMENT_PROTOCOL_VERSION_V1;
    prepared.prepared_record_digest.clear();
    validate_enrollment_prepared_shape(&prepared, false)?;
    prepared.prepared_record_digest = enrollment_prepared_digest(&prepared)?;
    validate_enrollment_prepared_shape(&prepared, true)?;
    Ok(prepared)
}

pub fn validate_private_oram_owner_enrollment_prepared_v1(
    prepared: &PrivateOramOwnerEnrollmentPreparedV1,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    validate_enrollment_prepared_shape(prepared, true)
}

pub fn validate_private_oram_owner_lifecycle_state_v1(
    state: &PrivateOramOwnerLifecycleStateV1,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    validate_lifecycle_state(state)
}

pub fn validate_private_oram_owner_lifecycle_signer_v1(
    signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    validate_signer(signer)
}

pub fn encode_private_oram_owner_enrollment_prepared_v1(
    prepared: &PrivateOramOwnerEnrollmentPreparedV1,
) -> Result<Vec<u8>, PrivateOramOwnerLifecycleError> {
    validate_private_oram_owner_enrollment_prepared_v1(prepared)?;
    canonical_json(prepared)
}

pub fn decode_private_oram_owner_enrollment_prepared_v1(
    bytes: &[u8],
) -> Result<PrivateOramOwnerEnrollmentPreparedV1, PrivateOramOwnerLifecycleError> {
    let value = canonical_decode(bytes)?;
    validate_private_oram_owner_enrollment_prepared_v1(&value)?;
    Ok(value)
}

pub fn sign_private_oram_owner_enrollment_genesis_commitment_v1(
    owner_key: &Ed25519KeyPair,
    prepared: &PrivateOramOwnerEnrollmentPreparedV1,
) -> Result<PrivateOramOwnerEnrollmentGenesisCommitmentV1, PrivateOramOwnerLifecycleError> {
    validate_enrollment_prepared_shape(prepared, true)?;
    let expected_public_key = BASE64URL_NOPAD.encode(owner_key.public_key().as_ref());
    if prepared.owner_signer.public_key != expected_public_key {
        return Err(PrivateOramOwnerLifecycleError::SignerMismatch);
    }
    let mut commitment = PrivateOramOwnerEnrollmentGenesisCommitmentV1 {
        version: PRIVATE_ORAM_OWNER_ENROLLMENT_PROTOCOL_VERSION_V1,
        prepared_record_digest: prepared.prepared_record_digest.clone(),
        enrollment_operation_id: prepared.enrollment_operation_id.clone(),
        collection_id: prepared.collection_id.clone(),
        collection_incarnation_digest: prepared.collection_incarnation_digest.clone(),
        owner_enrollment_id: prepared.owner_enrollment_id.clone(),
        owner_peer_id: prepared.owner_peer_id,
        owner_store_incarnation_digest: prepared.owner_store_incarnation_digest.clone(),
        lifecycle_state: prepared.expected_genesis_state.clone(),
        owner_signer: prepared.owner_signer.clone(),
        commitment_digest: String::new(),
        signature: empty_signature(&prepared.owner_signer),
    };
    commitment.commitment_digest = enrollment_commitment_digest(&commitment)?;
    let signature = owner_key.sign(&signature_message(
        PRIVATE_ORAM_OWNER_ENROLLMENT_GENESIS_SIGNATURE_DOMAIN_V1,
        &commitment.commitment_digest,
    )?);
    commitment.signature.sig = BASE64URL_NOPAD.encode(signature.as_ref());
    validate_enrollment_commitment_shape(&commitment)?;
    Ok(commitment)
}

pub fn validate_private_oram_owner_enrollment_genesis_commitment_v1(
    commitment: &PrivateOramOwnerEnrollmentGenesisCommitmentV1,
    prepared: &PrivateOramOwnerEnrollmentPreparedV1,
) -> Result<VerifiedPrivateOramOwnerEnrollmentGenesisCommitmentV1, PrivateOramOwnerLifecycleError> {
    validate_enrollment_prepared_shape(prepared, true)?;
    validate_enrollment_commitment_shape(commitment)?;
    if commitment.prepared_record_digest != prepared.prepared_record_digest
        || commitment.enrollment_operation_id != prepared.enrollment_operation_id
        || commitment.collection_id != prepared.collection_id
        || commitment.collection_incarnation_digest != prepared.collection_incarnation_digest
        || commitment.owner_enrollment_id != prepared.owner_enrollment_id
        || commitment.owner_peer_id != prepared.owner_peer_id
        || commitment.owner_store_incarnation_digest != prepared.owner_store_incarnation_digest
        || commitment.lifecycle_state != prepared.expected_genesis_state
        || commitment.owner_signer != prepared.owner_signer
    {
        return Err(PrivateOramOwnerLifecycleError::ContextMismatch);
    }
    verify_signature(
        &commitment.owner_signer,
        &commitment.signature,
        PRIVATE_ORAM_OWNER_ENROLLMENT_GENESIS_SIGNATURE_DOMAIN_V1,
        &commitment.commitment_digest,
    )?;
    Ok(VerifiedPrivateOramOwnerEnrollmentGenesisCommitmentV1 {
        commitment: commitment.clone(),
    })
}

pub fn sign_private_oram_owner_lifecycle_status_attestation_v1(
    owner_key: &Ed25519KeyPair,
    challenge: PrivateOramOwnerLifecycleStatusChallengeV1,
    observed_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    status_mode: PrivateOramOwnerLifecycleStatusModeV1,
    terminal_capacity_ready: bool,
    owner_signer: PrivateOramOwnerCleanupSignerV1,
) -> Result<PrivateOramOwnerLifecycleStatusAttestationV1, PrivateOramOwnerLifecycleError> {
    validate_status_challenge(&challenge)?;
    validate_lifecycle_state(&observed_lifecycle_state)?;
    if owner_signer.public_key != BASE64URL_NOPAD.encode(owner_key.public_key().as_ref())
        || observed_lifecycle_state.owner_store_incarnation_digest
            != challenge.owner_store_incarnation_digest
    {
        return Err(PrivateOramOwnerLifecycleError::SignerMismatch);
    }
    let mut attestation = PrivateOramOwnerLifecycleStatusAttestationV1 {
        version: PRIVATE_ORAM_OWNER_STATUS_PROTOCOL_VERSION_V1,
        challenge,
        observed_lifecycle_state,
        status_mode,
        terminal_capacity_ready,
        owner_signer: owner_signer.clone(),
        attestation_digest: String::new(),
        signature: empty_signature(&owner_signer),
    };
    attestation.attestation_digest = status_attestation_digest(&attestation)?;
    let signature = owner_key.sign(&signature_message(
        PRIVATE_ORAM_OWNER_STATUS_SIGNATURE_DOMAIN_V1,
        &attestation.attestation_digest,
    )?);
    attestation.signature.sig = BASE64URL_NOPAD.encode(signature.as_ref());
    validate_status_attestation_shape(&attestation)?;
    Ok(attestation)
}

pub fn validate_private_oram_owner_lifecycle_status_attestation_v1(
    attestation: &PrivateOramOwnerLifecycleStatusAttestationV1,
    expected_challenge: &PrivateOramOwnerLifecycleStatusChallengeV1,
    expected_signer: &PrivateOramOwnerCleanupSignerV1,
    expected_lifecycle_state: &PrivateOramOwnerLifecycleStateV1,
) -> Result<VerifiedPrivateOramOwnerLifecycleStatusAttestationV1, PrivateOramOwnerLifecycleError> {
    validate_status_attestation_shape(attestation)?;
    if &attestation.challenge != expected_challenge
        || &attestation.owner_signer != expected_signer
        || &attestation.observed_lifecycle_state != expected_lifecycle_state
        || attestation.status_mode != PrivateOramOwnerLifecycleStatusModeV1::ReadyExact
        || !attestation.terminal_capacity_ready
    {
        return Err(PrivateOramOwnerLifecycleError::ContextMismatch);
    }
    verify_signature(
        expected_signer,
        &attestation.signature,
        PRIVATE_ORAM_OWNER_STATUS_SIGNATURE_DOMAIN_V1,
        &attestation.attestation_digest,
    )?;
    Ok(VerifiedPrivateOramOwnerLifecycleStatusAttestationV1 {
        attestation: attestation.clone(),
    })
}

pub fn encode_private_oram_owner_lifecycle_status_attestation_v1(
    attestation: &PrivateOramOwnerLifecycleStatusAttestationV1,
) -> Result<Vec<u8>, PrivateOramOwnerLifecycleError> {
    validate_status_attestation_shape(attestation)?;
    canonical_json(attestation)
}

pub fn decode_private_oram_owner_lifecycle_status_attestation_v1(
    bytes: &[u8],
) -> Result<PrivateOramOwnerLifecycleStatusAttestationV1, PrivateOramOwnerLifecycleError> {
    let value = canonical_decode(bytes)?;
    validate_status_attestation_shape(&value)?;
    Ok(value)
}

pub fn encode_private_oram_owner_enrollment_genesis_commitment_v1(
    commitment: &PrivateOramOwnerEnrollmentGenesisCommitmentV1,
) -> Result<Vec<u8>, PrivateOramOwnerLifecycleError> {
    validate_enrollment_commitment_shape(commitment)?;
    canonical_json(commitment)
}

pub fn decode_private_oram_owner_enrollment_genesis_commitment_v1(
    bytes: &[u8],
) -> Result<PrivateOramOwnerEnrollmentGenesisCommitmentV1, PrivateOramOwnerLifecycleError> {
    let value = canonical_decode(bytes)?;
    validate_enrollment_commitment_shape(&value)?;
    Ok(value)
}

fn validate_enrollment_prepared_shape(
    value: &PrivateOramOwnerEnrollmentPreparedV1,
    require_digest: bool,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    if value.version != PRIVATE_ORAM_OWNER_ENROLLMENT_PROTOCOL_VERSION_V1
        || value.capability_epoch == 0
        || value.membership_epoch == 0
        || value.owner_peer_id == 0
        || value.expected_genesis_state.generation != 0
        || value.expected_genesis_state.owner_store_incarnation_digest
            != value.owner_store_incarnation_digest
    {
        return Err(PrivateOramOwnerLifecycleError::InvalidField("enrollment"));
    }
    for digest in [
        &value.consensus_history_id_digest,
        &value.raft_group_id_digest,
        &value.collection_lifetime_id_digest,
        &value.collection_incarnation_digest,
        &value.activation_anchor_digest,
        &value.protocol_capability_digest,
        &value.owner_enrollment_id,
        &value.owner_store_incarnation_digest,
        &value.authority_registry_digest,
        &value.owner_registry_digest,
        &value.enrollment_operation_id,
    ] {
        validate_digest(digest, "enrollment")?;
    }
    validate_identifier(&value.collection_id, "collection_id")?;
    validate_signer(&value.owner_signer)?;
    validate_lifecycle_state(&value.expected_genesis_state)?;
    if value.expected_genesis_state
        != private_oram_owner_lifecycle_genesis_state_v1(
            value.owner_store_incarnation_digest.clone(),
        )
        .map_err(|_| PrivateOramOwnerLifecycleError::InvalidField("expected_genesis_state"))?
    {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "expected_genesis_state",
        ));
    }
    if require_digest {
        validate_digest(&value.prepared_record_digest, "prepared_record_digest")?;
        if value.prepared_record_digest != enrollment_prepared_digest(value)? {
            return Err(PrivateOramOwnerLifecycleError::InvalidField(
                "prepared_record_digest",
            ));
        }
    } else if !value.prepared_record_digest.is_empty() {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "prepared_record_digest",
        ));
    }
    ensure_canonical_size(value)
}

fn validate_enrollment_commitment_shape(
    value: &PrivateOramOwnerEnrollmentGenesisCommitmentV1,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    if value.version != PRIVATE_ORAM_OWNER_ENROLLMENT_PROTOCOL_VERSION_V1
        || value.owner_peer_id == 0
        || value.lifecycle_state.generation != 0
        || value.lifecycle_state.owner_store_incarnation_digest
            != value.owner_store_incarnation_digest
    {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "genesis_commitment",
        ));
    }
    for digest in [
        &value.prepared_record_digest,
        &value.enrollment_operation_id,
        &value.collection_incarnation_digest,
        &value.owner_enrollment_id,
        &value.owner_store_incarnation_digest,
        &value.commitment_digest,
    ] {
        validate_digest(digest, "genesis_commitment")?;
    }
    validate_identifier(&value.collection_id, "collection_id")?;
    validate_signer(&value.owner_signer)?;
    validate_lifecycle_state(&value.lifecycle_state)?;
    if value.lifecycle_state
        != private_oram_owner_lifecycle_genesis_state_v1(
            value.owner_store_incarnation_digest.clone(),
        )
        .map_err(|_| PrivateOramOwnerLifecycleError::InvalidField("lifecycle_state"))?
    {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "lifecycle_state",
        ));
    }
    validate_signature_shape(&value.signature, &value.owner_signer)?;
    if value.commitment_digest != enrollment_commitment_digest(value)? {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "commitment_digest",
        ));
    }
    ensure_canonical_size(value)
}

fn validate_status_challenge(
    value: &PrivateOramOwnerLifecycleStatusChallengeV1,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    if value.version != PRIVATE_ORAM_OWNER_STATUS_PROTOCOL_VERSION_V1
        || value.capability_epoch == 0
        || value.membership_epoch == 0
        || value.expected_checkpoint_sequence == 0
        || value.owner_peer_id == 0
    {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "status_challenge",
        ));
    }
    for digest in [
        &value.consensus_history_id_digest,
        &value.raft_group_id_digest,
        &value.collection_lifetime_id_digest,
        &value.collection_incarnation_digest,
        &value.activation_anchor_digest,
        &value.protocol_capability_digest,
        &value.attempt_id,
        &value.attempt_context_digest,
        &value.expected_checkpoint_record_digest,
        &value.owner_enrollment_id,
        &value.owner_store_incarnation_digest,
        &value.authority_registry_digest,
        &value.owner_registry_digest,
    ] {
        validate_digest(digest, "status_challenge")?;
    }
    validate_identifier(&value.collection_id, "collection_id")?;
    validate_base64_exact(&value.challenge_nonce, CHALLENGE_BYTES, "challenge_nonce")
}

fn validate_status_attestation_shape(
    value: &PrivateOramOwnerLifecycleStatusAttestationV1,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    if value.version != PRIVATE_ORAM_OWNER_STATUS_PROTOCOL_VERSION_V1
        || value
            .observed_lifecycle_state
            .owner_store_incarnation_digest
            != value.challenge.owner_store_incarnation_digest
    {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "status_attestation",
        ));
    }
    validate_status_challenge(&value.challenge)?;
    validate_lifecycle_state(&value.observed_lifecycle_state)?;
    validate_signer(&value.owner_signer)?;
    validate_signature_shape(&value.signature, &value.owner_signer)?;
    validate_digest(&value.attestation_digest, "attestation_digest")?;
    if value.attestation_digest != status_attestation_digest(value)? {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "attestation_digest",
        ));
    }
    ensure_canonical_size(value)
}

fn enrollment_prepared_digest(
    value: &PrivateOramOwnerEnrollmentPreparedV1,
) -> Result<String, PrivateOramOwnerLifecycleError> {
    #[derive(Serialize)]
    struct Core<'a> {
        version: u16,
        consensus_history_id_digest: &'a str,
        raft_group_id_digest: &'a str,
        collection_id: &'a str,
        collection_lifetime_id_digest: &'a str,
        collection_incarnation_digest: &'a str,
        activation_anchor_digest: &'a str,
        capability_epoch: u64,
        protocol_capability_digest: &'a str,
        membership_epoch: u64,
        owner_enrollment_id: &'a str,
        owner_peer_id: u64,
        owner_signer: &'a PrivateOramOwnerCleanupSignerV1,
        owner_store_incarnation_digest: &'a str,
        expected_genesis_state: &'a PrivateOramOwnerLifecycleStateV1,
        authority_registry_digest: &'a str,
        owner_registry_digest: &'a str,
        enrollment_operation_id: &'a str,
    }
    digest_canonical(
        ENROLLMENT_PREPARED_DIGEST_DOMAIN_V1,
        &Core {
            version: value.version,
            consensus_history_id_digest: &value.consensus_history_id_digest,
            raft_group_id_digest: &value.raft_group_id_digest,
            collection_id: &value.collection_id,
            collection_lifetime_id_digest: &value.collection_lifetime_id_digest,
            collection_incarnation_digest: &value.collection_incarnation_digest,
            activation_anchor_digest: &value.activation_anchor_digest,
            capability_epoch: value.capability_epoch,
            protocol_capability_digest: &value.protocol_capability_digest,
            membership_epoch: value.membership_epoch,
            owner_enrollment_id: &value.owner_enrollment_id,
            owner_peer_id: value.owner_peer_id,
            owner_signer: &value.owner_signer,
            owner_store_incarnation_digest: &value.owner_store_incarnation_digest,
            expected_genesis_state: &value.expected_genesis_state,
            authority_registry_digest: &value.authority_registry_digest,
            owner_registry_digest: &value.owner_registry_digest,
            enrollment_operation_id: &value.enrollment_operation_id,
        },
    )
}

fn enrollment_commitment_digest(
    value: &PrivateOramOwnerEnrollmentGenesisCommitmentV1,
) -> Result<String, PrivateOramOwnerLifecycleError> {
    #[derive(Serialize)]
    struct Core<'a> {
        version: u16,
        prepared_record_digest: &'a str,
        enrollment_operation_id: &'a str,
        collection_id: &'a str,
        collection_incarnation_digest: &'a str,
        owner_enrollment_id: &'a str,
        owner_peer_id: u64,
        owner_store_incarnation_digest: &'a str,
        lifecycle_state: &'a PrivateOramOwnerLifecycleStateV1,
        owner_signer: &'a PrivateOramOwnerCleanupSignerV1,
    }
    digest_canonical(
        ENROLLMENT_COMMITMENT_DIGEST_DOMAIN_V1,
        &Core {
            version: value.version,
            prepared_record_digest: &value.prepared_record_digest,
            enrollment_operation_id: &value.enrollment_operation_id,
            collection_id: &value.collection_id,
            collection_incarnation_digest: &value.collection_incarnation_digest,
            owner_enrollment_id: &value.owner_enrollment_id,
            owner_peer_id: value.owner_peer_id,
            owner_store_incarnation_digest: &value.owner_store_incarnation_digest,
            lifecycle_state: &value.lifecycle_state,
            owner_signer: &value.owner_signer,
        },
    )
}

fn status_attestation_digest(
    value: &PrivateOramOwnerLifecycleStatusAttestationV1,
) -> Result<String, PrivateOramOwnerLifecycleError> {
    #[derive(Serialize)]
    struct Core<'a> {
        version: u16,
        challenge: &'a PrivateOramOwnerLifecycleStatusChallengeV1,
        observed_lifecycle_state: &'a PrivateOramOwnerLifecycleStateV1,
        status_mode: PrivateOramOwnerLifecycleStatusModeV1,
        terminal_capacity_ready: bool,
        owner_signer: &'a PrivateOramOwnerCleanupSignerV1,
    }
    digest_canonical(
        OWNER_STATUS_DIGEST_DOMAIN_V1,
        &Core {
            version: value.version,
            challenge: &value.challenge,
            observed_lifecycle_state: &value.observed_lifecycle_state,
            status_mode: value.status_mode,
            terminal_capacity_ready: value.terminal_capacity_ready,
            owner_signer: &value.owner_signer,
        },
    )
}

fn digest_canonical<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, PrivateOramOwnerLifecycleError> {
    let encoded = canonical_json(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(encoded.len())
            .map_err(|_| PrivateOramOwnerLifecycleError::NonCanonicalEncoding)?
            .to_be_bytes(),
    );
    hasher.update(encoded);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
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

fn signature_message(
    domain: &str,
    digest: &str,
) -> Result<Vec<u8>, PrivateOramOwnerLifecycleError> {
    validate_digest(digest, "signature_digest")?;
    let mut message = Vec::with_capacity(domain.len() + DIGEST_BYTES + 16);
    message.extend_from_slice(
        &u64::try_from(domain.len())
            .map_err(|_| PrivateOramOwnerLifecycleError::InvalidField("signature_domain"))?
            .to_be_bytes(),
    );
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(
        &BASE64URL_NOPAD
            .decode(digest.as_bytes())
            .map_err(|_| PrivateOramOwnerLifecycleError::InvalidField("signature_digest"))?,
    );
    Ok(message)
}

fn verify_signature(
    signer: &PrivateOramOwnerCleanupSignerV1,
    signature: &PrivateOramOwnerCleanupSignatureV1,
    domain: &str,
    digest: &str,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    validate_signer(signer)?;
    validate_signature_shape(signature, signer)?;
    let public_key = BASE64URL_NOPAD
        .decode(signer.public_key.as_bytes())
        .map_err(|_| PrivateOramOwnerLifecycleError::InvalidField("public_key"))?;
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| PrivateOramOwnerLifecycleError::InvalidSignature)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signature_message(domain, digest)?, &signature_bytes)
        .map_err(|_| PrivateOramOwnerLifecycleError::InvalidSignature)
}

fn validate_signer(
    signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    // A signer is only well formed when `key_id` is the id derived from `public_key`; the
    // cleanup and resolution validators require the same, so a record keyed by `key_id` can
    // never carry another owner's id next to an unrelated key.
    validate_identifier(&signer.key_id, "key_id")?;
    let peer = PrivateOramPeerRecoveryPublicKeyV1 {
        version: signer.version,
        alg: signer.alg.clone(),
        key_epoch: signer.key_epoch,
        key_id: signer.key_id.clone(),
        public_key: signer.public_key.clone(),
    };
    validate_private_oram_peer_recovery_public_key_v1(&peer)
        .map(|_| ())
        .map_err(|_| PrivateOramOwnerLifecycleError::InvalidField("signer"))
}

fn validate_signature_shape(
    signature: &PrivateOramOwnerCleanupSignatureV1,
    signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    if signature.version != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION
        || signature.alg != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM
        || signature.key_epoch != signer.key_epoch
        || signature.key_id != signer.key_id
    {
        return Err(PrivateOramOwnerLifecycleError::SignerMismatch);
    }
    validate_base64_exact(&signature.sig, SIGNATURE_BYTES, "signature")
}

fn validate_lifecycle_state(
    state: &PrivateOramOwnerLifecycleStateV1,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    if state.minimum_reader_version == 0 || state.capability.is_empty() {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
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

fn validate_digest(value: &str, field: &'static str) -> Result<(), PrivateOramOwnerLifecycleError> {
    validate_base64_exact(value, DIGEST_BYTES, field)
}

fn validate_base64_exact(
    value: &str,
    expected_len: usize,
    field: &'static str,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramOwnerLifecycleError::InvalidField(field))?;
    if decoded.len() != expected_len || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(field));
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerLifecycleError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(field));
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, PrivateOramOwnerLifecycleError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| PrivateOramOwnerLifecycleError::NonCanonicalEncoding)?;
    if bytes.len() > MAX_CANONICAL_BYTES {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "canonical_bytes",
        ));
    }
    Ok(bytes)
}

fn canonical_decode<T>(bytes: &[u8]) -> Result<T, PrivateOramOwnerLifecycleError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_BYTES {
        return Err(PrivateOramOwnerLifecycleError::InvalidField(
            "canonical_bytes",
        ));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| PrivateOramOwnerLifecycleError::NonCanonicalEncoding)?;
    if serde_json::to_vec(&value)
        .map_err(|_| PrivateOramOwnerLifecycleError::NonCanonicalEncoding)?
        != bytes
    {
        return Err(PrivateOramOwnerLifecycleError::NonCanonicalEncoding);
    }
    Ok(value)
}

fn ensure_canonical_size<T: Serialize>(value: &T) -> Result<(), PrivateOramOwnerLifecycleError> {
    canonical_json(value).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        private_oram_owner_cleanup_signer_v1, private_oram_owner_lifecycle_genesis_state_v1,
    };

    fn digest(seed: u8) -> String {
        BASE64URL_NOPAD.encode(&[seed; DIGEST_BYTES])
    }

    fn fixture() -> (
        Ed25519KeyPair,
        PrivateOramOwnerEnrollmentPreparedV1,
        PrivateOramOwnerLifecycleStatusChallengeV1,
    ) {
        let key = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
        let signer = private_oram_owner_cleanup_signer_v1(&key, 3).unwrap();
        let incarnation = digest(9);
        let genesis = private_oram_owner_lifecycle_genesis_state_v1(incarnation.clone()).unwrap();
        let prepared =
            prepare_private_oram_owner_enrollment_v1(PrivateOramOwnerEnrollmentPreparedV1 {
                version: 0,
                consensus_history_id_digest: digest(1),
                raft_group_id_digest: digest(2),
                collection_id: "collection-a".to_string(),
                collection_lifetime_id_digest: digest(3),
                collection_incarnation_digest: digest(4),
                activation_anchor_digest: digest(5),
                capability_epoch: 2,
                protocol_capability_digest: digest(15),
                membership_epoch: 7,
                owner_enrollment_id: digest(6),
                owner_peer_id: 11,
                owner_signer: signer,
                owner_store_incarnation_digest: incarnation.clone(),
                expected_genesis_state: genesis,
                authority_registry_digest: digest(7),
                owner_registry_digest: digest(8),
                enrollment_operation_id: digest(10),
                prepared_record_digest: String::new(),
            })
            .unwrap();
        let challenge = PrivateOramOwnerLifecycleStatusChallengeV1 {
            version: PRIVATE_ORAM_OWNER_STATUS_PROTOCOL_VERSION_V1,
            consensus_history_id_digest: prepared.consensus_history_id_digest.clone(),
            raft_group_id_digest: prepared.raft_group_id_digest.clone(),
            collection_id: prepared.collection_id.clone(),
            collection_lifetime_id_digest: prepared.collection_lifetime_id_digest.clone(),
            collection_incarnation_digest: prepared.collection_incarnation_digest.clone(),
            activation_anchor_digest: prepared.activation_anchor_digest.clone(),
            capability_epoch: prepared.capability_epoch,
            protocol_capability_digest: prepared.protocol_capability_digest.clone(),
            membership_epoch: prepared.membership_epoch,
            attempt_id: digest(11),
            attempt_context_digest: digest(12),
            challenge_nonce: BASE64URL_NOPAD.encode(&[13; CHALLENGE_BYTES]),
            expected_checkpoint_record_digest: digest(14),
            expected_checkpoint_sequence: 1,
            owner_index: 0,
            owner_enrollment_id: prepared.owner_enrollment_id.clone(),
            owner_peer_id: prepared.owner_peer_id,
            owner_store_incarnation_digest: incarnation,
            authority_registry_digest: prepared.authority_registry_digest.clone(),
            owner_registry_digest: prepared.owner_registry_digest.clone(),
        };
        (key, prepared, challenge)
    }

    #[test]
    fn enrollment_genesis_is_exactly_bound_to_prepared_record() {
        let (key, prepared, _) = fixture();
        let commitment =
            sign_private_oram_owner_enrollment_genesis_commitment_v1(&key, &prepared).unwrap();
        let _verified =
            validate_private_oram_owner_enrollment_genesis_commitment_v1(&commitment, &prepared)
                .unwrap();
        let encoded =
            encode_private_oram_owner_enrollment_genesis_commitment_v1(&commitment).unwrap();
        assert_eq!(
            decode_private_oram_owner_enrollment_genesis_commitment_v1(&encoded).unwrap(),
            commitment
        );

        let mut replay_target = prepared.clone();
        replay_target.owner_enrollment_id = digest(99);
        replay_target.prepared_record_digest.clear();
        replay_target = prepare_private_oram_owner_enrollment_v1(replay_target).unwrap();
        assert_eq!(
            validate_private_oram_owner_enrollment_genesis_commitment_v1(
                &commitment,
                &replay_target
            ),
            Err(PrivateOramOwnerLifecycleError::ContextMismatch)
        );
    }

    #[test]
    fn owner_status_requires_exact_retained_context_and_ready_state() {
        let (key, prepared, challenge) = fixture();
        let attestation = sign_private_oram_owner_lifecycle_status_attestation_v1(
            &key,
            challenge.clone(),
            prepared.expected_genesis_state.clone(),
            PrivateOramOwnerLifecycleStatusModeV1::ReadyExact,
            true,
            prepared.owner_signer.clone(),
        )
        .unwrap();
        let _verified = validate_private_oram_owner_lifecycle_status_attestation_v1(
            &attestation,
            &challenge,
            &prepared.owner_signer,
            &prepared.expected_genesis_state,
        )
        .unwrap();
        let encoded =
            encode_private_oram_owner_lifecycle_status_attestation_v1(&attestation).unwrap();
        assert_eq!(
            decode_private_oram_owner_lifecycle_status_attestation_v1(&encoded).unwrap(),
            attestation
        );

        let mut foreign_attempt = challenge.clone();
        foreign_attempt.attempt_id = digest(98);
        assert_eq!(
            validate_private_oram_owner_lifecycle_status_attestation_v1(
                &attestation,
                &foreign_attempt,
                &prepared.owner_signer,
                &prepared.expected_genesis_state,
            ),
            Err(PrivateOramOwnerLifecycleError::ContextMismatch)
        );

        let mut status_tampered = attestation.clone();
        status_tampered.terminal_capacity_ready = false;
        status_tampered.attestation_digest = status_attestation_digest(&status_tampered).unwrap();
        assert_eq!(
            validate_private_oram_owner_lifecycle_status_attestation_v1(
                &status_tampered,
                &challenge,
                &prepared.owner_signer,
                &prepared.expected_genesis_state,
            ),
            Err(PrivateOramOwnerLifecycleError::ContextMismatch)
        );
        assert_eq!(
            verify_signature(
                &prepared.owner_signer,
                &status_tampered.signature,
                PRIVATE_ORAM_OWNER_STATUS_SIGNATURE_DOMAIN_V1,
                &status_tampered.attestation_digest,
            ),
            Err(PrivateOramOwnerLifecycleError::InvalidSignature)
        );

        let repair_pending = sign_private_oram_owner_lifecycle_status_attestation_v1(
            &key,
            challenge.clone(),
            prepared.expected_genesis_state.clone(),
            PrivateOramOwnerLifecycleStatusModeV1::RepairPending,
            true,
            prepared.owner_signer.clone(),
        )
        .unwrap();
        assert_eq!(
            validate_private_oram_owner_lifecycle_status_attestation_v1(
                &repair_pending,
                &challenge,
                &prepared.owner_signer,
                &prepared.expected_genesis_state,
            ),
            Err(PrivateOramOwnerLifecycleError::ContextMismatch)
        );
    }

    #[test]
    fn lifecycle_codecs_reject_unknown_and_noncanonical_fields() {
        let (key, prepared, challenge) = fixture();
        let attestation = sign_private_oram_owner_lifecycle_status_attestation_v1(
            &key,
            challenge,
            prepared.expected_genesis_state,
            PrivateOramOwnerLifecycleStatusModeV1::ReadyExact,
            true,
            prepared.owner_signer,
        )
        .unwrap();
        let encoded =
            encode_private_oram_owner_lifecycle_status_attestation_v1(&attestation).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(
            decode_private_oram_owner_lifecycle_status_attestation_v1(
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
        let padded = format!(" {}", String::from_utf8(encoded).unwrap());
        assert!(
            decode_private_oram_owner_lifecycle_status_attestation_v1(padded.as_bytes()).is_err()
        );
    }

    mod field_mutation_fuzz {
        use proptest::prelude::*;

        use super::*;
        use crate::json_mutation::mutate_json_leaf;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(192))]

            /// Every scalar field of a genesis commitment or status attestation is covered by
            /// its digest and signature: changing any one of them is rejected, for the
            /// attestation even when the mutated challenge is handed over as the expected one.
            #[test]
            fn every_field_mutation_is_rejected(index in any::<usize>(), salt in any::<u8>()) {
                let (key, prepared, challenge) = fixture();
                let commitment =
                    sign_private_oram_owner_enrollment_genesis_commitment_v1(&key, &prepared)
                        .unwrap();
                let mut value = serde_json::to_value(&commitment).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) =
                    serde_json::from_value::<PrivateOramOwnerEnrollmentGenesisCommitmentV1>(value)
                {
                    prop_assert!(
                        validate_private_oram_owner_enrollment_genesis_commitment_v1(
                            &mutated, &prepared,
                        )
                        .is_err(),
                        "commitment mutation at {} was accepted",
                        path
                    );
                }

                let attestation = sign_private_oram_owner_lifecycle_status_attestation_v1(
                    &key,
                    challenge,
                    prepared.expected_genesis_state.clone(),
                    PrivateOramOwnerLifecycleStatusModeV1::ReadyExact,
                    true,
                    prepared.owner_signer.clone(),
                )
                .unwrap();
                let mut value = serde_json::to_value(&attestation).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) =
                    serde_json::from_value::<PrivateOramOwnerLifecycleStatusAttestationV1>(value)
                {
                    prop_assert!(
                        validate_private_oram_owner_lifecycle_status_attestation_v1(
                            &mutated,
                            &mutated.challenge,
                            &prepared.owner_signer,
                            &prepared.expected_genesis_state,
                        )
                        .is_err(),
                        "attestation mutation at {} was accepted",
                        path
                    );
                }
            }
        }
    }
}
