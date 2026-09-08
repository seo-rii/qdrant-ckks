use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM, PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
    PrivateOramPeerRecoveryPublicKeyV1, PrivateOramPeerRecoverySignatureV2,
    private_oram_peer_recovery_public_key_v1, validate_private_oram_peer_recovery_public_key_v1,
    validate_private_oram_peer_recovery_signature_v2_shape,
};

pub const PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2: u16 = 2;
pub const PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_REQUEST_SIGNATURE_DOMAIN_V2: &str =
    "qdrant-sec/private-oram-owner-capsule-install-request-signature/v2";
pub const PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_RESPONSE_SIGNATURE_DOMAIN_V2: &str =
    "qdrant-sec/private-oram-owner-capsule-install-response-signature/v2";
pub const PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_ATTESTATION_SIGNATURE_DOMAIN_V2: &str =
    "qdrant-sec/private-oram-owner-capsule-install-attestation-signature/v2";
pub const PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_ATTESTATION_DIGEST_DOMAIN_V2: &str =
    "qdrant-sec/private-oram-owner-capsule-install-attestation-digest/v2";
pub const PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_REQUEST_DIGEST_DOMAIN_V2: &str =
    "qdrant-sec/private-oram-owner-capsule-install-request-digest/v2";
pub const PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2: usize = 128 * 1024 * 1024;
pub const PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2: usize = 64 * 1024;
pub const PRIVATE_ORAM_OWNER_CAPSULE_ATTESTATION_MAX_CANONICAL_BYTES_V2: usize = 16 * 1024;

const CHALLENGE_BYTES: usize = 16;
const BASE64URL_NOPAD_16_BYTE_LEN: usize = 22;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;
const MAX_COLLECTION_NAME_BYTES: usize = 255;
const MAX_VECTOR_NAME_BYTES: usize = 255;
const MAX_RESOURCE_ID_BYTES: usize = 256;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramOwnerCapsuleTransportError {
    #[error("private ORAM owner capsule transport protocol version is unsupported")]
    UnsupportedProtocolVersion(u16),
    #[error("private ORAM owner capsule transport field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM owner capsule transport body does not match its signed request")]
    BodyMismatch,
    #[error("private ORAM owner capsule transport response context does not match")]
    ResponseContextMismatch(&'static str),
    #[error("private ORAM owner capsule transport signature key does not match")]
    SignatureKeyMismatch,
    #[error("private ORAM owner capsule transport signature is malformed")]
    MalformedSignature,
    #[error("private ORAM owner capsule transport signature verification failed")]
    InvalidSignature,
    #[error("private ORAM owner capsule transport secure randomness is unavailable")]
    RandomnessUnavailable,
}

impl Debug for PrivateOramOwnerCapsuleTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramOwnerCapsuleTransportError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCapsuleInstallRequestV2 {
    pub protocol_version: u16,
    pub challenge_nonce: String,
    pub collection_name: String,
    pub collection_id: String,
    pub mutation_id: String,
    pub parent_descriptor_digest: String,
    pub coordinator_peer_id: u64,
    pub owner_peer_id: u64,
    pub vector_name: String,
    pub owner_signing_key_id: String,
    pub activation_registry_generation: u64,
    pub activation_manifest_digest: String,
    pub capsule_digest: String,
    pub capsule_set_digest: String,
    pub package_sha256: String,
    pub package_len: u64,
}

impl Debug for PrivateOramOwnerCapsuleInstallRequestV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCapsuleInstallRequestV2")
            .field("protocol_version", &self.protocol_version)
            .field("challenge_nonce", &"[redacted]")
            .field("collection_name", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("coordinator_peer_id", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("vector_name", &"[redacted]")
            .field("owner_signing_key_id", &"[redacted]")
            .field(
                "activation_registry_generation",
                &self.activation_registry_generation,
            )
            .field("activation_manifest_digest", &"[redacted]")
            .field("capsule_digest", &"[redacted]")
            .field("capsule_set_digest", &"[redacted]")
            .field("package_sha256", &"[redacted]")
            .field("package_len", &self.package_len)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCapsuleInstallResponseV2 {
    pub protocol_version: u16,
    pub challenge_nonce: String,
    pub coordinator_peer_id: u64,
    pub owner_peer_id: u64,
    pub request_digest: String,
    pub parent_descriptor_digest: String,
    pub capsule_digest: String,
    pub capsule_set_digest: String,
    pub activation_registry_generation: u64,
    pub activation_manifest_digest: String,
    pub receipt_digest: String,
    pub receipt_sha256: String,
    pub receipt_len: u64,
}

/// Transport-independent statement that one owner durably installed one exact capsule.
///
/// Unlike the request/response signatures, this statement has no challenge or coordinator. The
/// same evidence can therefore be produced after either a local or remote install and retained in
/// Raft state. Consensus must additionally compare `owner_public_key` with the peer pin from the
/// exact activation authority locator carried here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCapsuleInstallAttestationStatementV2 {
    pub protocol_version: u16,
    pub collection_id: String,
    pub mutation_id: String,
    pub parent_descriptor_digest: String,
    pub owner_peer_id: u64,
    pub activation_registry_generation: u64,
    pub activation_manifest_digest: String,
    pub capsule_digest: String,
    pub capsule_set_digest: String,
    pub receipt_digest: String,
    pub receipt_canonical_sha256: String,
}

impl Debug for PrivateOramOwnerCapsuleInstallAttestationStatementV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCapsuleInstallAttestationStatementV2")
            .field("protocol_version", &self.protocol_version)
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field(
                "activation_registry_generation",
                &self.activation_registry_generation,
            )
            .field("activation_manifest_digest", &"[redacted]")
            .field("capsule_digest", &"[redacted]")
            .field("capsule_set_digest", &"[redacted]")
            .field("receipt_digest", &"[redacted]")
            .field("receipt_canonical_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCapsuleInstallAttestationV2 {
    pub statement: PrivateOramOwnerCapsuleInstallAttestationStatementV2,
    pub owner_public_key: PrivateOramPeerRecoveryPublicKeyV1,
    pub signature: PrivateOramPeerRecoverySignatureV2,
}

impl Debug for PrivateOramOwnerCapsuleInstallAttestationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCapsuleInstallAttestationV2")
            .field("statement", &self.statement)
            .field("owner_public_key", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

impl Debug for PrivateOramOwnerCapsuleInstallResponseV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCapsuleInstallResponseV2")
            .field("protocol_version", &self.protocol_version)
            .field("challenge_nonce", &"[redacted]")
            .field("coordinator_peer_id", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("request_digest", &"[redacted]")
            .field("parent_descriptor_digest", &"[redacted]")
            .field("capsule_digest", &"[redacted]")
            .field("capsule_set_digest", &"[redacted]")
            .field(
                "activation_registry_generation",
                &self.activation_registry_generation,
            )
            .field("activation_manifest_digest", &"[redacted]")
            .field("receipt_digest", &"[redacted]")
            .field("receipt_sha256", &"[redacted]")
            .field("receipt_len", &self.receipt_len)
            .finish()
    }
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerCapsuleInstallRequestV2 {
    request: PrivateOramOwnerCapsuleInstallRequestV2,
    coordinator_public_key: PrivateOramPeerRecoveryPublicKeyV1,
    signature: PrivateOramPeerRecoverySignatureV2,
}

impl Debug for VerifiedPrivateOramOwnerCapsuleInstallRequestV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramOwnerCapsuleInstallRequestV2")
            .field("request", &"[redacted]")
            .field("coordinator_public_key", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

impl VerifiedPrivateOramOwnerCapsuleInstallRequestV2 {
    pub fn request(&self) -> &PrivateOramOwnerCapsuleInstallRequestV2 {
        &self.request
    }

    pub fn coordinator_public_key(&self) -> &PrivateOramPeerRecoveryPublicKeyV1 {
        &self.coordinator_public_key
    }

    pub fn signature(&self) -> &PrivateOramPeerRecoverySignatureV2 {
        &self.signature
    }
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerCapsuleInstallResponseV2 {
    request: PrivateOramOwnerCapsuleInstallRequestV2,
    response: PrivateOramOwnerCapsuleInstallResponseV2,
    owner_public_key: PrivateOramPeerRecoveryPublicKeyV1,
    signature: PrivateOramPeerRecoverySignatureV2,
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerCapsuleInstallAttestationV2 {
    attestation: PrivateOramOwnerCapsuleInstallAttestationV2,
    attestation_digest: String,
}

impl Debug for VerifiedPrivateOramOwnerCapsuleInstallAttestationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramOwnerCapsuleInstallAttestationV2")
            .field("attestation", &"[redacted]")
            .field("attestation_digest", &"[redacted]")
            .finish()
    }
}

impl VerifiedPrivateOramOwnerCapsuleInstallAttestationV2 {
    pub fn attestation(&self) -> &PrivateOramOwnerCapsuleInstallAttestationV2 {
        &self.attestation
    }

    pub fn statement(&self) -> &PrivateOramOwnerCapsuleInstallAttestationStatementV2 {
        &self.attestation.statement
    }

    pub fn attestation_digest(&self) -> &str {
        &self.attestation_digest
    }
}

impl Debug for VerifiedPrivateOramOwnerCapsuleInstallResponseV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramOwnerCapsuleInstallResponseV2")
            .field("request", &"[redacted]")
            .field("response", &"[redacted]")
            .field("owner_public_key", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

impl VerifiedPrivateOramOwnerCapsuleInstallResponseV2 {
    pub fn request(&self) -> &PrivateOramOwnerCapsuleInstallRequestV2 {
        &self.request
    }

    pub fn response(&self) -> &PrivateOramOwnerCapsuleInstallResponseV2 {
        &self.response
    }

    pub fn owner_public_key(&self) -> &PrivateOramPeerRecoveryPublicKeyV1 {
        &self.owner_public_key
    }

    pub fn signature(&self) -> &PrivateOramPeerRecoverySignatureV2 {
        &self.signature
    }
}

pub fn new_private_oram_owner_capsule_install_challenge_nonce_v2()
-> Result<String, PrivateOramOwnerCapsuleTransportError> {
    let mut challenge = [0_u8; CHALLENGE_BYTES];
    SystemRandom::new()
        .fill(&mut challenge)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::RandomnessUnavailable)?;
    Ok(BASE64URL_NOPAD.encode(&challenge))
}

pub fn private_oram_owner_capsule_canonical_sha256_v2(encoded: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(encoded))
}

pub fn private_oram_owner_capsule_install_attestation_statement_v2(
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    receipt_canonical_json: &[u8],
    receipt_digest: String,
) -> Result<
    PrivateOramOwnerCapsuleInstallAttestationStatementV2,
    PrivateOramOwnerCapsuleTransportError,
> {
    validate_private_oram_owner_capsule_install_request_v2_shape(request)?;
    if receipt_canonical_json.is_empty()
        || receipt_canonical_json.len() > PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2
    {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "receipt_len",
        ));
    }
    let statement = PrivateOramOwnerCapsuleInstallAttestationStatementV2 {
        protocol_version: PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2,
        collection_id: request.collection_id.clone(),
        mutation_id: request.mutation_id.clone(),
        parent_descriptor_digest: request.parent_descriptor_digest.clone(),
        owner_peer_id: request.owner_peer_id,
        activation_registry_generation: request.activation_registry_generation,
        activation_manifest_digest: request.activation_manifest_digest.clone(),
        capsule_digest: request.capsule_digest.clone(),
        capsule_set_digest: request.capsule_set_digest.clone(),
        receipt_digest,
        receipt_canonical_sha256: private_oram_owner_capsule_canonical_sha256_v2(
            receipt_canonical_json,
        ),
    };
    validate_private_oram_owner_capsule_install_attestation_statement_v2(&statement)?;
    Ok(statement)
}

pub fn validate_private_oram_owner_capsule_install_attestation_statement_v2(
    statement: &PrivateOramOwnerCapsuleInstallAttestationStatementV2,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    if statement.protocol_version != PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2 {
        return Err(
            PrivateOramOwnerCapsuleTransportError::UnsupportedProtocolVersion(
                statement.protocol_version,
            ),
        );
    }
    validate_resource_id(&statement.collection_id, "collection_id")?;
    decode_base64url_32(&statement.mutation_id, "mutation_id")?;
    decode_base64url_32(
        &statement.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    if statement.owner_peer_id == 0 {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "owner_peer_id",
        ));
    }
    if statement.activation_registry_generation == 0 {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "activation_registry_generation",
        ));
    }
    decode_base64url_32(
        &statement.activation_manifest_digest,
        "activation_manifest_digest",
    )?;
    decode_base64url_32(&statement.capsule_digest, "capsule_digest")?;
    decode_base64url_32(&statement.capsule_set_digest, "capsule_set_digest")?;
    decode_base64url_32(&statement.receipt_digest, "receipt_digest")?;
    decode_base64url_32(
        &statement.receipt_canonical_sha256,
        "receipt_canonical_sha256",
    )?;
    Ok(())
}

pub fn try_private_oram_owner_capsule_install_attestation_signature_message_v2(
    statement: &PrivateOramOwnerCapsuleInstallAttestationStatementV2,
    owner_public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<Vec<u8>, PrivateOramOwnerCapsuleTransportError> {
    validate_private_oram_owner_capsule_install_attestation_statement_v2(statement)?;
    validate_private_oram_peer_recovery_public_key_v1(owner_public_key)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch)?;
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_ATTESTATION_SIGNATURE_DOMAIN_V2.as_bytes(),
    )?;
    push_attestation_statement_fields(&mut message, statement)?;
    push_public_key_fields(&mut message, owner_public_key)?;
    Ok(message)
}

pub fn sign_private_oram_owner_capsule_install_attestation_v2(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    statement: &PrivateOramOwnerCapsuleInstallAttestationStatementV2,
) -> Result<PrivateOramOwnerCapsuleInstallAttestationV2, PrivateOramOwnerCapsuleTransportError> {
    let owner_public_key = private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch)?;
    let message = try_private_oram_owner_capsule_install_attestation_signature_message_v2(
        statement,
        &owner_public_key,
    )?;
    let signature = PrivateOramPeerRecoverySignatureV2 {
        version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
        alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch,
        key_id: owner_public_key.key_id.clone(),
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    };
    let attestation = PrivateOramOwnerCapsuleInstallAttestationV2 {
        statement: statement.clone(),
        owner_public_key,
        signature,
    };
    let _verified = validate_private_oram_owner_capsule_install_attestation_v2(&attestation)?;
    Ok(attestation)
}

pub fn validate_private_oram_owner_capsule_install_attestation_v2(
    attestation: &PrivateOramOwnerCapsuleInstallAttestationV2,
) -> Result<
    VerifiedPrivateOramOwnerCapsuleInstallAttestationV2,
    PrivateOramOwnerCapsuleTransportError,
> {
    let public_key =
        validate_private_oram_peer_recovery_public_key_v1(&attestation.owner_public_key)
            .map_err(|_| PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch)?;
    validate_transport_signature(&attestation.signature, &attestation.owner_public_key)?;
    let signature_bytes = decode_signature(&attestation.signature.sig)?;
    let message = try_private_oram_owner_capsule_install_attestation_signature_message_v2(
        &attestation.statement,
        &attestation.owner_public_key,
    )?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidSignature)?;
    let attestation_digest =
        private_oram_owner_capsule_install_attestation_digest_from_verified_v2(
            &message,
            &attestation.signature,
        )?;
    Ok(VerifiedPrivateOramOwnerCapsuleInstallAttestationV2 {
        attestation: attestation.clone(),
        attestation_digest,
    })
}

pub fn validate_private_oram_owner_capsule_install_attestation_for_signer_v2(
    attestation: &PrivateOramOwnerCapsuleInstallAttestationV2,
    expected_owner_public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<
    VerifiedPrivateOramOwnerCapsuleInstallAttestationV2,
    PrivateOramOwnerCapsuleTransportError,
> {
    if &attestation.owner_public_key != expected_owner_public_key {
        return Err(PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch);
    }
    validate_private_oram_owner_capsule_install_attestation_v2(attestation)
}

pub fn private_oram_owner_capsule_install_attestation_digest_v2(
    attestation: &PrivateOramOwnerCapsuleInstallAttestationV2,
) -> Result<String, PrivateOramOwnerCapsuleTransportError> {
    Ok(validate_private_oram_owner_capsule_install_attestation_v2(attestation)?.attestation_digest)
}

pub fn encode_private_oram_owner_capsule_install_attestation_v2(
    attestation: &PrivateOramOwnerCapsuleInstallAttestationV2,
) -> Result<Vec<u8>, PrivateOramOwnerCapsuleTransportError> {
    let _verified = validate_private_oram_owner_capsule_install_attestation_v2(attestation)?;
    let encoded = serde_json::to_vec(attestation)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidField("install_attestation"))?;
    if encoded.is_empty()
        || encoded.len() > PRIVATE_ORAM_OWNER_CAPSULE_ATTESTATION_MAX_CANONICAL_BYTES_V2
    {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "install_attestation",
        ));
    }
    Ok(encoded)
}

pub fn decode_private_oram_owner_capsule_install_attestation_v2(
    encoded: &[u8],
) -> Result<PrivateOramOwnerCapsuleInstallAttestationV2, PrivateOramOwnerCapsuleTransportError> {
    if encoded.is_empty()
        || encoded.len() > PRIVATE_ORAM_OWNER_CAPSULE_ATTESTATION_MAX_CANONICAL_BYTES_V2
    {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "install_attestation",
        ));
    }
    let attestation: PrivateOramOwnerCapsuleInstallAttestationV2 = serde_json::from_slice(encoded)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidField("install_attestation"))?;
    let _verified = validate_private_oram_owner_capsule_install_attestation_v2(&attestation)?;
    if encode_private_oram_owner_capsule_install_attestation_v2(&attestation)? != encoded {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "install_attestation",
        ));
    }
    Ok(attestation)
}

pub fn validate_private_oram_owner_capsule_install_request_v2_shape(
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    if request.protocol_version != PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2 {
        return Err(
            PrivateOramOwnerCapsuleTransportError::UnsupportedProtocolVersion(
                request.protocol_version,
            ),
        );
    }
    decode_base64url_exact::<CHALLENGE_BYTES>(
        &request.challenge_nonce,
        BASE64URL_NOPAD_16_BYTE_LEN,
        "challenge_nonce",
    )?;
    validate_bounded_name(
        &request.collection_name,
        MAX_COLLECTION_NAME_BYTES,
        "collection_name",
    )?;
    validate_resource_id(&request.collection_id, "collection_id")?;
    decode_base64url_32(&request.mutation_id, "mutation_id")?;
    decode_base64url_32(
        &request.parent_descriptor_digest,
        "parent_descriptor_digest",
    )?;
    if request.coordinator_peer_id == 0
        || request.owner_peer_id == 0
        || request.coordinator_peer_id == request.owner_peer_id
    {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "coordinator_peer_id",
        ));
    }
    validate_bounded_name(&request.vector_name, MAX_VECTOR_NAME_BYTES, "vector_name")?;
    validate_resource_id(&request.owner_signing_key_id, "owner_signing_key_id")?;
    if request.activation_registry_generation == 0 {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "activation_registry_generation",
        ));
    }
    decode_base64url_32(
        &request.activation_manifest_digest,
        "activation_manifest_digest",
    )?;
    decode_base64url_32(&request.capsule_digest, "capsule_digest")?;
    decode_base64url_32(&request.capsule_set_digest, "capsule_set_digest")?;
    decode_base64url_32(&request.package_sha256, "package_sha256")?;
    let package_len = usize::try_from(request.package_len)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidField("package_len"))?;
    if package_len == 0 || package_len > PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2 {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "package_len",
        ));
    }
    Ok(())
}

pub fn validate_private_oram_owner_capsule_install_package_v2(
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    package_canonical_json: &[u8],
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    validate_private_oram_owner_capsule_install_request_v2_shape(request)?;
    let expected_len = usize::try_from(request.package_len)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidField("package_len"))?;
    if package_canonical_json.len() != expected_len
        || package_canonical_json.is_empty()
        || package_canonical_json.len() > PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2
        || private_oram_owner_capsule_canonical_sha256_v2(package_canonical_json)
            != request.package_sha256
    {
        return Err(PrivateOramOwnerCapsuleTransportError::BodyMismatch);
    }
    Ok(())
}

pub fn private_oram_owner_capsule_install_request_digest_v2(
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
) -> Result<String, PrivateOramOwnerCapsuleTransportError> {
    validate_private_oram_owner_capsule_install_request_v2_shape(request)?;
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_REQUEST_DIGEST_DOMAIN_V2.as_bytes(),
    )?;
    push_request_fields(&mut message, request)?;
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

pub fn try_private_oram_owner_capsule_install_request_signature_message_v2(
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    coordinator_public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<Vec<u8>, PrivateOramOwnerCapsuleTransportError> {
    validate_private_oram_owner_capsule_install_request_v2_shape(request)?;
    validate_private_oram_peer_recovery_public_key_v1(coordinator_public_key)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch)?;
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_REQUEST_SIGNATURE_DOMAIN_V2.as_bytes(),
    )?;
    push_request_fields(&mut message, request)?;
    push_public_key_fields(&mut message, coordinator_public_key)?;
    Ok(message)
}

pub fn sign_private_oram_owner_capsule_install_request_v2(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramOwnerCapsuleTransportError> {
    let public_key = private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch)?;
    let message =
        try_private_oram_owner_capsule_install_request_signature_message_v2(request, &public_key)?;
    Ok(PrivateOramPeerRecoverySignatureV2 {
        version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
        alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch,
        key_id: public_key.key_id,
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    })
}

pub fn validate_private_oram_owner_capsule_install_request_signature_v2(
    coordinator_public_key: &PrivateOramPeerRecoveryPublicKeyV1,
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    package_canonical_json: &[u8],
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<VerifiedPrivateOramOwnerCapsuleInstallRequestV2, PrivateOramOwnerCapsuleTransportError>
{
    // The request signature already commits to `package_len` and `package_sha256`, so verify
    // it before hashing the package body: a forged request must not cost the receiver a hash
    // pass over up to `PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2` bytes.
    validate_private_oram_owner_capsule_install_request_v2_shape(request)?;
    let public_key = validate_private_oram_peer_recovery_public_key_v1(coordinator_public_key)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch)?;
    validate_transport_signature(signature, coordinator_public_key)?;
    let signature_bytes = decode_signature(&signature.sig)?;
    let message = try_private_oram_owner_capsule_install_request_signature_message_v2(
        request,
        coordinator_public_key,
    )?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidSignature)?;
    validate_private_oram_owner_capsule_install_package_v2(request, package_canonical_json)?;
    Ok(VerifiedPrivateOramOwnerCapsuleInstallRequestV2 {
        request: request.clone(),
        coordinator_public_key: coordinator_public_key.clone(),
        signature: signature.clone(),
    })
}

pub fn private_oram_owner_capsule_install_response_v2(
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    receipt_canonical_json: &[u8],
    receipt_digest: String,
) -> Result<PrivateOramOwnerCapsuleInstallResponseV2, PrivateOramOwnerCapsuleTransportError> {
    validate_private_oram_owner_capsule_install_request_v2_shape(request)?;
    decode_base64url_32(&receipt_digest, "receipt_digest")?;
    if receipt_canonical_json.is_empty()
        || receipt_canonical_json.len() > PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2
    {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(
            "receipt_len",
        ));
    }
    let response = PrivateOramOwnerCapsuleInstallResponseV2 {
        protocol_version: PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2,
        challenge_nonce: request.challenge_nonce.clone(),
        coordinator_peer_id: request.coordinator_peer_id,
        owner_peer_id: request.owner_peer_id,
        request_digest: private_oram_owner_capsule_install_request_digest_v2(request)?,
        parent_descriptor_digest: request.parent_descriptor_digest.clone(),
        capsule_digest: request.capsule_digest.clone(),
        capsule_set_digest: request.capsule_set_digest.clone(),
        activation_registry_generation: request.activation_registry_generation,
        activation_manifest_digest: request.activation_manifest_digest.clone(),
        receipt_digest,
        receipt_sha256: private_oram_owner_capsule_canonical_sha256_v2(receipt_canonical_json),
        receipt_len: u64::try_from(receipt_canonical_json.len())
            .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidField("receipt_len"))?,
    };
    validate_private_oram_owner_capsule_install_response_v2(
        request,
        &response,
        receipt_canonical_json,
    )?;
    Ok(response)
}

pub fn validate_private_oram_owner_capsule_install_response_v2(
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    response: &PrivateOramOwnerCapsuleInstallResponseV2,
    receipt_canonical_json: &[u8],
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    validate_private_oram_owner_capsule_install_request_v2_shape(request)?;
    if response.protocol_version != PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2 {
        return Err(
            PrivateOramOwnerCapsuleTransportError::UnsupportedProtocolVersion(
                response.protocol_version,
            ),
        );
    }
    decode_base64url_exact::<CHALLENGE_BYTES>(
        &response.challenge_nonce,
        BASE64URL_NOPAD_16_BYTE_LEN,
        "response.challenge_nonce",
    )?;
    for (matches, field) in [
        (
            response.challenge_nonce == request.challenge_nonce,
            "challenge_nonce",
        ),
        (
            response.coordinator_peer_id == request.coordinator_peer_id,
            "coordinator_peer_id",
        ),
        (
            response.owner_peer_id == request.owner_peer_id,
            "owner_peer_id",
        ),
        (
            response.request_digest
                == private_oram_owner_capsule_install_request_digest_v2(request)?,
            "request_digest",
        ),
        (
            response.parent_descriptor_digest == request.parent_descriptor_digest,
            "parent_descriptor_digest",
        ),
        (
            response.capsule_digest == request.capsule_digest,
            "capsule_digest",
        ),
        (
            response.capsule_set_digest == request.capsule_set_digest,
            "capsule_set_digest",
        ),
        (
            response.activation_registry_generation == request.activation_registry_generation,
            "activation_registry_generation",
        ),
        (
            response.activation_manifest_digest == request.activation_manifest_digest,
            "activation_manifest_digest",
        ),
    ] {
        if !matches {
            return Err(PrivateOramOwnerCapsuleTransportError::ResponseContextMismatch(field));
        }
    }
    decode_base64url_32(&response.request_digest, "request_digest")?;
    decode_base64url_32(&response.receipt_digest, "receipt_digest")?;
    decode_base64url_32(&response.receipt_sha256, "receipt_sha256")?;
    let receipt_len = usize::try_from(response.receipt_len)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidField("receipt_len"))?;
    if receipt_len == 0
        || receipt_len > PRIVATE_ORAM_OWNER_CAPSULE_RECEIPT_MAX_CANONICAL_BYTES_V2
        || receipt_canonical_json.len() != receipt_len
        || private_oram_owner_capsule_canonical_sha256_v2(receipt_canonical_json)
            != response.receipt_sha256
    {
        return Err(PrivateOramOwnerCapsuleTransportError::BodyMismatch);
    }
    Ok(())
}

pub fn try_private_oram_owner_capsule_install_response_signature_message_v2(
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    response: &PrivateOramOwnerCapsuleInstallResponseV2,
    receipt_canonical_json: &[u8],
    owner_public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<Vec<u8>, PrivateOramOwnerCapsuleTransportError> {
    validate_private_oram_owner_capsule_install_response_v2(
        request,
        response,
        receipt_canonical_json,
    )?;
    validate_private_oram_peer_recovery_public_key_v1(owner_public_key)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch)?;
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_RESPONSE_SIGNATURE_DOMAIN_V2.as_bytes(),
    )?;
    push_response_fields(&mut message, response)?;
    push_public_key_fields(&mut message, owner_public_key)?;
    Ok(message)
}

pub fn sign_private_oram_owner_capsule_install_response_v2(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    response: &PrivateOramOwnerCapsuleInstallResponseV2,
    receipt_canonical_json: &[u8],
) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramOwnerCapsuleTransportError> {
    let public_key = private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch)?;
    let message = try_private_oram_owner_capsule_install_response_signature_message_v2(
        request,
        response,
        receipt_canonical_json,
        &public_key,
    )?;
    Ok(PrivateOramPeerRecoverySignatureV2 {
        version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
        alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch,
        key_id: public_key.key_id,
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    })
}

pub fn validate_private_oram_owner_capsule_install_response_signature_v2(
    owner_public_key: &PrivateOramPeerRecoveryPublicKeyV1,
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    response: &PrivateOramOwnerCapsuleInstallResponseV2,
    receipt_canonical_json: &[u8],
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<VerifiedPrivateOramOwnerCapsuleInstallResponseV2, PrivateOramOwnerCapsuleTransportError>
{
    let public_key = validate_private_oram_peer_recovery_public_key_v1(owner_public_key)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch)?;
    validate_transport_signature(signature, owner_public_key)?;
    let signature_bytes = decode_signature(&signature.sig)?;
    let message = try_private_oram_owner_capsule_install_response_signature_message_v2(
        request,
        response,
        receipt_canonical_json,
        owner_public_key,
    )?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidSignature)?;
    Ok(VerifiedPrivateOramOwnerCapsuleInstallResponseV2 {
        request: request.clone(),
        response: response.clone(),
        owner_public_key: owner_public_key.clone(),
        signature: signature.clone(),
    })
}

fn validate_transport_signature(
    signature: &PrivateOramPeerRecoverySignatureV2,
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    validate_private_oram_peer_recovery_signature_v2_shape(signature)
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::MalformedSignature)?;
    if signature.alg != public_key.alg
        || signature.key_epoch != public_key.key_epoch
        || signature.key_id != public_key.key_id
    {
        return Err(PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch);
    }
    Ok(())
}

fn push_request_fields(
    message: &mut Vec<u8>,
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    push_u16(message, request.protocol_version);
    push_str(message, &request.challenge_nonce)?;
    push_str(message, &request.collection_name)?;
    push_str(message, &request.collection_id)?;
    push_str(message, &request.mutation_id)?;
    push_str(message, &request.parent_descriptor_digest)?;
    push_u64(message, request.coordinator_peer_id);
    push_u64(message, request.owner_peer_id);
    push_str(message, &request.vector_name)?;
    push_str(message, &request.owner_signing_key_id)?;
    push_u64(message, request.activation_registry_generation);
    push_str(message, &request.activation_manifest_digest)?;
    push_str(message, &request.capsule_digest)?;
    push_str(message, &request.capsule_set_digest)?;
    push_str(message, &request.package_sha256)?;
    push_u64(message, request.package_len);
    Ok(())
}

fn push_response_fields(
    message: &mut Vec<u8>,
    response: &PrivateOramOwnerCapsuleInstallResponseV2,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    push_u16(message, response.protocol_version);
    push_str(message, &response.challenge_nonce)?;
    push_u64(message, response.coordinator_peer_id);
    push_u64(message, response.owner_peer_id);
    push_str(message, &response.request_digest)?;
    push_str(message, &response.parent_descriptor_digest)?;
    push_str(message, &response.capsule_digest)?;
    push_str(message, &response.capsule_set_digest)?;
    push_u64(message, response.activation_registry_generation);
    push_str(message, &response.activation_manifest_digest)?;
    push_str(message, &response.receipt_digest)?;
    push_str(message, &response.receipt_sha256)?;
    push_u64(message, response.receipt_len);
    Ok(())
}

fn push_attestation_statement_fields(
    message: &mut Vec<u8>,
    statement: &PrivateOramOwnerCapsuleInstallAttestationStatementV2,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    push_u16(message, statement.protocol_version);
    push_str(message, &statement.collection_id)?;
    push_str(message, &statement.mutation_id)?;
    push_str(message, &statement.parent_descriptor_digest)?;
    push_u64(message, statement.owner_peer_id);
    push_u64(message, statement.activation_registry_generation);
    push_str(message, &statement.activation_manifest_digest)?;
    push_str(message, &statement.capsule_digest)?;
    push_str(message, &statement.capsule_set_digest)?;
    push_str(message, &statement.receipt_digest)?;
    push_str(message, &statement.receipt_canonical_sha256)?;
    Ok(())
}

fn private_oram_owner_capsule_install_attestation_digest_from_verified_v2(
    signature_message: &[u8],
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<String, PrivateOramOwnerCapsuleTransportError> {
    let mut message = Vec::new();
    push_domain(
        &mut message,
        PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_ATTESTATION_DIGEST_DOMAIN_V2.as_bytes(),
    )?;
    push_u64(
        &mut message,
        u64::try_from(signature_message.len()).map_err(|_| {
            PrivateOramOwnerCapsuleTransportError::InvalidField("install_attestation")
        })?,
    );
    message.extend_from_slice(signature_message);
    push_u16(&mut message, signature.version);
    push_str(&mut message, &signature.alg)?;
    push_u64(&mut message, signature.key_epoch);
    push_str(&mut message, &signature.key_id)?;
    push_str(&mut message, &signature.sig)?;
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

fn push_public_key_fields(
    message: &mut Vec<u8>,
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    push_u16(message, public_key.version);
    push_str(message, &public_key.alg)?;
    push_u64(message, public_key.key_epoch);
    push_str(message, &public_key.key_id)?;
    push_str(message, &public_key.public_key)
}

fn validate_bounded_name(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(field));
    }
    Ok(())
}

fn validate_resource_id(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    // The same charset and length as the peer recovery and external checkpoint validators, so an
    // id those refuse cannot arrive through the install path either.
    if value.is_empty()
        || value.len() > MAX_RESOURCE_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(field));
    }
    Ok(())
}

fn decode_base64url_32(
    value: &str,
    field: &'static str,
) -> Result<[u8; 32], PrivateOramOwnerCapsuleTransportError> {
    decode_base64url_exact::<32>(value, BASE64URL_NOPAD_32_BYTE_LEN, field)
}

fn decode_base64url_exact<const N: usize>(
    value: &str,
    encoded_len: usize,
    field: &'static str,
) -> Result<[u8; N], PrivateOramOwnerCapsuleTransportError> {
    if value.len() != encoded_len {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(field));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidField(field))?;
    let decoded: [u8; N] = decoded
        .try_into()
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::InvalidField(field))?;
    if BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramOwnerCapsuleTransportError::InvalidField(field));
    }
    Ok(decoded)
}

fn decode_signature(value: &str) -> Result<[u8; 64], PrivateOramOwnerCapsuleTransportError> {
    if value.len() != BASE64URL_NOPAD_64_BYTE_LEN {
        return Err(PrivateOramOwnerCapsuleTransportError::MalformedSignature);
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::MalformedSignature)?;
    let decoded: [u8; 64] = decoded
        .try_into()
        .map_err(|_| PrivateOramOwnerCapsuleTransportError::MalformedSignature)?;
    if BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramOwnerCapsuleTransportError::MalformedSignature);
    }
    Ok(decoded)
}

fn push_domain(
    message: &mut Vec<u8>,
    domain: &[u8],
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    push_u32(
        message,
        u32::try_from(domain.len()).map_err(|_| {
            PrivateOramOwnerCapsuleTransportError::InvalidField("signature_message")
        })?,
    );
    message.extend_from_slice(domain);
    Ok(())
}

fn push_str(
    message: &mut Vec<u8>,
    value: &str,
) -> Result<(), PrivateOramOwnerCapsuleTransportError> {
    push_u64(
        message,
        u64::try_from(value.len()).map_err(|_| {
            PrivateOramOwnerCapsuleTransportError::InvalidField("signature_message")
        })?,
    );
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
    use ring::signature::KeyPair;

    use super::*;

    fn key_pair(seed: u8) -> Ed25519KeyPair {
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_add(u8::try_from(index).unwrap());
        }
        Ed25519KeyPair::from_seed_unchecked(&bytes).unwrap()
    }

    fn digest(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn request(package: &[u8]) -> PrivateOramOwnerCapsuleInstallRequestV2 {
        PrivateOramOwnerCapsuleInstallRequestV2 {
            protocol_version: PRIVATE_ORAM_OWNER_CAPSULE_INSTALL_PROTOCOL_VERSION_V2,
            challenge_nonce: BASE64URL_NOPAD.encode(&[7; CHALLENGE_BYTES]),
            collection_name: "docs".to_string(),
            collection_id: "stable-collection-id".to_string(),
            mutation_id: digest(1),
            parent_descriptor_digest: digest(2),
            coordinator_peer_id: 11,
            owner_peer_id: 13,
            vector_name: "text".to_string(),
            owner_signing_key_id: "tenant-a-owner-v1".to_string(),
            activation_registry_generation: 9,
            activation_manifest_digest: digest(3),
            capsule_digest: digest(4),
            capsule_set_digest: digest(5),
            package_sha256: private_oram_owner_capsule_canonical_sha256_v2(package),
            package_len: u64::try_from(package.len()).unwrap(),
        }
    }

    #[test]
    fn owner_capsule_install_request_and_response_signatures_bind_exact_bodies() {
        let coordinator = key_pair(10);
        let owner = key_pair(70);
        let package = br#"{"capsule":"opaque"}"#;
        let request = request(package);
        let coordinator_public_key =
            private_oram_peer_recovery_public_key_v1(&coordinator, 1).unwrap();
        let request_signature =
            sign_private_oram_owner_capsule_install_request_v2(&coordinator, 1, &request).unwrap();
        let verified_request = validate_private_oram_owner_capsule_install_request_signature_v2(
            &coordinator_public_key,
            &request,
            package,
            &request_signature,
        )
        .unwrap();
        assert_eq!(verified_request.request(), &request);

        let receipt = br#"{"receipt":"opaque"}"#;
        let response =
            private_oram_owner_capsule_install_response_v2(&request, receipt, digest(6)).unwrap();
        let owner_public_key = private_oram_peer_recovery_public_key_v1(&owner, 1).unwrap();
        let response_signature = sign_private_oram_owner_capsule_install_response_v2(
            &owner, 1, &request, &response, receipt,
        )
        .unwrap();
        let verified_response = validate_private_oram_owner_capsule_install_response_signature_v2(
            &owner_public_key,
            &request,
            &response,
            receipt,
            &response_signature,
        )
        .unwrap();
        assert_eq!(verified_response.response(), &response);

        let mut wrong_package = package.to_vec();
        wrong_package[0] ^= 1;
        assert_eq!(
            validate_private_oram_owner_capsule_install_request_signature_v2(
                &coordinator_public_key,
                &request,
                &wrong_package,
                &request_signature,
            )
            .unwrap_err(),
            PrivateOramOwnerCapsuleTransportError::BodyMismatch,
        );
        let mut wrong_receipt = receipt.to_vec();
        wrong_receipt[0] ^= 1;
        assert_eq!(
            validate_private_oram_owner_capsule_install_response_signature_v2(
                &owner_public_key,
                &request,
                &response,
                &wrong_receipt,
                &response_signature,
            )
            .unwrap_err(),
            PrivateOramOwnerCapsuleTransportError::BodyMismatch,
        );
    }

    #[test]
    fn owner_capsule_install_request_verifies_the_signature_before_hashing_the_body() {
        let coordinator = key_pair(14);
        let package = br#"{"capsule":"opaque"}"#;
        let request = request(package);
        let coordinator_public_key =
            private_oram_peer_recovery_public_key_v1(&coordinator, 1).unwrap();
        let mut forged_signature =
            sign_private_oram_owner_capsule_install_request_v2(&coordinator, 1, &request).unwrap();
        forged_signature.sig = BASE64URL_NOPAD.encode(&[0x5a; 64]);

        // A body that does not match the request would fail the body check, but a request
        // whose signature does not verify must be rejected as such without hashing the body.
        let mut wrong_package = package.to_vec();
        wrong_package[0] ^= 1;
        assert_eq!(
            validate_private_oram_owner_capsule_install_request_signature_v2(
                &coordinator_public_key,
                &request,
                &wrong_package,
                &forged_signature,
            )
            .unwrap_err(),
            PrivateOramOwnerCapsuleTransportError::InvalidSignature,
        );
        assert_eq!(
            validate_private_oram_owner_capsule_install_request_signature_v2(
                &coordinator_public_key,
                &request,
                package,
                &forged_signature,
            )
            .unwrap_err(),
            PrivateOramOwnerCapsuleTransportError::InvalidSignature,
        );
    }

    #[test]
    fn owner_capsule_transport_rejects_context_and_signer_substitution() {
        let coordinator = key_pair(12);
        let other = key_pair(13);
        let owner = key_pair(90);
        let package = br#"{"capsule":"opaque"}"#;
        let request = request(package);
        let coordinator_public_key =
            private_oram_peer_recovery_public_key_v1(&coordinator, 2).unwrap();
        let signature =
            sign_private_oram_owner_capsule_install_request_v2(&coordinator, 2, &request).unwrap();
        let other_public_key = private_oram_peer_recovery_public_key_v1(&other, 2).unwrap();
        assert_eq!(
            validate_private_oram_owner_capsule_install_request_signature_v2(
                &other_public_key,
                &request,
                package,
                &signature,
            )
            .unwrap_err(),
            PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch,
        );

        let receipt = br#"{"receipt":"opaque"}"#;
        let response =
            private_oram_owner_capsule_install_response_v2(&request, receipt, digest(7)).unwrap();
        let owner_public_key = private_oram_peer_recovery_public_key_v1(&owner, 3).unwrap();
        let response_signature = sign_private_oram_owner_capsule_install_response_v2(
            &owner, 3, &request, &response, receipt,
        )
        .unwrap();
        let mut changed_request = request.clone();
        changed_request.challenge_nonce = BASE64URL_NOPAD.encode(&[8; CHALLENGE_BYTES]);
        assert!(matches!(
            validate_private_oram_owner_capsule_install_response_signature_v2(
                &owner_public_key,
                &changed_request,
                &response,
                receipt,
                &response_signature,
            ),
            Err(PrivateOramOwnerCapsuleTransportError::ResponseContextMismatch(_))
        ));

        let rendered = format!(
            "{:?}{:?}{:?}",
            request,
            response,
            validate_private_oram_owner_capsule_install_request_signature_v2(
                &coordinator_public_key,
                &request,
                package,
                &signature,
            )
            .unwrap()
        );
        for secret in [
            request.challenge_nonce.as_str(),
            request.collection_id.as_str(),
            request.mutation_id.as_str(),
            request.package_sha256.as_str(),
            coordinator
                .public_key()
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .as_str(),
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn owner_capsule_transport_nonce_and_canonical_digest_are_stable() {
        let first = new_private_oram_owner_capsule_install_challenge_nonce_v2().unwrap();
        let second = new_private_oram_owner_capsule_install_challenge_nonce_v2().unwrap();
        assert_ne!(first, second);
        decode_base64url_exact::<CHALLENGE_BYTES>(
            &first,
            BASE64URL_NOPAD_16_BYTE_LEN,
            "challenge_nonce",
        )
        .unwrap();

        let package = br#"{"capsule":"opaque"}"#;
        let request = request(package);
        assert_eq!(
            private_oram_owner_capsule_install_request_digest_v2(&request).unwrap(),
            private_oram_owner_capsule_install_request_digest_v2(&request).unwrap(),
        );
        let mut oversized = request;
        oversized.package_len =
            u64::try_from(PRIVATE_ORAM_OWNER_CAPSULE_MAX_CANONICAL_BYTES_V2).unwrap() + 1;
        assert_eq!(
            validate_private_oram_owner_capsule_install_request_v2_shape(&oversized).unwrap_err(),
            PrivateOramOwnerCapsuleTransportError::InvalidField("package_len"),
        );
    }

    #[test]
    fn durable_owner_attestation_binds_receipt_and_full_mutation_context() {
        let owner = key_pair(101);
        let package = br#"{"capsule":"opaque"}"#;
        let request = request(package);
        let receipt = br#"{"receipt":"opaque"}"#;
        let statement = private_oram_owner_capsule_install_attestation_statement_v2(
            &request,
            receipt,
            digest(31),
        )
        .unwrap();
        let attestation =
            sign_private_oram_owner_capsule_install_attestation_v2(&owner, 4, &statement).unwrap();
        let verified =
            validate_private_oram_owner_capsule_install_attestation_v2(&attestation).unwrap();
        assert_eq!(verified.statement(), &statement);
        assert_eq!(verified.attestation().owner_public_key.key_epoch, 4);
        assert_eq!(
            verified.attestation_digest(),
            private_oram_owner_capsule_install_attestation_digest_v2(&attestation).unwrap(),
        );

        let encoded =
            encode_private_oram_owner_capsule_install_attestation_v2(&attestation).unwrap();
        assert_eq!(
            decode_private_oram_owner_capsule_install_attestation_v2(&encoded).unwrap(),
            attestation,
        );
        let mut noncanonical = encoded.clone();
        noncanonical.push(b' ');
        assert_eq!(
            decode_private_oram_owner_capsule_install_attestation_v2(&noncanonical).unwrap_err(),
            PrivateOramOwnerCapsuleTransportError::InvalidField("install_attestation"),
        );

        for mutate in [
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.collection_id.push('x');
            },
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.mutation_id = digest(32);
            },
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.parent_descriptor_digest = digest(33);
            },
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.owner_peer_id += 1;
            },
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.activation_registry_generation += 1;
            },
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.activation_manifest_digest = digest(34);
            },
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.capsule_digest = digest(35);
            },
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.capsule_set_digest = digest(36);
            },
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.receipt_digest = digest(37);
            },
            |value: &mut PrivateOramOwnerCapsuleInstallAttestationV2| {
                value.statement.receipt_canonical_sha256 = digest(38);
            },
        ] {
            let mut changed = attestation.clone();
            mutate(&mut changed);
            assert_eq!(
                validate_private_oram_owner_capsule_install_attestation_v2(&changed).unwrap_err(),
                PrivateOramOwnerCapsuleTransportError::InvalidSignature,
            );
        }
    }

    #[test]
    fn durable_owner_attestation_rejects_valid_but_unpinned_signer() {
        let owner = key_pair(111);
        let attacker = key_pair(112);
        let request = request(br#"{"capsule":"opaque"}"#);
        let statement = private_oram_owner_capsule_install_attestation_statement_v2(
            &request,
            br#"{"receipt":"opaque"}"#,
            digest(41),
        )
        .unwrap();
        let attacker_attestation =
            sign_private_oram_owner_capsule_install_attestation_v2(&attacker, 5, &statement)
                .unwrap();
        let owner_public_key = private_oram_peer_recovery_public_key_v1(&owner, 5).unwrap();
        assert_eq!(
            validate_private_oram_owner_capsule_install_attestation_for_signer_v2(
                &attacker_attestation,
                &owner_public_key,
            )
            .unwrap_err(),
            PrivateOramOwnerCapsuleTransportError::SignatureKeyMismatch,
        );
    }

    mod field_mutation_fuzz {
        use proptest::prelude::*;

        use super::*;
        use crate::json_mutation::mutate_json_leaf;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(192))]

            /// Every scalar field of an install request, response or durable attestation is
            /// covered by its signature: changing any one of them is rejected.
            #[test]
            fn every_field_mutation_is_rejected(index in any::<usize>(), salt in any::<u8>()) {
                let coordinator = key_pair(10);
                let owner = key_pair(70);
                let package = br#"{"capsule":"opaque"}"#;
                let request = request(package);
                let coordinator_public_key =
                    private_oram_peer_recovery_public_key_v1(&coordinator, 1).unwrap();
                let request_signature =
                    sign_private_oram_owner_capsule_install_request_v2(&coordinator, 1, &request)
                        .unwrap();
                let mut value = serde_json::to_value(&request).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) =
                    serde_json::from_value::<PrivateOramOwnerCapsuleInstallRequestV2>(value)
                {
                    prop_assert!(
                        validate_private_oram_owner_capsule_install_request_signature_v2(
                            &coordinator_public_key,
                            &mutated,
                            package,
                            &request_signature,
                        )
                        .is_err(),
                        "request mutation at {} was accepted",
                        path
                    );
                }

                let receipt = br#"{"receipt":"opaque"}"#;
                let response =
                    private_oram_owner_capsule_install_response_v2(&request, receipt, digest(6))
                        .unwrap();
                let owner_public_key = private_oram_peer_recovery_public_key_v1(&owner, 1).unwrap();
                let response_signature = sign_private_oram_owner_capsule_install_response_v2(
                    &owner, 1, &request, &response, receipt,
                )
                .unwrap();
                let mut value = serde_json::to_value(&response).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) =
                    serde_json::from_value::<PrivateOramOwnerCapsuleInstallResponseV2>(value)
                {
                    prop_assert!(
                        validate_private_oram_owner_capsule_install_response_signature_v2(
                            &owner_public_key,
                            &request,
                            &mutated,
                            receipt,
                            &response_signature,
                        )
                        .is_err(),
                        "response mutation at {} was accepted",
                        path
                    );
                }

                let statement = private_oram_owner_capsule_install_attestation_statement_v2(
                    &request,
                    receipt,
                    digest(31),
                )
                .unwrap();
                let attestation =
                    sign_private_oram_owner_capsule_install_attestation_v2(&owner, 4, &statement)
                        .unwrap();
                let mut value = serde_json::to_value(&attestation).unwrap();
                let path = mutate_json_leaf(&mut value, index, salt);
                if let Ok(mutated) =
                    serde_json::from_value::<PrivateOramOwnerCapsuleInstallAttestationV2>(value)
                {
                    prop_assert!(
                        validate_private_oram_owner_capsule_install_attestation_v2(&mutated)
                            .is_err(),
                        "attestation mutation at {} was accepted",
                        path
                    );
                }
            }
        }
    }
}
