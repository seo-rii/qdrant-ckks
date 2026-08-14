//! State-bound authorization and evidence for private-ORAM owner cleanup.
//!
//! The types in this module do not decide that cleanup is allowed. The storage authority layer
//! must derive every authorization from one committed negative append outcome. An owner accepts an
//! authorization only when its pinned lifecycle state exactly matches the expected predecessor,
//! publishes the terminal marker durably, and then signs the derived receipt.

use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM, PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
    PrivateOramPeerRecoveryPublicKeyV1, validate_private_oram_peer_recovery_public_key_v1,
};

pub const PRIVATE_ORAM_OWNER_CLEANUP_PROTOCOL_V1: &str = "vector/private-hnsw-oram@v2";
pub const PRIVATE_ORAM_OWNER_CLEANUP_AUTHORIZATION_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_OWNER_CLEANUP_RECEIPT_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_ALL_OWNER_CLEANUP_CERTIFICATE_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_OWNER_LIFECYCLE_READER_VERSION_V1: u16 = 1;
pub const PRIVATE_ORAM_OWNER_LIFECYCLE_CAPABILITY_V1: &str = "private-oram-owner-lifecycle-root-v1";
pub const PRIVATE_ORAM_OWNER_CLEANUP_AUTHORIZATION_SIGNATURE_DOMAIN_V1: &str =
    "qdrant-sec/private-oram-owner-cleanup-authorization-signature/v1";
pub const PRIVATE_ORAM_OWNER_CLEANUP_RECEIPT_SIGNATURE_DOMAIN_V1: &str =
    "qdrant-sec/private-oram-owner-cleanup-receipt-signature/v1";

const CLEANUP_OPERATION_ID_DOMAIN_V1: &[u8] = b"qdrant-sec/private-oram-owner-cleanup-operation/v1";
const CLEANUP_AUTHORIZATION_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-cleanup-authorization/v1";
const CLEANUP_AUTHORIZATION_VERIFICATION_CONTEXT_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-cleanup-verification-context/v1";
const CLEANUP_TARGET_DIGEST_DOMAIN_V1: &[u8] = b"qdrant-sec/private-oram-owner-cleanup-target/v1";
const CLEANUP_INTENT_IDENTITY_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-cleanup-intent-identity/v1";
const CLEANUP_RECEIPT_DIGEST_DOMAIN_V1: &[u8] = b"qdrant-sec/private-oram-owner-cleanup-receipt/v1";
const CLEANUP_TERMINAL_MARKER_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-cleanup-terminal-marker/v1";
const OWNER_LIFECYCLE_GENESIS_ROOT_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-lifecycle-genesis-root/v1";
const OWNER_LIFECYCLE_STATE_ROOT_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-owner-lifecycle-state-root/v1";
const ALL_OWNER_CLEANUP_CERTIFICATE_DIGEST_DOMAIN_V1: &[u8] =
    b"qdrant-sec/private-oram-all-owner-cleanup-certificate/v1";

const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 1_024;
const MAX_OWNERS: usize = 1_024;
const MAX_CANONICAL_BYTES: usize = 8 * 1024 * 1024;

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
            return Err(serde::de::Error::custom(
                "expected canonical unsigned decimal string",
            ));
        }
        Ok(value)
    }
}

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramOwnerCleanupError {
    #[error("private ORAM owner cleanup version is unsupported")]
    UnsupportedVersion,
    #[error("private ORAM owner cleanup field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM owner cleanup transition is invalid")]
    InvalidTransition,
    #[error("private ORAM owner cleanup signer does not match")]
    SignerMismatch,
    #[error("private ORAM owner cleanup signature is invalid")]
    InvalidSignature,
    #[error("private ORAM owner cleanup certificate is incomplete")]
    IncompleteCertificate,
    #[error("private ORAM owner cleanup encoding is not canonical")]
    NonCanonicalEncoding,
}

impl Debug for PrivateOramOwnerCleanupError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramOwnerCleanupError")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCleanupSignerV1 {
    pub version: u16,
    pub alg: String,
    #[serde(with = "decimal_u64")]
    pub key_epoch: u64,
    pub key_id: String,
    pub public_key: String,
}

impl Debug for PrivateOramOwnerCleanupSignerV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCleanupSignerV1")
            .field("version", &self.version)
            .field("key_epoch", &self.key_epoch)
            .field("alg", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCleanupSignatureV1 {
    pub version: u16,
    pub alg: String,
    #[serde(with = "decimal_u64")]
    pub key_epoch: u64,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateOramOwnerCleanupSignatureV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCleanupSignatureV1")
            .field("version", &self.version)
            .field("key_epoch", &self.key_epoch)
            .field("alg", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerCleanupNegativeOutcomeKindV1 {
    PrestageAborted,
    AdmissionRejected,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerCleanupPolicyV1 {
    TombstoneAbsentOrQuarantineIntent,
    RequireMatchingIntentQuarantine,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerCleanupObservedPrestateV1 {
    Absent,
    Intent,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerCleanupTerminalStateV1 {
    TombstonedAbsent,
    Quarantined,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerCleanupPayloadStateV1 {
    NoPayload,
    QuarantineMoveRecoverable,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramOwnerCleanupBodyLocationV1 {
    None,
    Quarantine,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramCleanupRaftLocatorV1 {
    #[serde(with = "decimal_u64")]
    pub term: u64,
    #[serde(with = "decimal_u64")]
    pub index: u64,
}

impl Debug for PrivateOramCleanupRaftLocatorV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramCleanupRaftLocatorV1")
            .field("term", &self.term)
            .field("index", &self.index)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerLifecycleStateV1 {
    pub owner_store_incarnation_digest: String,
    #[serde(with = "decimal_u64")]
    pub generation: u64,
    pub state_root: String,
    pub minimum_reader_version: u16,
    pub capability: String,
}

impl Debug for PrivateOramOwnerLifecycleStateV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerLifecycleStateV1")
            .field("generation", &self.generation)
            .field("minimum_reader_version", &self.minimum_reader_version)
            .field("owner_store_incarnation_digest", &"[redacted]")
            .field("state_root", &"[redacted]")
            .field("capability", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCleanupAuthorityContextV1 {
    pub consensus_history_id_digest: String,
    pub raft_group_id_digest: String,
    pub collection_id: String,
    pub collection_lifetime_id_digest: String,
    pub collection_incarnation_digest: String,
    pub activation_anchor_digest: String,
    #[serde(with = "decimal_u64")]
    pub activation_registry_generation: u64,
    pub activation_manifest_digest: String,
    pub owner_roster_digest: String,
}

impl Debug for PrivateOramOwnerCleanupAuthorityContextV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCleanupAuthorityContextV1")
            .field(
                "activation_registry_generation",
                &self.activation_registry_generation,
            )
            .field("collection_id", &"[redacted]")
            .field("collection_incarnation_digest", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCleanupAttemptContextV1 {
    pub attempt_id: String,
    #[serde(with = "decimal_u64")]
    pub attempt_sequence: u64,
    pub mutation_id: String,
    pub mutation_digest: String,
    pub expected_aggregate_digest: String,
    pub reservation_digest: String,
    pub reservation_applied: PrivateOramCleanupRaftLocatorV1,
    #[serde(with = "decimal_u64")]
    pub lease_generation: u64,
    #[serde(with = "decimal_u64")]
    pub writer_fence: u64,
}

impl Debug for PrivateOramOwnerCleanupAttemptContextV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCleanupAttemptContextV1")
            .field("attempt_sequence", &self.attempt_sequence)
            .field("lease_generation", &self.lease_generation)
            .field("writer_fence", &self.writer_fence)
            .field("reservation_applied", &self.reservation_applied)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCleanupOutcomeContextV1 {
    pub kind: PrivateOramOwnerCleanupNegativeOutcomeKindV1,
    pub outcome_key: String,
    pub outcome_digest: String,
    pub negative_record_digest: String,
    pub outcome_applied: PrivateOramCleanupRaftLocatorV1,
}

impl Debug for PrivateOramOwnerCleanupOutcomeContextV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCleanupOutcomeContextV1")
            .field("kind", &self.kind)
            .field("outcome_applied", &self.outcome_applied)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCleanupTargetV1 {
    pub owner_index: u32,
    #[serde(with = "decimal_u64")]
    pub owner_peer_id: u64,
    pub owner_signer: PrivateOramOwnerCleanupSignerV1,
    pub expected_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    pub intent_key: String,
    pub intent_identity_digest: String,
    pub package_sha256: String,
    #[serde(with = "decimal_u64")]
    pub package_len: u64,
    pub owner_request_digest: String,
    pub prestage_receipt_digest: Option<String>,
    pub intent_marker_digest: Option<String>,
    pub parent_descriptor_digest: String,
    pub parent_lease_acquired_record_digest: String,
    pub owner_journal_descriptor_digest: Option<String>,
    pub target_digest: String,
}

impl Debug for PrivateOramOwnerCleanupTargetV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCleanupTargetV1")
            .field("owner_index", &self.owner_index)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("package_len", &self.package_len)
            .field("expected_lifecycle_state", &self.expected_lifecycle_state)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCleanupAuthorizationV1 {
    pub version: u16,
    pub protocol: String,
    pub authority: PrivateOramOwnerCleanupAuthorityContextV1,
    pub attempt: PrivateOramOwnerCleanupAttemptContextV1,
    pub outcome: PrivateOramOwnerCleanupOutcomeContextV1,
    pub target: PrivateOramOwnerCleanupTargetV1,
    pub policy: PrivateOramOwnerCleanupPolicyV1,
    pub cleanup_operation_id: String,
    pub authorization_digest: String,
}

impl Debug for PrivateOramOwnerCleanupAuthorizationV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCleanupAuthorizationV1")
            .field("version", &self.version)
            .field("attempt_sequence", &self.attempt.attempt_sequence)
            .field("owner_index", &self.target.owner_index)
            .field("owner_peer_id", &self.target.owner_peer_id)
            .field("outcome_kind", &self.outcome.kind)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivateOramOwnerCleanupAuthorizationV1 {
    pub authorization: PrivateOramOwnerCleanupAuthorizationV1,
    pub signature: PrivateOramOwnerCleanupSignatureV1,
}

impl Debug for SignedPrivateOramOwnerCleanupAuthorizationV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPrivateOramOwnerCleanupAuthorizationV1")
            .field("authorization", &self.authorization)
            .field("signature", &self.signature)
            .finish()
    }
}

/// Exact retained-consensus and registry inputs used to authenticate one cleanup grant.
///
/// This is deliberately not serializable. The storage authority layer constructs it from its
/// retained Raft state and pinned signer registries; owner-local disk data is never a source.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramOwnerCleanupAuthorizationVerificationContextV1 {
    expected_authorization: PrivateOramOwnerCleanupAuthorizationV1,
    authority_signer: PrivateOramOwnerCleanupSignerV1,
    expected_owner_signer: PrivateOramOwnerCleanupSignerV1,
    acknowledged_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    retained_cleanup_grant_digest: String,
    authority_registry_digest: String,
    owner_registry_digest: String,
    context_digest: String,
}

impl Debug for PrivateOramOwnerCleanupAuthorizationVerificationContextV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCleanupAuthorizationVerificationContextV1")
            .field("expected_authorization", &self.expected_authorization)
            .field(
                "acknowledged_lifecycle_state",
                &self.acknowledged_lifecycle_state,
            )
            .field("retained_cleanup_grant_digest", &"[redacted]")
            .field("authority_registry_digest", &"[redacted]")
            .field("owner_registry_digest", &"[redacted]")
            .field("context_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerCleanupAuthorizationVerificationContextV1 {
    pub fn expected_authorization(&self) -> &PrivateOramOwnerCleanupAuthorizationV1 {
        &self.expected_authorization
    }

    pub fn acknowledged_lifecycle_state(&self) -> &PrivateOramOwnerLifecycleStateV1 {
        &self.acknowledged_lifecycle_state
    }

    pub fn retained_cleanup_grant_digest(&self) -> &str {
        &self.retained_cleanup_grant_digest
    }

    pub fn context_digest(&self) -> &str {
        &self.context_digest
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerCleanupAuthorizationV1 {
    signed: SignedPrivateOramOwnerCleanupAuthorizationV1,
    verification_context: PrivateOramOwnerCleanupAuthorizationVerificationContextV1,
}

impl Debug for VerifiedPrivateOramOwnerCleanupAuthorizationV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramOwnerCleanupAuthorizationV1")
            .field("authorization", &self.signed.authorization)
            .field("verification_context", &self.verification_context)
            .finish()
    }
}

impl VerifiedPrivateOramOwnerCleanupAuthorizationV1 {
    pub fn signed(&self) -> &SignedPrivateOramOwnerCleanupAuthorizationV1 {
        &self.signed
    }

    pub fn authorization(&self) -> &PrivateOramOwnerCleanupAuthorizationV1 {
        &self.signed.authorization
    }

    pub fn authority_signer(&self) -> &PrivateOramOwnerCleanupSignerV1 {
        &self.verification_context.authority_signer
    }

    pub fn verification_context(
        &self,
    ) -> &PrivateOramOwnerCleanupAuthorizationVerificationContextV1 {
        &self.verification_context
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerCleanupReceiptV1 {
    pub version: u16,
    pub protocol: String,
    pub cleanup_authorization_digest: String,
    pub cleanup_operation_id: String,
    pub owner_target_digest: String,
    pub collection_incarnation_digest: String,
    pub attempt_id: String,
    pub outcome_key: String,
    #[serde(with = "decimal_u64")]
    pub owner_peer_id: u64,
    pub owner_signer: PrivateOramOwnerCleanupSignerV1,
    pub intent_key: String,
    pub intent_identity_digest: String,
    pub observed_prestate: PrivateOramOwnerCleanupObservedPrestateV1,
    pub terminal_state: PrivateOramOwnerCleanupTerminalStateV1,
    pub terminal_marker_digest: String,
    pub previous_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    pub new_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    pub payload_state: PrivateOramOwnerCleanupPayloadStateV1,
    pub body_digest: Option<String>,
    pub final_body_location: PrivateOramOwnerCleanupBodyLocationV1,
    pub receipt_digest: String,
}

impl Debug for PrivateOramOwnerCleanupReceiptV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerCleanupReceiptV1")
            .field("version", &self.version)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("observed_prestate", &self.observed_prestate)
            .field("terminal_state", &self.terminal_state)
            .field("payload_state", &self.payload_state)
            .field(
                "previous_generation",
                &self.previous_lifecycle_state.generation,
            )
            .field("new_generation", &self.new_lifecycle_state.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivateOramOwnerCleanupReceiptV1 {
    pub receipt: PrivateOramOwnerCleanupReceiptV1,
    pub signature: PrivateOramOwnerCleanupSignatureV1,
}

impl Debug for SignedPrivateOramOwnerCleanupReceiptV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPrivateOramOwnerCleanupReceiptV1")
            .field("receipt", &self.receipt)
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPrivateOramOwnerCleanupReceiptV1 {
    signed: SignedPrivateOramOwnerCleanupReceiptV1,
}

impl Debug for VerifiedPrivateOramOwnerCleanupReceiptV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPrivateOramOwnerCleanupReceiptV1")
            .field("receipt", &self.signed.receipt)
            .finish()
    }
}

impl VerifiedPrivateOramOwnerCleanupReceiptV1 {
    pub fn signed(&self) -> &SignedPrivateOramOwnerCleanupReceiptV1 {
        &self.signed
    }

    pub fn receipt(&self) -> &PrivateOramOwnerCleanupReceiptV1 {
        &self.signed.receipt
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAllOwnerCleanupCertificateEntryV1 {
    pub authorization: SignedPrivateOramOwnerCleanupAuthorizationV1,
    pub receipt: SignedPrivateOramOwnerCleanupReceiptV1,
}

impl Debug for PrivateOramAllOwnerCleanupCertificateEntryV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramAllOwnerCleanupCertificateEntryV1")
            .field(
                "owner_index",
                &self.authorization.authorization.target.owner_index,
            )
            .field(
                "owner_peer_id",
                &self.authorization.authorization.target.owner_peer_id,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAllOwnerCleanupCertificateV1 {
    pub version: u16,
    pub protocol: String,
    pub consensus_history_id_digest: String,
    pub raft_group_id_digest: String,
    pub collection_incarnation_digest: String,
    #[serde(with = "decimal_u64")]
    pub activation_registry_generation: u64,
    pub activation_manifest_digest: String,
    pub owner_roster_digest: String,
    pub attempt_id: String,
    #[serde(with = "decimal_u64")]
    pub attempt_sequence: u64,
    pub outcome_key: String,
    pub outcome_digest: String,
    pub negative_record_digest: String,
    pub owner_count: u32,
    pub entries: Vec<PrivateOramAllOwnerCleanupCertificateEntryV1>,
    pub certificate_digest: String,
}

impl Debug for PrivateOramAllOwnerCleanupCertificateV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramAllOwnerCleanupCertificateV1")
            .field("version", &self.version)
            .field("attempt_sequence", &self.attempt_sequence)
            .field("owner_count", &self.owner_count)
            .finish_non_exhaustive()
    }
}

pub fn private_oram_owner_cleanup_signer_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
) -> Result<PrivateOramOwnerCleanupSignerV1, PrivateOramOwnerCleanupError> {
    if key_epoch == 0 {
        return Err(PrivateOramOwnerCleanupError::InvalidField("key_epoch"));
    }
    let public_key = BASE64URL_NOPAD.encode(key_pair.public_key().as_ref());
    let peer_key = crate::private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)
        .map_err(|_| PrivateOramOwnerCleanupError::InvalidField("signer"))?;
    Ok(PrivateOramOwnerCleanupSignerV1 {
        version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
        alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch,
        key_id: peer_key.key_id,
        public_key,
    })
}

pub fn private_oram_owner_cleanup_signer_from_peer_key_v1(
    signer: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<PrivateOramOwnerCleanupSignerV1, PrivateOramOwnerCleanupError> {
    validate_private_oram_peer_recovery_public_key_v1(signer)
        .map_err(|_| PrivateOramOwnerCleanupError::InvalidField("signer"))?;
    let converted = PrivateOramOwnerCleanupSignerV1 {
        version: signer.version,
        alg: signer.alg.clone(),
        key_epoch: signer.key_epoch,
        key_id: signer.key_id.clone(),
        public_key: signer.public_key.clone(),
    };
    validate_signer(&converted)?;
    Ok(converted)
}

pub fn private_oram_owner_lifecycle_genesis_state_v1(
    owner_store_incarnation_digest: String,
) -> Result<PrivateOramOwnerLifecycleStateV1, PrivateOramOwnerCleanupError> {
    validate_digest(
        &owner_store_incarnation_digest,
        "owner_store_incarnation_digest",
    )?;
    let mut hasher = Sha256::new();
    hasher.update(OWNER_LIFECYCLE_GENESIS_ROOT_DOMAIN_V1);
    hash_str(&mut hasher, &owner_store_incarnation_digest)?;
    Ok(PrivateOramOwnerLifecycleStateV1 {
        owner_store_incarnation_digest,
        generation: 0,
        state_root: BASE64URL_NOPAD.encode(&hasher.finalize()),
        minimum_reader_version: PRIVATE_ORAM_OWNER_LIFECYCLE_READER_VERSION_V1,
        capability: PRIVATE_ORAM_OWNER_LIFECYCLE_CAPABILITY_V1.to_string(),
    })
}

pub fn private_oram_owner_cleanup_authorization_v1(
    mut authorization: PrivateOramOwnerCleanupAuthorizationV1,
) -> Result<PrivateOramOwnerCleanupAuthorizationV1, PrivateOramOwnerCleanupError> {
    authorization.version = PRIVATE_ORAM_OWNER_CLEANUP_AUTHORIZATION_VERSION_V1;
    authorization.protocol = PRIVATE_ORAM_OWNER_CLEANUP_PROTOCOL_V1.to_string();
    authorization.target.intent_identity_digest =
        private_oram_owner_cleanup_intent_identity_digest_v1(&authorization.target)?;
    authorization.target.target_digest = cleanup_target_digest_v1(&authorization.target)?;
    authorization.cleanup_operation_id.clear();
    authorization.authorization_digest.clear();
    authorization.cleanup_operation_id = cleanup_operation_id_v1(&authorization)?;
    authorization.authorization_digest = cleanup_authorization_digest_v1(&authorization)?;
    validate_private_oram_owner_cleanup_authorization_v1(&authorization)?;
    Ok(authorization)
}

pub fn sign_private_oram_owner_cleanup_authorization_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    authorization: &PrivateOramOwnerCleanupAuthorizationV1,
) -> Result<SignedPrivateOramOwnerCleanupAuthorizationV1, PrivateOramOwnerCleanupError> {
    validate_private_oram_owner_cleanup_authorization_v1(authorization)?;
    let signer = private_oram_owner_cleanup_signer_v1(key_pair, key_epoch)?;
    let message = signature_message(
        PRIVATE_ORAM_OWNER_CLEANUP_AUTHORIZATION_SIGNATURE_DOMAIN_V1,
        &authorization.authorization_digest,
    )?;
    Ok(SignedPrivateOramOwnerCleanupAuthorizationV1 {
        authorization: authorization.clone(),
        signature: PrivateOramOwnerCleanupSignatureV1 {
            version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
            alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
            key_epoch,
            key_id: signer.key_id,
            sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub fn private_oram_owner_cleanup_authorization_verification_context_v1(
    expected_authorization: PrivateOramOwnerCleanupAuthorizationV1,
    authority_signer: PrivateOramOwnerCleanupSignerV1,
    expected_owner_signer: PrivateOramOwnerCleanupSignerV1,
    acknowledged_lifecycle_state: PrivateOramOwnerLifecycleStateV1,
    retained_cleanup_grant_digest: String,
    authority_registry_digest: String,
    owner_registry_digest: String,
) -> Result<PrivateOramOwnerCleanupAuthorizationVerificationContextV1, PrivateOramOwnerCleanupError>
{
    validate_private_oram_owner_cleanup_authorization_v1(&expected_authorization)?;
    validate_signer(&authority_signer)?;
    validate_signer(&expected_owner_signer)?;
    validate_lifecycle_state(&acknowledged_lifecycle_state)?;
    for digest in [
        &retained_cleanup_grant_digest,
        &authority_registry_digest,
        &owner_registry_digest,
    ] {
        validate_digest(digest, "verification_context")?;
    }
    if expected_authorization.target.owner_signer != expected_owner_signer
        || expected_authorization.target.expected_lifecycle_state != acknowledged_lifecycle_state
    {
        return Err(PrivateOramOwnerCleanupError::InvalidTransition);
    }
    let context_digest = cleanup_authorization_verification_context_digest_v1(
        &expected_authorization,
        &authority_signer,
        &expected_owner_signer,
        &acknowledged_lifecycle_state,
        &retained_cleanup_grant_digest,
        &authority_registry_digest,
        &owner_registry_digest,
    )?;
    Ok(PrivateOramOwnerCleanupAuthorizationVerificationContextV1 {
        expected_authorization,
        authority_signer,
        expected_owner_signer,
        acknowledged_lifecycle_state,
        retained_cleanup_grant_digest,
        authority_registry_digest,
        owner_registry_digest,
        context_digest,
    })
}

pub fn validate_self_consistent_signed_private_oram_owner_cleanup_authorization_v1(
    signed: &SignedPrivateOramOwnerCleanupAuthorizationV1,
    authority_signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    validate_private_oram_owner_cleanup_authorization_v1(&signed.authorization)?;
    verify_signature(
        authority_signer,
        &signed.signature,
        PRIVATE_ORAM_OWNER_CLEANUP_AUTHORIZATION_SIGNATURE_DOMAIN_V1,
        &signed.authorization.authorization_digest,
    )
}

pub fn validate_signed_private_oram_owner_cleanup_authorization_v1(
    signed: &SignedPrivateOramOwnerCleanupAuthorizationV1,
    verification_context: &PrivateOramOwnerCleanupAuthorizationVerificationContextV1,
) -> Result<VerifiedPrivateOramOwnerCleanupAuthorizationV1, PrivateOramOwnerCleanupError> {
    if signed.authorization != verification_context.expected_authorization
        || signed.authorization.target.owner_signer != verification_context.expected_owner_signer
        || signed.authorization.target.expected_lifecycle_state
            != verification_context.acknowledged_lifecycle_state
    {
        return Err(PrivateOramOwnerCleanupError::InvalidTransition);
    }
    validate_self_consistent_signed_private_oram_owner_cleanup_authorization_v1(
        signed,
        &verification_context.authority_signer,
    )?;
    Ok(VerifiedPrivateOramOwnerCleanupAuthorizationV1 {
        signed: signed.clone(),
        verification_context: verification_context.clone(),
    })
}

pub fn private_oram_owner_cleanup_receipt_v1(
    authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
    observed_prestate: PrivateOramOwnerCleanupObservedPrestateV1,
) -> Result<PrivateOramOwnerCleanupReceiptV1, PrivateOramOwnerCleanupError> {
    validate_private_oram_owner_cleanup_authorization_v1(authorization.authorization())?;
    let receipt = derive_private_oram_owner_cleanup_receipt_v1(
        authorization.authorization(),
        observed_prestate,
    )?;
    validate_private_oram_owner_cleanup_receipt_v1(&receipt, authorization.authorization())?;
    Ok(receipt)
}

fn derive_private_oram_owner_cleanup_receipt_v1(
    authorization: &PrivateOramOwnerCleanupAuthorizationV1,
    observed_prestate: PrivateOramOwnerCleanupObservedPrestateV1,
) -> Result<PrivateOramOwnerCleanupReceiptV1, PrivateOramOwnerCleanupError> {
    let (terminal_state, payload_state, body_digest, final_body_location) =
        match (&authorization.policy, &observed_prestate) {
            (
                PrivateOramOwnerCleanupPolicyV1::TombstoneAbsentOrQuarantineIntent,
                PrivateOramOwnerCleanupObservedPrestateV1::Absent,
            ) => (
                PrivateOramOwnerCleanupTerminalStateV1::TombstonedAbsent,
                PrivateOramOwnerCleanupPayloadStateV1::NoPayload,
                None,
                PrivateOramOwnerCleanupBodyLocationV1::None,
            ),
            (
                PrivateOramOwnerCleanupPolicyV1::TombstoneAbsentOrQuarantineIntent
                | PrivateOramOwnerCleanupPolicyV1::RequireMatchingIntentQuarantine,
                PrivateOramOwnerCleanupObservedPrestateV1::Intent,
            ) => (
                PrivateOramOwnerCleanupTerminalStateV1::Quarantined,
                PrivateOramOwnerCleanupPayloadStateV1::QuarantineMoveRecoverable,
                Some(authorization.target.package_sha256.clone()),
                PrivateOramOwnerCleanupBodyLocationV1::Quarantine,
            ),
            (
                PrivateOramOwnerCleanupPolicyV1::RequireMatchingIntentQuarantine,
                PrivateOramOwnerCleanupObservedPrestateV1::Absent,
            ) => return Err(PrivateOramOwnerCleanupError::InvalidTransition),
        };
    let previous_lifecycle_state = authorization.target.expected_lifecycle_state.clone();
    let generation = previous_lifecycle_state
        .generation
        .checked_add(1)
        .ok_or(PrivateOramOwnerCleanupError::InvalidTransition)?;
    let mut receipt = PrivateOramOwnerCleanupReceiptV1 {
        version: PRIVATE_ORAM_OWNER_CLEANUP_RECEIPT_VERSION_V1,
        protocol: PRIVATE_ORAM_OWNER_CLEANUP_PROTOCOL_V1.to_string(),
        cleanup_authorization_digest: authorization.authorization_digest.clone(),
        cleanup_operation_id: authorization.cleanup_operation_id.clone(),
        owner_target_digest: authorization.target.target_digest.clone(),
        collection_incarnation_digest: authorization
            .authority
            .collection_incarnation_digest
            .clone(),
        attempt_id: authorization.attempt.attempt_id.clone(),
        outcome_key: authorization.outcome.outcome_key.clone(),
        owner_peer_id: authorization.target.owner_peer_id,
        owner_signer: authorization.target.owner_signer.clone(),
        intent_key: authorization.target.intent_key.clone(),
        intent_identity_digest: authorization.target.intent_identity_digest.clone(),
        observed_prestate,
        terminal_state,
        terminal_marker_digest: String::new(),
        previous_lifecycle_state: previous_lifecycle_state.clone(),
        new_lifecycle_state: PrivateOramOwnerLifecycleStateV1 {
            owner_store_incarnation_digest: previous_lifecycle_state
                .owner_store_incarnation_digest
                .clone(),
            generation,
            state_root: String::new(),
            minimum_reader_version: PRIVATE_ORAM_OWNER_LIFECYCLE_READER_VERSION_V1,
            capability: PRIVATE_ORAM_OWNER_LIFECYCLE_CAPABILITY_V1.to_string(),
        },
        payload_state,
        body_digest,
        final_body_location,
        receipt_digest: String::new(),
    };
    receipt.terminal_marker_digest = cleanup_terminal_marker_digest_v1(&receipt)?;
    receipt.new_lifecycle_state.state_root = private_oram_owner_lifecycle_state_root_v1(
        &previous_lifecycle_state,
        generation,
        &receipt.terminal_marker_digest,
        &receipt.intent_identity_digest,
        &receipt.terminal_state,
    )?;
    receipt.receipt_digest = cleanup_receipt_digest_v1(&receipt)?;
    Ok(receipt)
}

pub fn sign_private_oram_owner_cleanup_receipt_v1(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    receipt: &PrivateOramOwnerCleanupReceiptV1,
) -> Result<SignedPrivateOramOwnerCleanupReceiptV1, PrivateOramOwnerCleanupError> {
    let signer = private_oram_owner_cleanup_signer_v1(key_pair, key_epoch)?;
    if signer != receipt.owner_signer {
        return Err(PrivateOramOwnerCleanupError::SignerMismatch);
    }
    let message = signature_message(
        PRIVATE_ORAM_OWNER_CLEANUP_RECEIPT_SIGNATURE_DOMAIN_V1,
        &receipt.receipt_digest,
    )?;
    Ok(SignedPrivateOramOwnerCleanupReceiptV1 {
        receipt: receipt.clone(),
        signature: PrivateOramOwnerCleanupSignatureV1 {
            version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
            alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
            key_epoch,
            key_id: signer.key_id,
            sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
        },
    })
}

pub fn validate_signed_private_oram_owner_cleanup_receipt_v1(
    signed: &SignedPrivateOramOwnerCleanupReceiptV1,
    authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
) -> Result<VerifiedPrivateOramOwnerCleanupReceiptV1, PrivateOramOwnerCleanupError> {
    validate_self_consistent_signed_private_oram_owner_cleanup_receipt_v1(
        signed,
        authorization.authorization(),
    )?;
    Ok(VerifiedPrivateOramOwnerCleanupReceiptV1 {
        signed: signed.clone(),
    })
}

pub fn validate_self_consistent_signed_private_oram_owner_cleanup_receipt_v1(
    signed: &SignedPrivateOramOwnerCleanupReceiptV1,
    authorization: &PrivateOramOwnerCleanupAuthorizationV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    validate_private_oram_owner_cleanup_receipt_v1(&signed.receipt, authorization)?;
    verify_signature(
        &authorization.target.owner_signer,
        &signed.signature,
        PRIVATE_ORAM_OWNER_CLEANUP_RECEIPT_SIGNATURE_DOMAIN_V1,
        &signed.receipt.receipt_digest,
    )
}

/// Validates a persisted receipt for lifecycle-tip reconstruction after its immutable terminal
/// marker is already durable. This never authorizes a new cleanup transition.
pub fn validate_self_consistent_persisted_private_oram_owner_cleanup_receipt_v1(
    signed: &SignedPrivateOramOwnerCleanupReceiptV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    validate_standalone_private_oram_owner_cleanup_receipt_v1(&signed.receipt)?;
    verify_signature(
        &signed.receipt.owner_signer,
        &signed.signature,
        PRIVATE_ORAM_OWNER_CLEANUP_RECEIPT_SIGNATURE_DOMAIN_V1,
        &signed.receipt.receipt_digest,
    )
}

#[cfg(test)]
fn private_oram_all_owner_cleanup_certificate_v1(
    authority_signer: &PrivateOramOwnerCleanupSignerV1,
    mut entries: Vec<PrivateOramAllOwnerCleanupCertificateEntryV1>,
) -> Result<PrivateOramAllOwnerCleanupCertificateV1, PrivateOramOwnerCleanupError> {
    if entries.is_empty() || entries.len() > MAX_OWNERS {
        return Err(PrivateOramOwnerCleanupError::IncompleteCertificate);
    }
    entries.sort_by_key(|entry| {
        (
            entry.authorization.authorization.target.owner_index,
            entry.authorization.authorization.target.owner_peer_id,
        )
    });
    let first = entries
        .first()
        .ok_or(PrivateOramOwnerCleanupError::IncompleteCertificate)?
        .authorization
        .authorization
        .clone();
    let mut certificate = PrivateOramAllOwnerCleanupCertificateV1 {
        version: PRIVATE_ORAM_ALL_OWNER_CLEANUP_CERTIFICATE_VERSION_V1,
        protocol: PRIVATE_ORAM_OWNER_CLEANUP_PROTOCOL_V1.to_string(),
        consensus_history_id_digest: first.authority.consensus_history_id_digest,
        raft_group_id_digest: first.authority.raft_group_id_digest,
        collection_incarnation_digest: first.authority.collection_incarnation_digest,
        activation_registry_generation: first.authority.activation_registry_generation,
        activation_manifest_digest: first.authority.activation_manifest_digest,
        owner_roster_digest: first.authority.owner_roster_digest,
        attempt_id: first.attempt.attempt_id,
        attempt_sequence: first.attempt.attempt_sequence,
        outcome_key: first.outcome.outcome_key,
        outcome_digest: first.outcome.outcome_digest,
        negative_record_digest: first.outcome.negative_record_digest,
        owner_count: u32::try_from(entries.len())
            .map_err(|_| PrivateOramOwnerCleanupError::IncompleteCertificate)?,
        entries,
        certificate_digest: String::new(),
    };
    certificate.certificate_digest = all_owner_cleanup_certificate_digest_v1(&certificate)?;
    validate_private_oram_all_owner_cleanup_certificate_v1(&certificate, authority_signer)?;
    Ok(certificate)
}

pub fn validate_private_oram_all_owner_cleanup_certificate_v1(
    certificate: &PrivateOramAllOwnerCleanupCertificateV1,
    authority_signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    validate_signer(authority_signer)?;
    if certificate.version != PRIVATE_ORAM_ALL_OWNER_CLEANUP_CERTIFICATE_VERSION_V1
        || certificate.protocol != PRIVATE_ORAM_OWNER_CLEANUP_PROTOCOL_V1
        || certificate.entries.is_empty()
        || certificate.entries.len() > MAX_OWNERS
        || usize::try_from(certificate.owner_count).ok() != Some(certificate.entries.len())
        || certificate.attempt_sequence == 0
        || certificate.activation_registry_generation == 0
    {
        return Err(PrivateOramOwnerCleanupError::IncompleteCertificate);
    }
    for digest in [
        &certificate.consensus_history_id_digest,
        &certificate.raft_group_id_digest,
        &certificate.collection_incarnation_digest,
        &certificate.activation_manifest_digest,
        &certificate.owner_roster_digest,
        &certificate.attempt_id,
        &certificate.outcome_key,
        &certificate.outcome_digest,
        &certificate.negative_record_digest,
        &certificate.certificate_digest,
    ] {
        validate_digest(digest, "certificate")?;
    }
    let mut previous = None;
    for entry in &certificate.entries {
        validate_self_consistent_signed_private_oram_owner_cleanup_authorization_v1(
            &entry.authorization,
            authority_signer,
        )?;
        validate_self_consistent_signed_private_oram_owner_cleanup_receipt_v1(
            &entry.receipt,
            &entry.authorization.authorization,
        )?;
        let authorization = &entry.authorization.authorization;
        let key = (
            authorization.target.owner_index,
            authorization.target.owner_peer_id,
        );
        if previous.is_some_and(|previous| previous >= key)
            || authorization.authority.consensus_history_id_digest
                != certificate.consensus_history_id_digest
            || authorization.authority.raft_group_id_digest != certificate.raft_group_id_digest
            || authorization.authority.collection_incarnation_digest
                != certificate.collection_incarnation_digest
            || authorization.authority.activation_registry_generation
                != certificate.activation_registry_generation
            || authorization.authority.activation_manifest_digest
                != certificate.activation_manifest_digest
            || authorization.authority.owner_roster_digest != certificate.owner_roster_digest
            || authorization.attempt.attempt_id != certificate.attempt_id
            || authorization.attempt.attempt_sequence != certificate.attempt_sequence
            || authorization.outcome.outcome_key != certificate.outcome_key
            || authorization.outcome.outcome_digest != certificate.outcome_digest
            || authorization.outcome.negative_record_digest != certificate.negative_record_digest
        {
            return Err(PrivateOramOwnerCleanupError::IncompleteCertificate);
        }
        previous = Some(key);
    }
    if certificate.certificate_digest != all_owner_cleanup_certificate_digest_v1(certificate)? {
        return Err(PrivateOramOwnerCleanupError::NonCanonicalEncoding);
    }
    ensure_canonical_size(certificate)?;
    Ok(())
}

pub fn private_oram_owner_lifecycle_state_root_v1(
    previous: &PrivateOramOwnerLifecycleStateV1,
    generation: u64,
    terminal_marker_digest: &str,
    intent_identity_digest: &str,
    terminal_state: &PrivateOramOwnerCleanupTerminalStateV1,
) -> Result<String, PrivateOramOwnerCleanupError> {
    validate_lifecycle_state(previous)?;
    if generation
        != previous
            .generation
            .checked_add(1)
            .ok_or(PrivateOramOwnerCleanupError::InvalidTransition)?
    {
        return Err(PrivateOramOwnerCleanupError::InvalidTransition);
    }
    validate_digest(terminal_marker_digest, "terminal_marker_digest")?;
    validate_digest(intent_identity_digest, "intent_identity_digest")?;
    let mut hasher = Sha256::new();
    hasher.update(OWNER_LIFECYCLE_STATE_ROOT_DOMAIN_V1);
    hash_str(&mut hasher, &previous.owner_store_incarnation_digest)?;
    hasher.update(previous.generation.to_be_bytes());
    hash_str(&mut hasher, &previous.state_root)?;
    hasher.update(generation.to_be_bytes());
    hash_str(&mut hasher, terminal_marker_digest)?;
    hash_str(&mut hasher, intent_identity_digest)?;
    hasher.update([terminal_state_tag(terminal_state)]);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_owner_cleanup_intent_identity_digest_v1(
    target: &PrivateOramOwnerCleanupTargetV1,
) -> Result<String, PrivateOramOwnerCleanupError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        owner_index: u32,
        owner_peer_id: u64,
        intent_key: &'a str,
        package_sha256: &'a str,
        package_len: u64,
        owner_request_digest: &'a str,
        prestage_receipt_digest: Option<&'a str>,
        intent_marker_digest: Option<&'a str>,
        parent_descriptor_digest: &'a str,
        parent_lease_acquired_record_digest: &'a str,
        owner_journal_descriptor_digest: Option<&'a str>,
    }
    canonical_digest(
        CLEANUP_INTENT_IDENTITY_DIGEST_DOMAIN_V1,
        &Identity {
            owner_index: target.owner_index,
            owner_peer_id: target.owner_peer_id,
            intent_key: &target.intent_key,
            package_sha256: &target.package_sha256,
            package_len: target.package_len,
            owner_request_digest: &target.owner_request_digest,
            prestage_receipt_digest: target.prestage_receipt_digest.as_deref(),
            intent_marker_digest: target.intent_marker_digest.as_deref(),
            parent_descriptor_digest: &target.parent_descriptor_digest,
            parent_lease_acquired_record_digest: &target.parent_lease_acquired_record_digest,
            owner_journal_descriptor_digest: target.owner_journal_descriptor_digest.as_deref(),
        },
    )
}

pub fn encode_private_oram_owner_cleanup_authorization_v1(
    value: &SignedPrivateOramOwnerCleanupAuthorizationV1,
    authority_signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<Vec<u8>, PrivateOramOwnerCleanupError> {
    validate_self_consistent_signed_private_oram_owner_cleanup_authorization_v1(
        value,
        authority_signer,
    )?;
    canonical_json(value)
}

pub fn decode_private_oram_owner_cleanup_authorization_v1(
    bytes: &[u8],
    authority_signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<SignedPrivateOramOwnerCleanupAuthorizationV1, PrivateOramOwnerCleanupError> {
    let value: SignedPrivateOramOwnerCleanupAuthorizationV1 = canonical_decode(bytes)?;
    validate_self_consistent_signed_private_oram_owner_cleanup_authorization_v1(
        &value,
        authority_signer,
    )?;
    Ok(value)
}

pub fn encode_private_oram_owner_cleanup_receipt_v1(
    value: &SignedPrivateOramOwnerCleanupReceiptV1,
    authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
) -> Result<Vec<u8>, PrivateOramOwnerCleanupError> {
    validate_signed_private_oram_owner_cleanup_receipt_v1(value, authorization)?;
    canonical_json(value)
}

pub fn decode_private_oram_owner_cleanup_receipt_v1(
    bytes: &[u8],
    authorization: &VerifiedPrivateOramOwnerCleanupAuthorizationV1,
) -> Result<VerifiedPrivateOramOwnerCleanupReceiptV1, PrivateOramOwnerCleanupError> {
    let value: SignedPrivateOramOwnerCleanupReceiptV1 = canonical_decode(bytes)?;
    validate_signed_private_oram_owner_cleanup_receipt_v1(&value, authorization)
}

pub fn encode_private_oram_all_owner_cleanup_certificate_v1(
    value: &PrivateOramAllOwnerCleanupCertificateV1,
    authority_signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<Vec<u8>, PrivateOramOwnerCleanupError> {
    validate_private_oram_all_owner_cleanup_certificate_v1(value, authority_signer)?;
    canonical_json(value)
}

pub fn decode_private_oram_all_owner_cleanup_certificate_v1(
    bytes: &[u8],
    authority_signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<PrivateOramAllOwnerCleanupCertificateV1, PrivateOramOwnerCleanupError> {
    let value: PrivateOramAllOwnerCleanupCertificateV1 = canonical_decode(bytes)?;
    validate_private_oram_all_owner_cleanup_certificate_v1(&value, authority_signer)?;
    Ok(value)
}

fn validate_private_oram_owner_cleanup_authorization_v1(
    authorization: &PrivateOramOwnerCleanupAuthorizationV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    if authorization.version != PRIVATE_ORAM_OWNER_CLEANUP_AUTHORIZATION_VERSION_V1
        || authorization.protocol != PRIVATE_ORAM_OWNER_CLEANUP_PROTOCOL_V1
        || authorization.authority.activation_registry_generation == 0
        || authorization.attempt.attempt_sequence == 0
        || authorization.attempt.lease_generation == 0
        || authorization.attempt.writer_fence == 0
        || authorization.target.owner_peer_id == 0
        || authorization.target.package_len == 0
    {
        return Err(PrivateOramOwnerCleanupError::InvalidField("authorization"));
    }
    validate_locator(&authorization.attempt.reservation_applied)?;
    validate_locator(&authorization.outcome.outcome_applied)?;
    if authorization.outcome.outcome_applied.index
        <= authorization.attempt.reservation_applied.index
    {
        return Err(PrivateOramOwnerCleanupError::InvalidTransition);
    }
    validate_signer(&authorization.target.owner_signer)?;
    validate_lifecycle_state(&authorization.target.expected_lifecycle_state)?;
    validate_identifier(&authorization.authority.collection_id, "collection_id")?;
    for digest in [
        &authorization.authority.consensus_history_id_digest,
        &authorization.authority.raft_group_id_digest,
        &authorization.authority.collection_lifetime_id_digest,
        &authorization.authority.collection_incarnation_digest,
        &authorization.authority.activation_anchor_digest,
        &authorization.authority.activation_manifest_digest,
        &authorization.authority.owner_roster_digest,
        &authorization.attempt.attempt_id,
        &authorization.attempt.mutation_id,
        &authorization.attempt.mutation_digest,
        &authorization.attempt.expected_aggregate_digest,
        &authorization.attempt.reservation_digest,
        &authorization.outcome.outcome_key,
        &authorization.outcome.outcome_digest,
        &authorization.outcome.negative_record_digest,
        &authorization.target.intent_key,
        &authorization.target.intent_identity_digest,
        &authorization.target.package_sha256,
        &authorization.target.owner_request_digest,
        &authorization.target.parent_descriptor_digest,
        &authorization.target.parent_lease_acquired_record_digest,
        &authorization.target.target_digest,
        &authorization.cleanup_operation_id,
        &authorization.authorization_digest,
    ] {
        validate_digest(digest, "authorization")?;
    }
    for optional in [
        authorization.target.prestage_receipt_digest.as_deref(),
        authorization.target.intent_marker_digest.as_deref(),
        authorization
            .target
            .owner_journal_descriptor_digest
            .as_deref(),
    ] {
        if let Some(digest) = optional {
            validate_digest(digest, "authorization")?;
        }
    }
    let prestage_bound = authorization.target.prestage_receipt_digest.is_some()
        && authorization.target.intent_marker_digest.is_some()
        && authorization
            .target
            .owner_journal_descriptor_digest
            .is_some();
    let no_prestage_binding = authorization.target.prestage_receipt_digest.is_none()
        && authorization.target.intent_marker_digest.is_none()
        && authorization
            .target
            .owner_journal_descriptor_digest
            .is_none();
    if !(prestage_bound || no_prestage_binding)
        || matches!(
            authorization.outcome.kind,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected
        ) && (!prestage_bound
            || authorization.policy
                != PrivateOramOwnerCleanupPolicyV1::RequireMatchingIntentQuarantine)
        || matches!(
            authorization.outcome.kind,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::PrestageAborted
        ) && authorization.policy
            != PrivateOramOwnerCleanupPolicyV1::TombstoneAbsentOrQuarantineIntent
    {
        return Err(PrivateOramOwnerCleanupError::InvalidTransition);
    }
    if authorization.target.intent_identity_digest
        != private_oram_owner_cleanup_intent_identity_digest_v1(&authorization.target)?
        || authorization.target.target_digest != cleanup_target_digest_v1(&authorization.target)?
        || authorization.cleanup_operation_id != cleanup_operation_id_v1(authorization)?
        || authorization.authorization_digest != cleanup_authorization_digest_v1(authorization)?
    {
        return Err(PrivateOramOwnerCleanupError::NonCanonicalEncoding);
    }
    ensure_canonical_size(authorization)?;
    Ok(())
}

fn validate_private_oram_owner_cleanup_receipt_v1(
    receipt: &PrivateOramOwnerCleanupReceiptV1,
    authorization: &PrivateOramOwnerCleanupAuthorizationV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    validate_private_oram_owner_cleanup_authorization_v1(authorization)?;
    validate_standalone_private_oram_owner_cleanup_receipt_v1(receipt)?;
    let expected = derive_private_oram_owner_cleanup_receipt_v1(
        authorization,
        receipt.observed_prestate.clone(),
    )?;
    if receipt.version != PRIVATE_ORAM_OWNER_CLEANUP_RECEIPT_VERSION_V1
        || receipt.protocol != PRIVATE_ORAM_OWNER_CLEANUP_PROTOCOL_V1
        || receipt != &expected
    {
        return Err(PrivateOramOwnerCleanupError::InvalidTransition);
    }
    ensure_canonical_size(receipt)?;
    Ok(())
}

fn validate_standalone_private_oram_owner_cleanup_receipt_v1(
    receipt: &PrivateOramOwnerCleanupReceiptV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    if receipt.version != PRIVATE_ORAM_OWNER_CLEANUP_RECEIPT_VERSION_V1
        || receipt.protocol != PRIVATE_ORAM_OWNER_CLEANUP_PROTOCOL_V1
        || receipt.owner_peer_id == 0
    {
        return Err(PrivateOramOwnerCleanupError::InvalidField("receipt"));
    }
    validate_signer(&receipt.owner_signer)?;
    validate_lifecycle_state(&receipt.previous_lifecycle_state)?;
    validate_lifecycle_state(&receipt.new_lifecycle_state)?;
    for digest in [
        &receipt.cleanup_authorization_digest,
        &receipt.cleanup_operation_id,
        &receipt.owner_target_digest,
        &receipt.collection_incarnation_digest,
        &receipt.attempt_id,
        &receipt.outcome_key,
        &receipt.intent_key,
        &receipt.intent_identity_digest,
        &receipt.terminal_marker_digest,
        &receipt.receipt_digest,
    ] {
        validate_digest(digest, "receipt")?;
    }
    if let Some(body_digest) = &receipt.body_digest {
        validate_digest(body_digest, "body_digest")?;
    }
    let valid_payload_shape = matches!(
        (
            &receipt.observed_prestate,
            &receipt.terminal_state,
            &receipt.payload_state,
            &receipt.body_digest,
            &receipt.final_body_location,
        ),
        (
            PrivateOramOwnerCleanupObservedPrestateV1::Absent,
            PrivateOramOwnerCleanupTerminalStateV1::TombstonedAbsent,
            PrivateOramOwnerCleanupPayloadStateV1::NoPayload,
            None,
            PrivateOramOwnerCleanupBodyLocationV1::None,
        ) | (
            PrivateOramOwnerCleanupObservedPrestateV1::Intent,
            PrivateOramOwnerCleanupTerminalStateV1::Quarantined,
            PrivateOramOwnerCleanupPayloadStateV1::QuarantineMoveRecoverable,
            Some(_),
            PrivateOramOwnerCleanupBodyLocationV1::Quarantine,
        )
    );
    if !valid_payload_shape
        || receipt
            .previous_lifecycle_state
            .owner_store_incarnation_digest
            != receipt.new_lifecycle_state.owner_store_incarnation_digest
        || receipt.new_lifecycle_state.generation
            != receipt
                .previous_lifecycle_state
                .generation
                .checked_add(1)
                .ok_or(PrivateOramOwnerCleanupError::InvalidTransition)?
        || receipt.terminal_marker_digest != cleanup_terminal_marker_digest_v1(receipt)?
        || receipt.new_lifecycle_state.state_root
            != private_oram_owner_lifecycle_state_root_v1(
                &receipt.previous_lifecycle_state,
                receipt.new_lifecycle_state.generation,
                &receipt.terminal_marker_digest,
                &receipt.intent_identity_digest,
                &receipt.terminal_state,
            )?
        || receipt.receipt_digest != cleanup_receipt_digest_v1(receipt)?
    {
        return Err(PrivateOramOwnerCleanupError::InvalidTransition);
    }
    ensure_canonical_size(receipt)?;
    Ok(())
}

fn cleanup_target_digest_v1(
    target: &PrivateOramOwnerCleanupTargetV1,
) -> Result<String, PrivateOramOwnerCleanupError> {
    let mut body = target.clone();
    body.target_digest.clear();
    canonical_digest(CLEANUP_TARGET_DIGEST_DOMAIN_V1, &body)
}

#[allow(clippy::too_many_arguments)]
fn cleanup_authorization_verification_context_digest_v1(
    expected_authorization: &PrivateOramOwnerCleanupAuthorizationV1,
    authority_signer: &PrivateOramOwnerCleanupSignerV1,
    expected_owner_signer: &PrivateOramOwnerCleanupSignerV1,
    acknowledged_lifecycle_state: &PrivateOramOwnerLifecycleStateV1,
    retained_cleanup_grant_digest: &str,
    authority_registry_digest: &str,
    owner_registry_digest: &str,
) -> Result<String, PrivateOramOwnerCleanupError> {
    #[derive(Serialize)]
    struct Context<'a> {
        expected_authorization: &'a PrivateOramOwnerCleanupAuthorizationV1,
        authority_signer: &'a PrivateOramOwnerCleanupSignerV1,
        expected_owner_signer: &'a PrivateOramOwnerCleanupSignerV1,
        acknowledged_lifecycle_state: &'a PrivateOramOwnerLifecycleStateV1,
        retained_cleanup_grant_digest: &'a str,
        authority_registry_digest: &'a str,
        owner_registry_digest: &'a str,
    }
    canonical_digest(
        CLEANUP_AUTHORIZATION_VERIFICATION_CONTEXT_DIGEST_DOMAIN_V1,
        &Context {
            expected_authorization,
            authority_signer,
            expected_owner_signer,
            acknowledged_lifecycle_state,
            retained_cleanup_grant_digest,
            authority_registry_digest,
            owner_registry_digest,
        },
    )
}

fn cleanup_operation_id_v1(
    authorization: &PrivateOramOwnerCleanupAuthorizationV1,
) -> Result<String, PrivateOramOwnerCleanupError> {
    let mut body = authorization.clone();
    body.cleanup_operation_id.clear();
    body.authorization_digest.clear();
    canonical_digest(CLEANUP_OPERATION_ID_DOMAIN_V1, &body)
}

fn cleanup_authorization_digest_v1(
    authorization: &PrivateOramOwnerCleanupAuthorizationV1,
) -> Result<String, PrivateOramOwnerCleanupError> {
    let mut body = authorization.clone();
    body.authorization_digest.clear();
    canonical_digest(CLEANUP_AUTHORIZATION_DIGEST_DOMAIN_V1, &body)
}

fn cleanup_receipt_digest_v1(
    receipt: &PrivateOramOwnerCleanupReceiptV1,
) -> Result<String, PrivateOramOwnerCleanupError> {
    let mut body = receipt.clone();
    body.receipt_digest.clear();
    canonical_digest(CLEANUP_RECEIPT_DIGEST_DOMAIN_V1, &body)
}

fn cleanup_terminal_marker_digest_v1(
    receipt: &PrivateOramOwnerCleanupReceiptV1,
) -> Result<String, PrivateOramOwnerCleanupError> {
    #[derive(Serialize)]
    struct Binding<'a> {
        cleanup_authorization_digest: &'a str,
        cleanup_operation_id: &'a str,
        owner_target_digest: &'a str,
        intent_identity_digest: &'a str,
        observed_prestate: &'a PrivateOramOwnerCleanupObservedPrestateV1,
        terminal_state: &'a PrivateOramOwnerCleanupTerminalStateV1,
        previous_lifecycle_state: &'a PrivateOramOwnerLifecycleStateV1,
        next_generation: u64,
        payload_state: &'a PrivateOramOwnerCleanupPayloadStateV1,
        body_digest: Option<&'a str>,
        final_body_location: &'a PrivateOramOwnerCleanupBodyLocationV1,
    }
    canonical_digest(
        CLEANUP_TERMINAL_MARKER_DIGEST_DOMAIN_V1,
        &Binding {
            cleanup_authorization_digest: &receipt.cleanup_authorization_digest,
            cleanup_operation_id: &receipt.cleanup_operation_id,
            owner_target_digest: &receipt.owner_target_digest,
            intent_identity_digest: &receipt.intent_identity_digest,
            observed_prestate: &receipt.observed_prestate,
            terminal_state: &receipt.terminal_state,
            previous_lifecycle_state: &receipt.previous_lifecycle_state,
            next_generation: receipt.new_lifecycle_state.generation,
            payload_state: &receipt.payload_state,
            body_digest: receipt.body_digest.as_deref(),
            final_body_location: &receipt.final_body_location,
        },
    )
}

fn all_owner_cleanup_certificate_digest_v1(
    certificate: &PrivateOramAllOwnerCleanupCertificateV1,
) -> Result<String, PrivateOramOwnerCleanupError> {
    let mut body = certificate.clone();
    body.certificate_digest.clear();
    canonical_digest(ALL_OWNER_CLEANUP_CERTIFICATE_DIGEST_DOMAIN_V1, &body)
}

fn canonical_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, PrivateOramOwnerCleanupError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|_| PrivateOramOwnerCleanupError::NonCanonicalEncoding)?;
    if encoded.is_empty() || encoded.len() > MAX_CANONICAL_BYTES {
        return Err(PrivateOramOwnerCleanupError::InvalidField(
            "canonical_bytes",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(encoded.len())
            .map_err(|_| PrivateOramOwnerCleanupError::InvalidField("canonical_bytes"))?
            .to_be_bytes(),
    );
    hasher.update(encoded);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn signature_message(domain: &str, digest: &str) -> Result<Vec<u8>, PrivateOramOwnerCleanupError> {
    let digest = decode_digest(digest, "signature_digest")?;
    let mut message = Vec::with_capacity(4 + domain.len() + DIGEST_BYTES);
    message.extend_from_slice(
        &u32::try_from(domain.len())
            .map_err(|_| PrivateOramOwnerCleanupError::InvalidField("signature_domain"))?
            .to_be_bytes(),
    );
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(&digest);
    Ok(message)
}

fn verify_signature(
    signer: &PrivateOramOwnerCleanupSignerV1,
    signature: &PrivateOramOwnerCleanupSignatureV1,
    domain: &str,
    digest: &str,
) -> Result<(), PrivateOramOwnerCleanupError> {
    validate_signer(signer)?;
    if signature.version != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION
        || signature.alg != PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM
        || signature.key_epoch != signer.key_epoch
        || signature.key_id != signer.key_id
    {
        return Err(PrivateOramOwnerCleanupError::SignerMismatch);
    }
    let public_key = BASE64URL_NOPAD
        .decode(signer.public_key.as_bytes())
        .map_err(|_| PrivateOramOwnerCleanupError::InvalidField("public_key"))?;
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| PrivateOramOwnerCleanupError::InvalidSignature)?;
    if public_key.len() != DIGEST_BYTES || signature_bytes.len() != SIGNATURE_BYTES {
        return Err(PrivateOramOwnerCleanupError::InvalidSignature);
    }
    let message = signature_message(domain, digest)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateOramOwnerCleanupError::InvalidSignature)
}

fn validate_signer(
    signer: &PrivateOramOwnerCleanupSignerV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    let peer = PrivateOramPeerRecoveryPublicKeyV1 {
        version: signer.version,
        alg: signer.alg.clone(),
        key_epoch: signer.key_epoch,
        key_id: signer.key_id.clone(),
        public_key: signer.public_key.clone(),
    };
    validate_private_oram_peer_recovery_public_key_v1(&peer)
        .map(|_| ())
        .map_err(|_| PrivateOramOwnerCleanupError::InvalidField("signer"))
}

fn validate_lifecycle_state(
    state: &PrivateOramOwnerLifecycleStateV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    validate_digest(
        &state.owner_store_incarnation_digest,
        "owner_store_incarnation_digest",
    )?;
    validate_digest(&state.state_root, "state_root")?;
    if state.minimum_reader_version != PRIVATE_ORAM_OWNER_LIFECYCLE_READER_VERSION_V1
        || state.capability != PRIVATE_ORAM_OWNER_LIFECYCLE_CAPABILITY_V1
    {
        return Err(PrivateOramOwnerCleanupError::UnsupportedVersion);
    }
    Ok(())
}

fn validate_locator(
    locator: &PrivateOramCleanupRaftLocatorV1,
) -> Result<(), PrivateOramOwnerCleanupError> {
    if locator.term == 0 || locator.index == 0 {
        return Err(PrivateOramOwnerCleanupError::InvalidField("raft_locator"));
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerCleanupError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(PrivateOramOwnerCleanupError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), PrivateOramOwnerCleanupError> {
    decode_digest(value, field).map(|_| ())
}

fn decode_digest(
    value: &str,
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], PrivateOramOwnerCleanupError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramOwnerCleanupError::InvalidField(field))?;
    decoded
        .try_into()
        .map_err(|_| PrivateOramOwnerCleanupError::InvalidField(field))
}

fn hash_str(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramOwnerCleanupError> {
    hasher.update(
        u64::try_from(value.len())
            .map_err(|_| PrivateOramOwnerCleanupError::InvalidField("hash_input"))?
            .to_be_bytes(),
    );
    hasher.update(value.as_bytes());
    Ok(())
}

fn terminal_state_tag(state: &PrivateOramOwnerCleanupTerminalStateV1) -> u8 {
    match state {
        PrivateOramOwnerCleanupTerminalStateV1::TombstonedAbsent => 1,
        PrivateOramOwnerCleanupTerminalStateV1::Quarantined => 2,
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, PrivateOramOwnerCleanupError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|_| PrivateOramOwnerCleanupError::NonCanonicalEncoding)?;
    if encoded.is_empty() || encoded.len() > MAX_CANONICAL_BYTES {
        return Err(PrivateOramOwnerCleanupError::InvalidField(
            "canonical_bytes",
        ));
    }
    Ok(encoded)
}

fn canonical_decode<T>(bytes: &[u8]) -> Result<T, PrivateOramOwnerCleanupError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_BYTES {
        return Err(PrivateOramOwnerCleanupError::InvalidField(
            "canonical_bytes",
        ));
    }
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|_| PrivateOramOwnerCleanupError::NonCanonicalEncoding)?;
    if serde_json::to_vec(&value).map_err(|_| PrivateOramOwnerCleanupError::NonCanonicalEncoding)?
        != bytes
    {
        return Err(PrivateOramOwnerCleanupError::NonCanonicalEncoding);
    }
    Ok(value)
}

fn ensure_canonical_size<T: Serialize>(value: &T) -> Result<(), PrivateOramOwnerCleanupError> {
    canonical_json(value).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; DIGEST_BYTES])
    }

    fn key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; DIGEST_BYTES]).unwrap()
    }

    fn authorization(
        authority_key: &Ed25519KeyPair,
        owner_key: &Ed25519KeyPair,
        owner_index: u32,
        owner_peer_id: u64,
        outcome_kind: PrivateOramOwnerCleanupNegativeOutcomeKindV1,
    ) -> (
        PrivateOramOwnerCleanupSignerV1,
        SignedPrivateOramOwnerCleanupAuthorizationV1,
    ) {
        let authority_signer = private_oram_owner_cleanup_signer_v1(authority_key, 7).unwrap();
        let owner_signer = private_oram_owner_cleanup_signer_v1(owner_key, 9).unwrap();
        let prestaged = matches!(
            outcome_kind,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected
        );
        let mut authorization = PrivateOramOwnerCleanupAuthorizationV1 {
            version: 0,
            protocol: String::new(),
            authority: PrivateOramOwnerCleanupAuthorityContextV1 {
                consensus_history_id_digest: digest(1),
                raft_group_id_digest: digest(2),
                collection_id: "collection-a".to_string(),
                collection_lifetime_id_digest: digest(3),
                collection_incarnation_digest: digest(4),
                activation_anchor_digest: digest(5),
                activation_registry_generation: 6,
                activation_manifest_digest: digest(6),
                owner_roster_digest: digest(7),
            },
            attempt: PrivateOramOwnerCleanupAttemptContextV1 {
                attempt_id: digest(8),
                attempt_sequence: 10,
                mutation_id: digest(9),
                mutation_digest: digest(10),
                expected_aggregate_digest: digest(11),
                reservation_digest: digest(12),
                reservation_applied: PrivateOramCleanupRaftLocatorV1 { term: 2, index: 20 },
                lease_generation: 4,
                writer_fence: 5,
            },
            outcome: PrivateOramOwnerCleanupOutcomeContextV1 {
                kind: outcome_kind,
                outcome_key: digest(13),
                outcome_digest: digest(14),
                negative_record_digest: digest(15),
                outcome_applied: PrivateOramCleanupRaftLocatorV1 { term: 2, index: 21 },
            },
            target: PrivateOramOwnerCleanupTargetV1 {
                owner_index,
                owner_peer_id,
                owner_signer,
                expected_lifecycle_state: private_oram_owner_lifecycle_genesis_state_v1(digest(
                    16_u8.wrapping_add(owner_index as u8),
                ))
                .unwrap(),
                intent_key: digest(20_u8.wrapping_add(owner_index as u8)),
                intent_identity_digest: digest(30_u8.wrapping_add(owner_index as u8)),
                package_sha256: digest(40_u8.wrapping_add(owner_index as u8)),
                package_len: 1024,
                owner_request_digest: digest(50_u8.wrapping_add(owner_index as u8)),
                prestage_receipt_digest: prestaged.then(|| digest(60)),
                intent_marker_digest: prestaged.then(|| digest(61)),
                parent_descriptor_digest: digest(62),
                parent_lease_acquired_record_digest: digest(63),
                owner_journal_descriptor_digest: prestaged.then(|| digest(64)),
                target_digest: String::new(),
            },
            policy: if prestaged {
                PrivateOramOwnerCleanupPolicyV1::RequireMatchingIntentQuarantine
            } else {
                PrivateOramOwnerCleanupPolicyV1::TombstoneAbsentOrQuarantineIntent
            },
            cleanup_operation_id: String::new(),
            authorization_digest: String::new(),
        };
        authorization = private_oram_owner_cleanup_authorization_v1(authorization).unwrap();
        let signed =
            sign_private_oram_owner_cleanup_authorization_v1(authority_key, 7, &authorization)
                .unwrap();
        (authority_signer, signed)
    }

    fn verification_context(
        signed: &SignedPrivateOramOwnerCleanupAuthorizationV1,
        authority_signer: &PrivateOramOwnerCleanupSignerV1,
    ) -> PrivateOramOwnerCleanupAuthorizationVerificationContextV1 {
        private_oram_owner_cleanup_authorization_verification_context_v1(
            signed.authorization.clone(),
            authority_signer.clone(),
            signed.authorization.target.owner_signer.clone(),
            signed.authorization.target.expected_lifecycle_state.clone(),
            digest(200),
            digest(201),
            digest(202),
        )
        .unwrap()
    }

    fn verified_authorization(
        signed: &SignedPrivateOramOwnerCleanupAuthorizationV1,
        authority_signer: &PrivateOramOwnerCleanupSignerV1,
    ) -> VerifiedPrivateOramOwnerCleanupAuthorizationV1 {
        validate_signed_private_oram_owner_cleanup_authorization_v1(
            signed,
            &verification_context(signed, authority_signer),
        )
        .unwrap()
    }

    #[test]
    fn authorization_receipt_and_root_chain_are_state_bound() {
        let authority_key = key(1);
        let owner_key = key(2);
        let (authority_signer, signed_authorization) = authorization(
            &authority_key,
            &owner_key,
            0,
            11,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
        );
        let verified_authorization =
            verified_authorization(&signed_authorization, &authority_signer);
        let receipt = private_oram_owner_cleanup_receipt_v1(
            &verified_authorization,
            PrivateOramOwnerCleanupObservedPrestateV1::Intent,
        )
        .unwrap();
        assert_eq!(receipt.previous_lifecycle_state.generation, 0);
        assert_eq!(receipt.new_lifecycle_state.generation, 1);
        assert_ne!(
            receipt.previous_lifecycle_state.state_root,
            receipt.new_lifecycle_state.state_root
        );
        let signed_receipt =
            sign_private_oram_owner_cleanup_receipt_v1(&owner_key, 9, &receipt).unwrap();
        validate_signed_private_oram_owner_cleanup_receipt_v1(
            &signed_receipt,
            &verified_authorization,
        )
        .unwrap();

        let mut rolled_back = signed_authorization.clone();
        rolled_back
            .authorization
            .target
            .expected_lifecycle_state
            .state_root = digest(99);
        assert!(matches!(
            validate_signed_private_oram_owner_cleanup_authorization_v1(
                &rolled_back,
                &verification_context(&signed_authorization, &authority_signer)
            ),
            Err(PrivateOramOwnerCleanupError::InvalidTransition)
        ));
    }

    #[test]
    fn admission_rejection_never_accepts_absent_owner_state() {
        let authority_key = key(3);
        let owner_key = key(4);
        let (authority_signer, signed) = authorization(
            &authority_key,
            &owner_key,
            0,
            11,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
        );
        let verified = verified_authorization(&signed, &authority_signer);
        assert!(matches!(
            private_oram_owner_cleanup_receipt_v1(
                &verified,
                PrivateOramOwnerCleanupObservedPrestateV1::Absent
            ),
            Err(PrivateOramOwnerCleanupError::InvalidTransition)
        ));
    }

    #[test]
    fn self_consistent_attacker_grant_is_not_externally_verified() {
        let trusted_authority_key = key(30);
        let trusted_owner_key = key(31);
        let attacker_authority_key = key(32);
        let attacker_owner_key = key(33);
        let (trusted_signer, trusted_signed) = authorization(
            &trusted_authority_key,
            &trusted_owner_key,
            0,
            11,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
        );
        let (attacker_signer, attacker_signed) = authorization(
            &attacker_authority_key,
            &attacker_owner_key,
            0,
            11,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::AdmissionRejected,
        );
        validate_self_consistent_signed_private_oram_owner_cleanup_authorization_v1(
            &attacker_signed,
            &attacker_signer,
        )
        .unwrap();

        let trusted_context = verification_context(&trusted_signed, &trusted_signer);
        assert!(matches!(
            validate_signed_private_oram_owner_cleanup_authorization_v1(
                &attacker_signed,
                &trusted_context,
            ),
            Err(PrivateOramOwnerCleanupError::InvalidTransition)
        ));
    }

    #[test]
    fn all_owner_certificate_sorts_and_rejects_omission_or_tampering() {
        let authority_key = key(5);
        let mut entries = Vec::new();
        let mut authority_signer = None;
        for (owner_index, owner_peer_id, owner_key) in [(1, 12, key(7)), (0, 11, key(6))] {
            let (signer, signed_authorization) = authorization(
                &authority_key,
                &owner_key,
                owner_index,
                owner_peer_id,
                PrivateOramOwnerCleanupNegativeOutcomeKindV1::PrestageAborted,
            );
            authority_signer = Some(signer.clone());
            let verified = verified_authorization(&signed_authorization, &signer);
            let receipt = private_oram_owner_cleanup_receipt_v1(
                &verified,
                PrivateOramOwnerCleanupObservedPrestateV1::Absent,
            )
            .unwrap();
            let signed_receipt =
                sign_private_oram_owner_cleanup_receipt_v1(&owner_key, 9, &receipt).unwrap();
            entries.push(PrivateOramAllOwnerCleanupCertificateEntryV1 {
                authorization: signed_authorization,
                receipt: signed_receipt,
            });
        }
        let authority_signer = authority_signer.unwrap();
        let certificate =
            private_oram_all_owner_cleanup_certificate_v1(&authority_signer, entries).unwrap();
        assert_eq!(
            certificate.entries[0]
                .authorization
                .authorization
                .target
                .owner_index,
            0
        );
        validate_private_oram_all_owner_cleanup_certificate_v1(&certificate, &authority_signer)
            .unwrap();

        let mut missing = certificate.clone();
        missing.entries.pop();
        assert!(matches!(
            validate_private_oram_all_owner_cleanup_certificate_v1(&missing, &authority_signer),
            Err(PrivateOramOwnerCleanupError::IncompleteCertificate)
        ));
        let mut tampered = certificate;
        tampered.entries[0]
            .receipt
            .receipt
            .new_lifecycle_state
            .state_root = digest(88);
        assert!(
            validate_private_oram_all_owner_cleanup_certificate_v1(&tampered, &authority_signer)
                .is_err()
        );
    }

    #[test]
    fn cleanup_wire_uses_decimal_u64_and_rejects_unknown_fields() {
        let authority_key = key(8);
        let owner_key = key(9);
        let (authority_signer, signed) = authorization(
            &authority_key,
            &owner_key,
            0,
            u64::MAX,
            PrivateOramOwnerCleanupNegativeOutcomeKindV1::PrestageAborted,
        );
        let encoded = canonical_json(&signed).unwrap();
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(text.contains(&format!("\"owner_peer_id\":\"{}\"", u64::MAX)));
        decode_private_oram_owner_cleanup_authorization_v1(&encoded, &authority_signer).unwrap();

        let mut value = serde_json::from_slice::<serde_json::Value>(&encoded).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_string(), serde_json::json!(true));
        assert!(
            decode_private_oram_owner_cleanup_authorization_v1(
                &serde_json::to_vec(&value).unwrap(),
                &authority_signer
            )
            .is_err()
        );
    }
}
