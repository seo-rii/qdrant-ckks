use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM, PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
    PrivateOramAppendOwnerPrepareV1, PrivateOramAppendReadTranscriptDigestInput,
    PrivateOramAppendReadWindowV1, PrivateOramImmutableManifestBundleV2, PrivateOramIndexKindV2,
    PrivateOramObservedReadTranscriptV1, PrivateOramPeerRecoveryPublicKeyV1,
    PrivateOramPeerRecoverySignatureV2, private_oram_append_mutation_v1_digest,
    private_oram_append_read_transcript_v1, validate_private_oram_peer_recovery_public_key_v1,
    validate_private_oram_peer_recovery_signature_v2_shape,
};

pub const PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2: u16 = 2;
pub const PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2: usize = 480 * 1024 * 1024;
pub const PRIVATE_ORAM_OWNER_PRESTAGE_RECEIPT_MAX_CANONICAL_BYTES_V2: usize = 64 * 1024;
pub const PRIVATE_ORAM_OWNER_PRESTAGE_ATTESTATION_MAX_CANONICAL_BYTES_V2: usize = 32 * 1024;
pub const PRIVATE_ORAM_OWNER_PRESTAGE_REQUEST_SIGNATURE_DOMAIN_V2: &str =
    "qdrant-sec/private-oram-owner-prestage-request-signature/v2";
pub const PRIVATE_ORAM_OWNER_PRESTAGE_RESPONSE_SIGNATURE_DOMAIN_V2: &str =
    "qdrant-sec/private-oram-owner-prestage-response-signature/v2";
pub const PRIVATE_ORAM_OWNER_PRESTAGE_ATTESTATION_SIGNATURE_DOMAIN_V2: &str =
    "qdrant-sec/private-oram-owner-prestage-attestation-signature/v2";

const INTENT_KEY_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-prestage-intent-key/v2";
const OWNER_ROSTER_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-prestage-roster/v2";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-prestage-request/v2";
const ATTESTATION_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-prestage-attestation/v2";
const BASE64URL_NOPAD_16_BYTE_LEN: usize = 22;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const MAX_NAME_BYTES: usize = 255;
const MAX_RESOURCE_BYTES: usize = 1_024;
const MAX_OWNER_COUNT: usize = 1_024;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramOwnerPrestageError {
    #[error("private ORAM owner pre-stage protocol version is unsupported")]
    UnsupportedVersion,
    #[error("private ORAM owner pre-stage field is invalid")]
    InvalidField(&'static str),
    #[error("private ORAM owner pre-stage package is not canonical")]
    NonCanonicalPackage,
    #[error("private ORAM owner pre-stage package does not match its request")]
    PackageMismatch,
    #[error("private ORAM owner pre-stage response context does not match")]
    ResponseMismatch,
    #[error("private ORAM owner pre-stage signature key does not match")]
    SignatureKeyMismatch,
    #[error("private ORAM owner pre-stage signature verification failed")]
    InvalidSignature,
}

impl Debug for PrivateOramOwnerPrestageError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramOwnerPrestageError")
            .field(&self.to_string())
            .finish()
    }
}

/// Inert recovery material installed before Raft admission.
///
/// This package carries no authority to modify canonical ORAM state. The signed mutation and
/// encrypted bucket bodies remain client-owned ciphertext. Durable observations omit path labels;
/// they and all encrypted bodies still remain redacted from diagnostics.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPrestagePackageV2 {
    pub version: u16,
    pub collection_name: String,
    pub collection_id: String,
    pub mutation_id: String,
    pub mutation_digest: String,
    pub transition_digest: String,
    pub base_record_digest: String,
    pub expected_aggregate_digest: String,
    pub lease_generation: u64,
    pub writer_fence: u64,
    pub coordinator_peer_id: u64,
    pub owner_peer_id: u64,
    pub vector_name: String,
    pub owner_signing_key_id: String,
    pub activation_registry_generation: u64,
    pub activation_manifest_digest: String,
    pub parent_descriptor_digest: String,
    pub parent_lease_acquired_record_digest: String,
    pub owner_peer_ids: Vec<u64>,
    pub owner_roster_digest: String,
    pub immutable_manifest: PrivateOramImmutableManifestBundleV2,
    pub owner_prepare: PrivateOramAppendOwnerPrepareV1,
    pub durable_read_observations: Vec<PrivateOramDurableReadObservationV2>,
    pub staged_insert_frame_b64: Option<String>,
}

impl Debug for PrivateOramOwnerPrestagePackageV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerPrestagePackageV2")
            .field("version", &self.version)
            .field("collection_name", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("mutation_digest", &"[redacted]")
            .field("lease_generation", &self.lease_generation)
            .field("writer_fence", &self.writer_fence)
            .field("coordinator_peer_id", &self.coordinator_peer_id)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("owner_count", &self.owner_peer_ids.len())
            .field("immutable_manifest", &"[redacted]")
            .field("owner_prepare", &"[redacted]")
            .field(
                "durable_read_observation_count",
                &self.durable_read_observations.len(),
            )
            .field("staged_insert_frame_b64", &"[redacted]")
            .finish()
    }
}

/// Label-free durable projection of one server-observed fixed-budget read transcript.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramDurableReadObservationV2 {
    pub collection_id: String,
    pub manifest_digest: String,
    pub mutation_id: String,
    pub old_state_digest: String,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub read_path_count: u32,
    pub paths_per_window: u32,
    pub tree_height: u32,
    pub transcript_digest: String,
}

impl Debug for PrivateOramDurableReadObservationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramDurableReadObservationV2")
            .field("kind", &self.kind)
            .field("writer_fence", &self.writer_fence)
            .field("read_path_count", &self.read_path_count)
            .field("paths_per_window", &self.paths_per_window)
            .field("tree_height", &self.tree_height)
            .finish_non_exhaustive()
    }
}

pub fn private_oram_owner_prestage_read_observations_v2(
    transcripts: &[PrivateOramObservedReadTranscriptV1],
) -> Result<Vec<PrivateOramDurableReadObservationV2>, PrivateOramOwnerPrestageError> {
    if transcripts.is_empty() || transcripts.len() > 2 {
        return Err(PrivateOramOwnerPrestageError::InvalidField(
            "read_observations",
        ));
    }
    Ok(transcripts
        .iter()
        .map(|transcript| PrivateOramDurableReadObservationV2 {
            collection_id: transcript.collection_id.clone(),
            manifest_digest: transcript.manifest_digest.clone(),
            mutation_id: transcript.mutation_id.clone(),
            old_state_digest: transcript.old_state_digest.clone(),
            writer_lease_digest: transcript.writer_lease_digest.clone(),
            writer_fence: transcript.writer_fence,
            kind: transcript.kind,
            index_name: transcript.index_name.clone(),
            read_path_count: transcript.read_path_count,
            paths_per_window: transcript.paths_per_window,
            tree_height: transcript.tree_height,
            transcript_digest: transcript.transcript_digest.clone(),
        })
        .collect())
}

pub fn reconstruct_private_oram_owner_prestage_read_transcripts_v2(
    prepare: &PrivateOramAppendOwnerPrepareV1,
    observations: &[PrivateOramDurableReadObservationV2],
) -> Result<Vec<PrivateOramObservedReadTranscriptV1>, PrivateOramOwnerPrestageError> {
    if observations.len() != prepare.mutation_bundle.mutation.writebacks.len()
        || observations.is_empty()
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField(
            "read_observations",
        ));
    }
    let mut transcripts = Vec::with_capacity(observations.len());
    for (observation, writeback) in observations
        .iter()
        .zip(&prepare.mutation_bundle.mutation.writebacks)
    {
        if observation.kind != writeback.kind
            || observation.index_name != writeback.index_name
            || observation.read_path_count != writeback.read_path_count
            || observation.transcript_digest != writeback.read_transcript_digest
            || observation.read_path_count == 0
            || observation.paths_per_window == 0
            || observation.tree_height == 0
            || observation.tree_height >= 63
            || observation.read_path_count % observation.paths_per_window != 0
        {
            return Err(PrivateOramOwnerPrestageError::InvalidField(
                "read_observations",
            ));
        }
        let path_bucket_count = usize::try_from(observation.tree_height)
            .ok()
            .and_then(|height| height.checked_add(1))
            .ok_or(PrivateOramOwnerPrestageError::InvalidField(
                "read_observations",
            ))?;
        let expected_bucket_count = usize::try_from(observation.read_path_count)
            .ok()
            .and_then(|count| count.checked_mul(path_bucket_count))
            .ok_or(PrivateOramOwnerPrestageError::InvalidField(
                "read_observations",
            ))?;
        if writeback.updated_buckets.len() != expected_bucket_count {
            return Err(PrivateOramOwnerPrestageError::InvalidField(
                "read_observations",
            ));
        }
        let leaf_base = (1u64 << observation.tree_height) - 1;
        let leaf_count = 1u64 << observation.tree_height;
        let mut labels = Vec::with_capacity(observation.read_path_count as usize);
        for frame in writeback.updated_buckets.chunks_exact(path_bucket_count) {
            let leaf_bucket = frame
                .last()
                .ok_or(PrivateOramOwnerPrestageError::InvalidField(
                    "read_observations",
                ))?
                .bucket_id;
            let leaf = leaf_bucket.checked_sub(leaf_base).ok_or(
                PrivateOramOwnerPrestageError::InvalidField("read_observations"),
            )?;
            if leaf >= leaf_count {
                return Err(PrivateOramOwnerPrestageError::InvalidField(
                    "read_observations",
                ));
            }
            labels.push(BASE64URL_NOPAD.encode(&leaf.to_be_bytes()));
        }
        let paths_per_window = usize::try_from(observation.paths_per_window)
            .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("read_observations"))?;
        let windows = labels
            .chunks(paths_per_window)
            .enumerate()
            .map(|(sequence, paths)| {
                Ok(PrivateOramAppendReadWindowV1 {
                    sequence: u32::try_from(sequence).map_err(|_| {
                        PrivateOramOwnerPrestageError::InvalidField("read_observations")
                    })?,
                    paths: paths.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, PrivateOramOwnerPrestageError>>()?;
        let reconstructed =
            private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
                collection_id: &observation.collection_id,
                manifest_digest: &observation.manifest_digest,
                mutation_id: &observation.mutation_id,
                old_state_digest: &observation.old_state_digest,
                writer_lease_digest: &observation.writer_lease_digest,
                writer_fence: observation.writer_fence,
                paths_per_window: observation.paths_per_window,
                tree_height: observation.tree_height,
                kind: observation.kind,
                index_name: &observation.index_name,
                windows: &windows,
            })
            .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("read_observations"))?;
        if reconstructed.transcript_digest != observation.transcript_digest {
            return Err(PrivateOramOwnerPrestageError::InvalidField(
                "read_observations",
            ));
        }
        transcripts.push(reconstructed);
    }
    Ok(transcripts)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPrestageRequestV2 {
    pub protocol_version: u16,
    pub challenge_nonce: String,
    pub collection_name: String,
    pub collection_id: String,
    pub mutation_id: String,
    pub mutation_digest: String,
    pub transition_digest: String,
    pub expected_aggregate_digest: String,
    pub lease_generation: u64,
    pub writer_fence: u64,
    pub parent_descriptor_digest: String,
    pub parent_lease_acquired_record_digest: String,
    pub owner_roster_digest: String,
    pub coordinator_peer_id: u64,
    pub owner_peer_id: u64,
    pub vector_name: String,
    pub owner_signing_key_id: String,
    pub activation_registry_generation: u64,
    pub activation_manifest_digest: String,
    pub intent_key: String,
    pub package_sha256: String,
    pub package_len: u64,
}

impl Debug for PrivateOramOwnerPrestageRequestV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerPrestageRequestV2")
            .field("protocol_version", &self.protocol_version)
            .field("lease_generation", &self.lease_generation)
            .field("writer_fence", &self.writer_fence)
            .field("coordinator_peer_id", &self.coordinator_peer_id)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("package_len", &self.package_len)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPrestageResponseV2 {
    pub protocol_version: u16,
    pub challenge_nonce: String,
    pub coordinator_peer_id: u64,
    pub owner_peer_id: u64,
    pub request_digest: String,
    pub intent_key: String,
    pub package_sha256: String,
    pub package_len: u64,
    pub receipt_digest: String,
    pub receipt_sha256: String,
    pub receipt_len: u64,
}

impl Debug for PrivateOramOwnerPrestageResponseV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerPrestageResponseV2")
            .field("protocol_version", &self.protocol_version)
            .field("coordinator_peer_id", &self.coordinator_peer_id)
            .field("owner_peer_id", &self.owner_peer_id)
            .field("package_len", &self.package_len)
            .field("receipt_len", &self.receipt_len)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPrestageAttestationStatementV2 {
    pub protocol_version: u16,
    pub collection_id: String,
    pub mutation_id: String,
    pub mutation_digest: String,
    pub transition_digest: String,
    pub expected_aggregate_digest: String,
    pub lease_generation: u64,
    pub writer_fence: u64,
    pub parent_descriptor_digest: String,
    pub parent_lease_acquired_record_digest: String,
    pub owner_roster_digest: String,
    pub owner_peer_id: u64,
    pub activation_registry_generation: u64,
    pub activation_manifest_digest: String,
    pub intent_key: String,
    pub package_sha256: String,
    pub receipt_digest: String,
    pub receipt_sha256: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerPrestageAttestationV2 {
    pub statement: PrivateOramOwnerPrestageAttestationStatementV2,
    pub owner_public_key: PrivateOramPeerRecoveryPublicKeyV1,
    pub signature: PrivateOramPeerRecoverySignatureV2,
}

impl Debug for PrivateOramOwnerPrestageAttestationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerPrestageAttestationV2")
            .field("statement", &"[redacted]")
            .field("owner_public_key", &"[redacted]")
            .field("signature", &"[redacted]")
            .finish()
    }
}

#[must_use]
pub struct VerifiedPrivateOramOwnerPrestageRequestV2 {
    request: PrivateOramOwnerPrestageRequestV2,
}

#[must_use]
pub struct VerifiedPrivateOramOwnerPrestageResponseV2 {
    response: PrivateOramOwnerPrestageResponseV2,
}

#[must_use]
pub struct VerifiedPrivateOramOwnerPrestageAttestationV2 {
    attestation: PrivateOramOwnerPrestageAttestationV2,
    digest: String,
}

impl VerifiedPrivateOramOwnerPrestageRequestV2 {
    pub fn request(&self) -> &PrivateOramOwnerPrestageRequestV2 {
        &self.request
    }
}

impl VerifiedPrivateOramOwnerPrestageResponseV2 {
    pub fn response(&self) -> &PrivateOramOwnerPrestageResponseV2 {
        &self.response
    }
}

impl VerifiedPrivateOramOwnerPrestageAttestationV2 {
    pub fn attestation(&self) -> &PrivateOramOwnerPrestageAttestationV2 {
        &self.attestation
    }

    pub fn statement(&self) -> &PrivateOramOwnerPrestageAttestationStatementV2 {
        &self.attestation.statement
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl Debug for VerifiedPrivateOramOwnerPrestageRequestV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedPrivateOramOwnerPrestageRequestV2([redacted])")
    }
}

impl Debug for VerifiedPrivateOramOwnerPrestageResponseV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedPrivateOramOwnerPrestageResponseV2([redacted])")
    }
}

impl Debug for VerifiedPrivateOramOwnerPrestageAttestationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedPrivateOramOwnerPrestageAttestationV2([redacted])")
    }
}

pub fn private_oram_owner_prestage_roster_digest_v2(
    owner_peer_ids: &[u64],
) -> Result<String, PrivateOramOwnerPrestageError> {
    if owner_peer_ids.is_empty()
        || owner_peer_ids.first() == Some(&0)
        || owner_peer_ids.len() > MAX_OWNER_COUNT
        || owner_peer_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField(
            "owner_peer_ids",
        ));
    }
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, OWNER_ROSTER_DOMAIN)?;
    hash_len(&mut hasher, owner_peer_ids.len())?;
    for peer_id in owner_peer_ids {
        hasher.update(peer_id.to_be_bytes());
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn new_private_oram_owner_prestage_challenge_nonce_v2()
-> Result<String, PrivateOramOwnerPrestageError> {
    let mut nonce = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("challenge_nonce"))?;
    Ok(BASE64URL_NOPAD.encode(&nonce))
}

pub fn encode_private_oram_owner_prestage_package_v2(
    package: &PrivateOramOwnerPrestagePackageV2,
) -> Result<Vec<u8>, PrivateOramOwnerPrestageError> {
    validate_package_shape(package)?;
    let encoded = serde_json::to_vec(package)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("package"))?;
    if encoded.is_empty() || encoded.len() > PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2 {
        return Err(PrivateOramOwnerPrestageError::InvalidField("package"));
    }
    Ok(encoded)
}

pub fn decode_private_oram_owner_prestage_package_v2(
    encoded: &[u8],
) -> Result<PrivateOramOwnerPrestagePackageV2, PrivateOramOwnerPrestageError> {
    if encoded.is_empty() || encoded.len() > PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2 {
        return Err(PrivateOramOwnerPrestageError::InvalidField("package"));
    }
    let package: PrivateOramOwnerPrestagePackageV2 = serde_json::from_slice(encoded)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("package"))?;
    validate_package_shape(&package)?;
    if serde_json::to_vec(&package)
        .map_err(|_| PrivateOramOwnerPrestageError::NonCanonicalPackage)?
        != encoded
    {
        return Err(PrivateOramOwnerPrestageError::NonCanonicalPackage);
    }
    Ok(package)
}

pub fn private_oram_owner_prestage_request_v2(
    challenge_nonce: String,
    package: &PrivateOramOwnerPrestagePackageV2,
    package_canonical_json: &[u8],
) -> Result<PrivateOramOwnerPrestageRequestV2, PrivateOramOwnerPrestageError> {
    validate_package_bytes(package, package_canonical_json)?;
    validate_challenge(&challenge_nonce)?;
    let package_sha256 = digest(package_canonical_json);
    let package_len = u64::try_from(package_canonical_json.len())
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("package_len"))?;
    let mut request = PrivateOramOwnerPrestageRequestV2 {
        protocol_version: PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
        challenge_nonce,
        collection_name: package.collection_name.clone(),
        collection_id: package.collection_id.clone(),
        mutation_id: package.mutation_id.clone(),
        mutation_digest: package.mutation_digest.clone(),
        transition_digest: package.transition_digest.clone(),
        expected_aggregate_digest: package.expected_aggregate_digest.clone(),
        lease_generation: package.lease_generation,
        writer_fence: package.writer_fence,
        parent_descriptor_digest: package.parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: package.parent_lease_acquired_record_digest.clone(),
        owner_roster_digest: package.owner_roster_digest.clone(),
        coordinator_peer_id: package.coordinator_peer_id,
        owner_peer_id: package.owner_peer_id,
        vector_name: package.vector_name.clone(),
        owner_signing_key_id: package.owner_signing_key_id.clone(),
        activation_registry_generation: package.activation_registry_generation,
        activation_manifest_digest: package.activation_manifest_digest.clone(),
        intent_key: String::new(),
        package_sha256,
        package_len,
    };
    request.intent_key = private_oram_owner_prestage_intent_key_v2(&request)?;
    validate_request_shape(&request)?;
    Ok(request)
}

pub fn sign_private_oram_owner_prestage_request_v2(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    request: &PrivateOramOwnerPrestageRequestV2,
) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramOwnerPrestageError> {
    sign(key_pair, key_epoch, request_signature_message(request)?)
}

pub fn validate_private_oram_owner_prestage_request_signature_v2(
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
    request: &PrivateOramOwnerPrestageRequestV2,
    package_canonical_json: &[u8],
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<VerifiedPrivateOramOwnerPrestageRequestV2, PrivateOramOwnerPrestageError> {
    validate_request_shape(request)?;
    if digest(package_canonical_json) != request.package_sha256
        || u64::try_from(package_canonical_json.len()).ok() != Some(request.package_len)
    {
        return Err(PrivateOramOwnerPrestageError::PackageMismatch);
    }
    verify(public_key, signature, &request_signature_message(request)?)?;
    Ok(VerifiedPrivateOramOwnerPrestageRequestV2 {
        request: request.clone(),
    })
}

pub fn validate_private_oram_owner_prestage_package_for_request_v2(
    verified: &VerifiedPrivateOramOwnerPrestageRequestV2,
    package: &PrivateOramOwnerPrestagePackageV2,
    package_canonical_json: &[u8],
) -> Result<(), PrivateOramOwnerPrestageError> {
    validate_package_bytes(package, package_canonical_json)?;
    let rebuilt = private_oram_owner_prestage_request_v2(
        verified.request.challenge_nonce.clone(),
        package,
        package_canonical_json,
    )?;
    if rebuilt != verified.request {
        return Err(PrivateOramOwnerPrestageError::PackageMismatch);
    }
    Ok(())
}

pub fn private_oram_owner_prestage_response_v2(
    request: &PrivateOramOwnerPrestageRequestV2,
    receipt_canonical_json: &[u8],
    receipt_digest: String,
) -> Result<PrivateOramOwnerPrestageResponseV2, PrivateOramOwnerPrestageError> {
    validate_request_shape(request)?;
    validate_digest(&receipt_digest, "receipt_digest")?;
    if receipt_canonical_json.is_empty()
        || receipt_canonical_json.len() > PRIVATE_ORAM_OWNER_PRESTAGE_RECEIPT_MAX_CANONICAL_BYTES_V2
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField("receipt"));
    }
    Ok(PrivateOramOwnerPrestageResponseV2 {
        protocol_version: PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
        challenge_nonce: request.challenge_nonce.clone(),
        coordinator_peer_id: request.coordinator_peer_id,
        owner_peer_id: request.owner_peer_id,
        request_digest: request_digest(request)?,
        intent_key: request.intent_key.clone(),
        package_sha256: request.package_sha256.clone(),
        package_len: request.package_len,
        receipt_digest,
        receipt_sha256: digest(receipt_canonical_json),
        receipt_len: u64::try_from(receipt_canonical_json.len())
            .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("receipt"))?,
    })
}

pub fn sign_private_oram_owner_prestage_response_v2(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    request: &PrivateOramOwnerPrestageRequestV2,
    response: &PrivateOramOwnerPrestageResponseV2,
    receipt_canonical_json: &[u8],
) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramOwnerPrestageError> {
    validate_response(request, response, receipt_canonical_json)?;
    sign(
        key_pair,
        key_epoch,
        response_signature_message(request, response)?,
    )
}

pub fn validate_private_oram_owner_prestage_response_signature_v2(
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
    request: &PrivateOramOwnerPrestageRequestV2,
    response: &PrivateOramOwnerPrestageResponseV2,
    receipt_canonical_json: &[u8],
    signature: &PrivateOramPeerRecoverySignatureV2,
) -> Result<VerifiedPrivateOramOwnerPrestageResponseV2, PrivateOramOwnerPrestageError> {
    validate_response(request, response, receipt_canonical_json)?;
    verify(
        public_key,
        signature,
        &response_signature_message(request, response)?,
    )?;
    Ok(VerifiedPrivateOramOwnerPrestageResponseV2 {
        response: response.clone(),
    })
}

/// Builds the statement an owner attests to. `response` must be the response the owner produced
/// for `request` over `receipt_canonical_json`, so the attested receipt hash and length are bound
/// to the receipt bytes instead of being copied from a self-asserted response.
pub fn private_oram_owner_prestage_attestation_statement_v2(
    request: &PrivateOramOwnerPrestageRequestV2,
    response: &PrivateOramOwnerPrestageResponseV2,
    receipt_canonical_json: &[u8],
) -> Result<PrivateOramOwnerPrestageAttestationStatementV2, PrivateOramOwnerPrestageError> {
    validate_response(request, response, receipt_canonical_json)?;
    Ok(PrivateOramOwnerPrestageAttestationStatementV2 {
        protocol_version: PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
        collection_id: request.collection_id.clone(),
        mutation_id: request.mutation_id.clone(),
        mutation_digest: request.mutation_digest.clone(),
        transition_digest: request.transition_digest.clone(),
        expected_aggregate_digest: request.expected_aggregate_digest.clone(),
        lease_generation: request.lease_generation,
        writer_fence: request.writer_fence,
        parent_descriptor_digest: request.parent_descriptor_digest.clone(),
        parent_lease_acquired_record_digest: request.parent_lease_acquired_record_digest.clone(),
        owner_roster_digest: request.owner_roster_digest.clone(),
        owner_peer_id: request.owner_peer_id,
        activation_registry_generation: request.activation_registry_generation,
        activation_manifest_digest: request.activation_manifest_digest.clone(),
        intent_key: request.intent_key.clone(),
        package_sha256: request.package_sha256.clone(),
        receipt_digest: response.receipt_digest.clone(),
        receipt_sha256: response.receipt_sha256.clone(),
    })
}

pub fn sign_private_oram_owner_prestage_attestation_v2(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    statement: &PrivateOramOwnerPrestageAttestationStatementV2,
) -> Result<PrivateOramOwnerPrestageAttestationV2, PrivateOramOwnerPrestageError> {
    validate_attestation_statement(statement)?;
    let public_key = crate::private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidSignature)?;
    let signature = sign(key_pair, key_epoch, attestation_message(statement)?)?;
    Ok(PrivateOramOwnerPrestageAttestationV2 {
        statement: statement.clone(),
        owner_public_key: public_key,
        signature,
    })
}

pub fn validate_private_oram_owner_prestage_attestation_v2(
    attestation: &PrivateOramOwnerPrestageAttestationV2,
) -> Result<VerifiedPrivateOramOwnerPrestageAttestationV2, PrivateOramOwnerPrestageError> {
    validate_attestation_statement(&attestation.statement)?;
    verify(
        &attestation.owner_public_key,
        &attestation.signature,
        &attestation_message(&attestation.statement)?,
    )?;
    Ok(VerifiedPrivateOramOwnerPrestageAttestationV2 {
        digest: digest_with_domain(
            ATTESTATION_DIGEST_DOMAIN,
            &serde_json::to_vec(attestation)
                .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("attestation"))?,
        )?,
        attestation: attestation.clone(),
    })
}

pub fn encode_private_oram_owner_prestage_attestation_v2(
    attestation: &PrivateOramOwnerPrestageAttestationV2,
) -> Result<Vec<u8>, PrivateOramOwnerPrestageError> {
    let _verified = validate_private_oram_owner_prestage_attestation_v2(attestation)?;
    let encoded = serde_json::to_vec(attestation)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("attestation"))?;
    if encoded.is_empty()
        || encoded.len() > PRIVATE_ORAM_OWNER_PRESTAGE_ATTESTATION_MAX_CANONICAL_BYTES_V2
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField("attestation"));
    }
    Ok(encoded)
}

pub fn decode_private_oram_owner_prestage_attestation_v2(
    encoded: &[u8],
) -> Result<PrivateOramOwnerPrestageAttestationV2, PrivateOramOwnerPrestageError> {
    if encoded.is_empty()
        || encoded.len() > PRIVATE_ORAM_OWNER_PRESTAGE_ATTESTATION_MAX_CANONICAL_BYTES_V2
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField("attestation"));
    }
    let attestation: PrivateOramOwnerPrestageAttestationV2 = serde_json::from_slice(encoded)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("attestation"))?;
    if encode_private_oram_owner_prestage_attestation_v2(&attestation)? != encoded {
        return Err(PrivateOramOwnerPrestageError::InvalidField("attestation"));
    }
    Ok(attestation)
}

pub fn validate_private_oram_owner_prestage_attestation_for_signer_v2(
    attestation: &PrivateOramOwnerPrestageAttestationV2,
    expected_signer: &PrivateOramPeerRecoveryPublicKeyV1,
) -> Result<VerifiedPrivateOramOwnerPrestageAttestationV2, PrivateOramOwnerPrestageError> {
    if &attestation.owner_public_key != expected_signer {
        return Err(PrivateOramOwnerPrestageError::SignatureKeyMismatch);
    }
    validate_private_oram_owner_prestage_attestation_v2(attestation)
}

fn validate_package_bytes(
    package: &PrivateOramOwnerPrestagePackageV2,
    encoded: &[u8],
) -> Result<(), PrivateOramOwnerPrestageError> {
    if encode_private_oram_owner_prestage_package_v2(package)? != encoded {
        return Err(PrivateOramOwnerPrestageError::NonCanonicalPackage);
    }
    Ok(())
}

fn validate_package_shape(
    package: &PrivateOramOwnerPrestagePackageV2,
) -> Result<(), PrivateOramOwnerPrestageError> {
    if package.version != PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2 {
        return Err(PrivateOramOwnerPrestageError::UnsupportedVersion);
    }
    validate_name(&package.collection_name, "collection_name")?;
    validate_resource(&package.collection_id, "collection_id")?;
    validate_resource(&package.vector_name, "vector_name")?;
    validate_resource(&package.owner_signing_key_id, "owner_signing_key_id")?;
    for (value, field) in [
        (&package.mutation_id, "mutation_id"),
        (&package.mutation_digest, "mutation_digest"),
        (&package.transition_digest, "transition_digest"),
        (&package.base_record_digest, "base_record_digest"),
        (
            &package.expected_aggregate_digest,
            "expected_aggregate_digest",
        ),
        (
            &package.activation_manifest_digest,
            "activation_manifest_digest",
        ),
        (
            &package.parent_descriptor_digest,
            "parent_descriptor_digest",
        ),
        (
            &package.parent_lease_acquired_record_digest,
            "parent_lease_acquired_record_digest",
        ),
        (&package.owner_roster_digest, "owner_roster_digest"),
    ] {
        validate_digest(value, field)?;
    }
    let mutation = &package.owner_prepare.mutation_bundle.mutation;
    if package.activation_registry_generation == 0
        || package.lease_generation == 0
        || package.writer_fence == 0
        || package.owner_peer_id == 0
        || package.coordinator_peer_id == 0
        || !package
            .owner_peer_ids
            .contains(&package.coordinator_peer_id)
        || !package.owner_peer_ids.contains(&package.owner_peer_id)
        || package.owner_roster_digest
            != private_oram_owner_prestage_roster_digest_v2(&package.owner_peer_ids)?
        || package.mutation_digest
            != private_oram_append_mutation_v1_digest(mutation)
                .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("mutation"))?
        || mutation.collection_id != package.collection_id
        || mutation.mutation_id != package.mutation_id
        || mutation.writer_fence != package.writer_fence
        || package.immutable_manifest.manifest.collection_id != package.collection_id
        || package.immutable_manifest.manifest.owner_signing_key_id != package.owner_signing_key_id
        || package.durable_read_observations.len() != package.owner_prepare.indexes.len()
        || reconstruct_private_oram_owner_prestage_read_transcripts_v2(
            &package.owner_prepare,
            &package.durable_read_observations,
        )
        .is_err()
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField("package"));
    }
    Ok(())
}

fn validate_request_shape(
    request: &PrivateOramOwnerPrestageRequestV2,
) -> Result<(), PrivateOramOwnerPrestageError> {
    if request.protocol_version != PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2 {
        return Err(PrivateOramOwnerPrestageError::UnsupportedVersion);
    }
    validate_challenge(&request.challenge_nonce)?;
    validate_name(&request.collection_name, "collection_name")?;
    validate_resource(&request.collection_id, "collection_id")?;
    validate_resource(&request.vector_name, "vector_name")?;
    validate_resource(&request.owner_signing_key_id, "owner_signing_key_id")?;
    for (value, field) in [
        (&request.mutation_id, "mutation_id"),
        (&request.mutation_digest, "mutation_digest"),
        (&request.transition_digest, "transition_digest"),
        (
            &request.expected_aggregate_digest,
            "expected_aggregate_digest",
        ),
        (
            &request.parent_descriptor_digest,
            "parent_descriptor_digest",
        ),
        (
            &request.parent_lease_acquired_record_digest,
            "parent_lease_acquired_record_digest",
        ),
        (&request.owner_roster_digest, "owner_roster_digest"),
        (
            &request.activation_manifest_digest,
            "activation_manifest_digest",
        ),
        (&request.intent_key, "intent_key"),
        (&request.package_sha256, "package_sha256"),
    ] {
        validate_digest(value, field)?;
    }
    if request.package_len == 0
        || request.package_len > PRIVATE_ORAM_OWNER_PRESTAGE_MAX_CANONICAL_BYTES_V2 as u64
        || request.lease_generation == 0
        || request.writer_fence == 0
        || request.activation_registry_generation == 0
        || request.owner_peer_id == 0
        || request.coordinator_peer_id == 0
        || request.intent_key != private_oram_owner_prestage_intent_key_v2(request)?
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField("request"));
    }
    Ok(())
}

fn validate_response(
    request: &PrivateOramOwnerPrestageRequestV2,
    response: &PrivateOramOwnerPrestageResponseV2,
    receipt: &[u8],
) -> Result<(), PrivateOramOwnerPrestageError> {
    validate_request_shape(request)?;
    if response.protocol_version != PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2
        || response.challenge_nonce != request.challenge_nonce
        || response.coordinator_peer_id != request.coordinator_peer_id
        || response.owner_peer_id != request.owner_peer_id
        || response.request_digest != request_digest(request)?
        || response.intent_key != request.intent_key
        || response.package_sha256 != request.package_sha256
        || response.package_len != request.package_len
        || response.receipt_sha256 != digest(receipt)
        || usize::try_from(response.receipt_len).ok() != Some(receipt.len())
    {
        return Err(PrivateOramOwnerPrestageError::ResponseMismatch);
    }
    validate_digest(&response.receipt_digest, "receipt_digest")
}

fn validate_attestation_statement(
    statement: &PrivateOramOwnerPrestageAttestationStatementV2,
) -> Result<(), PrivateOramOwnerPrestageError> {
    if statement.protocol_version != PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2
        || statement.lease_generation == 0
        || statement.writer_fence == 0
        || statement.activation_registry_generation == 0
        || statement.owner_peer_id == 0
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField("attestation"));
    }
    validate_resource(&statement.collection_id, "collection_id")?;
    for (value, field) in [
        (&statement.mutation_id, "mutation_id"),
        (&statement.mutation_digest, "mutation_digest"),
        (&statement.transition_digest, "transition_digest"),
        (
            &statement.expected_aggregate_digest,
            "expected_aggregate_digest",
        ),
        (
            &statement.parent_descriptor_digest,
            "parent_descriptor_digest",
        ),
        (
            &statement.parent_lease_acquired_record_digest,
            "parent_lease_acquired_record_digest",
        ),
        (&statement.owner_roster_digest, "owner_roster_digest"),
        (
            &statement.activation_manifest_digest,
            "activation_manifest_digest",
        ),
        (&statement.intent_key, "intent_key"),
        (&statement.package_sha256, "package_sha256"),
        (&statement.receipt_digest, "receipt_digest"),
        (&statement.receipt_sha256, "receipt_sha256"),
    ] {
        validate_digest(value, field)?;
    }
    Ok(())
}

fn private_oram_owner_prestage_intent_key_v2(
    request: &PrivateOramOwnerPrestageRequestV2,
) -> Result<String, PrivateOramOwnerPrestageError> {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, INTENT_KEY_DOMAIN)?;
    for value in [
        &request.collection_id,
        &request.mutation_id,
        &request.mutation_digest,
        &request.transition_digest,
        &request.expected_aggregate_digest,
        &request.parent_descriptor_digest,
        &request.parent_lease_acquired_record_digest,
        &request.owner_roster_digest,
        &request.activation_manifest_digest,
        &request.package_sha256,
    ] {
        hash_bytes(&mut hasher, value.as_bytes())?;
    }
    hasher.update(request.lease_generation.to_be_bytes());
    hasher.update(request.writer_fence.to_be_bytes());
    hasher.update(request.activation_registry_generation.to_be_bytes());
    hasher.update(request.owner_peer_id.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_owner_prestage_request_digest_v2(
    request: &PrivateOramOwnerPrestageRequestV2,
) -> Result<String, PrivateOramOwnerPrestageError> {
    digest_with_domain(
        REQUEST_DIGEST_DOMAIN,
        &serde_json::to_vec(request)
            .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("request"))?,
    )
}

fn request_digest(
    request: &PrivateOramOwnerPrestageRequestV2,
) -> Result<String, PrivateOramOwnerPrestageError> {
    private_oram_owner_prestage_request_digest_v2(request)
}

fn request_signature_message(
    request: &PrivateOramOwnerPrestageRequestV2,
) -> Result<Vec<u8>, PrivateOramOwnerPrestageError> {
    validate_request_shape(request)?;
    signature_message(
        PRIVATE_ORAM_OWNER_PRESTAGE_REQUEST_SIGNATURE_DOMAIN_V2,
        &[&serde_json::to_vec(request)
            .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("request"))?],
    )
}

fn response_signature_message(
    request: &PrivateOramOwnerPrestageRequestV2,
    response: &PrivateOramOwnerPrestageResponseV2,
) -> Result<Vec<u8>, PrivateOramOwnerPrestageError> {
    signature_message(
        PRIVATE_ORAM_OWNER_PRESTAGE_RESPONSE_SIGNATURE_DOMAIN_V2,
        &[
            &serde_json::to_vec(request)
                .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("request"))?,
            &serde_json::to_vec(response)
                .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("response"))?,
        ],
    )
}

fn attestation_message(
    statement: &PrivateOramOwnerPrestageAttestationStatementV2,
) -> Result<Vec<u8>, PrivateOramOwnerPrestageError> {
    validate_attestation_statement(statement)?;
    signature_message(
        PRIVATE_ORAM_OWNER_PRESTAGE_ATTESTATION_SIGNATURE_DOMAIN_V2,
        &[&serde_json::to_vec(statement)
            .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("attestation"))?],
    )
}

fn signature_message(
    domain: &str,
    fields: &[&[u8]],
) -> Result<Vec<u8>, PrivateOramOwnerPrestageError> {
    let mut output = Vec::new();
    push_len(&mut output, domain.len(), 4)?;
    output.extend_from_slice(domain.as_bytes());
    for field in fields {
        push_len(&mut output, field.len(), 8)?;
        output.extend_from_slice(field);
    }
    Ok(output)
}

fn sign(
    key_pair: &Ed25519KeyPair,
    key_epoch: u64,
    message: Vec<u8>,
) -> Result<PrivateOramPeerRecoverySignatureV2, PrivateOramOwnerPrestageError> {
    let public_key = crate::private_oram_peer_recovery_public_key_v1(key_pair, key_epoch)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidSignature)?;
    Ok(PrivateOramPeerRecoverySignatureV2 {
        version: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_VERSION,
        alg: PRIVATE_ORAM_PEER_RECOVERY_SIGNATURE_ALGORITHM.to_string(),
        key_epoch: public_key.key_epoch,
        key_id: public_key.key_id,
        sig: BASE64URL_NOPAD.encode(key_pair.sign(&message).as_ref()),
    })
}

fn verify(
    public_key: &PrivateOramPeerRecoveryPublicKeyV1,
    signature: &PrivateOramPeerRecoverySignatureV2,
    message: &[u8],
) -> Result<(), PrivateOramOwnerPrestageError> {
    let key = validate_private_oram_peer_recovery_public_key_v1(public_key)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidSignature)?;
    validate_private_oram_peer_recovery_signature_v2_shape(signature)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidSignature)?;
    if signature.alg != public_key.alg
        || signature.key_epoch != public_key.key_epoch
        || signature.key_id != public_key.key_id
    {
        return Err(PrivateOramOwnerPrestageError::SignatureKeyMismatch);
    }
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidSignature)?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(message, &signature_bytes)
        .map_err(|_| PrivateOramOwnerPrestageError::InvalidSignature)
}

fn validate_challenge(value: &str) -> Result<(), PrivateOramOwnerPrestageError> {
    if value.len() != BASE64URL_NOPAD_16_BYTE_LEN
        || BASE64URL_NOPAD
            .decode(value.as_bytes())
            .map_or(true, |v| v.len() != 16)
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField(
            "challenge_nonce",
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), PrivateOramOwnerPrestageError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN
        || BASE64URL_NOPAD
            .decode(value.as_bytes())
            .map_or(true, |v| v.len() != 32)
    {
        return Err(PrivateOramOwnerPrestageError::InvalidField(field));
    }
    Ok(())
}

fn validate_name(value: &str, field: &'static str) -> Result<(), PrivateOramOwnerPrestageError> {
    if value.is_empty() || value.len() > MAX_NAME_BYTES {
        return Err(PrivateOramOwnerPrestageError::InvalidField(field));
    }
    Ok(())
}

fn validate_resource(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramOwnerPrestageError> {
    if value.is_empty() || value.len() > MAX_RESOURCE_BYTES {
        return Err(PrivateOramOwnerPrestageError::InvalidField(field));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(bytes))
}

fn digest_with_domain(
    domain: &[u8],
    bytes: &[u8],
) -> Result<String, PrivateOramOwnerPrestageError> {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, domain)?;
    hash_bytes(&mut hasher, bytes)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), PrivateOramOwnerPrestageError> {
    hasher.update(
        u64::try_from(bytes.len())
            .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("length"))?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Ok(())
}

fn hash_len(hasher: &mut Sha256, len: usize) -> Result<(), PrivateOramOwnerPrestageError> {
    hasher.update(
        u64::try_from(len)
            .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("length"))?
            .to_be_bytes(),
    );
    Ok(())
}

fn push_len(
    output: &mut Vec<u8>,
    len: usize,
    width: usize,
) -> Result<(), PrivateOramOwnerPrestageError> {
    match width {
        4 => output.extend_from_slice(
            &u32::try_from(len)
                .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("length"))?
                .to_be_bytes(),
        ),
        8 => output.extend_from_slice(
            &u64::try_from(len)
                .map_err(|_| PrivateOramOwnerPrestageError::InvalidField("length"))?
                .to_be_bytes(),
        ),
        _ => return Err(PrivateOramOwnerPrestageError::InvalidField("length")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::json_mutation::mutate_json_leaf;

    fn fixed_digest(seed: u8) -> String {
        BASE64URL_NOPAD.encode(&[seed; 32])
    }

    fn request(package: &[u8]) -> PrivateOramOwnerPrestageRequestV2 {
        let mut request = PrivateOramOwnerPrestageRequestV2 {
            protocol_version: PRIVATE_ORAM_OWNER_PRESTAGE_PROTOCOL_VERSION_V2,
            challenge_nonce: BASE64URL_NOPAD.encode(&[7; 16]),
            collection_name: "docs".to_string(),
            collection_id: "collection-uuid-1".to_string(),
            mutation_id: fixed_digest(1),
            mutation_digest: fixed_digest(2),
            transition_digest: fixed_digest(3),
            expected_aggregate_digest: fixed_digest(4),
            lease_generation: 4,
            writer_fence: 9,
            parent_descriptor_digest: fixed_digest(5),
            parent_lease_acquired_record_digest: fixed_digest(6),
            owner_roster_digest: private_oram_owner_prestage_roster_digest_v2(&[11, 12]).unwrap(),
            coordinator_peer_id: 11,
            owner_peer_id: 12,
            vector_name: "text".to_string(),
            owner_signing_key_id: "tenant-a/private-oram-owner-v1".to_string(),
            activation_registry_generation: 3,
            activation_manifest_digest: fixed_digest(7),
            intent_key: String::new(),
            package_sha256: digest(package),
            package_len: u64::try_from(package.len()).unwrap(),
        };
        request.intent_key = private_oram_owner_prestage_intent_key_v2(&request).unwrap();
        request
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(192))]

        /// Every scalar field of a pre-stage request, response or attestation is covered by
        /// its signature: changing any one of them is rejected.
        #[test]
        fn every_field_mutation_is_rejected(index in any::<usize>(), salt in any::<u8>()) {
            let coordinator = Ed25519KeyPair::from_seed_unchecked(&[41; 32]).unwrap();
            let owner = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
            let package = br#"{"package":"opaque"}"#;
            let request = request(package);
            let coordinator_public_key =
                crate::private_oram_peer_recovery_public_key_v1(&coordinator, 1).unwrap();
            let request_signature =
                sign_private_oram_owner_prestage_request_v2(&coordinator, 1, &request).unwrap();
            let mut value = serde_json::to_value(&request).unwrap();
            let path = mutate_json_leaf(&mut value, index, salt);
            if let Ok(mutated) = serde_json::from_value::<PrivateOramOwnerPrestageRequestV2>(value)
            {
                prop_assert!(
                    validate_private_oram_owner_prestage_request_signature_v2(
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
                private_oram_owner_prestage_response_v2(&request, receipt, fixed_digest(8)).unwrap();
            let owner_public_key =
                crate::private_oram_peer_recovery_public_key_v1(&owner, 1).unwrap();
            let response_signature = sign_private_oram_owner_prestage_response_v2(
                &owner, 1, &request, &response, receipt,
            )
            .unwrap();
            let mut value = serde_json::to_value(&response).unwrap();
            let path = mutate_json_leaf(&mut value, index, salt);
            if let Ok(mutated) =
                serde_json::from_value::<PrivateOramOwnerPrestageResponseV2>(value)
            {
                prop_assert!(
                    validate_private_oram_owner_prestage_response_signature_v2(
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

            let statement =
                private_oram_owner_prestage_attestation_statement_v2(&request, &response, receipt)
                    .unwrap();
            let attestation =
                sign_private_oram_owner_prestage_attestation_v2(&owner, 1, &statement).unwrap();
            let mut value = serde_json::to_value(&attestation).unwrap();
            let path = mutate_json_leaf(&mut value, index, salt);
            if let Ok(mutated) =
                serde_json::from_value::<PrivateOramOwnerPrestageAttestationV2>(value)
            {
                prop_assert!(
                    validate_private_oram_owner_prestage_attestation_for_signer_v2(
                        &mutated,
                        &owner_public_key,
                    )
                    .is_err(),
                    "attestation mutation at {} was accepted",
                    path
                );
            }
        }
    }
}
