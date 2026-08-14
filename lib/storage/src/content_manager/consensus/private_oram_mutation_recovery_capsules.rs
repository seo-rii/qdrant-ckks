//! Consensus-bound proof that every canonical owner durably installed the exact sequence-3
//! recovery capsule before a terminal mutation decision.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt::{self, Debug, Formatter};

use collection::shards::shard::PeerId;
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PrivateOramOwnerCapsuleInstallAttestationV2, private_oram_owner_capsule_canonical_sha256_v2,
    private_oram_owner_capsule_install_attestation_digest_v2,
    validate_private_oram_owner_capsule_install_attestation_for_signer_v2,
    validate_private_oram_owner_capsule_install_attestation_v2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::private_oram_activation_authority::{
    PrivateOramActivationAuthorityLocatorV1, PrivateOramActivationAuthorityStateV1,
};
use super::private_oram_mutation_watermark::{
    PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationParentWatermarkV2,
    validate_private_oram_mutation_parent_watermark_v2_shape,
};
use crate::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationJournalError, PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
    encode_private_oram_owner_recovery_capsule_install_receipt_v2,
    validate_private_oram_owner_recovery_capsule_install_receipt_v2,
};

const RECOVERY_CAPSULES_READY_VERSION: u16 = 2;
const OWNER_RECOVERY_CAPSULE_VERSION: u16 = 2;
const MAX_RECOVERY_CAPSULE_OWNERS: usize = 1_024;
const MAX_RECOVERY_CAPSULES_READY_JSON_BYTES: usize = 4 * 1024 * 1024;
const CAPSULE_SET_DIGEST_DOMAIN: &[u8] = b"qdrant-sec/private-oram-owner-recovery-capsule-set/v2";
const ATTESTATION_SET_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-owner-recovery-attestation-set/v2";
const RECOVERY_CAPSULES_READY_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-mutation-recovery-capsules-ready/v2";

/// Exact local storage receipt plus the owner's durable, transport-independent signature.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2 {
    receipt: PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
    attestation: PrivateOramOwnerCapsuleInstallAttestationV2,
}

impl Debug for PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2")
            .field("owner_peer_id", &"[redacted]")
            .field("receipt", &"[redacted]")
            .field("attestation", &"[redacted]")
            .finish()
    }
}

impl PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2 {
    pub fn from_signed_attestation(
        receipt: PrivateOramOwnerRecoveryCapsuleInstallReceiptV2,
        attestation: PrivateOramOwnerCapsuleInstallAttestationV2,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        let evidence = Self {
            receipt,
            attestation,
        };
        validate_owner_install_evidence_v2(&evidence)?;
        Ok(evidence)
    }

    pub fn owner_peer_id(&self) -> PeerId {
        self.receipt.owner_peer_id()
    }

    pub fn receipt(&self) -> &PrivateOramOwnerRecoveryCapsuleInstallReceiptV2 {
        &self.receipt
    }

    pub fn attestation(&self) -> &PrivateOramOwnerCapsuleInstallAttestationV2 {
        &self.attestation
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationRecoveryCapsulesReadyV2 {
    version: u16,
    point_stage_watermark: PrivateOramMutationParentWatermarkV2,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    capsule_set_digest: String,
    owner_evidence: Vec<PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2>,
    attestation_set_digest: String,
    ready_digest: String,
}

impl Debug for PrivateOramMutationRecoveryCapsulesReadyV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationRecoveryCapsulesReadyV2")
            .field("version", &self.version)
            .field("point_stage_watermark", &self.point_stage_watermark)
            .field("activation_authority", &self.activation_authority)
            .field("owner_evidence_count", &self.owner_evidence.len())
            .field("capsule_set_digest", &"[redacted]")
            .field("attestation_set_digest", &"[redacted]")
            .field("ready_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationRecoveryCapsulesReadyV2 {
    pub(crate) fn generation(&self) -> u64 {
        self.point_stage_watermark.lease_generation()
    }

    pub(crate) fn point_stage_watermark(&self) -> &PrivateOramMutationParentWatermarkV2 {
        &self.point_stage_watermark
    }

    pub(crate) fn activation_authority(&self) -> &PrivateOramActivationAuthorityLocatorV1 {
        &self.activation_authority
    }

    pub(crate) fn capsule_set_digest(&self) -> &str {
        &self.capsule_set_digest
    }

    pub(crate) fn ready_digest(&self) -> &str {
        &self.ready_digest
    }

    pub(crate) fn owner_peer_ids(&self) -> Vec<PeerId> {
        self.owner_evidence
            .iter()
            .map(PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2::owner_peer_id)
            .collect()
    }

    pub(crate) fn receipt_for_owner(
        &self,
        owner_peer_id: PeerId,
    ) -> Option<&PrivateOramOwnerRecoveryCapsuleInstallReceiptV2> {
        self.owner_evidence
            .binary_search_by_key(&owner_peer_id, |evidence| evidence.owner_peer_id())
            .ok()
            .map(|index| self.owner_evidence[index].receipt())
    }

    pub(crate) fn evidence_for_owner(
        &self,
        owner_peer_id: PeerId,
    ) -> Option<&PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2> {
        self.owner_evidence
            .binary_search_by_key(&owner_peer_id, |evidence| evidence.owner_peer_id())
            .ok()
            .map(|index| &self.owner_evidence[index])
    }
}

/// Non-serializable construction wrapper. The wire codec carries only its validated inner value.
pub(crate) struct PrivateOramMutationRecoveryCapsulesReadyExpectationV2 {
    ready: PrivateOramMutationRecoveryCapsulesReadyV2,
}

impl Debug for PrivateOramMutationRecoveryCapsulesReadyExpectationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramMutationRecoveryCapsulesReadyExpectationV2")
            .field(&self.ready)
            .finish()
    }
}

impl PrivateOramMutationRecoveryCapsulesReadyExpectationV2 {
    pub(crate) fn ready(&self) -> &PrivateOramMutationRecoveryCapsulesReadyV2 {
        &self.ready
    }
}

pub(in crate::content_manager) fn derive_private_oram_mutation_recovery_capsules_ready_v2(
    point_stage: &PrivateOramMutationParentWatermarkExpectationV2,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    mut owner_evidence: Vec<PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2>,
) -> Result<PrivateOramMutationRecoveryCapsulesReadyExpectationV2, PrivateOramMutationJournalError>
{
    owner_evidence.sort_by_key(PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2::owner_peer_id);
    let capsule_set_digest = owner_evidence
        .first()
        .ok_or(PrivateOramMutationJournalError::InvalidInput(
            "owner_recovery_evidence",
        ))?
        .receipt()
        .capsule_set_digest()
        .to_string();
    let mut ready = PrivateOramMutationRecoveryCapsulesReadyV2 {
        version: RECOVERY_CAPSULES_READY_VERSION,
        point_stage_watermark: point_stage.watermark().clone(),
        activation_authority,
        capsule_set_digest,
        owner_evidence,
        attestation_set_digest: String::new(),
        ready_digest: String::new(),
    };
    ready.attestation_set_digest = recovery_attestation_set_digest_v2(&ready.owner_evidence)?;
    ready.ready_digest = recovery_capsules_ready_digest_v2(&ready)?;
    validate_private_oram_mutation_recovery_capsules_ready_v2(&ready)?;
    Ok(PrivateOramMutationRecoveryCapsulesReadyExpectationV2 { ready })
}

pub(in crate::content_manager) fn encode_private_oram_mutation_recovery_capsules_ready_v2(
    expectation: &PrivateOramMutationRecoveryCapsulesReadyExpectationV2,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_recovery_capsules_ready_v2(expectation.ready())?;
    let encoded = serde_json::to_string(expectation.ready())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.len() > MAX_RECOVERY_CAPSULES_READY_JSON_BYTES {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "recovery_capsules_ready",
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode_private_oram_mutation_recovery_capsules_ready_v2(
    encoded: &str,
) -> Result<PrivateOramMutationRecoveryCapsulesReadyExpectationV2, PrivateOramMutationJournalError>
{
    if encoded.is_empty() || encoded.len() > MAX_RECOVERY_CAPSULES_READY_JSON_BYTES {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "recovery_capsules_ready",
        ));
    }
    let ready: PrivateOramMutationRecoveryCapsulesReadyV2 = serde_json::from_str(encoded)
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("recovery_capsules_ready"))?;
    validate_private_oram_mutation_recovery_capsules_ready_v2(&ready)?;
    let canonical =
        serde_json::to_string(&ready).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if canonical != encoded {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "recovery_capsules_ready",
        ));
    }
    Ok(PrivateOramMutationRecoveryCapsulesReadyExpectationV2 { ready })
}

pub(crate) fn validate_private_oram_mutation_recovery_capsules_ready_v2(
    ready: &PrivateOramMutationRecoveryCapsulesReadyV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_mutation_parent_watermark_v2_shape(&ready.point_stage_watermark)?;
    if ready.version != RECOVERY_CAPSULES_READY_VERSION
        || ready.point_stage_watermark.sequence() != 3
        || ready.point_stage_watermark.phase_sequence() != 3
        || ready.point_stage_watermark.record_digest().is_none()
        || ready.activation_authority.registry_generation() == 0
        || !is_digest(ready.activation_authority.manifest_digest())
        || ready.owner_evidence.is_empty()
        || ready.owner_evidence.len() > MAX_RECOVERY_CAPSULE_OWNERS
        || !is_digest(&ready.capsule_set_digest)
        || !is_digest(&ready.attestation_set_digest)
        || !is_digest(&ready.ready_digest)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut previous_owner = None;
    for evidence in &ready.owner_evidence {
        validate_owner_install_evidence_v2(evidence)?;
        let receipt = evidence.receipt();
        let statement = &evidence.attestation().statement;
        if previous_owner.is_some_and(|previous| previous >= evidence.owner_peer_id())
            || statement.mutation_id != ready.point_stage_watermark.mutation_id()
            || receipt.parent_descriptor_digest() != ready.point_stage_watermark.descriptor_digest()
            || receipt.capsule_set_digest() != ready.capsule_set_digest
            || receipt.activation_authority() != &ready.activation_authority
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        previous_owner = Some(evidence.owner_peer_id());
    }
    let capsule_entries = ready
        .owner_evidence
        .iter()
        .map(|evidence| {
            (
                evidence.owner_peer_id(),
                evidence.receipt().capsule_digest().to_string(),
            )
        })
        .collect::<Vec<_>>();
    if ready.capsule_set_digest != private_oram_owner_capsule_set_digest_v2(&capsule_entries)?
        || ready.attestation_set_digest
            != recovery_attestation_set_digest_v2(&ready.owner_evidence)?
        || ready.ready_digest != recovery_capsules_ready_digest_v2(ready)?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

pub(crate) fn validate_private_oram_mutation_recovery_capsules_ready_against_authority_v2(
    ready: &PrivateOramMutationRecoveryCapsulesReadyV2,
    expected_collection_id: &str,
    authority: &PrivateOramActivationAuthorityStateV1,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_mutation_recovery_capsules_ready_v2(ready)?;
    if expected_collection_id.is_empty() || ready.activation_authority != authority.locator() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    for evidence in &ready.owner_evidence {
        let statement = &evidence.attestation().statement;
        let pinned_signer = authority
            .manifest()
            .peers
            .binary_search_by_key(&evidence.owner_peer_id(), |peer| peer.peer_id)
            .ok()
            .map(|index| &authority.manifest().peers[index].signer)
            .ok_or(PrivateOramMutationJournalError::InvalidTransition)?;
        if statement.collection_id != expected_collection_id
            || statement.mutation_id != ready.point_stage_watermark.mutation_id()
            || validate_private_oram_owner_capsule_install_attestation_for_signer_v2(
                evidence.attestation(),
                pinned_signer,
            )
            .is_err()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok(())
}

pub(crate) fn private_oram_owner_capsule_set_digest_v2(
    entries: &[(PeerId, String)],
) -> Result<String, PrivateOramMutationJournalError> {
    if entries.is_empty() || entries.len() > MAX_RECOVERY_CAPSULE_OWNERS {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "owner_capsule_set",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(CAPSULE_SET_DIGEST_DOMAIN);
    hasher.update(OWNER_RECOVERY_CAPSULE_VERSION.to_be_bytes());
    hasher.update(
        u64::try_from(entries.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    let mut previous_owner = None;
    for (owner_peer_id, capsule_digest) in entries {
        if *owner_peer_id == 0 || previous_owner.is_some_and(|previous| previous >= *owner_peer_id)
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "owner_capsule_set",
            ));
        }
        hasher.update(owner_peer_id.to_be_bytes());
        hash_digest(&mut hasher, capsule_digest)?;
        previous_owner = Some(*owner_peer_id);
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn recovery_attestation_set_digest_v2(
    evidence: &[PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2],
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(ATTESTATION_SET_DIGEST_DOMAIN);
    hasher.update(RECOVERY_CAPSULES_READY_VERSION.to_be_bytes());
    hasher.update(
        u64::try_from(evidence.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    for owner_evidence in evidence {
        hasher.update(owner_evidence.owner_peer_id().to_be_bytes());
        let attestation_digest =
            private_oram_owner_capsule_install_attestation_digest_v2(owner_evidence.attestation())
                .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        hash_digest(&mut hasher, &attestation_digest)?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn recovery_capsules_ready_digest_v2(
    ready: &PrivateOramMutationRecoveryCapsulesReadyV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_CAPSULES_READY_DIGEST_DOMAIN);
    hasher.update(ready.version.to_be_bytes());
    hash_digest(&mut hasher, ready.point_stage_watermark.watermark_digest())?;
    hasher.update(
        ready
            .activation_authority
            .registry_generation()
            .to_be_bytes(),
    );
    hash_digest(&mut hasher, ready.activation_authority.manifest_digest())?;
    hash_digest(&mut hasher, &ready.capsule_set_digest)?;
    hash_digest(&mut hasher, &ready.attestation_set_digest)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_owner_install_evidence_v2(
    evidence: &PrivateOramOwnerRecoveryCapsuleInstallEvidenceV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_owner_recovery_capsule_install_receipt_v2(&evidence.receipt)?;
    let _verified =
        validate_private_oram_owner_capsule_install_attestation_v2(&evidence.attestation)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let statement = &evidence.attestation.statement;
    let receipt = &evidence.receipt;
    let receipt_canonical_json =
        encode_private_oram_owner_recovery_capsule_install_receipt_v2(receipt)?;
    if statement.owner_peer_id != receipt.owner_peer_id()
        || statement.parent_descriptor_digest != receipt.parent_descriptor_digest()
        || statement.activation_registry_generation
            != receipt.activation_authority().registry_generation()
        || statement.activation_manifest_digest != receipt.activation_authority().manifest_digest()
        || statement.capsule_digest != receipt.capsule_digest()
        || statement.capsule_set_digest != receipt.capsule_set_digest()
        || statement.receipt_digest != receipt.receipt_digest()
        || statement.receipt_canonical_sha256
            != private_oram_owner_capsule_canonical_sha256_v2(&receipt_canonical_json)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

fn hash_digest(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    hasher.update(
        u64::try_from(decoded.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    hasher.update(decoded);
    Ok(())
}

fn is_digest(value: &str) -> bool {
    BASE64URL_NOPAD
        .decode(value.as_bytes())
        .is_ok_and(|decoded| decoded.len() == 32 && BASE64URL_NOPAD.encode(&decoded) == value)
}
