//! Dormant consensus watermark model for one private-ORAM parent mutation history.
//!
//! A structurally valid local journal is not cleanup or lease-clear authority. This module only
//! packages its canonical prefix for a later consensus CAS. The CAS, live-resource verification,
//! cleanup witness, and mixed-version activation barrier are separate steps.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt::{self, Debug, Formatter};

use collection::shards::shard::PeerId;
use data_encoding::BASE64URL_NOPAD;
use serde::de::{self, IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::content_manager::consensus_ops::PrivateOramMutationLease;
use crate::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationJournalError, PrivateOramMutationJournalStructuralSnapshotV2,
};
use crate::content_manager::private_oram_mutation_state_v2::{
    PrivateOramMutationJournalPhaseV2, private_oram_collection_id_digest_v2,
    record_digest_at_phase_v2, validate_private_oram_mutation_state_v2_structure,
};

pub(crate) const PRIVATE_ORAM_MUTATION_PARENT_WATERMARK_VERSION: u16 = 1;

const PARENT_WATERMARK_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-parent-watermark/v2";
const MUTATION_LEASE_LINEAGE_DIGEST_DOMAIN_V2: &[u8] =
    b"qdrant-sec/private-oram-mutation-lease-lineage/v2";
const MAX_PARENT_WATERMARK_ENTRIES: usize = 7;
const MAX_PARENT_WATERMARK_CANONICAL_JSON_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationParentWatermarkEntryV2 {
    sequence: u64,
    phase: PrivateOramMutationJournalPhaseV2,
    record_digest: String,
}

impl Debug for PrivateOramMutationParentWatermarkEntryV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationParentWatermarkEntryV2")
            .field("sequence", &self.sequence)
            .field("phase", &self.phase)
            .field("record_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationParentWatermarkV2 {
    version: u16,
    collection_id_digest: String,
    lease_generation: u64,
    owner_peer_id: PeerId,
    mutation_id: String,
    signed_mutation_digest: String,
    transition_digest: String,
    base_record_digest: String,
    base_state_sequence: u64,
    writer_lease_digest: String,
    writer_fence: u64,
    lease_issued_at_unix: u64,
    lease_lineage_digest: String,
    descriptor_digest: String,
    #[serde(deserialize_with = "deserialize_parent_watermark_history")]
    history: Vec<PrivateOramMutationParentWatermarkEntryV2>,
    watermark_digest: String,
}

impl Debug for PrivateOramMutationParentWatermarkV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationParentWatermarkV2")
            .field("version", &self.version)
            .field("lease_generation", &"[redacted]")
            .field("owner_peer_id", &"[redacted]")
            .field("base_state_sequence", &self.base_state_sequence)
            .field("writer_fence", &"[redacted]")
            .field("history", &self.history)
            .field("collection_id_digest", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("signed_mutation_digest", &"[redacted]")
            .field("transition_digest", &"[redacted]")
            .field("base_record_digest", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("lease_issued_at_unix", &"[redacted]")
            .field("lease_lineage_digest", &"[redacted]")
            .field("descriptor_digest", &"[redacted]")
            .field("watermark_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationParentWatermarkV2 {
    pub(crate) fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    pub(crate) fn mutation_id(&self) -> &str {
        &self.mutation_id
    }

    pub(crate) fn collection_id_digest(&self) -> &str {
        &self.collection_id_digest
    }

    pub(crate) fn owner_peer_id(&self) -> PeerId {
        self.owner_peer_id
    }

    pub(crate) fn signed_mutation_digest(&self) -> &str {
        &self.signed_mutation_digest
    }

    pub(crate) fn base_record_digest(&self) -> &str {
        &self.base_record_digest
    }

    pub(crate) fn lease_lineage_digest(&self) -> &str {
        &self.lease_lineage_digest
    }

    pub(crate) fn descriptor_digest(&self) -> &str {
        &self.descriptor_digest
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.history.last().map_or(0, |entry| entry.sequence)
    }

    pub(crate) fn phase_sequence(&self) -> u64 {
        self.history
            .last()
            .map_or(0, |entry| entry.phase.sequence())
    }

    pub(crate) fn record_digest(&self) -> Option<&str> {
        self.history
            .last()
            .map(|entry| entry.record_digest.as_str())
    }

    pub(crate) fn watermark_digest(&self) -> &str {
        &self.watermark_digest
    }

    fn has_same_identity(&self, other: &Self) -> bool {
        self.version == other.version
            && self.collection_id_digest == other.collection_id_digest
            && self.lease_generation == other.lease_generation
            && self.owner_peer_id == other.owner_peer_id
            && self.mutation_id == other.mutation_id
            && self.signed_mutation_digest == other.signed_mutation_digest
            && self.transition_digest == other.transition_digest
            && self.base_record_digest == other.base_record_digest
            && self.base_state_sequence == other.base_state_sequence
            && self.writer_lease_digest == other.writer_lease_digest
            && self.writer_fence == other.writer_fence
            && self.lease_issued_at_unix == other.lease_issued_at_unix
            && self.lease_lineage_digest == other.lease_lineage_digest
            && self.descriptor_digest == other.descriptor_digest
    }
}

/// A non-serializable expectation derived from a signature-validated journal snapshot.
///
/// It proves only where a structural watermark came from. It is not cleanup, lease-clear, or
/// mutation-admission authority.
pub(crate) struct PrivateOramMutationParentWatermarkExpectationV2 {
    watermark: PrivateOramMutationParentWatermarkV2,
}

impl Debug for PrivateOramMutationParentWatermarkExpectationV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PrivateOramMutationParentWatermarkExpectationV2")
            .field(&self.watermark)
            .finish()
    }
}

impl PrivateOramMutationParentWatermarkExpectationV2 {
    pub(crate) fn watermark(&self) -> &PrivateOramMutationParentWatermarkV2 {
        &self.watermark
    }
}

pub(in crate::content_manager) fn encode_private_oram_mutation_parent_watermark_expectation_v2(
    expectation: &PrivateOramMutationParentWatermarkExpectationV2,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_parent_watermark_v2_shape(expectation.watermark())?;
    let encoded = serde_json::to_string(expectation.watermark())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.len() > MAX_PARENT_WATERMARK_CANONICAL_JSON_BYTES {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "parent_watermark",
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode_private_oram_mutation_parent_watermark_expectation_v2(
    encoded: &str,
) -> Result<PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationJournalError> {
    if encoded.is_empty() || encoded.len() > MAX_PARENT_WATERMARK_CANONICAL_JSON_BYTES {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "parent_watermark",
        ));
    }
    let watermark: PrivateOramMutationParentWatermarkV2 = serde_json::from_str(encoded)
        .map_err(|_| PrivateOramMutationJournalError::InvalidInput("parent_watermark"))?;
    validate_private_oram_mutation_parent_watermark_v2_shape(&watermark)?;
    let canonical =
        serde_json::to_string(&watermark).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if canonical != encoded {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "parent_watermark",
        ));
    }
    Ok(PrivateOramMutationParentWatermarkExpectationV2 { watermark })
}

/// Derives an exact structural expectation from a snapshot whose descriptor signature and complete
/// on-disk V2 history were validated by the journal loader.
pub(in crate::content_manager) fn derive_private_oram_mutation_parent_watermark_expectation_v2(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
) -> Result<PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationJournalError> {
    derive_private_oram_mutation_parent_watermark_for_state_v2(
        snapshot.validated_descriptor(),
        snapshot.effective_state(),
    )
}

pub(in crate::content_manager) fn derive_private_oram_mutation_parent_watermark_at_sequence_v2(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
    sequence: u64,
) -> Result<PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationJournalError> {
    let expected = derive_private_oram_mutation_parent_watermark_expectation_v2(snapshot)?;
    truncate_private_oram_mutation_parent_watermark_expectation_v2(&expected, sequence)
}

pub(in crate::content_manager) fn derive_private_oram_mutation_parent_watermark_for_state_v2(
    descriptor: &crate::content_manager::private_oram_mutation_journal::PrivateOramMutationJournalDescriptorV1,
    state: &crate::content_manager::private_oram_mutation_state_v2::PrivateOramMutationJournalStateV2,
) -> Result<PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_state_v2_structure(descriptor, state)?;
    let lease = &descriptor.preparing_lease;
    let mut history = Vec::with_capacity(state.sequence as usize);
    for sequence in 1..=state.sequence {
        let phase = PrivateOramMutationJournalPhaseV2::from_sequence(sequence)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        history.push(PrivateOramMutationParentWatermarkEntryV2 {
            sequence,
            phase,
            record_digest: record_digest_at_phase_v2(descriptor, state, phase)?,
        });
    }
    let mut candidate = PrivateOramMutationParentWatermarkV2 {
        version: PRIVATE_ORAM_MUTATION_PARENT_WATERMARK_VERSION,
        collection_id_digest: private_oram_collection_id_digest_v2(
            &descriptor.mutation_bundle.mutation.collection_id,
        )?,
        lease_generation: lease.generation,
        owner_peer_id: lease.owner_peer_id,
        mutation_id: lease.mutation_id.clone(),
        signed_mutation_digest: lease.signed_mutation_digest.clone(),
        transition_digest: lease.transition_digest.clone(),
        base_record_digest: lease.base_record_digest.clone(),
        base_state_sequence: lease.base_state_sequence,
        writer_lease_digest: lease.writer_lease_digest.clone(),
        writer_fence: lease.writer_fence,
        lease_issued_at_unix: lease.issued_at_unix,
        lease_lineage_digest: private_oram_mutation_lease_lineage_digest_v2(lease)?,
        descriptor_digest: descriptor.descriptor_digest.clone(),
        history,
        watermark_digest: String::new(),
    };
    candidate.watermark_digest = private_oram_mutation_parent_watermark_digest_v2(&candidate)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(&candidate)?;
    Ok(PrivateOramMutationParentWatermarkExpectationV2 {
        watermark: candidate,
    })
}

#[cfg(test)]
pub(crate) fn private_oram_mutation_parent_watermark_expectation_for_test(
    lease: &PrivateOramMutationLease,
    descriptor_digest: String,
    record_digests: Vec<String>,
) -> Result<PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationJournalError> {
    let mut history = Vec::with_capacity(record_digests.len());
    for (index, record_digest) in record_digests.into_iter().enumerate() {
        let sequence = u64::try_from(index)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .checked_add(1)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let phase = PrivateOramMutationJournalPhaseV2::from_sequence(sequence)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        history.push(PrivateOramMutationParentWatermarkEntryV2 {
            sequence,
            phase,
            record_digest,
        });
    }
    let mut candidate = PrivateOramMutationParentWatermarkV2 {
        version: PRIVATE_ORAM_MUTATION_PARENT_WATERMARK_VERSION,
        collection_id_digest: private_oram_collection_id_digest_v2(&lease.collection_id)?,
        lease_generation: lease.generation,
        owner_peer_id: lease.owner_peer_id,
        mutation_id: lease.mutation_id.clone(),
        signed_mutation_digest: lease.signed_mutation_digest.clone(),
        transition_digest: lease.transition_digest.clone(),
        base_record_digest: lease.base_record_digest.clone(),
        base_state_sequence: lease.base_state_sequence,
        writer_lease_digest: lease.writer_lease_digest.clone(),
        writer_fence: lease.writer_fence,
        lease_issued_at_unix: lease.issued_at_unix,
        lease_lineage_digest: private_oram_mutation_lease_lineage_digest_v2(lease)?,
        descriptor_digest,
        history,
        watermark_digest: String::new(),
    };
    candidate.watermark_digest = private_oram_mutation_parent_watermark_digest_v2(&candidate)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(&candidate)?;
    Ok(PrivateOramMutationParentWatermarkExpectationV2 {
        watermark: candidate,
    })
}

pub(crate) fn validate_private_oram_mutation_parent_watermark_v2_shape(
    watermark: &PrivateOramMutationParentWatermarkV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if watermark.version != PRIVATE_ORAM_MUTATION_PARENT_WATERMARK_VERSION
        || watermark.lease_generation == 0
        || watermark.lease_issued_at_unix == 0
        || watermark.history.is_empty()
        || watermark.history.len() > MAX_PARENT_WATERMARK_ENTRIES
        || !is_digest(&watermark.collection_id_digest)
        || !is_digest(&watermark.mutation_id)
        || !is_digest(&watermark.signed_mutation_digest)
        || !is_digest(&watermark.transition_digest)
        || !is_digest(&watermark.base_record_digest)
        || !is_digest(&watermark.writer_lease_digest)
        || !is_digest(&watermark.lease_lineage_digest)
        || !is_digest(&watermark.descriptor_digest)
        || !is_digest(&watermark.watermark_digest)
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    if watermark.lease_lineage_digest
        != private_oram_mutation_lease_lineage_digest_from_parts_v2(
            watermark.lease_generation,
            &watermark.collection_id_digest,
            watermark.owner_peer_id,
            &watermark.mutation_id,
            &watermark.signed_mutation_digest,
            &watermark.transition_digest,
            &watermark.base_record_digest,
            watermark.base_state_sequence,
            &watermark.writer_lease_digest,
            watermark.writer_fence,
            watermark.lease_issued_at_unix,
        )?
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    for (offset, entry) in watermark.history.iter().enumerate() {
        let sequence = u64::try_from(offset)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .checked_add(1)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if entry.sequence != sequence
            || entry.phase.sequence() != sequence
            || !is_digest(&entry.record_digest)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
    }
    if watermark.watermark_digest != private_oram_mutation_parent_watermark_digest_v2(watermark)? {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(())
}

/// Accepts an exact replay or one appended phase that exactly matches a validated journal snapshot.
pub(crate) fn validate_private_oram_mutation_parent_watermark_v2_cas_transition(
    current: &PrivateOramMutationParentWatermarkV2,
    incoming: &PrivateOramMutationParentWatermarkV2,
    expected: &PrivateOramMutationParentWatermarkExpectationV2,
) -> Result<(), PrivateOramMutationJournalError> {
    validate_private_oram_mutation_parent_watermark_v2_shape(current)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(incoming)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(expected.watermark())?;
    if incoming != expected.watermark()
        || !current.has_same_identity(incoming)
        || !incoming.history.starts_with(&current.history)
        || !(incoming.history.len() == current.history.len()
            || incoming.history.len() == current.history.len() + 1)
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

pub(crate) fn private_oram_mutation_parent_watermark_is_canonical_prefix_v2(
    candidate: &PrivateOramMutationParentWatermarkV2,
    current: &PrivateOramMutationParentWatermarkV2,
) -> Result<bool, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_parent_watermark_v2_shape(candidate)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(current)?;
    Ok(candidate.has_same_identity(current)
        && candidate.history.len() <= current.history.len()
        && current.history.starts_with(&candidate.history))
}

/// Allows a snapshot to carry a later prefix only when a validated local journal expects it.
/// Bootstrap from no watermark remains unavailable until an external authority anchor exists.
pub(crate) fn validate_private_oram_mutation_parent_watermark_v2_snapshot_transition(
    current: Option<&PrivateOramMutationParentWatermarkV2>,
    incoming: Option<&PrivateOramMutationParentWatermarkV2>,
    expected: Option<&PrivateOramMutationParentWatermarkExpectationV2>,
) -> Result<(), PrivateOramMutationJournalError> {
    match (current, incoming, expected) {
        (None, None, None) => Ok(()),
        (Some(current), Some(incoming), Some(expected)) => {
            validate_private_oram_mutation_parent_watermark_v2_shape(current)?;
            validate_private_oram_mutation_parent_watermark_v2_shape(incoming)?;
            validate_private_oram_mutation_parent_watermark_v2_shape(expected.watermark())?;
            if incoming != expected.watermark()
                || !current.has_same_identity(incoming)
                || !incoming.history.starts_with(&current.history)
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            Ok(())
        }
        _ => Err(PrivateOramMutationJournalError::InvalidTransition),
    }
}

fn deserialize_parent_watermark_history<'de, D>(
    deserializer: D,
) -> Result<Vec<PrivateOramMutationParentWatermarkEntryV2>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedHistoryVisitor;

    impl<'de> Visitor<'de> for BoundedHistoryVisitor {
        type Value = Vec<PrivateOramMutationParentWatermarkEntryV2>;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_PARENT_WATERMARK_ENTRIES} private ORAM mutation watermark entries"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|size| size > MAX_PARENT_WATERMARK_ENTRIES)
            {
                return Err(de::Error::custom(
                    "private ORAM watermark history is oversized",
                ));
            }
            let mut history = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_PARENT_WATERMARK_ENTRIES),
            );
            while history.len() < MAX_PARENT_WATERMARK_ENTRIES {
                let Some(entry) = sequence.next_element()? else {
                    return Ok(history);
                };
                history.push(entry);
            }
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(de::Error::custom(
                    "private ORAM watermark history is oversized",
                ));
            }
            Ok(history)
        }
    }

    deserializer.deserialize_seq(BoundedHistoryVisitor)
}

fn private_oram_mutation_parent_watermark_digest_v2(
    watermark: &PrivateOramMutationParentWatermarkV2,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(PARENT_WATERMARK_DIGEST_DOMAIN_V2);
    hasher.update(watermark.version.to_be_bytes());
    hash_digest(&mut hasher, &watermark.collection_id_digest)?;
    hasher.update(watermark.lease_generation.to_be_bytes());
    hasher.update(watermark.owner_peer_id.to_be_bytes());
    hash_digest(&mut hasher, &watermark.mutation_id)?;
    hash_digest(&mut hasher, &watermark.signed_mutation_digest)?;
    hash_digest(&mut hasher, &watermark.transition_digest)?;
    hash_digest(&mut hasher, &watermark.base_record_digest)?;
    hasher.update(watermark.base_state_sequence.to_be_bytes());
    hash_digest(&mut hasher, &watermark.writer_lease_digest)?;
    hasher.update(watermark.writer_fence.to_be_bytes());
    hasher.update(watermark.lease_issued_at_unix.to_be_bytes());
    hash_digest(&mut hasher, &watermark.lease_lineage_digest)?;
    hash_digest(&mut hasher, &watermark.descriptor_digest)?;
    hasher.update(
        u64::try_from(watermark.history.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    for entry in &watermark.history {
        hasher.update(entry.sequence.to_be_bytes());
        hasher.update([entry.phase.sequence() as u8]);
        hash_digest(&mut hasher, &entry.record_digest)?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(crate) fn private_oram_mutation_lease_lineage_digest_v2(
    lease: &PrivateOramMutationLease,
) -> Result<String, PrivateOramMutationJournalError> {
    if lease.generation == 0 || lease.writer_fence == 0 || lease.issued_at_unix == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    private_oram_mutation_lease_lineage_digest_from_parts_v2(
        lease.generation,
        &private_oram_collection_id_digest_v2(&lease.collection_id)?,
        lease.owner_peer_id,
        &lease.mutation_id,
        &lease.signed_mutation_digest,
        &lease.transition_digest,
        &lease.base_record_digest,
        lease.base_state_sequence,
        &lease.writer_lease_digest,
        lease.writer_fence,
        lease.issued_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_oram_mutation_lease_lineage_digest_from_parts_v2(
    generation: u64,
    collection_id_digest: &str,
    owner_peer_id: PeerId,
    mutation_id: &str,
    signed_mutation_digest: &str,
    transition_digest: &str,
    base_record_digest: &str,
    base_state_sequence: u64,
    writer_lease_digest: &str,
    writer_fence: u64,
    issued_at_unix: u64,
) -> Result<String, PrivateOramMutationJournalError> {
    if generation == 0 || writer_fence == 0 || issued_at_unix == 0 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut hasher = Sha256::new();
    hasher.update(MUTATION_LEASE_LINEAGE_DIGEST_DOMAIN_V2);
    hasher.update(generation.to_be_bytes());
    hash_digest(&mut hasher, collection_id_digest)?;
    hasher.update(owner_peer_id.to_be_bytes());
    hash_digest(&mut hasher, mutation_id)?;
    hash_digest(&mut hasher, signed_mutation_digest)?;
    hash_digest(&mut hasher, transition_digest)?;
    hash_digest(&mut hasher, base_record_digest)?;
    hasher.update(base_state_sequence.to_be_bytes());
    hash_digest(&mut hasher, writer_lease_digest)?;
    hasher.update(writer_fence.to_be_bytes());
    hasher.update(issued_at_unix.to_be_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn hash_digest(hasher: &mut Sha256, value: &str) -> Result<(), PrivateOramMutationJournalError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    hasher.update(decoded);
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 43
        && BASE64URL_NOPAD
            .decode(value.as_bytes())
            .is_ok_and(|decoded| decoded.len() == 32 && BASE64URL_NOPAD.encode(&decoded) == value)
}

#[cfg(test)]
pub(crate) fn replace_private_oram_mutation_parent_watermark_record_for_test(
    mut watermark: PrivateOramMutationParentWatermarkV2,
    sequence: u64,
    record_digest: String,
) -> Result<PrivateOramMutationParentWatermarkV2, PrivateOramMutationJournalError> {
    let index = usize::try_from(
        sequence
            .checked_sub(1)
            .ok_or(PrivateOramMutationJournalError::Corrupt)?,
    )
    .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    watermark
        .history
        .get_mut(index)
        .ok_or(PrivateOramMutationJournalError::Corrupt)?
        .record_digest = record_digest;
    watermark.watermark_digest = private_oram_mutation_parent_watermark_digest_v2(&watermark)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(&watermark)?;
    Ok(watermark)
}

fn truncate_private_oram_mutation_parent_watermark_expectation_v2(
    expected: &PrivateOramMutationParentWatermarkExpectationV2,
    sequence: u64,
) -> Result<PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationJournalError> {
    let sequence =
        usize::try_from(sequence).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if sequence == 0 || sequence > expected.watermark.history.len() {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    let mut watermark = expected.watermark.clone();
    watermark.history.truncate(sequence);
    watermark.watermark_digest = private_oram_mutation_parent_watermark_digest_v2(&watermark)?;
    validate_private_oram_mutation_parent_watermark_v2_shape(&watermark)?;
    Ok(PrivateOramMutationParentWatermarkExpectationV2 { watermark })
}

#[cfg(test)]
pub(crate) fn truncate_private_oram_mutation_parent_watermark_expectation_for_test(
    expected: &PrivateOramMutationParentWatermarkExpectationV2,
    sequence: u64,
) -> Result<PrivateOramMutationParentWatermarkExpectationV2, PrivateOramMutationJournalError> {
    truncate_private_oram_mutation_parent_watermark_expectation_v2(expected, sequence)
}
