//! Append reservation wire envelope bound to retained owner checkpoints.

#![cfg_attr(not(test), allow(dead_code))]

use std::fmt::{self, Debug, Formatter};
use std::ops::Deref;

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::private_oram_mutation_protocol_capability_digest_v2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::owner_checkpoint::{
    PrivateOramOwnerCheckpointReservationBindingV1, PrivateOramOwnerCheckpointReservationContextV1,
    validate_private_oram_owner_checkpoint_binding_context_v1,
    validate_private_oram_owner_checkpoint_reservation_context_v1,
};
use super::{PrivateOramRaftApplyLocatorV2, validate_apply_locator_v2};
use crate::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1;
use crate::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationAllOwnersPrestagedV2, PrivateOramMutationAppendReservationV2,
    PrivateOramMutationJournalError, decode_private_oram_mutation_append_reservation_v2,
    private_oram_mutation_append_prepared_request_digest_v2,
    private_oram_mutation_reserved_rejection_request_digest_v2,
    validate_private_oram_mutation_append_reservation_manifest_v2,
    validate_private_oram_mutation_append_reservation_v2,
};
use crate::content_manager::private_oram_mutation_state_v2::private_oram_collection_id_digest_v2;

const APPEND_RESERVATION_VERSION_V3: u16 = 3;
const RESERVATION_INTENT_VERSION_V3: u16 = 1;
const PREPARED_RESERVATION_CHALLENGE_VERSION_V3: u16 = 1;
const APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V3: usize = 8 * 1024 * 1024;
const APPEND_RESERVATION_DIGEST_DOMAIN_V3: &[u8] =
    b"qdrant-sec/private-oram-mutation-append-reservation/v3";
const RESERVATION_INTENT_DIGEST_DOMAIN_V3: &[u8] =
    b"qdrant-sec/private-oram-mutation-reservation-intent/v3";
const APPEND_PREPARED_REQUEST_DIGEST_DOMAIN_V3: &[u8] =
    b"qdrant-sec/private-oram-mutation-append-prepared-request/v3";
const RESERVED_REJECTION_REQUEST_DIGEST_DOMAIN_V3: &[u8] =
    b"qdrant-sec/private-oram-mutation-reserved-rejection-request/v3";
const PREPARED_RESERVATION_CHALLENGE_DIGEST_DOMAIN_V3: &[u8] =
    b"qdrant-sec/private-oram-mutation-prepared-reservation-challenge/v3";
const OWNER_CHALLENGE_NONCE_BYTES: usize = 16;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationReservationIntentV3 {
    version: u16,
    base_reservation_digest: String,
    current_protocol_capability_digest: String,
    expected_aggregate_digest: String,
    consensus_history_id_digest: String,
    raft_group_id_digest: String,
    collection_key_digest: String,
    collection_lifetime_id_digest: String,
    collection_incarnation_digest: String,
    activation_anchor_digest: String,
    activation_authority: PrivateOramActivationAuthorityLocatorV1,
    controller_id: String,
    controller_peer_id: u64,
    controller_term: u64,
    attempt_id: String,
    attempt_sequence: u64,
    owner_prestage_roster_digest: String,
    intent_digest: String,
}

impl Debug for PrivateOramMutationReservationIntentV3 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationReservationIntentV3")
            .field("version", &self.version)
            .field("controller_peer_id", &self.controller_peer_id)
            .field("controller_term", &self.controller_term)
            .field("attempt_sequence", &self.attempt_sequence)
            .field("base_reservation_digest", &"[redacted]")
            .field("attempt_id", &"[redacted]")
            .field("owner_prestage_roster_digest", &"[redacted]")
            .field("intent_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationReservationIntentV3 {
    pub(crate) fn intent_digest(&self) -> &str {
        &self.intent_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationPreparedReservationChallengeV3 {
    version: u16,
    base_reservation: PrivateOramMutationAppendReservationV2,
    reservation_intent: PrivateOramMutationReservationIntentV3,
    checkpoint_context: PrivateOramOwnerCheckpointReservationContextV1,
    owner_challenge_nonces: Vec<String>,
    prepared_challenge_digest: String,
}

impl Debug for PrivateOramMutationPreparedReservationChallengeV3 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationPreparedReservationChallengeV3")
            .field("version", &self.version)
            .field("owner_count", &self.owner_challenge_nonces.len())
            .field("base_reservation", &self.base_reservation)
            .field("reservation_intent", &self.reservation_intent)
            .field("checkpoint_context", &self.checkpoint_context)
            .field("owner_challenge_nonces", &"[redacted]")
            .field("prepared_challenge_digest", &"[redacted]")
            .finish()
    }
}

impl PrivateOramMutationPreparedReservationChallengeV3 {
    pub(crate) fn base_reservation(&self) -> &PrivateOramMutationAppendReservationV2 {
        &self.base_reservation
    }

    pub(crate) fn reservation_intent(&self) -> &PrivateOramMutationReservationIntentV3 {
        &self.reservation_intent
    }

    pub(crate) fn checkpoint_context(&self) -> &PrivateOramOwnerCheckpointReservationContextV1 {
        &self.checkpoint_context
    }

    pub(crate) fn owner_challenge_nonces(&self) -> &[String] {
        &self.owner_challenge_nonces
    }

    pub(crate) fn prepared_challenge_digest(&self) -> &str {
        &self.prepared_challenge_digest
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrivateOramMutationAppendReservationV3 {
    version: u16,
    base_reservation: PrivateOramMutationAppendReservationV2,
    reservation_intent: PrivateOramMutationReservationIntentV3,
    checkpoint_context: PrivateOramOwnerCheckpointReservationContextV1,
    prepared_challenge: PrivateOramMutationPreparedReservationChallengeV3,
    challenge_applied: PrivateOramRaftApplyLocatorV2,
    checkpoint_bindings: Vec<PrivateOramOwnerCheckpointReservationBindingV1>,
    reservation_digest: String,
}

impl Debug for PrivateOramMutationAppendReservationV3 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateOramMutationAppendReservationV3")
            .field("version", &self.version)
            .field("base_reservation", &self.base_reservation)
            .field("reservation_intent", &self.reservation_intent)
            .field("checkpoint_context", &self.checkpoint_context)
            .field("prepared_challenge", &self.prepared_challenge)
            .field("challenge_applied", &self.challenge_applied)
            .field("checkpoint_binding_count", &self.checkpoint_bindings.len())
            .field("reservation_digest", &"[redacted]")
            .finish()
    }
}

impl Deref for PrivateOramMutationAppendReservationV3 {
    type Target = PrivateOramMutationAppendReservationV2;

    fn deref(&self) -> &Self::Target {
        &self.base_reservation
    }
}

impl PrivateOramMutationAppendReservationV3 {
    pub(crate) fn base_reservation(&self) -> &PrivateOramMutationAppendReservationV2 {
        &self.base_reservation
    }

    pub(crate) fn checkpoint_context(&self) -> &PrivateOramOwnerCheckpointReservationContextV1 {
        &self.checkpoint_context
    }

    pub(crate) fn reservation_intent(&self) -> &PrivateOramMutationReservationIntentV3 {
        &self.reservation_intent
    }

    pub(crate) fn prepared_challenge(&self) -> &PrivateOramMutationPreparedReservationChallengeV3 {
        &self.prepared_challenge
    }

    pub(crate) fn challenge_applied(&self) -> &PrivateOramRaftApplyLocatorV2 {
        &self.challenge_applied
    }

    pub(crate) fn checkpoint_bindings(&self) -> &[PrivateOramOwnerCheckpointReservationBindingV1] {
        &self.checkpoint_bindings
    }

    pub(crate) fn reservation_digest_v3(&self) -> &str {
        &self.reservation_digest
    }
}

pub(crate) enum DecodedPrivateOramMutationAppendReservation {
    HistoricalV2(PrivateOramMutationAppendReservationV2),
    CheckpointBoundV3(PrivateOramMutationAppendReservationV3),
}

impl DecodedPrivateOramMutationAppendReservation {
    pub(crate) fn base_reservation(&self) -> &PrivateOramMutationAppendReservationV2 {
        match self {
            Self::HistoricalV2(reservation) => reservation,
            Self::CheckpointBoundV3(reservation) => reservation.base_reservation(),
        }
    }

    pub(crate) fn reservation_digest(&self) -> &str {
        match self {
            Self::HistoricalV2(reservation) => reservation.reservation_digest(),
            Self::CheckpointBoundV3(reservation) => reservation.reservation_digest_v3(),
        }
    }

    pub(crate) fn checkpoint_bound_v3(&self) -> Option<&PrivateOramMutationAppendReservationV3> {
        match self {
            Self::HistoricalV2(_) => None,
            Self::CheckpointBoundV3(reservation) => Some(reservation),
        }
    }

    pub(crate) fn validate_manifest(
        &self,
        manifest: &PrivateOramMutationAllOwnersPrestagedV2,
    ) -> Result<(), PrivateOramMutationJournalError> {
        validate_private_oram_mutation_append_reservation_manifest_v2(
            self.base_reservation(),
            manifest,
        )
    }

    pub(crate) fn append_prepared_request_digest(
        &self,
        manifest: &PrivateOramMutationAllOwnersPrestagedV2,
    ) -> Result<String, PrivateOramMutationJournalError> {
        let base_digest = private_oram_mutation_append_prepared_request_digest_v2(
            self.base_reservation(),
            manifest,
        )?;
        match self {
            Self::HistoricalV2(_) => Ok(base_digest),
            Self::CheckpointBoundV3(reservation) => digest_pair(
                APPEND_PREPARED_REQUEST_DIGEST_DOMAIN_V3,
                reservation.reservation_digest_v3(),
                &base_digest,
            ),
        }
    }

    pub(crate) fn reserved_rejection_request_digest(
        &self,
    ) -> Result<String, PrivateOramMutationJournalError> {
        let base_digest =
            private_oram_mutation_reserved_rejection_request_digest_v2(self.base_reservation())?;
        match self {
            Self::HistoricalV2(_) => Ok(base_digest),
            Self::CheckpointBoundV3(reservation) => digest_pair(
                RESERVED_REJECTION_REQUEST_DIGEST_DOMAIN_V3,
                reservation.reservation_digest_v3(),
                &base_digest,
            ),
        }
    }
}

pub(crate) fn private_oram_mutation_reservation_intent_v3(
    base_reservation: &PrivateOramMutationAppendReservationV2,
) -> Result<PrivateOramMutationReservationIntentV3, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_append_reservation_v2(base_reservation)?;
    let mut intent = PrivateOramMutationReservationIntentV3 {
        version: RESERVATION_INTENT_VERSION_V3,
        base_reservation_digest: base_reservation.reservation_digest().to_string(),
        current_protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
        expected_aggregate_digest: base_reservation.expected_aggregate_digest().to_string(),
        consensus_history_id_digest: base_reservation.consensus_history_id_digest().to_string(),
        raft_group_id_digest: base_reservation.raft_group_id_digest().to_string(),
        collection_key_digest: private_oram_collection_id_digest_v2(
            base_reservation.collection_id(),
        )?,
        collection_lifetime_id_digest: base_reservation.collection_lifetime_id_digest().to_string(),
        collection_incarnation_digest: base_reservation.collection_incarnation_digest().to_string(),
        activation_anchor_digest: base_reservation.activation_anchor_digest().to_string(),
        activation_authority: base_reservation.activation_authority().clone(),
        controller_id: base_reservation.controller_id().to_string(),
        controller_peer_id: base_reservation.controller_peer_id(),
        controller_term: base_reservation.controller_term(),
        attempt_id: base_reservation.attempt_id().to_string(),
        attempt_sequence: base_reservation.attempt_sequence(),
        owner_prestage_roster_digest: base_reservation.owner_roster_digest().to_string(),
        intent_digest: String::new(),
    };
    intent.intent_digest = reservation_intent_digest_v3(&intent)?;
    validate_private_oram_mutation_reservation_intent_v3(&intent)?;
    Ok(intent)
}

fn validate_private_oram_mutation_reservation_intent_v3(
    intent: &PrivateOramMutationReservationIntentV3,
) -> Result<(), PrivateOramMutationJournalError> {
    if intent.version != RESERVATION_INTENT_VERSION_V3
        || intent.current_protocol_capability_digest
            != private_oram_mutation_protocol_capability_digest_v2()
        || intent.controller_peer_id == 0
        || intent.controller_term == 0
        || intent.attempt_sequence == 0
        || intent.activation_authority.registry_generation() == 0
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "reservation_intent_v3",
        ));
    }
    for digest in [
        &intent.base_reservation_digest,
        &intent.current_protocol_capability_digest,
        &intent.expected_aggregate_digest,
        &intent.consensus_history_id_digest,
        &intent.raft_group_id_digest,
        &intent.collection_key_digest,
        &intent.collection_lifetime_id_digest,
        &intent.collection_incarnation_digest,
        &intent.activation_anchor_digest,
        intent.activation_authority.manifest_digest(),
        &intent.controller_id,
        &intent.attempt_id,
        &intent.owner_prestage_roster_digest,
        &intent.intent_digest,
    ] {
        validate_digest_value(digest)?;
    }
    if intent.intent_digest != reservation_intent_digest_v3(intent)? {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "reservation_intent_v3",
        ));
    }
    Ok(())
}

pub(crate) fn private_oram_mutation_prepared_reservation_challenge_v3(
    base_reservation: PrivateOramMutationAppendReservationV2,
    reservation_intent: PrivateOramMutationReservationIntentV3,
    checkpoint_context: PrivateOramOwnerCheckpointReservationContextV1,
    owner_challenge_nonces: Vec<String>,
) -> Result<PrivateOramMutationPreparedReservationChallengeV3, PrivateOramMutationJournalError> {
    let mut challenge = PrivateOramMutationPreparedReservationChallengeV3 {
        version: PREPARED_RESERVATION_CHALLENGE_VERSION_V3,
        base_reservation,
        reservation_intent,
        checkpoint_context,
        owner_challenge_nonces,
        prepared_challenge_digest: String::new(),
    };
    challenge.prepared_challenge_digest = prepared_reservation_challenge_digest_v3(&challenge)?;
    validate_private_oram_mutation_prepared_reservation_challenge_v3(&challenge)?;
    Ok(challenge)
}

pub(crate) fn encode_private_oram_mutation_prepared_reservation_challenge_v3(
    challenge: &PrivateOramMutationPreparedReservationChallengeV3,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_prepared_reservation_challenge_v3(challenge)?;
    let encoded =
        serde_json::to_string(challenge).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() > APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V3 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "prepared_reservation_challenge_v3",
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode_private_oram_mutation_prepared_reservation_challenge_v3(
    encoded: &str,
) -> Result<PrivateOramMutationPreparedReservationChallengeV3, PrivateOramMutationJournalError> {
    if encoded.is_empty() || encoded.len() > APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V3 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "prepared_reservation_challenge_v3",
        ));
    }
    let challenge: PrivateOramMutationPreparedReservationChallengeV3 =
        serde_json::from_str(encoded).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_private_oram_mutation_prepared_reservation_challenge_v3(&challenge)?;
    if serde_json::to_string(&challenge).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        != encoded
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "prepared_reservation_challenge_v3",
        ));
    }
    Ok(challenge)
}

pub(crate) fn validate_private_oram_mutation_prepared_reservation_challenge_v3(
    challenge: &PrivateOramMutationPreparedReservationChallengeV3,
) -> Result<(), PrivateOramMutationJournalError> {
    if challenge.version != PREPARED_RESERVATION_CHALLENGE_VERSION_V3 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "prepared_reservation_challenge_v3",
        ));
    }
    validate_private_oram_mutation_append_reservation_v2(&challenge.base_reservation)?;
    validate_private_oram_mutation_reservation_intent_v3(&challenge.reservation_intent)?;
    validate_private_oram_owner_checkpoint_reservation_context_v1(&challenge.checkpoint_context)?;
    if challenge.reservation_intent
        != private_oram_mutation_reservation_intent_v3(&challenge.base_reservation)?
        || challenge.checkpoint_context.reservation_intent_digest()
            != challenge.reservation_intent.intent_digest()
        || challenge.checkpoint_context.consensus_history_id_digest()
            != challenge.base_reservation.consensus_history_id_digest()
        || challenge.checkpoint_context.raft_group_id_digest()
            != challenge.base_reservation.raft_group_id_digest()
        || challenge.checkpoint_context.collection_key_digest()
            != private_oram_collection_id_digest_v2(challenge.base_reservation.collection_id())?
        || challenge.checkpoint_context.collection_lifetime_id_digest()
            != challenge.base_reservation.collection_lifetime_id_digest()
        || challenge.checkpoint_context.collection_incarnation_digest()
            != challenge.base_reservation.collection_incarnation_digest()
        || challenge.checkpoint_context.activation_anchor_digest()
            != challenge.base_reservation.activation_anchor_digest()
        || challenge.checkpoint_context.protocol_capability_digest()
            != private_oram_mutation_protocol_capability_digest_v2()
        || challenge.owner_challenge_nonces.len()
            != challenge.base_reservation.owner_targets().len()
        || challenge.owner_challenge_nonces.len()
            != challenge.checkpoint_context.owner_expectations().len()
        || challenge.owner_challenge_nonces.is_empty()
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "prepared_reservation_challenge_v3",
        ));
    }
    for nonce in &challenge.owner_challenge_nonces {
        let bytes = BASE64URL_NOPAD
            .decode(nonce.as_bytes())
            .map_err(|_| PrivateOramMutationJournalError::InvalidInput("owner_challenge_nonce"))?;
        if bytes.len() != OWNER_CHALLENGE_NONCE_BYTES || BASE64URL_NOPAD.encode(&bytes) != *nonce {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "owner_challenge_nonce",
            ));
        }
    }
    if challenge.prepared_challenge_digest != prepared_reservation_challenge_digest_v3(challenge)? {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "prepared_reservation_challenge_v3",
        ));
    }
    Ok(())
}

pub(crate) fn private_oram_mutation_append_reservation_v3(
    base_reservation: PrivateOramMutationAppendReservationV2,
    reservation_intent: PrivateOramMutationReservationIntentV3,
    checkpoint_context: PrivateOramOwnerCheckpointReservationContextV1,
    prepared_challenge: PrivateOramMutationPreparedReservationChallengeV3,
    challenge_applied: PrivateOramRaftApplyLocatorV2,
    checkpoint_bindings: Vec<PrivateOramOwnerCheckpointReservationBindingV1>,
) -> Result<PrivateOramMutationAppendReservationV3, PrivateOramMutationJournalError> {
    let mut reservation = PrivateOramMutationAppendReservationV3 {
        version: APPEND_RESERVATION_VERSION_V3,
        base_reservation,
        reservation_intent,
        checkpoint_context,
        prepared_challenge,
        challenge_applied,
        checkpoint_bindings,
        reservation_digest: String::new(),
    };
    reservation.reservation_digest = append_reservation_digest_v3(&reservation)?;
    validate_private_oram_mutation_append_reservation_v3(&reservation)?;
    Ok(reservation)
}

pub(crate) fn encode_private_oram_mutation_append_reservation_v3(
    reservation: &PrivateOramMutationAppendReservationV3,
) -> Result<String, PrivateOramMutationJournalError> {
    validate_private_oram_mutation_append_reservation_v3(reservation)?;
    let encoded =
        serde_json::to_string(reservation).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() > APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V3 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation_v3",
        ));
    }
    Ok(encoded)
}

pub(crate) fn decode_private_oram_mutation_append_reservation_v3(
    encoded: &str,
) -> Result<PrivateOramMutationAppendReservationV3, PrivateOramMutationJournalError> {
    if encoded.is_empty() || encoded.len() > APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V3 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation_v3",
        ));
    }
    let reservation: PrivateOramMutationAppendReservationV3 =
        serde_json::from_str(encoded).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    validate_private_oram_mutation_append_reservation_v3(&reservation)?;
    if serde_json::to_string(&reservation).map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        != encoded
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation_v3",
        ));
    }
    Ok(reservation)
}

pub(crate) fn decode_private_oram_mutation_append_reservation_wire(
    encoded: &str,
) -> Result<DecodedPrivateOramMutationAppendReservation, PrivateOramMutationJournalError> {
    if encoded.is_empty() || encoded.len() > APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V3 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation_wire",
        ));
    }
    let value: serde_json::Value =
        serde_json::from_str(encoded).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let version = value
        .as_object()
        .and_then(|object| object.get("version"))
        .and_then(serde_json::Value::as_u64)
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    match version {
        2 => decode_private_oram_mutation_append_reservation_v2(encoded)
            .map(DecodedPrivateOramMutationAppendReservation::HistoricalV2),
        3 => decode_private_oram_mutation_append_reservation_v3(encoded)
            .map(DecodedPrivateOramMutationAppendReservation::CheckpointBoundV3),
        _ => Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation_wire",
        )),
    }
}

pub(crate) fn validate_private_oram_mutation_append_reservation_v3(
    reservation: &PrivateOramMutationAppendReservationV3,
) -> Result<(), PrivateOramMutationJournalError> {
    if reservation.version != APPEND_RESERVATION_VERSION_V3 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation_v3",
        ));
    }
    validate_private_oram_mutation_append_reservation_v2(&reservation.base_reservation)?;
    validate_private_oram_mutation_reservation_intent_v3(&reservation.reservation_intent)?;
    validate_private_oram_mutation_prepared_reservation_challenge_v3(
        &reservation.prepared_challenge,
    )?;
    validate_apply_locator_v2(&reservation.challenge_applied)?;
    let expected_intent =
        private_oram_mutation_reservation_intent_v3(&reservation.base_reservation)?;
    validate_private_oram_owner_checkpoint_reservation_context_v1(&reservation.checkpoint_context)?;
    if reservation.reservation_intent != expected_intent
        || reservation.checkpoint_context.reservation_intent_digest()
            != reservation.reservation_intent.intent_digest()
        || reservation.checkpoint_context.consensus_history_id_digest()
            != reservation.base_reservation.consensus_history_id_digest()
        || reservation.checkpoint_context.raft_group_id_digest()
            != reservation.base_reservation.raft_group_id_digest()
        || reservation.checkpoint_context.collection_key_digest()
            != private_oram_collection_id_digest_v2(reservation.base_reservation.collection_id())?
        || reservation
            .checkpoint_context
            .collection_lifetime_id_digest()
            != reservation.base_reservation.collection_lifetime_id_digest()
        || reservation
            .checkpoint_context
            .collection_incarnation_digest()
            != reservation.base_reservation.collection_incarnation_digest()
        || reservation.checkpoint_context.activation_anchor_digest()
            != reservation.base_reservation.activation_anchor_digest()
        || reservation.checkpoint_context.protocol_capability_digest()
            != private_oram_mutation_protocol_capability_digest_v2()
        || reservation.prepared_challenge.base_reservation != reservation.base_reservation
        || reservation.prepared_challenge.reservation_intent != reservation.reservation_intent
        || reservation.prepared_challenge.checkpoint_context != reservation.checkpoint_context
        || reservation.challenge_applied.consensus_history_id_digest
            != reservation.base_reservation.consensus_history_id_digest()
        || reservation.challenge_applied.raft_group_id_digest
            != reservation.base_reservation.raft_group_id_digest()
        || reservation.checkpoint_bindings.len()
            != reservation.checkpoint_context.owner_expectations().len()
        || reservation.checkpoint_bindings.len()
            != reservation.base_reservation.owner_targets().len()
    {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation_v3",
        ));
    }
    for (position, ((target, expectation), binding)) in reservation
        .base_reservation
        .owner_targets()
        .iter()
        .zip(reservation.checkpoint_context.owner_expectations())
        .zip(&reservation.checkpoint_bindings)
        .enumerate()
    {
        validate_private_oram_owner_checkpoint_binding_context_v1(
            &reservation.checkpoint_context,
            binding,
        )?;
        if target.owner_index() != binding.owner_index()
            || target.owner_peer_id() != expectation.owner_peer_id()
            || binding.owner_enrollment_id()
                != binding.reservation_prepare().challenge.owner_enrollment_id
            || binding.reservation_prepare().challenge.attempt_id
                != reservation.base_reservation.attempt_id()
            || binding
                .reservation_prepare()
                .challenge
                .committed_challenge_digest
                != reservation.prepared_challenge.prepared_challenge_digest
            || binding
                .reservation_prepare()
                .challenge
                .challenge_applied_term
                != reservation.challenge_applied.term
            || binding
                .reservation_prepare()
                .challenge
                .challenge_applied_index
                != reservation.challenge_applied.index
            || binding.reservation_prepare().challenge.challenge_nonce
                != reservation.prepared_challenge.owner_challenge_nonces[position]
            || binding
                .reservation_prepare()
                .challenge
                .reservation_intent_digest
                != reservation.reservation_intent.intent_digest
            || binding
                .reservation_prepare()
                .challenge
                .checkpoint_context_digest
                != reservation.checkpoint_context.context_digest()
            || binding
                .reservation_prepare()
                .challenge
                .expected_owner_target_digest
                != target.target_digest()
            || binding
                .reservation_prepare()
                .challenge
                .reserved_terminal_intent_key
                != target.intent_key()
            || usize::try_from(binding.reservation_prepare().challenge.owner_count).ok()
                != Some(reservation.checkpoint_bindings.len())
        {
            return Err(PrivateOramMutationJournalError::InvalidInput(
                "append_reservation_v3",
            ));
        }
    }
    if reservation.reservation_digest != append_reservation_digest_v3(reservation)? {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation_v3",
        ));
    }
    let encoded =
        serde_json::to_vec(reservation).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if encoded.is_empty() || encoded.len() > APPEND_RESERVATION_MAX_CANONICAL_JSON_BYTES_V3 {
        return Err(PrivateOramMutationJournalError::InvalidInput(
            "append_reservation_v3",
        ));
    }
    Ok(())
}

fn append_reservation_digest_v3(
    reservation: &PrivateOramMutationAppendReservationV3,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(APPEND_RESERVATION_DIGEST_DOMAIN_V3);
    hasher.update(reservation.version.to_be_bytes());
    hash_digest(
        &mut hasher,
        reservation.base_reservation.reservation_digest(),
    )?;
    hash_digest(&mut hasher, reservation.reservation_intent.intent_digest())?;
    hash_digest(&mut hasher, reservation.checkpoint_context.context_digest())?;
    hash_digest(
        &mut hasher,
        reservation.prepared_challenge.prepared_challenge_digest(),
    )?;
    hash_digest(
        &mut hasher,
        &reservation.challenge_applied.consensus_history_id_digest,
    )?;
    hash_digest(
        &mut hasher,
        &reservation.challenge_applied.raft_group_id_digest,
    )?;
    hasher.update(reservation.challenge_applied.term.to_be_bytes());
    hasher.update(reservation.challenge_applied.index.to_be_bytes());
    let count = u64::try_from(reservation.checkpoint_bindings.len())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    hasher.update(count.to_be_bytes());
    for binding in &reservation.checkpoint_bindings {
        hash_digest(&mut hasher, binding.binding_digest())?;
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn reservation_intent_digest_v3(
    intent: &PrivateOramMutationReservationIntentV3,
) -> Result<String, PrivateOramMutationJournalError> {
    #[derive(Serialize)]
    struct ReservationIntentDigestInput<'a> {
        version: u16,
        base_reservation_digest: &'a str,
        current_protocol_capability_digest: &'a str,
        expected_aggregate_digest: &'a str,
        consensus_history_id_digest: &'a str,
        raft_group_id_digest: &'a str,
        collection_key_digest: &'a str,
        collection_lifetime_id_digest: &'a str,
        collection_incarnation_digest: &'a str,
        activation_anchor_digest: &'a str,
        activation_authority: &'a PrivateOramActivationAuthorityLocatorV1,
        controller_id: &'a str,
        controller_peer_id: u64,
        controller_term: u64,
        attempt_id: &'a str,
        attempt_sequence: u64,
        owner_prestage_roster_digest: &'a str,
    }

    let encoded = serde_json::to_vec(&ReservationIntentDigestInput {
        version: intent.version,
        base_reservation_digest: &intent.base_reservation_digest,
        current_protocol_capability_digest: &intent.current_protocol_capability_digest,
        expected_aggregate_digest: &intent.expected_aggregate_digest,
        consensus_history_id_digest: &intent.consensus_history_id_digest,
        raft_group_id_digest: &intent.raft_group_id_digest,
        collection_key_digest: &intent.collection_key_digest,
        collection_lifetime_id_digest: &intent.collection_lifetime_id_digest,
        collection_incarnation_digest: &intent.collection_incarnation_digest,
        activation_anchor_digest: &intent.activation_anchor_digest,
        activation_authority: &intent.activation_authority,
        controller_id: &intent.controller_id,
        controller_peer_id: intent.controller_peer_id,
        controller_term: intent.controller_term,
        attempt_id: &intent.attempt_id,
        attempt_sequence: intent.attempt_sequence,
        owner_prestage_roster_digest: &intent.owner_prestage_roster_digest,
    })
    .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    let mut hasher = Sha256::new();
    hasher.update(RESERVATION_INTENT_DIGEST_DOMAIN_V3);
    hasher.update(
        u64::try_from(encoded.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    hasher.update(encoded);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn prepared_reservation_challenge_digest_v3(
    challenge: &PrivateOramMutationPreparedReservationChallengeV3,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_RESERVATION_CHALLENGE_DIGEST_DOMAIN_V3);
    hasher.update(challenge.version.to_be_bytes());
    hash_digest(&mut hasher, challenge.base_reservation.reservation_digest())?;
    hash_digest(&mut hasher, challenge.reservation_intent.intent_digest())?;
    hash_digest(&mut hasher, challenge.checkpoint_context.context_digest())?;
    hasher.update(
        u64::try_from(challenge.owner_challenge_nonces.len())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
            .to_be_bytes(),
    );
    for nonce in &challenge.owner_challenge_nonces {
        let bytes = BASE64URL_NOPAD
            .decode(nonce.as_bytes())
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        if bytes.len() != OWNER_CHALLENGE_NONCE_BYTES {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        hasher.update(bytes);
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn hash_digest(hasher: &mut Sha256, digest: &str) -> Result<(), PrivateOramMutationJournalError> {
    let bytes = BASE64URL_NOPAD
        .decode(digest.as_bytes())
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
    if bytes.len() != 32 {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    hasher.update(bytes);
    Ok(())
}

fn validate_digest_value(digest: &str) -> Result<(), PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hash_digest(&mut hasher, digest)
}

fn digest_pair(
    domain: &[u8],
    left: &str,
    right: &str,
) -> Result<String, PrivateOramMutationJournalError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hash_digest(&mut hasher, left)?;
    hash_digest(&mut hasher, right)?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use qdrant_sec::{
        PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1, PrivateOramOwnerEnrollmentPreparedV1,
        PrivateOramOwnerReservationPrepareChallengeV1, prepare_private_oram_owner_enrollment_v1,
        private_oram_mutation_protocol_capability_digest_v2, private_oram_owner_cleanup_signer_v1,
        private_oram_owner_lifecycle_genesis_state_v1,
        sign_private_oram_owner_enrollment_genesis_commitment_v1,
        sign_private_oram_owner_reservation_prepare_v1,
    };
    use ring::signature::Ed25519KeyPair;

    use super::*;
    use crate::content_manager::consensus::private_oram_activation_authority::PrivateOramActivationAuthorityLocatorV1;
    use crate::content_manager::consensus::private_oram_mutation_cleanup::owner_checkpoint::{
        activate_private_oram_owner_enrollment_transition_v1,
        prepare_private_oram_owner_enrollment_transition_v1,
        private_oram_owner_checkpoint_reservation_binding_v1,
        private_oram_owner_checkpoint_reservation_context_v1,
        private_oram_owner_checkpoint_table_genesis_v1,
    };
    use crate::content_manager::consensus::private_oram_mutation_cleanup::{
        APPLY_LOCATOR_VERSION, PrivateOramRaftApplyLocatorV2,
    };
    use crate::content_manager::consensus_ops::{
        PrivateOramMutationLease, PrivateOramMutationLeasePhase,
    };
    use crate::content_manager::private_oram_mutation_journal::{
        PrivateOramMutationAppendAuthorityContextV2, private_oram_mutation_append_fixture_for_test,
    };
    use crate::content_manager::private_oram_mutation_state_v2::private_oram_collection_id_digest_v2;

    fn digest(seed: u8) -> String {
        BASE64URL_NOPAD.encode(&[seed; 32])
    }

    fn locator(index: u64) -> PrivateOramRaftApplyLocatorV2 {
        PrivateOramRaftApplyLocatorV2 {
            version: APPLY_LOCATOR_VERSION,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            term: 1,
            index,
        }
    }

    #[test]
    fn checkpoint_bound_v3_round_trips_and_never_falls_back_to_v2() {
        let owner_key = Ed25519KeyPair::from_seed_unchecked(&[71; 32]).unwrap();
        let base_table = private_oram_owner_checkpoint_table_genesis_v1(
            digest(1),
            digest(2),
            private_oram_collection_id_digest_v2("collection-a").unwrap(),
            digest(3),
            digest(4),
            digest(5),
            locator(1),
            7,
            private_oram_mutation_protocol_capability_digest_v2(),
        )
        .unwrap();
        let owner_incarnation = digest(20);
        let prepared =
            prepare_private_oram_owner_enrollment_v1(PrivateOramOwnerEnrollmentPreparedV1 {
                version: 0,
                consensus_history_id_digest: digest(1),
                raft_group_id_digest: digest(2),
                collection_id: "collection-a".to_string(),
                collection_lifetime_id_digest: digest(3),
                collection_incarnation_digest: digest(4),
                activation_anchor_digest: digest(5),
                capability_epoch: 7,
                protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
                membership_epoch: 9,
                owner_enrollment_id: digest(21),
                owner_peer_id: 11,
                owner_signer: private_oram_owner_cleanup_signer_v1(&owner_key, 1).unwrap(),
                owner_store_incarnation_digest: owner_incarnation.clone(),
                expected_genesis_state: private_oram_owner_lifecycle_genesis_state_v1(
                    owner_incarnation,
                )
                .unwrap(),
                authority_registry_digest: digest(22),
                owner_registry_digest: digest(23),
                enrollment_operation_id: digest(24),
                prepared_record_digest: String::new(),
            })
            .unwrap();
        let pending = prepare_private_oram_owner_enrollment_transition_v1(
            &base_table,
            prepared.clone(),
            locator(2),
        )
        .unwrap();
        let commitment =
            sign_private_oram_owner_enrollment_genesis_commitment_v1(&owner_key, &prepared)
                .unwrap();
        let table =
            activate_private_oram_owner_enrollment_transition_v1(&pending, &commitment, locator(3))
                .unwrap();

        let lease = PrivateOramMutationLease {
            generation: 1,
            collection_id: "collection-a".to_string(),
            owner_peer_id: 11,
            mutation_id: digest(30),
            signed_mutation_digest: digest(31),
            transition_digest: digest(32),
            base_record_digest: digest(33),
            base_state_sequence: 1,
            writer_lease_digest: digest(34),
            writer_fence: 1,
            issued_at_unix: 100,
            expires_at_unix: 200,
            renewal_revision: 0,
            phase: PrivateOramMutationLeasePhase::Preparing,
        };
        let authority_context = PrivateOramMutationAppendAuthorityContextV2::from_authority(
            digest(40),
            digest(1),
            digest(2),
            digest(3),
            digest(4),
            digest(5),
            4,
        )
        .unwrap();
        let (base_reservation, _) = private_oram_mutation_append_fixture_for_test(
            &lease,
            authority_context,
            1,
            &[11],
            PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(1, digest(41)),
        );
        let reservation_intent =
            private_oram_mutation_reservation_intent_v3(&base_reservation).unwrap();
        let context = private_oram_owner_checkpoint_reservation_context_v1(
            &table,
            reservation_intent.intent_digest().to_string(),
        )
        .unwrap();
        let checkpoint = &table.checkpoints()[0];
        let owner_target = &base_reservation.owner_targets()[0];
        let owner_nonce = BASE64URL_NOPAD.encode(&[42; 16]);
        let prepared_challenge = private_oram_mutation_prepared_reservation_challenge_v3(
            base_reservation.clone(),
            reservation_intent.clone(),
            context.clone(),
            vec![owner_nonce.clone()],
        )
        .unwrap();
        let challenge_applied = locator(4);
        let challenge = PrivateOramOwnerReservationPrepareChallengeV1 {
            version: PRIVATE_ORAM_OWNER_RESERVATION_PREPARE_VERSION_V1,
            consensus_history_id_digest: digest(1),
            raft_group_id_digest: digest(2),
            collection_id: "collection-a".to_string(),
            collection_lifetime_id_digest: digest(3),
            collection_incarnation_digest: digest(4),
            activation_anchor_digest: digest(5),
            capability_epoch: 7,
            protocol_capability_digest: private_oram_mutation_protocol_capability_digest_v2(),
            membership_epoch: 9,
            reservation_intent_digest: reservation_intent.intent_digest().to_string(),
            checkpoint_context_digest: context.context_digest().to_string(),
            committed_challenge_digest: prepared_challenge.prepared_challenge_digest().to_string(),
            challenge_applied_term: challenge_applied.term,
            challenge_applied_index: challenge_applied.index,
            attempt_id: base_reservation.attempt_id().to_string(),
            challenge_nonce: owner_nonce,
            expected_checkpoint_record_digest: checkpoint.checkpoint_record_digest().to_string(),
            expected_checkpoint_sequence: checkpoint.checkpoint_sequence(),
            expected_owner_target_digest: owner_target.target_digest().to_string(),
            reserved_terminal_intent_key: owner_target.intent_key().to_string(),
            owner_index: 0,
            owner_count: 1,
            owner_enrollment_id: checkpoint.owner_enrollment_id().to_string(),
            owner_peer_id: checkpoint.owner_peer_id(),
            owner_store_incarnation_digest: checkpoint
                .lifecycle_state()
                .owner_store_incarnation_digest
                .clone(),
            authority_registry_digest: digest(22),
            owner_registry_digest: digest(23),
        };
        let prepare = sign_private_oram_owner_reservation_prepare_v1(
            &owner_key,
            challenge,
            checkpoint.lifecycle_state().clone(),
            checkpoint.lifecycle_state().generation,
            digest(44),
            checkpoint.owner_signer().clone(),
        )
        .unwrap();
        let binding =
            private_oram_owner_checkpoint_reservation_binding_v1(0, checkpoint, prepare).unwrap();
        let reservation = private_oram_mutation_append_reservation_v3(
            base_reservation,
            reservation_intent,
            context,
            prepared_challenge,
            challenge_applied.clone(),
            vec![binding],
        )
        .unwrap();
        let encoded = encode_private_oram_mutation_append_reservation_v3(&reservation).unwrap();
        let decoded = decode_private_oram_mutation_append_reservation_wire(&encoded).unwrap();
        assert_eq!(
            decoded.reservation_digest(),
            reservation.reservation_digest_v3()
        );
        assert!(decoded.checkpoint_bound_v3().is_some());

        let alternate_authority_context =
            PrivateOramMutationAppendAuthorityContextV2::from_authority(
                digest(40),
                digest(1),
                digest(2),
                digest(3),
                digest(4),
                digest(5),
                4,
            )
            .unwrap();
        let (alternate_base, _) = private_oram_mutation_append_fixture_for_test(
            &lease,
            alternate_authority_context,
            2,
            &[11],
            PrivateOramActivationAuthorityLocatorV1::from_parts_for_test(1, digest(41)),
        );
        let alternate_intent =
            private_oram_mutation_reservation_intent_v3(&alternate_base).unwrap();
        let alternate_context = private_oram_owner_checkpoint_reservation_context_v1(
            &table,
            alternate_intent.intent_digest().to_string(),
        )
        .unwrap();
        assert!(
            private_oram_mutation_append_reservation_v3(
                alternate_base,
                alternate_intent,
                alternate_context,
                reservation.prepared_challenge.clone(),
                challenge_applied,
                reservation.checkpoint_bindings.clone(),
            )
            .is_err()
        );

        let mut malformed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        malformed["checkpoint_context"]["context_digest"] = serde_json::Value::String(digest(99));
        assert!(
            decode_private_oram_mutation_append_reservation_wire(
                &serde_json::to_string(&malformed).unwrap(),
            )
            .is_err()
        );
    }
}
