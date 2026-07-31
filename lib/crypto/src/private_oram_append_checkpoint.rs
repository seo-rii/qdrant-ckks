use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use thiserror::Error;

use crate::aead::SecretKey;
use crate::private_hnsw_client::{
    PRIVATE_HNSW_NODE_BLOCK_VERSION, PrivateHnswNodeBlockPlaintext,
    decode_private_hnsw_oram_leaf_label, private_hnsw_oram_bucket_ids_for_leaf,
};
use crate::private_hnsw_oram::ResultPrivacyMode;
use crate::private_oram_append_client::{
    PrivateOramAppendClientCheckpointV2, PrivateOramAppendClientError,
    PrivateOramAppendClientIndexCheckpointV2, PrivateOramAppendHnswRecordV2,
    PrivateOramAppendPointRecordV2, PrivateOramAppendResultRecordV2,
    PrivateOramEncryptedAppendClientCheckpointV2, bind_private_oram_append_client_checkpoint_v2,
    open_private_oram_append_client_checkpoint_v2,
    private_oram_append_client_checkpoint_plaintext_v3_digest,
    private_oram_append_client_checkpoint_v2_digest, seal_private_oram_append_client_checkpoint_v2,
    validate_private_oram_append_client_checkpoint_v2,
};
use crate::private_oram_append_result_transaction::{
    PrivateOramAppendResultTransactionOutputV2,
    validate_private_oram_append_result_transaction_output_v2,
};
use crate::private_oram_append_transaction::{
    PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION,
    PrivateOramAppendHnswPreparedCommitDigestInputV4, PrivateOramAppendHnswTransactionOutputV2,
    PrivateOramAppendRecoveryPhaseV2, PrivateOramAppendTransactionError,
    private_oram_append_hnsw_prepared_commit_v4_digest,
};
use crate::private_oram_mutation::{
    PRIVATE_ORAM_SIGNED_STATE_V2_VERSION, PrivateOramAppendReadTranscriptDigestInput,
    PrivateOramAppendReadWindowV1, PrivateOramAppendWritebackDigestInput,
    PrivateOramImmutableIndexParamsV2, PrivateOramImmutableManifestV2, PrivateOramIndexKindV2,
    PrivateOramIndexStateV2, PrivateOramMutationError, PrivateOramSignedStateV2,
    private_oram_append_read_transcript_v1, private_oram_append_writeback_v1_digest,
    private_oram_immutable_manifest_v2_digest, private_oram_signed_state_v2_digest,
    validate_private_oram_immutable_manifest_v2_shape, validate_private_oram_signed_state_v2_shape,
};
use crate::private_result_oram::{
    decode_private_result_oram_leaf_label, private_result_oram_bucket_ids_for_leaf,
};
#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramAppendCheckpointError {
    #[error("private ORAM append checkpoint operation failed")]
    Client(#[source] PrivateOramAppendClientError),
    #[error("private ORAM append prepared transaction is invalid")]
    Transaction(#[source] PrivateOramAppendTransactionError),
    #[error("private ORAM append mutation contract failed")]
    Mutation(#[source] PrivateOramMutationError),
    #[error("private ORAM append checkpoint topology is unsupported")]
    UnsupportedTopology,
    #[error("private ORAM append paired prepared output does not match")]
    PreparedOutputMismatch(&'static str),
    #[error("private ORAM append checkpoint transition is invalid")]
    InvalidTransition(&'static str),
    #[error("private ORAM append checkpoint reseal did not reopen exactly")]
    CheckpointRoundTripMismatch,
}

impl Debug for PrivateOramAppendCheckpointError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(_) => f.write_str("Client([redacted])"),
            Self::Transaction(_) => f.write_str("Transaction([redacted])"),
            Self::Mutation(_) => f.write_str("Mutation([redacted])"),
            Self::UnsupportedTopology => f.write_str("UnsupportedTopology"),
            Self::PreparedOutputMismatch(field) => f
                .debug_tuple("PreparedOutputMismatch")
                .field(field)
                .finish(),
            Self::InvalidTransition(field) => {
                f.debug_tuple("InvalidTransition").field(field).finish()
            }
            Self::CheckpointRoundTripMismatch => f.write_str("CheckpointRoundTripMismatch"),
        }
    }
}

impl From<PrivateOramAppendClientError> for PrivateOramAppendCheckpointError {
    fn from(error: PrivateOramAppendClientError) -> Self {
        Self::Client(error)
    }
}

impl From<PrivateOramAppendTransactionError> for PrivateOramAppendCheckpointError {
    fn from(error: PrivateOramAppendTransactionError) -> Self {
        Self::Transaction(error)
    }
}

impl From<PrivateOramMutationError> for PrivateOramAppendCheckpointError {
    fn from(error: PrivateOramMutationError) -> Self {
        Self::Mutation(error)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramAppendPairedCheckpointDeltaV2 {
    checkpoint: PrivateOramAppendClientCheckpointV2,
    next_indexes: Vec<PrivateOramIndexStateV2>,
    mutation_id: String,
}

impl PrivateOramAppendPairedCheckpointDeltaV2 {
    pub const fn checkpoint(&self) -> &PrivateOramAppendClientCheckpointV2 {
        &self.checkpoint
    }

    pub fn next_indexes(&self) -> &[PrivateOramIndexStateV2] {
        &self.next_indexes
    }

    pub fn mutation_id(&self) -> &str {
        &self.mutation_id
    }
}

impl Debug for PrivateOramAppendPairedCheckpointDeltaV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendPairedCheckpointDeltaV2")
            .field("checkpoint", &"[redacted]")
            .field("next_index_count", &self.next_indexes.len())
            .field("mutation_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramAppendPairedCheckpointResealV2 {
    pub checkpoint: PrivateOramAppendClientCheckpointV2,
    pub encrypted_checkpoint: PrivateOramEncryptedAppendClientCheckpointV2,
    pub new_state: PrivateOramSignedStateV2,
}

impl Debug for PrivateOramAppendPairedCheckpointResealV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendPairedCheckpointResealV2")
            .field("checkpoint", &"[redacted]")
            .field("encrypted_checkpoint", &"[redacted]")
            .field("new_state", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramAppendPairedCheckpointResealInputV2<'a> {
    pub manifest: &'a PrivateOramImmutableManifestV2,
    pub old_state: &'a PrivateOramSignedStateV2,
    pub old_encrypted_checkpoint: &'a PrivateOramEncryptedAppendClientCheckpointV2,
    pub hnsw_output: &'a PrivateOramAppendHnswTransactionOutputV2,
    pub result_output: &'a PrivateOramAppendResultTransactionOutputV2,
    pub new_state_signed_at_unix: u64,
}

impl Debug for PrivateOramAppendPairedCheckpointResealInputV2<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendPairedCheckpointResealInputV2")
            .field("manifest", &"[redacted]")
            .field("old_state", &"[redacted]")
            .field("old_encrypted_checkpoint", &"[redacted]")
            .field("hnsw_output", &"[redacted]")
            .field("result_output", &"[redacted]")
            .field("new_state_signed_at_unix", &self.new_state_signed_at_unix)
            .finish()
    }
}

/// Plans the paired ledger transition from an already authenticated old checkpoint.
///
/// Callers that start from persisted state should use
/// [`reseal_private_oram_append_paired_checkpoint_v2`], which authenticates and
/// opens the old encrypted checkpoint before invoking this planner.
pub fn plan_private_oram_append_paired_checkpoint_delta_v2(
    manifest: &PrivateOramImmutableManifestV2,
    old_state: &PrivateOramSignedStateV2,
    checkpoint: &PrivateOramAppendClientCheckpointV2,
    hnsw_output: &PrivateOramAppendHnswTransactionOutputV2,
    result_output: &PrivateOramAppendResultTransactionOutputV2,
) -> Result<PrivateOramAppendPairedCheckpointDeltaV2, PrivateOramAppendCheckpointError> {
    validate_private_oram_immutable_manifest_v2_shape(manifest)?;
    validate_private_oram_signed_state_v2_shape(old_state)?;
    validate_private_oram_append_client_checkpoint_v2(checkpoint, manifest, old_state)?;

    if manifest.result_privacy != ResultPrivacyMode::PrivatePayloadOramRequired
        || manifest.indexes.len() != 2
        || manifest
            .indexes
            .iter()
            .filter(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
            .count()
            != 1
        || manifest
            .indexes
            .iter()
            .filter(|index| index.kind() == PrivateOramIndexKindV2::Result)
            .count()
            != 1
    {
        return Err(PrivateOramAppendCheckpointError::UnsupportedTopology);
    }

    validate_old_state_capacity(manifest, old_state)?;
    validate_private_oram_append_result_transaction_output_v2(manifest, result_output)?;

    let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
    let old_state_digest = private_oram_signed_state_v2_digest(old_state)?;
    let source_checkpoint_digest =
        private_oram_append_client_checkpoint_plaintext_v3_digest(checkpoint)?;
    let hnsw_offset = manifest
        .indexes
        .iter()
        .position(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
        .ok_or(PrivateOramAppendCheckpointError::UnsupportedTopology)?;
    let result_offset = manifest
        .indexes
        .iter()
        .position(|index| index.kind() == PrivateOramIndexKindV2::Result)
        .ok_or(PrivateOramAppendCheckpointError::UnsupportedTopology)?;

    let hnsw_writeback_digest = validate_hnsw_prepared_output(
        manifest,
        old_state,
        &manifest_digest,
        &old_state_digest,
        hnsw_offset,
        hnsw_output,
    )?;
    let result_writeback_digest = validate_result_prepared_output_identity(
        manifest,
        old_state,
        &manifest_digest,
        &old_state_digest,
        result_offset,
        result_output,
    )?;
    validate_paired_output_identity(hnsw_output, result_output)?;
    if hnsw_output.source_checkpoint_digest != source_checkpoint_digest
        || result_output.source_checkpoint_digest != source_checkpoint_digest
    {
        return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "source_checkpoint_digest",
        ));
    }
    if old_state.last_mutation_id.as_deref()
        == Some(hnsw_output.recovery_marker.mutation_id.as_str())
    {
        return Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "mutation_id",
        ));
    }

    let point_record = validate_paired_point_records(hnsw_output, result_output)?;
    let points = append_point_record(checkpoint, point_record.clone())?;
    let hnsw_records = advance_hnsw_records(checkpoint, hnsw_output)?;
    let result_records = advance_result_records(checkpoint, result_output)?;

    let next_sequence = old_state.state_sequence.checked_add(1).ok_or(
        PrivateOramAppendCheckpointError::InvalidTransition("state_sequence"),
    )?;
    let mut next_checkpoint = PrivateOramAppendClientCheckpointV2 {
        version: checkpoint.version,
        collection_id: checkpoint.collection_id.clone(),
        manifest_digest: checkpoint.manifest_digest.clone(),
        layout_generation: checkpoint.layout_generation,
        state_sequence: next_sequence,
        points,
        indexes: Vec::with_capacity(checkpoint.indexes.len()),
    };
    for index in &checkpoint.indexes {
        match index {
            PrivateOramAppendClientIndexCheckpointV2::Hnsw { index_name, .. } => {
                if index_name != &hnsw_output.writeback.index_name {
                    return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
                        "hnsw.index_name",
                    ));
                }
                next_checkpoint
                    .indexes
                    .push(PrivateOramAppendClientIndexCheckpointV2::Hnsw {
                        index_name: index_name.clone(),
                        index_epoch: hnsw_output.new_epoch,
                        root_hash: hnsw_output.new_root_hash.clone(),
                        entry_node_id: Some(
                            BASE64URL_NOPAD.encode(&hnsw_output.graph_delta.next_entry_node_id),
                        ),
                        state: hnsw_output.next_client_state.clone(),
                        records: hnsw_records.clone(),
                    });
            }
            PrivateOramAppendClientIndexCheckpointV2::Result { index_name, .. } => {
                if index_name != &result_output.writeback.index_name {
                    return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
                        "result.index_name",
                    ));
                }
                next_checkpoint
                    .indexes
                    .push(PrivateOramAppendClientIndexCheckpointV2::Result {
                        index_name: index_name.clone(),
                        index_epoch: result_output.new_epoch,
                        root_hash: result_output.new_root_hash.clone(),
                        state: result_output.next_client_state.clone(),
                        records: result_records.clone(),
                    });
            }
        }
    }

    let next_indexes = manifest
        .indexes
        .iter()
        .zip(&old_state.indexes)
        .map(|(manifest_index, old_index)| {
            let (new_epoch, new_root_hash, writeback_digest) = match old_index.kind {
                PrivateOramIndexKindV2::Hnsw => (
                    hnsw_output.new_epoch,
                    hnsw_output.new_root_hash.clone(),
                    hnsw_writeback_digest.clone(),
                ),
                PrivateOramIndexKindV2::Result => (
                    result_output.new_epoch,
                    result_output.new_root_hash.clone(),
                    result_writeback_digest.clone(),
                ),
            };
            let logical_count = old_index.logical_count.checked_add(1).ok_or(
                PrivateOramAppendCheckpointError::InvalidTransition("logical_count"),
            )?;
            let dummy_count = old_index.dummy_count.checked_sub(1).ok_or(
                PrivateOramAppendCheckpointError::InvalidTransition("dummy_count"),
            )?;
            if logical_count > manifest_index.capacity.logical_capacity
                || logical_count
                    .checked_add(dummy_count)
                    .is_none_or(|count| count != manifest_index.capacity.logical_capacity)
                || new_root_hash == old_index.root_hash
                || writeback_digest == old_index.last_writeback_digest
            {
                return Err(PrivateOramAppendCheckpointError::InvalidTransition(
                    "index_state",
                ));
            }
            Ok(PrivateOramIndexStateV2 {
                kind: old_index.kind,
                index_name: old_index.index_name.clone(),
                index_epoch: new_epoch,
                root_hash: new_root_hash,
                logical_count,
                dummy_count,
                last_writeback_digest: writeback_digest,
            })
        })
        .collect::<Result<Vec<_>, PrivateOramAppendCheckpointError>>()?;

    let provisional_state = PrivateOramSignedStateV2 {
        version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        collection_id: old_state.collection_id.clone(),
        manifest_digest: old_state.manifest_digest.clone(),
        layout_generation: old_state.layout_generation,
        layout_digest: old_state.layout_digest.clone(),
        state_sequence: next_sequence,
        indexes: next_indexes.clone(),
        client_state_digest: old_state.client_state_digest.clone(),
        last_mutation_id: Some(hnsw_output.recovery_marker.mutation_id.clone()),
        owner_signing_key_id: old_state.owner_signing_key_id.clone(),
        signed_at_unix: old_state.signed_at_unix,
    };
    validate_private_oram_append_client_checkpoint_v2(
        &next_checkpoint,
        manifest,
        &provisional_state,
    )?;

    Ok(PrivateOramAppendPairedCheckpointDeltaV2 {
        checkpoint: next_checkpoint,
        next_indexes,
        mutation_id: hnsw_output.recovery_marker.mutation_id.clone(),
    })
}

/// Authenticates the old checkpoint, applies the paired delta, and returns one
/// exact pending reseal artifact. A retry must persist and reuse the returned
/// ciphertext and state payload rather than invoke this randomized seal again.
pub fn reseal_private_oram_append_paired_checkpoint_v2(
    checkpoint_key: &SecretKey,
    input: PrivateOramAppendPairedCheckpointResealInputV2<'_>,
) -> Result<PrivateOramAppendPairedCheckpointResealV2, PrivateOramAppendCheckpointError> {
    let manifest = input.manifest;
    let old_state = input.old_state;
    if old_state.owner_signing_key_id != manifest.owner_signing_key_id
        || old_state.manifest_digest != private_oram_immutable_manifest_v2_digest(manifest)?
        || input.new_state_signed_at_unix < old_state.signed_at_unix
    {
        return Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "signed_state",
        ));
    }
    let checkpoint = open_private_oram_append_client_checkpoint_v2(
        checkpoint_key,
        input.old_encrypted_checkpoint,
        manifest,
        old_state,
    )?;

    let delta = plan_private_oram_append_paired_checkpoint_delta_v2(
        manifest,
        old_state,
        &checkpoint,
        input.hnsw_output,
        input.result_output,
    )?;
    let sealed = seal_private_oram_append_client_checkpoint_v2(checkpoint_key, &delta.checkpoint)?;
    let client_state_digest = private_oram_append_client_checkpoint_v2_digest(&sealed)?;
    if client_state_digest == old_state.client_state_digest {
        return Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "client_state_digest",
        ));
    }
    let new_state = PrivateOramSignedStateV2 {
        version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        collection_id: old_state.collection_id.clone(),
        manifest_digest: old_state.manifest_digest.clone(),
        layout_generation: old_state.layout_generation,
        layout_digest: old_state.layout_digest.clone(),
        state_sequence: delta.checkpoint.state_sequence,
        indexes: delta.next_indexes.clone(),
        client_state_digest,
        last_mutation_id: Some(delta.mutation_id.clone()),
        owner_signing_key_id: old_state.owner_signing_key_id.clone(),
        signed_at_unix: input.new_state_signed_at_unix,
    };
    validate_private_oram_signed_state_v2_shape(&new_state)?;
    validate_private_oram_append_client_checkpoint_v2(&delta.checkpoint, manifest, &new_state)?;

    let encrypted_checkpoint = bind_private_oram_append_client_checkpoint_v2(sealed, &new_state)?;
    let reopened = open_private_oram_append_client_checkpoint_v2(
        checkpoint_key,
        &encrypted_checkpoint,
        manifest,
        &new_state,
    )?;
    if reopened != delta.checkpoint {
        return Err(PrivateOramAppendCheckpointError::CheckpointRoundTripMismatch);
    }

    Ok(PrivateOramAppendPairedCheckpointResealV2 {
        checkpoint: delta.checkpoint,
        encrypted_checkpoint,
        new_state,
    })
}

fn validate_old_state_capacity(
    manifest: &PrivateOramImmutableManifestV2,
    old_state: &PrivateOramSignedStateV2,
) -> Result<(), PrivateOramAppendCheckpointError> {
    if manifest.indexes.len() != old_state.indexes.len()
        || old_state.collection_id != manifest.collection_id
        || old_state.owner_signing_key_id != manifest.owner_signing_key_id
        || old_state.signed_at_unix < manifest.created_at_unix
    {
        return Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "old_state.indexes",
        ));
    }
    for (manifest_index, state_index) in manifest.indexes.iter().zip(&old_state.indexes) {
        if manifest_index.kind() != state_index.kind
            || manifest_index.index_name != state_index.index_name
            || state_index
                .logical_count
                .checked_add(state_index.dummy_count)
                .is_none_or(|count| count != manifest_index.capacity.logical_capacity)
            || state_index.logical_count >= manifest_index.capacity.logical_capacity
            || state_index.dummy_count == 0
        {
            return Err(PrivateOramAppendCheckpointError::InvalidTransition(
                "old_state.capacity",
            ));
        }
    }
    Ok(())
}

fn validate_hnsw_prepared_output(
    manifest: &PrivateOramImmutableManifestV2,
    old_state: &PrivateOramSignedStateV2,
    manifest_digest: &str,
    old_state_digest: &str,
    index_offset: usize,
    output: &PrivateOramAppendHnswTransactionOutputV2,
) -> Result<String, PrivateOramAppendCheckpointError> {
    let manifest_index = &manifest.indexes[index_offset];
    let old_index = &old_state.indexes[index_offset];
    let PrivateOramImmutableIndexParamsV2::Hnsw { oram, .. } = &manifest_index.params else {
        return Err(PrivateOramAppendCheckpointError::UnsupportedTopology);
    };
    let marker = &output.recovery_marker;
    let expected_new_epoch = old_index.index_epoch.checked_add(1).ok_or(
        PrivateOramAppendCheckpointError::InvalidTransition("index_epoch"),
    )?;
    if marker.version != PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION
        || marker.collection_id != manifest.collection_id
        || marker.manifest_digest != manifest_digest
        || marker.old_state_digest != old_state_digest
        || marker.index_kind != PrivateOramIndexKindV2::Hnsw
        || marker.index_name != manifest_index.index_name
        || marker.phase != PrivateOramAppendRecoveryPhaseV2::PreparedCommit
        || marker.prepared_commit_digest.is_none()
        || output.graph_delta.index_name != manifest_index.index_name
        || output.graph_delta.fixed_read_path_count
            != manifest_index.capacity.fixed_append_read_path_count
        || output.old_epoch != old_index.index_epoch
        || output.new_epoch != expected_new_epoch
        || output.old_root_hash != old_index.root_hash
        || output.new_root_hash == old_index.root_hash
        || output.writeback.kind != PrivateOramIndexKindV2::Hnsw
        || output.writeback.index_name != manifest_index.index_name
        || output.writeback.read_path_count != manifest_index.capacity.fixed_append_read_path_count
        || output.writeback.read_path_count != output.read_transcript.read_path_count
        || output.writeback.read_transcript_digest != output.read_transcript.transcript_digest
        || output.writeback.updated_buckets.len()
            != usize::try_from(manifest_index.capacity.fixed_append_write_bucket_count).map_err(
                |_| {
                    PrivateOramAppendCheckpointError::PreparedOutputMismatch("hnsw.writeback_count")
                },
            )?
        || output.ordered_encrypted_buckets.len() != output.writeback.updated_buckets.len()
    {
        return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "hnsw",
        ));
    }
    decode_base64url_32(&output.source_checkpoint_digest)?;

    validate_prepared_read_transcript_and_frames(
        PreparedReadValidationInput {
            manifest,
            manifest_digest,
            old_state_digest,
            marker,
            tree_height: oram.tree_height,
            paths_per_window: oram.path_batch_size,
            transcript: &output.read_transcript,
            writeback: &output.writeback,
        },
        |leaf_label| {
            let leaf = decode_private_hnsw_oram_leaf_label(leaf_label, oram.tree_height)
                .map_err(PrivateOramAppendTransactionError::from)?;
            private_hnsw_oram_bucket_ids_for_leaf(leaf, oram.tree_height)
                .map_err(PrivateOramAppendTransactionError::from)
        },
    )?;

    let writeback_digest =
        private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
            collection_id: &manifest.collection_id,
            manifest_digest,
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: &manifest_index.index_name,
            old_epoch: output.old_epoch,
            new_epoch: output.new_epoch,
            old_root_hash: &output.old_root_hash,
            new_root_hash: &output.new_root_hash,
            read_path_count: output.writeback.read_path_count,
            read_transcript_digest: &output.writeback.read_transcript_digest,
            updated_buckets: &output.writeback.updated_buckets,
        })?;
    let prepared_digest = private_oram_append_hnsw_prepared_commit_v4_digest(
        PrivateOramAppendHnswPreparedCommitDigestInputV4 {
            attempt_digest: &marker.attempt_digest,
            source_checkpoint_digest: &output.source_checkpoint_digest,
            graph_delta: &output.graph_delta,
            old_epoch: output.old_epoch,
            new_epoch: output.new_epoch,
            old_root_hash: &output.old_root_hash,
            new_root_hash: &output.new_root_hash,
            read_transcript_digest: &output.read_transcript.transcript_digest,
            writeback_digest: &writeback_digest,
            next_client_state: &output.next_client_state,
        },
    )?;
    if marker.prepared_commit_digest.as_deref() != Some(prepared_digest.as_str()) {
        return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "hnsw.prepared_commit_digest",
        ));
    }
    Ok(writeback_digest)
}

fn validate_result_prepared_output_identity(
    manifest: &PrivateOramImmutableManifestV2,
    old_state: &PrivateOramSignedStateV2,
    manifest_digest: &str,
    old_state_digest: &str,
    index_offset: usize,
    output: &PrivateOramAppendResultTransactionOutputV2,
) -> Result<String, PrivateOramAppendCheckpointError> {
    let manifest_index = &manifest.indexes[index_offset];
    let old_index = &old_state.indexes[index_offset];
    let PrivateOramImmutableIndexParamsV2::Result { oram, .. } = &manifest_index.params else {
        return Err(PrivateOramAppendCheckpointError::UnsupportedTopology);
    };
    let marker = &output.recovery_marker;
    if marker.collection_id != manifest.collection_id
        || marker.manifest_digest != manifest_digest
        || marker.old_state_digest != old_state_digest
        || marker.index_kind != PrivateOramIndexKindV2::Result
        || marker.index_name != manifest_index.index_name
        || output.old_epoch != old_index.index_epoch
        || output.new_epoch
            != old_index.index_epoch.checked_add(1).ok_or(
                PrivateOramAppendCheckpointError::InvalidTransition("index_epoch"),
            )?
        || output.old_root_hash != old_index.root_hash
        || output.new_root_hash == old_index.root_hash
    {
        return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "result",
        ));
    }
    validate_prepared_read_transcript_and_frames(
        PreparedReadValidationInput {
            manifest,
            manifest_digest,
            old_state_digest,
            marker,
            tree_height: oram.tree_height,
            paths_per_window: oram.path_batch_size,
            transcript: &output.read_transcript,
            writeback: &output.writeback,
        },
        |leaf_label| {
            let leaf = decode_private_result_oram_leaf_label(leaf_label, oram.tree_height)
                .map_err(PrivateOramAppendTransactionError::from)?;
            private_result_oram_bucket_ids_for_leaf(leaf, oram.tree_height)
                .map_err(PrivateOramAppendTransactionError::from)
        },
    )?;
    Ok(private_oram_append_writeback_v1_digest(
        PrivateOramAppendWritebackDigestInput {
            collection_id: &manifest.collection_id,
            manifest_digest,
            kind: PrivateOramIndexKindV2::Result,
            index_name: &manifest_index.index_name,
            old_epoch: output.old_epoch,
            new_epoch: output.new_epoch,
            old_root_hash: &output.old_root_hash,
            new_root_hash: &output.new_root_hash,
            read_path_count: output.writeback.read_path_count,
            read_transcript_digest: &output.writeback.read_transcript_digest,
            updated_buckets: &output.writeback.updated_buckets,
        },
    )?)
}

fn validate_paired_output_identity(
    hnsw_output: &PrivateOramAppendHnswTransactionOutputV2,
    result_output: &PrivateOramAppendResultTransactionOutputV2,
) -> Result<(), PrivateOramAppendCheckpointError> {
    let hnsw = &hnsw_output.recovery_marker;
    let result = &result_output.recovery_marker;
    if hnsw.mutation_id != result.mutation_id
        || hnsw.collection_id != result.collection_id
        || hnsw.manifest_digest != result.manifest_digest
        || hnsw.old_state_digest != result.old_state_digest
        || hnsw_output.source_checkpoint_digest != result_output.source_checkpoint_digest
        || hnsw.writer_lease_digest != result.writer_lease_digest
        || hnsw.writer_fence != result.writer_fence
    {
        return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "paired_identity",
        ));
    }
    Ok(())
}

fn validate_paired_point_records(
    hnsw_output: &PrivateOramAppendHnswTransactionOutputV2,
    result_output: &PrivateOramAppendResultTransactionOutputV2,
) -> Result<PrivateOramAppendPointRecordV2, PrivateOramAppendCheckpointError> {
    let graph = &hnsw_output.graph_delta;
    let point = &graph.point_record;
    let hnsw_record = &graph.hnsw_record;
    let result_record = &result_output.result_record;
    let node_id = BASE64URL_NOPAD.encode(&graph.new_block.node_id);
    let point_token = BASE64URL_NOPAD.encode(&graph.new_block.point_token);
    let payload_fetch_token = graph
        .new_block
        .payload_fetch_token
        .map(|token| BASE64URL_NOPAD.encode(&token));
    if graph.new_block.node_id == [0; 32]
        || graph.new_block.point_token == [0; 32]
        || graph.new_block.payload_fetch_token == Some([0; 32])
        || graph.next_entry_node_id == [0; 32]
        || graph.new_block.version != PRIVATE_HNSW_NODE_BLOCK_VERSION
        || graph.new_block.deleted
        || graph.new_block.generation != 1
        || hnsw_record.generation != 1
        || hnsw_record.node_id != node_id
        || hnsw_record.point_token != point_token
        || hnsw_record.level_mask != graph.new_block.level_mask
        || point.point_token != point_token
        || point.visible_point_id.is_some()
        || point.payload_fetch_token != payload_fetch_token
        || result_record.point_token != point_token
        || point.payload_fetch_token.as_deref() != Some(result_record.payload_fetch_token.as_str())
        || result_record.generation != 1
    {
        return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "point_ledger",
        ));
    }
    Ok(point.clone())
}

fn append_point_record(
    checkpoint: &PrivateOramAppendClientCheckpointV2,
    point_record: PrivateOramAppendPointRecordV2,
) -> Result<Vec<PrivateOramAppendPointRecordV2>, PrivateOramAppendCheckpointError> {
    let mut records = checkpoint
        .points
        .iter()
        .cloned()
        .map(|record| Ok((decode_base64url_32(&record.point_token)?, record)))
        .collect::<Result<BTreeMap<_, _>, PrivateOramAppendCheckpointError>>()?;
    let point_token = decode_base64url_32(&point_record.point_token)?;
    if records.insert(point_token, point_record).is_some() {
        return Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "point_token",
        ));
    }
    Ok(records.into_values().collect())
}

fn advance_hnsw_records(
    checkpoint: &PrivateOramAppendClientCheckpointV2,
    output: &PrivateOramAppendHnswTransactionOutputV2,
) -> Result<Vec<PrivateOramAppendHnswRecordV2>, PrivateOramAppendCheckpointError> {
    let old_records = checkpoint
        .indexes
        .iter()
        .find_map(|index| match index {
            PrivateOramAppendClientIndexCheckpointV2::Hnsw { records, .. } => Some(records),
            PrivateOramAppendClientIndexCheckpointV2::Result { .. } => None,
        })
        .ok_or(PrivateOramAppendCheckpointError::UnsupportedTopology)?;
    let mut records = old_records
        .iter()
        .cloned()
        .map(|record| Ok((decode_base64url_32(&record.node_id)?, record)))
        .collect::<Result<BTreeMap<_, _>, PrivateOramAppendCheckpointError>>()?;
    let mut rewritten = BTreeSet::new();
    for rewrite in &output.graph_delta.neighbor_rewrites {
        validate_hnsw_rewrite(&rewrite.previous, &rewrite.replacement)?;
        if !rewritten.insert(rewrite.previous.node_id) {
            return Err(PrivateOramAppendCheckpointError::InvalidTransition(
                "neighbor_rewrites",
            ));
        }
        let record = records.get_mut(&rewrite.previous.node_id).ok_or(
            PrivateOramAppendCheckpointError::InvalidTransition("neighbor_rewrites"),
        )?;
        if record.point_token != BASE64URL_NOPAD.encode(&rewrite.previous.point_token)
            || record.level_mask != rewrite.previous.level_mask
            || record.generation != rewrite.previous.generation
        {
            return Err(PrivateOramAppendCheckpointError::InvalidTransition(
                "neighbor_rewrites",
            ));
        }
        record.generation = rewrite.replacement.generation;
    }

    let new_record = output.graph_delta.hnsw_record.clone();
    let node_id = decode_base64url_32(&new_record.node_id)?;
    if records.insert(node_id, new_record).is_some() {
        return Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "node_id",
        ));
    }
    Ok(records.into_values().collect())
}

fn validate_hnsw_rewrite(
    previous: &PrivateHnswNodeBlockPlaintext,
    replacement: &PrivateHnswNodeBlockPlaintext,
) -> Result<(), PrivateOramAppendCheckpointError> {
    if previous.version != PRIVATE_HNSW_NODE_BLOCK_VERSION
        || previous.deleted
        || replacement.deleted
        || previous.version != replacement.version
        || previous.node_id != replacement.node_id
        || previous.point_token != replacement.point_token
        || previous.level_mask != replacement.level_mask
        || previous.vector_encoding != replacement.vector_encoding
        || previous.vector != replacement.vector
        || previous.payload_fetch_token != replacement.payload_fetch_token
        || replacement.generation
            != previous.generation.checked_add(1).ok_or(
                PrivateOramAppendCheckpointError::InvalidTransition("generation"),
            )?
    {
        return Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "neighbor_rewrite",
        ));
    }
    Ok(())
}

fn advance_result_records(
    checkpoint: &PrivateOramAppendClientCheckpointV2,
    output: &PrivateOramAppendResultTransactionOutputV2,
) -> Result<Vec<PrivateOramAppendResultRecordV2>, PrivateOramAppendCheckpointError> {
    let old_records = checkpoint
        .indexes
        .iter()
        .find_map(|index| match index {
            PrivateOramAppendClientIndexCheckpointV2::Result { records, .. } => Some(records),
            PrivateOramAppendClientIndexCheckpointV2::Hnsw { .. } => None,
        })
        .ok_or(PrivateOramAppendCheckpointError::UnsupportedTopology)?;
    let mut records = old_records
        .iter()
        .cloned()
        .map(|record| Ok((decode_base64url_32(&record.payload_fetch_token)?, record)))
        .collect::<Result<BTreeMap<_, _>, PrivateOramAppendCheckpointError>>()?;
    let new_record = output.result_record.clone();
    let payload_fetch_token = decode_base64url_32(&new_record.payload_fetch_token)?;
    if records.insert(payload_fetch_token, new_record).is_some() {
        return Err(PrivateOramAppendCheckpointError::InvalidTransition(
            "payload_fetch_token",
        ));
    }
    Ok(records.into_values().collect())
}

#[derive(Clone, Copy)]
struct PreparedReadValidationInput<'a> {
    manifest: &'a PrivateOramImmutableManifestV2,
    manifest_digest: &'a str,
    old_state_digest: &'a str,
    marker: &'a crate::private_oram_append_transaction::PrivateOramAppendRecoveryMarkerV3,
    tree_height: u32,
    paths_per_window: u32,
    transcript: &'a crate::private_oram_mutation::PrivateOramObservedReadTranscriptV1,
    writeback: &'a crate::private_oram_mutation::PrivateOramAppendIndexWritebackV1,
}

fn validate_prepared_read_transcript_and_frames<F>(
    input: PreparedReadValidationInput<'_>,
    bucket_ids_for_leaf: F,
) -> Result<(), PrivateOramAppendCheckpointError>
where
    F: Fn(&str) -> Result<Vec<u64>, PrivateOramAppendTransactionError>,
{
    let PreparedReadValidationInput {
        manifest,
        manifest_digest,
        old_state_digest,
        marker,
        tree_height,
        paths_per_window,
        transcript,
        writeback,
    } = input;
    let paths_per_window_usize = usize::try_from(paths_per_window).map_err(|_| {
        PrivateOramAppendCheckpointError::PreparedOutputMismatch("paths_per_window")
    })?;
    if paths_per_window_usize == 0
        || transcript.collection_id != manifest.collection_id
        || transcript.manifest_digest != manifest_digest
        || transcript.mutation_id != marker.mutation_id
        || transcript.old_state_digest != old_state_digest
        || transcript.writer_lease_digest != marker.writer_lease_digest
        || transcript.writer_fence != marker.writer_fence
        || transcript.kind != marker.index_kind
        || transcript.index_name != marker.index_name
        || transcript.paths_per_window != paths_per_window
        || transcript.tree_height != tree_height
        || transcript.ordered_leaf_labels.len()
            != usize::try_from(transcript.read_path_count).map_err(|_| {
                PrivateOramAppendCheckpointError::PreparedOutputMismatch("read_path_count")
            })?
        || !transcript
            .ordered_leaf_labels
            .len()
            .is_multiple_of(paths_per_window_usize)
    {
        return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "read_transcript",
        ));
    }
    let windows = transcript
        .ordered_leaf_labels
        .chunks(paths_per_window_usize)
        .enumerate()
        .map(|(sequence, paths)| {
            Ok(PrivateOramAppendReadWindowV1 {
                sequence: u32::try_from(sequence).map_err(|_| {
                    PrivateOramAppendCheckpointError::PreparedOutputMismatch(
                        "read_transcript.sequence",
                    )
                })?,
                paths: paths.to_vec(),
            })
        })
        .collect::<Result<Vec<_>, PrivateOramAppendCheckpointError>>()?;
    let expected_transcript =
        private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
            collection_id: &manifest.collection_id,
            manifest_digest,
            mutation_id: &marker.mutation_id,
            old_state_digest,
            writer_lease_digest: &marker.writer_lease_digest,
            writer_fence: marker.writer_fence,
            paths_per_window,
            tree_height,
            kind: marker.index_kind,
            index_name: &marker.index_name,
            windows: &windows,
        })?;
    if &expected_transcript != transcript
        || marker.requested_window_count
            != u32::try_from(windows.len()).map_err(|_| {
                PrivateOramAppendCheckpointError::PreparedOutputMismatch("window_count")
            })?
        || marker.accepted_window_count != marker.requested_window_count
        || marker.observed_read_path_count != transcript.read_path_count
    {
        return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "read_transcript",
        ));
    }

    let path_bucket_count = usize::try_from(tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "tree_height",
        ))?;
    if writeback.updated_buckets.len()
        != transcript
            .ordered_leaf_labels
            .len()
            .checked_mul(path_bucket_count)
            .ok_or(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
                "writeback_count",
            ))?
    {
        return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
            "writeback_count",
        ));
    }
    for (leaf_label, bucket_frame) in transcript
        .ordered_leaf_labels
        .iter()
        .zip(writeback.updated_buckets.chunks_exact(path_bucket_count))
    {
        let expected_bucket_ids = bucket_ids_for_leaf(leaf_label)?;
        if bucket_frame.len() != expected_bucket_ids.len()
            || bucket_frame
                .iter()
                .zip(expected_bucket_ids)
                .any(|(bucket, expected_bucket_id)| bucket.bucket_id != expected_bucket_id)
        {
            return Err(PrivateOramAppendCheckpointError::PreparedOutputMismatch(
                "writeback_frame",
            ));
        }
    }
    Ok(())
}

fn decode_base64url_32(value: &str) -> Result<[u8; 32], PrivateOramAppendCheckpointError> {
    BASE64URL_NOPAD
        .decode(value.as_bytes())
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(PrivateOramAppendCheckpointError::InvalidTransition(
            "base64url_32",
        ))
}
