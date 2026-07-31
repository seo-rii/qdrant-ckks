use std::fmt::{self, Debug, Formatter};

use ring::signature::{Ed25519KeyPair, KeyPair};
use thiserror::Error;

use crate::aead::SecretKey;
use crate::private_oram_append_checkpoint::{
    PrivateOramAppendCheckpointError, PrivateOramAppendPairedCheckpointResealInputV2,
    reseal_private_oram_append_paired_checkpoint_v2,
};
use crate::private_oram_append_client::{
    PrivateOramAppendClientCheckpointV2, PrivateOramAppendClientError,
    PrivateOramEncryptedAppendClientCheckpointV2, open_private_oram_append_client_checkpoint_v2,
};
use crate::private_oram_append_result_transaction::{
    PrivateOramAppendResultTransactionOutputV2,
    validate_private_oram_append_result_transaction_output_v2,
};
use crate::private_oram_append_transaction::{
    PrivateOramAppendHnswTransactionOutputV2, PrivateOramAppendTransactionError,
    validate_private_oram_append_hnsw_transaction_output_v2,
};
use crate::private_oram_mutation::{
    PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION, PrivateOramAppendMutationBundleV1,
    PrivateOramAppendMutationV1, PrivateOramAppendValidationContext,
    PrivateOramImmutableManifestBundleV2, PrivateOramIndexKindV2, PrivateOramMutationError,
    PrivateOramPointOperationKindV1, PrivateOramSignatureVerification,
    PrivateOramSignedStateBundleV2, package_private_oram_append_mutation_v1,
    package_private_oram_signed_state_v2, private_oram_immutable_manifest_v2_digest,
    private_oram_no_server_point_record_v1_digest, private_oram_signed_state_v2_digest,
    validate_private_oram_append_mutation_v1,
    validate_private_oram_immutable_manifest_v2_signature,
    validate_private_oram_signed_state_v2_signature,
};

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramAppendFinalizerError {
    #[error("private ORAM append finalizer checkpoint operation failed")]
    Checkpoint(#[source] PrivateOramAppendCheckpointError),
    #[error("private ORAM append finalizer client checkpoint operation failed")]
    Client(#[source] PrivateOramAppendClientError),
    #[error("private ORAM append finalizer prepared transaction is invalid")]
    Transaction(#[source] PrivateOramAppendTransactionError),
    #[error("private ORAM append finalizer mutation contract failed")]
    Mutation(#[source] PrivateOramMutationError),
    #[error("private ORAM append finalizer signing key does not match trusted verification key")]
    SigningKeyMismatch,
    #[error("private ORAM append finalizer trusted context does not match prepared state")]
    ContextMismatch(&'static str),
    #[error("private ORAM append finalizer checkpoint did not reopen exactly")]
    CheckpointRoundTripMismatch,
}

impl Debug for PrivateOramAppendFinalizerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checkpoint(_) => f.write_str("Checkpoint([redacted])"),
            Self::Client(_) => f.write_str("Client([redacted])"),
            Self::Transaction(_) => f.write_str("Transaction([redacted])"),
            Self::Mutation(_) => f.write_str("Mutation([redacted])"),
            Self::SigningKeyMismatch => f.write_str("SigningKeyMismatch"),
            Self::ContextMismatch(field) => f.debug_tuple("ContextMismatch").field(field).finish(),
            Self::CheckpointRoundTripMismatch => f.write_str("CheckpointRoundTripMismatch"),
        }
    }
}

impl From<PrivateOramAppendCheckpointError> for PrivateOramAppendFinalizerError {
    fn from(error: PrivateOramAppendCheckpointError) -> Self {
        Self::Checkpoint(error)
    }
}

impl From<PrivateOramAppendClientError> for PrivateOramAppendFinalizerError {
    fn from(error: PrivateOramAppendClientError) -> Self {
        Self::Client(error)
    }
}

impl From<PrivateOramAppendTransactionError> for PrivateOramAppendFinalizerError {
    fn from(error: PrivateOramAppendTransactionError) -> Self {
        Self::Transaction(error)
    }
}

impl From<PrivateOramMutationError> for PrivateOramAppendFinalizerError {
    fn from(error: PrivateOramMutationError) -> Self {
        Self::Mutation(error)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramAppendPairedFinalizationContextV1<'a> {
    pub expected_collection_id: &'a str,
    pub expected_manifest_digest: &'a str,
    pub expected_owner_signing_key_id: &'a str,
    pub expected_layout_generation: u64,
    pub expected_layout_digest: &'a str,
    pub expected_writer_lease_digest: &'a str,
    pub expected_writer_fence: u64,
    pub expected_state_sequence: u64,
    pub expected_old_state_digest: &'a str,
    pub now_unix: u64,
    pub max_mutation_ttl_secs: u64,
    pub public_key: &'a [u8],
}

impl Debug for PrivateOramAppendPairedFinalizationContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendPairedFinalizationContextV1")
            .field("expected_collection_id", &"[redacted]")
            .field("expected_manifest_digest", &"[redacted]")
            .field("expected_owner_signing_key_id", &"[redacted]")
            .field(
                "expected_layout_generation",
                &self.expected_layout_generation,
            )
            .field("expected_layout_digest", &"[redacted]")
            .field("expected_writer_lease_digest", &"[redacted]")
            .field("expected_writer_fence", &self.expected_writer_fence)
            .field("expected_state_sequence", &self.expected_state_sequence)
            .field("expected_old_state_digest", &"[redacted]")
            .field("now_unix", &self.now_unix)
            .field("max_mutation_ttl_secs", &self.max_mutation_ttl_secs)
            .field("public_key", &"[redacted]")
            .finish()
    }
}

pub struct PrivateOramAppendPairedFinalizationInputV1<'a> {
    pub manifest_bundle: &'a PrivateOramImmutableManifestBundleV2,
    pub old_state_bundle: &'a PrivateOramSignedStateBundleV2,
    pub old_encrypted_checkpoint: &'a PrivateOramEncryptedAppendClientCheckpointV2,
    pub hnsw_output: PrivateOramAppendHnswTransactionOutputV2,
    pub result_output: PrivateOramAppendResultTransactionOutputV2,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub new_state_signed_at_unix: u64,
    pub validation: PrivateOramAppendPairedFinalizationContextV1<'a>,
}

impl Debug for PrivateOramAppendPairedFinalizationInputV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendPairedFinalizationInputV1")
            .field("manifest_bundle", &"[redacted]")
            .field("old_state_bundle", &"[redacted]")
            .field("old_encrypted_checkpoint", &"[redacted]")
            .field("hnsw_output", &"[redacted]")
            .field("result_output", &"[redacted]")
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("new_state_signed_at_unix", &self.new_state_signed_at_unix)
            .field("validation", &self.validation)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct PrivateOramAppendPairedFinalizationV1 {
    pub checkpoint: PrivateOramAppendClientCheckpointV2,
    pub encrypted_checkpoint: PrivateOramEncryptedAppendClientCheckpointV2,
    pub hnsw_output: PrivateOramAppendHnswTransactionOutputV2,
    pub result_output: PrivateOramAppendResultTransactionOutputV2,
    pub mutation_bundle: PrivateOramAppendMutationBundleV1,
}

impl Debug for PrivateOramAppendPairedFinalizationV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendPairedFinalizationV1")
            .field("checkpoint", &"[redacted]")
            .field("encrypted_checkpoint", &"[redacted]")
            .field("hnsw_output", &"[redacted]")
            .field("result_output", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .finish()
    }
}

pub fn finalize_private_oram_append_paired_mutation_v1(
    checkpoint_key: &SecretKey,
    owner_key_pair: &Ed25519KeyPair,
    input: PrivateOramAppendPairedFinalizationInputV1<'_>,
) -> Result<PrivateOramAppendPairedFinalizationV1, PrivateOramAppendFinalizerError> {
    let manifest = &input.manifest_bundle.manifest;
    let old_state = &input.old_state_bundle.state;
    let validation = input.validation;
    if owner_key_pair.public_key().as_ref() != validation.public_key {
        return Err(PrivateOramAppendFinalizerError::SigningKeyMismatch);
    }
    let signature_verification = PrivateOramSignatureVerification {
        expected_key_id: validation.expected_owner_signing_key_id,
        public_key: validation.public_key,
    };
    validate_private_oram_immutable_manifest_v2_signature(
        manifest,
        Some(&input.manifest_bundle.signature),
        signature_verification,
    )?;
    validate_private_oram_signed_state_v2_signature(
        old_state,
        Some(&input.old_state_bundle.signature),
        signature_verification,
    )?;
    let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
    let old_state_digest = private_oram_signed_state_v2_digest(old_state)?;
    if manifest.collection_id != validation.expected_collection_id
        || manifest_digest != validation.expected_manifest_digest
        || manifest.owner_signing_key_id != validation.expected_owner_signing_key_id
    {
        return Err(PrivateOramAppendFinalizerError::ContextMismatch("manifest"));
    }
    if old_state.collection_id != validation.expected_collection_id
        || old_state.manifest_digest != validation.expected_manifest_digest
        || old_state.owner_signing_key_id != validation.expected_owner_signing_key_id
        || old_state.layout_generation != validation.expected_layout_generation
        || old_state.layout_digest != validation.expected_layout_digest
        || old_state.state_sequence != validation.expected_state_sequence
        || old_state_digest != validation.expected_old_state_digest
    {
        return Err(PrivateOramAppendFinalizerError::ContextMismatch(
            "old_state",
        ));
    }
    if input.hnsw_output.recovery_marker.writer_lease_digest
        != validation.expected_writer_lease_digest
        || input.result_output.recovery_marker.writer_lease_digest
            != validation.expected_writer_lease_digest
        || input.hnsw_output.recovery_marker.writer_fence != validation.expected_writer_fence
        || input.result_output.recovery_marker.writer_fence != validation.expected_writer_fence
    {
        return Err(PrivateOramAppendFinalizerError::ContextMismatch(
            "writer_lease",
        ));
    }

    validate_private_oram_append_hnsw_transaction_output_v2(manifest, &input.hnsw_output)?;
    validate_private_oram_append_result_transaction_output_v2(manifest, &input.result_output)?;
    let resealed = reseal_private_oram_append_paired_checkpoint_v2(
        checkpoint_key,
        PrivateOramAppendPairedCheckpointResealInputV2 {
            manifest,
            old_state,
            old_encrypted_checkpoint: input.old_encrypted_checkpoint,
            hnsw_output: &input.hnsw_output,
            result_output: &input.result_output,
            new_state_signed_at_unix: input.new_state_signed_at_unix,
        },
    )?;
    let new_state_bundle =
        package_private_oram_signed_state_v2(owner_key_pair, resealed.new_state.clone())?;

    let mut writebacks = Vec::with_capacity(manifest.indexes.len());
    let mut observed_read_transcripts = Vec::with_capacity(manifest.indexes.len());
    for index in &manifest.indexes {
        match index.kind() {
            PrivateOramIndexKindV2::Hnsw => {
                writebacks.push(input.hnsw_output.writeback.clone());
                observed_read_transcripts.push(input.hnsw_output.read_transcript.clone());
            }
            PrivateOramIndexKindV2::Result => {
                writebacks.push(input.result_output.writeback.clone());
                observed_read_transcripts.push(input.result_output.read_transcript.clone());
            }
        }
    }
    let mutation_id = input.hnsw_output.recovery_marker.mutation_id.clone();
    let point_operation_digest = private_oram_no_server_point_record_v1_digest(
        &manifest.collection_id,
        &manifest_digest,
        &mutation_id,
    )?;
    let mutation = PrivateOramAppendMutationV1 {
        version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
        mutation_id,
        collection_id: manifest.collection_id.clone(),
        manifest_digest: manifest_digest.clone(),
        layout_generation: old_state.layout_generation,
        writer_lease_digest: validation.expected_writer_lease_digest.to_string(),
        writer_fence: validation.expected_writer_fence,
        issued_at_unix: input.issued_at_unix,
        expires_at_unix: input.expires_at_unix,
        old_state: input.old_state_bundle.clone(),
        new_state: new_state_bundle,
        point_operation_kind: PrivateOramPointOperationKindV1::NoServerPointRecord,
        point_operation_digest,
        writebacks,
        owner_signing_key_id: manifest.owner_signing_key_id.clone(),
    };
    let mutation_bundle = package_private_oram_append_mutation_v1(owner_key_pair, mutation)?;
    validate_private_oram_append_mutation_v1(
        input.manifest_bundle,
        &mutation_bundle,
        PrivateOramAppendValidationContext {
            expected_collection_id: validation.expected_collection_id,
            expected_manifest_digest: validation.expected_manifest_digest,
            expected_owner_signing_key_id: validation.expected_owner_signing_key_id,
            expected_layout_generation: validation.expected_layout_generation,
            expected_layout_digest: validation.expected_layout_digest,
            expected_writer_lease_digest: validation.expected_writer_lease_digest,
            expected_writer_fence: validation.expected_writer_fence,
            expected_state_sequence: validation.expected_state_sequence,
            expected_old_state_digest: validation.expected_old_state_digest,
            expected_visible_point_record: None,
            observed_read_transcripts: &observed_read_transcripts,
            now_unix: validation.now_unix,
            max_mutation_ttl_secs: validation.max_mutation_ttl_secs,
            public_key: validation.public_key,
        },
    )?;

    let reopened = open_private_oram_append_client_checkpoint_v2(
        checkpoint_key,
        &resealed.encrypted_checkpoint,
        manifest,
        &mutation_bundle.mutation.new_state.state,
    )?;
    if reopened != resealed.checkpoint {
        return Err(PrivateOramAppendFinalizerError::CheckpointRoundTripMismatch);
    }

    Ok(PrivateOramAppendPairedFinalizationV1 {
        checkpoint: resealed.checkpoint,
        encrypted_checkpoint: resealed.encrypted_checkpoint,
        hnsw_output: input.hnsw_output,
        result_output: input.result_output,
        mutation_bundle,
    })
}
