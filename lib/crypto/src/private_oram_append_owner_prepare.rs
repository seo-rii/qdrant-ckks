use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::private_hnsw_client::{
    PrivateHnswBucketAeadBaseContext, PrivateHnswClientError, validate_private_hnsw_upload_bucket,
};
use crate::private_hnsw_oram::{PrivateHnswOramBucket, private_hnsw_oram_bucket_ciphertext_bytes};
use crate::private_oram_append_client::{
    PrivateOramAppendClientError, PrivateOramAppendMerklePatchProofV1,
    apply_private_oram_append_sparse_merkle_patch_v1,
};
use crate::private_oram_mutation::{
    PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS, PrivateOramAppendBucketRefV1,
    PrivateOramAppendMutationBundleV1, PrivateOramAppendReadTranscriptDigestInput,
    PrivateOramAppendValidationContext, PrivateOramImmutableIndexParamsV2,
    PrivateOramImmutableManifestBundleV2, PrivateOramIndexKindV2, PrivateOramMutationError,
    PrivateOramObservedReadTranscriptV1, PrivateOramVisiblePointRecordV1,
    private_oram_append_mutation_v1_digest, private_oram_append_read_transcript_v1,
    validate_private_oram_append_mutation_v1,
};
use crate::private_result_oram::{
    PrivateResultOramBucket, PrivateResultOramBucketAeadBaseContext, PrivateResultOramError,
    private_result_oram_bucket_ciphertext_bytes, validate_private_result_upload_bucket,
};

pub const PRIVATE_ORAM_APPEND_OWNER_PREPARE_V1_VERSION: u16 = 1;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateOramAppendOwnerPrepareError {
    #[error("private ORAM append owner prepare mutation contract failed")]
    Mutation(#[source] PrivateOramMutationError),
    #[error("private ORAM append owner prepare HNSW bucket validation failed")]
    Hnsw(#[source] PrivateHnswClientError),
    #[error("private ORAM append owner prepare result bucket validation failed")]
    Result(#[source] PrivateResultOramError),
    #[error("private ORAM append owner prepare Merkle transition failed")]
    Merkle(#[source] PrivateOramAppendClientError),
    #[error("private ORAM append owner prepare contract is invalid")]
    InvalidInput(&'static str),
}

impl Debug for PrivateOramAppendOwnerPrepareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mutation(_) => f.write_str("Mutation([redacted])"),
            Self::Hnsw(_) => f.write_str("Hnsw([redacted])"),
            Self::Result(_) => f.write_str("Result([redacted])"),
            Self::Merkle(_) => f.write_str("Merkle([redacted])"),
            Self::InvalidInput(field) => f.debug_tuple("InvalidInput").field(field).finish(),
        }
    }
}

impl From<PrivateOramMutationError> for PrivateOramAppendOwnerPrepareError {
    fn from(error: PrivateOramMutationError) -> Self {
        Self::Mutation(error)
    }
}

impl From<PrivateHnswClientError> for PrivateOramAppendOwnerPrepareError {
    fn from(error: PrivateHnswClientError) -> Self {
        Self::Hnsw(error)
    }
}

impl From<PrivateResultOramError> for PrivateOramAppendOwnerPrepareError {
    fn from(error: PrivateResultOramError) -> Self {
        Self::Result(error)
    }
}

impl From<PrivateOramAppendClientError> for PrivateOramAppendOwnerPrepareError {
    fn from(error: PrivateOramAppendClientError) -> Self {
        Self::Merkle(error)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "buckets",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PrivateOramAppendOwnerBucketBatchV1 {
    Hnsw(Vec<PrivateHnswOramBucket>),
    Result(Vec<PrivateResultOramBucket>),
}

impl PrivateOramAppendOwnerBucketBatchV1 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        match self {
            Self::Hnsw(_) => PrivateOramIndexKindV2::Hnsw,
            Self::Result(_) => PrivateOramIndexKindV2::Result,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Hnsw(buckets) => buckets.len(),
            Self::Result(buckets) => buckets.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Debug for PrivateOramAppendOwnerBucketBatchV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendOwnerBucketBatchV1")
            .field("kind", &self.kind())
            .field("bucket_count", &self.len())
            .field("buckets", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendOwnerIndexPrepareV1 {
    pub index_name: String,
    pub ordered_encrypted_buckets: PrivateOramAppendOwnerBucketBatchV1,
    pub merkle_patch_proof: PrivateOramAppendMerklePatchProofV1,
}

impl Debug for PrivateOramAppendOwnerIndexPrepareV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendOwnerIndexPrepareV1")
            .field("kind", &self.ordered_encrypted_buckets.kind())
            .field("index_name", &"[redacted]")
            .field(
                "ordered_encrypted_bucket_count",
                &self.ordered_encrypted_buckets.len(),
            )
            .field("merkle_patch_proof", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOramAppendOwnerPrepareV1 {
    pub version: u16,
    pub mutation_bundle: PrivateOramAppendMutationBundleV1,
    pub indexes: Vec<PrivateOramAppendOwnerIndexPrepareV1>,
}

impl Debug for PrivateOramAppendOwnerPrepareV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendOwnerPrepareV1")
            .field("version", &self.version)
            .field("mutation_bundle", &"[redacted]")
            .field("index_count", &self.indexes.len())
            .finish()
    }
}

struct PrivateOramServerReadEvidenceCapabilityV1;

#[derive(Clone)]
pub struct PrivateOramServerReadEvidenceRecorderV1 {
    capability: Arc<PrivateOramServerReadEvidenceCapabilityV1>,
}

impl PrivateOramServerReadEvidenceRecorderV1 {
    pub fn new() -> Self {
        Self {
            capability: Arc::new(PrivateOramServerReadEvidenceCapabilityV1),
        }
    }

    /// Records the exact read windows served by this trusted server session.
    ///
    /// The resulting evidence cannot be serialized and is accepted only with
    /// the same in-memory session recorder. Never record a client-carried claim.
    pub fn record(
        &self,
        input: PrivateOramAppendReadTranscriptDigestInput<'_>,
    ) -> Result<PrivateOramServerReadEvidenceV1, PrivateOramMutationError> {
        Ok(PrivateOramServerReadEvidenceV1 {
            capability: Arc::clone(&self.capability),
            transcript: private_oram_append_read_transcript_v1(input)?,
        })
    }

    fn issued(&self, evidence: &PrivateOramServerReadEvidenceV1) -> bool {
        Arc::ptr_eq(&self.capability, &evidence.capability)
    }
}

impl Default for PrivateOramServerReadEvidenceRecorderV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for PrivateOramServerReadEvidenceRecorderV1 {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.capability, &other.capability)
    }
}

impl Eq for PrivateOramServerReadEvidenceRecorderV1 {}

impl Debug for PrivateOramServerReadEvidenceRecorderV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramServerReadEvidenceRecorderV1")
            .field("capability", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
pub struct PrivateOramServerReadEvidenceV1 {
    capability: Arc<PrivateOramServerReadEvidenceCapabilityV1>,
    transcript: PrivateOramObservedReadTranscriptV1,
}

impl PartialEq for PrivateOramServerReadEvidenceV1 {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.capability, &other.capability) && self.transcript == other.transcript
    }
}

impl Eq for PrivateOramServerReadEvidenceV1 {}

impl Debug for PrivateOramServerReadEvidenceV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramServerReadEvidenceV1")
            .field("transcript", &self.transcript)
            .finish()
    }
}

impl PrivateOramServerReadEvidenceV1 {
    pub fn transcript(&self) -> &PrivateOramObservedReadTranscriptV1 {
        &self.transcript
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateOramAppendOwnerPrepareValidationContextV1<'a> {
    pub expected_collection_id: &'a str,
    pub expected_manifest_digest: &'a str,
    pub expected_owner_signing_key_id: &'a str,
    pub expected_layout_generation: u64,
    pub expected_layout_digest: &'a str,
    pub expected_writer_lease_digest: &'a str,
    pub expected_writer_fence: u64,
    pub expected_state_sequence: u64,
    pub expected_old_state_digest: &'a str,
    pub expected_visible_point_record: Option<PrivateOramVisiblePointRecordV1<'a>>,
    pub server_read_evidence_recorder: &'a PrivateOramServerReadEvidenceRecorderV1,
    pub server_read_evidence: &'a [PrivateOramServerReadEvidenceV1],
    pub now_unix: u64,
    pub max_mutation_ttl_secs: u64,
    pub public_key: &'a [u8],
}

impl Debug for PrivateOramAppendOwnerPrepareValidationContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendOwnerPrepareValidationContextV1")
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
            .field(
                "has_expected_visible_point_record",
                &self.expected_visible_point_record.is_some(),
            )
            .field(
                "server_read_evidence_count",
                &self.server_read_evidence.len(),
            )
            .field("server_read_evidence_recorder", &"[redacted]")
            .field("now_unix", &self.now_unix)
            .field("max_mutation_ttl_secs", &self.max_mutation_ttl_secs)
            .field("public_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum PrivateOramValidatedOwnerFinalBucketsV1 {
    Hnsw(Vec<PrivateHnswOramBucket>),
    Result(Vec<PrivateResultOramBucket>),
}

impl PrivateOramValidatedOwnerFinalBucketsV1 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        match self {
            Self::Hnsw(_) => PrivateOramIndexKindV2::Hnsw,
            Self::Result(_) => PrivateOramIndexKindV2::Result,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Hnsw(buckets) => buckets.len(),
            Self::Result(buckets) => buckets.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Debug for PrivateOramValidatedOwnerFinalBucketsV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedOwnerFinalBucketsV1")
            .field("kind", &self.kind())
            .field("bucket_count", &self.len())
            .field("buckets", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramValidatedOwnerIndexPrepareV1 {
    kind: PrivateOramIndexKindV2,
    index_name: String,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    new_root_hash: String,
    writeback_digest: String,
    read_transcript: PrivateOramObservedReadTranscriptV1,
    merkle_patch_proof: PrivateOramAppendMerklePatchProofV1,
    ordered_bucket_refs: Vec<PrivateOramAppendBucketRefV1>,
    final_bucket_refs: Vec<PrivateOramAppendBucketRefV1>,
    final_buckets: PrivateOramValidatedOwnerFinalBucketsV1,
}

impl Debug for PrivateOramValidatedOwnerIndexPrepareV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedOwnerIndexPrepareV1")
            .field("kind", &self.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("read_transcript", &self.read_transcript)
            .field("merkle_patch_proof", &"[redacted]")
            .field("ordered_bucket_count", &self.ordered_bucket_refs.len())
            .field("final_bucket_count", &self.final_bucket_refs.len())
            .field("final_buckets", &self.final_buckets)
            .finish()
    }
}

impl PrivateOramValidatedOwnerIndexPrepareV1 {
    pub const fn kind(&self) -> PrivateOramIndexKindV2 {
        self.kind
    }

    pub fn index_name(&self) -> &str {
        &self.index_name
    }

    pub const fn old_epoch(&self) -> u64 {
        self.old_epoch
    }

    pub const fn new_epoch(&self) -> u64 {
        self.new_epoch
    }

    pub fn old_root_hash(&self) -> &str {
        &self.old_root_hash
    }

    pub fn new_root_hash(&self) -> &str {
        &self.new_root_hash
    }

    pub fn writeback_digest(&self) -> &str {
        &self.writeback_digest
    }

    pub fn read_transcript(&self) -> &PrivateOramObservedReadTranscriptV1 {
        &self.read_transcript
    }

    pub fn merkle_patch_proof(&self) -> &PrivateOramAppendMerklePatchProofV1 {
        &self.merkle_patch_proof
    }

    pub fn ordered_bucket_refs(&self) -> &[PrivateOramAppendBucketRefV1] {
        &self.ordered_bucket_refs
    }

    pub fn final_bucket_refs(&self) -> &[PrivateOramAppendBucketRefV1] {
        &self.final_bucket_refs
    }

    pub fn final_buckets(&self) -> &PrivateOramValidatedOwnerFinalBucketsV1 {
        &self.final_buckets
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramValidatedOwnerPrepareV1 {
    mutation_bundle: PrivateOramAppendMutationBundleV1,
    mutation_digest: String,
    indexes: Vec<PrivateOramValidatedOwnerIndexPrepareV1>,
}

impl Debug for PrivateOramValidatedOwnerPrepareV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramValidatedOwnerPrepareV1")
            .field("prepare", &"[redacted]")
            .field("mutation_digest", &"[redacted]")
            .field("indexes", &self.indexes)
            .finish()
    }
}

impl PrivateOramValidatedOwnerPrepareV1 {
    pub fn mutation_bundle(&self) -> &PrivateOramAppendMutationBundleV1 {
        &self.mutation_bundle
    }

    pub fn mutation_digest(&self) -> &str {
        &self.mutation_digest
    }

    pub fn indexes(&self) -> &[PrivateOramValidatedOwnerIndexPrepareV1] {
        &self.indexes
    }
}

pub fn validate_private_oram_append_owner_prepare_v1(
    manifest_bundle: &PrivateOramImmutableManifestBundleV2,
    prepare: &PrivateOramAppendOwnerPrepareV1,
    context: PrivateOramAppendOwnerPrepareValidationContextV1<'_>,
) -> Result<PrivateOramValidatedOwnerPrepareV1, PrivateOramAppendOwnerPrepareError> {
    if prepare.version != PRIVATE_ORAM_APPEND_OWNER_PREPARE_V1_VERSION
        || prepare.indexes.len() != manifest_bundle.manifest.indexes.len()
        || prepare.indexes.is_empty()
    {
        return Err(PrivateOramAppendOwnerPrepareError::InvalidInput("prepare"));
    }
    let total_bucket_count = prepare.indexes.iter().try_fold(0usize, |count, index| {
        count.checked_add(index.ordered_encrypted_buckets.len())
    });
    if total_bucket_count
        .is_none_or(|count| count == 0 || count > PRIVATE_ORAM_APPEND_MAX_TOTAL_BUCKET_REFS)
    {
        return Err(PrivateOramAppendOwnerPrepareError::InvalidInput(
            "ordered_encrypted_buckets",
        ));
    }

    if context.server_read_evidence.len() != prepare.indexes.len()
        || context
            .server_read_evidence
            .iter()
            .any(|evidence| !context.server_read_evidence_recorder.issued(evidence))
    {
        return Err(PrivateOramAppendOwnerPrepareError::InvalidInput(
            "server_read_evidence",
        ));
    }
    let observed_read_transcripts = context
        .server_read_evidence
        .iter()
        .map(|evidence| evidence.transcript.clone())
        .collect::<Vec<_>>();
    validate_private_oram_append_mutation_v1(
        manifest_bundle,
        &prepare.mutation_bundle,
        PrivateOramAppendValidationContext {
            expected_collection_id: context.expected_collection_id,
            expected_manifest_digest: context.expected_manifest_digest,
            expected_owner_signing_key_id: context.expected_owner_signing_key_id,
            expected_layout_generation: context.expected_layout_generation,
            expected_layout_digest: context.expected_layout_digest,
            expected_writer_lease_digest: context.expected_writer_lease_digest,
            expected_writer_fence: context.expected_writer_fence,
            expected_state_sequence: context.expected_state_sequence,
            expected_old_state_digest: context.expected_old_state_digest,
            expected_visible_point_record: context.expected_visible_point_record,
            observed_read_transcripts: &observed_read_transcripts,
            now_unix: context.now_unix,
            max_mutation_ttl_secs: context.max_mutation_ttl_secs,
            public_key: context.public_key,
        },
    )?;

    let mutation = &prepare.mutation_bundle.mutation;
    let mut validated_indexes = Vec::with_capacity(prepare.indexes.len());
    for (((((manifest_index, old_index), new_index), writeback), index_prepare), read_transcript) in
        manifest_bundle
            .manifest
            .indexes
            .iter()
            .zip(&mutation.old_state.state.indexes)
            .zip(&mutation.new_state.state.indexes)
            .zip(&mutation.writebacks)
            .zip(&prepare.indexes)
            .zip(&observed_read_transcripts)
    {
        if index_prepare.ordered_encrypted_buckets.kind() != manifest_index.kind()
            || index_prepare.ordered_encrypted_buckets.kind() != writeback.kind
            || index_prepare.index_name != writeback.index_name
            || read_transcript.kind != writeback.kind
            || read_transcript.index_name != writeback.index_name
        {
            return Err(PrivateOramAppendOwnerPrepareError::InvalidInput(
                "index_prepare",
            ));
        }

        let final_buckets = match (
            &manifest_index.params,
            &index_prepare.ordered_encrypted_buckets,
        ) {
            (
                PrivateOramImmutableIndexParamsV2::Hnsw {
                    key_id,
                    rk_id,
                    rk_epoch,
                    oram,
                    ..
                },
                PrivateOramAppendOwnerBucketBatchV1::Hnsw(buckets),
            ) => {
                let expected_ciphertext_bytes = private_hnsw_oram_bucket_ciphertext_bytes(oram)
                    .map_err(|_| {
                        PrivateOramAppendOwnerPrepareError::InvalidInput("hnsw_buckets")
                    })?;
                let base_context = PrivateHnswBucketAeadBaseContext {
                    collection_id: &mutation.collection_id,
                    vector_name: &manifest_index.index_name,
                    key_id,
                    rk_id,
                    rk_epoch: *rk_epoch,
                };
                let mut final_by_bucket = BTreeMap::new();
                for (bucket, expected_ref) in buckets.iter().zip(&writeback.updated_buckets) {
                    validate_private_hnsw_upload_bucket(
                        base_context,
                        bucket,
                        new_index.index_epoch,
                        manifest_index.capacity.bucket_count,
                        expected_ciphertext_bytes,
                    )?;
                    if hnsw_bucket_ref(bucket) != *expected_ref {
                        return Err(PrivateOramAppendOwnerPrepareError::InvalidInput(
                            "hnsw_buckets",
                        ));
                    }
                    final_by_bucket.insert(bucket.bucket_id, bucket.clone());
                }
                PrivateOramValidatedOwnerFinalBucketsV1::Hnsw(
                    final_by_bucket.into_values().collect(),
                )
            }
            (
                PrivateOramImmutableIndexParamsV2::Result {
                    key_id,
                    rk_id,
                    rk_epoch,
                    oram,
                    ..
                },
                PrivateOramAppendOwnerBucketBatchV1::Result(buckets),
            ) => {
                let expected_ciphertext_bytes = private_result_oram_bucket_ciphertext_bytes(oram)?;
                let base_context = PrivateResultOramBucketAeadBaseContext {
                    collection_id: &mutation.collection_id,
                    key_id,
                    rk_id,
                    rk_epoch: *rk_epoch,
                };
                let mut final_by_bucket = BTreeMap::new();
                for (bucket, expected_ref) in buckets.iter().zip(&writeback.updated_buckets) {
                    validate_private_result_upload_bucket(
                        base_context,
                        bucket,
                        new_index.index_epoch,
                        manifest_index.capacity.bucket_count,
                        expected_ciphertext_bytes,
                    )?;
                    if result_bucket_ref(bucket) != *expected_ref {
                        return Err(PrivateOramAppendOwnerPrepareError::InvalidInput(
                            "result_buckets",
                        ));
                    }
                    final_by_bucket.insert(bucket.bucket_id, bucket.clone());
                }
                PrivateOramValidatedOwnerFinalBucketsV1::Result(
                    final_by_bucket.into_values().collect(),
                )
            }
            _ => {
                return Err(PrivateOramAppendOwnerPrepareError::InvalidInput(
                    "index_prepare",
                ));
            }
        };

        if index_prepare.ordered_encrypted_buckets.len() != writeback.updated_buckets.len() {
            return Err(PrivateOramAppendOwnerPrepareError::InvalidInput(
                "ordered_encrypted_buckets",
            ));
        }
        let expected_proof_bucket_ids = writeback
            .updated_buckets
            .iter()
            .map(|bucket| bucket.bucket_id)
            .collect::<BTreeSet<_>>();
        if index_prepare.merkle_patch_proof.leaves.len() != expected_proof_bucket_ids.len()
            || index_prepare
                .merkle_patch_proof
                .leaves
                .windows(2)
                .any(|pair| pair[0].bucket_id >= pair[1].bucket_id)
            || index_prepare
                .merkle_patch_proof
                .leaves
                .iter()
                .map(|leaf| leaf.bucket_id)
                .ne(expected_proof_bucket_ids.iter().copied())
        {
            return Err(PrivateOramAppendOwnerPrepareError::InvalidInput(
                "merkle_patch_proof",
            ));
        }
        let patch = apply_private_oram_append_sparse_merkle_patch_v1(
            old_index.index_epoch,
            &old_index.root_hash,
            manifest_index.capacity.bucket_count,
            &index_prepare.merkle_patch_proof,
            &writeback.updated_buckets,
        )?;
        let final_bucket_refs = match &final_buckets {
            PrivateOramValidatedOwnerFinalBucketsV1::Hnsw(buckets) => {
                buckets.iter().map(hnsw_bucket_ref).collect::<Vec<_>>()
            }
            PrivateOramValidatedOwnerFinalBucketsV1::Result(buckets) => {
                buckets.iter().map(result_bucket_ref).collect::<Vec<_>>()
            }
        };
        if patch.new_root_hash != new_index.root_hash || patch.final_buckets != final_bucket_refs {
            return Err(PrivateOramAppendOwnerPrepareError::InvalidInput(
                "merkle_patch_proof",
            ));
        }
        validated_indexes.push(PrivateOramValidatedOwnerIndexPrepareV1 {
            kind: writeback.kind,
            index_name: writeback.index_name.clone(),
            old_epoch: old_index.index_epoch,
            new_epoch: new_index.index_epoch,
            old_root_hash: old_index.root_hash.clone(),
            new_root_hash: new_index.root_hash.clone(),
            writeback_digest: new_index.last_writeback_digest.clone(),
            read_transcript: read_transcript.clone(),
            merkle_patch_proof: index_prepare.merkle_patch_proof.clone(),
            ordered_bucket_refs: writeback.updated_buckets.clone(),
            final_bucket_refs,
            final_buckets,
        });
    }

    Ok(PrivateOramValidatedOwnerPrepareV1 {
        mutation_digest: private_oram_append_mutation_v1_digest(mutation)?,
        mutation_bundle: prepare.mutation_bundle.clone(),
        indexes: validated_indexes,
    })
}

fn hnsw_bucket_ref(bucket: &PrivateHnswOramBucket) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id: bucket.bucket_id,
        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        bucket_commitment: bucket.bucket_commitment.clone(),
    }
}

fn result_bucket_ref(bucket: &PrivateResultOramBucket) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id: bucket.bucket_id,
        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        bucket_commitment: bucket.bucket_commitment.clone(),
    }
}
