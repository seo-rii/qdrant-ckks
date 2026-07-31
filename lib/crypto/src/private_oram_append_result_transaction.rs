use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};

use crate::private_hnsw_oram::ResultPrivacyMode;
use crate::private_oram_append_client::{
    PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION, PrivateOramAppendClientCheckpointV2,
    PrivateOramAppendClientIndexCheckpointV2, PrivateOramAppendMerklePatchLeafV1,
    PrivateOramAppendMerklePatchProofV1, PrivateOramAppendMerkleSiblingPositionV1,
    PrivateOramAppendResultRecordV2, apply_private_oram_append_sparse_merkle_patch_v1,
    private_oram_append_client_checkpoint_plaintext_v3_digest,
    private_oram_append_result_client_state_v3_digest,
    validate_private_oram_append_client_checkpoint_v2,
};
use crate::private_oram_append_transaction::{
    PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION, PrivateOramAppendRecoveryMarkerV3,
    PrivateOramAppendRecoveryPhaseV2, PrivateOramAppendTransactionError, update_digest_domain_v3,
};
use crate::private_oram_mutation::{
    PrivateOramAppendBucketRefV1, PrivateOramAppendIndexWritebackV1,
    PrivateOramAppendReadTranscriptDigestInput, PrivateOramAppendReadWindowV1,
    PrivateOramAppendWritebackDigestInput, PrivateOramImmutableIndexParamsV2,
    PrivateOramImmutableManifestV2, PrivateOramIndexKindV2, PrivateOramObservedReadTranscriptV1,
    PrivateOramSignedStateV2, private_oram_append_read_transcript_v1,
    private_oram_append_writeback_v1_digest, private_oram_immutable_manifest_v2_digest,
    private_oram_signed_state_v2_digest,
};
use crate::private_result_oram::{
    PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION, PrivateResultOramBucket,
    PrivateResultOramBucketAeadBaseContext, PrivateResultOramBucketCommitmentContext,
    PrivateResultOramBucketValidationContext, PrivateResultOramClientConfig,
    PrivateResultOramClientKeys, PrivateResultOramClientState,
    PrivateResultOramClientStateSnapshot, PrivateResultOramEncryptedBucketBatch,
    PrivateResultOramMerkleProof, PrivateResultOramPayloadBlockPlaintext,
    PrivateResultOramPlaintextBucket, decode_private_result_oram_leaf_label,
    encode_private_result_oram_bucket_plaintext, encode_private_result_oram_leaf_label,
    encode_private_result_oram_payload_block, evict_private_result_oram_path,
    open_private_result_oram_verified_bucket_batch, private_result_oram_bucket_ciphertext_bytes,
    private_result_oram_bucket_commitment, private_result_oram_bucket_count,
    private_result_oram_bucket_ids_for_leaf, seal_private_result_oram_plaintext_bucket,
    validate_private_result_oram_bucket_shape,
};

pub const PRIVATE_ORAM_APPEND_RESULT_ATTEMPT_V3_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-result-attempt/v3";
pub const PRIVATE_ORAM_APPEND_RESULT_PREPARED_COMMIT_V3_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-result-prepared-commit/v3";
pub const PRIVATE_ORAM_APPEND_RESULT_PREPARED_COMMIT_V4_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-result-prepared-commit/v4";
pub const PRIVATE_ORAM_APPEND_RESULT_WORKING_ARTIFACT_V3_DIGEST_DOMAIN: &str =
    "qdrant-sec/private-oram-append-result-working-artifact/v3";

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramAppendResultPointV2 {
    pub payload_fetch_token: [u8; 32],
    pub point_token: [u8; 32],
    pub payload: Vec<u8>,
    pub initial_leaf: u64,
}

impl Debug for PrivateOramAppendResultPointV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendResultPointV2")
            .field("payload_fetch_token", &"[redacted]")
            .field("point_token", &"[redacted]")
            .field("payload_len", &"[redacted]")
            .field("initial_leaf", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramAppendResultTransactionPlanV2 {
    pub index_name: String,
    pub mutation_id: String,
    pub writer_lease_digest: String,
    pub writer_fence: u64,
    pub paths_per_window: u32,
    pub padding_leaves: Vec<u64>,
}

impl Debug for PrivateOramAppendResultTransactionPlanV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendResultTransactionPlanV2")
            .field("index_name", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("writer_lease_digest", &"[redacted]")
            .field("writer_fence", &self.writer_fence)
            .field("paths_per_window", &self.paths_per_window)
            .field("padding_leaf_count", &self.padding_leaves.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramAppendResultAttemptDigestInputV3<'a> {
    pub manifest_digest: &'a str,
    pub old_state_digest: &'a str,
    pub checkpoint: &'a PrivateOramAppendClientCheckpointV2,
    pub point: &'a PrivateOramAppendResultPointV2,
    pub plan: &'a PrivateOramAppendResultTransactionPlanV2,
}

impl Debug for PrivateOramAppendResultAttemptDigestInputV3<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendResultAttemptDigestInputV3")
            .field("manifest_digest", &"[redacted]")
            .field("old_state_digest", &"[redacted]")
            .field("checkpoint", &"[redacted]")
            .field("point", &"[redacted]")
            .field("plan", &self.plan)
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramAppendResultPreparedCommitDigestInputV3<'a> {
    pub attempt_digest: &'a str,
    pub result_record: &'a PrivateOramAppendResultRecordV2,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub read_transcript_digest: &'a str,
    pub writeback_digest: &'a str,
    pub next_client_state: &'a PrivateResultOramClientStateSnapshot,
}

impl Debug for PrivateOramAppendResultPreparedCommitDigestInputV3<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendResultPreparedCommitDigestInputV3")
            .field("attempt_digest", &"[redacted]")
            .field("result_record", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("read_transcript_digest", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("next_client_state", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateOramAppendResultPreparedCommitDigestInputV4<'a> {
    pub attempt_digest: &'a str,
    pub source_checkpoint_digest: &'a str,
    pub result_record: &'a PrivateOramAppendResultRecordV2,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub read_transcript_digest: &'a str,
    pub writeback_digest: &'a str,
    pub next_client_state: &'a PrivateResultOramClientStateSnapshot,
}

impl Debug for PrivateOramAppendResultPreparedCommitDigestInputV4<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendResultPreparedCommitDigestInputV4")
            .field("attempt_digest", &"[redacted]")
            .field("source_checkpoint_digest", &"[redacted]")
            .field("result_record", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("read_transcript_digest", &"[redacted]")
            .field("writeback_digest", &"[redacted]")
            .field("next_client_state", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramAppendResultReadRequestV2 {
    pub window: PrivateOramAppendReadWindowV1,
    pub recovery_marker: PrivateOramAppendRecoveryMarkerV3,
}

impl Debug for PrivateOramAppendResultReadRequestV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendResultReadRequestV2")
            .field("window", &self.window)
            .field("recovery_marker", &self.recovery_marker)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateOramAppendResultTransactionOutputV2 {
    pub source_checkpoint_digest: String,
    pub result_record: PrivateOramAppendResultRecordV2,
    pub read_transcript: PrivateOramObservedReadTranscriptV1,
    pub writeback: PrivateOramAppendIndexWritebackV1,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub next_client_state: PrivateResultOramClientStateSnapshot,
    pub ordered_encrypted_buckets: Vec<PrivateResultOramBucket>,
    pub final_encrypted_buckets: Vec<PrivateResultOramBucket>,
    pub merkle_patch_proof: PrivateOramAppendMerklePatchProofV1,
    pub recovery_marker: PrivateOramAppendRecoveryMarkerV3,
}

impl Debug for PrivateOramAppendResultTransactionOutputV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendResultTransactionOutputV2")
            .field("source_checkpoint_digest", &"[redacted]")
            .field("result_record", &"[redacted]")
            .field("read_transcript", &self.read_transcript)
            .field("writeback", &self.writeback)
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("next_client_state", &self.next_client_state)
            .field(
                "ordered_encrypted_bucket_count",
                &self.ordered_encrypted_buckets.len(),
            )
            .field(
                "final_encrypted_bucket_count",
                &self.final_encrypted_buckets.len(),
            )
            .field(
                "merkle_patch_proof_leaf_count",
                &self.merkle_patch_proof.leaves.len(),
            )
            .field("recovery_marker", &self.recovery_marker)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateOramAppendResultTransactionProgressV2 {
    pub accepted_read_path_count: u32,
    pub accepted_window_count: u32,
    pub prepared_write_bucket_count: usize,
    pub plaintext_overlay_bucket_count: usize,
    pub client_stash_block_count: usize,
}

#[derive(Clone, Copy)]
enum PrivateOramAppendResultPathActionV2 {
    Insert { leaf: u64 },
    Padding { leaf: u64 },
}

impl PrivateOramAppendResultPathActionV2 {
    const fn leaf(self) -> u64 {
        match self {
            Self::Insert { leaf } | Self::Padding { leaf } => leaf,
        }
    }
}

enum PrivateOramAppendResultTransactionStatusV2 {
    Ready,
    MarkerPrepared {
        marker: Box<PrivateOramAppendRecoveryMarkerV3>,
        window: PrivateOramAppendReadWindowV1,
        actions: Vec<PrivateOramAppendResultPathActionV2>,
    },
    Awaiting {
        window: PrivateOramAppendReadWindowV1,
        actions: Vec<PrivateOramAppendResultPathActionV2>,
    },
    Poisoned,
}

pub struct PrivateOramAppendResultTransactionV2 {
    manifest: PrivateOramImmutableManifestV2,
    plan: PrivateOramAppendResultTransactionPlanV2,
    manifest_digest: String,
    old_state_digest: String,
    source_checkpoint_digest: String,
    attempt_digest: String,
    result_record: PrivateOramAppendResultRecordV2,
    new_block: PrivateResultOramPayloadBlockPlaintext,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    bucket_count: u64,
    fixed_read_path_count: u32,
    fixed_write_bucket_count: usize,
    max_ciphertext_encoded_len: usize,
    max_client_stash_blocks: usize,
    config: PrivateResultOramClientConfig,
    key_id: String,
    rk_id: String,
    rk_epoch: u64,
    working_state: PrivateResultOramClientState,
    status: PrivateOramAppendResultTransactionStatusV2,
    actions: VecDeque<PrivateOramAppendResultPathActionV2>,
    accepted_windows: Vec<PrivateOramAppendReadWindowV1>,
    requested_window_count: u32,
    accepted_path_count: u32,
    inserted: bool,
    plaintext_overlay: BTreeMap<u64, PrivateResultOramPlaintextBucket>,
    proof_leaves: BTreeMap<u64, PrivateOramAppendMerklePatchLeafV1>,
    ordered_refs: Vec<PrivateOramAppendBucketRefV1>,
    ordered_encrypted_buckets: Vec<PrivateResultOramBucket>,
    final_encrypted_buckets: BTreeMap<u64, PrivateResultOramBucket>,
}

#[derive(Clone)]
struct PrivateOramAppendResultWindowSnapshotV2 {
    working_state: PrivateResultOramClientState,
    accepted_windows: Vec<PrivateOramAppendReadWindowV1>,
    accepted_path_count: u32,
    inserted: bool,
    plaintext_overlay: BTreeMap<u64, PrivateResultOramPlaintextBucket>,
    proof_leaves: BTreeMap<u64, PrivateOramAppendMerklePatchLeafV1>,
    ordered_refs: Vec<PrivateOramAppendBucketRefV1>,
    ordered_encrypted_buckets: Vec<PrivateResultOramBucket>,
    final_encrypted_buckets: BTreeMap<u64, PrivateResultOramBucket>,
}

impl Debug for PrivateOramAppendResultTransactionV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramAppendResultTransactionV2")
            .field("collection_id", &"[redacted]")
            .field("index_name", &"[redacted]")
            .field("mutation_id", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("fixed_read_path_count", &self.fixed_read_path_count)
            .field("accepted_path_count", &self.accepted_path_count)
            .field("requested_window_count", &self.requested_window_count)
            .field("accepted_window_count", &self.accepted_windows.len())
            .field("pending_action_count", &self.actions.len())
            .field("inserted", &self.inserted)
            .field("requires_recovery", &self.requires_recovery())
            .field("poisoned", &self.is_poisoned())
            .finish()
    }
}

impl PrivateOramAppendResultTransactionV2 {
    pub fn begin(
        manifest: &PrivateOramImmutableManifestV2,
        old_state: &PrivateOramSignedStateV2,
        checkpoint: &PrivateOramAppendClientCheckpointV2,
        point: PrivateOramAppendResultPointV2,
        plan: PrivateOramAppendResultTransactionPlanV2,
    ) -> Result<Self, PrivateOramAppendTransactionError> {
        validate_private_oram_append_client_checkpoint_v2(checkpoint, manifest, old_state)?;
        validate_base64url_32(&plan.mutation_id, "mutation_id")?;
        validate_base64url_32(&plan.writer_lease_digest, "writer_lease_digest")?;
        if plan.writer_fence == 0 || plan.paths_per_window == 0 {
            return Err(PrivateOramAppendTransactionError::InvalidInput("plan"));
        }
        if manifest.result_privacy != ResultPrivacyMode::PrivatePayloadOramRequired {
            return Err(PrivateOramAppendTransactionError::UnsupportedTopology);
        }
        let hnsw_count = manifest
            .indexes
            .iter()
            .filter(|index| index.kind() == PrivateOramIndexKindV2::Hnsw)
            .count();
        let result_offsets = manifest
            .indexes
            .iter()
            .enumerate()
            .filter_map(|(offset, index)| {
                (index.kind() == PrivateOramIndexKindV2::Result).then_some(offset)
            })
            .collect::<Vec<_>>();
        if hnsw_count != 1 || result_offsets.len() != 1 || manifest.indexes.len() != 2 {
            return Err(PrivateOramAppendTransactionError::UnsupportedTopology);
        }
        let index_offset = result_offsets[0];
        let manifest_index = &manifest.indexes[index_offset];
        if manifest_index.index_name != plan.index_name {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "index_name",
            ));
        }
        let (key_id, rk_id, rk_epoch, oram, checkpoint_state) =
            match (&manifest_index.params, &checkpoint.indexes[index_offset]) {
                (
                    PrivateOramImmutableIndexParamsV2::Result {
                        key_id,
                        rk_id,
                        rk_epoch,
                        oram,
                        ..
                    },
                    PrivateOramAppendClientIndexCheckpointV2::Result {
                        index_name, state, ..
                    },
                ) if index_name == &plan.index_name => {
                    (key_id.clone(), rk_id.clone(), *rk_epoch, oram, state)
                }
                _ => return Err(PrivateOramAppendTransactionError::UnsupportedTopology),
            };
        let state_index = &old_state.indexes[index_offset];
        let old_epoch = state_index.index_epoch;
        let new_epoch =
            old_epoch
                .checked_add(1)
                .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                    "index_epoch",
                ))?;
        if state_index.logical_count >= manifest_index.capacity.logical_capacity
            || state_index.dummy_count == 0
        {
            return Err(PrivateOramAppendTransactionError::Client(
                crate::private_oram_append_client::PrivateOramAppendClientError::AppendCapacityExhausted,
            ));
        }
        let bucket_count = private_result_oram_bucket_count(oram.tree_height)?;
        let expected_ciphertext_bytes = private_result_oram_bucket_ciphertext_bytes(oram)?;
        let max_ciphertext_encoded_len = expected_ciphertext_bytes
            .checked_mul(4)
            .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                "ciphertext_size",
            ))?
            .div_ceil(3);
        if bucket_count != manifest_index.capacity.bucket_count {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "bucket_count",
            ));
        }
        let fixed_read_path_count = manifest_index.capacity.fixed_append_read_path_count;
        if fixed_read_path_count == 0
            || !fixed_read_path_count.is_multiple_of(plan.paths_per_window)
            || plan.paths_per_window > fixed_read_path_count
            || plan.paths_per_window != oram.path_batch_size
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "paths_per_window",
            ));
        }
        let expected_write_count = usize::try_from(fixed_read_path_count)
            .ok()
            .and_then(|count| {
                usize::try_from(oram.tree_height)
                    .ok()
                    .and_then(|height| count.checked_mul(height + 1))
            })
            .ok_or(PrivateOramAppendTransactionError::InvalidInput(
                "fixed_write_bucket_count",
            ))?;
        let fixed_write_bucket_count = usize::try_from(
            manifest_index.capacity.fixed_append_write_bucket_count,
        )
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("fixed_write_bucket_count"))?;
        if fixed_write_bucket_count != expected_write_count
            || plan.padding_leaves.len()
                != usize::try_from(fixed_read_path_count - 1).map_err(|_| {
                    PrivateOramAppendTransactionError::InvalidInput("padding_leaves")
                })?
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "fixed_leaf_schedule",
            ));
        }
        let config = PrivateResultOramClientConfig {
            tree_height: oram.tree_height,
            bucket_size: usize::try_from(oram.bucket_size)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("oram"))?,
            block_size_bytes: usize::try_from(oram.block_size_bytes)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("oram"))?,
        };
        for leaf in plan
            .padding_leaves
            .iter()
            .chain(std::iter::once(&point.initial_leaf))
        {
            encode_private_result_oram_leaf_label(*leaf, config.tree_height)?;
        }
        let paths_per_window = usize::try_from(plan.paths_per_window)
            .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("paths_per_window"))?;
        let fixed_leaves = std::iter::once(point.initial_leaf)
            .chain(plan.padding_leaves.iter().copied())
            .collect::<Vec<_>>();
        if fixed_leaves.chunks(paths_per_window).any(|window| {
            window.len() != paths_per_window
                || window.iter().copied().collect::<BTreeSet<_>>().len() != window.len()
        }) {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "duplicate_window_path",
            ));
        }
        if point.payload_fetch_token == [0; 32] || point.point_token == [0; 32] {
            return Err(PrivateOramAppendTransactionError::InvalidInput("point"));
        }
        let payload_fetch_token = BASE64URL_NOPAD.encode(&point.payload_fetch_token);
        let point_token = BASE64URL_NOPAD.encode(&point.point_token);
        if checkpoint.points.iter().any(|record| {
            record.point_token == point_token
                || record.payload_fetch_token.as_deref() == Some(payload_fetch_token.as_str())
        }) {
            return Err(PrivateOramAppendTransactionError::Client(
                crate::private_oram_append_client::PrivateOramAppendClientError::DuplicateCheckpointRecord,
            ));
        }
        let new_block = PrivateResultOramPayloadBlockPlaintext {
            version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
            payload_fetch_token: point.payload_fetch_token,
            point_token: point.point_token,
            payload: point.payload.clone(),
            deleted: false,
            generation: 1,
        };
        encode_private_result_oram_payload_block(&new_block, config.block_size_bytes)?;
        let working_state = PrivateResultOramClientState::from_snapshot(checkpoint_state)?;
        let mut preflight_state = working_state.clone();
        preflight_state.insert_new_stash_block(new_block.clone(), point.initial_leaf, config)?;
        let max_client_stash_blocks =
            usize::try_from(manifest_index.capacity.max_client_stash_blocks).map_err(|_| {
                PrivateOramAppendTransactionError::InvalidInput("max_client_stash_blocks")
            })?;
        if working_state.stash_len() > max_client_stash_blocks
            || preflight_state.stash_len() > max_client_stash_blocks
        {
            return Err(PrivateOramAppendTransactionError::StashBoundExceeded);
        }

        let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
        let old_state_digest = private_oram_signed_state_v2_digest(old_state)?;
        let source_checkpoint_digest =
            private_oram_append_client_checkpoint_plaintext_v3_digest(checkpoint)?;
        let attempt_digest = private_oram_append_result_attempt_v3_digest(
            PrivateOramAppendResultAttemptDigestInputV3 {
                manifest_digest: &manifest_digest,
                old_state_digest: &old_state_digest,
                checkpoint,
                point: &point,
                plan: &plan,
            },
        )?;
        let result_record = PrivateOramAppendResultRecordV2 {
            payload_fetch_token,
            point_token,
            generation: 1,
        };
        let mut actions = VecDeque::with_capacity(
            usize::try_from(fixed_read_path_count)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("actions"))?,
        );
        actions.push_back(PrivateOramAppendResultPathActionV2::Insert {
            leaf: point.initial_leaf,
        });
        actions.extend(
            plan.padding_leaves
                .iter()
                .copied()
                .map(|leaf| PrivateOramAppendResultPathActionV2::Padding { leaf }),
        );
        Ok(Self {
            manifest: manifest.clone(),
            plan,
            manifest_digest,
            old_state_digest,
            source_checkpoint_digest,
            attempt_digest,
            result_record,
            new_block,
            old_epoch,
            new_epoch,
            old_root_hash: state_index.root_hash.clone(),
            bucket_count,
            fixed_read_path_count,
            fixed_write_bucket_count,
            max_ciphertext_encoded_len,
            max_client_stash_blocks,
            config,
            key_id,
            rk_id,
            rk_epoch,
            working_state,
            status: PrivateOramAppendResultTransactionStatusV2::Ready,
            actions,
            accepted_windows: Vec::new(),
            requested_window_count: 0,
            accepted_path_count: 0,
            inserted: false,
            plaintext_overlay: BTreeMap::new(),
            proof_leaves: BTreeMap::new(),
            ordered_refs: Vec::new(),
            ordered_encrypted_buckets: Vec::new(),
            final_encrypted_buckets: BTreeMap::new(),
        })
    }

    pub fn prepare_next_read_window(
        &mut self,
    ) -> Result<Option<PrivateOramAppendRecoveryMarkerV3>, PrivateOramAppendTransactionError> {
        match self.status {
            PrivateOramAppendResultTransactionStatusV2::MarkerPrepared { .. }
            | PrivateOramAppendResultTransactionStatusV2::Awaiting { .. } => {
                return Err(PrivateOramAppendTransactionError::WindowPending);
            }
            PrivateOramAppendResultTransactionStatusV2::Poisoned => {
                return Err(PrivateOramAppendTransactionError::RecoveryRequired);
            }
            PrivateOramAppendResultTransactionStatusV2::Ready => {}
        }
        if self.actions.is_empty() {
            if self.accepted_path_count == self.fixed_read_path_count && self.inserted {
                return Ok(None);
            }
            if self.requires_recovery() {
                self.status = PrivateOramAppendResultTransactionStatusV2::Poisoned;
            }
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        let paths_per_window = usize::try_from(self.plan.paths_per_window)
            .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("paths_per_window"))?;
        if self.actions.len() < paths_per_window {
            self.status = PrivateOramAppendResultTransactionStatusV2::Poisoned;
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        let actions = self
            .actions
            .iter()
            .take(paths_per_window)
            .copied()
            .collect::<Vec<_>>();
        let paths = actions
            .iter()
            .map(|action| {
                encode_private_result_oram_leaf_label(action.leaf(), self.config.tree_height)
                    .map_err(Into::into)
            })
            .collect::<Result<Vec<_>, PrivateOramAppendTransactionError>>();
        let paths = match paths {
            Ok(paths) => paths,
            Err(error) => return self.fail_prepare(error),
        };
        if paths.iter().collect::<BTreeSet<_>>().len() != paths.len() {
            return self.fail_prepare(PrivateOramAppendTransactionError::InvalidInput(
                "duplicate_window_path",
            ));
        }
        let sequence = self.requested_window_count;
        let window = PrivateOramAppendReadWindowV1 { sequence, paths };
        let requested_window_count = self.requested_window_count.checked_add(1).ok_or(
            PrivateOramAppendTransactionError::InvalidInput("requested_window_count"),
        )?;
        let marker = self.build_recovery_marker(
            requested_window_count,
            PrivateOramAppendRecoveryPhaseV2::WindowIssued,
        );
        self.status = PrivateOramAppendResultTransactionStatusV2::MarkerPrepared {
            marker: Box::new(marker.clone()),
            window,
            actions,
        };
        Ok(Some(marker))
    }

    pub fn next_read_window(
        &mut self,
        persisted_marker: &PrivateOramAppendRecoveryMarkerV3,
    ) -> Result<PrivateOramAppendResultReadRequestV2, PrivateOramAppendTransactionError> {
        let pending = std::mem::replace(
            &mut self.status,
            PrivateOramAppendResultTransactionStatusV2::Ready,
        );
        let PrivateOramAppendResultTransactionStatusV2::MarkerPrepared {
            marker,
            window,
            actions,
        } = pending
        else {
            let error = match pending {
                PrivateOramAppendResultTransactionStatusV2::Poisoned => {
                    PrivateOramAppendTransactionError::RecoveryRequired
                }
                PrivateOramAppendResultTransactionStatusV2::Awaiting { .. } => {
                    PrivateOramAppendTransactionError::WindowPending
                }
                PrivateOramAppendResultTransactionStatusV2::Ready => {
                    PrivateOramAppendTransactionError::WindowNotPending
                }
                PrivateOramAppendResultTransactionStatusV2::MarkerPrepared { .. } => unreachable!(),
            };
            self.status = pending;
            return Err(error);
        };
        if marker.as_ref() != persisted_marker {
            self.status = PrivateOramAppendResultTransactionStatusV2::MarkerPrepared {
                marker,
                window,
                actions,
            };
            return Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch);
        }
        self.actions.drain(..actions.len());
        self.requested_window_count = marker.requested_window_count;
        self.status = PrivateOramAppendResultTransactionStatusV2::Awaiting {
            window: window.clone(),
            actions,
        };
        Ok(PrivateOramAppendResultReadRequestV2 {
            window,
            recovery_marker: *marker,
        })
    }

    pub fn accept_verified_window(
        &mut self,
        sequence: u32,
        keys: &PrivateResultOramClientKeys,
        encrypted_batch: &PrivateResultOramEncryptedBucketBatch,
    ) -> Result<(), PrivateOramAppendTransactionError> {
        if matches!(
            self.status,
            PrivateOramAppendResultTransactionStatusV2::Poisoned
        ) {
            return Err(PrivateOramAppendTransactionError::RecoveryRequired);
        }
        let pending = std::mem::replace(
            &mut self.status,
            PrivateOramAppendResultTransactionStatusV2::Poisoned,
        );
        let PrivateOramAppendResultTransactionStatusV2::Awaiting { window, actions } = pending
        else {
            self.status = pending;
            return Err(PrivateOramAppendTransactionError::WindowNotPending);
        };
        if window.sequence != sequence {
            return Err(PrivateOramAppendTransactionError::WindowSequenceMismatch);
        }
        let snapshot = self.window_snapshot();
        if let Err(error) =
            self.accept_verified_window_inner(&window, &actions, keys, encrypted_batch)
        {
            self.restore_window_snapshot(snapshot);
            return Err(error);
        }
        self.status = PrivateOramAppendResultTransactionStatusV2::Ready;
        Ok(())
    }

    pub fn finalize(
        self,
    ) -> Result<PrivateOramAppendResultTransactionOutputV2, PrivateOramAppendTransactionError> {
        if matches!(
            self.status,
            PrivateOramAppendResultTransactionStatusV2::Poisoned
        ) {
            return Err(PrivateOramAppendTransactionError::RecoveryRequired);
        }
        if !matches!(
            self.status,
            PrivateOramAppendResultTransactionStatusV2::Ready
        ) || !self.actions.is_empty()
            || self.accepted_path_count != self.fixed_read_path_count
            || self.ordered_refs.len() != self.fixed_write_bucket_count
            || self.ordered_encrypted_buckets.len() != self.fixed_write_bucket_count
            || !self.inserted
        {
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        let mut recovery_marker = self.build_recovery_marker(
            self.requested_window_count,
            PrivateOramAppendRecoveryPhaseV2::PreparedCommit,
        );
        let proof = PrivateOramAppendMerklePatchProofV1 {
            version: PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION,
            index_epoch: self.old_epoch,
            old_root_hash: self.old_root_hash.clone(),
            bucket_count: self.bucket_count,
            leaves: self.proof_leaves.into_values().collect(),
        };
        let patch = apply_private_oram_append_sparse_merkle_patch_v1(
            self.old_epoch,
            &self.old_root_hash,
            self.bucket_count,
            &proof,
            &self.ordered_refs,
        )?;
        let final_encrypted_buckets = self
            .final_encrypted_buckets
            .into_values()
            .collect::<Vec<_>>();
        let final_refs = final_encrypted_buckets
            .iter()
            .map(bucket_ref)
            .collect::<Vec<_>>();
        if final_refs != patch.final_buckets {
            return Err(PrivateOramAppendTransactionError::ProofSetMismatch);
        }
        let read_transcript =
            private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
                collection_id: &self.manifest.collection_id,
                manifest_digest: &self.manifest_digest,
                mutation_id: &self.plan.mutation_id,
                old_state_digest: &self.old_state_digest,
                writer_lease_digest: &self.plan.writer_lease_digest,
                writer_fence: self.plan.writer_fence,
                paths_per_window: self.plan.paths_per_window,
                tree_height: self.config.tree_height,
                kind: PrivateOramIndexKindV2::Result,
                index_name: &self.plan.index_name,
                windows: &self.accepted_windows,
            })?;
        if read_transcript.read_path_count != self.fixed_read_path_count {
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        let writeback = PrivateOramAppendIndexWritebackV1 {
            kind: PrivateOramIndexKindV2::Result,
            index_name: self.plan.index_name.clone(),
            read_path_count: read_transcript.read_path_count,
            read_transcript_digest: read_transcript.transcript_digest.clone(),
            updated_buckets: self.ordered_refs,
        };
        let next_client_state = self.working_state.to_snapshot(self.config.tree_height)?;
        let writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &self.manifest.collection_id,
                manifest_digest: &self.manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: self.old_epoch,
                new_epoch: self.new_epoch,
                old_root_hash: &self.old_root_hash,
                new_root_hash: &patch.new_root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            })?;
        recovery_marker.prepared_commit_digest =
            Some(private_oram_append_result_prepared_commit_v4_digest(
                PrivateOramAppendResultPreparedCommitDigestInputV4 {
                    attempt_digest: &self.attempt_digest,
                    source_checkpoint_digest: &self.source_checkpoint_digest,
                    result_record: &self.result_record,
                    old_epoch: self.old_epoch,
                    new_epoch: self.new_epoch,
                    old_root_hash: &self.old_root_hash,
                    new_root_hash: &patch.new_root_hash,
                    read_transcript_digest: &read_transcript.transcript_digest,
                    writeback_digest: &writeback_digest,
                    next_client_state: &next_client_state,
                },
            )?);
        let manifest = self.manifest.clone();
        let output = PrivateOramAppendResultTransactionOutputV2 {
            source_checkpoint_digest: self.source_checkpoint_digest,
            result_record: self.result_record,
            read_transcript,
            writeback,
            old_epoch: self.old_epoch,
            new_epoch: self.new_epoch,
            old_root_hash: self.old_root_hash,
            new_root_hash: patch.new_root_hash,
            next_client_state,
            ordered_encrypted_buckets: self.ordered_encrypted_buckets,
            final_encrypted_buckets,
            merkle_patch_proof: proof,
            recovery_marker,
        };
        validate_private_oram_append_result_transaction_output_v2(&manifest, &output)?;
        Ok(output)
    }

    pub fn requires_recovery(&self) -> bool {
        self.requested_window_count != 0
    }

    pub fn is_poisoned(&self) -> bool {
        matches!(
            self.status,
            PrivateOramAppendResultTransactionStatusV2::Poisoned
        )
    }

    pub fn progress(&self) -> PrivateOramAppendResultTransactionProgressV2 {
        PrivateOramAppendResultTransactionProgressV2 {
            accepted_read_path_count: self.accepted_path_count,
            accepted_window_count: u32::try_from(self.accepted_windows.len()).unwrap_or(u32::MAX),
            prepared_write_bucket_count: self.ordered_refs.len(),
            plaintext_overlay_bucket_count: self.plaintext_overlay.len(),
            client_stash_block_count: self.working_state.stash_len(),
        }
    }

    pub fn working_client_state_digest(&self) -> Result<String, PrivateOramAppendTransactionError> {
        let snapshot = self.working_state.to_snapshot(self.config.tree_height)?;
        Ok(private_oram_append_result_client_state_v3_digest(
            &snapshot,
        )?)
    }

    pub fn working_artifact_digest(&self) -> Result<String, PrivateOramAppendTransactionError> {
        let mut hasher = Sha256::new();
        update_digest_domain_v3(
            &mut hasher,
            PRIVATE_ORAM_APPEND_RESULT_WORKING_ARTIFACT_V3_DIGEST_DOMAIN.as_bytes(),
        )?;
        update_digest_bytes(&mut hasher, self.working_client_state_digest()?.as_bytes())?;
        update_digest_len(&mut hasher, self.accepted_windows.len())?;
        for window in &self.accepted_windows {
            hasher.update(window.sequence.to_be_bytes());
            update_digest_len(&mut hasher, window.paths.len())?;
            for path in &window.paths {
                update_digest_bytes(&mut hasher, path.as_bytes())?;
            }
        }
        hasher.update(self.accepted_path_count.to_be_bytes());
        hasher.update([u8::from(self.inserted)]);

        update_digest_len(&mut hasher, self.plaintext_overlay.len())?;
        for (bucket_id, bucket) in &self.plaintext_overlay {
            hasher.update(bucket_id.to_be_bytes());
            update_digest_bytes(
                &mut hasher,
                &encode_private_result_oram_bucket_plaintext(bucket, self.config)?,
            )?;
        }

        update_digest_len(&mut hasher, self.proof_leaves.len())?;
        for (bucket_id, leaf) in &self.proof_leaves {
            hasher.update(bucket_id.to_be_bytes());
            hasher.update(leaf.bucket_id.to_be_bytes());
            update_digest_bytes(&mut hasher, leaf.old_commitment.as_bytes())?;
            update_digest_len(&mut hasher, leaf.siblings.len())?;
            for sibling in &leaf.siblings {
                hasher.update(sibling.level.to_be_bytes());
                hasher.update([match sibling.position {
                    PrivateOramAppendMerkleSiblingPositionV1::Left => 1,
                    PrivateOramAppendMerkleSiblingPositionV1::Right => 2,
                }]);
                update_digest_bytes(&mut hasher, sibling.hash.as_bytes())?;
            }
        }

        update_digest_len(&mut hasher, self.ordered_refs.len())?;
        for bucket in &self.ordered_refs {
            hasher.update(bucket.bucket_id.to_be_bytes());
            update_digest_bytes(&mut hasher, bucket.ciphertext_sha256.as_bytes())?;
            update_digest_bytes(&mut hasher, bucket.bucket_commitment.as_bytes())?;
        }
        update_digest_len(&mut hasher, self.ordered_encrypted_buckets.len())?;
        for bucket in &self.ordered_encrypted_buckets {
            hasher.update(bucket.version.to_be_bytes());
            hasher.update(bucket.bucket_id.to_be_bytes());
            hasher.update(bucket.index_epoch.to_be_bytes());
            update_digest_bytes(&mut hasher, bucket.ciphertext.as_bytes())?;
            update_digest_bytes(&mut hasher, bucket.ciphertext_sha256.as_bytes())?;
            update_digest_bytes(&mut hasher, bucket.bucket_commitment.as_bytes())?;
        }
        update_digest_len(&mut hasher, self.final_encrypted_buckets.len())?;
        for (bucket_id, bucket) in &self.final_encrypted_buckets {
            hasher.update(bucket_id.to_be_bytes());
            hasher.update(bucket.version.to_be_bytes());
            hasher.update(bucket.bucket_id.to_be_bytes());
            hasher.update(bucket.index_epoch.to_be_bytes());
            update_digest_bytes(&mut hasher, bucket.ciphertext.as_bytes())?;
            update_digest_bytes(&mut hasher, bucket.ciphertext_sha256.as_bytes())?;
            update_digest_bytes(&mut hasher, bucket.bucket_commitment.as_bytes())?;
        }
        Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
    }

    pub fn recovery_marker(&self) -> Option<PrivateOramAppendRecoveryMarkerV3> {
        self.requires_recovery().then(|| {
            let phase = if self.is_poisoned() {
                PrivateOramAppendRecoveryPhaseV2::Poisoned
            } else {
                PrivateOramAppendRecoveryPhaseV2::WindowIssued
            };
            self.build_recovery_marker(self.requested_window_count, phase)
        })
    }

    fn build_recovery_marker(
        &self,
        requested_window_count: u32,
        phase: PrivateOramAppendRecoveryPhaseV2,
    ) -> PrivateOramAppendRecoveryMarkerV3 {
        PrivateOramAppendRecoveryMarkerV3 {
            version: PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION,
            collection_id: self.manifest.collection_id.clone(),
            manifest_digest: self.manifest_digest.clone(),
            mutation_id: self.plan.mutation_id.clone(),
            old_state_digest: self.old_state_digest.clone(),
            attempt_digest: self.attempt_digest.clone(),
            index_kind: PrivateOramIndexKindV2::Result,
            index_name: self.plan.index_name.clone(),
            writer_lease_digest: self.plan.writer_lease_digest.clone(),
            writer_fence: self.plan.writer_fence,
            requested_window_count,
            accepted_window_count: u32::try_from(self.accepted_windows.len()).unwrap_or(u32::MAX),
            observed_read_path_count: requested_window_count
                .saturating_mul(self.plan.paths_per_window),
            phase,
            prepared_commit_digest: None,
        }
    }

    fn fail_prepare<T>(
        &mut self,
        error: PrivateOramAppendTransactionError,
    ) -> Result<T, PrivateOramAppendTransactionError> {
        if self.requires_recovery() {
            self.status = PrivateOramAppendResultTransactionStatusV2::Poisoned;
        }
        Err(error)
    }

    fn window_snapshot(&self) -> PrivateOramAppendResultWindowSnapshotV2 {
        PrivateOramAppendResultWindowSnapshotV2 {
            working_state: self.working_state.clone(),
            accepted_windows: self.accepted_windows.clone(),
            accepted_path_count: self.accepted_path_count,
            inserted: self.inserted,
            plaintext_overlay: self.plaintext_overlay.clone(),
            proof_leaves: self.proof_leaves.clone(),
            ordered_refs: self.ordered_refs.clone(),
            ordered_encrypted_buckets: self.ordered_encrypted_buckets.clone(),
            final_encrypted_buckets: self.final_encrypted_buckets.clone(),
        }
    }

    fn restore_window_snapshot(&mut self, snapshot: PrivateOramAppendResultWindowSnapshotV2) {
        self.working_state = snapshot.working_state;
        self.accepted_windows = snapshot.accepted_windows;
        self.accepted_path_count = snapshot.accepted_path_count;
        self.inserted = snapshot.inserted;
        self.plaintext_overlay = snapshot.plaintext_overlay;
        self.proof_leaves = snapshot.proof_leaves;
        self.ordered_refs = snapshot.ordered_refs;
        self.ordered_encrypted_buckets = snapshot.ordered_encrypted_buckets;
        self.final_encrypted_buckets = snapshot.final_encrypted_buckets;
    }

    fn accept_verified_window_inner(
        &mut self,
        window: &PrivateOramAppendReadWindowV1,
        actions: &[PrivateOramAppendResultPathActionV2],
        keys: &PrivateResultOramClientKeys,
        encrypted_batch: &PrivateResultOramEncryptedBucketBatch,
    ) -> Result<(), PrivateOramAppendTransactionError> {
        if actions.len() != window.paths.len()
            || window.paths.len()
                != usize::try_from(self.plan.paths_per_window)
                    .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("window"))?
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput("window"));
        }
        let expected_bucket_ids = actions
            .iter()
            .copied()
            .map(PrivateOramAppendResultPathActionV2::leaf)
            .map(|leaf| private_result_oram_bucket_ids_for_leaf(leaf, self.config.tree_height))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if encrypted_batch.buckets.len() != expected_bucket_ids.len()
            || encrypted_batch
                .buckets
                .iter()
                .zip(&expected_bucket_ids)
                .any(|(bucket, expected_bucket_id)| bucket.bucket_id != *expected_bucket_id)
            || encrypted_batch.index_epoch != self.old_epoch
            || encrypted_batch.root_hash != self.old_root_hash
            || encrypted_batch.bucket_count != self.bucket_count
        {
            return Err(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch);
        }
        if encrypted_batch
            .buckets
            .iter()
            .any(|bucket| bucket.ciphertext.len() > self.max_ciphertext_encoded_len)
        {
            return Err(PrivateOramAppendTransactionError::Result(
                crate::private_result_oram::PrivateResultOramError::BucketOversized,
            ));
        }
        let collection_id = self.manifest.collection_id.clone();
        let key_id = self.key_id.clone();
        let rk_id = self.rk_id.clone();
        let base_context = PrivateResultOramBucketAeadBaseContext {
            collection_id: &collection_id,
            key_id: &key_id,
            rk_id: &rk_id,
            rk_epoch: self.rk_epoch,
        };
        let opened = open_private_result_oram_verified_bucket_batch(
            keys,
            base_context,
            self.config,
            self.old_epoch,
            &self.old_root_hash,
            self.bucket_count,
            &encrypted_batch.proof_value,
            &encrypted_batch.buckets,
        )?;
        let old_plaintext_by_id = opened
            .into_iter()
            .map(|bucket| (bucket.bucket_id, bucket))
            .collect::<BTreeMap<_, _>>();
        let expected_unique_bucket_ids =
            expected_bucket_ids.iter().copied().collect::<BTreeSet<_>>();
        if old_plaintext_by_id.len() != expected_unique_bucket_ids.len()
            || !expected_unique_bucket_ids
                .iter()
                .all(|bucket_id| old_plaintext_by_id.contains_key(bucket_id))
        {
            return Err(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch);
        }
        let proof =
            serde_json::from_str::<PrivateResultOramMerkleProof>(&encrypted_batch.proof_value)
                .map_err(|_| PrivateOramAppendTransactionError::ProofSetMismatch)?;
        self.merge_proof(&PrivateOramAppendMerklePatchProofV1::from(&proof))?;

        for action in actions {
            let leaf = action.leaf();
            let path_bucket_ids =
                private_result_oram_bucket_ids_for_leaf(leaf, self.config.tree_height)?;
            let path_buckets = path_bucket_ids
                .iter()
                .map(|bucket_id| {
                    self.plaintext_overlay
                        .get(bucket_id)
                        .or_else(|| old_plaintext_by_id.get(bucket_id))
                        .cloned()
                        .ok_or(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let writeback_buckets = match action {
                PrivateOramAppendResultPathActionV2::Insert { leaf } => {
                    if self.inserted {
                        return Err(PrivateOramAppendTransactionError::InvalidInput("insert"));
                    }
                    self.working_state.insert_new_stash_block(
                        self.new_block.clone(),
                        *leaf,
                        self.config,
                    )?;
                    let eviction = evict_private_result_oram_path(
                        &mut self.working_state,
                        self.config,
                        *leaf,
                        &path_buckets,
                    )?;
                    self.inserted = true;
                    eviction.writeback_buckets
                }
                PrivateOramAppendResultPathActionV2::Padding { leaf } => {
                    evict_private_result_oram_path(
                        &mut self.working_state,
                        self.config,
                        *leaf,
                        &path_buckets,
                    )?
                    .writeback_buckets
                }
            };
            if self.working_state.stash_len() > self.max_client_stash_blocks {
                return Err(PrivateOramAppendTransactionError::StashBoundExceeded);
            }
            self.seal_ordered_writeback(keys, base_context, &path_bucket_ids, writeback_buckets)?;
        }
        self.accepted_path_count = self
            .accepted_path_count
            .checked_add(
                u32::try_from(actions.len())
                    .map_err(|_| PrivateOramAppendTransactionError::Incomplete)?,
            )
            .ok_or(PrivateOramAppendTransactionError::Incomplete)?;
        self.accepted_windows.push(window.clone());
        Ok(())
    }

    fn seal_ordered_writeback(
        &mut self,
        keys: &PrivateResultOramClientKeys,
        base_context: PrivateResultOramBucketAeadBaseContext<'_>,
        expected_bucket_ids: &[u64],
        writeback_buckets: Vec<PrivateResultOramPlaintextBucket>,
    ) -> Result<(), PrivateOramAppendTransactionError> {
        if writeback_buckets.len() != expected_bucket_ids.len()
            || writeback_buckets
                .iter()
                .zip(expected_bucket_ids)
                .any(|(bucket, expected_id)| bucket.bucket_id != *expected_id)
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "writeback_buckets",
            ));
        }
        for plaintext_bucket in writeback_buckets {
            let encrypted_bucket = seal_private_result_oram_plaintext_bucket(
                keys,
                base_context,
                self.new_epoch,
                &plaintext_bucket,
                self.config,
            )?;
            self.plaintext_overlay
                .insert(plaintext_bucket.bucket_id, plaintext_bucket);
            self.ordered_refs.push(bucket_ref(&encrypted_bucket));
            self.final_encrypted_buckets
                .insert(encrypted_bucket.bucket_id, encrypted_bucket.clone());
            self.ordered_encrypted_buckets.push(encrypted_bucket);
        }
        if self.ordered_refs.len() > self.fixed_write_bucket_count {
            return Err(PrivateOramAppendTransactionError::Incomplete);
        }
        Ok(())
    }

    fn merge_proof(
        &mut self,
        proof: &PrivateOramAppendMerklePatchProofV1,
    ) -> Result<(), PrivateOramAppendTransactionError> {
        if proof.version != PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION
            || proof.index_epoch != self.old_epoch
            || proof.old_root_hash != self.old_root_hash
            || proof.bucket_count != self.bucket_count
        {
            return Err(PrivateOramAppendTransactionError::ProofSetMismatch);
        }
        for leaf in &proof.leaves {
            if let Some(existing) = self.proof_leaves.get(&leaf.bucket_id) {
                if existing != leaf {
                    return Err(PrivateOramAppendTransactionError::ProofSetMismatch);
                }
            } else {
                self.proof_leaves.insert(leaf.bucket_id, leaf.clone());
            }
        }
        Ok(())
    }
}

pub fn validate_private_oram_append_result_transaction_output_v2(
    manifest: &PrivateOramImmutableManifestV2,
    output: &PrivateOramAppendResultTransactionOutputV2,
) -> Result<(), PrivateOramAppendTransactionError> {
    let manifest_digest = private_oram_immutable_manifest_v2_digest(manifest)?;
    let result_indexes = manifest
        .indexes
        .iter()
        .filter(|index| index.kind() == PrivateOramIndexKindV2::Result)
        .collect::<Vec<_>>();
    if manifest.result_privacy != ResultPrivacyMode::PrivatePayloadOramRequired
        || result_indexes.len() != 1
        || manifest.indexes.len() != 2
    {
        return Err(PrivateOramAppendTransactionError::UnsupportedTopology);
    }
    let manifest_index = result_indexes[0];
    let PrivateOramImmutableIndexParamsV2::Result {
        key_id,
        rk_id,
        rk_epoch,
        oram,
        ..
    } = &manifest_index.params
    else {
        return Err(PrivateOramAppendTransactionError::UnsupportedTopology);
    };
    let marker = &output.recovery_marker;
    let window_count = output
        .read_transcript
        .read_path_count
        .checked_div(oram.path_batch_size)
        .ok_or(PrivateOramAppendTransactionError::InvalidInput(
            "read_transcript",
        ))?;
    if marker.version != PRIVATE_ORAM_APPEND_RECOVERY_MARKER_V3_VERSION
        || marker.collection_id != manifest.collection_id
        || marker.manifest_digest != manifest_digest
        || marker.index_kind != PrivateOramIndexKindV2::Result
        || marker.index_name != manifest_index.index_name
        || marker.phase != PrivateOramAppendRecoveryPhaseV2::PreparedCommit
        || marker.requested_window_count != window_count
        || marker.accepted_window_count != window_count
        || marker.observed_read_path_count != output.read_transcript.read_path_count
        || marker.prepared_commit_digest.is_none()
        || output.new_epoch
            != output.old_epoch.checked_add(1).ok_or(
                PrivateOramAppendTransactionError::InvalidInput("index_epoch"),
            )?
        || output.writeback.kind != PrivateOramIndexKindV2::Result
        || output.writeback.index_name != manifest_index.index_name
        || output.writeback.read_path_count != manifest_index.capacity.fixed_append_read_path_count
        || output.writeback.read_path_count != output.read_transcript.read_path_count
        || output.writeback.read_transcript_digest != output.read_transcript.transcript_digest
        || output.writeback.updated_buckets.len()
            != usize::try_from(manifest_index.capacity.fixed_append_write_bucket_count).map_err(
                |_| PrivateOramAppendTransactionError::InvalidInput("fixed_write_bucket_count"),
            )?
        || output.ordered_encrypted_buckets.len() != output.writeback.updated_buckets.len()
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "prepared_output",
        ));
    }
    validate_base64url_32(&marker.attempt_digest, "attempt_digest")?;
    validate_base64url_32(&output.source_checkpoint_digest, "source_checkpoint_digest")?;
    validate_base64url_32(&output.old_root_hash, "old_root_hash")?;
    validate_base64url_32(&output.new_root_hash, "new_root_hash")?;

    let paths_per_window = oram.path_batch_size;
    let paths_per_window_usize = usize::try_from(paths_per_window)
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("paths_per_window"))?;
    if output.read_transcript.collection_id != manifest.collection_id
        || output.read_transcript.manifest_digest != manifest_digest
        || output.read_transcript.mutation_id != marker.mutation_id
        || output.read_transcript.old_state_digest != marker.old_state_digest
        || output.read_transcript.writer_lease_digest != marker.writer_lease_digest
        || output.read_transcript.writer_fence != marker.writer_fence
        || output.read_transcript.kind != PrivateOramIndexKindV2::Result
        || output.read_transcript.index_name != manifest_index.index_name
        || output.read_transcript.paths_per_window != paths_per_window
        || output.read_transcript.tree_height != oram.tree_height
        || output.read_transcript.ordered_leaf_labels.len()
            != usize::try_from(output.read_transcript.read_path_count)
                .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("read_path_count"))?
        || !output
            .read_transcript
            .ordered_leaf_labels
            .len()
            .is_multiple_of(paths_per_window_usize)
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "read_transcript",
        ));
    }
    let windows = output
        .read_transcript
        .ordered_leaf_labels
        .chunks(paths_per_window_usize)
        .enumerate()
        .map(|(sequence, paths)| {
            Ok(PrivateOramAppendReadWindowV1 {
                sequence: u32::try_from(sequence).map_err(|_| {
                    PrivateOramAppendTransactionError::InvalidInput("read_transcript")
                })?,
                paths: paths.to_vec(),
            })
        })
        .collect::<Result<Vec<_>, PrivateOramAppendTransactionError>>()?;
    let expected_transcript =
        private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
            collection_id: &manifest.collection_id,
            manifest_digest: &manifest_digest,
            mutation_id: &marker.mutation_id,
            old_state_digest: &marker.old_state_digest,
            writer_lease_digest: &marker.writer_lease_digest,
            writer_fence: marker.writer_fence,
            paths_per_window,
            tree_height: oram.tree_height,
            kind: PrivateOramIndexKindV2::Result,
            index_name: &manifest_index.index_name,
            windows: &windows,
        })?;
    if expected_transcript != output.read_transcript {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "read_transcript",
        ));
    }
    let expected_ordered_bucket_ids = output
        .read_transcript
        .ordered_leaf_labels
        .iter()
        .map(|leaf_label| {
            decode_private_result_oram_leaf_label(leaf_label, oram.tree_height)
                .map_err(PrivateOramAppendTransactionError::from)
        })
        .map(|leaf| {
            leaf.and_then(|leaf| {
                private_result_oram_bucket_ids_for_leaf(leaf, oram.tree_height)
                    .map_err(PrivateOramAppendTransactionError::from)
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if expected_ordered_bucket_ids.len() != output.writeback.updated_buckets.len()
        || output
            .writeback
            .updated_buckets
            .iter()
            .zip(&expected_ordered_bucket_ids)
            .any(|(bucket, expected_bucket_id)| bucket.bucket_id != *expected_bucket_id)
        || output
            .ordered_encrypted_buckets
            .iter()
            .zip(&expected_ordered_bucket_ids)
            .any(|(bucket, expected_bucket_id)| bucket.bucket_id != *expected_bucket_id)
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "ordered_bucket_frames",
        ));
    }

    let bucket_count = private_result_oram_bucket_count(oram.tree_height)?;
    if bucket_count != manifest_index.capacity.bucket_count {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "bucket_count",
        ));
    }
    let expected_ciphertext_bytes = private_result_oram_bucket_ciphertext_bytes(oram)?;
    let validation_context = PrivateResultOramBucketValidationContext {
        expected_index_epoch: output.new_epoch,
        bucket_count,
        max_ciphertext_bytes: expected_ciphertext_bytes,
    };
    let mut expected_final = BTreeMap::new();
    for (bucket, expected_ref) in output
        .ordered_encrypted_buckets
        .iter()
        .zip(&output.writeback.updated_buckets)
    {
        validate_private_result_oram_bucket_shape(bucket, validation_context)?;
        let ciphertext = BASE64URL_NOPAD
            .decode(bucket.ciphertext.as_bytes())
            .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("ciphertext"))?;
        if ciphertext.len() != expected_ciphertext_bytes
            || bucket_ref(bucket) != *expected_ref
            || private_result_oram_bucket_commitment(
                PrivateResultOramBucketCommitmentContext {
                    collection_id: &manifest.collection_id,
                    key_id,
                    rk_id,
                    rk_epoch: *rk_epoch,
                    bucket_id: bucket.bucket_id,
                    index_epoch: output.new_epoch,
                },
                &bucket.ciphertext_sha256,
            )? != bucket.bucket_commitment
        {
            return Err(PrivateOramAppendTransactionError::InvalidInput(
                "encrypted_buckets",
            ));
        }
        expected_final.insert(bucket.bucket_id, bucket.clone());
    }
    if output
        .final_encrypted_buckets
        .windows(2)
        .any(|pair| pair[0].bucket_id >= pair[1].bucket_id)
        || output.final_encrypted_buckets != expected_final.into_values().collect::<Vec<_>>()
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "final_encrypted_buckets",
        ));
    }
    let patch = apply_private_oram_append_sparse_merkle_patch_v1(
        output.old_epoch,
        &output.old_root_hash,
        bucket_count,
        &output.merkle_patch_proof,
        &output.writeback.updated_buckets,
    )?;
    let final_refs = output
        .final_encrypted_buckets
        .iter()
        .map(bucket_ref)
        .collect::<Vec<_>>();
    if patch.new_root_hash != output.new_root_hash || patch.final_buckets != final_refs {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "merkle_patch_proof",
        ));
    }

    let payload_fetch_token = BASE64URL_NOPAD
        .decode(output.result_record.payload_fetch_token.as_bytes())
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(PrivateOramAppendTransactionError::InvalidInput(
            "result_record",
        ))?;
    validate_base64url_32(&output.result_record.point_token, "result_record")?;
    if output.result_record.generation != 1 {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "result_record",
        ));
    }
    let next_state = PrivateResultOramClientState::from_snapshot(&output.next_client_state)?;
    if next_state.position(&payload_fetch_token).is_none()
        || output.next_client_state.tree_height != oram.tree_height
        || output.next_client_state.stash.iter().any(|block| {
            block.payload_fetch_token == payload_fetch_token
                && (BASE64URL_NOPAD.encode(&block.point_token) != output.result_record.point_token
                    || block.generation != output.result_record.generation)
        })
    {
        return Err(PrivateOramAppendTransactionError::InvalidInput(
            "next_client_state",
        ));
    }

    let writeback_digest =
        private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
            collection_id: &manifest.collection_id,
            manifest_digest: &manifest_digest,
            kind: output.writeback.kind,
            index_name: &output.writeback.index_name,
            old_epoch: output.old_epoch,
            new_epoch: output.new_epoch,
            old_root_hash: &output.old_root_hash,
            new_root_hash: &output.new_root_hash,
            read_path_count: output.writeback.read_path_count,
            read_transcript_digest: &output.writeback.read_transcript_digest,
            updated_buckets: &output.writeback.updated_buckets,
        })?;
    let prepared_digest = private_oram_append_result_prepared_commit_v4_digest(
        PrivateOramAppendResultPreparedCommitDigestInputV4 {
            attempt_digest: &marker.attempt_digest,
            source_checkpoint_digest: &output.source_checkpoint_digest,
            result_record: &output.result_record,
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
        return Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch);
    }
    Ok(())
}

pub fn private_oram_append_result_attempt_v3_digest(
    input: PrivateOramAppendResultAttemptDigestInputV3<'_>,
) -> Result<String, PrivateOramAppendTransactionError> {
    let checkpoint_digest =
        private_oram_append_client_checkpoint_plaintext_v3_digest(input.checkpoint)?;
    let point = input.point;
    let plan = input.plan;
    let mut hasher = Sha256::new();
    update_digest_domain_v3(
        &mut hasher,
        PRIVATE_ORAM_APPEND_RESULT_ATTEMPT_V3_DIGEST_DOMAIN.as_bytes(),
    )?;
    update_digest_bytes(&mut hasher, input.manifest_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, input.old_state_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, checkpoint_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, plan.index_name.as_bytes())?;
    update_digest_bytes(&mut hasher, plan.mutation_id.as_bytes())?;
    update_digest_bytes(&mut hasher, plan.writer_lease_digest.as_bytes())?;
    hasher.update(plan.writer_fence.to_be_bytes());
    hasher.update(plan.paths_per_window.to_be_bytes());
    update_digest_bytes(&mut hasher, &point.payload_fetch_token)?;
    update_digest_bytes(&mut hasher, &point.point_token)?;
    update_digest_bytes(&mut hasher, &point.payload)?;
    hasher.update(point.initial_leaf.to_be_bytes());
    update_digest_len(&mut hasher, plan.padding_leaves.len())?;
    for leaf in &plan.padding_leaves {
        hasher.update(leaf.to_be_bytes());
    }
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_append_result_prepared_commit_v3_digest(
    input: PrivateOramAppendResultPreparedCommitDigestInputV3<'_>,
) -> Result<String, PrivateOramAppendTransactionError> {
    let next_client_state_digest =
        private_oram_append_result_client_state_v3_digest(input.next_client_state)?;
    let mut hasher = Sha256::new();
    update_digest_domain_v3(
        &mut hasher,
        PRIVATE_ORAM_APPEND_RESULT_PREPARED_COMMIT_V3_DIGEST_DOMAIN.as_bytes(),
    )?;
    update_digest_bytes(&mut hasher, input.attempt_digest.as_bytes())?;
    update_digest_bytes(
        &mut hasher,
        input.result_record.payload_fetch_token.as_bytes(),
    )?;
    update_digest_bytes(&mut hasher, input.result_record.point_token.as_bytes())?;
    hasher.update(input.result_record.generation.to_be_bytes());
    hasher.update(input.old_epoch.to_be_bytes());
    hasher.update(input.new_epoch.to_be_bytes());
    update_digest_bytes(&mut hasher, input.old_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.new_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.read_transcript_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, input.writeback_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, next_client_state_digest.as_bytes())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_append_result_prepared_commit_v4_digest(
    input: PrivateOramAppendResultPreparedCommitDigestInputV4<'_>,
) -> Result<String, PrivateOramAppendTransactionError> {
    validate_base64url_32(input.source_checkpoint_digest, "source_checkpoint_digest")?;
    let next_client_state_digest =
        private_oram_append_result_client_state_v3_digest(input.next_client_state)?;
    let mut hasher = Sha256::new();
    update_digest_domain_v3(
        &mut hasher,
        PRIVATE_ORAM_APPEND_RESULT_PREPARED_COMMIT_V4_DIGEST_DOMAIN.as_bytes(),
    )?;
    update_digest_bytes(&mut hasher, input.attempt_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, input.source_checkpoint_digest.as_bytes())?;
    update_digest_bytes(
        &mut hasher,
        input.result_record.payload_fetch_token.as_bytes(),
    )?;
    update_digest_bytes(&mut hasher, input.result_record.point_token.as_bytes())?;
    hasher.update(input.result_record.generation.to_be_bytes());
    hasher.update(input.old_epoch.to_be_bytes());
    hasher.update(input.new_epoch.to_be_bytes());
    update_digest_bytes(&mut hasher, input.old_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.new_root_hash.as_bytes())?;
    update_digest_bytes(&mut hasher, input.read_transcript_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, input.writeback_digest.as_bytes())?;
    update_digest_bytes(&mut hasher, next_client_state_digest.as_bytes())?;
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn update_digest_bytes(
    hasher: &mut Sha256,
    value: &[u8],
) -> Result<(), PrivateOramAppendTransactionError> {
    update_digest_len(hasher, value.len())?;
    hasher.update(value);
    Ok(())
}

fn update_digest_len(
    hasher: &mut Sha256,
    len: usize,
) -> Result<(), PrivateOramAppendTransactionError> {
    let len = u64::try_from(len)
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput("digest_input"))?;
    hasher.update(len.to_be_bytes());
    Ok(())
}

fn bucket_ref(bucket: &PrivateResultOramBucket) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id: bucket.bucket_id,
        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        bucket_commitment: bucket.bucket_commitment.clone(),
    }
}

fn validate_base64url_32(
    value: &str,
    field: &'static str,
) -> Result<(), PrivateOramAppendTransactionError> {
    if value.len() != 43 {
        return Err(PrivateOramAppendTransactionError::InvalidInput(field));
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateOramAppendTransactionError::InvalidInput(field))?;
    if decoded.len() != 32 {
        return Err(PrivateOramAppendTransactionError::InvalidInput(field));
    }
    Ok(())
}
