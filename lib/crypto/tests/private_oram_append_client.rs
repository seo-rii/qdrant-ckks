use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::*;
use sha2::{Digest, Sha256};

fn digest(byte: u8) -> String {
    BASE64URL_NOPAD.encode(&[byte; 32])
}

fn merkle_levels(commitments: &[String]) -> Vec<Vec<[u8; 32]>> {
    let mut leaves = commitments
        .iter()
        .map(|commitment| {
            BASE64URL_NOPAD
                .decode(commitment.as_bytes())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<_>>();
    leaves.resize(leaves.len().next_power_of_two(), [0; 32]);
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let next = levels
            .last()
            .unwrap()
            .chunks_exact(2)
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update([1]);
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                hasher.finalize().into()
            })
            .collect();
        levels.push(next);
    }
    levels
}

fn hnsw_merkle_proof(
    index_epoch: u64,
    commitments: &[String],
    bucket_ids: &[u64],
) -> PrivateHnswOramMerkleProof {
    let levels = merkle_levels(commitments);
    PrivateHnswOramMerkleProof {
        kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
        index_epoch,
        root_hash: BASE64URL_NOPAD.encode(&levels.last().unwrap()[0]),
        bucket_count: commitments.len().try_into().unwrap(),
        leaves: bucket_ids
            .iter()
            .map(|bucket_id| {
                let mut index = usize::try_from(*bucket_id).unwrap();
                let siblings = levels[..levels.len() - 1]
                    .iter()
                    .enumerate()
                    .map(|(level, hashes)| {
                        let sibling_index = index ^ 1;
                        let sibling = PrivateHnswOramMerkleSibling {
                            level: level.try_into().unwrap(),
                            position: if index % 2 == 0 {
                                PrivateHnswMerkleSiblingPosition::Right
                            } else {
                                PrivateHnswMerkleSiblingPosition::Left
                            },
                            hash: BASE64URL_NOPAD.encode(&hashes[sibling_index]),
                        };
                        index /= 2;
                        sibling
                    })
                    .collect();
                PrivateHnswOramMerkleProofLeaf {
                    bucket_id: *bucket_id,
                    leaf_hash: commitments[usize::try_from(*bucket_id).unwrap()].clone(),
                    siblings,
                }
            })
            .collect(),
    }
}

fn append_bucket(bucket_id: u64, byte: u8) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id,
        ciphertext_sha256: digest(byte.wrapping_add(64)),
        bucket_commitment: digest(byte),
    }
}

fn checkpoint_candidate_block() -> PrivateHnswNodeBlockPlaintext {
    PrivateHnswNodeBlockPlaintext {
        version: 1,
        node_id: [2; 32],
        point_token: [3; 32],
        level_mask: 1,
        vector_encoding: PrivateHnswVectorEncoding::F32Le,
        vector: [1.0f32, 0.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect(),
        neighbors: vec![],
        neighbor_levels: vec![],
        deleted: false,
        generation: 0,
        payload_fetch_token: Some([4; 32]),
    }
}

fn oram() -> OramParams {
    OramParams {
        kind: OramKind::PathOram,
        bucket_size: 2,
        block_size_bytes: 512,
        tree_height: 2,
        path_batch_size: 1,
    }
}

fn capacity() -> PrivateOramIndexCapacityV2 {
    PrivateOramIndexCapacityV2 {
        bucket_count: 7,
        logical_capacity: 4,
        reserved_physical_slots: 4,
        max_client_stash_blocks: 4,
        fixed_append_read_path_count: 4,
        fixed_append_write_bucket_count: 12,
    }
}

fn manifest() -> PrivateOramImmutableManifestV2 {
    PrivateOramImmutableManifestV2 {
        version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
        collection_id: "collection-uuid-1".to_string(),
        manifest_nonce: digest(1),
        indexes: vec![
            PrivateOramImmutableIndexV2 {
                index_name: "text".to_string(),
                params: PrivateOramImmutableIndexParamsV2::Hnsw {
                    provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                    binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                    key_id: "tenant-a/vector-rk".to_string(),
                    rk_id: "tenant-a/vector-rk".to_string(),
                    rk_epoch: 7,
                    dim: 2,
                    vector_encoding: PrivateHnswVectorEncoding::F32Le,
                    distance: DistanceKind::Cosine,
                    hnsw: PrivateHnswParams {
                        m: 2,
                        ef_construction: 8,
                        max_layers: 4,
                        fixed_neighbor_slots: 2,
                    },
                    oram: oram(),
                    fixed_search_budget: FixedBudgetParams {
                        enabled: true,
                        upper_layer_steps: 2,
                        base_layer_steps: 4,
                        paths_per_round: 1,
                        fixed_result_k: 1,
                    },
                    max_neighbor_rewrites: 1,
                },
                capacity: capacity(),
            },
            PrivateOramImmutableIndexV2 {
                index_name: "private-payload".to_string(),
                params: PrivateOramImmutableIndexParamsV2::Result {
                    provider: PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
                    binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
                    key_id: "tenant-a/result-rk".to_string(),
                    rk_id: "tenant-a/result-rk".to_string(),
                    rk_epoch: 7,
                    oram: oram(),
                },
                capacity: capacity(),
            },
        ],
        result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
        owner_signing_key_id: "tenant-a/private-oram-owner-v2".to_string(),
        created_at_unix: 1_770_000_000,
    }
}

fn checkpoint(manifest: &PrivateOramImmutableManifestV2) -> PrivateOramAppendClientCheckpointV2 {
    let node_id = [2; 32];
    let point_token = [3; 32];
    let payload_fetch_token = [4; 32];
    PrivateOramAppendClientCheckpointV2 {
        version: PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_V2_VERSION,
        collection_id: manifest.collection_id.clone(),
        manifest_digest: private_oram_immutable_manifest_v2_digest(manifest).unwrap(),
        layout_generation: 5,
        state_sequence: 7,
        points: vec![PrivateOramAppendPointRecordV2 {
            point_token: BASE64URL_NOPAD.encode(&point_token),
            visible_point_id: None,
            payload_fetch_token: Some(BASE64URL_NOPAD.encode(&payload_fetch_token)),
        }],
        indexes: vec![
            PrivateOramAppendClientIndexCheckpointV2::Hnsw {
                index_name: "text".to_string(),
                index_epoch: 11,
                root_hash: digest(5),
                entry_node_id: Some(BASE64URL_NOPAD.encode(&node_id)),
                state: PrivateHnswOramClientStateSnapshot {
                    version: 1,
                    tree_height: 2,
                    positions: vec![PrivateHnswPositionMapSnapshotEntry {
                        node_id: BASE64URL_NOPAD.encode(&node_id),
                        leaf_label: encode_private_hnsw_oram_leaf_label(1, 2).unwrap(),
                    }],
                    stash: vec![],
                },
                records: vec![PrivateOramAppendHnswRecordV2 {
                    node_id: BASE64URL_NOPAD.encode(&node_id),
                    point_token: BASE64URL_NOPAD.encode(&point_token),
                    level_mask: 1,
                    generation: 0,
                }],
            },
            PrivateOramAppendClientIndexCheckpointV2::Result {
                index_name: "private-payload".to_string(),
                index_epoch: 11,
                root_hash: digest(6),
                state: PrivateResultOramClientStateSnapshot {
                    version: 1,
                    tree_height: 2,
                    positions: vec![PrivateResultOramPositionMapSnapshotEntry {
                        payload_fetch_token: BASE64URL_NOPAD.encode(&payload_fetch_token),
                        leaf_label: encode_private_result_oram_leaf_label(1, 2).unwrap(),
                    }],
                    stash: vec![],
                },
                records: vec![PrivateOramAppendResultRecordV2 {
                    payload_fetch_token: BASE64URL_NOPAD.encode(&payload_fetch_token),
                    point_token: BASE64URL_NOPAD.encode(&point_token),
                    generation: 0,
                }],
            },
        ],
    }
}

fn state(
    manifest: &PrivateOramImmutableManifestV2,
    client_state_digest: String,
) -> PrivateOramSignedStateV2 {
    PrivateOramSignedStateV2 {
        version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        collection_id: manifest.collection_id.clone(),
        manifest_digest: private_oram_immutable_manifest_v2_digest(manifest).unwrap(),
        layout_generation: 5,
        layout_digest: digest(7),
        state_sequence: 7,
        indexes: vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: "text".to_string(),
                index_epoch: 11,
                root_hash: digest(5),
                logical_count: 1,
                dummy_count: 3,
                last_writeback_digest: digest(8),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: "private-payload".to_string(),
                index_epoch: 11,
                root_hash: digest(6),
                logical_count: 1,
                dummy_count: 3,
                last_writeback_digest: digest(9),
            },
        ],
        client_state_digest,
        last_mutation_id: Some(digest(10)),
        owner_signing_key_id: manifest.owner_signing_key_id.clone(),
        signed_at_unix: 1_770_000_100,
    }
}

fn sealed_checkpoint_fixture() -> (
    SecretKey,
    PrivateOramImmutableManifestV2,
    PrivateOramSignedStateV2,
    PrivateOramEncryptedAppendClientCheckpointV2,
) {
    let key = SecretKey::from_bytes([11; 32]);
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let sealed = seal_private_oram_append_client_checkpoint_v2(&key, &checkpoint).unwrap();
    let state = state(
        &manifest,
        private_oram_append_client_checkpoint_v2_digest(&sealed).unwrap(),
    );
    let encrypted = bind_private_oram_append_client_checkpoint_v2(sealed, &state).unwrap();
    (key, manifest, state, encrypted)
}

struct HnswAppendTransactionFixture {
    manifest: PrivateOramImmutableManifestV2,
    state: PrivateOramSignedStateV2,
    checkpoint: PrivateOramAppendClientCheckpointV2,
    keys: PrivateHnswClientKeys,
    buckets: Vec<PrivateHnswOramBucket>,
}

fn hnsw_append_transaction_fixture() -> HnswAppendTransactionFixture {
    hnsw_append_transaction_fixture_with_path_batch_size(1)
}

fn hnsw_append_transaction_fixture_with_path_batch_size(
    path_batch_size: u32,
) -> HnswAppendTransactionFixture {
    hnsw_append_transaction_fixture_with_candidate_generation(path_batch_size, None)
}

fn hnsw_append_transaction_fixture_with_candidate_generation(
    path_batch_size: u32,
    candidate_generation: Option<u64>,
) -> HnswAppendTransactionFixture {
    let mut manifest = manifest();
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        oram,
        fixed_search_budget,
        ..
    } = &mut manifest.indexes[0].params
    else {
        panic!("fixture HNSW manifest is missing");
    };
    oram.path_batch_size = path_batch_size;
    fixed_search_budget.paths_per_round = path_batch_size;
    let mut checkpoint = checkpoint(&manifest);
    let config = PrivateHnswOramClientConfig {
        tree_height: 2,
        bucket_size: 2,
        block_size_bytes: 512,
        fixed_neighbor_slots: 2,
    };
    let mut plaintext_buckets = (0..capacity().bucket_count)
        .map(|bucket_id| empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    let mut candidate = checkpoint_candidate_block();
    if let Some(generation) = candidate_generation {
        candidate.generation = generation;
    }
    let candidate_leaf_bucket = *private_hnsw_oram_bucket_ids_for_leaf(1, 2)
        .unwrap()
        .last()
        .unwrap();
    plaintext_buckets[usize::try_from(candidate_leaf_bucket).unwrap()].blocks[0] = Some(candidate);

    let resource_key = SecretKey::from_bytes([31; 32]);
    let keys = PrivateHnswClientKeys::derive_from_resource_key_with_context(
        &resource_key,
        &manifest.collection_id,
        "text",
        "tenant-a/vector-rk",
        7,
    )
    .unwrap();
    let base_context = PrivateHnswBucketAeadBaseContext {
        collection_id: &manifest.collection_id,
        vector_name: "text",
        key_id: "tenant-a/vector-rk",
        rk_id: "tenant-a/vector-rk",
        rk_epoch: 7,
    };
    let buckets = plaintext_buckets
        .iter()
        .map(|bucket| {
            seal_private_hnsw_oram_plaintext_bucket(&keys, base_context, 11, bucket, config)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let root_hash = private_hnsw_oram_merkle_root_for_commitments(
        &buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        root_hash: checkpoint_root,
        ..
    } = &mut checkpoint.indexes[0]
    else {
        panic!("fixture HNSW checkpoint is missing");
    };
    *checkpoint_root = root_hash.clone();
    let mut state = state(&manifest, digest(30));
    state.indexes[0].root_hash = root_hash;

    HnswAppendTransactionFixture {
        manifest,
        state,
        checkpoint,
        keys,
        buckets,
    }
}

fn hnsw_append_transaction_plan() -> PrivateOramAppendHnswTransactionPlanV2 {
    PrivateOramAppendHnswTransactionPlanV2 {
        index_name: "text".to_string(),
        mutation_id: digest(20),
        writer_lease_digest: digest(21),
        writer_fence: 3,
        paths_per_window: 1,
        candidate_node_ids: vec![[2; 32]],
        candidate_remap_leaves: vec![2],
        rewrite_remap_leaves: vec![0],
        padding_leaves: vec![3, 1, 2, 0],
    }
}

fn hnsw_append_transaction_point() -> PrivateOramAppendLevel0PointV2 {
    PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![0.0, 1.0],
        initial_leaf: 3,
    }
}

fn encrypted_hnsw_window_batch(
    window: &PrivateOramAppendReadWindowV1,
    buckets: &[PrivateHnswOramBucket],
) -> PrivateHnswEncryptedPathBatch {
    let bucket_ids = window
        .paths
        .iter()
        .map(|leaf_label| decode_private_hnsw_oram_leaf_label(leaf_label, 2).unwrap())
        .flat_map(|leaf| private_hnsw_oram_bucket_ids_for_leaf(leaf, 2).unwrap())
        .collect::<Vec<_>>();
    let commitments = buckets
        .iter()
        .map(|bucket| bucket.bucket_commitment.clone())
        .collect::<Vec<_>>();
    let proof = hnsw_merkle_proof(11, &commitments, &bucket_ids);
    PrivateHnswEncryptedPathBatch {
        index_epoch: 11,
        root_hash: proof.root_hash.clone(),
        bucket_count: buckets.len().try_into().unwrap(),
        proof_value: serde_json::to_string(&proof).unwrap(),
        buckets: bucket_ids
            .iter()
            .map(|bucket_id| buckets[usize::try_from(*bucket_id).unwrap()].clone())
            .collect(),
    }
}

fn complete_hnsw_append_transaction(
    fixture: &HnswAppendTransactionFixture,
    plan: PrivateOramAppendHnswTransactionPlanV2,
) -> (PrivateOramAppendHnswTransactionOutputV2, u32) {
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        plan,
    )
    .unwrap();
    assert!(!transaction.requires_recovery());

    let mut accepted_windows = 0;
    while let Some(marker) = transaction.prepare_next_read_window().unwrap() {
        assert_eq!(transaction.requires_recovery(), accepted_windows != 0);
        assert_eq!(marker.phase, PrivateOramAppendRecoveryPhaseV2::WindowIssued);
        assert_eq!(marker.attempt_digest.len(), 43);
        assert_eq!(marker.prepared_commit_digest, None);
        let request = transaction.next_read_window(&marker).unwrap();
        assert_eq!(request.window.sequence, accepted_windows);
        assert_eq!(
            request.recovery_marker.requested_window_count,
            accepted_windows + 1
        );
        let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
        transaction
            .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
            .unwrap();
        accepted_windows += 1;
    }
    (transaction.finalize().unwrap(), accepted_windows)
}

#[test]
fn hnsw_append_transaction_accepts_fixed_size_read_sequence_with_shared_ancestors() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        plan,
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
    let bucket_ids = batch
        .buckets
        .iter()
        .map(|bucket| bucket.bucket_id)
        .collect::<Vec<_>>();

    assert_eq!(bucket_ids.len(), 6);
    assert_eq!(bucket_ids[0], bucket_ids[3]);
    transaction
        .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
        .unwrap();
}

#[test]
fn hnsw_append_transaction_rejects_reordered_fixed_size_read_sequence() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        plan,
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let mut batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
    batch.buckets.swap(1, 2);

    assert_eq!(
        transaction.accept_verified_window(request.window.sequence, &fixture.keys, &batch),
        Err(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch)
    );
    assert!(transaction.requires_recovery());
}

#[test]
fn paired_checkpoint_seals_binds_and_opens_against_signed_state() {
    let (key, manifest, state, encrypted) = sealed_checkpoint_fixture();
    let opened =
        open_private_oram_append_client_checkpoint_v2(&key, &encrypted, &manifest, &state).unwrap();
    assert_eq!(opened, checkpoint(&manifest));
    validate_private_oram_append_client_checkpoint_v2(&opened, &manifest, &state).unwrap();
}

#[test]
fn checkpoint_digest_known_answer_is_stable() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/qdrant-sec-private-oram-append-checkpoint-test-vector.json"
    ))
    .unwrap();
    let input = &vector["input"];
    let sealed = PrivateOramSealedAppendClientCheckpointV2 {
        version: input["version"].as_u64().unwrap().try_into().unwrap(),
        collection_id: input["collection_id"].as_str().unwrap().to_string(),
        manifest_digest: input["manifest_digest"].as_str().unwrap().to_string(),
        layout_generation: input["layout_generation"].as_u64().unwrap(),
        state_sequence: input["state_sequence"].as_u64().unwrap(),
        ciphertext: input["ciphertext"].as_str().unwrap().to_string(),
        ciphertext_sha256: input["ciphertext_sha256"].as_str().unwrap().to_string(),
    };
    let message = try_private_oram_append_client_checkpoint_v2_digest_message(&sealed).unwrap();
    assert_eq!(
        vector["domain"],
        serde_json::json!(PRIVATE_ORAM_APPEND_CLIENT_CHECKPOINT_DIGEST_DOMAIN)
    );
    assert_eq!(
        vector["digest_message_len"],
        serde_json::json!(message.len())
    );
    assert_eq!(
        vector["digest_message_b64"],
        serde_json::json!(BASE64URL_NOPAD.encode(&message))
    );
    assert_eq!(
        vector["digest_b64"],
        serde_json::json!(private_oram_append_client_checkpoint_v2_digest(&sealed).unwrap())
    );
}

#[test]
fn hnsw_append_recovery_digest_known_answers_are_stable() {
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let state = state(&manifest, digest(30));
    let point = hnsw_append_transaction_point();
    let plan = hnsw_append_transaction_plan();
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&state).unwrap();
    let attempt =
        private_oram_append_hnsw_attempt_v2_digest(PrivateOramAppendHnswAttemptDigestInput {
            manifest_digest: &manifest_digest,
            old_state_digest: &old_state_digest,
            checkpoint: &checkpoint,
            point: &point,
            plan: &plan,
        })
        .unwrap();
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        state: next_client_state,
        ..
    } = &checkpoint.indexes[0]
    else {
        panic!("fixture HNSW checkpoint is missing");
    };
    let prepared = private_oram_append_hnsw_prepared_commit_v2_digest(
        PrivateOramAppendHnswPreparedCommitDigestInput {
            attempt_digest: &attempt,
            old_epoch: 11,
            new_epoch: 12,
            old_root_hash: &digest(5),
            new_root_hash: &digest(6),
            read_transcript_digest: &digest(40),
            writeback_digest: &digest(41),
            next_client_state,
        },
    )
    .unwrap();

    assert_eq!(attempt, "k6aBmpM33qQZMHZUlLm8zjcuFuNJIxs_kmRYFFOH_9M");
    assert_eq!(prepared, "ftlODQe353ZRs3E7s_ZUGCJrY16zvRysuW3-SR4iRQQ");
}

#[test]
fn checkpoint_rejects_duplicate_and_cross_index_token_records() {
    let manifest = manifest();
    let mut malformed_checkpoint = checkpoint(&manifest);
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        state: hnsw_state,
        records,
        ..
    } = &mut malformed_checkpoint.indexes[0]
    else {
        unreachable!();
    };
    hnsw_state
        .positions
        .push(PrivateHnswPositionMapSnapshotEntry {
            node_id: digest(12),
            leaf_label: encode_private_hnsw_oram_leaf_label(2, 2).unwrap(),
        });
    let mut duplicate = records[0].clone();
    duplicate.node_id = digest(12);
    records.push(duplicate);
    assert_eq!(
        validate_private_oram_append_client_checkpoint_v2_shape(&malformed_checkpoint),
        Err(PrivateOramAppendClientError::DuplicateCheckpointRecord)
    );

    let mut mismatched_checkpoint = checkpoint(&manifest);
    let PrivateOramAppendClientIndexCheckpointV2::Result { records, .. } =
        &mut mismatched_checkpoint.indexes[1]
    else {
        unreachable!();
    };
    records[0].point_token = digest(13);
    let signed_state = state(&manifest, digest(14));
    assert_eq!(
        validate_private_oram_append_client_checkpoint_v2(
            &mismatched_checkpoint,
            &manifest,
            &signed_state,
        ),
        Err(PrivateOramAppendClientError::CheckpointStateMismatch)
    );

    let mut visible_duplicate = checkpoint(&manifest);
    visible_duplicate.points[0].visible_point_id = Some("42".to_string());
    visible_duplicate
        .points
        .push(PrivateOramAppendPointRecordV2 {
            point_token: digest(15),
            visible_point_id: Some("42".to_string()),
            payload_fetch_token: None,
        });
    assert_eq!(
        validate_private_oram_append_client_checkpoint_v2_shape(&visible_duplicate),
        Err(PrivateOramAppendClientError::DuplicateCheckpointRecord)
    );
}

#[test]
fn checkpoint_rejects_state_binding_and_ciphertext_tampering() {
    let (key, manifest, state, encrypted) = sealed_checkpoint_fixture();

    let mut wrong_state = state.clone();
    wrong_state.state_sequence += 1;
    assert_eq!(
        open_private_oram_append_client_checkpoint_v2(&key, &encrypted, &manifest, &wrong_state,),
        Err(PrivateOramAppendClientError::CheckpointStateMismatch)
    );

    let mut tampered = encrypted.clone();
    let mut raw_ciphertext = BASE64URL_NOPAD
        .decode(tampered.sealed.ciphertext.as_bytes())
        .unwrap();
    *raw_ciphertext.last_mut().unwrap() ^= 1;
    tampered.sealed.ciphertext = BASE64URL_NOPAD.encode(&raw_ciphertext);
    assert_eq!(
        open_private_oram_append_client_checkpoint_v2(&key, &tampered, &manifest, &state,),
        Err(PrivateOramAppendClientError::InvalidCheckpointCiphertextHash)
    );

    assert_eq!(
        open_private_oram_append_client_checkpoint_v2(
            &SecretKey::from_bytes([12; 32]),
            &encrypted,
            &manifest,
            &state,
        ),
        Err(PrivateOramAppendClientError::CheckpointOpenFailed)
    );
}

#[test]
fn checkpoint_supports_empty_paired_state_and_ids_visible_point_mapping() {
    let paired_manifest = manifest();
    let mut empty_checkpoint = checkpoint(&paired_manifest);
    empty_checkpoint.points.clear();
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        entry_node_id,
        state: hnsw_state,
        records: hnsw_records,
        ..
    } = &mut empty_checkpoint.indexes[0]
    else {
        unreachable!();
    };
    *entry_node_id = None;
    hnsw_state.positions.clear();
    hnsw_records.clear();
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        state: result_state,
        records: result_records,
        ..
    } = &mut empty_checkpoint.indexes[1]
    else {
        unreachable!();
    };
    result_state.positions.clear();
    result_records.clear();
    let mut empty_state = state(&paired_manifest, digest(16));
    for index in &mut empty_state.indexes {
        index.logical_count = 0;
        index.dummy_count = 4;
    }
    validate_private_oram_append_client_checkpoint_v2(
        &empty_checkpoint,
        &paired_manifest,
        &empty_state,
    )
    .unwrap();

    let mut visible_manifest = paired_manifest;
    visible_manifest.indexes.pop();
    visible_manifest.result_privacy = ResultPrivacyMode::IdsVisible;
    let mut visible_checkpoint = checkpoint(&manifest());
    visible_checkpoint.manifest_digest =
        private_oram_immutable_manifest_v2_digest(&visible_manifest).unwrap();
    visible_checkpoint.indexes.pop();
    visible_checkpoint.points[0].visible_point_id = Some("42".to_string());
    visible_checkpoint.points[0].payload_fetch_token = None;

    let mut visible_state = state(&manifest(), digest(17));
    visible_state.manifest_digest = visible_checkpoint.manifest_digest.clone();
    visible_state.indexes.pop();
    validate_private_oram_append_client_checkpoint_v2(
        &visible_checkpoint,
        &visible_manifest,
        &visible_state,
    )
    .unwrap();
}

#[test]
fn append_only_position_and_stash_apis_do_not_overwrite_existing_records() {
    let node_id = [2; 32];
    let point_token = [3; 32];
    let payload_fetch_token = [4; 32];
    let mut hnsw = PrivateHnswOramClientState::with_position_map([(node_id, 1)], 2).unwrap();
    let before = hnsw.clone();
    assert_eq!(
        hnsw.insert_position_if_absent(node_id, 2, 2),
        Err(PrivateHnswClientError::DuplicateBlock)
    );
    assert_eq!(hnsw, before);
    assert_eq!(
        hnsw.insert_new_stash_block(
            PrivateHnswNodeBlockPlaintext {
                version: 1,
                node_id,
                point_token,
                level_mask: 1,
                vector_encoding: PrivateHnswVectorEncoding::F32Le,
                vector: [1.0f32, 0.0]
                    .into_iter()
                    .flat_map(f32::to_le_bytes)
                    .collect(),
                neighbors: vec![],
                neighbor_levels: vec![],
                deleted: false,
                generation: 0,
                payload_fetch_token: Some(payload_fetch_token),
            },
            1,
            PrivateHnswOramClientConfig {
                tree_height: 2,
                bucket_size: 2,
                block_size_bytes: 512,
                fixed_neighbor_slots: 2,
            },
        ),
        Err(PrivateHnswClientError::DuplicateBlock)
    );
    assert_eq!(hnsw, before);

    let mut result =
        PrivateResultOramClientState::with_position_map([(payload_fetch_token, 1)], 2).unwrap();
    let before = result.clone();
    assert_eq!(
        result.insert_position_if_absent(payload_fetch_token, 2, 2),
        Err(PrivateResultOramError::DuplicatePayloadFetchToken)
    );
    assert_eq!(result, before);
}

#[test]
fn checkpoint_debug_output_redacts_client_owned_identifiers_and_ciphertext() {
    let (_key, manifest, _state, encrypted) = sealed_checkpoint_fixture();
    let checkpoint = checkpoint(&manifest);
    let checkpoint_debug = format!("{checkpoint:?}");
    let encrypted_debug = format!("{encrypted:?}");
    for sentinel in [
        checkpoint.collection_id.as_str(),
        checkpoint.manifest_digest.as_str(),
        encrypted.sealed.ciphertext.as_str(),
        encrypted.sealed.ciphertext_sha256.as_str(),
        encrypted.state_digest.as_str(),
    ] {
        assert!(!checkpoint_debug.contains(sentinel));
        assert!(!encrypted_debug.contains(sentinel));
    }
}

#[test]
fn sparse_merkle_patch_matches_full_recompute_and_uses_last_occurrence() {
    let commitments = (1..=7).map(digest).collect::<Vec<_>>();
    let old_root = private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap();
    let hnsw_proof = hnsw_merkle_proof(11, &commitments, &[0, 1, 3]);
    let proof = PrivateOramAppendMerklePatchProofV1::from(&hnsw_proof);
    let ordered_updates = vec![
        append_bucket(0, 20),
        append_bucket(1, 21),
        append_bucket(0, 22),
        append_bucket(3, 23),
    ];

    let patch = apply_private_oram_append_sparse_merkle_patch_v1(
        11,
        &old_root,
        commitments.len().try_into().unwrap(),
        &proof,
        &ordered_updates,
    )
    .unwrap();
    let mut expected_commitments = commitments;
    expected_commitments[0] = digest(22);
    expected_commitments[1] = digest(21);
    expected_commitments[3] = digest(23);
    assert_eq!(
        patch.new_root_hash,
        private_hnsw_oram_merkle_root_for_commitments(&expected_commitments).unwrap()
    );
    assert_eq!(
        patch
            .final_buckets
            .iter()
            .map(|bucket| bucket.bucket_id)
            .collect::<Vec<_>>(),
        vec![0, 1, 3]
    );
    assert_eq!(patch.final_buckets[0], append_bucket(0, 22));

    let result_proof = PrivateResultOramMerkleProof {
        kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
        index_epoch: hnsw_proof.index_epoch,
        root_hash: hnsw_proof.root_hash.clone(),
        bucket_count: hnsw_proof.bucket_count,
        leaves: hnsw_proof
            .leaves
            .iter()
            .map(|leaf| PrivateResultOramMerkleProofLeaf {
                bucket_id: leaf.bucket_id,
                leaf_hash: leaf.leaf_hash.clone(),
                siblings: leaf
                    .siblings
                    .iter()
                    .map(|sibling| PrivateResultOramMerkleSibling {
                        level: sibling.level,
                        position: match sibling.position {
                            PrivateHnswMerkleSiblingPosition::Left => {
                                PrivateResultOramMerkleSiblingPosition::Left
                            }
                            PrivateHnswMerkleSiblingPosition::Right => {
                                PrivateResultOramMerkleSiblingPosition::Right
                            }
                        },
                        hash: sibling.hash.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };
    assert_eq!(
        PrivateOramAppendMerklePatchProofV1::from(&result_proof),
        proof
    );
}

#[test]
fn sparse_merkle_patch_rejects_unproven_updates_and_conflicting_proofs() {
    let commitments = (1..=7).map(digest).collect::<Vec<_>>();
    let old_root = private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap();
    let proof =
        PrivateOramAppendMerklePatchProofV1::from(&hnsw_merkle_proof(11, &commitments, &[0]));

    assert_eq!(
        apply_private_oram_append_sparse_merkle_patch_v1(
            11,
            &old_root,
            commitments.len().try_into().unwrap(),
            &proof,
            &[append_bucket(1, 20)],
        ),
        Err(PrivateOramAppendClientError::MerklePatchMismatch)
    );
    assert_eq!(
        apply_private_oram_append_sparse_merkle_patch_v1(
            12,
            &old_root,
            commitments.len().try_into().unwrap(),
            &proof,
            &[append_bucket(0, 20)],
        ),
        Err(PrivateOramAppendClientError::InvalidMerklePatch)
    );

    let mut conflicting = proof;
    let mut duplicate = conflicting.leaves[0].clone();
    duplicate.old_commitment = digest(31);
    conflicting.leaves.push(duplicate);
    assert_eq!(
        apply_private_oram_append_sparse_merkle_patch_v1(
            11,
            &old_root,
            commitments.len().try_into().unwrap(),
            &conflicting,
            &[append_bucket(0, 20)],
        ),
        Err(PrivateOramAppendClientError::MerklePatchMismatch)
    );
}

#[test]
fn sparse_merkle_patch_handles_a_single_bucket_tree() {
    let commitments = vec![digest(1)];
    let old_root = commitments[0].clone();
    let proof =
        PrivateOramAppendMerklePatchProofV1::from(&hnsw_merkle_proof(3, &commitments, &[0]));
    let patch = apply_private_oram_append_sparse_merkle_patch_v1(
        3,
        &old_root,
        1,
        &proof,
        &[append_bucket(0, 9)],
    )
    .unwrap();
    assert_eq!(patch.new_root_hash, digest(9));
}

#[test]
fn level0_append_plan_is_bounded_and_rewrites_a_visited_neighbor() {
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let state = state(&manifest, digest(40));
    let checkpoint_before = checkpoint.clone();
    let point = PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![0.9, 0.1],
        initial_leaf: 2,
    };
    let candidate = checkpoint_candidate_block();

    let plan = plan_private_oram_level0_hnsw_graph_delta_v2(
        &manifest,
        &state,
        &checkpoint,
        "text",
        &point,
        std::slice::from_ref(&candidate),
        1,
    )
    .unwrap();

    assert_eq!(checkpoint, checkpoint_before);
    assert_eq!(plan.new_block.node_id, point.node_id);
    assert_eq!(plan.new_block.generation, 1);
    assert_eq!(plan.new_block.level_mask, 1);
    assert_eq!(plan.selected_neighbor_ids, vec![candidate.node_id]);
    assert_eq!(plan.neighbor_rewrites.len(), 1);
    let rewrite = &plan.neighbor_rewrites[0];
    assert_eq!(rewrite.previous, candidate);
    assert_eq!(rewrite.replacement.generation, 1);
    assert_eq!(rewrite.replacement.point_token, candidate.point_token);
    assert_eq!(rewrite.replacement.vector, candidate.vector);
    assert_eq!(rewrite.replacement.neighbors, vec![point.node_id]);
    assert_eq!(rewrite.replacement.neighbor_levels, vec![0]);
    assert_eq!(plan.next_entry_node_id, candidate.node_id);
    assert_eq!(plan.fixed_read_path_count, 4);
    assert_eq!(plan.candidate_read_path_budget, 2);
    assert_eq!(plan.candidate_read_path_count, 1);
    assert_eq!(plan.rewrite_read_path_budget, 1);
    assert_eq!(plan.rewrite_read_path_count, 1);
    assert_eq!(plan.real_read_path_count, 3);
    assert_eq!(plan.padding_read_path_count, 1);
}

#[test]
fn level0_append_plan_rejects_duplicate_stale_and_over_budget_inputs() {
    let manifest = manifest();
    let checkpoint = checkpoint(&manifest);
    let state = state(&manifest, digest(41));
    let mut point = PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![0.9, 0.1],
        initial_leaf: 2,
    };
    let candidate = checkpoint_candidate_block();

    point.node_id = candidate.node_id;
    assert_eq!(
        plan_private_oram_level0_hnsw_graph_delta_v2(
            &manifest,
            &state,
            &checkpoint,
            "text",
            &point,
            std::slice::from_ref(&candidate),
            1,
        ),
        Err(PrivateOramAppendClientError::DuplicateCheckpointRecord)
    );
    point.node_id = [5; 32];
    assert_eq!(
        plan_private_oram_level0_hnsw_graph_delta_v2(
            &manifest,
            &state,
            &checkpoint,
            "text",
            &point,
            std::slice::from_ref(&candidate),
            3,
        ),
        Err(PrivateOramAppendClientError::AppendBudgetExceeded)
    );

    let mut stale_candidate = candidate;
    stale_candidate.generation = 1;
    assert_eq!(
        plan_private_oram_level0_hnsw_graph_delta_v2(
            &manifest,
            &state,
            &checkpoint,
            "text",
            &point,
            &[stale_candidate],
            1,
        ),
        Err(PrivateOramAppendClientError::AppendCandidateMismatch)
    );
}

#[test]
fn level0_append_plan_initializes_an_empty_index_with_padding() {
    let manifest = manifest();
    let mut checkpoint = checkpoint(&manifest);
    checkpoint.points.clear();
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        entry_node_id,
        state: hnsw_state,
        records,
        ..
    } = &mut checkpoint.indexes[0]
    else {
        unreachable!();
    };
    *entry_node_id = None;
    hnsw_state.positions.clear();
    records.clear();
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        state: result_state,
        records,
        ..
    } = &mut checkpoint.indexes[1]
    else {
        unreachable!();
    };
    result_state.positions.clear();
    records.clear();
    let mut state = state(&manifest, digest(42));
    for index in &mut state.indexes {
        index.logical_count = 0;
        index.dummy_count = 4;
    }
    let point = PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![1.0, 0.0],
        initial_leaf: 1,
    };

    let plan = plan_private_oram_level0_hnsw_graph_delta_v2(
        &manifest,
        &state,
        &checkpoint,
        "text",
        &point,
        &[],
        0,
    )
    .unwrap();
    assert!(plan.selected_neighbor_ids.is_empty());
    assert!(plan.neighbor_rewrites.is_empty());
    assert_eq!(plan.next_entry_node_id, point.node_id);
    assert_eq!(plan.real_read_path_count, 1);
    assert_eq!(plan.padding_read_path_count, 3);
}

#[test]
fn level0_graph_delta_promotes_new_entry_when_reverse_edge_is_pruned() {
    let mut manifest = manifest();
    let PrivateOramImmutableIndexParamsV2::Hnsw { distance, hnsw, .. } =
        &mut manifest.indexes[0].params
    else {
        unreachable!();
    };
    *distance = DistanceKind::Euclid;
    hnsw.m = 1;
    hnsw.fixed_neighbor_slots = 1;

    let mut checkpoint = checkpoint(&manifest);
    checkpoint.points.push(PrivateOramAppendPointRecordV2 {
        point_token: BASE64URL_NOPAD.encode(&[9; 32]),
        visible_point_id: None,
        payload_fetch_token: Some(BASE64URL_NOPAD.encode(&[10; 32])),
    });
    let PrivateOramAppendClientIndexCheckpointV2::Hnsw {
        state: hnsw_state,
        records: hnsw_records,
        ..
    } = &mut checkpoint.indexes[0]
    else {
        unreachable!();
    };
    hnsw_state
        .positions
        .push(PrivateHnswPositionMapSnapshotEntry {
            node_id: BASE64URL_NOPAD.encode(&[8; 32]),
            leaf_label: encode_private_hnsw_oram_leaf_label(2, 2).unwrap(),
        });
    hnsw_records.push(PrivateOramAppendHnswRecordV2 {
        node_id: BASE64URL_NOPAD.encode(&[8; 32]),
        point_token: BASE64URL_NOPAD.encode(&[9; 32]),
        level_mask: 1,
        generation: 0,
    });
    let PrivateOramAppendClientIndexCheckpointV2::Result {
        state: result_state,
        records: result_records,
        ..
    } = &mut checkpoint.indexes[1]
    else {
        unreachable!();
    };
    result_state
        .positions
        .push(PrivateResultOramPositionMapSnapshotEntry {
            payload_fetch_token: BASE64URL_NOPAD.encode(&[10; 32]),
            leaf_label: encode_private_result_oram_leaf_label(2, 2).unwrap(),
        });
    result_records.push(PrivateOramAppendResultRecordV2 {
        payload_fetch_token: BASE64URL_NOPAD.encode(&[10; 32]),
        point_token: BASE64URL_NOPAD.encode(&[9; 32]),
        generation: 0,
    });

    let mut state = state(&manifest, digest(43));
    for index in &mut state.indexes {
        index.logical_count = 2;
        index.dummy_count = 2;
    }
    let mut entry = checkpoint_candidate_block();
    entry.vector = [0.0f32, 0.0]
        .into_iter()
        .flat_map(f32::to_le_bytes)
        .collect();
    entry.neighbors = vec![[8; 32]];
    entry.neighbor_levels = vec![0];
    let second = PrivateHnswNodeBlockPlaintext {
        version: PRIVATE_HNSW_NODE_BLOCK_VERSION,
        node_id: [8; 32],
        point_token: [9; 32],
        level_mask: 1,
        vector_encoding: PrivateHnswVectorEncoding::F32Le,
        vector: [1.0f32, 0.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect(),
        neighbors: vec![entry.node_id],
        neighbor_levels: vec![0],
        deleted: false,
        generation: 0,
        payload_fetch_token: Some([10; 32]),
    };
    let point = PrivateOramAppendLevel0PointV2 {
        node_id: [5; 32],
        point_token: [6; 32],
        visible_point_id: None,
        payload_fetch_token: Some([7; 32]),
        vector: vec![2.0, 0.0],
        initial_leaf: 3,
    };

    let delta = plan_private_oram_level0_hnsw_graph_delta_v2(
        &manifest,
        &state,
        &checkpoint,
        "text",
        &point,
        &[entry.clone(), second],
        2,
    )
    .unwrap();
    assert!(delta.neighbor_rewrites.is_empty());
    assert_eq!(delta.next_entry_node_id, point.node_id);
    assert_eq!(delta.new_block.neighbors, vec![entry.node_id]);
    assert_eq!(delta.rewrite_read_path_count, 0);
    assert_eq!(delta.real_read_path_count, 3);
    assert_eq!(delta.padding_read_path_count, 1);
}

#[test]
fn append_rewrite_and_targetless_hnsw_eviction_are_atomic() {
    let config = PrivateHnswOramClientConfig {
        tree_height: 2,
        bucket_size: 2,
        block_size_bytes: 512,
        fixed_neighbor_slots: 2,
    };
    let block = checkpoint_candidate_block();
    let mut state = PrivateHnswOramClientState::with_position_map([(block.node_id, 1)], 2).unwrap();
    let mut path = private_hnsw_oram_bucket_ids_for_leaf(1, 2)
        .unwrap()
        .into_iter()
        .map(|bucket_id| empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    path.last_mut().unwrap().blocks[0] = Some(block.clone());

    let access = access_private_hnsw_oram_path_with_append_rewrite(
        &mut state,
        config,
        block.node_id,
        &path,
        2,
        |previous| {
            let mut replacement = previous.clone();
            replacement.neighbors.push([5; 32]);
            replacement.neighbor_levels.push(0);
            replacement.generation += 1;
            Ok(replacement)
        },
    )
    .unwrap();
    assert_eq!(state.position(&block.node_id), Some(2));
    assert_eq!(access.block.neighbors, vec![[5; 32]]);
    assert!(
        access
            .writeback_buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .any(|written| written == &access.block)
    );

    let mut rejected_state =
        PrivateHnswOramClientState::with_position_map([(block.node_id, 1)], 2).unwrap();
    let before = rejected_state.clone();
    assert_eq!(
        access_private_hnsw_oram_path_with_append_rewrite(
            &mut rejected_state,
            config,
            block.node_id,
            &path,
            2,
            |previous| {
                let mut replacement = previous.clone();
                replacement.vector[0] ^= 1;
                replacement.generation += 1;
                Ok(replacement)
            },
        ),
        Err(PrivateHnswClientError::InvalidAppendRewrite)
    );
    assert_eq!(rejected_state, before);

    let new_block = PrivateHnswNodeBlockPlaintext {
        node_id: [11; 32],
        point_token: [12; 32],
        payload_fetch_token: Some([13; 32]),
        vector: [0.0f32, 1.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect(),
        ..checkpoint_candidate_block()
    };
    let mut insertion_state = PrivateHnswOramClientState::new();
    insertion_state
        .insert_new_stash_block(new_block.clone(), 3, config)
        .unwrap();
    let empty_path = private_hnsw_oram_bucket_ids_for_leaf(3, 2)
        .unwrap()
        .into_iter()
        .map(|bucket_id| empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    let eviction =
        evict_private_hnsw_oram_path(&mut insertion_state, config, 3, &empty_path).unwrap();
    assert_eq!(insertion_state.stash_len(), 0);
    assert!(
        eviction
            .writeback_buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .any(|written| written == &new_block)
    );
}

#[test]
fn targetless_result_eviction_places_a_new_private_payload_block() {
    let config = PrivateResultOramClientConfig {
        tree_height: 2,
        bucket_size: 2,
        block_size_bytes: 512,
    };
    let block = PrivateResultOramPayloadBlockPlaintext {
        version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
        payload_fetch_token: [7; 32],
        point_token: [6; 32],
        payload: b"encrypted-client-payload-plaintext".to_vec(),
        deleted: false,
        generation: 1,
    };
    let mut state = PrivateResultOramClientState::new();
    state
        .insert_new_stash_block(block.clone(), 2, config)
        .unwrap();
    let path = private_result_oram_bucket_ids_for_leaf(2, 2)
        .unwrap()
        .into_iter()
        .map(|bucket_id| empty_private_result_oram_plaintext_bucket(bucket_id, config).unwrap())
        .collect::<Vec<_>>();
    let eviction = evict_private_result_oram_path(&mut state, config, 2, &path).unwrap();
    assert_eq!(state.stash_len(), 0);
    assert!(
        eviction
            .writeback_buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten())
            .any(|written| written == &block)
    );

    let mut rejected_state = PrivateResultOramClientState::new();
    rejected_state
        .insert_new_stash_block(block, 2, config)
        .unwrap();
    let before = rejected_state.clone();
    assert_eq!(
        evict_private_result_oram_path(&mut rejected_state, config, 2, &path[..2]),
        Err(PrivateResultOramError::PathBucketMismatch)
    );
    assert_eq!(rejected_state, before);
}

#[test]
fn verified_hnsw_append_transaction_preserves_fixed_ordered_frames() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let (output, accepted_windows) = complete_hnsw_append_transaction(&fixture, plan);
    assert_eq!(accepted_windows, 2);

    assert_eq!(output.old_epoch, 11);
    assert_eq!(output.new_epoch, 12);
    assert_eq!(output.read_transcript.read_path_count, 4);
    assert_eq!(output.read_transcript.ordered_leaf_labels.len(), 4);
    assert_eq!(
        output.read_transcript.ordered_leaf_labels[1],
        output.read_transcript.ordered_leaf_labels[3]
    );
    assert_eq!(output.writeback.updated_buckets.len(), 12);
    assert_eq!(output.ordered_encrypted_buckets.len(), 12);
    assert_eq!(
        output
            .writeback
            .updated_buckets
            .iter()
            .filter(|bucket| bucket.bucket_id == 0)
            .count(),
        4
    );
    assert_eq!(output.graph_delta.neighbor_rewrites.len(), 1);
    assert_eq!(output.graph_delta.new_block.node_id, [5; 32]);
    assert_eq!(
        output.recovery_marker.phase,
        PrivateOramAppendRecoveryPhaseV2::PreparedCommit
    );
    assert_eq!(output.recovery_marker.attempt_digest.len(), 43);
    assert_eq!(
        output
            .recovery_marker
            .prepared_commit_digest
            .as_ref()
            .map(String::len),
        Some(43)
    );
    assert!(
        output
            .next_client_state
            .positions
            .iter()
            .any(|entry| entry.node_id == BASE64URL_NOPAD.encode(&[5; 32]))
    );

    let mut next_commitments = fixture
        .buckets
        .iter()
        .map(|bucket| bucket.bucket_commitment.clone())
        .collect::<Vec<_>>();
    for bucket in &output.final_encrypted_buckets {
        next_commitments[usize::try_from(bucket.bucket_id).unwrap()] =
            bucket.bucket_commitment.clone();
    }
    assert_eq!(
        private_hnsw_oram_merkle_root_for_commitments(&next_commitments).unwrap(),
        output.new_root_hash
    );
}

#[test]
fn prepared_commit_marker_binds_randomized_ciphertext_artifact() {
    let fixture = hnsw_append_transaction_fixture();
    let (first, _) = complete_hnsw_append_transaction(&fixture, hnsw_append_transaction_plan());
    let (second, _) = complete_hnsw_append_transaction(&fixture, hnsw_append_transaction_plan());

    assert_eq!(
        first.recovery_marker.attempt_digest,
        second.recovery_marker.attempt_digest
    );
    assert_ne!(first.new_root_hash, second.new_root_hash);
    assert_ne!(
        first.recovery_marker.prepared_commit_digest,
        second.recovery_marker.prepared_commit_digest
    );
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&fixture.manifest).unwrap();
    let writeback_digest =
        private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
            collection_id: &fixture.manifest.collection_id,
            manifest_digest: &manifest_digest,
            kind: first.writeback.kind,
            index_name: &first.writeback.index_name,
            old_epoch: first.old_epoch,
            new_epoch: first.new_epoch,
            old_root_hash: &first.old_root_hash,
            new_root_hash: &first.new_root_hash,
            read_path_count: first.writeback.read_path_count,
            read_transcript_digest: &first.writeback.read_transcript_digest,
            updated_buckets: &first.writeback.updated_buckets,
        })
        .unwrap();
    let expected = private_oram_append_hnsw_prepared_commit_v2_digest(
        PrivateOramAppendHnswPreparedCommitDigestInput {
            attempt_digest: &first.recovery_marker.attempt_digest,
            old_epoch: first.old_epoch,
            new_epoch: first.new_epoch,
            old_root_hash: &first.old_root_hash,
            new_root_hash: &first.new_root_hash,
            read_transcript_digest: &first.read_transcript.transcript_digest,
            writeback_digest: &writeback_digest,
            next_client_state: &first.next_client_state,
        },
    )
    .unwrap();
    assert_eq!(
        first.recovery_marker.prepared_commit_digest.as_deref(),
        Some(expected.as_str())
    );
}

#[test]
fn hnsw_append_recovery_marker_binds_the_exact_attempt_plan() {
    let fixture = hnsw_append_transaction_fixture();
    let point = hnsw_append_transaction_point();
    let plan = hnsw_append_transaction_plan();
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&fixture.manifest).unwrap();
    let old_state_digest = private_oram_signed_state_v2_digest(&fixture.state).unwrap();
    let expected_attempt =
        private_oram_append_hnsw_attempt_v2_digest(PrivateOramAppendHnswAttemptDigestInput {
            manifest_digest: &manifest_digest,
            old_state_digest: &old_state_digest,
            checkpoint: &fixture.checkpoint,
            point: &point,
            plan: &plan,
        })
        .unwrap();
    let mut first = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        point,
        plan,
    )
    .unwrap();
    let first_marker = first.prepare_next_read_window().unwrap().unwrap();
    assert_eq!(first_marker.attempt_digest, expected_attempt);

    let mut changed_plan = hnsw_append_transaction_plan();
    changed_plan.padding_leaves[3] = 3;
    let mut changed = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        changed_plan,
    )
    .unwrap();
    let changed_marker = changed.prepare_next_read_window().unwrap().unwrap();

    assert_ne!(first_marker.attempt_digest, changed_marker.attempt_digest);
    assert_eq!(
        changed.next_read_window(&first_marker),
        Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch)
    );
}

#[test]
fn hnsw_append_transaction_rejects_duplicate_point_before_first_read() {
    let fixture = hnsw_append_transaction_fixture();
    let mut duplicate = hnsw_append_transaction_point();
    duplicate.node_id = [2; 32];
    assert_eq!(
        PrivateOramAppendHnswTransactionV2::begin(
            &fixture.manifest,
            &fixture.state,
            &fixture.checkpoint,
            duplicate,
            hnsw_append_transaction_plan(),
        )
        .unwrap_err(),
        PrivateOramAppendTransactionError::Client(
            PrivateOramAppendClientError::DuplicateCheckpointRecord,
        )
    );
}

#[test]
fn hnsw_append_transaction_rejects_duplicate_paths_within_a_fixed_window() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    plan.padding_leaves[0] = 1;
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        plan,
    )
    .unwrap();
    assert_eq!(
        transaction.prepare_next_read_window(),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "duplicate_window_path",
        ))
    );
    assert!(!transaction.requires_recovery());
}

#[test]
fn hnsw_append_transaction_poisoned_when_later_window_plan_fails() {
    let fixture = hnsw_append_transaction_fixture_with_path_batch_size(2);
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    plan.padding_leaves[0] = 0;
    let mut point = hnsw_append_transaction_point();
    point.initial_leaf = 2;
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        point,
        plan,
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
    transaction
        .accept_verified_window(request.window.sequence, &fixture.keys, &batch)
        .unwrap();

    assert_eq!(
        transaction.prepare_next_read_window(),
        Err(PrivateOramAppendTransactionError::InvalidInput(
            "duplicate_window_path",
        ))
    );
    assert!(transaction.is_poisoned());
    assert_eq!(
        transaction.recovery_marker().unwrap().phase,
        PrivateOramAppendRecoveryPhaseV2::Poisoned
    );
}

#[test]
fn hnsw_append_transaction_rolls_back_a_fully_applied_window_when_planning_fails() {
    let fixture = hnsw_append_transaction_fixture_with_candidate_generation(2, Some(99));
    let mut plan = hnsw_append_transaction_plan();
    plan.paths_per_window = 2;
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        plan,
    )
    .unwrap();
    let before = transaction.progress();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    let request = transaction.next_read_window(&marker).unwrap();
    let batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);

    assert_eq!(
        transaction.accept_verified_window(request.window.sequence, &fixture.keys, &batch),
        Err(PrivateOramAppendTransactionError::Client(
            PrivateOramAppendClientError::AppendCandidateMismatch
        ))
    );
    assert!(transaction.is_poisoned());
    assert_eq!(transaction.progress(), before);
    let recovery = transaction.recovery_marker().unwrap();
    assert_eq!(recovery.accepted_window_count, 0);
    assert_eq!(recovery.observed_read_path_count, 2);
    assert_eq!(recovery.phase, PrivateOramAppendRecoveryPhaseV2::Poisoned);
}

#[test]
fn hnsw_append_transaction_poisoning_requires_recovery_after_first_read() {
    let fixture = hnsw_append_transaction_fixture();
    let mut transaction = PrivateOramAppendHnswTransactionV2::begin(
        &fixture.manifest,
        &fixture.state,
        &fixture.checkpoint,
        hnsw_append_transaction_point(),
        hnsw_append_transaction_plan(),
    )
    .unwrap();
    let marker = transaction.prepare_next_read_window().unwrap().unwrap();
    assert!(!transaction.requires_recovery());
    let mut wrong_marker = marker.clone();
    wrong_marker.writer_fence += 1;
    assert_eq!(
        transaction.next_read_window(&wrong_marker),
        Err(PrivateOramAppendTransactionError::RecoveryMarkerMismatch)
    );
    assert!(!transaction.requires_recovery());
    let request = transaction.next_read_window(&marker).unwrap();
    assert!(transaction.requires_recovery());
    assert_eq!(
        transaction.next_read_window(&marker),
        Err(PrivateOramAppendTransactionError::WindowPending)
    );

    let mut incomplete_batch = encrypted_hnsw_window_batch(&request.window, &fixture.buckets);
    incomplete_batch.buckets.pop();
    assert_eq!(
        transaction.accept_verified_window(
            request.window.sequence,
            &fixture.keys,
            &incomplete_batch,
        ),
        Err(PrivateOramAppendTransactionError::ResponseBucketSequenceMismatch)
    );
    assert!(transaction.is_poisoned());
    let marker = transaction.recovery_marker().unwrap();
    assert_eq!(marker.phase, PrivateOramAppendRecoveryPhaseV2::Poisoned);
    assert_eq!(marker.requested_window_count, 1);
    assert_eq!(marker.accepted_window_count, 0);
    assert_eq!(marker.observed_read_path_count, 1);
    assert_eq!(
        transaction.prepare_next_read_window(),
        Err(PrivateOramAppendTransactionError::RecoveryRequired)
    );
    assert_eq!(
        transaction.finalize(),
        Err(PrivateOramAppendTransactionError::RecoveryRequired)
    );
}
