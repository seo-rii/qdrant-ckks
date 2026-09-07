use data_encoding::BASE64URL_NOPAD;
use proptest::prelude::*;
use qdrant_sec::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::Digest;

use crate::json_mutation::mutate_json_leaf;

#[allow(dead_code)]
#[path = "../src/json_mutation.rs"]
mod json_mutation;

fn digest(byte: u8) -> String {
    BASE64URL_NOPAD.encode(&[byte; 32])
}

fn leaf_label(value: u64) -> String {
    BASE64URL_NOPAD.encode(&value.to_be_bytes())
}

fn read_windows(offset: usize) -> Vec<PrivateOramAppendReadWindowV1> {
    let base = u64::try_from(offset * 3).unwrap();
    vec![
        PrivateOramAppendReadWindowV1 {
            sequence: 0,
            paths: vec![leaf_label(base), leaf_label(base + 1)],
        },
        PrivateOramAppendReadWindowV1 {
            sequence: 1,
            paths: vec![leaf_label(base + 1), leaf_label(base + 2)],
        },
    ]
}

fn deterministic_key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap()
}

fn capacity() -> PrivateOramIndexCapacityV2 {
    PrivateOramIndexCapacityV2 {
        bucket_count: 15,
        logical_capacity: 32,
        reserved_physical_slots: 16,
        max_client_stash_blocks: 8,
        fixed_append_read_path_count: 4,
        fixed_append_write_bucket_count: 16,
    }
}

fn hnsw_index() -> PrivateOramImmutableIndexV2 {
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
                ef_construction: 16,
                max_layers: 8,
                fixed_neighbor_slots: 4,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 512,
                tree_height: 3,
                path_batch_size: 2,
            },
            fixed_search_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 4,
                base_layer_steps: 16,
                paths_per_round: 2,
                fixed_result_k: 3,
            },
            max_neighbor_rewrites: 1,
        },
        capacity: capacity(),
    }
}

fn result_index() -> PrivateOramImmutableIndexV2 {
    PrivateOramImmutableIndexV2 {
        index_name: "private-payload".to_string(),
        params: PrivateOramImmutableIndexParamsV2::Result {
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
            key_id: "tenant-a/result-rk".to_string(),
            rk_id: "tenant-a/result-rk".to_string(),
            rk_epoch: 7,
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 512,
                tree_height: 3,
                path_batch_size: 2,
            },
        },
        capacity: capacity(),
    }
}

fn fixture_manifest(paired: bool) -> PrivateOramImmutableManifestV2 {
    let mut indexes = vec![hnsw_index()];
    if paired {
        indexes.push(result_index());
    }
    PrivateOramImmutableManifestV2 {
        version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
        collection_id: "collection-uuid-1".to_string(),
        manifest_nonce: digest(11),
        indexes,
        result_privacy: if paired {
            ResultPrivacyMode::PrivatePayloadOramRequired
        } else {
            ResultPrivacyMode::IdsVisible
        },
        owner_signing_key_id: "tenant-a/private-oram-owner-v2".to_string(),
        created_at_unix: 1_770_000_000,
    }
}

fn path_bucket_ids(leaf: u64, tree_height: u32) -> Vec<u64> {
    (0..=tree_height)
        .map(|level| {
            let level_start = (1u64 << level) - 1;
            let prefix = if level == 0 {
                0
            } else {
                leaf >> (tree_height - level)
            };
            level_start + prefix
        })
        .collect()
}

fn bucket_refs(seed: u8, offset: usize) -> Vec<PrivateOramAppendBucketRefV1> {
    read_windows(offset)
        .into_iter()
        .flat_map(|window| window.paths)
        .flat_map(|leaf_label| {
            let leaf_bytes = BASE64URL_NOPAD.decode(leaf_label.as_bytes()).unwrap();
            let leaf = u64::from_be_bytes(leaf_bytes.try_into().unwrap());
            path_bucket_ids(leaf, 3)
        })
        .enumerate()
        .map(|(occurrence, bucket_id)| {
            let digest_offset = u8::try_from(occurrence * 2).unwrap();
            PrivateOramAppendBucketRefV1 {
                bucket_id,
                ciphertext_sha256: digest(seed.checked_add(digest_offset).unwrap()),
                bucket_commitment: digest(seed.checked_add(digest_offset + 1).unwrap()),
            }
        })
        .collect()
}

fn fixture_state(
    manifest: &PrivateOramImmutableManifestV2,
    manifest_digest: &str,
    new: bool,
    mutation_id: &str,
) -> PrivateOramSignedStateV2 {
    let indexes = manifest
        .indexes
        .iter()
        .enumerate()
        .map(|(offset, index)| PrivateOramIndexStateV2 {
            kind: index.kind(),
            index_name: index.index_name.clone(),
            index_epoch: if new { 12 } else { 11 },
            root_hash: digest(if new {
                31 + u8::try_from(offset).unwrap()
            } else {
                21 + u8::try_from(offset).unwrap()
            }),
            logical_count: if new { 9 } else { 8 },
            dummy_count: if new { 23 } else { 24 },
            last_writeback_digest: digest(if new {
                51 + u8::try_from(offset).unwrap()
            } else {
                41 + u8::try_from(offset).unwrap()
            }),
        })
        .collect();
    PrivateOramSignedStateV2 {
        version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        collection_id: manifest.collection_id.clone(),
        manifest_digest: manifest_digest.to_string(),
        layout_generation: 5,
        layout_digest: digest(12),
        state_sequence: if new { 8 } else { 7 },
        indexes,
        client_state_digest: digest(if new { 62 } else { 61 }),
        last_mutation_id: Some(if new {
            mutation_id.to_string()
        } else {
            digest(60)
        }),
        owner_signing_key_id: manifest.owner_signing_key_id.clone(),
        signed_at_unix: if new { 1_770_000_130 } else { 1_770_000_100 },
    }
}

fn resign_mutation(key_pair: &Ed25519KeyPair, bundle: &mut PrivateOramAppendMutationBundleV1) {
    bundle.mutation.old_state.signature =
        sign_private_oram_signed_state_v2(key_pair, &bundle.mutation.old_state.state).unwrap();
    bundle.mutation.new_state.signature =
        sign_private_oram_signed_state_v2(key_pair, &bundle.mutation.new_state.state).unwrap();
    bundle.signature = sign_private_oram_append_mutation_v1(key_pair, &bundle.mutation).unwrap();
}

fn fixture(
    paired: bool,
) -> (
    Ed25519KeyPair,
    PrivateOramImmutableManifestBundleV2,
    PrivateOramAppendMutationBundleV1,
) {
    let key_pair = deterministic_key_pair();
    let manifest = fixture_manifest(paired);
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&manifest).unwrap();
    let manifest_bundle = package_private_oram_immutable_manifest_v2(&key_pair, manifest).unwrap();
    let mutation_id = digest(70);
    let old_state = fixture_state(
        &manifest_bundle.manifest,
        &manifest_digest,
        false,
        &mutation_id,
    );
    let mut new_state = fixture_state(
        &manifest_bundle.manifest,
        &manifest_digest,
        true,
        &mutation_id,
    );
    let mut writebacks = Vec::new();
    let old_state_digest = private_oram_signed_state_v2_digest(&old_state).unwrap();
    for offset in 0..old_state.indexes.len() {
        let old_index = &old_state.indexes[offset];
        let new_index = &new_state.indexes[offset];
        let updated_buckets = bucket_refs(80 + u8::try_from(offset * 32).unwrap(), offset);
        let windows = read_windows(offset);
        let observed_read =
            private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
                collection_id: &manifest_bundle.manifest.collection_id,
                manifest_digest: &manifest_digest,
                mutation_id: &mutation_id,
                old_state_digest: &old_state_digest,
                writer_lease_digest: &digest(13),
                writer_fence: 9,
                paths_per_window: 2,
                tree_height: 3,
                kind: old_index.kind,
                index_name: &old_index.index_name,
                windows: &windows,
            })
            .unwrap();
        let writeback = PrivateOramAppendIndexWritebackV1 {
            kind: old_index.kind,
            index_name: old_index.index_name.clone(),
            read_path_count: observed_read.read_path_count,
            read_transcript_digest: observed_read.transcript_digest,
            updated_buckets,
        };
        new_state.indexes[offset].last_writeback_digest =
            private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                collection_id: &manifest_bundle.manifest.collection_id,
                manifest_digest: &manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: old_index.index_epoch,
                new_epoch: new_index.index_epoch,
                old_root_hash: &old_index.root_hash,
                new_root_hash: &new_index.root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            })
            .unwrap();
        writebacks.push(writeback);
    }
    let point_operation_kind = if paired {
        PrivateOramPointOperationKindV1::NoServerPointRecord
    } else {
        PrivateOramPointOperationKindV1::VisiblePointRecord
    };
    let point_operation_digest = if paired {
        private_oram_no_server_point_record_v1_digest(
            &manifest_bundle.manifest.collection_id,
            &manifest_digest,
            &mutation_id,
        )
        .unwrap()
    } else {
        private_oram_visible_point_record_v1_digest(
            &manifest_bundle.manifest.collection_id,
            &manifest_digest,
            &mutation_id,
            PrivateOramVisiblePointRecordV1 {
                point_id: "42",
                staged_insert_sha256: &digest(98),
            },
        )
        .unwrap()
    };
    let old_state = package_private_oram_signed_state_v2(&key_pair, old_state).unwrap();
    let new_state = package_private_oram_signed_state_v2(&key_pair, new_state).unwrap();
    let mutation = PrivateOramAppendMutationV1 {
        version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
        mutation_id,
        collection_id: manifest_bundle.manifest.collection_id.clone(),
        manifest_digest,
        layout_generation: 5,
        writer_lease_digest: digest(13),
        writer_fence: 9,
        issued_at_unix: 1_770_000_120,
        expires_at_unix: 1_770_000_180,
        old_state,
        new_state,
        point_operation_kind,
        point_operation_digest,
        writebacks,
        owner_signing_key_id: manifest_bundle.manifest.owner_signing_key_id.clone(),
    };
    let mutation_bundle = package_private_oram_append_mutation_v1(&key_pair, mutation).unwrap();
    (key_pair, manifest_bundle, mutation_bundle)
}

struct ExpectedValidation {
    manifest_digest: String,
    layout_digest: String,
    writer_lease_digest: String,
    old_state_digest: String,
    visible_point_id: Option<String>,
    visible_staged_insert_sha256: Option<String>,
    observed_read_transcripts: Vec<PrivateOramObservedReadTranscriptV1>,
}

fn expected_validation(
    manifest: &PrivateOramImmutableManifestBundleV2,
    old_state_digest: &str,
) -> ExpectedValidation {
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&manifest.manifest).unwrap();
    let mutation_id = digest(70);
    let (visible_point_id, visible_staged_insert_sha256) = match manifest.manifest.result_privacy {
        ResultPrivacyMode::IdsVisible => (Some("42".to_string()), Some(digest(98))),
        ResultPrivacyMode::PrivatePayloadOramRequired => (None, None),
    };
    let writer_lease_digest = digest(13);
    let observed_read_transcripts = manifest
        .manifest
        .indexes
        .iter()
        .enumerate()
        .map(|(offset, index)| {
            let windows = read_windows(offset);
            private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
                collection_id: &manifest.manifest.collection_id,
                manifest_digest: &manifest_digest,
                mutation_id: &mutation_id,
                old_state_digest,
                writer_lease_digest: &writer_lease_digest,
                writer_fence: 9,
                paths_per_window: 2,
                tree_height: 3,
                kind: index.kind(),
                index_name: &index.index_name,
                windows: &windows,
            })
            .unwrap()
        })
        .collect();
    ExpectedValidation {
        manifest_digest,
        layout_digest: digest(12),
        writer_lease_digest,
        old_state_digest: old_state_digest.to_string(),
        visible_point_id,
        visible_staged_insert_sha256,
        observed_read_transcripts,
    }
}

fn validation_context<'a>(
    key_pair: &'a Ed25519KeyPair,
    manifest: &'a PrivateOramImmutableManifestBundleV2,
    expected: &'a ExpectedValidation,
) -> PrivateOramAppendValidationContext<'a> {
    PrivateOramAppendValidationContext {
        expected_collection_id: &manifest.manifest.collection_id,
        expected_manifest_digest: &expected.manifest_digest,
        expected_owner_signing_key_id: &manifest.manifest.owner_signing_key_id,
        expected_layout_generation: 5,
        expected_layout_digest: &expected.layout_digest,
        expected_writer_lease_digest: &expected.writer_lease_digest,
        expected_writer_fence: 9,
        expected_state_sequence: 7,
        expected_old_state_digest: &expected.old_state_digest,
        expected_visible_point_record: expected.visible_point_id.as_deref().map(|point_id| {
            PrivateOramVisiblePointRecordV1 {
                point_id,
                staged_insert_sha256: expected.visible_staged_insert_sha256.as_deref().unwrap(),
            }
        }),
        observed_read_transcripts: &expected.observed_read_transcripts,
        now_unix: 1_770_000_140,
        max_mutation_ttl_secs: 300,
        public_key: key_pair.public_key().as_ref(),
    }
}

fn validate_fixture(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateOramImmutableManifestBundleV2,
    mutation: &PrivateOramAppendMutationBundleV1,
    old_state_digest: &str,
) -> Result<(), PrivateOramMutationError> {
    let expected = expected_validation(manifest, old_state_digest);
    validate_private_oram_append_mutation_v1(
        manifest,
        mutation,
        validation_context(key_pair, manifest, &expected),
    )
}

#[test]
fn v2_contract_known_answers_are_stable() {
    let (key_pair, manifest, mutation) = fixture(true);
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&manifest.manifest).unwrap();
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let mutation_digest = private_oram_append_mutation_v1_digest(&mutation.mutation).unwrap();
    let public_key = BASE64URL_NOPAD.encode(key_pair.public_key().as_ref());
    assert_eq!(
        (
            manifest_digest.as_str(),
            old_state_digest.as_str(),
            mutation_digest.as_str(),
            manifest.signature.sig.as_str(),
            mutation.mutation.old_state.signature.sig.as_str(),
            mutation.signature.sig.as_str(),
            public_key.as_str(),
        ),
        (
            "eSae60fPObBj31V1HB5gXourNDEv7VXKyQmVuKfJ1hI",
            "bYbtgb90kq9YAyBgPrHBaGpYw31ZHHquymfe2VK2K9U",
            "pcpSKXjXg9AEHf9DCZEaubr6_IBIj9chx7eDYNFReR8",
            "eA6PMgv_qfsBbN2JDAyRRpHLZxBH7MIqJQN2v_uxlsopkriWPu0Fn8HjUsAAM4ZTBxCuP892SH5kKRy_553_BQ",
            "L8feWwlvr5x9NHvvV2j494oxnMhcM8m4v5qCT1MPQ_6bkjfz8s3AxaLJ-c0mijMJchnlw5tlwy8xcQgMUPOMDw",
            "TKn06fK4-rUMx7kyMxUlbS6qznTp5Vf3TR2PcMtdyfZsYe-ufaXdB3oMkSAKQJE5Ed8aGHVxzvhu-iQwVdARCw",
            "vtfSq2aNo--tYTmY8G96v3h186a3Z3qfPOlH1313YKY",
        )
    );
}

#[test]
fn read_transcript_preserves_order_and_multiplicity() {
    let manifest_digest =
        private_oram_immutable_manifest_v2_digest(&fixture_manifest(true)).unwrap();
    let writer_lease_digest = digest(13);
    let windows = read_windows(0);
    let transcript = |windows: &[PrivateOramAppendReadWindowV1]| {
        private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
            collection_id: "collection-uuid-1",
            manifest_digest: &manifest_digest,
            mutation_id: &digest(70),
            old_state_digest: &digest(71),
            writer_lease_digest: &writer_lease_digest,
            writer_fence: 9,
            paths_per_window: 2,
            tree_height: 3,
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: "text",
            windows,
        })
    };

    let canonical = transcript(&windows).unwrap();
    assert_eq!(canonical.read_path_count, 4);

    let mut reordered = windows.clone();
    reordered[0].paths.swap(0, 1);
    assert_ne!(
        transcript(&reordered).unwrap().transcript_digest,
        canonical.transcript_digest
    );

    let mut without_duplicate = windows.clone();
    without_duplicate[1].paths[0] = leaf_label(3);
    let deduplicated = transcript(&without_duplicate).unwrap();
    assert_eq!(deduplicated.read_path_count, 4);
    assert_ne!(deduplicated.transcript_digest, canonical.transcript_digest);
}

#[test]
fn read_transcript_rejects_noncontiguous_windows_and_malformed_paths() {
    let manifest_digest =
        private_oram_immutable_manifest_v2_digest(&fixture_manifest(true)).unwrap();
    let writer_lease_digest = digest(13);
    let transcript = |windows: &[PrivateOramAppendReadWindowV1]| {
        private_oram_append_read_transcript_v1(PrivateOramAppendReadTranscriptDigestInput {
            collection_id: "collection-uuid-1",
            manifest_digest: &manifest_digest,
            mutation_id: &digest(70),
            old_state_digest: &digest(71),
            writer_lease_digest: &writer_lease_digest,
            writer_fence: 9,
            paths_per_window: 2,
            tree_height: 3,
            kind: PrivateOramIndexKindV2::Hnsw,
            index_name: "text",
            windows,
        })
    };

    let mut noncontiguous = read_windows(0);
    noncontiguous[1].sequence = 2;
    assert_eq!(
        transcript(&noncontiguous),
        Err(PrivateOramMutationError::InvalidMutationField(
            "read_windows"
        ))
    );

    let mut short_window = read_windows(0);
    short_window[1].paths.pop();
    assert_eq!(
        transcript(&short_window),
        Err(PrivateOramMutationError::InvalidMutationField(
            "read_windows"
        ))
    );

    let mut malformed = read_windows(0);
    malformed[0].paths[0] = "not-a-leaf".to_string();
    assert_eq!(
        transcript(&malformed),
        Err(PrivateOramMutationError::InvalidMutationField(
            "read_windows.paths"
        ))
    );

    let mut out_of_range = read_windows(0);
    out_of_range[0].paths[0] = leaf_label(8);
    assert_eq!(
        transcript(&out_of_range),
        Err(PrivateOramMutationError::InvalidMutationField(
            "read_windows.paths"
        ))
    );

    let mut duplicate_in_window = read_windows(0);
    duplicate_in_window[0].paths[1] = duplicate_in_window[0].paths[0].clone();
    assert_eq!(
        transcript(&duplicate_in_window),
        Err(PrivateOramMutationError::InvalidMutationField(
            "read_windows.paths"
        ))
    );
}

fn signature_case(
    name: &str,
    domain: &str,
    key_id: &str,
    message: &[u8],
    signature: &str,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "domain": domain,
        "signature_alg": "ed25519",
        "signature_key_id": key_id,
        "signature_message_len": message.len(),
        "signature_message_b64": BASE64URL_NOPAD.encode(message),
        "signature_message_sha256_b64": BASE64URL_NOPAD.encode(&sha2::Sha256::digest(message)),
        "signature_b64": signature,
    })
}

fn digest_case(name: &str, domain: &str, message: &[u8], digest: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "domain": domain,
        "digest_message_len": message.len(),
        "digest_message_b64": BASE64URL_NOPAD.encode(message),
        "digest_b64": digest,
    })
}

fn private_oram_mutation_kat_vector() -> serde_json::Value {
    let (key_pair, manifest, mutation) = fixture(true);
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&manifest.manifest).unwrap();
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let manifest_message =
        try_private_oram_immutable_manifest_v2_signature_message(&manifest.manifest).unwrap();
    let old_state_message =
        try_private_oram_signed_state_v2_signature_message(&mutation.mutation.old_state.state)
            .unwrap();
    let mutation_message =
        try_private_oram_append_mutation_v1_signature_message(&mutation.mutation).unwrap();
    let new_state_message =
        try_private_oram_signed_state_v2_signature_message(&mutation.mutation.new_state.state)
            .unwrap();

    let mut read_inputs = Vec::new();
    let mut cases = vec![
        signature_case(
            "immutable_manifest_v2",
            PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_SIGNATURE_DOMAIN,
            &manifest.manifest.owner_signing_key_id,
            &manifest_message,
            &manifest.signature.sig,
        ),
        signature_case(
            "signed_state_v2",
            PRIVATE_ORAM_SIGNED_STATE_V2_SIGNATURE_DOMAIN,
            &mutation.mutation.old_state.state.owner_signing_key_id,
            &old_state_message,
            &mutation.mutation.old_state.signature.sig,
        ),
        signature_case(
            "append_mutation_v1",
            PRIVATE_ORAM_APPEND_MUTATION_V1_SIGNATURE_DOMAIN,
            &mutation.mutation.owner_signing_key_id,
            &mutation_message,
            &mutation.signature.sig,
        ),
    ];
    for (offset, index) in mutation.mutation.old_state.state.indexes.iter().enumerate() {
        let windows = read_windows(offset);
        let input = PrivateOramAppendReadTranscriptDigestInput {
            collection_id: &mutation.mutation.collection_id,
            manifest_digest: &manifest_digest,
            mutation_id: &mutation.mutation.mutation_id,
            old_state_digest: &old_state_digest,
            writer_lease_digest: &mutation.mutation.writer_lease_digest,
            writer_fence: mutation.mutation.writer_fence,
            paths_per_window: 2,
            tree_height: 3,
            kind: index.kind,
            index_name: &index.index_name,
            windows: &windows,
        };
        let message = try_private_oram_append_read_transcript_v1_digest_message(input).unwrap();
        read_inputs.push(serde_json::json!({
            "collection_id": input.collection_id,
            "manifest_digest": input.manifest_digest,
            "mutation_id": input.mutation_id,
            "old_state_digest": input.old_state_digest,
            "writer_lease_digest": input.writer_lease_digest,
            "writer_fence": input.writer_fence,
            "paths_per_window": input.paths_per_window,
            "tree_height": input.tree_height,
            "kind": input.kind,
            "index_name": input.index_name,
            "windows": windows,
        }));
        cases.push(digest_case(
            match offset {
                0 => "append_read_transcript_v1_hnsw",
                1 => "append_read_transcript_v1_result",
                _ => unreachable!(),
            },
            PRIVATE_ORAM_APPEND_READ_TRANSCRIPT_V1_DIGEST_DOMAIN,
            &message,
            &mutation.mutation.writebacks[offset].read_transcript_digest,
        ));
    }
    cases.push(signature_case(
        "new_signed_state_v2",
        PRIVATE_ORAM_SIGNED_STATE_V2_SIGNATURE_DOMAIN,
        &mutation.mutation.new_state.state.owner_signing_key_id,
        &new_state_message,
        &mutation.mutation.new_state.signature.sig,
    ));
    for (offset, writeback) in mutation.mutation.writebacks.iter().enumerate() {
        let old_index = &mutation.mutation.old_state.state.indexes[offset];
        let new_index = &mutation.mutation.new_state.state.indexes[offset];
        let message = try_private_oram_append_writeback_v1_digest_message(
            PrivateOramAppendWritebackDigestInput {
                collection_id: &mutation.mutation.collection_id,
                manifest_digest: &mutation.mutation.manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: old_index.index_epoch,
                new_epoch: new_index.index_epoch,
                old_root_hash: &old_index.root_hash,
                new_root_hash: &new_index.root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            },
        )
        .unwrap();
        cases.push(digest_case(
            match offset {
                0 => "append_writeback_v1_hnsw",
                1 => "append_writeback_v1_result",
                _ => unreachable!(),
            },
            PRIVATE_ORAM_APPEND_WRITEBACK_V1_DIGEST_DOMAIN,
            &message,
            &new_index.last_writeback_digest,
        ));
    }
    let no_server_message = try_private_oram_no_server_point_record_v1_digest_message(
        &mutation.mutation.collection_id,
        &mutation.mutation.manifest_digest,
        &mutation.mutation.mutation_id,
    )
    .unwrap();
    cases.push(digest_case(
        "no_server_point_record_v1",
        PRIVATE_ORAM_NO_SERVER_POINT_RECORD_V1_DIGEST_DOMAIN,
        &no_server_message,
        &mutation.mutation.point_operation_digest,
    ));

    let (_visible_key_pair, _visible_manifest, visible_mutation) = fixture(false);
    let visible_input = serde_json::json!({
        "collection_id": visible_mutation.mutation.collection_id,
        "manifest_digest": visible_mutation.mutation.manifest_digest,
        "mutation_id": visible_mutation.mutation.mutation_id,
        "point_id": "42",
        "staged_insert_sha256": digest(98),
    });
    let visible_record = PrivateOramVisiblePointRecordV1 {
        point_id: visible_input["point_id"].as_str().unwrap(),
        staged_insert_sha256: visible_input["staged_insert_sha256"].as_str().unwrap(),
    };
    let visible_message = try_private_oram_visible_point_record_v1_digest_message(
        visible_input["collection_id"].as_str().unwrap(),
        visible_input["manifest_digest"].as_str().unwrap(),
        visible_input["mutation_id"].as_str().unwrap(),
        visible_record,
    )
    .unwrap();
    cases.push(digest_case(
        "visible_point_record_v1",
        PRIVATE_ORAM_VISIBLE_POINT_RECORD_V1_DIGEST_DOMAIN,
        &visible_message,
        &visible_mutation.mutation.point_operation_digest,
    ));

    serde_json::json!({
        "format": "qdrant-sec/private-oram-v2-append-contract-test-vector/v1",
        "fixture": "paired_hnsw_result_append",
        "deterministic_seed_hex": "25".repeat(32),
        "public_key_b64": BASE64URL_NOPAD.encode(key_pair.public_key().as_ref()),
        "inputs": {
            "immutable_manifest_v2": manifest.manifest,
            "signed_state_v2": mutation.mutation.old_state.state,
            "append_mutation_v1": mutation.mutation,
            "append_read_transcripts_v1": read_inputs,
            "visible_point_record_v1": visible_input,
        },
        "cases": cases,
    })
}

#[test]
fn v2_contract_json_test_vector_matches_known_answers() {
    let generated = private_oram_mutation_kat_vector();
    if std::env::var_os("QDRANT_SEC_UPDATE_PRIVATE_ORAM_MUTATION_KAT").is_some() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/qdrant-sec-private-oram-mutation-signature-test-vector.json");
        let mut encoded = serde_json::to_vec_pretty(&generated).unwrap();
        encoded.push(b'\n');
        std::fs::write(path, encoded).unwrap();
        return;
    }
    let (_key_pair, manifest, mutation) = fixture(true);
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/qdrant-sec-private-oram-mutation-signature-test-vector.json"
    ))
    .unwrap();
    assert_eq!(vector, generated);
    assert_eq!(
        vector["public_key_b64"],
        serde_json::json!("vtfSq2aNo--tYTmY8G96v3h186a3Z3qfPOlH1313YKY")
    );
    assert_eq!(
        vector["deterministic_seed_hex"],
        serde_json::json!("25".repeat(32))
    );
    assert_eq!(
        serde_json::from_value::<PrivateOramImmutableManifestV2>(
            vector["inputs"]["immutable_manifest_v2"].clone()
        )
        .unwrap(),
        manifest.manifest
    );
    assert_eq!(
        serde_json::from_value::<PrivateOramSignedStateV2>(
            vector["inputs"]["signed_state_v2"].clone()
        )
        .unwrap(),
        mutation.mutation.old_state.state
    );
    assert_eq!(
        serde_json::from_value::<PrivateOramAppendMutationV1>(
            vector["inputs"]["append_mutation_v1"].clone()
        )
        .unwrap(),
        mutation.mutation
    );

    let cases = vector["cases"].as_array().unwrap();
    let case = |name: &str| {
        cases
            .iter()
            .find(|case| case["name"].as_str() == Some(name))
            .unwrap()
    };
    let manifest_case = case("immutable_manifest_v2");
    let state_case = case("signed_state_v2");
    let mutation_case = case("append_mutation_v1");
    assert_eq!(
        manifest_case["domain"],
        serde_json::json!(PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_SIGNATURE_DOMAIN)
    );
    assert_eq!(
        state_case["domain"],
        serde_json::json!(PRIVATE_ORAM_SIGNED_STATE_V2_SIGNATURE_DOMAIN)
    );
    assert_eq!(
        mutation_case["domain"],
        serde_json::json!(PRIVATE_ORAM_APPEND_MUTATION_V1_SIGNATURE_DOMAIN)
    );
    assert_eq!(
        manifest_case["signature_message_sha256_b64"],
        serde_json::json!(private_oram_immutable_manifest_v2_digest(&manifest.manifest).unwrap())
    );
    assert_eq!(
        manifest_case["signature_b64"],
        serde_json::json!(manifest.signature.sig)
    );
    assert_eq!(
        state_case["signature_message_sha256_b64"],
        serde_json::json!(
            private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap()
        )
    );
    assert_eq!(
        state_case["signature_b64"],
        serde_json::json!(mutation.mutation.old_state.signature.sig)
    );
    assert_eq!(
        mutation_case["signature_message_sha256_b64"],
        serde_json::json!(private_oram_append_mutation_v1_digest(&mutation.mutation).unwrap())
    );
    assert_eq!(
        mutation_case["signature_b64"],
        serde_json::json!(mutation.signature.sig)
    );
    assert_eq!(
        manifest_case["signature_message_len"],
        serde_json::json!(
            try_private_oram_immutable_manifest_v2_signature_message(&manifest.manifest)
                .unwrap()
                .len()
        )
    );
    assert_eq!(
        state_case["signature_message_len"],
        serde_json::json!(
            try_private_oram_signed_state_v2_signature_message(&mutation.mutation.old_state.state)
                .unwrap()
                .len()
        )
    );
    assert_eq!(
        mutation_case["signature_message_len"],
        serde_json::json!(
            try_private_oram_append_mutation_v1_signature_message(&mutation.mutation)
                .unwrap()
                .len()
        )
    );
    assert_eq!(
        manifest_case["signature_message_b64"],
        serde_json::json!(BASE64URL_NOPAD.encode(
            &try_private_oram_immutable_manifest_v2_signature_message(&manifest.manifest).unwrap()
        ))
    );
    assert_eq!(
        state_case["signature_message_b64"],
        serde_json::json!(
            BASE64URL_NOPAD.encode(
                &try_private_oram_signed_state_v2_signature_message(
                    &mutation.mutation.old_state.state
                )
                .unwrap()
            )
        )
    );
    assert_eq!(
        mutation_case["signature_message_b64"],
        serde_json::json!(BASE64URL_NOPAD.encode(
            &try_private_oram_append_mutation_v1_signature_message(&mutation.mutation).unwrap()
        ))
    );

    let read_inputs = vector["inputs"]["append_read_transcripts_v1"]
        .as_array()
        .unwrap();
    for (offset, input) in read_inputs.iter().enumerate() {
        let windows =
            serde_json::from_value::<Vec<PrivateOramAppendReadWindowV1>>(input["windows"].clone())
                .unwrap();
        let message = try_private_oram_append_read_transcript_v1_digest_message(
            PrivateOramAppendReadTranscriptDigestInput {
                collection_id: input["collection_id"].as_str().unwrap(),
                manifest_digest: input["manifest_digest"].as_str().unwrap(),
                mutation_id: input["mutation_id"].as_str().unwrap(),
                old_state_digest: input["old_state_digest"].as_str().unwrap(),
                writer_lease_digest: input["writer_lease_digest"].as_str().unwrap(),
                writer_fence: input["writer_fence"].as_u64().unwrap(),
                paths_per_window: u32::try_from(input["paths_per_window"].as_u64().unwrap())
                    .unwrap(),
                tree_height: u32::try_from(input["tree_height"].as_u64().unwrap()).unwrap(),
                kind: serde_json::from_value(input["kind"].clone()).unwrap(),
                index_name: input["index_name"].as_str().unwrap(),
                windows: &windows,
            },
        )
        .unwrap();
        let case = case(match offset {
            0 => "append_read_transcript_v1_hnsw",
            1 => "append_read_transcript_v1_result",
            _ => unreachable!(),
        });
        assert_eq!(
            case["domain"],
            serde_json::json!(PRIVATE_ORAM_APPEND_READ_TRANSCRIPT_V1_DIGEST_DOMAIN)
        );
        assert_eq!(case["digest_message_len"], serde_json::json!(message.len()));
        assert_eq!(
            case["digest_message_b64"],
            serde_json::json!(BASE64URL_NOPAD.encode(&message))
        );
        assert_eq!(
            case["digest_b64"],
            serde_json::json!(mutation.mutation.writebacks[offset].read_transcript_digest)
        );
    }

    let new_state_message =
        try_private_oram_signed_state_v2_signature_message(&mutation.mutation.new_state.state)
            .unwrap();
    let new_state_case = case("new_signed_state_v2");
    assert_eq!(
        new_state_case["domain"],
        serde_json::json!(PRIVATE_ORAM_SIGNED_STATE_V2_SIGNATURE_DOMAIN)
    );
    assert_eq!(
        new_state_case["signature_message_len"],
        serde_json::json!(new_state_message.len())
    );
    assert_eq!(
        new_state_case["signature_message_b64"],
        serde_json::json!(BASE64URL_NOPAD.encode(&new_state_message))
    );
    assert_eq!(
        new_state_case["signature_message_sha256_b64"],
        serde_json::json!(
            private_oram_signed_state_v2_digest(&mutation.mutation.new_state.state).unwrap()
        )
    );
    assert_eq!(
        new_state_case["signature_b64"],
        serde_json::json!(mutation.mutation.new_state.signature.sig)
    );

    for offset in 0..mutation.mutation.writebacks.len() {
        let old_index = &mutation.mutation.old_state.state.indexes[offset];
        let new_index = &mutation.mutation.new_state.state.indexes[offset];
        let writeback = &mutation.mutation.writebacks[offset];
        let message = try_private_oram_append_writeback_v1_digest_message(
            PrivateOramAppendWritebackDigestInput {
                collection_id: &mutation.mutation.collection_id,
                manifest_digest: &mutation.mutation.manifest_digest,
                kind: writeback.kind,
                index_name: &writeback.index_name,
                old_epoch: old_index.index_epoch,
                new_epoch: new_index.index_epoch,
                old_root_hash: &old_index.root_hash,
                new_root_hash: &new_index.root_hash,
                read_path_count: writeback.read_path_count,
                read_transcript_digest: &writeback.read_transcript_digest,
                updated_buckets: &writeback.updated_buckets,
            },
        )
        .unwrap();
        let writeback_case = case(match offset {
            0 => "append_writeback_v1_hnsw",
            1 => "append_writeback_v1_result",
            _ => unreachable!(),
        });
        assert_eq!(
            writeback_case["domain"],
            serde_json::json!(PRIVATE_ORAM_APPEND_WRITEBACK_V1_DIGEST_DOMAIN)
        );
        assert_eq!(
            writeback_case["digest_message_len"],
            serde_json::json!(message.len())
        );
        assert_eq!(
            writeback_case["digest_message_b64"],
            serde_json::json!(BASE64URL_NOPAD.encode(&message))
        );
        assert_eq!(
            writeback_case["digest_b64"],
            serde_json::json!(new_index.last_writeback_digest)
        );
    }

    let no_server_message = try_private_oram_no_server_point_record_v1_digest_message(
        &mutation.mutation.collection_id,
        &mutation.mutation.manifest_digest,
        &mutation.mutation.mutation_id,
    )
    .unwrap();
    let no_server_case = case("no_server_point_record_v1");
    assert_eq!(
        no_server_case["domain"],
        serde_json::json!(PRIVATE_ORAM_NO_SERVER_POINT_RECORD_V1_DIGEST_DOMAIN)
    );
    assert_eq!(
        no_server_case["digest_message_len"],
        serde_json::json!(no_server_message.len())
    );
    assert_eq!(
        no_server_case["digest_message_b64"],
        serde_json::json!(BASE64URL_NOPAD.encode(&no_server_message))
    );
    assert_eq!(
        no_server_case["digest_b64"],
        serde_json::json!(mutation.mutation.point_operation_digest)
    );

    let visible_input = &vector["inputs"]["visible_point_record_v1"];
    let (_visible_key_pair, visible_manifest, visible_mutation) = fixture(false);
    assert_eq!(
        visible_input["manifest_digest"],
        serde_json::json!(
            private_oram_immutable_manifest_v2_digest(&visible_manifest.manifest).unwrap()
        )
    );
    let visible_record = PrivateOramVisiblePointRecordV1 {
        point_id: visible_input["point_id"].as_str().unwrap(),
        staged_insert_sha256: visible_input["staged_insert_sha256"].as_str().unwrap(),
    };
    let visible_message = try_private_oram_visible_point_record_v1_digest_message(
        visible_input["collection_id"].as_str().unwrap(),
        visible_input["manifest_digest"].as_str().unwrap(),
        visible_input["mutation_id"].as_str().unwrap(),
        visible_record,
    )
    .unwrap();
    let visible_case = case("visible_point_record_v1");
    assert_eq!(
        visible_case["domain"],
        serde_json::json!(PRIVATE_ORAM_VISIBLE_POINT_RECORD_V1_DIGEST_DOMAIN)
    );
    assert_eq!(
        visible_case["digest_message_len"],
        serde_json::json!(visible_message.len())
    );
    assert_eq!(
        visible_case["digest_message_b64"],
        serde_json::json!(BASE64URL_NOPAD.encode(&visible_message))
    );
    assert_eq!(
        visible_case["digest_b64"],
        serde_json::json!(visible_mutation.mutation.point_operation_digest)
    );
    assert_eq!(
        visible_mutation.mutation.point_operation_digest,
        private_oram_visible_point_record_v1_digest(
            visible_input["collection_id"].as_str().unwrap(),
            visible_input["manifest_digest"].as_str().unwrap(),
            visible_input["mutation_id"].as_str().unwrap(),
            visible_record,
        )
        .unwrap()
    );
}

#[test]
fn paired_append_contract_signs_and_validates_round_trip() {
    let (key_pair, manifest, mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest).unwrap();
}

#[test]
fn hnsw_only_visible_point_append_validates() {
    let (key_pair, manifest, mutation) = fixture(false);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest).unwrap();
}

#[test]
fn append_rejects_observed_transcript_whose_digest_does_not_cover_its_paths() {
    let (key_pair, manifest, mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let mut expected = expected_validation(&manifest, &old_state_digest);
    // The digest still matches the writeback, but no longer covers the labels it sits beside.
    expected.observed_read_transcripts[0]
        .ordered_leaf_labels
        .swap(0, 1);
    assert_eq!(
        validate_private_oram_append_mutation_v1(
            &manifest,
            &mutation,
            validation_context(&key_pair, &manifest, &expected),
        ),
        Err(PrivateOramMutationError::InvalidMutationField(
            "observed_read_transcripts.transcript_digest"
        ))
    );
}

#[test]
fn manifest_rejects_capacity_without_reserved_slack_and_mixed_capacities() {
    let mut manifest = fixture_manifest(true);
    manifest.indexes[0].capacity.reserved_physical_slots = 29;
    assert!(matches!(
        validate_private_oram_immutable_manifest_v2_shape(&manifest),
        Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.capacity"
        ))
    ));

    let mut manifest = fixture_manifest(true);
    manifest.indexes[1].capacity.logical_capacity -= 1;
    assert!(matches!(
        validate_private_oram_immutable_manifest_v2_shape(&manifest),
        Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.logical_capacity"
        ))
    ));

    let mut manifest = fixture_manifest(false);
    manifest.indexes[0].capacity.fixed_append_write_bucket_count = 3;
    assert!(matches!(
        validate_private_oram_immutable_manifest_v2_shape(&manifest),
        Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.capacity"
        ))
    ));

    let mut manifest = fixture_manifest(false);
    manifest.indexes[0].capacity.fixed_append_read_path_count = 3;
    assert!(matches!(
        validate_private_oram_immutable_manifest_v2_shape(&manifest),
        Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.capacity"
        ))
    ));

    let mut manifest = fixture_manifest(false);
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        max_neighbor_rewrites,
        ..
    } = &mut manifest.indexes[0].params
    else {
        unreachable!()
    };
    *max_neighbor_rewrites = 3;
    assert!(matches!(
        validate_private_oram_immutable_manifest_v2_shape(&manifest),
        Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.max_neighbor_rewrites"
        ))
    ));

    // fixed_append_read_path_count=4, path_batch_size=2: two rewrites plus the insert leave a
    // single candidate path, less than one candidate window, so no append into a non-empty
    // graph could ever be planned against this immutable manifest.
    let mut manifest = fixture_manifest(false);
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        max_neighbor_rewrites,
        ..
    } = &mut manifest.indexes[0].params
    else {
        unreachable!()
    };
    *max_neighbor_rewrites = 2;
    assert!(matches!(
        validate_private_oram_immutable_manifest_v2_shape(&manifest),
        Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.max_neighbor_rewrites"
        ))
    ));

    let mut manifest = fixture_manifest(false);
    let PrivateOramImmutableIndexParamsV2::Hnsw {
        vector_encoding, ..
    } = &mut manifest.indexes[0].params
    else {
        unreachable!()
    };
    *vector_encoding = PrivateHnswVectorEncoding::I8Quantized;
    assert!(matches!(
        validate_private_oram_immutable_manifest_v2_shape(&manifest),
        Err(PrivateOramMutationError::InvalidManifestField(
            "indexes.hnsw"
        ))
    ));
}

#[test]
fn signed_state_rejects_mixed_paired_occupancy() {
    let manifest = fixture_manifest(true);
    let manifest_digest = private_oram_immutable_manifest_v2_digest(&manifest).unwrap();
    let mut state = fixture_state(&manifest, &manifest_digest, false, &digest(70));
    state.indexes[1].logical_count += 1;
    state.indexes[1].dummy_count -= 1;
    assert!(matches!(
        validate_private_oram_signed_state_v2_shape(&state),
        Err(PrivateOramMutationError::InvalidStateField(
            "indexes.occupancy"
        ))
    ));
}

#[test]
fn append_rejects_stale_sequence_and_skipped_epoch() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let expected = expected_validation(&manifest, &old_state_digest);
    let mut context = validation_context(&key_pair, &manifest, &expected);
    context.expected_state_sequence += 1;
    assert_eq!(
        validate_private_oram_append_mutation_v1(&manifest, &mutation, context),
        Err(PrivateOramMutationError::StaleState)
    );

    mutation.mutation.new_state.state.indexes[0].index_epoch += 1;
    resign_mutation(&key_pair, &mut mutation);
    assert!(matches!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::InvalidStateTransition(
            "index_epoch"
        ))
    ));
}

#[test]
fn append_rejects_capacity_exhaustion_and_unchanged_private_state() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    for index in &mut mutation.mutation.old_state.state.indexes {
        index.logical_count = 32;
        index.dummy_count = 0;
    }
    for index in &mut mutation.mutation.new_state.state.indexes {
        index.logical_count = 33;
        index.dummy_count = 0;
    }
    resign_mutation(&key_pair, &mut mutation);
    let exhausted_old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &exhausted_old_state_digest,),
        Err(PrivateOramMutationError::CapacityExhausted)
    );

    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.new_state.state.client_state_digest = mutation
        .mutation
        .old_state
        .state
        .client_state_digest
        .clone();
    resign_mutation(&key_pair, &mut mutation);
    assert!(matches!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::InvalidStateTransition(
            "client_state_digest"
        ))
    ));

    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.new_state.state.indexes[0].root_hash =
        mutation.mutation.old_state.state.indexes[0]
            .root_hash
            .clone();
    resign_mutation(&key_pair, &mut mutation);
    assert!(matches!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::InvalidStateTransition(
            "root_hash"
        ))
    ));
}

#[test]
fn append_rejects_out_of_order_path_frames_and_non_fixed_bucket_batches() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.writebacks[0].updated_buckets.swap(0, 1);
    resign_mutation(&key_pair, &mut mutation);
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::FixedBudgetMismatch)
    );

    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.writebacks[0].updated_buckets.pop();
    resign_mutation(&key_pair, &mut mutation);
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::FixedBudgetMismatch)
    );
}

#[test]
fn append_rejects_wrong_writeback_digest_and_out_of_range_bucket() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.writebacks[0].updated_buckets[0].ciphertext_sha256 = digest(111);
    resign_mutation(&key_pair, &mut mutation);
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::WritebackDigestMismatch)
    );

    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.writebacks[0].updated_buckets[3].bucket_id = 15;
    resign_mutation(&key_pair, &mut mutation);
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::FixedBudgetMismatch)
    );
}

#[test]
fn append_rejects_point_operation_drift_and_expiry() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.point_operation_digest = digest(123);
    resign_mutation(&key_pair, &mut mutation);
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::PointOperationMismatch)
    );

    let (key_pair, manifest, mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let expected = expected_validation(&manifest, &old_state_digest);
    let mut context = validation_context(&key_pair, &manifest, &expected);
    context.now_unix = mutation.mutation.expires_at_unix + 1;
    assert_eq!(
        validate_private_oram_append_mutation_v1(&manifest, &mutation, context),
        Err(PrivateOramMutationError::MutationExpired)
    );
}

#[test]
fn append_derives_result_privacy_from_manifest() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.point_operation_kind = PrivateOramPointOperationKindV1::VisiblePointRecord;
    mutation.mutation.point_operation_digest = digest(99);
    resign_mutation(&key_pair, &mut mutation);
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::PointOperationMismatch)
    );
}

#[test]
fn append_rejects_unobserved_read_transcript_and_stale_writer_fence() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.writebacks[0].read_transcript_digest = digest(122);
    resign_mutation(&key_pair, &mut mutation);
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::FixedBudgetMismatch)
    );

    let (key_pair, manifest, mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let mut expected = expected_validation(&manifest, &old_state_digest);
    expected.observed_read_transcripts[0].paths_per_window = 1;
    assert_eq!(
        validate_private_oram_append_mutation_v1(
            &manifest,
            &mutation,
            validation_context(&key_pair, &manifest, &expected),
        ),
        Err(PrivateOramMutationError::InvalidMutationField(
            "observed_read_transcripts.transcript_digest"
        ))
    );

    let (key_pair, manifest, mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let mut expected = expected_validation(&manifest, &old_state_digest);
    expected.observed_read_transcripts[0].manifest_digest = digest(124);
    assert_eq!(
        validate_private_oram_append_mutation_v1(
            &manifest,
            &mutation,
            validation_context(&key_pair, &manifest, &expected),
        ),
        Err(PrivateOramMutationError::InvalidMutationField(
            "observed_read_transcripts.transcript_digest"
        ))
    );

    let (key_pair, manifest, mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let expected = expected_validation(&manifest, &old_state_digest);
    let mut context = validation_context(&key_pair, &manifest, &expected);
    context.expected_writer_fence += 1;
    assert!(matches!(
        validate_private_oram_append_mutation_v1(&manifest, &mutation, context),
        Err(PrivateOramMutationError::MutationContextMismatch(
            "writer_lease"
        ))
    ));

    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.writer_fence += 1;
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::InvalidMutationSignature)
    );
}

#[test]
fn append_rejects_sequence_and_epoch_overflow() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    mutation.mutation.old_state.state.state_sequence = u64::MAX;
    mutation.mutation.new_state.state.state_sequence = 0;
    mutation.mutation.new_state.state.last_mutation_id = None;
    resign_mutation(&key_pair, &mut mutation);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let expected = expected_validation(&manifest, &old_state_digest);
    let mut context = validation_context(&key_pair, &manifest, &expected);
    context.expected_state_sequence = u64::MAX;
    assert!(matches!(
        validate_private_oram_append_mutation_v1(&manifest, &mutation, context),
        Err(PrivateOramMutationError::InvalidStateTransition(
            "state_sequence"
        ))
    ));

    let (key_pair, manifest, mut mutation) = fixture(true);
    mutation.mutation.old_state.state.indexes[0].index_epoch = u64::MAX;
    mutation.mutation.new_state.state.indexes[0].index_epoch = 0;
    resign_mutation(&key_pair, &mut mutation);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    assert!(matches!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::InvalidStateTransition(
            "index_epoch"
        ))
    ));
}

#[test]
fn append_rejects_immediate_mutation_id_reuse_and_future_state_time() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    mutation.mutation.old_state.state.last_mutation_id =
        Some(mutation.mutation.mutation_id.clone());
    resign_mutation(&key_pair, &mut mutation);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    assert!(matches!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::InvalidStateTransition(
            "mutation_id"
        ))
    ));

    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.new_state.state.signed_at_unix = 1_770_000_150;
    resign_mutation(&key_pair, &mut mutation);
    assert!(matches!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::InvalidStateTransition(
            "signed_at_unix"
        ))
    ));
}

#[test]
fn append_rejects_tampered_state_and_mutation_signatures() {
    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.mutation.new_state.signature.sig = BASE64URL_NOPAD.encode(&[0; 64]);
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::InvalidStateSignature)
    );

    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.signature.sig = BASE64URL_NOPAD.encode(&[0; 64]);
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::InvalidMutationSignature)
    );

    let (key_pair, manifest, mut mutation) = fixture(true);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    mutation.signature.key_id = "tenant-a/other-owner".to_string();
    assert_eq!(
        validate_fixture(&key_pair, &manifest, &mutation, &old_state_digest),
        Err(PrivateOramMutationError::SignatureKeyIdMismatch)
    );
}

#[test]
fn contract_serde_rejects_unknown_fields_and_debug_redacts_values() {
    let (_key_pair, manifest, mutation) = fixture(true);
    let mut value = serde_json::to_value(&manifest.manifest).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("position_map".to_string(), serde_json::json!("sentinel"));
    assert!(serde_json::from_value::<PrivateOramImmutableManifestV2>(value).is_err());

    let mut value = serde_json::to_value(&mutation.mutation).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("query_vector".to_string(), serde_json::json!("sentinel"));
    assert!(serde_json::from_value::<PrivateOramAppendMutationV1>(value).is_err());

    let manifest_debug = format!("{:?}", manifest.manifest);
    let mutation_debug = format!("{:?}", mutation.mutation);
    let old_state_digest =
        private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
    let expected = expected_validation(&manifest, &old_state_digest);
    let observed_debug = format!("{:?}", expected.observed_read_transcripts[0]);
    let visible_point_id = "point-id-sentinel";
    let visible_staged_insert_sha256 = digest(125);
    let visible_debug = format!(
        "{:?}",
        PrivateOramVisiblePointRecordV1 {
            point_id: visible_point_id,
            staged_insert_sha256: &visible_staged_insert_sha256,
        }
    );
    for sentinel in [
        manifest.manifest.collection_id.as_str(),
        manifest.manifest.manifest_nonce.as_str(),
        manifest.manifest.owner_signing_key_id.as_str(),
        mutation.mutation.mutation_id.as_str(),
        mutation.mutation.point_operation_digest.as_str(),
        mutation
            .mutation
            .old_state
            .state
            .client_state_digest
            .as_str(),
    ] {
        assert!(!manifest_debug.contains(sentinel));
        assert!(!mutation_debug.contains(sentinel));
    }
    for sentinel in [
        expected.observed_read_transcripts[0].collection_id.as_str(),
        expected.observed_read_transcripts[0]
            .manifest_digest
            .as_str(),
        expected.observed_read_transcripts[0].mutation_id.as_str(),
        expected.observed_read_transcripts[0]
            .old_state_digest
            .as_str(),
        expected.observed_read_transcripts[0]
            .writer_lease_digest
            .as_str(),
        expected.observed_read_transcripts[0]
            .transcript_digest
            .as_str(),
    ] {
        assert!(!observed_debug.contains(sentinel));
    }
    assert!(!visible_debug.contains(visible_point_id));
    assert!(!visible_debug.contains(&visible_staged_insert_sha256));
    let error_debug = format!(
        "{:?}",
        PrivateOramMutationError::UnsupportedSignatureAlgorithm(
            "signature-algorithm-sentinel".to_string()
        )
    );
    assert!(!error_debug.contains("signature-algorithm-sentinel"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Every scalar field of a signed append mutation bundle (the embedded signed states and
    /// the bundle signature included) is covered by a signature or a digest the validator
    /// recomputes: changing any one of them is rejected.
    #[test]
    fn every_field_mutation_of_a_signed_append_mutation_is_rejected(
        index in any::<usize>(),
        salt in any::<u8>(),
    ) {
        let (key_pair, manifest, mutation) = fixture(true);
        let old_state_digest =
            private_oram_signed_state_v2_digest(&mutation.mutation.old_state.state).unwrap();
        let mut value = serde_json::to_value(&mutation).unwrap();
        let path = mutate_json_leaf(&mut value, index, salt);
        if let Ok(mutated) = serde_json::from_value::<PrivateOramAppendMutationBundleV1>(value) {
            prop_assert!(
                validate_fixture(&key_pair, &manifest, &mutated, &old_state_digest).is_err(),
                "mutation at {} was accepted",
                path
            );
        }
    }
}
