//! Property-based and fuzz-style tests for the untrusted-input surfaces of the crypto crate.
//!
//! Every decoder, verifier and state machine here consumes bytes that arrive from a peer, the
//! server or persisted state. The properties asserted are:
//!
//! - no input makes a decoder or verifier panic (fail closed instead);
//! - encoders and decoders are exact inverses on the accepted set (canonical encodings);
//! - any mutation of authenticated data is rejected;
//! - fixed-shape privacy invariants (batch sizes, path lengths) hold regardless of collisions;
//! - the Path ORAM client never loses or duplicates a block across arbitrary access sequences.

use std::collections::{BTreeMap, BTreeSet};

use data_encoding::BASE64URL_NOPAD;
use proptest::prelude::*;
use qdrant_sec::control_plane::{
    CiphertextEnvelope, CryptoCapability, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
};
use qdrant_sec::payload::{
    ClientPayloadValidationContext, PayloadEncryptionPolicy, PayloadTextEncryptor,
    is_client_encrypted_payload_value, is_encrypted_payload_value, validate_client_payload_value,
};
use qdrant_sec::private_hnsw_client::*;
use qdrant_sec::private_hnsw_oram::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PrivateHnswManifestValidationContext,
    PrivateHnswOramBucket, PrivateHnswOramManifest, PrivateHnswOramSignature,
    PrivateHnswOramUploadBundle, PrivateHnswParams, PrivateHnswSignatureVerification,
    ResultPrivacyMode, validate_private_hnsw_oram_manifest_shape,
    validate_private_hnsw_oram_manifest_signature_shape, validate_private_hnsw_oram_upload_bundle,
    validate_private_hnsw_oram_upload_bundle_with_signature,
};
use qdrant_sec::private_oram_append_client::{
    PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION, PrivateOramAppendMerklePatchLeafV1,
    PrivateOramAppendMerklePatchProofV1, PrivateOramAppendMerkleSiblingPositionV1,
    PrivateOramAppendMerkleSiblingV1, apply_private_oram_append_sparse_merkle_patch_v1,
};
use qdrant_sec::private_oram_mutation::PrivateOramAppendBucketRefV1;
use qdrant_sec::private_oram_owner_lifecycle::{
    decode_private_oram_owner_enrollment_genesis_commitment_v1,
    decode_private_oram_owner_enrollment_prepared_v1,
    decode_private_oram_owner_lifecycle_status_attestation_v1,
};
use qdrant_sec::private_oram_owner_prestage::{
    decode_private_oram_owner_prestage_attestation_v2,
    decode_private_oram_owner_prestage_package_v2,
};
use qdrant_sec::private_oram_owner_reservation_prepare::decode_private_oram_owner_reservation_prepare_v1;
use qdrant_sec::private_oram_owner_reservation_resolution::decode_private_oram_owner_reservation_resolution_receipt_v1;
use qdrant_sec::private_oram_point_staging::*;
use qdrant_sec::private_result_oram::*;
use qdrant_sec::vector::{
    CkksParameters, CkksPublicMaterial, ClientCkksVectorSignatureVerification,
    ClientCkksVectorValidationContext, client_ckks_vector_sidecar_envelope_key,
    client_ckks_vector_signature_message, is_client_ckks_vector_payload_value,
    is_encrypted_ckks_vector_payload_value, validate_client_ckks_vector_payload_value_for_runtime,
};
use qdrant_sec::{AeadCipher, EncryptedEnvelope, EncryptionContext, SecretKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------------------------

const COLLECTION_ID: &str = "collection-uuid-fuzz";
const KEY_ID: &str = "tenant-a:fuzz";
const RK_ID: &str = "tenant-a/fuzz-rk";
const RK_EPOCH: u64 = 3;
const VECTOR_NAME: &str = "text";

fn cases(n: u32) -> ProptestConfig {
    ProptestConfig {
        cases: n,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn digest(byte: u8) -> String {
    BASE64URL_NOPAD.encode(&[byte; 32])
}

fn fixed_cipher() -> AeadCipher {
    AeadCipher::new_with_material_fingerprint(
        KEY_ID,
        SecretKey::from_bytes([7; 32]),
        "tenant-a/fuzz@v1",
    )
    .unwrap()
    .with_resource_key_metadata(RK_ID, RK_EPOCH)
    .unwrap()
}

fn payload_context<'a>(point_id: &'a str) -> EncryptionContext<'a> {
    EncryptionContext::payload_text("docs", point_id, "body")
}

fn result_keys() -> PrivateResultOramClientKeys {
    PrivateResultOramClientKeys::derive_from_resource_key_with_context(
        &SecretKey::from_bytes([9; 32]),
        COLLECTION_ID,
        RK_ID,
        RK_EPOCH,
    )
    .unwrap()
}

fn hnsw_keys() -> PrivateHnswClientKeys {
    PrivateHnswClientKeys::derive_from_resource_key_with_context(
        &SecretKey::from_bytes([11; 32]),
        COLLECTION_ID,
        VECTOR_NAME,
        RK_ID,
        RK_EPOCH,
    )
    .unwrap()
}

fn result_base_context() -> PrivateResultOramBucketAeadBaseContext<'static> {
    PrivateResultOramBucketAeadBaseContext {
        collection_id: COLLECTION_ID,
        key_id: KEY_ID,
        rk_id: RK_ID,
        rk_epoch: RK_EPOCH,
    }
}

fn hnsw_base_context() -> PrivateHnswBucketAeadBaseContext<'static> {
    PrivateHnswBucketAeadBaseContext {
        collection_id: COLLECTION_ID,
        vector_name: VECTOR_NAME,
        key_id: KEY_ID,
        rk_id: RK_ID,
        rk_epoch: RK_EPOCH,
    }
}

fn result_config(
    tree_height: u32,
    bucket_size: usize,
    block_size_bytes: usize,
) -> PrivateResultOramClientConfig {
    PrivateResultOramClientConfig {
        tree_height,
        bucket_size,
        block_size_bytes,
    }
}

fn hnsw_config(
    tree_height: u32,
    bucket_size: usize,
    block_size_bytes: usize,
    fixed_neighbor_slots: usize,
) -> PrivateHnswOramClientConfig {
    PrivateHnswOramClientConfig {
        tree_height,
        bucket_size,
        block_size_bytes,
        fixed_neighbor_slots,
    }
}

fn result_manifest(tree_height: u32, path_batch_size: u32) -> PrivateResultOramManifest {
    let bucket_count = private_result_oram_bucket_count(tree_height).unwrap();
    PrivateResultOramManifest {
        version: 1,
        provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
        binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
        collection_id: COLLECTION_ID.to_string(),
        key_id: KEY_ID.to_string(),
        rk_id: RK_ID.to_string(),
        rk_epoch: RK_EPOCH,
        oram: OramParams {
            kind: OramKind::PathOram,
            bucket_size: 4,
            block_size_bytes: 256,
            tree_height,
            path_batch_size,
        },
        index_epoch: 1,
        root_hash: digest(1),
        bucket_count,
        logical_result_count: 1,
        dummy_result_count: 0,
        owner_signing_key_id: "tenant-a/owner".to_string(),
        created_at_unix: 1,
    }
}

/// Merkle tree construction mirroring the crate's scheme (zero-padded to a power of two,
/// parents hashed as `SHA-256(0x01 || left || right)`).
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
        .collect::<Vec<[u8; 32]>>();
    leaves.resize(leaves.len().next_power_of_two(), [0; 32]);
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let next = levels
            .last()
            .unwrap()
            .as_chunks::<2>()
            .0
            .iter()
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

fn result_merkle_proof(
    index_epoch: u64,
    commitments: &[String],
    bucket_ids: &[u64],
) -> PrivateResultOramMerkleProof {
    let levels = merkle_levels(commitments);
    PrivateResultOramMerkleProof {
        kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
        index_epoch,
        root_hash: BASE64URL_NOPAD.encode(&levels.last().unwrap()[0]),
        bucket_count: commitments.len() as u64,
        leaves: bucket_ids
            .iter()
            .map(|bucket_id| {
                let mut index = *bucket_id as usize;
                let siblings = levels[..levels.len() - 1]
                    .iter()
                    .enumerate()
                    .map(|(level, hashes)| {
                        let sibling = PrivateResultOramMerkleSibling {
                            level: level as u32,
                            position: if index.is_multiple_of(2) {
                                PrivateResultOramMerkleSiblingPosition::Right
                            } else {
                                PrivateResultOramMerkleSiblingPosition::Left
                            },
                            hash: BASE64URL_NOPAD.encode(&hashes[index ^ 1]),
                        };
                        index /= 2;
                        sibling
                    })
                    .collect();
                PrivateResultOramMerkleProofLeaf {
                    bucket_id: *bucket_id,
                    leaf_hash: commitments[*bucket_id as usize].clone(),
                    siblings,
                }
            })
            .collect(),
    }
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
        bucket_count: commitments.len() as u64,
        leaves: bucket_ids
            .iter()
            .map(|bucket_id| {
                let mut index = *bucket_id as usize;
                let siblings = levels[..levels.len() - 1]
                    .iter()
                    .enumerate()
                    .map(|(level, hashes)| {
                        let sibling = PrivateHnswOramMerkleSibling {
                            level: level as u32,
                            position: if index.is_multiple_of(2) {
                                PrivateHnswMerkleSiblingPosition::Right
                            } else {
                                PrivateHnswMerkleSiblingPosition::Left
                            },
                            hash: BASE64URL_NOPAD.encode(&hashes[index ^ 1]),
                        };
                        index /= 2;
                        sibling
                    })
                    .collect();
                PrivateHnswOramMerkleProofLeaf {
                    bucket_id: *bucket_id,
                    leaf_hash: commitments[*bucket_id as usize].clone(),
                    siblings,
                }
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------------------------

fn token() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn result_block(
    max_payload: usize,
) -> impl Strategy<Value = PrivateResultOramPayloadBlockPlaintext> {
    (
        token(),
        token(),
        proptest::collection::vec(any::<u8>(), 0..=max_payload),
        any::<bool>(),
        any::<u64>(),
    )
        .prop_map(
            |(payload_fetch_token, point_token, payload, deleted, generation)| {
                PrivateResultOramPayloadBlockPlaintext {
                    version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
                    payload_fetch_token,
                    point_token,
                    payload,
                    deleted,
                    generation,
                }
            },
        )
}

/// A valid node block for `fixed_neighbor_slots` slots and `dim` f32 values.
fn hnsw_block(
    fixed_neighbor_slots: usize,
    dim: usize,
) -> impl Strategy<Value = PrivateHnswNodeBlockPlaintext> {
    (
        token(),
        token(),
        0u32..8,
        proptest::collection::vec(-100.0f32..100.0, dim),
        proptest::collection::vec((token(), 0u8..8), 0..=fixed_neighbor_slots),
        any::<bool>(),
        any::<u64>(),
        proptest::option::of(token()),
    )
        .prop_map(
            |(
                node_id,
                point_token,
                top_level,
                vector,
                raw_neighbors,
                deleted,
                generation,
                payload_fetch_token,
            )| {
                // Level mask is contiguous from level 0 up to `top_level`.
                let level_mask = if top_level >= 63 {
                    u64::MAX
                } else {
                    (1u64 << (top_level + 1)) - 1
                };
                let mut seen = BTreeSet::new();
                let mut neighbors = Vec::new();
                let mut neighbor_levels = Vec::new();
                for (neighbor, level) in raw_neighbors {
                    let level = level.min(top_level as u8);
                    if neighbor == node_id || !seen.insert((neighbor, level)) {
                        continue;
                    }
                    neighbors.push(neighbor);
                    neighbor_levels.push(level);
                }
                PrivateHnswNodeBlockPlaintext {
                    version: 1,
                    node_id,
                    point_token,
                    level_mask,
                    vector_encoding: PrivateHnswVectorEncoding::F32Le,
                    vector: vector
                        .iter()
                        .flat_map(|value| value.to_le_bytes())
                        .collect(),
                    neighbors,
                    neighbor_levels,
                    deleted,
                    generation,
                    payload_fetch_token,
                }
            },
        )
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|v| json!(v)),
        any::<f64>()
            .prop_filter("finite", |v| v.is_finite())
            .prop_map(|v| json!(v)),
        "\\PC{0,24}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::btree_map("[a-z$_]{1,12}", inner, 0..6)
                .prop_map(|map| { Value::Object(map.into_iter().collect()) }),
        ]
    })
}

/// Flip one byte, insert, delete or truncate: the mutations a tampering server would apply.
fn mutate_bytes(bytes: &[u8], choice: u32, index: usize, byte: u8) -> Vec<u8> {
    let mut mutated = bytes.to_vec();
    if mutated.is_empty() {
        mutated.push(byte);
        return mutated;
    }
    let index = index % mutated.len();
    match choice % 4 {
        0 => mutated[index] ^= byte | 1,
        1 => mutated.insert(index, byte),
        2 => {
            mutated.remove(index);
        }
        _ => mutated.truncate(index),
    }
    mutated
}

fn mutate_string(value: &str, choice: u32, index: usize, byte: u8) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let replacement = alphabet[usize::from(byte) % alphabet.len()] as char;
    let mut chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        chars.push(replacement);
        return chars.into_iter().collect();
    }
    let index = index % chars.len();
    match choice % 4 {
        0 => {
            if chars[index] == replacement {
                chars[index] = if replacement == 'A' { 'B' } else { 'A' };
            } else {
                chars[index] = replacement;
            }
        }
        1 => chars.insert(index, replacement),
        2 => {
            chars.remove(index);
        }
        _ => chars.truncate(index),
    }
    chars.into_iter().collect()
}

// ---------------------------------------------------------------------------------------------
// AEAD envelopes
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    #[test]
    fn aead_envelope_field_mutations_fail_closed(
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        field in 0u32..8,
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let cipher = fixed_cipher();
        let context = payload_context("fuzz");
        let envelope = cipher.encrypt(&plaintext, context).unwrap();
        let mut mutated = envelope.clone();
        match field {
            0 => mutated.nonce = mutate_string(&envelope.nonce, choice, index, byte),
            1 => mutated.ciphertext = mutate_string(&envelope.ciphertext, choice, index, byte),
            2 => mutated.key_id = mutate_string(&envelope.key_id, choice, index, byte),
            3 => mutated.material_fingerprint = mutate_string(&envelope.material_fingerprint, choice, index, byte),
            4 => mutated.rk_id = mutate_string(&envelope.rk_id, choice, index, byte),
            5 => mutated.rk_epoch = Some(envelope.rk_epoch.unwrap_or(0).wrapping_add(u64::from(byte) + 1)),
            6 => mutated.version = envelope.version.wrapping_add(byte.max(1)),
            _ => mutated.algorithm = mutate_string(&envelope.algorithm, choice, index, byte),
        }
        prop_assume!(mutated != envelope);
        prop_assert!(cipher.decrypt(&mutated, context).is_err());
        // The original still opens, so the failure is caused by the mutation alone.
        prop_assert_eq!(cipher.decrypt(&envelope, context).unwrap(), plaintext);
    }

    #[test]
    fn aead_envelope_from_arbitrary_json_never_panics(value in json_value()) {
        if let Ok(envelope) = serde_json::from_value::<EncryptedEnvelope>(value) {
            let cipher = fixed_cipher();
            prop_assert!(cipher.decrypt(&envelope, payload_context("fuzz")).is_err());
        }
    }

    #[test]
    fn aead_envelope_with_arbitrary_base64_fields_never_panics(
        nonce in "[A-Za-z0-9_-]{0,40}",
        ciphertext in "[A-Za-z0-9_-]{0,80}",
    ) {
        let cipher = fixed_cipher();
        let mut envelope = cipher.encrypt(b"seed", payload_context("fuzz")).unwrap();
        envelope.nonce = nonce;
        envelope.ciphertext = ciphertext;
        prop_assert!(cipher.decrypt(&envelope, payload_context("fuzz")).is_err());
    }
}

// ---------------------------------------------------------------------------------------------
// Control-plane envelope and payload layer
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    #[test]
    fn control_plane_envelope_parser_never_panics(value in json_value()) {
        let _ = CiphertextEnvelope::from_stored_value(&value);
        let wrapped = json!({ "$qdrant_ciphertext": value });
        let _ = CiphertextEnvelope::from_stored_value(&wrapped);
    }

    #[test]
    fn payload_policy_accepts_or_rejects_arbitrary_paths_without_panicking(
        paths in proptest::collection::vec("\\PC{0,20}", 0..4),
    ) {
        let _ = PayloadEncryptionPolicy::new(paths.iter().map(String::as_str));
    }

    #[test]
    fn payload_validators_never_panic_on_arbitrary_json(value in json_value()) {
        let _ = is_encrypted_payload_value(&value);
        let _ = is_client_encrypted_payload_value(&value);
        let _ = validate_client_payload_value(
            &value,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "1",
                field_path: "body",
                expected_key_id: None,
                expected_rk_id: None,
                min_rk_epoch: None,
                max_rk_epoch: None,
                key_id_required: false,
                signature_required: false,
                signature_verification: None,
            },
        );
        let encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs",
            KEY_ID,
            &SecretKey::from_bytes([5; 32]),
            "tenant-a/fuzz@v1",
            RK_ID,
            RK_EPOCH,
        )
        .unwrap();
        let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
        let mut payload = Map::new();
        payload.insert("body".to_string(), value);
        let _ = encryptor.decrypt_selected_fields("1", &mut payload, &policy);
        let _ = encryptor.decrypt_selected_fields_if_encrypted("1", &mut payload, &policy);
    }

    #[test]
    fn payload_envelope_mutation_is_rejected(
        body in "\\PC{0,64}",
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs",
            KEY_ID,
            &SecretKey::from_bytes([5; 32]),
            "tenant-a/fuzz@v1",
            RK_ID,
            RK_EPOCH,
        )
        .unwrap();
        let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
        let mut payload = Map::new();
        payload.insert("body".to_string(), Value::String(body.clone()));
        encryptor.encrypt_selected_fields("1", &mut payload, &policy).unwrap();

        // Mutate the serialized envelope JSON; anything that still parses must not decrypt.
        let serialized = serde_json::to_string(&payload["body"]).unwrap();
        let mutated = mutate_string(&serialized, choice, index, byte);
        prop_assume!(mutated != serialized);
        if let Ok(mutated_value) = serde_json::from_str::<Value>(&mutated) {
            let mut mutated_payload = Map::new();
            mutated_payload.insert("body".to_string(), mutated_value);
            if encryptor.decrypt_selected_fields("1", &mut mutated_payload, &policy).is_ok() {
                prop_assert_eq!(mutated_payload["body"].as_str(), Some(body.as_str()));
            }
        }
        // A different point id never opens the envelope.
        prop_assert!(encryptor.decrypt_selected_fields("2", &mut payload.clone(), &policy).is_err());
    }
}

// ---------------------------------------------------------------------------------------------
// Leaf labels
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(512))]

    #[test]
    fn leaf_labels_round_trip_and_reject_out_of_range(
        tree_height in 1u32..12,
        leaf in any::<u64>(),
        garbage in "\\PC{0,16}",
    ) {
        let leaf_count = 1u64 << tree_height;
        let in_range = leaf % leaf_count;
        let label = encode_private_result_oram_leaf_label(in_range, tree_height).unwrap();
        prop_assert_eq!(decode_private_result_oram_leaf_label(&label, tree_height).unwrap(), in_range);
        let hnsw_label = encode_private_hnsw_oram_leaf_label(in_range, tree_height).unwrap();
        prop_assert_eq!(&hnsw_label, &label, "both ORAMs share one label encoding");
        prop_assert_eq!(decode_private_hnsw_oram_leaf_label(&hnsw_label, tree_height).unwrap(), in_range);

        if leaf >= leaf_count {
            prop_assert!(encode_private_result_oram_leaf_label(leaf, tree_height).is_err());
            let big = BASE64URL_NOPAD.encode(&leaf.to_be_bytes());
            prop_assert!(decode_private_result_oram_leaf_label(&big, tree_height).is_err());
            prop_assert!(decode_private_hnsw_oram_leaf_label(&big, tree_height).is_err());
        }
        let _ = decode_private_result_oram_leaf_label(&garbage, tree_height);
        let _ = decode_private_hnsw_oram_leaf_label(&garbage, tree_height);
        // A label of a taller tree never decodes in a shorter one.
        if tree_height > 1 {
            let shorter = tree_height - 1;
            let top = encode_private_result_oram_leaf_label(leaf_count - 1, tree_height).unwrap();
            prop_assert!(decode_private_result_oram_leaf_label(&top, shorter).is_err());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Result ORAM block and bucket codecs
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    #[test]
    fn result_payload_block_codec_is_canonical(
        block in result_block(200),
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let encoded = encode_private_result_oram_payload_block(&block, 320).unwrap();
        prop_assert_eq!(encoded.len(), 320);
        prop_assert_eq!(decode_private_result_oram_payload_block(&encoded).unwrap(), block.clone());

        let mutated = mutate_bytes(&encoded, choice, index, byte);
        if let Ok(decoded) = decode_private_result_oram_payload_block(&mutated) {
            // Whatever decodes must re-encode to exactly the bytes it came from.
            let reencoded = encode_private_result_oram_payload_block(&decoded, mutated.len()).unwrap();
            prop_assert_eq!(reencoded, mutated);
        }
    }

    #[test]
    fn result_payload_block_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = decode_private_result_oram_payload_block(&bytes);
    }

    #[test]
    fn result_bucket_plaintext_codec_is_canonical(
        blocks in proptest::collection::vec(proptest::option::of(result_block(40)), 3),
        bucket_id in any::<u64>(),
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let config = result_config(3, 3, 128);
        // Make tokens unique so the bucket is valid.
        let mut fetch_tokens = BTreeSet::new();
        let mut point_tokens = BTreeSet::new();
        let blocks: Vec<_> = blocks
            .into_iter()
            .map(|slot| {
                slot.filter(|block| {
                    fetch_tokens.insert(block.payload_fetch_token)
                        && point_tokens.insert(block.point_token)
                })
            })
            .collect();
        let bucket = PrivateResultOramPlaintextBucket { bucket_id, blocks };
        let encoded = encode_private_result_oram_bucket_plaintext(&bucket, config).unwrap();
        prop_assert_eq!(
            decode_private_result_oram_bucket_plaintext(bucket_id, &encoded, config).unwrap(),
            bucket
        );
        prop_assert!(
            decode_private_result_oram_bucket_plaintext(bucket_id.wrapping_add(1), &encoded, config).is_err()
        );

        let mutated = mutate_bytes(&encoded, choice, index, byte);
        if let Ok(decoded) = decode_private_result_oram_bucket_plaintext(bucket_id, &mutated, config) {
            let reencoded = encode_private_result_oram_bucket_plaintext(&decoded, config).unwrap();
            prop_assert_eq!(reencoded, mutated);
        }
    }

    #[test]
    fn result_bucket_decoder_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..600),
        bucket_size in 1usize..4,
        block_size in 1usize..200,
    ) {
        let config = result_config(2, bucket_size, block_size);
        let _ = decode_private_result_oram_bucket_plaintext(0, &bytes, config);
    }
}

// ---------------------------------------------------------------------------------------------
// HNSW node block and bucket codecs
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    #[test]
    fn hnsw_node_block_codec_is_canonical(
        block in hnsw_block(4, 3),
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let block_size = 512;
        let encoded = encode_private_hnsw_node_block(&block, block_size, 4).unwrap();
        prop_assert_eq!(encoded.len(), block_size);
        let decoded = decode_private_hnsw_node_block(&encoded).unwrap();
        prop_assert_eq!(&decoded, &block);
        let vector = decode_private_hnsw_f32_vector(&decoded).unwrap();
        prop_assert_eq!(vector.len(), 3);

        let mutated = mutate_bytes(&encoded, choice, index, byte);
        if let Ok(decoded) = decode_private_hnsw_node_block(&mutated) {
            // The slot count is a layout parameter that the struct does not carry, so some slot
            // count must reproduce the accepted bytes exactly; otherwise the decoder accepted a
            // non-canonical (attacker-malleable) encoding.
            let canonical = (decoded.neighbors.len()..=8).any(|slots| {
                encode_private_hnsw_node_block(&decoded, mutated.len(), slots).ok().as_deref()
                    == Some(mutated.as_slice())
            });
            prop_assert!(canonical, "decoder accepted a non-canonical node block");
        }
    }

    #[test]
    fn hnsw_node_block_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..700)) {
        let _ = decode_private_hnsw_node_block(&bytes);
    }

    #[test]
    fn hnsw_bucket_plaintext_codec_is_canonical(
        blocks in proptest::collection::vec(proptest::option::of(hnsw_block(2, 2)), 2),
        bucket_id in any::<u64>(),
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let config = hnsw_config(3, 2, 256, 2);
        let mut node_ids = BTreeSet::new();
        let mut point_tokens = BTreeSet::new();
        let mut fetch_tokens = BTreeSet::new();
        let blocks: Vec<_> = blocks
            .into_iter()
            .map(|slot| {
                slot.filter(|block| {
                    node_ids.insert(block.node_id)
                        && point_tokens.insert(block.point_token)
                        && block.payload_fetch_token.is_none_or(|token| fetch_tokens.insert(token))
                })
            })
            .collect();
        let bucket = PrivateHnswOramPlaintextBucket { bucket_id, blocks };
        let encoded = encode_private_hnsw_oram_bucket_plaintext(&bucket, config).unwrap();
        prop_assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(bucket_id, &encoded, config).unwrap(),
            bucket
        );

        let mutated = mutate_bytes(&encoded, choice, index, byte);
        if let Ok(decoded) = decode_private_hnsw_oram_bucket_plaintext(bucket_id, &mutated, config) {
            let reencoded = encode_private_hnsw_oram_bucket_plaintext(&decoded, config).unwrap();
            prop_assert_eq!(reencoded, mutated);
        }
    }
}

/// A node block whose neighbor counters claim four billion slots must be rejected before any
/// allocation sized by those counters happens.
#[test]
fn hnsw_node_block_rejects_neighbor_counts_larger_than_the_block() {
    let block = PrivateHnswNodeBlockPlaintext {
        version: 1,
        node_id: [1; 32],
        point_token: [2; 32],
        level_mask: 1,
        vector_encoding: PrivateHnswVectorEncoding::F32Le,
        vector: 1.0f32.to_le_bytes().to_vec(),
        neighbors: Vec::new(),
        neighbor_levels: Vec::new(),
        deleted: false,
        generation: 0,
        payload_fetch_token: None,
    };
    let encoded = encode_private_hnsw_node_block(&block, 256, 1).unwrap();
    // Layout: magic(6?) .. we locate the counters by re-encoding with distinct slot counts.
    let with_two_slots = encode_private_hnsw_node_block(&block, 256, 2).unwrap();
    let counter_offset = encoded
        .iter()
        .zip(&with_two_slots)
        .position(|(a, b)| a != b)
        .expect("fixed_neighbor_slots counter differs");
    // `fixed_neighbor_slots` is a big-endian u32 whose lowest byte differs first; the field starts
    // three bytes earlier and `neighbor_count` is the u32 immediately before it.
    let slots_start = counter_offset - 3;
    let count_start = slots_start - 4;
    let mut hostile = encoded.clone();
    hostile[count_start..count_start + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    hostile[slots_start..slots_start + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        decode_private_hnsw_node_block(&hostile).is_err(),
        "counters larger than the block must be rejected"
    );
    // The same with only the slot counter inflated (neighbor_count stays 0).
    let mut hostile_slots = encoded;
    hostile_slots[slots_start..slots_start + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_private_hnsw_node_block(&hostile_slots).is_err());
}

// ---------------------------------------------------------------------------------------------
// Sealed buckets and client state snapshots
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(128))]

    #[test]
    fn result_bucket_seal_open_rejects_any_mutation(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        bucket_id in 0u64..15,
        index_epoch in 1u64..10,
        field in 0u32..6,
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let keys = result_keys();
        let context = result_base_context().for_bucket(bucket_id, index_epoch);
        let bucket = seal_private_result_oram_bucket(&keys, context, &plaintext).unwrap();
        prop_assert_eq!(open_private_result_oram_bucket(&keys, context, &bucket).unwrap(), plaintext.clone());

        let mut mutated = bucket.clone();
        match field {
            0 => mutated.ciphertext = mutate_string(&bucket.ciphertext, choice, index, byte),
            1 => mutated.ciphertext_sha256 = mutate_string(&bucket.ciphertext_sha256, choice, index, byte),
            2 => mutated.bucket_commitment = mutate_string(&bucket.bucket_commitment, choice, index, byte),
            3 => mutated.bucket_id = bucket.bucket_id.wrapping_add(u64::from(byte) + 1),
            4 => mutated.index_epoch = bucket.index_epoch.wrapping_add(u64::from(byte) + 1),
            _ => mutated.version = bucket.version.wrapping_add(u16::from(byte) + 1),
        }
        prop_assert!(open_private_result_oram_bucket(&keys, context, &mutated).is_err());
        // A bucket sealed for one slot never opens in another slot or epoch.
        let other_slot = result_base_context().for_bucket(bucket_id + 1, index_epoch);
        prop_assert!(open_private_result_oram_bucket(&keys, other_slot, &bucket).is_err());
        let other_epoch = result_base_context().for_bucket(bucket_id, index_epoch + 1);
        prop_assert!(open_private_result_oram_bucket(&keys, other_epoch, &bucket).is_err());
        let other_keys = PrivateResultOramClientKeys::derive_from_resource_key_with_context(
            &SecretKey::from_bytes([9; 32]),
            COLLECTION_ID,
            RK_ID,
            RK_EPOCH + 1,
        )
        .unwrap();
        prop_assert!(open_private_result_oram_bucket(&other_keys, context, &bucket).is_err());
    }

    #[test]
    fn hnsw_bucket_seal_open_rejects_any_mutation(
        plaintext in proptest::collection::vec(any::<u8>(), 1..128),
        bucket_id in 0u64..15,
        index_epoch in 1u64..10,
        field in 0u32..6,
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let keys = hnsw_keys();
        let context = hnsw_base_context().for_bucket(bucket_id, index_epoch);
        let bucket = seal_private_hnsw_oram_bucket(&keys, context, &plaintext).unwrap();
        prop_assert_eq!(open_private_hnsw_oram_bucket(&keys, context, &bucket).unwrap(), plaintext.clone());

        let mut mutated = bucket.clone();
        match field {
            0 => mutated.ciphertext = mutate_string(&bucket.ciphertext, choice, index, byte),
            1 => mutated.ciphertext_sha256 = mutate_string(&bucket.ciphertext_sha256, choice, index, byte),
            2 => mutated.bucket_commitment = mutate_string(&bucket.bucket_commitment, choice, index, byte),
            3 => mutated.bucket_id = bucket.bucket_id.wrapping_add(u64::from(byte) + 1),
            4 => mutated.index_epoch = bucket.index_epoch.wrapping_add(u64::from(byte) + 1),
            _ => mutated.version = bucket.version.wrapping_add(u16::from(byte) + 1),
        }
        prop_assert!(open_private_hnsw_oram_bucket(&keys, context, &mutated).is_err());
        let other_vector = PrivateHnswBucketAeadBaseContext {
            vector_name: "other",
            ..hnsw_base_context()
        }
        .for_bucket(bucket_id, index_epoch);
        prop_assert!(open_private_hnsw_oram_bucket(&keys, other_vector, &bucket).is_err());
    }

    #[test]
    fn result_client_state_snapshot_seal_open_round_trips_and_rejects_mutation(
        blocks in proptest::collection::vec(result_block(24), 0..6),
        leaves in proptest::collection::vec(0u64..8, 6),
        stash_mask in 0u8..64,
        field in 0u32..5,
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let config = result_config(3, 2, 128);
        let mut state = PrivateResultOramClientState::new();
        for (i, block) in blocks.iter().enumerate() {
            if stash_mask & (1 << i) != 0 {
                let _ = state.insert_new_stash_block(block.clone(), leaves[i], config);
            } else {
                state.insert_position(block.payload_fetch_token, leaves[i], config.tree_height).unwrap();
            }
        }
        let snapshot = state.to_snapshot(config.tree_height).unwrap();
        prop_assert_eq!(PrivateResultOramClientState::from_snapshot(&snapshot).unwrap(), state.clone());

        let keys = result_keys();
        let root_hash = digest(0x42);
        let context = PrivateResultOramClientStateAeadContext {
            collection_id: COLLECTION_ID,
            key_id: KEY_ID,
            rk_id: RK_ID,
            rk_epoch: RK_EPOCH,
            index_epoch: 5,
            root_hash: &root_hash,
        };
        let padding = PrivateResultOramClientStateSnapshotPadding {
            block_size_bytes: config.block_size_bytes,
            stash_capacity: blocks.len(),
        };
        let sealed =
            seal_private_result_oram_client_state_snapshot(&keys, context, &snapshot, padding)
                .unwrap();
        prop_assert_eq!(
            open_private_result_oram_client_state_snapshot(&keys, context, &sealed).unwrap(),
            snapshot
        );
        let mut mutated = sealed.clone();
        match field {
            0 => mutated.ciphertext = mutate_string(&sealed.ciphertext, choice, index, byte),
            1 => mutated.ciphertext_sha256 = mutate_string(&sealed.ciphertext_sha256, choice, index, byte),
            2 => mutated.root_hash = digest(0x43),
            3 => mutated.index_epoch = sealed.index_epoch + 1,
            _ => mutated.version = sealed.version.wrapping_add(1),
        }
        prop_assert!(open_private_result_oram_client_state_snapshot(&keys, context, &mutated).is_err());
        let other_root = digest(0x43);
        let other_context = PrivateResultOramClientStateAeadContext { root_hash: &other_root, ..context };
        prop_assert!(open_private_result_oram_client_state_snapshot(&keys, other_context, &sealed).is_err());
    }

    #[test]
    fn hnsw_client_state_snapshot_seal_open_round_trips_and_rejects_mutation(
        blocks in proptest::collection::vec(hnsw_block(2, 2), 0..5),
        leaves in proptest::collection::vec(0u64..8, 5),
        stash_mask in 0u8..32,
        field in 0u32..5,
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let config = hnsw_config(3, 2, 256, 2);
        let mut state = PrivateHnswOramClientState::new();
        for (i, block) in blocks.iter().enumerate() {
            if stash_mask & (1 << i) != 0 {
                let _ = state.insert_new_stash_block(block.clone(), leaves[i], config);
            } else {
                state.insert_position(block.node_id, leaves[i], config.tree_height).unwrap();
            }
        }
        let snapshot = state.to_snapshot(config.tree_height).unwrap();
        prop_assert_eq!(PrivateHnswOramClientState::from_snapshot(&snapshot).unwrap(), state.clone());

        let keys = hnsw_keys();
        let root_hash = digest(0x42);
        let context = PrivateHnswClientStateAeadContext {
            collection_id: COLLECTION_ID,
            vector_name: VECTOR_NAME,
            key_id: KEY_ID,
            rk_id: RK_ID,
            rk_epoch: RK_EPOCH,
            index_epoch: 5,
            root_hash: &root_hash,
        };
        let sealed = seal_private_hnsw_oram_client_state_snapshot(&keys, context, &snapshot).unwrap();
        prop_assert_eq!(
            open_private_hnsw_oram_client_state_snapshot(&keys, context, &sealed).unwrap(),
            snapshot
        );
        let mut mutated = sealed.clone();
        match field {
            0 => mutated.ciphertext = mutate_string(&sealed.ciphertext, choice, index, byte),
            1 => mutated.ciphertext_sha256 = mutate_string(&sealed.ciphertext_sha256, choice, index, byte),
            2 => mutated.root_hash = digest(0x43),
            3 => mutated.index_epoch = sealed.index_epoch + 1,
            _ => mutated.version = sealed.version.wrapping_add(1),
        }
        prop_assert!(open_private_hnsw_oram_client_state_snapshot(&keys, context, &mutated).is_err());
    }

    #[test]
    fn client_state_snapshot_json_never_panics(value in json_value()) {
        if let Ok(snapshot) = serde_json::from_value::<PrivateResultOramClientStateSnapshot>(value.clone()) {
            let _ = PrivateResultOramClientState::from_snapshot(&snapshot);
        }
        if let Ok(snapshot) = serde_json::from_value::<PrivateHnswOramClientStateSnapshot>(value) {
            let _ = PrivateHnswOramClientState::from_snapshot(&snapshot);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Merkle proofs
// ---------------------------------------------------------------------------------------------

fn sealed_result_buckets(tree_height: u32, index_epoch: u64) -> Vec<PrivateResultOramBucket> {
    let keys = result_keys();
    let bucket_count = private_result_oram_bucket_count(tree_height).unwrap();
    (0..bucket_count)
        .map(|bucket_id| {
            seal_private_result_oram_bucket(
                &keys,
                result_base_context().for_bucket(bucket_id, index_epoch),
                &bucket_id.to_be_bytes(),
            )
            .unwrap()
        })
        .collect()
}

fn sealed_hnsw_buckets(tree_height: u32, index_epoch: u64) -> Vec<PrivateHnswOramBucket> {
    let keys = hnsw_keys();
    let bucket_count = private_hnsw_oram_bucket_count(tree_height).unwrap();
    (0..bucket_count)
        .map(|bucket_id| {
            seal_private_hnsw_oram_bucket(
                &keys,
                hnsw_base_context().for_bucket(bucket_id, index_epoch),
                &bucket_id.to_be_bytes(),
            )
            .unwrap()
        })
        .collect()
}

proptest! {
    #![proptest_config(cases(96))]

    #[test]
    fn result_merkle_proofs_verify_and_every_mutation_is_rejected(
        tree_height in 1u32..5,
        selection in proptest::collection::btree_set(0u64..31, 1..6),
        mutation in 0u32..12,
        leaf_choice in any::<usize>(),
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let index_epoch = 4;
        let buckets = sealed_result_buckets(tree_height, index_epoch);
        let bucket_count = buckets.len() as u64;
        let commitments: Vec<String> = buckets.iter().map(|b| b.bucket_commitment.clone()).collect();
        let root = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let bucket_ids: Vec<u64> = selection.into_iter().filter(|id| *id < bucket_count).collect();
        prop_assume!(!bucket_ids.is_empty());
        let selected: Vec<_> = bucket_ids.iter().map(|id| buckets[*id as usize].clone()).collect();
        let proof = result_merkle_proof(index_epoch, &commitments, &bucket_ids);
        let proof_json = serde_json::to_string(&proof).unwrap();
        prop_assert_eq!(&proof.root_hash, &root);
        verify_private_result_oram_merkle_proof_json(&proof_json, index_epoch, &root, bucket_count, &selected).unwrap();

        let leaf_index = leaf_choice % proof.leaves.len();
        let mut mutated = proof.clone();
        let mut mutated_buckets = selected.clone();
        let mut epoch = index_epoch;
        let mut expected_root = root.clone();
        let expected_count = bucket_count;
        match mutation {
            0 => mutated.root_hash = digest(byte),
            1 => mutated.index_epoch = index_epoch + 1 + u64::from(byte),
            2 => mutated.bucket_count = bucket_count + 1 + u64::from(byte),
            3 => mutated.kind = mutate_string(&proof.kind, choice, index, byte),
            4 => {
                let leaf = &mut mutated.leaves[leaf_index];
                prop_assume!(!leaf.siblings.is_empty());
                let sibling_index = index % leaf.siblings.len();
                let sibling = &mut leaf.siblings[sibling_index];
                sibling.hash = mutate_string(&sibling.hash, choice, index, byte);
            }
            5 => {
                let leaf = &mut mutated.leaves[leaf_index];
                prop_assume!(!leaf.siblings.is_empty());
                let sibling_index = index % leaf.siblings.len();
                let sibling = &mut leaf.siblings[sibling_index];
                sibling.position = match sibling.position {
                    PrivateResultOramMerkleSiblingPosition::Left => PrivateResultOramMerkleSiblingPosition::Right,
                    PrivateResultOramMerkleSiblingPosition::Right => PrivateResultOramMerkleSiblingPosition::Left,
                };
            }
            6 => {
                let leaf = &mut mutated.leaves[leaf_index];
                prop_assume!(!leaf.siblings.is_empty());
                leaf.siblings.pop();
            }
            7 => {
                let leaf = &mut mutated.leaves[leaf_index];
                leaf.leaf_hash = digest(byte);
            }
            8 => {
                // Serve a different bucket's ciphertext under the proven bucket id.
                let other = (bucket_ids[leaf_index] + 1 + u64::from(byte)) % bucket_count;
                prop_assume!(!bucket_ids.contains(&other));
                let mut swapped = buckets[other as usize].clone();
                swapped.bucket_id = bucket_ids[leaf_index];
                mutated_buckets[leaf_index] = swapped;
            }
            9 => {
                // Serve a bucket from an older epoch whose commitment differs.
                let old = sealed_result_buckets(tree_height, index_epoch - 1);
                mutated_buckets[leaf_index] = old[bucket_ids[leaf_index] as usize].clone();
            }
            10 => epoch = index_epoch + 1,
            _ => expected_root = digest(byte.wrapping_add(1)),
        }
        prop_assume!(mutated != proof || mutated_buckets != selected || epoch != index_epoch || expected_root != root);
        let mutated_json = serde_json::to_string(&mutated).unwrap();
        prop_assert!(
            verify_private_result_oram_merkle_proof_json(&mutated_json, epoch, &expected_root, expected_count, &mutated_buckets).is_err(),
            "mutation {} was accepted", mutation
        );
        // A proof that omits one of the served buckets is rejected too.
        if selected.len() > 1 {
            let mut fewer_leaves = proof.clone();
            fewer_leaves.leaves.remove(leaf_index);
            let fewer_json = serde_json::to_string(&fewer_leaves).unwrap();
            prop_assert!(verify_private_result_oram_merkle_proof_json(&fewer_json, index_epoch, &root, bucket_count, &selected).is_err());
        }
    }

    #[test]
    fn hnsw_merkle_proofs_verify_and_every_mutation_is_rejected(
        tree_height in 1u32..5,
        selection in proptest::collection::btree_set(0u64..31, 1..6),
        mutation in 0u32..9,
        leaf_choice in any::<usize>(),
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let index_epoch = 4;
        let buckets = sealed_hnsw_buckets(tree_height, index_epoch);
        let bucket_count = buckets.len() as u64;
        let commitments: Vec<String> = buckets.iter().map(|b| b.bucket_commitment.clone()).collect();
        let root = private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap();
        let bucket_ids: Vec<u64> = selection.into_iter().filter(|id| *id < bucket_count).collect();
        prop_assume!(!bucket_ids.is_empty());
        let selected: Vec<_> = bucket_ids.iter().map(|id| buckets[*id as usize].clone()).collect();
        let proof = hnsw_merkle_proof(index_epoch, &commitments, &bucket_ids);
        let proof_json = serde_json::to_string(&proof).unwrap();
        prop_assert_eq!(&proof.root_hash, &root);
        verify_private_hnsw_oram_merkle_proof_json(&proof_json, index_epoch, &root, bucket_count, &selected).unwrap();

        let leaf_index = leaf_choice % proof.leaves.len();
        let mut mutated = proof.clone();
        let mut mutated_buckets = selected.clone();
        match mutation {
            0 => mutated.root_hash = digest(byte),
            1 => mutated.index_epoch = index_epoch + 1 + u64::from(byte),
            2 => mutated.bucket_count = bucket_count + 1 + u64::from(byte),
            3 => mutated.kind = mutate_string(&proof.kind, choice, index, byte),
            4 => {
                let leaf = &mut mutated.leaves[leaf_index];
                prop_assume!(!leaf.siblings.is_empty());
                let sibling_index = index % leaf.siblings.len();
                let sibling = &mut leaf.siblings[sibling_index];
                sibling.hash = mutate_string(&sibling.hash, choice, index, byte);
            }
            5 => {
                let leaf = &mut mutated.leaves[leaf_index];
                prop_assume!(!leaf.siblings.is_empty());
                let sibling_index = index % leaf.siblings.len();
                let sibling = &mut leaf.siblings[sibling_index];
                sibling.position = match sibling.position {
                    PrivateHnswMerkleSiblingPosition::Left => PrivateHnswMerkleSiblingPosition::Right,
                    PrivateHnswMerkleSiblingPosition::Right => PrivateHnswMerkleSiblingPosition::Left,
                };
            }
            6 => {
                let leaf = &mut mutated.leaves[leaf_index];
                prop_assume!(!leaf.siblings.is_empty());
                leaf.siblings.pop();
            }
            7 => mutated.leaves[leaf_index].leaf_hash = digest(byte),
            _ => {
                let other = (bucket_ids[leaf_index] + 1 + u64::from(byte)) % bucket_count;
                prop_assume!(!bucket_ids.contains(&other));
                let mut swapped = buckets[other as usize].clone();
                swapped.bucket_id = bucket_ids[leaf_index];
                mutated_buckets[leaf_index] = swapped;
            }
        }
        prop_assume!(mutated != proof || mutated_buckets != selected);
        let mutated_json = serde_json::to_string(&mutated).unwrap();
        prop_assert!(
            verify_private_hnsw_oram_merkle_proof_json(&mutated_json, index_epoch, &root, bucket_count, &mutated_buckets).is_err(),
            "mutation {} was accepted", mutation
        );
    }

    #[test]
    fn merkle_proof_json_parsers_never_panic(value in json_value(), text in "\\PC{0,64}") {
        let buckets = sealed_result_buckets(1, 1);
        let root = digest(1);
        let rendered = serde_json::to_string(&value).unwrap();
        let _ = verify_private_result_oram_merkle_proof_json(&rendered, 1, &root, 3, &buckets);
        let _ = verify_private_result_oram_merkle_proof_json(&text, 1, &root, 3, &buckets);
        let hnsw_buckets = sealed_hnsw_buckets(1, 1);
        let _ = verify_private_hnsw_oram_merkle_proof_json(&rendered, 1, &root, 3, &hnsw_buckets);
        let _ = verify_private_hnsw_oram_merkle_proof_json(&text, 1, &root, 3, &hnsw_buckets);
    }
}

// ---------------------------------------------------------------------------------------------
// Fetch planning: request shape must not depend on leaf collisions
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    #[test]
    fn fetch_batches_have_fixed_shape_regardless_of_collisions(
        tree_height in 1u32..6,
        path_batch_size in 1u32..5,
        batch_count in 1usize..4,
        leaf_seed in proptest::collection::vec(any::<u64>(), 16),
        padding_offset in any::<u64>(),
    ) {
        let leaf_count = 1u64 << tree_height;
        prop_assume!(u64::from(path_batch_size) <= leaf_count);
        let manifest = result_manifest(tree_height, path_batch_size);
        let token_count = path_batch_size as usize * batch_count;
        let tokens: Vec<[u8; 32]> = (0..token_count)
            .map(|i| {
                let mut token = [0u8; 32];
                token[0] = i as u8;
                token[1] = 0xA5;
                token
            })
            .collect();
        let positions: Vec<_> = tokens
            .iter()
            .enumerate()
            .map(|(i, token)| PrivateResultOramFetchTokenPosition {
                payload_fetch_token: *token,
                leaf: leaf_seed[i % leaf_seed.len()] % leaf_count,
            })
            .collect();
        // A round-robin sampler from a random offset visits every leaf within `leaf_count`
        // draws, so the planner can never legitimately run out of distinct dummy leaves.
        let mut cursor = padding_offset;
        let mut next_leaf = || {
            cursor = cursor.wrapping_add(1);
            Ok(cursor % leaf_count)
        };

        let path_len = tree_height as usize + 1;
        let plan = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(&manifest, &tokens, &positions, &mut next_leaf);
        let plan = match plan {
            Ok(plan) => plan,
            Err(err) => return Err(TestCaseError::fail(format!("unexpected planning error {err:?}"))),
        };
        prop_assert_eq!(plan.batches.len(), batch_count);
        prop_assert_eq!(plan.token_count, token_count);
        for (batch_index, batch) in plan.batches.iter().enumerate() {
            prop_assert_eq!(batch.token_count, path_batch_size as usize);
            // Exactly `path_batch_size` distinct paths per batch, whatever the collisions.
            prop_assert_eq!(batch.bucket_ids.len(), path_len * path_batch_size as usize, "batch {}", batch_index);
            let real_leaves: BTreeSet<u64> = tokens[batch_index * path_batch_size as usize..(batch_index + 1) * path_batch_size as usize]
                .iter()
                .map(|token| positions.iter().find(|p| p.payload_fetch_token == *token).unwrap().leaf)
                .collect();
            let padding: BTreeSet<u64> = batch.padding_leaves.iter().copied().collect();
            prop_assert_eq!(padding.len(), batch.padding_leaves.len(), "padding leaves are distinct");
            prop_assert!(padding.is_disjoint(&real_leaves), "padding never repeats a real leaf");
            prop_assert_eq!(real_leaves.len() + padding.len(), path_batch_size as usize);
            // The bucket id list is exactly the union of the paths, in path order.
            let mut expected = Vec::new();
            for leaf in real_leaves.iter().chain(batch.padding_leaves.iter()) {
                expected.extend(private_result_oram_bucket_ids_for_leaf(*leaf, tree_height).unwrap());
            }
            let expected_set: BTreeSet<u64> = expected.iter().copied().collect();
            let actual_set: BTreeSet<u64> = batch.bucket_ids.iter().copied().collect();
            prop_assert_eq!(actual_set, expected_set);
        }

        // The ordered planner never needs more padding than the naive one and keeps the token set.
        let mut ordered_cursor = padding_offset;
        let ordered = plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens(&manifest, &tokens, &positions, || {
            ordered_cursor = ordered_cursor.wrapping_add(1);
            Ok(ordered_cursor % leaf_count)
        });
        if let Ok(ordered) = ordered {
            let naive_padding: usize = plan.batches.iter().map(|b| b.padding_leaves.len()).sum();
            let ordered_padding: usize = ordered.read_plan.batches.iter().map(|b| b.padding_leaves.len()).sum();
            // A leaf with `n` tokens can be served once per batch, so the fewest collisions any
            // ordering can reach is `token_count - sum(min(n, batch_count))`.
            let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
            for position in &positions {
                *counts.entry(position.leaf).or_default() += 1;
            }
            let optimal_padding = token_count - counts.values().map(|n| (*n).min(batch_count)).sum::<usize>();
            prop_assert!(naive_padding >= optimal_padding);
            prop_assert_eq!(ordered_padding, optimal_padding, "ordered planner must spread collisions optimally");
            prop_assert!(ordered_padding <= naive_padding);
            let mut sorted = ordered.payload_fetch_tokens.clone();
            sorted.sort();
            let mut original = tokens.clone();
            original.sort();
            prop_assert_eq!(sorted, original);
            for batch in &ordered.read_plan.batches {
                prop_assert_eq!(batch.bucket_ids.len(), path_len * path_batch_size as usize);
            }
        }
    }

    #[test]
    fn fetch_planner_rejects_malformed_inputs_without_panicking(
        tree_height in 0u32..8,
        path_batch_size in 0u32..6,
        token_count in 0usize..8,
        leaves in proptest::collection::vec(any::<u64>(), 8),
        duplicate in any::<bool>(),
    ) {
        let mut manifest = result_manifest(tree_height.max(1), path_batch_size.max(1));
        manifest.oram.tree_height = tree_height;
        manifest.oram.path_batch_size = path_batch_size;
        let tokens: Vec<[u8; 32]> = (0..token_count).map(|i| [i as u8; 32]).collect();
        let mut positions: Vec<_> = tokens
            .iter()
            .enumerate()
            .map(|(i, token)| PrivateResultOramFetchTokenPosition { payload_fetch_token: *token, leaf: leaves[i] })
            .collect();
        if duplicate && !positions.is_empty() {
            positions.push(positions[0].clone());
        }
        let _ = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(&manifest, &tokens, &positions, || Ok(0));
        let _ = plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens(&manifest, &tokens, &positions, || Ok(0));
    }
}

// ---------------------------------------------------------------------------------------------
// Path ORAM client simulation
// ---------------------------------------------------------------------------------------------

/// In-memory server: every bucket of the tree, updated from the client's write-backs.
struct ResultOramServer {
    config: PrivateResultOramClientConfig,
    buckets: Vec<PrivateResultOramPlaintextBucket>,
}

impl ResultOramServer {
    fn new(config: PrivateResultOramClientConfig) -> Self {
        let bucket_count = private_result_oram_bucket_count(config.tree_height).unwrap();
        Self {
            config,
            buckets: (0..bucket_count)
                .map(|id| empty_private_result_oram_plaintext_bucket(id, config).unwrap())
                .collect(),
        }
    }

    fn path(&self, leaf: u64) -> Vec<PrivateResultOramPlaintextBucket> {
        private_result_oram_bucket_ids_for_leaf(leaf, self.config.tree_height)
            .unwrap()
            .into_iter()
            .map(|id| self.buckets[id as usize].clone())
            .collect()
    }

    fn write_back(&mut self, buckets: &[PrivateResultOramPlaintextBucket]) {
        for bucket in buckets {
            assert_eq!(
                bucket.blocks.len(),
                self.config.bucket_size,
                "write-back keeps bucket shape"
            );
            self.buckets[bucket.bucket_id as usize] = bucket.clone();
        }
    }

    /// Every stored block, keyed by fetch token, with the bucket it lives in.
    fn stored(&self) -> BTreeMap<[u8; 32], (u64, PrivateResultOramPayloadBlockPlaintext)> {
        let mut stored = BTreeMap::new();
        for bucket in &self.buckets {
            for block in bucket.blocks.iter().flatten() {
                let previous =
                    stored.insert(block.payload_fetch_token, (bucket.bucket_id, block.clone()));
                assert!(previous.is_none(), "a block is stored in two buckets");
            }
        }
        stored
    }
}

proptest! {
    #![proptest_config(cases(64))]

    #[test]
    fn result_path_oram_never_loses_or_duplicates_blocks(
        tree_height in 2u32..5,
        bucket_size in 2usize..5,
        block_count in 1usize..24,
        initial_leaves in proptest::collection::vec(any::<u64>(), 24),
        ops in proptest::collection::vec((any::<u8>(), any::<u64>(), any::<u64>()), 1..80),
    ) {
        let config = result_config(tree_height, bucket_size, 96);
        let leaf_count = 1u64 << tree_height;
        let capacity = (private_result_oram_bucket_count(tree_height).unwrap() * bucket_size as u64) as usize;
        let block_count = block_count.min(capacity / 2).max(1);
        let mut server = ResultOramServer::new(config);
        let mut state = PrivateResultOramClientState::new();
        let mut expected: BTreeMap<[u8; 32], PrivateResultOramPayloadBlockPlaintext> = BTreeMap::new();

        // Insert every block through the stash and evict it onto its leaf path.
        for i in 0..block_count {
            let block = PrivateResultOramPayloadBlockPlaintext {
                version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
                payload_fetch_token: [i as u8; 32],
                point_token: [(i as u8).wrapping_add(100); 32],
                payload: vec![i as u8; (i % 7) + 1],
                deleted: false,
                generation: i as u64,
            };
            // Independent initial leaves: drawing them from a one-element `ops` put every block
            // on one path, whose capacity no eviction schedule can exceed.
            let leaf = initial_leaves[i] % leaf_count;
            state.insert_new_stash_block(block.clone(), leaf, config).unwrap();
            expected.insert(block.payload_fetch_token, block);
            let eviction = evict_private_result_oram_path(&mut state, config, leaf, &server.path(leaf)).unwrap();
            server.write_back(&eviction.writeback_buckets);
        }

        let check_invariants = |state: &PrivateResultOramClientState, server: &ResultOramServer| -> Result<(), TestCaseError> {
            let stored = server.stored();
            for (token, block) in &expected {
                let leaf = state.position(token).expect("every block keeps a position");
                let path: BTreeSet<u64> = private_result_oram_bucket_ids_for_leaf(leaf, tree_height).unwrap().into_iter().collect();
                match stored.get(token) {
                    Some((bucket_id, stored_block)) => {
                        prop_assert!(!state.stash_contains(token), "block both stored and stashed");
                        prop_assert!(path.contains(bucket_id), "stored block off its position path");
                        prop_assert_eq!(stored_block, block);
                    }
                    None => prop_assert!(state.stash_contains(token), "block lost"),
                }
            }
            prop_assert_eq!(stored.len() + state.stash_len(), expected.len(), "no foreign blocks");
            Ok(())
        };
        check_invariants(&state, &server)?;

        for (op, a, b) in &ops {
            let token = [(*a as usize % block_count) as u8; 32];
            let leaf = b % leaf_count;
            if op % 3 == 0 {
                let evict_leaf = a % leaf_count;
                let eviction = evict_private_result_oram_path(&mut state, config, evict_leaf, &server.path(evict_leaf)).unwrap();
                server.write_back(&eviction.writeback_buckets);
            } else {
                let old_leaf = state.position(&token).unwrap();
                let access = access_private_result_oram_path(&mut state, config, token, &server.path(old_leaf), leaf).unwrap();
                prop_assert_eq!(&access.block, &expected[&token]);
                prop_assert_eq!(access.old_leaf, old_leaf);
                prop_assert_eq!(access.new_leaf, leaf);
                prop_assert_eq!(state.position(&token), Some(leaf));
                prop_assert_eq!(access.writeback_buckets.len(), tree_height as usize + 1);
                server.write_back(&access.writeback_buckets);
            }
            check_invariants(&state, &server)?;
        }
        // With half-full capacity and Z >= 2 the stash must drain to a small constant.
        for leaf in 0..leaf_count {
            let eviction = evict_private_result_oram_path(&mut state, config, leaf, &server.path(leaf)).unwrap();
            server.write_back(&eviction.writeback_buckets);
        }
        check_invariants(&state, &server)?;
        prop_assert!(state.stash_len() <= bucket_size * 2, "stash did not drain: {}", state.stash_len());
    }

    #[test]
    fn result_path_oram_rejects_tampered_paths_without_touching_state(
        tree_height in 2u32..4,
        leaf in any::<u64>(),
        other in any::<u64>(),
    ) {
        let config = result_config(tree_height, 2, 96);
        let leaf_count = 1u64 << tree_height;
        let leaf = leaf % leaf_count;
        let other = other % leaf_count;
        let mut server = ResultOramServer::new(config);
        let mut state = PrivateResultOramClientState::new();
        let target = [1u8; 32];
        let neighbor = [5u8; 32];
        for (token, point) in [(target, [2u8; 32]), (neighbor, [6u8; 32])] {
            let block = PrivateResultOramPayloadBlockPlaintext {
                version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
                payload_fetch_token: token,
                point_token: point,
                payload: vec![3],
                deleted: false,
                generation: 1,
            };
            state.insert_new_stash_block(block, leaf, config).unwrap();
        }
        let eviction = evict_private_result_oram_path(&mut state, config, leaf, &server.path(leaf)).unwrap();
        server.write_back(&eviction.writeback_buckets);
        prop_assert_eq!(state.stash_len(), 0, "both blocks fit on their path");
        let before = state.to_snapshot(tree_height).unwrap();
        let unchanged = |state: &PrivateResultOramClientState| -> Result<(), TestCaseError> {
            prop_assert_eq!(state.to_snapshot(tree_height).unwrap(), before.clone(), "a failed access must not alter the client state");
            Ok(())
        };

        // The server answers with the path of a different leaf.
        if other != leaf {
            let wrong = access_private_result_oram_path(&mut state, config, target, &server.path(other), leaf);
            prop_assert!(matches!(wrong, Err(PrivateResultOramError::PathBucketMismatch)), "{:?}", wrong);
            unchanged(&state)?;
        }
        // A path that carries the same block twice.
        let mut duplicated = server.path(leaf);
        let clone = duplicated.iter().flat_map(|b| b.blocks.iter().flatten()).next().cloned().unwrap();
        let bucket_index = duplicated.iter().position(|b| b.blocks.iter().any(Option::is_none)).unwrap();
        let slot_index = duplicated[bucket_index].blocks.iter().position(Option::is_none).unwrap();
        duplicated[bucket_index].blocks[slot_index] = Some(clone);
        let dup = access_private_result_oram_path(&mut state, config, target, &duplicated, leaf);
        prop_assert!(matches!(dup, Err(PrivateResultOramError::DuplicatePayloadFetchToken)), "{:?}", dup);
        unchanged(&state)?;
        // A bucket of the wrong shape.
        let mut short = server.path(leaf);
        short[0].blocks.pop();
        let shape = access_private_result_oram_path(&mut state, config, target, &short, leaf);
        prop_assert!(matches!(shape, Err(PrivateResultOramError::BucketPlaintextSlotCountMismatch)), "{:?}", shape);
        unchanged(&state)?;
        // The target block is missing while its neighbor is present: the access fails and the
        // neighbor must not be left behind in the stash (the server still holds it, so a later
        // path read would collide with the stashed copy and wedge the client).
        let mut missing = server.path(leaf);
        for bucket in &mut missing {
            for slot in &mut bucket.blocks {
                if slot.as_ref().is_some_and(|block| block.payload_fetch_token == target) {
                    *slot = None;
                }
            }
        }
        let gone = access_private_result_oram_path(&mut state, config, target, &missing, leaf);
        prop_assert!(matches!(gone, Err(PrivateResultOramError::MissingBlock)), "{:?}", gone);
        unchanged(&state)?;
        // Eviction with a wrong path is rejected the same way.
        if other != leaf {
            let evict = evict_private_result_oram_path(&mut state, config, leaf, &server.path(other));
            prop_assert!(matches!(evict, Err(PrivateResultOramError::PathBucketMismatch)), "{:?}", evict);
            unchanged(&state)?;
        }
        // After every rejected answer a correct one still works.
        let ok = access_private_result_oram_path(&mut state, config, target, &server.path(leaf), other).unwrap();
        prop_assert_eq!(ok.block.payload_fetch_token, target);
        prop_assert_eq!(state.position(&target), Some(other));
        server.write_back(&ok.writeback_buckets);
        let ok = access_private_result_oram_path(&mut state, config, neighbor, &server.path(leaf), leaf).unwrap();
        prop_assert_eq!(ok.block.payload_fetch_token, neighbor);
    }
}

// ---------------------------------------------------------------------------------------------
// HNSW Path ORAM client simulation
// ---------------------------------------------------------------------------------------------

struct HnswOramServer {
    config: PrivateHnswOramClientConfig,
    buckets: Vec<PrivateHnswOramPlaintextBucket>,
}

impl HnswOramServer {
    fn new(config: PrivateHnswOramClientConfig) -> Self {
        let bucket_count = private_hnsw_oram_bucket_count(config.tree_height).unwrap();
        Self {
            config,
            buckets: (0..bucket_count)
                .map(|id| empty_private_hnsw_oram_plaintext_bucket(id, config).unwrap())
                .collect(),
        }
    }

    fn path(&self, leaf: u64) -> Vec<PrivateHnswOramPlaintextBucket> {
        private_hnsw_oram_bucket_ids_for_leaf(leaf, self.config.tree_height)
            .unwrap()
            .into_iter()
            .map(|id| self.buckets[id as usize].clone())
            .collect()
    }

    fn write_back(&mut self, buckets: &[PrivateHnswOramPlaintextBucket]) {
        for bucket in buckets {
            assert_eq!(bucket.blocks.len(), self.config.bucket_size);
            self.buckets[bucket.bucket_id as usize] = bucket.clone();
        }
    }

    fn stored(&self) -> BTreeMap<[u8; 32], (u64, PrivateHnswNodeBlockPlaintext)> {
        let mut stored = BTreeMap::new();
        for bucket in &self.buckets {
            for block in bucket.blocks.iter().flatten() {
                assert!(
                    stored
                        .insert(block.node_id, (bucket.bucket_id, block.clone()))
                        .is_none()
                );
            }
        }
        stored
    }
}

fn simple_hnsw_block(i: usize) -> PrivateHnswNodeBlockPlaintext {
    PrivateHnswNodeBlockPlaintext {
        version: 1,
        node_id: [i as u8; 32],
        point_token: [(i as u8).wrapping_add(100); 32],
        level_mask: 1,
        vector_encoding: PrivateHnswVectorEncoding::F32Le,
        vector: (i as f32).to_le_bytes().to_vec(),
        neighbors: vec![[(i as u8).wrapping_add(1); 32]],
        neighbor_levels: vec![0],
        deleted: false,
        generation: i as u64,
        payload_fetch_token: Some([(i as u8).wrapping_add(200); 32]),
    }
}

proptest! {
    #![proptest_config(cases(48))]

    #[test]
    fn hnsw_path_oram_never_loses_or_duplicates_blocks(
        tree_height in 2u32..5,
        bucket_size in 2usize..4,
        block_count in 1usize..16,
        ops in proptest::collection::vec((any::<u8>(), any::<u64>(), any::<u64>()), 1..60),
    ) {
        let config = hnsw_config(tree_height, bucket_size, 256, 1);
        let leaf_count = 1u64 << tree_height;
        let capacity = (private_hnsw_oram_bucket_count(tree_height).unwrap() * bucket_size as u64) as usize;
        let block_count = block_count.min(capacity / 2).max(1);
        let mut server = HnswOramServer::new(config);
        let mut state = PrivateHnswOramClientState::new();
        let mut expected = BTreeMap::new();
        for i in 0..block_count {
            let block = simple_hnsw_block(i);
            let leaf = ops[i % ops.len()].1 % leaf_count;
            state.insert_new_stash_block(block.clone(), leaf, config).unwrap();
            expected.insert(block.node_id, block);
            let eviction = evict_private_hnsw_oram_path(&mut state, config, leaf, &server.path(leaf)).unwrap();
            server.write_back(&eviction.writeback_buckets);
        }
        check_hnsw_invariants(&expected, &state, &server, tree_height)?;
        for (op, a, b) in &ops {
            let node_id = [(*a as usize % block_count) as u8; 32];
            let leaf = b % leaf_count;
            if op % 3 == 0 {
                let evict_leaf = a % leaf_count;
                let eviction = evict_private_hnsw_oram_path(&mut state, config, evict_leaf, &server.path(evict_leaf)).unwrap();
                server.write_back(&eviction.writeback_buckets);
            } else if op % 3 == 1 {
                let old_leaf = state.position(&node_id).unwrap();
                let access = access_private_hnsw_oram_path(&mut state, config, node_id, &server.path(old_leaf), leaf).unwrap();
                prop_assert_eq!(&access.block, &expected[&node_id]);
                prop_assert_eq!(state.position(&node_id), Some(leaf));
                server.write_back(&access.writeback_buckets);
            } else {
                // Append-style rewrite that bumps the generation; the rewritten block must be the
                // one that lands on the new path.
                let old_leaf = state.position(&node_id).unwrap();
                let access = access_private_hnsw_oram_path_with_append_rewrite(
                    &mut state,
                    config,
                    node_id,
                    &server.path(old_leaf),
                    leaf,
                    |previous| {
                        let mut next = previous.clone();
                        next.generation = previous.generation.wrapping_add(1);
                        Ok(next)
                    },
                );
                match access {
                    Ok(access) => {
                        expected.insert(node_id, access.block.clone());
                        server.write_back(&access.writeback_buckets);
                    }
                    Err(err) => {
                        // A rejected rewrite must leave both sides untouched.
                        prop_assert_eq!(err, PrivateHnswClientError::InvalidAppendRewrite);
                    }
                }
            }
            check_hnsw_invariants(&expected, &state, &server, tree_height)?;
        }
    }
}

proptest! {
    #![proptest_config(cases(32))]

    #[test]
    fn hnsw_path_oram_failed_access_leaves_state_unchanged(
        tree_height in 2u32..4,
        leaf in any::<u64>(),
        other in any::<u64>(),
    ) {
        let config = hnsw_config(tree_height, 2, 256, 1);
        let leaf_count = 1u64 << tree_height;
        let leaf = leaf % leaf_count;
        let other = other % leaf_count;
        let mut server = HnswOramServer::new(config);
        let mut state = PrivateHnswOramClientState::new();
        let target = simple_hnsw_block(1);
        let neighbor = simple_hnsw_block(5);
        state.insert_new_stash_block(target.clone(), leaf, config).unwrap();
        state.insert_new_stash_block(neighbor.clone(), leaf, config).unwrap();
        let eviction = evict_private_hnsw_oram_path(&mut state, config, leaf, &server.path(leaf)).unwrap();
        server.write_back(&eviction.writeback_buckets);
        prop_assert_eq!(state.stash_len(), 0);
        let before = state.to_snapshot(tree_height).unwrap();

        if other != leaf {
            let wrong = access_private_hnsw_oram_path(&mut state, config, target.node_id, &server.path(other), leaf);
            prop_assert!(wrong.is_err());
            prop_assert_eq!(state.to_snapshot(tree_height).unwrap(), before.clone());
        }
        let mut missing = server.path(leaf);
        for bucket in &mut missing {
            for slot in &mut bucket.blocks {
                if slot.as_ref().is_some_and(|block| block.node_id == target.node_id) {
                    *slot = None;
                }
            }
        }
        let gone = access_private_hnsw_oram_path(&mut state, config, target.node_id, &missing, leaf);
        prop_assert!(matches!(gone, Err(PrivateHnswClientError::MissingBlock)), "{:?}", gone);
        prop_assert_eq!(state.to_snapshot(tree_height).unwrap(), before.clone(), "a failed access must not alter the client state");
        let gone = access_private_hnsw_oram_path_with_append_rewrite(&mut state, config, target.node_id, &missing, leaf, |previous| Ok(previous.clone()));
        prop_assert!(matches!(gone, Err(PrivateHnswClientError::MissingBlock)), "{:?}", gone);
        prop_assert_eq!(state.to_snapshot(tree_height).unwrap(), before.clone());

        let ok = access_private_hnsw_oram_path(&mut state, config, target.node_id, &server.path(leaf), other).unwrap();
        prop_assert_eq!(ok.block, target);
        server.write_back(&ok.writeback_buckets);
        let ok = access_private_hnsw_oram_path(&mut state, config, neighbor.node_id, &server.path(leaf), leaf).unwrap();
        prop_assert_eq!(ok.block, neighbor);
    }
}

fn check_hnsw_invariants(
    expected: &BTreeMap<[u8; 32], PrivateHnswNodeBlockPlaintext>,
    state: &PrivateHnswOramClientState,
    server: &HnswOramServer,
    tree_height: u32,
) -> Result<(), TestCaseError> {
    let stored = server.stored();
    for (node_id, block) in expected {
        let leaf = state.position(node_id).expect("position kept");
        let path: BTreeSet<u64> = private_hnsw_oram_bucket_ids_for_leaf(leaf, tree_height)
            .unwrap()
            .into_iter()
            .collect();
        match stored.get(node_id) {
            Some((bucket_id, stored_block)) => {
                prop_assert!(!state.stash_contains(node_id));
                prop_assert!(path.contains(bucket_id));
                prop_assert_eq!(stored_block, block);
            }
            None => prop_assert!(state.stash_contains(node_id), "block lost"),
        }
    }
    prop_assert_eq!(stored.len() + state.stash_len(), expected.len());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// CKKS parameters and public material
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(256))]

    #[test]
    fn ckks_parameters_validate_without_panicking(
        poly in any::<u32>(),
        depth in any::<u32>(),
        scale in any::<u32>(),
        first in any::<u32>(),
        batch in any::<u32>(),
    ) {
        let parameters = CkksParameters {
            poly_modulus_degree: poly,
            multiplicative_depth: depth,
            scaling_mod_size: scale,
            first_mod_size: first,
            batch_size: batch,
        };
        let validated = parameters.validate();
        if validated.is_ok() {
            prop_assert!(parameters.security_profile().is_some());
            prop_assert!(batch >= 1 && batch <= poly / 2);
        }
        let _ = CkksPublicMaterial::new(vec![1u8; (poly % 64) as usize], vec![2u8; (batch % 64) as usize]);
    }
}

// ---------------------------------------------------------------------------------------------
// Canonical binary and JSON frames
// ---------------------------------------------------------------------------------------------

fn sample_frame() -> PrivateOramStagedInsertFrameV1 {
    let mut payload = Map::new();
    payload.insert("title".to_string(), json!("secret"));
    PrivateOramStagedInsertFrameV1 {
        version: PRIVATE_ORAM_STAGED_INSERT_FRAME_V1_VERSION,
        collection_id: "secret-collection".to_string(),
        manifest_digest: digest(1),
        mutation_id: digest(2),
        old_state_digest: digest(3),
        new_state_digest: digest(4),
        layout_generation: 7,
        layout_digest: digest(6),
        old_state_sequence: 41,
        new_state_sequence: 42,
        writer_lease_digest: digest(5),
        writer_fence: 11,
        target_shard_ids: vec![13, 21],
        shard_key: Some(PrivateOramStagedShardKeyV1::Keyword {
            value: "secret-shard-key".to_string(),
        }),
        point: PrivateOramStagedPointV1 {
            id: PrivateOramStagedPointIdV1::Numeric { value: 9 },
            vectors: vec![
                PrivateOramStagedNamedVectorV1 {
                    name: "a-vector".to_string(),
                    vector: PrivateOramStagedVectorV1::Sparse {
                        indices: vec![2, 9],
                        values: vec![4.0, 1.5],
                    },
                },
                PrivateOramStagedNamedVectorV1 {
                    name: "z-vector".to_string(),
                    vector: PrivateOramStagedVectorV1::Dense {
                        values: vec![0.5, 1.5],
                    },
                },
            ],
            payload: Some(payload),
        },
    }
}

proptest! {
    #![proptest_config(cases(512))]

    #[test]
    fn staged_insert_frame_codec_is_canonical_under_mutation(
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
        payload in json_value(),
        point_id in any::<u64>(),
        shard_ids in proptest::collection::btree_set(any::<u32>(), 1..4),
    ) {
        let mut frame = sample_frame();
        frame.point.id = PrivateOramStagedPointIdV1::Numeric { value: point_id };
        frame.target_shard_ids = shard_ids.into_iter().collect();
        frame.point.payload = match payload {
            Value::Object(map) => Some(map),
            _ => None,
        };
        let Ok(encoded) = encode_private_oram_staged_insert_frame_v1(&frame) else {
            return Ok(());
        };
        let decoded = decode_private_oram_staged_insert_frame_v1(&encoded).unwrap();
        prop_assert!(decoded == frame, "frame round trip");

        let mutated = mutate_bytes(&encoded, choice, index, byte);
        if let Ok(decoded) = decode_private_oram_staged_insert_frame_v1(&mutated) {
            let reencoded = encode_private_oram_staged_insert_frame_v1(&decoded).unwrap();
            prop_assert_eq!(reencoded, mutated, "decoder accepted a non-canonical frame");
        }
    }

    #[test]
    fn staged_insert_frame_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_private_oram_staged_insert_frame_v1(&bytes);
    }

    #[test]
    fn owner_lifecycle_json_frame_decoders_never_panic(value in json_value(), bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let rendered = serde_json::to_vec(&value).unwrap();
        for input in [rendered.as_slice(), bytes.as_slice()] {
            let _ = decode_private_oram_owner_enrollment_prepared_v1(input);
            let _ = decode_private_oram_owner_lifecycle_status_attestation_v1(input);
            let _ = decode_private_oram_owner_enrollment_genesis_commitment_v1(input);
            let _ = decode_private_oram_owner_reservation_prepare_v1(input);
            let _ = decode_private_oram_owner_reservation_resolution_receipt_v1(input);
            let _ = decode_private_oram_owner_prestage_package_v2(input);
            let _ = decode_private_oram_owner_prestage_attestation_v2(input);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Sparse Merkle patches (append transactions)
// ---------------------------------------------------------------------------------------------

fn patch_proof(
    index_epoch: u64,
    old_commitments: &[String],
    bucket_ids: &[u64],
) -> PrivateOramAppendMerklePatchProofV1 {
    let levels = merkle_levels(old_commitments);
    PrivateOramAppendMerklePatchProofV1 {
        version: PRIVATE_ORAM_APPEND_MERKLE_PATCH_PROOF_V1_VERSION,
        index_epoch,
        old_root_hash: BASE64URL_NOPAD.encode(&levels.last().unwrap()[0]),
        bucket_count: old_commitments.len() as u64,
        leaves: bucket_ids
            .iter()
            .map(|bucket_id| {
                let mut index = *bucket_id as usize;
                let siblings = levels[..levels.len() - 1]
                    .iter()
                    .enumerate()
                    .map(|(level, hashes)| {
                        let sibling = PrivateOramAppendMerkleSiblingV1 {
                            level: level as u32,
                            position: if index.is_multiple_of(2) {
                                PrivateOramAppendMerkleSiblingPositionV1::Right
                            } else {
                                PrivateOramAppendMerkleSiblingPositionV1::Left
                            },
                            hash: BASE64URL_NOPAD.encode(&hashes[index ^ 1]),
                        };
                        index /= 2;
                        sibling
                    })
                    .collect();
                PrivateOramAppendMerklePatchLeafV1 {
                    bucket_id: *bucket_id,
                    old_commitment: old_commitments[*bucket_id as usize].clone(),
                    siblings,
                }
            })
            .collect(),
    }
}

proptest! {
    #![proptest_config(cases(128))]

    #[test]
    fn sparse_merkle_patch_matches_full_recomputation_and_rejects_mutation(
        bucket_count in 1u64..40,
        old_seed in any::<u64>(),
        updates in proptest::collection::btree_map(0u64..40, any::<u8>(), 1..8),
        mutation in 0u32..9,
        which in any::<usize>(),
        byte in any::<u8>(),
        choice in any::<u32>(),
        index in any::<usize>(),
    ) {
        let old_commitments: Vec<String> = (0..bucket_count)
            .map(|id| {
                let mut hasher = Sha256::new();
                hasher.update(old_seed.to_be_bytes());
                hasher.update(id.to_be_bytes());
                BASE64URL_NOPAD.encode(hasher.finalize().as_ref())
            })
            .collect();
        let updates: BTreeMap<u64, u8> = updates.into_iter().filter(|(id, _)| *id < bucket_count).collect();
        prop_assume!(!updates.is_empty());
        let bucket_ids: Vec<u64> = updates.keys().copied().collect();
        let proof = patch_proof(3, &old_commitments, &bucket_ids);
        let old_root = proof.old_root_hash.clone();
        let ordered_updates: Vec<PrivateOramAppendBucketRefV1> = updates
            .iter()
            .map(|(id, b)| PrivateOramAppendBucketRefV1 {
                bucket_id: *id,
                ciphertext_sha256: digest(*b),
                bucket_commitment: digest(b.wrapping_add(1)),
            })
            .collect();

        let patch = apply_private_oram_append_sparse_merkle_patch_v1(3, &old_root, bucket_count, &proof, &ordered_updates).unwrap();
        let mut new_commitments = old_commitments.clone();
        for update in &ordered_updates {
            new_commitments[update.bucket_id as usize] = update.bucket_commitment.clone();
        }
        let expected_root = BASE64URL_NOPAD.encode(&merkle_levels(&new_commitments).last().unwrap()[0]);
        prop_assert_eq!(&patch.new_root_hash, &expected_root, "sparse patch must equal a full recomputation");
        prop_assert_eq!(patch.final_buckets.len(), ordered_updates.len());
        if ordered_updates.iter().any(|u| u.bucket_commitment != old_commitments[u.bucket_id as usize]) {
            prop_assert_ne!(&patch.new_root_hash, &old_root, "a changed commitment must move the root");
        }

        let leaf_index = which % proof.leaves.len();
        let mut mutated = proof.clone();
        let mut mutated_updates = ordered_updates.clone();
        let mut expected_old_root = old_root.clone();
        let mut epoch = 3u64;
        match mutation {
            0 => mutated.old_root_hash = digest(byte),
            1 => expected_old_root = digest(byte),
            2 => epoch = 4,
            3 => mutated.leaves[leaf_index].old_commitment = digest(byte),
            4 => {
                let leaf = &mut mutated.leaves[leaf_index];
                prop_assume!(!leaf.siblings.is_empty());
                let sibling_index = index % leaf.siblings.len();
                let hash = leaf.siblings[sibling_index].hash.clone();
                leaf.siblings[sibling_index].hash = mutate_string(&hash, choice, index, byte);
            }
            5 => {
                let leaf = &mut mutated.leaves[leaf_index];
                prop_assume!(!leaf.siblings.is_empty());
                leaf.siblings.pop();
            }
            6 => {
                // An update for a bucket the proof does not cover.
                let unproven = (0..bucket_count).find(|id| !bucket_ids.contains(id));
                prop_assume!(unproven.is_some());
                mutated_updates.push(PrivateOramAppendBucketRefV1 {
                    bucket_id: unproven.unwrap(),
                    ciphertext_sha256: digest(byte),
                    bucket_commitment: digest(byte),
                });
            }
            7 => mutated.bucket_count = bucket_count + 1,
            _ => {
                // Two leaves that disagree about a shared ancestor's sibling.
                prop_assume!(mutated.leaves.len() > 1);
                let leaf = &mut mutated.leaves[leaf_index];
                prop_assume!(!leaf.siblings.is_empty());
                leaf.siblings.last_mut().unwrap().hash = digest(byte);
            }
        }
        prop_assume!(mutated != proof || mutated_updates != ordered_updates || expected_old_root != old_root || epoch != 3);
        prop_assert!(
            apply_private_oram_append_sparse_merkle_patch_v1(epoch, &expected_old_root, bucket_count, &mutated, &mutated_updates).is_err(),
            "mutation {} accepted", mutation
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Server-side ingress validators: upload bundles, manifests, client CKKS sidecars
// ---------------------------------------------------------------------------------------------

static ZERO_PUBLIC_KEY: [u8; 32] = [0; 32];

fn hnsw_manifest_fixture() -> PrivateHnswOramManifest {
    PrivateHnswOramManifest {
        version: 1,
        provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
        binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
        collection_id: COLLECTION_ID.to_string(),
        vector_name: VECTOR_NAME.to_string(),
        key_id: KEY_ID.to_string(),
        rk_id: RK_ID.to_string(),
        rk_epoch: RK_EPOCH,
        dim: 4,
        distance: DistanceKind::Euclid,
        hnsw: PrivateHnswParams {
            m: 2,
            ef_construction: 32,
            max_layers: 4,
            fixed_neighbor_slots: 2,
        },
        oram: OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 512,
            tree_height: 1,
            path_batch_size: 2,
        },
        fixed_budget: FixedBudgetParams {
            enabled: true,
            upper_layer_steps: 4,
            base_layer_steps: 8,
            paths_per_round: 2,
            fixed_result_k: 2,
        },
        index_epoch: 5,
        root_hash: digest(0),
        bucket_count: 3,
        logical_node_count: 3,
        dummy_node_count: 0,
        result_privacy: ResultPrivacyMode::IdsVisible,
        owner_signing_key_id: "tenant-a/owner".to_string(),
        created_at_unix: 1,
    }
}

fn hnsw_validation_context() -> PrivateHnswManifestValidationContext<'static> {
    PrivateHnswManifestValidationContext {
        expected_collection_id: COLLECTION_ID,
        expected_vector_name: VECTOR_NAME,
        expected_key_id: KEY_ID,
        expected_rk_id: RK_ID,
        min_rk_epoch: RK_EPOCH,
        max_rk_epoch: RK_EPOCH,
        expected_dim: 4,
        expected_distance: DistanceKind::Euclid,
        signature_verification: PrivateHnswSignatureVerification {
            expected_key_id: "tenant-a/owner",
            public_key: &ZERO_PUBLIC_KEY,
        },
    }
}

/// A structurally valid HNSW upload bundle: fixed-size sealed buckets whose commitments match
/// the manifest root, with a well-formed (but unverifiable) owner signature.
fn hnsw_upload_bundle() -> PrivateHnswOramUploadBundle {
    let mut manifest = hnsw_manifest_fixture();
    let config = hnsw_config(1, 2, 512, 2);
    let keys = hnsw_keys();
    let buckets: Vec<PrivateHnswOramBucket> = (0..3)
        .map(|id| {
            seal_private_hnsw_oram_plaintext_bucket(
                &keys,
                hnsw_base_context(),
                manifest.index_epoch,
                &empty_private_hnsw_oram_plaintext_bucket(id, config).unwrap(),
                config,
            )
            .unwrap()
        })
        .collect();
    let commitments: Vec<String> = buckets
        .iter()
        .map(|b| b.bucket_commitment.clone())
        .collect();
    manifest.root_hash = private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap();
    PrivateHnswOramUploadBundle {
        manifest,
        manifest_signature: PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/owner".to_string(),
            sig: BASE64URL_NOPAD.encode(&[1u8; 64]),
        },
        buckets,
    }
}

fn result_upload_bundle() -> PrivateResultOramUploadBundle {
    let mut manifest = result_manifest(1, 2);
    let config = result_config(1, 4, 256);
    let keys = result_keys();
    let buckets: Vec<PrivateResultOramBucket> = (0..3)
        .map(|id| {
            seal_private_result_oram_plaintext_bucket(
                &keys,
                result_base_context(),
                manifest.index_epoch,
                &empty_private_result_oram_plaintext_bucket(id, config).unwrap(),
                config,
            )
            .unwrap()
        })
        .collect();
    let commitments: Vec<String> = buckets
        .iter()
        .map(|b| b.bucket_commitment.clone())
        .collect();
    manifest.root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
    PrivateResultOramUploadBundle {
        manifest,
        manifest_signature: PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/owner".to_string(),
            sig: BASE64URL_NOPAD.encode(&[1u8; 64]),
        },
        buckets,
    }
}

/// Replaces one manifest field either with arbitrary JSON or with a same-typed tweak.
fn mutate_manifest_field(
    manifest_value: &Value,
    field: usize,
    replacement: Value,
    byte: u8,
) -> (String, Vec<Value>) {
    let object = manifest_value.as_object().unwrap();
    let keys: Vec<&String> = object.keys().collect();
    let key = keys[field % keys.len()].clone();
    let original = object[&key].clone();
    let tweaked = match &original {
        Value::String(s) => Value::String(mutate_string(s, field as u32, field, byte)),
        Value::Number(n) => json!(n.as_u64().unwrap_or(0).wrapping_add(u64::from(byte) + 1)),
        Value::Bool(b) => Value::Bool(!b),
        other => other.clone(),
    };
    let candidates = [replacement, tweaked]
        .into_iter()
        .map(|mutated| {
            let mut candidate = manifest_value.clone();
            candidate[key.as_str()] = mutated;
            candidate
        })
        .collect();
    (key, candidates)
}

const HNSW_BINDING_FIELDS: &[&str] = &[
    "version",
    "provider",
    "binding",
    "collection_id",
    "vector_name",
    "key_id",
    "rk_id",
    "rk_epoch",
    "index_epoch",
    "root_hash",
    "bucket_count",
    "owner_signing_key_id",
];

const RESULT_BINDING_FIELDS: &[&str] = &[
    "version",
    "provider",
    "binding",
    "collection_id",
    "key_id",
    "rk_id",
    "rk_epoch",
    "index_epoch",
    "root_hash",
    "bucket_count",
    "owner_signing_key_id",
];

proptest! {
    #![proptest_config(cases(256))]

    #[test]
    fn ingress_validators_never_panic_on_arbitrary_json(value in json_value()) {
        if let Ok(manifest) = serde_json::from_value::<PrivateHnswOramManifest>(value.clone()) {
            let _ = validate_private_hnsw_oram_manifest_shape(&manifest);
        }
        if let Ok(signature) = serde_json::from_value::<PrivateHnswOramSignature>(value.clone()) {
            let _ = validate_private_hnsw_oram_manifest_signature_shape(&signature);
        }
        if let Ok(bundle) = serde_json::from_value::<PrivateHnswOramUploadBundle>(value.clone()) {
            let _ = validate_private_hnsw_oram_upload_bundle(&bundle);
        }
        if let Ok(manifest) = serde_json::from_value::<PrivateResultOramManifest>(value.clone()) {
            let _ = validate_private_result_oram_manifest_shape(&manifest);
        }
        if let Ok(bundle) = serde_json::from_value::<PrivateResultOramUploadBundle>(value.clone()) {
            let _ = validate_private_result_oram_upload_bundle(&bundle);
        }
        let _ = is_encrypted_ckks_vector_payload_value(&value);
        let _ = is_client_ckks_vector_payload_value(&value);
        let _ = client_ckks_vector_signature_message(&value);
        let _ = client_ckks_vector_sidecar_envelope_key(&value, "text");
        let context_digest = digest(3);
        let _ = validate_client_ckks_vector_payload_value_for_runtime(
            &value,
            ClientCkksVectorValidationContext {
                collection_id: "docs",
                point_id: "1",
                vector_name: "text",
                expected_key_id: KEY_ID,
                expected_rk_id: RK_ID,
                min_rk_epoch: 0,
                max_rk_epoch: u64::MAX,
                expected_context_digest: &context_digest,
                max_slots: 16,
                signature_verification: ClientCkksVectorSignatureVerification {
                    expected_key_id: "tenant-a/signing",
                    public_key: &ZERO_PUBLIC_KEY,
                },
            },
        );
    }

    #[test]
    fn hnsw_upload_bundle_validation_survives_manifest_mutations(
        field in any::<usize>(),
        replacement in json_value(),
        byte in any::<u8>(),
    ) {
        let bundle = hnsw_upload_bundle();
        let commitments = validate_private_hnsw_oram_upload_bundle(&bundle).unwrap();
        prop_assert_eq!(commitments.len(), 3);
        // A well-formed signature that does not verify never passes the signed validation.
        prop_assert!(
            validate_private_hnsw_oram_upload_bundle_with_signature(&bundle, hnsw_validation_context()).is_err()
        );

        let manifest_value = serde_json::to_value(&bundle.manifest).unwrap();
        let (key, candidates) = mutate_manifest_field(&manifest_value, field, replacement, byte);
        for candidate in candidates {
            let Ok(manifest) = serde_json::from_value::<PrivateHnswOramManifest>(candidate) else {
                continue;
            };
            if manifest == bundle.manifest {
                continue;
            }
            let _ = validate_private_hnsw_oram_manifest_shape(&manifest);
            let mutated = PrivateHnswOramUploadBundle {
                manifest,
                manifest_signature: bundle.manifest_signature.clone(),
                buckets: bundle.buckets.clone(),
            };
            let result = validate_private_hnsw_oram_upload_bundle(&mutated);
            if HNSW_BINDING_FIELDS.contains(&key.as_str()) {
                prop_assert!(result.is_err(), "mutated manifest field {} was accepted", key);
            }
            let _ = validate_private_hnsw_oram_upload_bundle_with_signature(&mutated, hnsw_validation_context());
        }
    }

    #[test]
    fn result_upload_bundle_validation_survives_manifest_mutations(
        field in any::<usize>(),
        replacement in json_value(),
        byte in any::<u8>(),
    ) {
        let bundle = result_upload_bundle();
        let commitments = validate_private_result_oram_upload_bundle(&bundle).unwrap();
        prop_assert_eq!(commitments.len(), 3);

        let manifest_value = serde_json::to_value(&bundle.manifest).unwrap();
        let (key, candidates) = mutate_manifest_field(&manifest_value, field, replacement, byte);
        for candidate in candidates {
            let Ok(manifest) = serde_json::from_value::<PrivateResultOramManifest>(candidate) else {
                continue;
            };
            if manifest == bundle.manifest {
                continue;
            }
            let _ = validate_private_result_oram_manifest_shape(&manifest);
            let mutated = PrivateResultOramUploadBundle {
                manifest,
                manifest_signature: bundle.manifest_signature.clone(),
                buckets: bundle.buckets.clone(),
            };
            let result = validate_private_result_oram_upload_bundle(&mutated);
            if RESULT_BINDING_FIELDS.contains(&key.as_str()) {
                prop_assert!(result.is_err(), "mutated manifest field {} was accepted", key);
            }
        }
    }

    #[test]
    fn upload_bundle_bucket_mutations_are_rejected(
        which in any::<usize>(),
        field in 0u32..5,
        choice in any::<u32>(),
        index in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let mut bundle = hnsw_upload_bundle();
        let bucket_index = which % bundle.buckets.len();
        let original = bundle.buckets[bucket_index].clone();
        {
            let bucket = &mut bundle.buckets[bucket_index];
            match field {
                0 => bucket.ciphertext = mutate_string(&original.ciphertext, choice, index, byte),
                1 => bucket.ciphertext_sha256 = mutate_string(&original.ciphertext_sha256, choice, index, byte),
                2 => bucket.bucket_commitment = mutate_string(&original.bucket_commitment, choice, index, byte),
                3 => bucket.bucket_id = (original.bucket_id + 1 + u64::from(byte)) % 3,
                _ => bucket.index_epoch = original.index_epoch.wrapping_add(u64::from(byte) + 1),
            }
        }
        prop_assume!(bundle.buckets[bucket_index] != original);
        prop_assert!(validate_private_hnsw_oram_upload_bundle(&bundle).is_err(), "mutated bucket accepted");
        // Duplicated or missing buckets are rejected as well.
        let mut duplicated = hnsw_upload_bundle();
        let clone = duplicated.buckets[bucket_index].clone();
        duplicated.buckets.push(clone);
        prop_assert!(validate_private_hnsw_oram_upload_bundle(&duplicated).is_err());
        let mut missing = hnsw_upload_bundle();
        missing.buckets.remove(bucket_index);
        prop_assert!(validate_private_hnsw_oram_upload_bundle(&missing).is_err());
    }

    #[test]
    fn control_plane_envelope_round_trips(
        version in 1u16..=u16::MAX,
        provider in "[a-z0-9._:/@-]{1,32}",
        fingerprint in "[a-z0-9._:/@-]{1,32}",
        key_id in "[a-z0-9._:/@-]{1,32}",
        binding in proptest::option::of("[a-z0-9._:/@-]{1,32}"),
        headers in json_value(),
        body in "[A-Za-z0-9_-]{1,64}",
        capability in 0u8..4,
    ) {
        let capability = match capability {
            0 => CryptoCapability::PayloadValue,
            1 => CryptoCapability::VectorCiphertext,
            2 => CryptoCapability::MetadataValue,
            _ => CryptoCapability::MetadataExactMatchToken,
        };
        let headers = match headers {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        let Ok(envelope) = CiphertextEnvelope::new(version, capability, provider, fingerprint, key_id, binding, headers, body) else {
            return Ok(());
        };
        let stored = envelope.to_stored_value();
        let parsed = CiphertextEnvelope::from_stored_value(&stored).unwrap();
        prop_assert!(parsed == Some(envelope.clone()), "stored envelope must parse back to itself");
        let mut extra = stored.clone();
        extra.as_object_mut().unwrap().insert("extra".to_string(), json!(1));
        prop_assert!(CiphertextEnvelope::from_stored_value(&extra).is_err(), "a second top-level key must be rejected");
    }
}

// ---------------------------------------------------------------------------------------------
// Result ORAM token fetch: what the server observes must not depend on leaf collisions
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(cases(48))]

    #[test]
    fn result_token_fetch_reads_canonical_batches_and_writes_back_every_read_path(
        tree_height in 2u32..4,
        block_count in 2usize..8,
        leaf_seed in proptest::collection::vec(any::<u64>(), 8),
        fetch_mask in 1u8..255,
        padding_offset in any::<u64>(),
        remap_offset in any::<u64>(),
    ) {
        let config = result_config(tree_height, 2, 96);
        let leaf_count = 1u64 << tree_height;
        let mut manifest = result_manifest(tree_height, 2);
        manifest.oram.bucket_size = 2;
        manifest.oram.block_size_bytes = 96;
        let index_epoch = manifest.index_epoch;

        // Populate a plaintext tree through the client, then seal it as the server would hold it.
        let mut server = ResultOramServer::new(config);
        let mut state = PrivateResultOramClientState::new();
        let mut blocks = Vec::new();
        for i in 0..block_count {
            let block = PrivateResultOramPayloadBlockPlaintext {
                version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
                payload_fetch_token: [i as u8 + 1; 32],
                point_token: [i as u8 + 100; 32],
                payload: vec![i as u8],
                deleted: false,
                generation: 1,
            };
            let leaf = leaf_seed[i % leaf_seed.len()] % leaf_count;
            state.insert_new_stash_block(block.clone(), leaf, config).unwrap();
            let eviction = evict_private_result_oram_path(&mut state, config, leaf, &server.path(leaf)).unwrap();
            server.write_back(&eviction.writeback_buckets);
            blocks.push(block);
        }
        let keys = result_keys();
        let sealed: Vec<PrivateResultOramBucket> = server
            .buckets
            .iter()
            .map(|bucket| {
                seal_private_result_oram_plaintext_bucket(&keys, result_base_context(), index_epoch, bucket, config).unwrap()
            })
            .collect();
        let commitments: Vec<String> = sealed.iter().map(|b| b.bucket_commitment.clone()).collect();
        let root = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let bucket_count = sealed.len() as u64;

        // Fetch an even number of the stored tokens; collisions on a leaf are the interesting case.
        let mut tokens: Vec<[u8; 32]> = blocks
            .iter()
            .enumerate()
            .filter(|(i, _)| fetch_mask & (1 << (i % 8)) != 0)
            .map(|(_, block)| block.payload_fetch_token)
            .collect();
        if tokens.len() % 2 == 1 {
            tokens.pop();
        }
        prop_assume!(!tokens.is_empty());
        let positions: Vec<_> = tokens
            .iter()
            .map(|token| PrivateResultOramFetchTokenPosition {
                payload_fetch_token: *token,
                leaf: state.position(token).unwrap(),
            })
            .collect();
        let mut padding_cursor = padding_offset;
        let plan = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(&manifest, &tokens, &positions, || {
            padding_cursor = padding_cursor.wrapping_add(1);
            Ok(padding_cursor % leaf_count)
        })
        .unwrap();

        // The batch layout is the canonical leaf order of real and padding paths together.
        for (batch, chunk) in plan.batches.iter().zip(tokens.chunks(2)) {
            let mut leaves: BTreeSet<u64> = chunk.iter().map(|token| state.position(token).unwrap()).collect();
            leaves.extend(batch.padding_leaves.iter().copied());
            let mut expected = Vec::new();
            for leaf in &leaves {
                expected.extend(private_result_oram_bucket_ids_for_leaf(*leaf, tree_height).unwrap());
            }
            prop_assert_eq!(&batch.bucket_ids, &expected, "batch must list paths in canonical leaf order");
        }

        let encrypted_batches: Vec<_> = plan
            .batches
            .iter()
            .map(|batch| PrivateResultOramEncryptedBucketBatch {
                index_epoch,
                root_hash: root.clone(),
                bucket_count,
                proof_value: serde_json::to_string(&result_merkle_proof(index_epoch, &commitments, &batch.bucket_ids)).unwrap(),
                buckets: batch.bucket_ids.iter().map(|id| sealed[*id as usize].clone()).collect(),
            })
            .collect();
        let mut remap_cursor = remap_offset;
        let result = fetch_private_result_oram_tokens_encrypted_verified(
            &keys,
            result_base_context(),
            index_epoch,
            &root,
            bucket_count,
            index_epoch + 1,
            &mut state,
            config,
            &tokens,
            &plan,
            &encrypted_batches,
            || {
                remap_cursor = remap_cursor.wrapping_add(1);
                Ok(remap_cursor % leaf_count)
            },
        )
        .unwrap();

        // The write-back covers exactly the read set, so it reveals nothing beyond the reads.
        let read_set: BTreeSet<u64> = plan.batches.iter().flat_map(|b| b.bucket_ids.iter().copied()).collect();
        let written: BTreeSet<u64> = result.updated_buckets.iter().map(|b| b.bucket_id).collect();
        prop_assert_eq!(written, read_set, "write-back must cover every read path, real or padding");
        prop_assert!(result.updated_buckets.iter().all(|b| b.index_epoch == index_epoch + 1));

        // The fetched blocks are the right ones and the client state moved with them.
        prop_assert_eq!(result.accesses.len(), tokens.len());
        for access in &result.accesses {
            let expected = blocks.iter().find(|b| b.payload_fetch_token == access.payload_fetch_token).unwrap();
            prop_assert_eq!(&access.block, expected);
            prop_assert_eq!(state.position(&access.payload_fetch_token), Some(access.new_leaf));
        }
    }
}
