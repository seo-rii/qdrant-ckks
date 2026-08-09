#![cfg(feature = "testing")]

use std::path::Path;

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    PRIVATE_HNSW_ORAM_BINDING, PRIVATE_HNSW_ORAM_V2_BINDING,
    PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION, PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
    PRIVATE_ORAM_SIGNED_STATE_V2_VERSION, PRIVATE_RESULT_ORAM_BINDING,
    PRIVATE_RESULT_ORAM_V2_BINDING, PrivateHnswBucketAeadContext,
    PrivateHnswManifestValidationContext, PrivateHnswOramBucket, PrivateHnswOramManifest,
    PrivateHnswOramSignature, PrivateHnswOramUploadBundle, PrivateHnswParams,
    PrivateHnswSignatureVerification, PrivateHnswVectorEncoding, PrivateOramAppendBucketRefV1,
    PrivateOramAppendIndexWritebackV1, PrivateOramAppendMutationBundleV1,
    PrivateOramAppendMutationV1, PrivateOramAppendWritebackDigestInput,
    PrivateOramImmutableIndexParamsV2, PrivateOramImmutableIndexV2,
    PrivateOramImmutableManifestBundleV2, PrivateOramImmutableManifestV2,
    PrivateOramIndexCapacityV2, PrivateOramIndexKindV2, PrivateOramIndexStateV2,
    PrivateOramPointOperationKindV1, PrivateOramSignatureVerification, PrivateOramSignedStateV2,
    PrivateResultOramBucket, PrivateResultOramBucketCommitmentContext, PrivateResultOramManifest,
    PrivateResultOramManifestValidationContext, PrivateResultOramSignature,
    PrivateResultOramSignatureVerification, PrivateResultOramUploadBundle, ResultPrivacyMode,
    VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER,
    package_private_oram_append_mutation_v1, package_private_oram_immutable_manifest_v2,
    package_private_oram_signed_state_v2, private_hnsw_bucket_commitment,
    private_hnsw_oram_bucket_ciphertext_bytes, private_oram_append_writeback_v1_digest,
    private_oram_immutable_manifest_v2_digest, private_oram_no_server_point_record_v1_digest,
    private_result_oram_bucket_ciphertext_bytes, private_result_oram_bucket_commitment,
    sign_private_hnsw_oram_manifest, sign_private_result_oram_manifest,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

use crate::private_hnsw_oram_store::PrivateHnswOramStore;
use crate::private_oram_owner_journal::{
    PrivateOramOwnerFinalBucketBatchV1, PrivateOramOwnerFinalBucketIndexV1, PrivateOramOwnerJournal,
};
use crate::private_oram_owner_store_adapter::PrivateOramOwnerRecoveryStorePairResourcesV1;
use crate::private_result_oram_store::PrivateResultOramStore;

pub const TEST_COLLECTION_ID: &str = "collection-uuid-1";
pub const TEST_HNSW_INDEX: &str = "text";
pub const TEST_RESULT_INDEX: &str = "private-payload";
pub const TEST_HNSW_KEY: &str = "tenant-a/vector-rk";
pub const TEST_RESULT_KEY: &str = "tenant-a/result-rk";
pub const TEST_OWNER_KEY: &str = "tenant-a/private-oram-owner-v2";

const MAX_CIPHERTEXT_BYTES: usize = 4096;
/// Prepared-index projection returned by the cross-crate recovery fixture.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateOramOwnerPreparedIndexTestEvidenceV1 {
    pub kind: PrivateOramIndexKindV2,
    pub index_name: String,
    pub prepared_journal_digest: String,
}

/// Real signed stores used to exercise the storage-to-collection recovery boundary.
#[doc(hidden)]
pub struct PrivateOramOwnerStorePairTestFixtureV1 {
    public_key: Vec<u8>,
    immutable_manifest: PrivateOramImmutableManifestBundleV2,
    mutation_bundle: PrivateOramAppendMutationBundleV1,
    hnsw_store: PrivateHnswOramStore,
    result_store: PrivateResultOramStore,
    owner_journal: PrivateOramOwnerJournal,
    hnsw_final: Vec<PrivateHnswOramBucket>,
    result_final: Vec<PrivateResultOramBucket>,
}

impl PrivateOramOwnerStorePairTestFixtureV1 {
    pub fn new(collection_path: &Path, non_secret_test_owner_seed: [u8; 32]) -> Self {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&non_secret_test_owner_seed).unwrap();
        let hnsw_store = PrivateHnswOramStore::new(collection_path, TEST_HNSW_INDEX).unwrap();
        let result_store = PrivateResultOramStore::new(collection_path);
        let owner_journal = PrivateOramOwnerJournal::new(hnsw_store.root_path());

        let hnsw_params = PrivateHnswParams {
            m: 1,
            ef_construction: 4,
            max_layers: 2,
            fixed_neighbor_slots: 2,
        };
        let fixed_budget = FixedBudgetParams {
            enabled: true,
            upper_layer_steps: 2,
            base_layer_steps: 4,
            paths_per_round: 2,
            fixed_result_k: 1,
        };
        let mut hnsw_manifest = PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: TEST_COLLECTION_ID.to_string(),
            vector_name: TEST_HNSW_INDEX.to_string(),
            key_id: TEST_HNSW_KEY.to_string(),
            rk_id: TEST_HNSW_KEY.to_string(),
            rk_epoch: 7,
            dim: 2,
            distance: DistanceKind::Cosine,
            hnsw: hnsw_params.clone(),
            oram: oram(),
            fixed_budget: fixed_budget.clone(),
            index_epoch: 11,
            root_hash: digest(1),
            bucket_count: 3,
            logical_node_count: 2,
            dummy_node_count: 3,
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: TEST_OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let hnsw_buckets = (0..3)
            .map(|bucket_id| hnsw_bucket(&hnsw_manifest, bucket_id, 11, 10 + bucket_id as u8))
            .collect::<Vec<_>>();
        hnsw_manifest.root_hash = PrivateHnswOramStore::merkle_root_for_commitments(
            &hnsw_buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let hnsw_signature: PrivateHnswOramSignature =
            sign_private_hnsw_oram_manifest(&key_pair, &hnsw_manifest).unwrap();
        hnsw_store
            .write_initial_upload_bundle_with_signature(
                &PrivateHnswOramUploadBundle {
                    manifest: hnsw_manifest.clone(),
                    manifest_signature: hnsw_signature,
                    buckets: hnsw_buckets,
                },
                MAX_CIPHERTEXT_BYTES,
                PrivateHnswManifestValidationContext {
                    expected_collection_id: TEST_COLLECTION_ID,
                    expected_vector_name: TEST_HNSW_INDEX,
                    expected_key_id: TEST_HNSW_KEY,
                    expected_rk_id: TEST_HNSW_KEY,
                    min_rk_epoch: 7,
                    max_rk_epoch: 7,
                    expected_dim: 2,
                    expected_distance: DistanceKind::Cosine,
                    signature_verification: PrivateHnswSignatureVerification {
                        expected_key_id: TEST_OWNER_KEY,
                        public_key: key_pair.public_key().as_ref(),
                    },
                },
            )
            .unwrap();

        let mut result_manifest = PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: TEST_COLLECTION_ID.to_string(),
            key_id: TEST_RESULT_KEY.to_string(),
            rk_id: TEST_RESULT_KEY.to_string(),
            rk_epoch: 7,
            oram: oram(),
            index_epoch: 11,
            root_hash: digest(2),
            bucket_count: 3,
            logical_result_count: 2,
            dummy_result_count: 3,
            owner_signing_key_id: TEST_OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let result_buckets = (0..3)
            .map(|bucket_id| result_bucket(&result_manifest, bucket_id, 11, 20 + bucket_id as u8))
            .collect::<Vec<_>>();
        result_manifest.root_hash = PrivateResultOramStore::merkle_root_for_commitments(
            &result_buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let result_signature: PrivateResultOramSignature =
            sign_private_result_oram_manifest(&key_pair, &result_manifest).unwrap();
        result_store
            .write_initial_upload_bundle_with_signature(
                &PrivateResultOramUploadBundle {
                    manifest: result_manifest.clone(),
                    manifest_signature: result_signature,
                    buckets: result_buckets,
                },
                MAX_CIPHERTEXT_BYTES,
                PrivateResultOramManifestValidationContext {
                    expected_collection_id: TEST_COLLECTION_ID,
                    expected_key_id: TEST_RESULT_KEY,
                    expected_rk_id: TEST_RESULT_KEY,
                    min_rk_epoch: 7,
                    max_rk_epoch: 7,
                    signature_verification: PrivateResultOramSignatureVerification {
                        expected_key_id: TEST_OWNER_KEY,
                        public_key: key_pair.public_key().as_ref(),
                    },
                },
            )
            .unwrap();

        let immutable_manifest = PrivateOramImmutableManifestV2 {
            version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
            collection_id: TEST_COLLECTION_ID.to_string(),
            manifest_nonce: digest(3),
            indexes: vec![
                PrivateOramImmutableIndexV2 {
                    index_name: TEST_HNSW_INDEX.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Hnsw {
                        provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                        key_id: TEST_HNSW_KEY.to_string(),
                        rk_id: TEST_HNSW_KEY.to_string(),
                        rk_epoch: 7,
                        dim: 2,
                        vector_encoding: PrivateHnswVectorEncoding::F32Le,
                        distance: DistanceKind::Cosine,
                        hnsw: hnsw_params,
                        oram: oram(),
                        fixed_search_budget: fixed_budget,
                        max_neighbor_rewrites: 1,
                    },
                    capacity: capacity(),
                },
                PrivateOramImmutableIndexV2 {
                    index_name: TEST_RESULT_INDEX.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Result {
                        provider: qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
                        key_id: TEST_RESULT_KEY.to_string(),
                        rk_id: TEST_RESULT_KEY.to_string(),
                        rk_epoch: 7,
                        oram: oram(),
                    },
                    capacity: capacity(),
                },
            ],
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: TEST_OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let immutable_manifest =
            package_private_oram_immutable_manifest_v2(&key_pair, immutable_manifest).unwrap();

        let hnsw_final = (0..3)
            .map(|bucket_id| hnsw_bucket(&hnsw_manifest, bucket_id, 12, 30 + bucket_id as u8))
            .collect::<Vec<_>>();
        let result_final = (0..3)
            .map(|bucket_id| result_bucket(&result_manifest, bucket_id, 12, 40 + bucket_id as u8))
            .collect::<Vec<_>>();
        let hnsw_new_root = PrivateHnswOramStore::merkle_root_for_commitments(
            &hnsw_final
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let result_new_root = PrivateResultOramStore::merkle_root_for_commitments(
            &result_final
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let old_indexes = vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: TEST_HNSW_INDEX.to_string(),
                index_epoch: 11,
                root_hash: hnsw_manifest.root_hash.clone(),
                logical_count: 2,
                dummy_count: 3,
                last_writeback_digest: digest(50),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: TEST_RESULT_INDEX.to_string(),
                index_epoch: 11,
                root_hash: result_manifest.root_hash.clone(),
                logical_count: 2,
                dummy_count: 3,
                last_writeback_digest: digest(51),
            },
        ];
        let mut new_indexes = vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: TEST_HNSW_INDEX.to_string(),
                index_epoch: 12,
                root_hash: hnsw_new_root,
                logical_count: 3,
                dummy_count: 2,
                last_writeback_digest: digest(52),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: TEST_RESULT_INDEX.to_string(),
                index_epoch: 12,
                root_hash: result_new_root,
                logical_count: 3,
                dummy_count: 2,
                last_writeback_digest: digest(53),
            },
        ];
        let writebacks = vec![
            PrivateOramAppendIndexWritebackV1 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: TEST_HNSW_INDEX.to_string(),
                read_path_count: 4,
                read_transcript_digest: digest(54),
                updated_buckets: repeated_path_refs(
                    &hnsw_final.iter().map(hnsw_ref).collect::<Vec<_>>(),
                ),
            },
            PrivateOramAppendIndexWritebackV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: TEST_RESULT_INDEX.to_string(),
                read_path_count: 4,
                read_transcript_digest: digest(55),
                updated_buckets: repeated_path_refs(
                    &result_final.iter().map(result_ref).collect::<Vec<_>>(),
                ),
            },
        ];
        for offset in 0..writebacks.len() {
            let old = &old_indexes[offset];
            let new = &new_indexes[offset];
            let writeback = &writebacks[offset];
            new_indexes[offset].last_writeback_digest =
                private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                    collection_id: TEST_COLLECTION_ID,
                    manifest_digest: &manifest_digest,
                    kind: writeback.kind,
                    index_name: &writeback.index_name,
                    old_epoch: old.index_epoch,
                    new_epoch: new.index_epoch,
                    old_root_hash: &old.root_hash,
                    new_root_hash: &new.root_hash,
                    read_path_count: writeback.read_path_count,
                    read_transcript_digest: &writeback.read_transcript_digest,
                    updated_buckets: &writeback.updated_buckets,
                })
                .unwrap();
        }
        let mutation_id = digest(56);
        let old_state = package_private_oram_signed_state_v2(
            &key_pair,
            PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: TEST_COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                layout_digest: digest(57),
                state_sequence: 0,
                indexes: old_indexes,
                client_state_digest: digest(58),
                last_mutation_id: None,
                owner_signing_key_id: TEST_OWNER_KEY.to_string(),
                signed_at_unix: 1_770_000_100,
            },
        )
        .unwrap();
        let new_state = package_private_oram_signed_state_v2(
            &key_pair,
            PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: TEST_COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                layout_digest: digest(57),
                state_sequence: 1,
                indexes: new_indexes,
                client_state_digest: digest(59),
                last_mutation_id: Some(mutation_id.clone()),
                owner_signing_key_id: TEST_OWNER_KEY.to_string(),
                signed_at_unix: 1_770_000_130,
            },
        )
        .unwrap();
        let mutation_bundle = package_private_oram_append_mutation_v1(
            &key_pair,
            PrivateOramAppendMutationV1 {
                version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
                mutation_id: mutation_id.clone(),
                collection_id: TEST_COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                writer_lease_digest: digest(60),
                writer_fence: 1,
                issued_at_unix: 1_770_000_120,
                expires_at_unix: 1_770_000_180,
                old_state,
                new_state,
                point_operation_kind: PrivateOramPointOperationKindV1::NoServerPointRecord,
                point_operation_digest: private_oram_no_server_point_record_v1_digest(
                    TEST_COLLECTION_ID,
                    &manifest_digest,
                    &mutation_id,
                )
                .unwrap(),
                writebacks,
                owner_signing_key_id: TEST_OWNER_KEY.to_string(),
            },
        )
        .unwrap();

        Self {
            public_key: key_pair.public_key().as_ref().to_vec(),
            immutable_manifest,
            mutation_bundle,
            hnsw_store,
            result_store,
            owner_journal,
            hnsw_final,
            result_final,
        }
    }

    pub fn mutation_bundle(&self) -> &PrivateOramAppendMutationBundleV1 {
        &self.mutation_bundle
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn hnsw_store(&self) -> &PrivateHnswOramStore {
        &self.hnsw_store
    }

    pub fn result_store(&self) -> &PrivateResultOramStore {
        &self.result_store
    }

    pub fn owner_journal(&self) -> &PrivateOramOwnerJournal {
        &self.owner_journal
    }

    pub fn prepare_owner(
        &self,
        owner_peer_id: u64,
        parent_descriptor_digest: &str,
        parent_lease_acquired_record_digest: &str,
    ) -> Vec<PrivateOramOwnerPreparedIndexTestEvidenceV1> {
        let (_, token) = self
            .owner_journal
            .prepare_store_adapter_test_fixture_v1(
                &self.mutation_bundle,
                owner_peer_id,
                parent_descriptor_digest,
                parent_lease_acquired_record_digest,
                vec![
                    PrivateOramOwnerFinalBucketIndexV1 {
                        index_name: TEST_HNSW_INDEX.to_string(),
                        buckets: PrivateOramOwnerFinalBucketBatchV1::Hnsw(self.hnsw_final.clone()),
                    },
                    PrivateOramOwnerFinalBucketIndexV1 {
                        index_name: TEST_RESULT_INDEX.to_string(),
                        buckets: PrivateOramOwnerFinalBucketBatchV1::Result(
                            self.result_final.clone(),
                        ),
                    },
                ],
            )
            .unwrap();
        token
            .indexes()
            .iter()
            .map(|index| PrivateOramOwnerPreparedIndexTestEvidenceV1 {
                kind: index.kind(),
                index_name: index.index_name().to_string(),
                prepared_journal_digest: index.prepared_journal_digest().to_string(),
            })
            .collect()
    }

    pub fn install_hnsw_exact_new_for_recovery(&self) {
        let mutation = &self.mutation_bundle.mutation;
        self.hnsw_store
            .apply_owner_exact_new_test_fixture_v1(
                &mutation.old_state.state.indexes[0],
                &mutation.new_state.state.indexes[0],
                &self.hnsw_final,
                3,
                MAX_CIPHERTEXT_BYTES,
            )
            .unwrap();
    }

    pub fn install_result_exact_new_for_recovery(&self) {
        let mutation = &self.mutation_bundle.mutation;
        self.result_store
            .apply_owner_exact_new_test_fixture_v1(
                &mutation.old_state.state.indexes[1],
                &mutation.new_state.state.indexes[1],
                &self.result_final,
                3,
                MAX_CIPHERTEXT_BYTES,
            )
            .unwrap();
    }

    pub fn resources(&self) -> PrivateOramOwnerRecoveryStorePairResourcesV1<'_> {
        PrivateOramOwnerRecoveryStorePairResourcesV1 {
            owner_journal: &self.owner_journal,
            immutable_manifest: &self.immutable_manifest,
            mutation_bundle: &self.mutation_bundle,
            signature_verification: PrivateOramSignatureVerification {
                expected_key_id: TEST_OWNER_KEY,
                public_key: &self.public_key,
            },
            hnsw_store: &self.hnsw_store,
            hnsw_manifest_validation: PrivateHnswManifestValidationContext {
                expected_collection_id: TEST_COLLECTION_ID,
                expected_vector_name: TEST_HNSW_INDEX,
                expected_key_id: TEST_HNSW_KEY,
                expected_rk_id: TEST_HNSW_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 2,
                expected_distance: DistanceKind::Cosine,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: TEST_OWNER_KEY,
                    public_key: &self.public_key,
                },
            },
            hnsw_max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
            result_store: &self.result_store,
            result_manifest_validation: PrivateResultOramManifestValidationContext {
                expected_collection_id: TEST_COLLECTION_ID,
                expected_key_id: TEST_RESULT_KEY,
                expected_rk_id: TEST_RESULT_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                signature_verification: PrivateResultOramSignatureVerification {
                    expected_key_id: TEST_OWNER_KEY,
                    public_key: &self.public_key,
                },
            },
            result_max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
        }
    }
}

fn digest(marker: u8) -> String {
    BASE64URL_NOPAD.encode(&[marker; 32])
}

fn oram() -> OramParams {
    OramParams {
        kind: OramKind::PathOram,
        bucket_size: 2,
        block_size_bytes: 512,
        tree_height: 1,
        path_batch_size: 2,
    }
}

fn capacity() -> PrivateOramIndexCapacityV2 {
    PrivateOramIndexCapacityV2 {
        bucket_count: 3,
        logical_capacity: 5,
        reserved_physical_slots: 1,
        max_client_stash_blocks: 1,
        fixed_append_read_path_count: 4,
        fixed_append_write_bucket_count: 8,
    }
}

fn ciphertext(size: usize, marker: u8) -> (String, String) {
    let mut bytes = vec![marker; size];
    bytes[0] = 1;
    (
        BASE64URL_NOPAD.encode(&bytes),
        BASE64URL_NOPAD.encode(Sha256::digest(&bytes).as_ref()),
    )
}

fn hnsw_bucket(
    manifest: &PrivateHnswOramManifest,
    bucket_id: u64,
    epoch: u64,
    marker: u8,
) -> PrivateHnswOramBucket {
    let (ciphertext, ciphertext_sha256) = ciphertext(
        private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
        marker,
    );
    let bucket_commitment = private_hnsw_bucket_commitment(
        PrivateHnswBucketAeadContext {
            collection_id: &manifest.collection_id,
            vector_name: &manifest.vector_name,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            bucket_id,
            index_epoch: epoch,
        },
        &ciphertext_sha256,
    )
    .unwrap();
    PrivateHnswOramBucket {
        version: 1,
        bucket_id,
        index_epoch: epoch,
        ciphertext,
        ciphertext_sha256,
        bucket_commitment,
    }
}

fn result_bucket(
    manifest: &PrivateResultOramManifest,
    bucket_id: u64,
    epoch: u64,
    marker: u8,
) -> PrivateResultOramBucket {
    let (ciphertext, ciphertext_sha256) = ciphertext(
        private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
        marker,
    );
    let bucket_commitment = private_result_oram_bucket_commitment(
        PrivateResultOramBucketCommitmentContext {
            collection_id: &manifest.collection_id,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            bucket_id,
            index_epoch: epoch,
        },
        &ciphertext_sha256,
    )
    .unwrap();
    PrivateResultOramBucket {
        version: 1,
        bucket_id,
        index_epoch: epoch,
        ciphertext,
        ciphertext_sha256,
        bucket_commitment,
    }
}

fn hnsw_ref(bucket: &PrivateHnswOramBucket) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id: bucket.bucket_id,
        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        bucket_commitment: bucket.bucket_commitment.clone(),
    }
}

fn result_ref(bucket: &PrivateResultOramBucket) -> PrivateOramAppendBucketRefV1 {
    PrivateOramAppendBucketRefV1 {
        bucket_id: bucket.bucket_id,
        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        bucket_commitment: bucket.bucket_commitment.clone(),
    }
}

fn repeated_path_refs(
    final_refs: &[PrivateOramAppendBucketRefV1],
) -> Vec<PrivateOramAppendBucketRefV1> {
    [0, 1, 0, 2, 0, 1, 0, 2]
        .into_iter()
        .map(|index| final_refs[index].clone())
        .collect()
}
