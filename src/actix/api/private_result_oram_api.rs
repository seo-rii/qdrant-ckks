use actix_web::{HttpResponse, post, web};
use actix_web_validator::{Json, Path};
use collection::operations::verification::new_unchecked_verification_pass;
use serde::{Deserialize, Serialize};
use storage::dispatcher::Dispatcher;
use tokio::time::Instant;
use validator::Validate;

use super::CollectionPath;
use crate::actix::auth::ActixAuth;
use crate::actix::helpers::process_response;
use crate::common::private_result_oram::{
    do_get_private_result_oram_manifest, do_read_private_result_oram_buckets,
    do_upload_private_result_oram_buckets, do_upload_private_result_oram_manifest,
};
use crate::settings::Settings;

#[derive(Deserialize, Validate)]
struct PrivateResultOramPath {
    #[validate(nested)]
    #[serde(flatten)]
    collection: CollectionPath,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct UploadPrivateResultOramManifestRequest {
    pub manifest: qdrant_sec::PrivateResultOramManifest,
    pub signature: qdrant_sec::PrivateResultOramSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct UploadPrivateResultOramBucketsRequest {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct ReadPrivateResultOramBucketsRequest {
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_ids: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateResultOramReadBucketsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
    pub proof: PrivateResultOramReadProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateResultOramReadProof {
    pub kind: String,
    pub value: String,
}

#[post("/collections/{collection_name}/private-result-oram/manifest")]
async fn upload_manifest(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<UploadPrivateResultOramManifestRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_upload_private_result_oram_manifest(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        request.manifest,
        request.signature,
    )
    .await;
    process_response(result, timing, None)
}

#[actix_web::get("/collections/{collection_name}/private-result-oram/manifest")]
async fn get_manifest(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let timing = Instant::now();
    let result = do_get_private_result_oram_manifest(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-result-oram/buckets")]
async fn upload_buckets(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<UploadPrivateResultOramBucketsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_upload_private_result_oram_buckets(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        request.index_epoch,
        request.root_hash,
        request.buckets,
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-result-oram/oram/read_buckets")]
async fn read_buckets(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<ReadPrivateResultOramBucketsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_read_private_result_oram_buckets(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        request.index_epoch,
        request.root_hash,
        request.bucket_ids,
    )
    .await;
    process_response(result, timing, None)
}

pub fn config_private_result_oram_api(cfg: &mut web::ServiceConfig) {
    cfg.service(upload_manifest)
        .service(get_manifest)
        .service(upload_buckets)
        .service(read_buckets);
}

#[cfg(test)]
mod private_result_oram_rest_tests {
    use std::collections::{BTreeMap, HashMap};
    use std::fmt::Debug;

    use actix_web::http::StatusCode;
    use actix_web::{App, test as actix_test, web};
    use collection::config::{
        CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector,
    };
    use collection::operations::types::VectorsConfig;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING,
        PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PrivateResultOramBucket,
        PrivateResultOramBucketCommitmentContext, PrivateResultOramManifest,
        private_result_oram_bucket_commitment, private_result_oram_merkle_root_for_commitments,
        sign_private_result_oram_manifest,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use storage::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreateCollection, CreateCollectionOperation,
    };
    use storage::dispatcher::Dispatcher;
    use storage::rbac::{Access, Auth};
    use uuid::Uuid;

    use super::*;
    use crate::common::private_hnsw_wire_fixture::{route_e2e_guard, test_dispatcher};
    use crate::settings::{CryptoInstanceConfig, CryptoSettings};

    const COLLECTION_NAME: &str = "docs";
    const COLLECTION_ID: &str = "12345678-90ab-cdef-1234-567890abcdef";
    const KEY_ID: &str = "tenant-a/result-private-rk";
    const RK_EPOCH: u64 = 7;
    const SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v1";
    const BASE_EPOCH: u64 = 42;

    struct PrivateResultRouteFixture {
        manifest: PrivateResultOramManifest,
        signature: qdrant_sec::PrivateResultOramSignature,
        buckets: Vec<PrivateResultOramBucket>,
        signing_key: Ed25519KeyPair,
    }

    impl PrivateResultRouteFixture {
        fn build() -> Self {
            let signing_key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
            let oram = OramParams {
                kind: OramKind::PathOram,
                bucket_size: 2,
                block_size_bytes: 1024,
                tree_height: 2,
                path_batch_size: 2,
            };
            let bucket_count = (1_u64 << (oram.tree_height + 1)) - 1;
            let mut manifest = PrivateResultOramManifest {
                version: 1,
                provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
                collection_id: COLLECTION_ID.to_string(),
                key_id: KEY_ID.to_string(),
                rk_id: KEY_ID.to_string(),
                rk_epoch: RK_EPOCH,
                oram: oram.clone(),
                index_epoch: BASE_EPOCH,
                root_hash: BASE64URL_NOPAD.encode(&[0; 32]),
                bucket_count,
                logical_result_count: 3,
                dummy_result_count: 1,
                owner_signing_key_id: SIGNING_KEY_ID.to_string(),
                created_at_unix: 1_770_000_000,
            };
            let buckets = (0..bucket_count)
                .map(|bucket_id| fixture_bucket(bucket_id, &manifest))
                .collect::<Vec<_>>();
            let commitments = buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>();
            manifest.root_hash =
                private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
            let buckets = (0..bucket_count)
                .map(|bucket_id| fixture_bucket(bucket_id, &manifest))
                .collect::<Vec<_>>();
            let signature = sign_private_result_oram_manifest(&signing_key, &manifest).unwrap();
            Self {
                manifest,
                signature,
                buckets,
                signing_key,
            }
        }

        fn settings(&self) -> Settings {
            let mut settings = Settings::new(None).unwrap();
            settings.crypto = CryptoSettings {
                zero_trust_profile: Some(crate::settings::ZERO_TRUST_PROFILE_STRICT.to_string()),
                instances: HashMap::from([(
                    "payload_result_oram_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({
                            "key_id": KEY_ID,
                            "expected_rk_id": KEY_ID,
                            "min_rk_epoch": RK_EPOCH,
                            "max_rk_epoch": RK_EPOCH,
                            "oram": {
                                "kind": "path_oram",
                                "bucket_size": self.manifest.oram.bucket_size,
                                "block_size_bytes": self.manifest.oram.block_size_bytes,
                                "tree_height": self.manifest.oram.tree_height,
                                "path_batch_size": self.manifest.oram.path_batch_size
                            },
                            "integrity": {
                                "manifest_signature_required": true,
                                "commit_signature_required": true,
                                "merkle_root_required": true
                            },
                            "signature_public_keys": {
                                SIGNING_KEY_ID: BASE64URL_NOPAD.encode(self.signing_key.public_key().as_ref())
                            }
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            };
            settings
        }
    }

    fn fixture_bucket(
        bucket_id: u64,
        manifest: &PrivateResultOramManifest,
    ) -> PrivateResultOramBucket {
        let ciphertext_bytes = [bucket_id as u8; 16];
        let ciphertext = BASE64URL_NOPAD.encode(&ciphertext_bytes);
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(ciphertext_bytes));
        let bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id,
                index_epoch: manifest.index_epoch,
            },
            &ciphertext_sha256,
        )
        .unwrap();
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: manifest.index_epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment,
        }
    }

    fn json_roundtrip<T>(value: &T) -> T
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        serde_json::from_value(serde_json::to_value(value).unwrap()).unwrap()
    }

    async fn create_private_result_collection(dispatcher: &Dispatcher) {
        dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::CreateCollection(
                    CreateCollectionOperation::new(
                        COLLECTION_NAME.to_string(),
                        CreateCollection {
                            vectors: VectorsConfig::Multi(BTreeMap::from([(
                                "text".to_string(),
                                VectorParamsBuilder::new(2, segment::types::Distance::Euclid)
                                    .build(),
                            )])),
                            sparse_vectors: None,
                            hnsw_config: None,
                            wal_config: None,
                            optimizers_config: None,
                            shard_number: Some(1),
                            on_disk_payload: None,
                            replication_factor: None,
                            write_consistency_factor: None,
                            quantization_config: None,
                            sharding_method: None,
                            encryption: Some(CollectionEncryptionConfig {
                                version: 1,
                                key_id: Some(KEY_ID.to_string()),
                                crypto_schema_version: 1,
                                encryption_epoch: RK_EPOCH,
                                migration_state: CryptoMigrationState::Active,
                                rules: vec![EncryptionRuleRef {
                                    id: "body_private_result".to_string(),
                                    selector: EncryptionSelector::PayloadPaths {
                                        paths: vec!["body".to_string()],
                                    },
                                    instance: "payload_result_oram_v1".to_string(),
                                    binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                                }],
                            }),
                            strict_mode_config: None,
                            uuid: Some(Uuid::parse_str(COLLECTION_ID).unwrap()),
                            metadata: None,
                        },
                    )
                    .unwrap(),
                ),
                Auth::new_internal(Access::full("private result ORAM route test")),
                None,
            )
            .await
            .unwrap();
    }

    #[test]
    fn private_result_oram_rest_dtos_roundtrip() {
        let fixture = PrivateResultRouteFixture::build();
        let manifest_request = UploadPrivateResultOramManifestRequest {
            manifest: fixture.manifest.clone(),
            signature: fixture.signature.clone(),
        };
        assert_eq!(json_roundtrip(&manifest_request), manifest_request);

        let buckets_request = UploadPrivateResultOramBucketsRequest {
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            buckets: fixture.buckets.clone(),
        };
        assert_eq!(json_roundtrip(&buckets_request), buckets_request);

        let read_request = ReadPrivateResultOramBucketsRequest {
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            bucket_ids: vec![0, 1],
        };
        assert_eq!(json_roundtrip(&read_request), read_request);
    }

    #[test]
    fn private_result_oram_uploads_and_reads_through_rest_routes() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;

            macro_rules! post_json_ok {
                ($uri:expr, $body:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service(&app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|err| {
                        panic!(
                            "failed to parse response body for {status}: {err}: {}",
                            String::from_utf8_lossy(&body_bytes)
                        )
                    });
                    assert_eq!(status, StatusCode::OK, "{body}");
                    assert_eq!(body["status"], "ok");
                    body["result"].clone()
                }};
            }
            macro_rules! post_json_error_contains {
                ($uri:expr, $body:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service(&app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }
            macro_rules! get_json_ok {
                ($uri:expr) => {{
                    let request = actix_test::TestRequest::get().uri($uri).to_request();
                    let response = actix_test::call_service(&app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|err| {
                        panic!(
                            "failed to parse response body for {status}: {err}: {}",
                            String::from_utf8_lossy(&body_bytes)
                        )
                    });
                    assert_eq!(status, StatusCode::OK, "{body}");
                    assert_eq!(body["status"], "ok");
                    body["result"].clone()
                }};
            }
            macro_rules! get_json_error_contains {
                ($uri:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::get().uri($uri).to_request();
                    let response = actix_test::call_service(&app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }

            let missing_manifest = get_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(!missing_manifest.contains("private_result_oram"));

            let missing_manifest_upload = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(!missing_manifest_upload.contains("private_result_oram"));

            let manifest_result = post_json_ok!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                }
            );
            assert_eq!(manifest_result["index_epoch"], fixture.manifest.index_epoch);
            assert_eq!(manifest_result["root_hash"], fixture.manifest.root_hash);

            let manifest_read = get_json_ok!("/collections/docs/private-result-oram/manifest");
            assert_eq!(
                manifest_read["manifest"]["root_hash"],
                fixture.manifest.root_hash
            );
            assert_eq!(manifest_read["signature"]["key_id"], SIGNING_KEY_ID);

            let buckets_result = post_json_ok!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                }
            );
            assert_eq!(buckets_result["index_epoch"], fixture.manifest.index_epoch);

            let read_result = post_json_ok!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: vec![0, 1],
                }
            );
            assert_eq!(
                read_result["proof"]["kind"],
                PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND
            );
            assert_eq!(read_result["buckets"].as_array().unwrap().len(), 2);
            assert_eq!(read_result["buckets"][0]["bucket_id"], 0);

            let duplicate_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: vec![0, 0],
                },
                StatusCode::BAD_REQUEST,
                "duplicate"
            );
            assert!(!duplicate_error.contains(&fixture.buckets[0].ciphertext));
        });
    }
}
