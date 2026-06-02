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
use crate::common::private_hnsw::{
    PrivateHnswClientSignature as CommonPrivateHnswClientSignature,
    PrivateHnswReadPadding as CommonPrivateHnswReadPadding, do_close_private_hnsw_session,
    do_commit_private_hnsw_paths, do_get_private_hnsw_manifest, do_open_private_hnsw_session,
    do_read_private_hnsw_paths, do_upload_private_hnsw_buckets, do_upload_private_hnsw_manifest,
};
use crate::settings::Settings;

#[derive(Deserialize, Validate)]
struct PrivateHnswPath {
    #[validate(nested)]
    #[serde(flatten)]
    collection: CollectionPath,
    #[validate(length(min = 1, max = 128))]
    vector_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct PrivateHnswClientSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct UploadPrivateHnswManifestRequest {
    pub manifest: qdrant_sec::PrivateHnswOramManifest,
    pub signature: qdrant_sec::PrivateHnswOramSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct UploadPrivateHnswBucketsRequest {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateHnswOramBucket>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct OpenPrivateHnswSessionRequest {
    pub client_id: String,
    pub desired_epoch: u64,
    pub fixed_budget: bool,
    pub result_privacy: qdrant_sec::ResultPrivacyMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateHnswSessionResponse {
    pub session_id: String,
    pub collection_id: String,
    pub vector_name: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub manifest: qdrant_sec::PrivateHnswOramManifest,
    pub lease_expires_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct OramReadPathsRequest {
    pub session_id: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub paths: Vec<String>,
    pub padding: OramReadPadding,
    pub client_signature: PrivateHnswClientSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct OramReadPadding {
    pub requested_paths: u32,
    pub dummy_paths_included: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct OramReadPathsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateHnswOramBucket>,
    pub proof: OramReadProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct OramReadProof {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct OramCommitRequest {
    pub session_id: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub updated_buckets: Vec<qdrant_sec::PrivateHnswOramBucket>,
    pub commit_signature: PrivateHnswClientSignature,
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/manifest")]
async fn upload_manifest(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<UploadPrivateHnswManifestRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_upload_private_hnsw_manifest(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        &path.vector_name,
        request.manifest,
        request.signature,
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/buckets")]
async fn upload_buckets(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<UploadPrivateHnswBucketsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_upload_private_hnsw_buckets(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        &path.vector_name,
        request.index_epoch,
        request.root_hash,
        request.buckets,
    )
    .await;
    process_response(result, timing, None)
}

#[actix_web::get("/collections/{collection_name}/private-hnsw/{vector_name}/manifest")]
async fn get_manifest(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let timing = Instant::now();
    let result = do_get_private_hnsw_manifest(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        &path.vector_name,
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/session")]
async fn open_session(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<OpenPrivateHnswSessionRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_open_private_hnsw_session(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        &path.vector_name,
        request.client_id,
        request.desired_epoch,
        request.fixed_budget,
        request.result_privacy,
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/oram/read_paths")]
async fn read_paths(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<OramReadPathsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_read_private_hnsw_paths(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        &path.vector_name,
        &request.session_id,
        request.index_epoch,
        &request.root_hash,
        request.paths,
        CommonPrivateHnswReadPadding {
            requested_paths: request.padding.requested_paths,
            dummy_paths_included: request.padding.dummy_paths_included,
        },
        request.client_signature.into(),
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/oram/commit")]
async fn commit_paths(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswPath>,
    request: Json<OramCommitRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_commit_private_hnsw_paths(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        &path.vector_name,
        &request.session_id,
        request.old_epoch,
        request.new_epoch,
        request.old_root_hash,
        request.new_root_hash,
        request.updated_buckets,
        request.commit_signature.into(),
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-hnsw/{vector_name}/session/{session_id}/close")]
async fn close_session(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateHnswClosePath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let timing = Instant::now();
    let result = do_close_private_hnsw_session(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.private_hnsw.collection.collection_name,
        &path.private_hnsw.vector_name,
        &path.session_id,
    )
    .await;
    process_response(result, timing, None)
}

#[derive(Deserialize, Validate)]
struct PrivateHnswClosePath {
    #[validate(nested)]
    #[serde(flatten)]
    private_hnsw: PrivateHnswPath,
    #[validate(length(min = 1, max = 256))]
    session_id: String,
}

impl From<PrivateHnswClientSignature> for CommonPrivateHnswClientSignature {
    fn from(signature: PrivateHnswClientSignature) -> Self {
        Self {
            alg: signature.alg,
            key_id: signature.key_id,
            sig: signature.sig,
        }
    }
}

pub fn config_private_hnsw_api(cfg: &mut web::ServiceConfig) {
    cfg.service(upload_manifest)
        .service(upload_buckets)
        .service(get_manifest)
        .service(open_session)
        .service(read_paths)
        .service(commit_paths)
        .service(close_session);
}

#[cfg(test)]
mod private_hnsw_rest_tests {
    use std::fmt::Debug;

    use actix_web::http::StatusCode;
    use actix_web::{App, test as actix_test, web};
    use serde::de::DeserializeOwned;
    use serde_json::Value;

    use super::*;
    use crate::common::private_hnsw_wire_fixture::{
        BASE_EPOCH, COLLECTION_ID, NEXT_EPOCH, PrivateHnswRouteWireFixture, SESSION_ID,
        SIGNING_KEY_ID, create_private_hnsw_collection, route_e2e_guard, test_dispatcher,
    };

    fn json_roundtrip<T>(value: &T) -> T
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        serde_json::from_value(serde_json::to_value(value).unwrap()).unwrap()
    }

    #[test]
    fn sdk_fixture_roundtrips_through_rest_wire_dtos() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let manifest_request = UploadPrivateHnswManifestRequest {
            manifest: fixture.manifest.clone(),
            signature: fixture.manifest_signature.clone(),
        };
        assert_eq!(json_roundtrip(&manifest_request), manifest_request);

        let buckets_request = UploadPrivateHnswBucketsRequest {
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            buckets: fixture.encrypted_build.buckets.clone(),
        };
        assert_eq!(json_roundtrip(&buckets_request), buckets_request);

        let session_request = OpenPrivateHnswSessionRequest {
            client_id: "tenant-a/sdk-instance-1".to_string(),
            desired_epoch: BASE_EPOCH,
            fixed_budget: true,
            result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
        };
        assert_eq!(json_roundtrip(&session_request), session_request);

        let (_bucket_ids, batch) = fixture.read_batch_for_leaf(0);
        let read_request = OramReadPathsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            paths: vec![fixture.entry_leaf_label()],
            padding: OramReadPadding {
                requested_paths: 1,
                dummy_paths_included: true,
            },
            client_signature: PrivateHnswClientSignature {
                alg: "ed25519".to_string(),
                key_id: SIGNING_KEY_ID.to_string(),
                sig: fixture.client_signature().sig,
            },
        };
        assert_eq!(json_roundtrip(&read_request), read_request);

        let read_response = OramReadPathsResponse {
            index_epoch: batch.index_epoch,
            root_hash: batch.root_hash,
            buckets: batch.buckets,
            proof: OramReadProof {
                kind: fixture.proof_kind(),
                value: batch.proof_value,
            },
        };
        assert_eq!(json_roundtrip(&read_response), read_response);

        let search_run = fixture.run_single_search_collect_writeback();
        assert_eq!(search_run.result.hits[0].node_id, [1; 32]);
        let commit_request = OramCommitRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: search_run.commit_plan.old_root_hash,
            new_root_hash: search_run.commit_plan.new_root_hash,
            updated_buckets: search_run.updated_buckets,
            commit_signature: PrivateHnswClientSignature {
                alg: search_run.commit_signature.alg,
                key_id: search_run.commit_signature.key_id,
                sig: search_run.commit_signature.sig,
            },
        };
        assert_eq!(json_roundtrip(&commit_request), commit_request);
    }

    #[test]
    fn sdk_fixture_uploads_reads_and_commits_through_rest_routes() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(settings.clone()))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_hnsw_api),
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

            let missing_manifest_read_error = get_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(
                !missing_manifest_read_error.contains("private_hnsw_oram"),
                "{missing_manifest_read_error}"
            );
            assert!(
                !missing_manifest_read_error.contains("/tmp"),
                "{missing_manifest_read_error}"
            );

            let missing_manifest_bucket_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                },
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(
                !missing_manifest_bucket_error.contains("private_hnsw_oram"),
                "{missing_manifest_bucket_error}"
            );
            assert!(
                !missing_manifest_bucket_error.contains("/tmp"),
                "{missing_manifest_bucket_error}"
            );

            let missing_manifest_session_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-before-manifest".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::NOT_FOUND,
                "manifest"
            );
            assert!(
                !missing_manifest_session_error.contains("private_hnsw_oram"),
                "{missing_manifest_session_error}"
            );
            assert!(
                !missing_manifest_session_error.contains("/tmp"),
                "{missing_manifest_session_error}"
            );

            let mut mismatched_collection_manifest = fixture.manifest.clone();
            mismatched_collection_manifest.collection_id = "other-collection".to_string();
            let mismatched_collection_signature =
                fixture.sign_manifest(&mismatched_collection_manifest);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_collection_manifest,
                    signature: mismatched_collection_signature,
                },
                StatusCode::BAD_REQUEST,
                "collection_id"
            );

            let mut mismatched_vector_manifest = fixture.manifest.clone();
            mismatched_vector_manifest.vector_name = "title".to_string();
            let mismatched_vector_signature = fixture.sign_manifest(&mismatched_vector_manifest);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_vector_manifest,
                    signature: mismatched_vector_signature,
                },
                StatusCode::BAD_REQUEST,
                "vector_name"
            );

            let mut mismatched_key_manifest = fixture.manifest.clone();
            mismatched_key_manifest.key_id = "tenant-b/vector-private-rk".to_string();
            let mismatched_key_signature = fixture.sign_manifest(&mismatched_key_manifest);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_key_manifest,
                    signature: mismatched_key_signature,
                },
                StatusCode::BAD_REQUEST,
                "key_id"
            );

            let mut mismatched_epoch_manifest = fixture.manifest.clone();
            mismatched_epoch_manifest.rk_epoch += 1;
            let mismatched_epoch_signature = fixture.sign_manifest(&mismatched_epoch_manifest);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_epoch_manifest,
                    signature: mismatched_epoch_signature,
                },
                StatusCode::BAD_REQUEST,
                "rk_epoch"
            );

            let mut mismatched_dim_manifest = fixture.manifest.clone();
            mismatched_dim_manifest.dim += 1;
            let mismatched_dim_signature = fixture.sign_manifest(&mismatched_dim_manifest);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_dim_manifest,
                    signature: mismatched_dim_signature,
                },
                StatusCode::BAD_REQUEST,
                "dim"
            );

            let mut mismatched_distance_manifest = fixture.manifest.clone();
            mismatched_distance_manifest.distance = qdrant_sec::DistanceKind::Cosine;
            let mismatched_distance_signature =
                fixture.sign_manifest(&mismatched_distance_manifest);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_distance_manifest,
                    signature: mismatched_distance_signature,
                },
                StatusCode::BAD_REQUEST,
                "distance"
            );

            let mut mismatched_bucket_count_manifest = fixture.manifest.clone();
            mismatched_bucket_count_manifest.bucket_count -= 1;
            let mismatched_bucket_count_signature =
                fixture.sign_manifest(&mismatched_bucket_count_manifest);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_bucket_count_manifest,
                    signature: mismatched_bucket_count_signature,
                },
                StatusCode::BAD_REQUEST,
                "bucket_count"
            );

            let mut mismatched_privacy_manifest = fixture.manifest.clone();
            mismatched_privacy_manifest.result_privacy =
                qdrant_sec::ResultPrivacyMode::PrivatePayloadOramRequired;
            let mismatched_privacy_signature = fixture.sign_manifest(&mismatched_privacy_manifest);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: mismatched_privacy_manifest,
                    signature: mismatched_privacy_signature,
                },
                StatusCode::BAD_REQUEST,
                "manifest result_privacy does not match runtime instance"
            );

            let mut bad_manifest_signature = fixture.manifest_signature.clone();
            let replacement = if bad_manifest_signature.sig.starts_with('A') {
                "B"
            } else {
                "A"
            };
            bad_manifest_signature.sig.replace_range(0..1, replacement);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: bad_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "manifest signature verification failed"
            );

            let manifest_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.manifest_signature.clone(),
                }
            );
            assert_eq!(manifest_result["index_epoch"], BASE_EPOCH);
            assert_eq!(
                manifest_result["root_hash"].as_str().unwrap(),
                fixture.encrypted_build.root_hash.as_str(),
            );
            let manifest_read = get_json_ok!("/collections/docs/private-hnsw/text/manifest");
            assert_eq!(
                manifest_read["manifest"]["root_hash"].as_str().unwrap(),
                fixture.encrypted_build.root_hash.as_str(),
            );
            assert_eq!(
                manifest_read["signature"]["sig"].as_str().unwrap(),
                fixture.manifest_signature.sig.as_str(),
            );

            let bucket_upload_root_sentinel = "bucket-upload-root-sentinel";
            let bucket_upload_epoch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: bucket_upload_root_sentinel.to_string(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "bucket upload epoch/root does not match current manifest epoch"
            );
            assert!(
                !bucket_upload_epoch_error.contains(bucket_upload_root_sentinel),
                "{bucket_upload_epoch_error}"
            );

            let mut hash_mismatch_buckets = fixture.encrypted_build.buckets.clone();
            let replacement = if hash_mismatch_buckets[0].ciphertext_sha256.starts_with('A') {
                "B"
            } else {
                "A"
            };
            hash_mismatch_buckets[0]
                .ciphertext_sha256
                .replace_range(0..1, replacement);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: hash_mismatch_buckets,
                },
                StatusCode::BAD_REQUEST,
                "ciphertext_sha256 mismatch"
            );

            let upload_ciphertext_sentinel = "bucket-upload-ciphertext-sentinel";
            let mut malformed_upload_buckets = fixture.encrypted_build.buckets.clone();
            malformed_upload_buckets[0].ciphertext = upload_ciphertext_sentinel.to_string();
            let malformed_upload_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: malformed_upload_buckets,
                },
                StatusCode::BAD_REQUEST,
                "ciphertext"
            );
            assert!(
                !malformed_upload_error.contains(upload_ciphertext_sentinel),
                "{malformed_upload_error}"
            );

            let mut missing_bucket_set = fixture.encrypted_build.buckets.clone();
            missing_bucket_set.pop();
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: missing_bucket_set,
                },
                StatusCode::BAD_REQUEST,
                "exactly"
            );

            let mut duplicate_bucket_set = fixture.encrypted_build.buckets.clone();
            assert!(
                duplicate_bucket_set.len() >= 2,
                "route fixture must contain at least two ORAM buckets"
            );
            duplicate_bucket_set[1] = duplicate_bucket_set[0].clone();
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: duplicate_bucket_set,
                },
                StatusCode::BAD_REQUEST,
                "duplicated"
            );

            let bucket_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                }
            );
            assert_eq!(bucket_result["index_epoch"], BASE_EPOCH);

            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-fixed-budget-off".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: false,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "strict mode requires fixed_budget=true"
            );
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-stale-epoch".to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "requested epoch"
            );
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-private-result".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::PrivatePayloadOramRequired,
                },
                StatusCode::BAD_REQUEST,
                "requested result_privacy does not match manifest"
            );

            let session_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                }
            );
            let session_id = session_result["session_id"].as_str().unwrap().to_string();
            assert_eq!(session_result["collection_id"], COLLECTION_ID);
            assert_eq!(session_result["index_epoch"], BASE_EPOCH);

            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-2".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "ConcurrentWriter"
            );

            let epoch_root_mismatch_paths = vec![fixture.entry_leaf_label()];
            let epoch_root_mismatch_signature =
                fixture.sign_read_paths(&epoch_root_mismatch_paths, 1, true);
            let read_root_sentinel = "read-root-sentinel";
            let epoch_root_mismatch_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: read_root_sentinel.to_string(),
                    paths: epoch_root_mismatch_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: epoch_root_mismatch_signature.alg,
                        key_id: epoch_root_mismatch_signature.key_id,
                        sig: epoch_root_mismatch_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "session epoch/root mismatch"
            );
            assert!(
                !epoch_root_mismatch_error.contains(read_root_sentinel),
                "{epoch_root_mismatch_error}"
            );

            let path_label_sentinel = "qdrant-sec-private-hnsw-path-label-sentinel";
            let sentinel_paths = vec![path_label_sentinel.to_string()];
            let sentinel_signature = fixture.sign_read_paths(&sentinel_paths, 1, true);
            let read_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: sentinel_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: sentinel_signature.alg,
                        key_id: sentinel_signature.key_id,
                        sig: sentinel_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "leaf label"
            );
            assert!(!read_error.contains(path_label_sentinel), "{read_error}");
            assert!(
                !read_error.contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{read_error}"
            );
            let wrong_budget_paths = vec![fixture.entry_leaf_label()];
            let wrong_budget_signature = fixture.sign_read_paths(&wrong_budget_paths, 2, true);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: wrong_budget_paths,
                    padding: OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: wrong_budget_signature.alg,
                        key_id: wrong_budget_signature.key_id,
                        sig: wrong_budget_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "fixed path budget"
            );

            let missing_dummy_paths = vec![fixture.entry_leaf_label()];
            let missing_dummy_signature = fixture.sign_read_paths(&missing_dummy_paths, 1, false);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: missing_dummy_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: false,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: missing_dummy_signature.alg,
                        key_id: missing_dummy_signature.key_id,
                        sig: missing_dummy_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "fixed path budget"
            );

            let invalid_signature_paths = vec![fixture.entry_leaf_label()];
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: invalid_signature_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.client_signature().sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "read_paths signature verification failed"
            );

            let ok_read_paths = vec![fixture.entry_leaf_label()];
            let read_signature = fixture.sign_read_paths(&ok_read_paths, 1, true);
            let read_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: ok_read_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: read_signature.alg,
                        key_id: read_signature.key_id,
                        sig: read_signature.sig,
                    },
                }
            );
            let read_response: OramReadPathsResponse = serde_json::from_value(read_result).unwrap();
            assert_eq!(read_response.index_epoch, BASE_EPOCH);
            assert_eq!(read_response.proof.kind, fixture.proof_kind());
            let opened_buckets = qdrant_sec::open_private_hnsw_oram_verified_path_batch(
                &fixture.keys,
                fixture.base_context,
                fixture.config,
                BASE_EPOCH,
                &fixture.encrypted_build.root_hash,
                fixture.encrypted_build.bucket_count,
                &read_response.proof.value,
                &read_response.buckets,
            )
            .unwrap();
            assert!(!opened_buckets.is_empty());

            let search_run = fixture.run_single_search_collect_writeback();
            let commit_old_root_sentinel = "commit-old-root-sentinel";
            let commit_old_root_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_old_root_sentinel.to_string(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.client_signature().sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "commit old epoch/root does not match active session"
            );
            assert!(
                !commit_old_root_error.contains(commit_old_root_sentinel),
                "{commit_old_root_error}"
            );

            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: BASE_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.client_signature().sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "new_epoch must be greater than old_epoch"
            );
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.client_signature().sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "commit signature verification failed"
            );

            let commit_ciphertext_sentinel = "commit-error-ciphertext-sentinel";
            let mut malformed_commit_buckets = search_run.updated_buckets.clone();
            malformed_commit_buckets[0].ciphertext = commit_ciphertext_sentinel.to_string();
            let malformed_commit_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: malformed_commit_buckets,
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "ciphertext"
            );
            assert!(
                !malformed_commit_error.contains(commit_ciphertext_sentinel),
                "{malformed_commit_error}"
            );

            let commit_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                }
            );
            assert_eq!(commit_result["index_epoch"], NEXT_EPOCH);
            let (refreshed_manifest, refreshed_signature) =
                fixture.sign_manifest_refresh(&search_run.commit_plan);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "old epoch/root does not match active session"
            );

            let close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{session_id}/close"
                ))
                .to_request();
            let close_response = actix_test::call_service(&app, close_request).await;
            assert_eq!(close_response.status(), StatusCode::OK);
            let close_body: Value = actix_test::read_body_json(close_response).await;
            assert_eq!(close_body["result"], true);

            let missing_close_session_id = "close-session-id-sentinel";
            let missing_close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{missing_close_session_id}/close"
                ))
                .to_request();
            let missing_close_response =
                actix_test::call_service(&app, missing_close_request).await;
            assert_eq!(missing_close_response.status(), StatusCode::BAD_REQUEST);
            let missing_close_body = actix_test::read_body(missing_close_response).await;
            let missing_close_body = String::from_utf8_lossy(&missing_close_body);
            assert!(missing_close_body.contains("session is missing or already closed"));
            assert!(
                !missing_close_body.contains(missing_close_session_id),
                "{missing_close_body}"
            );

            let closed_read_paths = vec![fixture.entry_leaf_label()];
            let closed_read_signature = fixture.sign_read_paths(&closed_read_paths, 1, true);
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: closed_read_paths,
                    padding: OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: closed_read_signature.alg,
                        key_id: closed_read_signature.key_id,
                        sig: closed_read_signature.sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );

            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run.updated_buckets.clone(),
                    commit_signature: PrivateHnswClientSignature {
                        alg: search_run.commit_signature.alg.clone(),
                        key_id: search_run.commit_signature.key_id.clone(),
                        sig: search_run.commit_signature.sig.clone(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );

            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-2".to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                },
                StatusCode::BAD_REQUEST,
                "manifest epoch/root does not match current epoch"
            );

            let refreshed_epoch = post_json_ok!(
                "/collections/docs/private-hnsw/text/manifest",
                UploadPrivateHnswManifestRequest {
                    manifest: refreshed_manifest,
                    signature: refreshed_signature,
                }
            );
            assert_eq!(refreshed_epoch["index_epoch"], NEXT_EPOCH);

            let reopened_session = post_json_ok!(
                "/collections/docs/private-hnsw/text/session",
                OpenPrivateHnswSessionRequest {
                    client_id: "tenant-a/sdk-instance-2".to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                    result_privacy: qdrant_sec::ResultPrivacyMode::IdsVisible,
                }
            );
            assert_eq!(reopened_session["index_epoch"], NEXT_EPOCH);
            let reopened_session_id = reopened_session["session_id"].as_str().unwrap();
            let close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-hnsw/text/session/{reopened_session_id}/close"
                ))
                .to_request();
            let close_response = actix_test::call_service(&app, close_request).await;
            assert_eq!(close_response.status(), StatusCode::OK);
        });
    }
}
