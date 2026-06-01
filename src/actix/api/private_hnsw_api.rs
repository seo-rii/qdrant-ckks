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

            let bucket_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/buckets",
                UploadPrivateHnswBucketsRequest {
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture.encrypted_build.buckets.clone(),
                }
            );
            assert_eq!(bucket_result["index_epoch"], BASE_EPOCH);

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

            let path_label_sentinel = "qdrant-sec-private-hnsw-path-label-sentinel";
            let read_error = post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![path_label_sentinel.to_string()],
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
                "leaf label"
            );
            assert!(!read_error.contains(path_label_sentinel), "{read_error}");
            assert!(
                !read_error.contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{read_error}"
            );
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![fixture.entry_leaf_label()],
                    padding: OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    },
                    client_signature: PrivateHnswClientSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.client_signature().sig,
                    },
                },
                StatusCode::BAD_REQUEST,
                "fixed path budget"
            );

            let read_result = post_json_ok!(
                "/collections/docs/private-hnsw/text/oram/read_paths",
                OramReadPathsRequest {
                    session_id: session_id.clone(),
                    index_epoch: BASE_EPOCH,
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
            post_json_error_contains!(
                "/collections/docs/private-hnsw/text/oram/commit",
                OramCommitRequest {
                    session_id: session_id.clone(),
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
        });
    }
}
