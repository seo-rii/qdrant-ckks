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
