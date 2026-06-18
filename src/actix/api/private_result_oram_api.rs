use std::fmt::{self, Debug, Formatter};

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
    do_close_private_result_oram_session, do_commit_private_result_oram_buckets,
    do_get_private_result_oram_manifest, do_open_private_result_oram_session,
    do_read_private_result_oram_buckets, do_upload_private_result_oram_buckets,
    do_upload_private_result_oram_manifest,
};
use crate::settings::Settings;

#[derive(Deserialize, Validate)]
struct PrivateResultOramPath {
    #[validate(nested)]
    #[serde(flatten)]
    collection: CollectionPath,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct UploadPrivateResultOramManifestRequest {
    pub manifest: qdrant_sec::PrivateResultOramManifest,
    pub signature: qdrant_sec::PrivateResultOramSignature,
}

impl Debug for UploadPrivateResultOramManifestRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadPrivateResultOramManifestRequest")
            .field("manifest", &self.manifest)
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct UploadPrivateResultOramBucketsRequest {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
}

impl Debug for UploadPrivateResultOramBucketsRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadPrivateResultOramBucketsRequest")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &self.buckets.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct OpenPrivateResultOramSessionRequest {
    pub client_id: String,
    pub desired_epoch: u64,
    pub fixed_budget: bool,
}

impl Debug for OpenPrivateResultOramSessionRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenPrivateResultOramSessionRequest")
            .field("client_id", &"[redacted]")
            .field("desired_epoch", &self.desired_epoch)
            .field("fixed_budget", &self.fixed_budget)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateResultOramSessionResponse {
    pub session_id: String,
    pub collection_id: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub manifest: qdrant_sec::PrivateResultOramManifest,
    pub lease_expires_unix: u64,
}

impl Debug for PrivateResultOramSessionResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramSessionResponse")
            .field("session_id", &"[redacted]")
            .field("collection_id", &self.collection_id)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("manifest", &self.manifest)
            .field("lease_expires_unix", &self.lease_expires_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct ReadPrivateResultOramBucketsRequest {
    pub session_id: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_ids: Vec<u64>,
    pub read_signature: qdrant_sec::PrivateResultOramSignature,
}

impl Debug for ReadPrivateResultOramBucketsRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadPrivateResultOramBucketsRequest")
            .field("session_id", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_id_count", &self.bucket_ids.len())
            .field("read_signature", &self.read_signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateResultOramReadBucketsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
    pub proof: PrivateResultOramReadProof,
}

impl Debug for PrivateResultOramReadBucketsResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadBucketsResponse")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &self.buckets.len())
            .field("proof", &self.proof)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PrivateResultOramReadProof {
    pub kind: String,
    pub value: String,
}

impl Debug for PrivateResultOramReadProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadProof")
            .field("kind", &self.kind)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct CommitPrivateResultOramBucketsRequest {
    pub session_id: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub updated_buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
    pub commit_signature: qdrant_sec::PrivateResultOramSignature,
}

impl Debug for CommitPrivateResultOramBucketsRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitPrivateResultOramBucketsRequest")
            .field("session_id", &"[redacted]")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("updated_bucket_count", &self.updated_buckets.len())
            .field("commit_signature", &self.commit_signature)
            .finish()
    }
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

#[post("/collections/{collection_name}/private-result-oram/session")]
async fn open_session(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<OpenPrivateResultOramSessionRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_open_private_result_oram_session(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        request.client_id,
        request.desired_epoch,
        request.fixed_budget,
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
        &request.session_id,
        request.index_epoch,
        request.root_hash,
        request.bucket_ids,
        request.read_signature,
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-result-oram/oram/commit")]
async fn commit_buckets(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramPath>,
    request: Json<CommitPrivateResultOramBucketsRequest>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let request = request.into_inner();
    let timing = Instant::now();
    let result = do_commit_private_result_oram_buckets(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.collection.collection_name,
        &request.session_id,
        request.old_epoch,
        request.new_epoch,
        request.old_root_hash,
        request.new_root_hash,
        request.updated_buckets,
        request.commit_signature,
    )
    .await;
    process_response(result, timing, None)
}

#[post("/collections/{collection_name}/private-result-oram/session/{session_id}/close")]
async fn close_session(
    dispatcher: web::Data<Dispatcher>,
    settings: web::Data<Settings>,
    path: Path<PrivateResultOramClosePath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let path = path.into_inner();
    let timing = Instant::now();
    let result = do_close_private_result_oram_session(
        dispatcher.toc(&auth, &new_unchecked_verification_pass()),
        &auth,
        settings.get_ref(),
        &path.private_result_oram.collection.collection_name,
        &path.session_id,
    )
    .await;
    process_response(result, timing, None)
}

#[derive(Deserialize, Validate)]
struct PrivateResultOramClosePath {
    #[validate(nested)]
    #[serde(flatten)]
    private_result_oram: PrivateResultOramPath,
    #[validate(length(min = 1, max = 256))]
    session_id: String,
}

pub fn config_private_result_oram_api(cfg: &mut web::ServiceConfig) {
    cfg.service(upload_manifest)
        .service(get_manifest)
        .service(upload_buckets)
        .service(open_session)
        .service(read_buckets)
        .service(commit_buckets)
        .service(close_session);
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
        PrivateResultOramBucketCommitmentContext, PrivateResultOramClientCommitBucketRef,
        PrivateResultOramCommitPlan, PrivateResultOramCommitSignatureContext,
        PrivateResultOramCommitSignatureInput, PrivateResultOramManifest,
        PrivateResultOramReadBucketsSignatureContext, private_result_oram_bucket_ciphertext_bytes,
        private_result_oram_bucket_commitment, private_result_oram_merkle_root_for_commitments,
        sign_private_result_oram_commit, sign_private_result_oram_manifest,
        sign_private_result_oram_read_buckets, sign_private_result_oram_read_buckets_for_manifest,
        try_private_result_oram_commit_signature_message,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use storage::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreateCollection, CreateCollectionOperation,
    };
    use storage::dispatcher::Dispatcher;
    use storage::rbac::{Access, AccessRequirements, Auth};
    use uuid::Uuid;

    use super::*;
    use crate::common::private_hnsw_wire_fixture::{
        route_e2e_guard, test_dispatcher, test_distributed_dispatcher,
    };
    use crate::settings::{CryptoInstanceConfig, CryptoSettings};

    const COLLECTION_NAME: &str = "docs";
    const COLLECTION_ID: &str = "12345678-90ab-cdef-1234-567890abcdef";
    const KEY_ID: &str = "tenant-a/result-private-rk";
    const RK_EPOCH: u64 = 7;
    const SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v1";
    const ALT_SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v2";
    const UNCONFIGURED_SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v3";
    const BASE_EPOCH: u64 = 42;
    const NEXT_EPOCH: u64 = 43;
    const SESSION_ID: &str = "session-1";

    struct PrivateResultRouteFixture {
        manifest: PrivateResultOramManifest,
        signature: qdrant_sec::PrivateResultOramSignature,
        buckets: Vec<PrivateResultOramBucket>,
        signing_key: Ed25519KeyPair,
        alt_signing_key: Ed25519KeyPair,
    }

    impl PrivateResultRouteFixture {
        fn build() -> Self {
            let signing_key = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
            let alt_signing_key = Ed25519KeyPair::from_seed_unchecked(&[10; 32]).unwrap();
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
                alt_signing_key,
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
                                SIGNING_KEY_ID: BASE64URL_NOPAD.encode(self.signing_key.public_key().as_ref()),
                                ALT_SIGNING_KEY_ID: BASE64URL_NOPAD.encode(self.alt_signing_key.public_key().as_ref())
                            }
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            };
            settings
        }

        fn commit_bucket(
            &self,
        ) -> (
            PrivateResultOramBucket,
            qdrant_sec::PrivateResultOramSignature,
            String,
        ) {
            let updated_bucket = fixture_bucket_for_epoch(0, &self.manifest, NEXT_EPOCH, &[42; 16]);
            let mut commitments = self
                .buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>();
            commitments[0] = updated_bucket.bucket_commitment.clone();
            let new_root_hash =
                private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
            let plan = PrivateResultOramCommitPlan {
                old_epoch: BASE_EPOCH,
                new_epoch: NEXT_EPOCH,
                old_root_hash: self.manifest.root_hash.clone(),
                new_root_hash: new_root_hash.clone(),
                leaf_commitments: commitments,
                updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                    bucket_id: updated_bucket.bucket_id,
                    ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
                }],
            };
            let commit_signature = sign_private_result_oram_commit(
                &self.signing_key,
                PrivateResultOramCommitSignatureContext {
                    collection_id: &self.manifest.collection_id,
                    key_id: &self.manifest.key_id,
                    rk_id: &self.manifest.rk_id,
                    rk_epoch: self.manifest.rk_epoch,
                    signing_key_id: SIGNING_KEY_ID,
                },
                &plan,
            )
            .unwrap();
            (updated_bucket, commit_signature, new_root_hash)
        }

        fn commit_signature_with_alt_key(
            &self,
            updated_bucket: &PrivateResultOramBucket,
            new_root_hash: &str,
        ) -> qdrant_sec::PrivateResultOramSignature {
            let mut commitments = self
                .buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>();
            commitments[updated_bucket.bucket_id as usize] =
                updated_bucket.bucket_commitment.clone();
            let plan = PrivateResultOramCommitPlan {
                old_epoch: BASE_EPOCH,
                new_epoch: NEXT_EPOCH,
                old_root_hash: self.manifest.root_hash.clone(),
                new_root_hash: new_root_hash.to_string(),
                leaf_commitments: commitments,
                updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                    bucket_id: updated_bucket.bucket_id,
                    ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
                }],
            };
            sign_private_result_oram_commit(
                &self.alt_signing_key,
                PrivateResultOramCommitSignatureContext {
                    collection_id: &self.manifest.collection_id,
                    key_id: &self.manifest.key_id,
                    rk_id: &self.manifest.rk_id,
                    rk_epoch: self.manifest.rk_epoch,
                    signing_key_id: ALT_SIGNING_KEY_ID,
                },
                &plan,
            )
            .unwrap()
        }

        fn sign_commit_unchecked(
            &self,
            plan: &PrivateResultOramCommitPlan,
        ) -> qdrant_sec::PrivateResultOramSignature {
            let bucket_refs = plan.signature_bucket_refs();
            let message = try_private_result_oram_commit_signature_message(
                PrivateResultOramCommitSignatureInput {
                    collection_id: &self.manifest.collection_id,
                    key_id: &self.manifest.key_id,
                    rk_id: &self.manifest.rk_id,
                    rk_epoch: self.manifest.rk_epoch,
                    old_epoch: plan.old_epoch,
                    new_epoch: plan.new_epoch,
                    old_root_hash: &plan.old_root_hash,
                    new_root_hash: &plan.new_root_hash,
                    updated_buckets: &bucket_refs,
                    signature_alg: "ed25519",
                    signature_key_id: SIGNING_KEY_ID,
                },
            )
            .unwrap();
            let signature = self.signing_key.sign(&message);
            qdrant_sec::PrivateResultOramSignature {
                alg: "ed25519".to_string(),
                key_id: SIGNING_KEY_ID.to_string(),
                sig: BASE64URL_NOPAD.encode(signature.as_ref()),
            }
        }

        fn read_signature(&self, bucket_ids: &[u64]) -> qdrant_sec::PrivateResultOramSignature {
            if let Ok(signature) = sign_private_result_oram_read_buckets_for_manifest(
                &self.signing_key,
                &self.manifest,
                bucket_ids,
            ) {
                return signature;
            }
            sign_private_result_oram_read_buckets(
                &self.signing_key,
                PrivateResultOramReadBucketsSignatureContext {
                    collection_id: &self.manifest.collection_id,
                    key_id: &self.manifest.key_id,
                    rk_id: &self.manifest.rk_id,
                    rk_epoch: self.manifest.rk_epoch,
                    signing_key_id: SIGNING_KEY_ID,
                },
                self.manifest.index_epoch,
                &self.manifest.root_hash,
                self.manifest.bucket_count,
                bucket_ids,
            )
            .unwrap()
        }

        fn read_signature_with_alt_key(
            &self,
            bucket_ids: &[u64],
        ) -> qdrant_sec::PrivateResultOramSignature {
            sign_private_result_oram_read_buckets(
                &self.alt_signing_key,
                PrivateResultOramReadBucketsSignatureContext {
                    collection_id: &self.manifest.collection_id,
                    key_id: &self.manifest.key_id,
                    rk_id: &self.manifest.rk_id,
                    rk_epoch: self.manifest.rk_epoch,
                    signing_key_id: ALT_SIGNING_KEY_ID,
                },
                self.manifest.index_epoch,
                &self.manifest.root_hash,
                self.manifest.bucket_count,
                bucket_ids,
            )
            .unwrap()
        }
    }

    fn fixture_bucket(
        bucket_id: u64,
        manifest: &PrivateResultOramManifest,
    ) -> PrivateResultOramBucket {
        fixture_bucket_for_epoch(
            bucket_id,
            manifest,
            manifest.index_epoch,
            &[bucket_id as u8; 16],
        )
    }

    fn fixture_bucket_for_epoch(
        bucket_id: u64,
        manifest: &PrivateResultOramManifest,
        index_epoch: u64,
        ciphertext_bytes: &[u8],
    ) -> PrivateResultOramBucket {
        let expected_len = private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
        let mut fixed_ciphertext = vec![0; expected_len];
        for (offset, byte) in fixed_ciphertext.iter_mut().enumerate() {
            let seed = ciphertext_bytes
                .get(offset % ciphertext_bytes.len().max(1))
                .copied()
                .unwrap_or(0);
            *byte = seed ^ (bucket_id as u8).wrapping_add(index_epoch as u8);
        }
        let ciphertext = BASE64URL_NOPAD.encode(&fixed_ciphertext);
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(&fixed_ciphertext));
        let bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id,
                index_epoch,
            },
            &ciphertext_sha256,
        )
        .unwrap();
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch,
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

    fn assert_unknown_field_rejected<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + Debug,
    {
        let mut value = serde_json::to_value(value).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".to_string(), json!("reject-me"));
        let err = serde_json::from_value::<T>(value).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    fn assert_requires_write_access(error: impl std::fmt::Display) {
        let rendered = error.to_string();
        assert!(
            rendered.contains("Global manage access is required")
                || rendered.contains("Write access to collection"),
            "expected write-access denial, got: {rendered}",
        );
    }

    #[test]
    fn private_result_oram_rest_dto_debug_redacts_sensitive_values() {
        let fixture = PrivateResultRouteFixture::build();
        let manifest_request = UploadPrivateResultOramManifestRequest {
            manifest: fixture.manifest.clone(),
            signature: fixture.signature.clone(),
        };
        let session_response = PrivateResultOramSessionResponse {
            session_id: SESSION_ID.to_string(),
            collection_id: COLLECTION_ID.to_string(),
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            manifest: fixture.manifest.clone(),
            lease_expires_unix: 1_770_000_000,
        };
        let bucket_ids = vec![987_654, 987_655];
        let read_signature = qdrant_sec::PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: SIGNING_KEY_ID.to_string(),
            sig: "RESULT-REST-READ-SIGNATURE-SENTINEL".to_string(),
        };
        let read_request = ReadPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            bucket_ids: bucket_ids.clone(),
            read_signature: read_signature.clone(),
        };
        let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
        let commit_request = CommitPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: fixture.manifest.root_hash.clone(),
            new_root_hash: new_root_hash.clone(),
            updated_buckets: vec![updated_bucket],
            commit_signature: commit_signature.clone(),
        };
        let buckets_request = UploadPrivateResultOramBucketsRequest {
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            buckets: fixture.buckets.clone(),
        };
        let read_response = PrivateResultOramReadBucketsResponse {
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            buckets: fixture.buckets.clone(),
            proof: PrivateResultOramReadProof {
                kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
                value: "RESULT-REST-PROOF-SENTINEL".to_string(),
            },
        };

        let rendered = [
            format!("{manifest_request:?}"),
            format!("{session_response:?}"),
            format!("{read_request:?}"),
            format!("{commit_request:?}"),
            format!("{buckets_request:?}"),
            format!("{read_response:?}"),
        ]
        .join("\n");
        for leaked in [
            SESSION_ID.to_string(),
            fixture.manifest.root_hash.clone(),
            new_root_hash,
            fixture.buckets[0].ciphertext.clone(),
            read_signature.sig,
            commit_signature.sig,
            "987654".to_string(),
            "RESULT-REST-PROOF-SENTINEL".to_string(),
        ] {
            assert!(!rendered.contains(&leaked), "{rendered}");
        }
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

        let session_request = OpenPrivateResultOramSessionRequest {
            client_id: "tenant-a/sdk-instance-1".to_string(),
            desired_epoch: BASE_EPOCH,
            fixed_budget: true,
        };
        assert_eq!(json_roundtrip(&session_request), session_request);

        let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
        let read_request = ReadPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            bucket_ids: read_bucket_ids.clone(),
            read_signature: fixture.read_signature(&read_bucket_ids),
        };
        assert_eq!(json_roundtrip(&read_request), read_request);

        let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
        let commit_request = CommitPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: fixture.manifest.root_hash.clone(),
            new_root_hash,
            updated_buckets: vec![updated_bucket],
            commit_signature,
        };
        assert_eq!(json_roundtrip(&commit_request), commit_request);
    }

    #[test]
    fn private_result_oram_rest_request_dtos_reject_unknown_fields() {
        let fixture = PrivateResultRouteFixture::build();
        let manifest_request = UploadPrivateResultOramManifestRequest {
            manifest: fixture.manifest.clone(),
            signature: fixture.signature.clone(),
        };
        assert_unknown_field_rejected(&manifest_request);

        let buckets_request = UploadPrivateResultOramBucketsRequest {
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            buckets: fixture.buckets.clone(),
        };
        assert_unknown_field_rejected(&buckets_request);

        let session_request = OpenPrivateResultOramSessionRequest {
            client_id: "tenant-a/sdk-instance-1".to_string(),
            desired_epoch: BASE_EPOCH,
            fixed_budget: true,
        };
        assert_unknown_field_rejected(&session_request);

        let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
        let read_request = ReadPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            index_epoch: fixture.manifest.index_epoch,
            root_hash: fixture.manifest.root_hash.clone(),
            bucket_ids: read_bucket_ids.clone(),
            read_signature: fixture.read_signature(&read_bucket_ids),
        };
        assert_unknown_field_rejected(&read_request);

        let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
        let commit_request = CommitPrivateResultOramBucketsRequest {
            session_id: SESSION_ID.to_string(),
            old_epoch: BASE_EPOCH,
            new_epoch: NEXT_EPOCH,
            old_root_hash: fixture.manifest.root_hash.clone(),
            new_root_hash,
            updated_buckets: vec![updated_bucket],
            commit_signature,
        };
        assert_unknown_field_rejected(&commit_request);
    }

    #[test]
    fn private_result_oram_common_ops_require_write_access_for_mutations() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let write_auth = Auth::new_internal(Access::full("private result ORAM write setup"));
            let read_auth =
                Auth::new_internal(Access::full_ro("private result ORAM read-only test"));
            let pass = new_unchecked_verification_pass();
            let write_toc = dispatcher.toc(&write_auth, &pass);
            let read_toc = dispatcher.toc(&read_auth, &pass);

            do_upload_private_result_oram_manifest(
                write_toc,
                &write_auth,
                &settings,
                COLLECTION_NAME,
                fixture.manifest.clone(),
                fixture.signature.clone(),
            )
            .await
            .unwrap();
            do_upload_private_result_oram_buckets(
                write_toc,
                &write_auth,
                &settings,
                COLLECTION_NAME,
                fixture.manifest.index_epoch,
                fixture.manifest.root_hash.clone(),
                fixture.buckets.clone(),
            )
            .await
            .unwrap();

            do_get_private_result_oram_manifest(read_toc, &read_auth, &settings, COLLECTION_NAME)
                .await
                .unwrap();

            let read_only_manifest_upload = do_upload_private_result_oram_manifest(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                fixture.manifest.clone(),
                fixture.signature.clone(),
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_manifest_upload);

            let read_only_bucket_upload = do_upload_private_result_oram_buckets(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                fixture.manifest.index_epoch,
                fixture.manifest.root_hash.clone(),
                fixture.buckets.clone(),
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_bucket_upload);

            let read_only_open = do_open_private_result_oram_session(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                "tenant-a/read-only-sdk".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_open);

            let session = do_open_private_result_oram_session(
                write_toc,
                &write_auth,
                &settings,
                COLLECTION_NAME,
                "tenant-a/write-sdk".to_string(),
                BASE_EPOCH,
                true,
            )
            .await
            .unwrap();

            let bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read_response = do_read_private_result_oram_buckets(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                &session.session_id,
                BASE_EPOCH,
                fixture.manifest.root_hash.clone(),
                bucket_ids.clone(),
                fixture.read_signature(&bucket_ids),
            )
            .await
            .unwrap();
            assert_eq!(read_response.buckets.len(), bucket_ids.len());

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let read_only_commit = do_commit_private_result_oram_buckets(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                &session.session_id,
                BASE_EPOCH,
                NEXT_EPOCH,
                fixture.manifest.root_hash.clone(),
                new_root_hash,
                vec![updated_bucket],
                commit_signature,
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_commit);

            let read_only_close = do_close_private_result_oram_session(
                read_toc,
                &read_auth,
                &settings,
                COLLECTION_NAME,
                &session.session_id,
            )
            .await
            .unwrap_err();
            assert_requires_write_access(read_only_close);

            assert!(
                do_close_private_result_oram_session(
                    write_toc,
                    &write_auth,
                    &settings,
                    COLLECTION_NAME,
                    &session.session_id,
                )
                .await
                .unwrap()
            );
        });
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

            let unsupported_manifest_alg_sentinel = "rsa-pss-result-manifest-sentinel";
            let mut unsupported_alg_manifest_signature = fixture.signature.clone();
            unsupported_alg_manifest_signature.alg = unsupported_manifest_alg_sentinel.to_string();
            let unsupported_manifest_alg_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: unsupported_alg_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !unsupported_manifest_alg_error.contains(unsupported_manifest_alg_sentinel),
                "{unsupported_manifest_alg_error}"
            );

            let mut alt_manifest_signature = fixture.signature.clone();
            alt_manifest_signature.key_id = ALT_SIGNING_KEY_ID.to_string();
            let alt_manifest_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: alt_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!alt_manifest_key_error.contains(ALT_SIGNING_KEY_ID));

            let mut unconfigured_manifest_signature = fixture.signature.clone();
            unconfigured_manifest_signature.key_id = UNCONFIGURED_SIGNING_KEY_ID.to_string();
            let unconfigured_manifest_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: unconfigured_manifest_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!unconfigured_manifest_key_error.contains(UNCONFIGURED_SIGNING_KEY_ID));
            assert!(!unconfigured_manifest_key_error.contains("not configured"));

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

            let bucket_upload_wrong_root = BASE64URL_NOPAD.encode(&[12; 32]);
            let bucket_upload_wrong_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: bucket_upload_wrong_root.clone(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "bucket upload epoch/root does not match current manifest epoch"
            );
            assert!(!bucket_upload_wrong_root_error.contains(&bucket_upload_wrong_root));
            assert!(!bucket_upload_wrong_root_error.contains(&fixture.buckets[0].ciphertext));

            let bucket_upload_root_sentinel = "AAAA";
            let malformed_bucket_upload_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: bucket_upload_root_sentinel.to_string(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "root_hash must be a base64url sha256 value"
            );
            assert!(!malformed_bucket_upload_root_error.contains(bucket_upload_root_sentinel));

            let mut hash_mismatch_buckets = fixture.buckets.clone();
            hash_mismatch_buckets[0].ciphertext =
                BASE64URL_NOPAD.encode(b"private-result-upload-ciphertext-sentinel");
            let hash_mismatch_ciphertext = hash_mismatch_buckets[0].ciphertext.clone();
            let bucket_upload_hash_mismatch_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: hash_mismatch_buckets,
                },
                StatusCode::BAD_REQUEST,
                "bucket ciphertext validation failed"
            );
            assert!(
                !bucket_upload_hash_mismatch_error
                    .contains("private-result-upload-ciphertext-sentinel")
            );
            assert!(!bucket_upload_hash_mismatch_error.contains(&hash_mismatch_ciphertext));

            let buckets_result = post_json_ok!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                }
            );
            assert_eq!(buckets_result["index_epoch"], fixture.manifest.index_epoch);

            let auth = Auth::new_internal(Access::full("private result ORAM route test"));
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new(),
                    "private_result_active_snapshot_upload_guard_test",
                )
                .unwrap();
            let pass = new_unchecked_verification_pass();
            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let config = collection.config_snapshot().await;
            let snapshot_guard =
                crate::common::private_result_oram::begin_private_result_oram_collection_snapshot(
                    collection.name(),
                    &config,
                )
                .unwrap()
                .unwrap();
            let active_snapshot_session_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-active-snapshot".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "active collection snapshot"
            );
            assert!(
                !active_snapshot_session_error.contains(&fixture.manifest.root_hash),
                "{active_snapshot_session_error}"
            );
            assert!(
                !active_snapshot_session_error.contains("private_result_oram"),
                "{active_snapshot_session_error}"
            );
            let active_snapshot_manifest_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "active collection snapshot"
            );
            assert!(
                !active_snapshot_manifest_upload_error.contains(&fixture.manifest.root_hash),
                "{active_snapshot_manifest_upload_error}"
            );
            assert!(
                !active_snapshot_manifest_upload_error.contains("private_result_oram"),
                "{active_snapshot_manifest_upload_error}"
            );
            let mut active_snapshot_bucket_upload = fixture.buckets.clone();
            active_snapshot_bucket_upload[0].ciphertext =
                "active-result-snapshot-bucket-ciphertext-sentinel".to_string();
            let active_snapshot_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: active_snapshot_bucket_upload,
                },
                StatusCode::BAD_REQUEST,
                "active collection snapshot"
            );
            assert!(
                !active_snapshot_bucket_upload_error
                    .contains("active-result-snapshot-bucket-ciphertext-sentinel"),
                "{active_snapshot_bucket_upload_error}"
            );
            assert!(
                !active_snapshot_bucket_upload_error.contains("private_result_oram"),
                "{active_snapshot_bucket_upload_error}"
            );
            drop(snapshot_guard);

            let client_id_sentinel = "result-session-client-id-sentinel";
            let oversized_client_id_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: format!("{client_id_sentinel}{}", "x".repeat(260)),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "client_id must be non-empty and at most 256 bytes"
            );
            assert!(
                !oversized_client_id_error.contains(client_id_sentinel),
                "{oversized_client_id_error}"
            );

            let malformed_client_id_sentinel = "result-session-client-id!sentinel";
            let malformed_client_id_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: malformed_client_id_sentinel.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "client_id is invalid"
            );
            assert!(
                !malformed_client_id_error.contains(malformed_client_id_sentinel),
                "{malformed_client_id_error}"
            );
            assert!(
                !malformed_client_id_error
                    .contains("client_id must be non-empty and at most 256 bytes"),
                "{malformed_client_id_error}"
            );

            let session_result = post_json_ok!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }
            );
            let session_id = session_result["session_id"].as_str().unwrap().to_string();
            assert_eq!(session_result["collection_id"], COLLECTION_ID);
            assert_eq!(session_result["index_epoch"], BASE_EPOCH);

            post_json_error_contains!(
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-2".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "active session"
            );

            let active_manifest_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "upload requires no active session"
            );
            assert!(!active_manifest_upload_error.contains(&session_id));

            let active_bucket_upload_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "upload requires no active session"
            );
            assert!(!active_bucket_upload_error.contains(&fixture.buckets[0].ciphertext));
            assert!(!active_bucket_upload_error.contains(&session_id));

            let active_snapshot_error = crate::common::collections::do_create_snapshot(
                dispatcher.toc(&auth, &pass).clone(),
                &auth,
                COLLECTION_NAME,
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                active_snapshot_error.contains("requires no active private ORAM session"),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains(&fixture.manifest.root_hash),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains(&session_id),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains(&fixture.buckets[0].ciphertext),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains("private_result_oram"),
                "{active_snapshot_error}"
            );
            let active_full_snapshot_error =
                crate::common::snapshots::do_create_full_snapshot(&dispatcher, auth.clone())
                    .await
                    .unwrap_err()
                    .to_string();
            assert!(
                active_full_snapshot_error.contains("requires no active private ORAM session"),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains(&fixture.manifest.root_hash),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains(&session_id),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains(&fixture.buckets[0].ciphertext),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains("private_result_oram"),
                "{active_full_snapshot_error}"
            );

            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read_result = post_json_ok!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&read_bucket_ids),
                }
            );
            assert_eq!(
                read_result["proof"]["kind"],
                PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND
            );
            assert_eq!(read_result["buckets"].as_array().unwrap().len(), 6);
            assert_eq!(read_result["buckets"][0]["bucket_id"], 0);

            let read_wrong_root = BASE64URL_NOPAD.encode(&[9; 32]);
            let read_wrong_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: read_wrong_root.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&read_bucket_ids),
                },
                StatusCode::BAD_REQUEST,
                "session epoch/root mismatch"
            );
            assert!(!read_wrong_root_error.contains(&read_wrong_root));
            assert!(!read_wrong_root_error.contains(&fixture.buckets[0].ciphertext));

            let read_root_sentinel = "AAAA";
            let malformed_read_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: read_root_sentinel.to_string(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&read_bucket_ids),
                },
                StatusCode::BAD_REQUEST,
                "root_hash must be a base64url sha256 value"
            );
            assert!(!malformed_read_root_error.contains(read_root_sentinel));

            let wrong_read_signature = fixture.read_signature(&[0, 1, 4, 0, 1, 3]);
            let invalid_read_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: wrong_read_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "read_buckets signature verification failed"
            );
            assert!(!invalid_read_signature_error.contains(&wrong_read_signature.sig));

            let invalid_signature_bad_path_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: vec![0, 2, 3, 0, 1, 4],
                    read_signature: wrong_read_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "valid ORAM paths"
            );
            assert!(!invalid_signature_bad_path_error.contains(&wrong_read_signature.sig));
            assert!(!invalid_signature_bad_path_error.contains(&fixture.buckets[0].ciphertext));

            let invalid_signature_out_of_range_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: vec![0, 1, fixture.manifest.bucket_count, 0, 1, 4],
                    read_signature: wrong_read_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "bucket id is out of range"
            );
            assert!(!invalid_signature_out_of_range_error.contains(&wrong_read_signature.sig));
            assert!(!invalid_signature_out_of_range_error.contains(&fixture.buckets[0].ciphertext));

            let unconfigured_read_key_id_sentinel = "tenant-a/private-result-signing-v1-unknown";
            let mut unconfigured_read_key_signature = fixture.read_signature(&read_bucket_ids);
            unconfigured_read_key_signature.key_id = unconfigured_read_key_id_sentinel.to_string();
            let unconfigured_read_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: unconfigured_read_key_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!unconfigured_read_key_error.contains("not configured"));
            assert!(
                !unconfigured_read_key_error.contains(unconfigured_read_key_id_sentinel),
                "{unconfigured_read_key_error}"
            );

            let alt_read_signature = fixture.read_signature_with_alt_key(&read_bucket_ids);
            let alt_read_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: alt_read_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!alt_read_key_error.contains(ALT_SIGNING_KEY_ID));

            let signature_body_sentinel = "signature!sentinel";
            let malformed_read_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: qdrant_sec::PrivateResultOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: signature_body_sentinel.to_string(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !malformed_read_signature_error.contains(signature_body_sentinel),
                "{malformed_read_signature_error}"
            );

            let read_signature_alg_sentinel = "rsa-pss-result-read-sentinel";
            let mut unsupported_read_signature = fixture.read_signature(&read_bucket_ids);
            unsupported_read_signature.alg = read_signature_alg_sentinel.to_string();
            let unsupported_read_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: unsupported_read_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !unsupported_read_signature_error.contains(read_signature_alg_sentinel),
                "{unsupported_read_signature_error}"
            );

            let deduped_bucket_ids = vec![0, 1, 3, 4];
            let deduped_path_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: deduped_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&deduped_bucket_ids),
                },
                StatusCode::BAD_REQUEST,
                "whole ORAM paths"
            );
            assert!(!deduped_path_error.contains(&fixture.buckets[0].ciphertext));

            let under_budget_bucket_ids = vec![0, 1, 3];
            let under_budget_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: under_budget_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&under_budget_bucket_ids),
                },
                StatusCode::BAD_REQUEST,
                "fixed path budget"
            );
            assert!(!under_budget_error.contains(&fixture.buckets[0].ciphertext));

            let unknown_read_session_sentinel = "read-session-id-sentinel";
            let unknown_read_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: unknown_read_session_sentinel.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&read_bucket_ids),
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            assert!(
                !unknown_read_error.contains(unknown_read_session_sentinel),
                "{unknown_read_error}"
            );

            let oversized_read_session_id = "s".repeat(129);
            let malformed_read_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_read_session_id.as_str(),
                malformed_read_session_id,
            ] {
                let error = post_json_error_contains!(
                    "/collections/docs/private-result-oram/oram/read_buckets",
                    ReadPrivateResultOramBucketsRequest {
                        session_id: invalid_session_id.to_string(),
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        bucket_ids: read_bucket_ids.clone(),
                        read_signature: fixture.read_signature(&read_bucket_ids),
                    },
                    StatusCode::BAD_REQUEST,
                    "session_id is invalid"
                );
                assert!(!error.contains(invalid_session_id), "{error}");
                assert!(!error.contains("session is missing or expired"), "{error}");
            }

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let unknown_commit_session_sentinel = "commit-session-id-sentinel";
            let unknown_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: unknown_commit_session_sentinel.to_string(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "session is missing or expired"
            );
            assert!(
                !unknown_commit_error.contains(unknown_commit_session_sentinel),
                "{unknown_commit_error}"
            );

            let oversized_commit_session_id = "s".repeat(129);
            let malformed_commit_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_commit_session_id.as_str(),
                malformed_commit_session_id,
            ] {
                let error = post_json_error_contains!(
                    "/collections/docs/private-result-oram/oram/commit",
                    CommitPrivateResultOramBucketsRequest {
                        session_id: invalid_session_id.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: vec![updated_bucket.clone()],
                        commit_signature: commit_signature.clone(),
                    },
                    StatusCode::BAD_REQUEST,
                    "session_id is invalid"
                );
                assert!(!error.contains(invalid_session_id), "{error}");
                assert!(!error.contains("session is missing or expired"), "{error}");
            }

            let commit_wrong_old_root = BASE64URL_NOPAD.encode(&[10; 32]);
            let commit_wrong_old_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_wrong_old_root.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit old epoch/root does not match active session"
            );
            assert!(!commit_wrong_old_root_error.contains(&commit_wrong_old_root));
            assert!(!commit_wrong_old_root_error.contains(&updated_bucket.ciphertext));

            let commit_old_root_sentinel = "AAAA";
            let malformed_commit_old_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_old_root_sentinel.to_string(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "old_root_hash must be a base64url sha256 value"
            );
            assert!(!malformed_commit_old_root_error.contains(commit_old_root_sentinel));

            let commit_wrong_new_root = BASE64URL_NOPAD.encode(&[11; 32]);
            let commit_wrong_new_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: commit_wrong_new_root.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit signature verification failed"
            );
            assert!(!commit_wrong_new_root_error.contains(&commit_wrong_new_root));
            assert!(!commit_wrong_new_root_error.contains(&commit_signature.sig));

            let commit_new_root_sentinel = "AAAA";
            let malformed_commit_new_root_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: commit_new_root_sentinel.to_string(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "new_root_hash must be a base64url sha256 value"
            );
            assert!(!malformed_commit_new_root_error.contains(commit_new_root_sentinel));

            let empty_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![],
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit updated_buckets must contain"
            );
            assert!(!empty_commit_error.contains(&commit_signature.sig));

            let oversized_commit_buckets = vec![updated_bucket.clone(); 8];
            let oversized_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: oversized_commit_buckets,
                    commit_signature: commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit updated_buckets must contain"
            );
            assert!(!oversized_commit_error.contains(&updated_bucket.ciphertext));
            assert!(!oversized_commit_error.contains("duplicate bucket id"));

            let wrong_commit_signature = fixture.signature.clone();
            let invalid_commit_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: wrong_commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "commit signature verification failed"
            );
            assert!(!invalid_commit_signature_error.contains(&wrong_commit_signature.sig));

            let duplicate_commit_buckets = vec![updated_bucket.clone(), updated_bucket.clone()];
            let duplicate_commit_plan = PrivateResultOramCommitPlan {
                old_epoch: BASE_EPOCH,
                new_epoch: NEXT_EPOCH,
                old_root_hash: fixture.manifest.root_hash.clone(),
                new_root_hash: new_root_hash.clone(),
                leaf_commitments: fixture
                    .buckets
                    .iter()
                    .map(|bucket| bucket.bucket_commitment.clone())
                    .collect(),
                updated_buckets: duplicate_commit_buckets
                    .iter()
                    .map(|bucket| PrivateResultOramClientCommitBucketRef {
                        bucket_id: bucket.bucket_id,
                        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                    })
                    .collect(),
            };
            let duplicate_commit_signature = fixture.sign_commit_unchecked(&duplicate_commit_plan);
            post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: duplicate_commit_plan.old_root_hash,
                    new_root_hash: duplicate_commit_plan.new_root_hash,
                    updated_buckets: duplicate_commit_buckets.clone(),
                    commit_signature: duplicate_commit_signature,
                },
                StatusCode::BAD_REQUEST,
                "duplicate bucket id"
            );

            post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone(), updated_bucket.clone()],
                    commit_signature: wrong_commit_signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "duplicate bucket id"
            );

            let unconfigured_commit_key_id_sentinel = "tenant-a/private-result-signing-v1-unknown";
            let mut unconfigured_commit_key_signature = commit_signature.clone();
            unconfigured_commit_key_signature.key_id =
                unconfigured_commit_key_id_sentinel.to_string();
            let unconfigured_commit_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: unconfigured_commit_key_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!unconfigured_commit_key_error.contains("not configured"));
            assert!(
                !unconfigured_commit_key_error.contains(unconfigured_commit_key_id_sentinel),
                "{unconfigured_commit_key_error}"
            );

            let alt_commit_signature =
                fixture.commit_signature_with_alt_key(&updated_bucket, &new_root_hash);
            let alt_commit_key_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: alt_commit_signature,
                },
                StatusCode::BAD_REQUEST,
                "signature key_id does not match manifest owner_signing_key_id"
            );
            assert!(!alt_commit_key_error.contains(ALT_SIGNING_KEY_ID));

            let commit_signature_body_sentinel = "commit-signature!sentinel";
            let malformed_commit_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: qdrant_sec::PrivateResultOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: commit_signature_body_sentinel.to_string(),
                    },
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !malformed_commit_signature_error.contains(commit_signature_body_sentinel),
                "{malformed_commit_signature_error}"
            );

            let commit_signature_alg_sentinel = "rsa-pss-result-commit-sentinel";
            let mut unsupported_commit_signature = commit_signature.clone();
            unsupported_commit_signature.alg = commit_signature_alg_sentinel.to_string();
            let unsupported_commit_signature_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: unsupported_commit_signature,
                },
                StatusCode::BAD_REQUEST,
                "request validation failed"
            );
            assert!(
                !unsupported_commit_signature_error.contains(commit_signature_alg_sentinel),
                "{unsupported_commit_signature_error}"
            );

            let commit_result = post_json_ok!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature: commit_signature.clone(),
                }
            );
            assert_eq!(commit_result["index_epoch"], NEXT_EPOCH);
            assert_eq!(commit_result["root_hash"], new_root_hash);

            let stale_commit_error = post_json_error_contains!(
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash,
                    updated_buckets: vec![updated_bucket],
                    commit_signature,
                },
                StatusCode::BAD_REQUEST,
                "old epoch/root"
            );
            assert!(!stale_commit_error.contains(&fixture.buckets[0].ciphertext));

            let close_uri =
                format!("/collections/docs/private-result-oram/session/{session_id}/close");
            let _ = post_json_ok!(close_uri.as_str(), serde_json::json!({}));

            let missing_close_session_id = "close-session-id-sentinel";
            let missing_close_request = actix_test::TestRequest::post()
                .uri(&format!(
                    "/collections/docs/private-result-oram/session/{missing_close_session_id}/close"
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

            let oversized_close_session_id = "s".repeat(129);
            let malformed_close_session_id = "bad.session-id";
            for invalid_session_id in [
                oversized_close_session_id.as_str(),
                malformed_close_session_id,
            ] {
                let invalid_close_request = actix_test::TestRequest::post()
                    .uri(&format!(
                        "/collections/docs/private-result-oram/session/{invalid_session_id}/close"
                    ))
                    .to_request();
                let invalid_close_response =
                    actix_test::call_service(&app, invalid_close_request).await;
                assert_eq!(invalid_close_response.status(), StatusCode::BAD_REQUEST);
                let invalid_close_body = actix_test::read_body(invalid_close_response).await;
                let invalid_close_body = String::from_utf8_lossy(&invalid_close_body);
                assert!(invalid_close_body.contains("session_id is invalid"));
                assert!(
                    !invalid_close_body.contains(invalid_session_id),
                    "{invalid_close_body}"
                );
                assert!(
                    !invalid_close_body.contains("session is missing or already closed"),
                    "{invalid_close_body}"
                );
            }
        });
    }

    #[test]
    fn setup_rest_routes_revalidate_runtime_oram_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("payload_result_oram_v1")
            .unwrap()
            .options["oram"]["tree_height"] = json!(1);
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
            let drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;

            macro_rules! post_json_ok_on {
                ($app:expr, $uri:expr, $body:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
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
            macro_rules! post_json_error_contains_on {
                ($app:expr, $uri:expr, $body:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }
            macro_rules! get_json_error_contains_on {
                ($app:expr, $uri:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::get().uri($uri).to_request();
                    let response = actix_test::call_service($app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }

            let drifted_manifest_upload_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(
                !drifted_manifest_upload_error.contains("tree_height"),
                "{drifted_manifest_upload_error}"
            );

            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                }
            );

            let drifted_manifest_read_error = get_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/manifest",
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(
                !drifted_manifest_read_error.contains("tree_height"),
                "{drifted_manifest_read_error}"
            );

            let missing_bucket_session_error = post_json_error_contains_on!(
                &app,
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-missing-buckets-test".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::NOT_FOUND,
                "encrypted bucket data is unavailable"
            );
            assert!(
                !missing_bucket_session_error.contains("private_result_oram"),
                "{missing_bucket_session_error}"
            );
            assert!(
                !missing_bucket_session_error.contains("/tmp"),
                "{missing_bucket_session_error}"
            );

            let drifted_bucket_upload_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(
                !drifted_bucket_upload_error.contains("tree_height"),
                "{drifted_bucket_upload_error}"
            );
            assert!(
                !drifted_bucket_upload_error.contains(&fixture.buckets[0].ciphertext),
                "{drifted_bucket_upload_error}"
            );

            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                }
            );

            let drifted_session_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-setup-drift-test".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(
                !drifted_session_error.contains("tree_height"),
                "{drifted_session_error}"
            );
        });
    }

    #[test]
    fn active_session_rest_read_rejects_runtime_oram_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("payload_result_oram_v1")
            .unwrap()
            .options["oram"]["tree_height"] = json!(1);
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
            let drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;

            macro_rules! post_json_ok_on {
                ($app:expr, $uri:expr, $body:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
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
            macro_rules! post_json_error_contains_on {
                ($app:expr, $uri:expr, $body:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }

            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                }
            );
            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                }
            );
            let session_result = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-drift-test".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }
            );
            let session_id = session_result["session_id"].as_str().unwrap().to_string();

            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let drift_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/oram/read_buckets",
                ReadPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: fixture.read_signature(&read_bucket_ids),
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(!drift_error.contains("tree_height"), "{drift_error}");

            let close_uri =
                format!("/collections/docs/private-result-oram/session/{session_id}/close");
            let closed = post_json_ok_on!(&app, close_uri.as_str(), serde_json::json!({}));
            assert_eq!(closed, json!(true));
        });
    }

    #[test]
    fn active_session_rest_commit_rejects_runtime_oram_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("payload_result_oram_v1")
            .unwrap()
            .options["oram"]["tree_height"] = json!(1);
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
            let drifted_app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(dispatcher.clone()))
                    .app_data(web::Data::new(drifted_settings))
                    .app_data(actix_web_validator::JsonConfig::default().limit(1024 * 1024))
                    .configure(config_private_result_oram_api),
            )
            .await;

            macro_rules! post_json_ok_on {
                ($app:expr, $uri:expr, $body:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
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
            macro_rules! post_json_error_contains_on {
                ($app:expr, $uri:expr, $body:expr, $status:expr, $needle:expr) => {{
                    let request = actix_test::TestRequest::post()
                        .uri($uri)
                        .set_json(&$body)
                        .to_request();
                    let response = actix_test::call_service($app, request).await;
                    let status = response.status();
                    let body_bytes = actix_test::read_body(response).await;
                    let body = String::from_utf8_lossy(&body_bytes);
                    assert_eq!(status, $status, "{body}");
                    assert!(body.contains($needle), "{body}");
                    body.to_string()
                }};
            }

            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/manifest",
                UploadPrivateResultOramManifestRequest {
                    manifest: fixture.manifest.clone(),
                    signature: fixture.signature.clone(),
                }
            );
            let _ = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/buckets",
                UploadPrivateResultOramBucketsRequest {
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.clone(),
                }
            );
            let session_result = post_json_ok_on!(
                &app,
                "/collections/docs/private-result-oram/session",
                OpenPrivateResultOramSessionRequest {
                    client_id: "tenant-a/sdk-instance-commit-drift-test".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }
            );
            let session_id = session_result["session_id"].as_str().unwrap().to_string();

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let drift_error = post_json_error_contains_on!(
                &drifted_app,
                "/collections/docs/private-result-oram/oram/commit",
                CommitPrivateResultOramBucketsRequest {
                    session_id: session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash,
                    updated_buckets: vec![updated_bucket.clone()],
                    commit_signature,
                },
                StatusCode::BAD_REQUEST,
                "manifest oram does not match runtime instance"
            );
            assert!(!drift_error.contains("tree_height"), "{drift_error}");
            assert!(
                !drift_error.contains(&updated_bucket.ciphertext),
                "{drift_error}"
            );

            let close_uri =
                format!("/collections/docs/private-result-oram/session/{session_id}/close");
            let closed = post_json_ok_on!(&app, close_uri.as_str(), serde_json::json!({}));
            assert_eq!(closed, json!(true));
        });
    }

    #[test]
    fn open_session_rest_route_rejects_distributed_epoch_mode() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_distributed_dispatcher();
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

            let manifest_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-result-oram/manifest")
                    .set_json(&UploadPrivateResultOramManifestRequest {
                        manifest: fixture.manifest.clone(),
                        signature: fixture.signature.clone(),
                    })
                    .to_request(),
            )
            .await;
            let manifest_status = manifest_response.status();
            let manifest_body_bytes = actix_test::read_body(manifest_response).await;
            let manifest_body = String::from_utf8_lossy(&manifest_body_bytes);
            assert_eq!(manifest_status, StatusCode::OK, "{manifest_body}");

            let bucket_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-result-oram/buckets")
                    .set_json(&UploadPrivateResultOramBucketsRequest {
                        index_epoch: fixture.manifest.index_epoch,
                        root_hash: fixture.manifest.root_hash.clone(),
                        buckets: fixture.buckets.clone(),
                    })
                    .to_request(),
            )
            .await;
            let bucket_status = bucket_response.status();
            let bucket_body_bytes = actix_test::read_body(bucket_response).await;
            let bucket_body = String::from_utf8_lossy(&bucket_body_bytes);
            assert_eq!(bucket_status, StatusCode::OK, "{bucket_body}");

            let session_response = actix_test::call_service(
                &app,
                actix_test::TestRequest::post()
                    .uri("/collections/docs/private-result-oram/session")
                    .set_json(&OpenPrivateResultOramSessionRequest {
                        client_id: "tenant-a/distributed-result-sdk-instance".to_string(),
                        desired_epoch: BASE_EPOCH,
                        fixed_budget: true,
                    })
                    .to_request(),
            )
            .await;
            let status = session_response.status();
            let body_bytes = actix_test::read_body(session_response).await;
            let body = String::from_utf8_lossy(&body_bytes);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(body.contains("consensus-backed epoch/root CAS"), "{body}");
        });
    }
}
