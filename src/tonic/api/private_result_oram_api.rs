use std::sync::Arc;
use std::time::Instant;

use api::grpc::qdrant as grpc;
use api::grpc::qdrant::private_result_oram_server::PrivateResultOram;
use collection::operations::verification::new_unchecked_verification_pass;
use qdrant_sec::{
    OramKind, OramParams, PrivateResultOramBucket, PrivateResultOramManifest,
    PrivateResultOramSignature,
};
use storage::dispatcher::Dispatcher;
use tonic::{Request, Response, Status, async_trait};

use crate::common::private_result_oram::{
    do_close_private_result_oram_session, do_commit_private_result_oram_buckets,
    do_get_private_result_oram_manifest, do_open_private_result_oram_session,
    do_read_private_result_oram_buckets, do_upload_private_result_oram_buckets,
    do_upload_private_result_oram_manifest,
};
use crate::settings::Settings;
use crate::tonic::auth::extract_auth;

const ORAM_KIND_PATH_ORAM: i32 = 1;

pub struct PrivateResultOramService {
    dispatcher: Arc<Dispatcher>,
    settings: Settings,
}

impl PrivateResultOramService {
    pub fn new(dispatcher: Arc<Dispatcher>, settings: Settings) -> Self {
        Self {
            dispatcher,
            settings,
        }
    }
}

#[async_trait]
impl PrivateResultOram for PrivateResultOramService {
    async fn get_private_result_oram_manifest(
        &self,
        mut request: Request<grpc::GetPrivateResultOramManifestRequest>,
    ) -> Result<Response<grpc::GetPrivateResultOramManifestResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let pass = new_unchecked_verification_pass();

        let record = do_get_private_result_oram_manifest(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
        )
        .await?;

        Ok(Response::new(grpc::GetPrivateResultOramManifestResponse {
            manifest: Some(manifest_to_proto(record.manifest)),
            signature: Some(signature_to_proto(record.signature)),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn upload_private_result_oram_manifest(
        &self,
        mut request: Request<grpc::UploadPrivateResultOramManifestRequest>,
    ) -> Result<Response<grpc::PrivateResultOramEpochResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let manifest = manifest_from_proto(required(request.manifest, "manifest")?)?;
        let signature = signature_from_proto(required(request.signature, "signature")?);
        let pass = new_unchecked_verification_pass();

        let epoch = do_upload_private_result_oram_manifest(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            manifest,
            signature,
        )
        .await?;

        Ok(Response::new(grpc::PrivateResultOramEpochResponse {
            index_epoch: epoch.index_epoch,
            root_hash: epoch.root_hash,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn upload_private_result_oram_buckets(
        &self,
        mut request: Request<grpc::UploadPrivateResultOramBucketsRequest>,
    ) -> Result<Response<grpc::PrivateResultOramEpochResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let buckets = request
            .buckets
            .into_iter()
            .map(bucket_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let pass = new_unchecked_verification_pass();

        let epoch = do_upload_private_result_oram_buckets(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            request.index_epoch,
            request.root_hash,
            buckets,
        )
        .await?;

        Ok(Response::new(grpc::PrivateResultOramEpochResponse {
            index_epoch: epoch.index_epoch,
            root_hash: epoch.root_hash,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn open_private_result_oram_session(
        &self,
        mut request: Request<grpc::OpenPrivateResultOramSessionRequest>,
    ) -> Result<Response<grpc::OpenPrivateResultOramSessionResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let pass = new_unchecked_verification_pass();

        let session = do_open_private_result_oram_session(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            request.client_id,
            request.desired_epoch,
            request.fixed_budget,
        )
        .await?;

        Ok(Response::new(grpc::OpenPrivateResultOramSessionResponse {
            session_id: session.session_id,
            collection_id: session.collection_id,
            index_epoch: session.index_epoch,
            root_hash: session.root_hash,
            manifest: Some(manifest_to_proto(session.manifest)),
            lease_expires_unix: session.lease_expires_unix,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn read_private_result_oram_buckets(
        &self,
        mut request: Request<grpc::ReadPrivateResultOramBucketsRequest>,
    ) -> Result<Response<grpc::ReadPrivateResultOramBucketsResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let pass = new_unchecked_verification_pass();
        let read_signature =
            signature_from_proto(required(request.read_signature, "read_signature")?);

        let response = do_read_private_result_oram_buckets(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.session_id,
            request.index_epoch,
            request.root_hash,
            request.bucket_ids,
            read_signature,
        )
        .await?;

        Ok(Response::new(grpc::ReadPrivateResultOramBucketsResponse {
            index_epoch: response.index_epoch,
            root_hash: response.root_hash,
            buckets: response.buckets.into_iter().map(bucket_to_proto).collect(),
            proof: Some(grpc::PrivateResultOramReadProof {
                kind: response.proof.kind,
                value: response.proof.value,
            }),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn commit_private_result_oram_buckets(
        &self,
        mut request: Request<grpc::CommitPrivateResultOramBucketsRequest>,
    ) -> Result<Response<grpc::PrivateResultOramEpochResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let updated_buckets = request
            .updated_buckets
            .into_iter()
            .map(bucket_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let commit_signature =
            signature_from_proto(required(request.commit_signature, "commit_signature")?);
        let pass = new_unchecked_verification_pass();

        let epoch = do_commit_private_result_oram_buckets(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.session_id,
            request.old_epoch,
            request.new_epoch,
            request.old_root_hash,
            request.new_root_hash,
            updated_buckets,
            commit_signature,
        )
        .await?;

        Ok(Response::new(grpc::PrivateResultOramEpochResponse {
            index_epoch: epoch.index_epoch,
            root_hash: epoch.root_hash,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn close_private_result_oram_session(
        &self,
        mut request: Request<grpc::ClosePrivateResultOramSessionRequest>,
    ) -> Result<Response<grpc::ClosePrivateResultOramSessionResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection(&request.collection_name)?;
        let pass = new_unchecked_verification_pass();

        let closed = do_close_private_result_oram_session(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.session_id,
        )
        .await?;

        Ok(Response::new(grpc::ClosePrivateResultOramSessionResponse {
            closed,
            time: timing.elapsed().as_secs_f64(),
        }))
    }
}

fn validate_collection(collection_name: &str) -> Result<(), Status> {
    if collection_name.is_empty() || collection_name.len() > 255 {
        return Err(Status::invalid_argument(
            "collection_name must be non-empty and at most 255 bytes",
        ));
    }
    Ok(())
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, Status> {
    value.ok_or_else(|| Status::invalid_argument(format!("{field} is required")))
}

fn manifest_to_proto(manifest: PrivateResultOramManifest) -> grpc::PrivateResultOramManifest {
    grpc::PrivateResultOramManifest {
        version: manifest.version as u32,
        provider: manifest.provider,
        binding: manifest.binding,
        collection_id: manifest.collection_id,
        key_id: manifest.key_id,
        rk_id: manifest.rk_id,
        rk_epoch: manifest.rk_epoch,
        oram: Some(grpc::OramParams {
            kind: oram_kind_to_proto(manifest.oram.kind),
            bucket_size: manifest.oram.bucket_size,
            block_size_bytes: manifest.oram.block_size_bytes,
            tree_height: manifest.oram.tree_height,
            path_batch_size: manifest.oram.path_batch_size,
        }),
        index_epoch: manifest.index_epoch,
        root_hash: manifest.root_hash,
        bucket_count: manifest.bucket_count,
        logical_result_count: manifest.logical_result_count,
        dummy_result_count: manifest.dummy_result_count,
        owner_signing_key_id: manifest.owner_signing_key_id,
        created_at_unix: manifest.created_at_unix,
    }
}

fn manifest_from_proto(
    manifest: grpc::PrivateResultOramManifest,
) -> Result<PrivateResultOramManifest, Status> {
    let version = u16::try_from(manifest.version)
        .map_err(|_| Status::invalid_argument("manifest.version exceeds u16"))?;
    let oram = required(manifest.oram, "manifest.oram")?;
    Ok(PrivateResultOramManifest {
        version,
        provider: manifest.provider,
        binding: manifest.binding,
        collection_id: manifest.collection_id,
        key_id: manifest.key_id,
        rk_id: manifest.rk_id,
        rk_epoch: manifest.rk_epoch,
        oram: OramParams {
            kind: oram_kind_from_proto(oram.kind)?,
            bucket_size: oram.bucket_size,
            block_size_bytes: oram.block_size_bytes,
            tree_height: oram.tree_height,
            path_batch_size: oram.path_batch_size,
        },
        index_epoch: manifest.index_epoch,
        root_hash: manifest.root_hash,
        bucket_count: manifest.bucket_count,
        logical_result_count: manifest.logical_result_count,
        dummy_result_count: manifest.dummy_result_count,
        owner_signing_key_id: manifest.owner_signing_key_id,
        created_at_unix: manifest.created_at_unix,
    })
}

fn bucket_to_proto(bucket: PrivateResultOramBucket) -> grpc::PrivateResultOramBucket {
    grpc::PrivateResultOramBucket {
        version: bucket.version as u32,
        bucket_id: bucket.bucket_id,
        index_epoch: bucket.index_epoch,
        ciphertext: bucket.ciphertext,
        ciphertext_sha256: bucket.ciphertext_sha256,
        bucket_commitment: bucket.bucket_commitment,
    }
}

fn bucket_from_proto(
    bucket: grpc::PrivateResultOramBucket,
) -> Result<PrivateResultOramBucket, Status> {
    let version = u16::try_from(bucket.version)
        .map_err(|_| Status::invalid_argument("bucket.version exceeds u16"))?;
    Ok(PrivateResultOramBucket {
        version,
        bucket_id: bucket.bucket_id,
        index_epoch: bucket.index_epoch,
        ciphertext: bucket.ciphertext,
        ciphertext_sha256: bucket.ciphertext_sha256,
        bucket_commitment: bucket.bucket_commitment,
    })
}

fn signature_to_proto(signature: PrivateResultOramSignature) -> grpc::PrivateResultOramSignature {
    grpc::PrivateResultOramSignature {
        alg: signature.alg,
        key_id: signature.key_id,
        sig: signature.sig,
    }
}

fn signature_from_proto(signature: grpc::PrivateResultOramSignature) -> PrivateResultOramSignature {
    PrivateResultOramSignature {
        alg: signature.alg,
        key_id: signature.key_id,
        sig: signature.sig,
    }
}

fn oram_kind_to_proto(kind: OramKind) -> i32 {
    match kind {
        OramKind::PathOram => ORAM_KIND_PATH_ORAM,
    }
}

fn oram_kind_from_proto(value: i32) -> Result<OramKind, Status> {
    match value {
        ORAM_KIND_PATH_ORAM => Ok(OramKind::PathOram),
        _ => Err(Status::invalid_argument(
            "private result ORAM kind is unspecified or unsupported",
        )),
    }
}

#[cfg(test)]
mod private_result_oram_grpc_tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    use collection::config::{
        CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector,
    };
    use collection::operations::types::VectorsConfig;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING,
        PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PrivateResultOramBucket,
        PrivateResultOramBucketCommitmentContext, PrivateResultOramClientCommitBucketRef,
        PrivateResultOramCommitPlan, PrivateResultOramCommitSignatureContext,
        PrivateResultOramReadBucketsSignatureContext, private_result_oram_bucket_commitment,
        private_result_oram_merkle_root_for_commitments, sign_private_result_oram_commit,
        sign_private_result_oram_manifest, sign_private_result_oram_read_buckets,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use storage::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreateCollection, CreateCollectionOperation,
    };
    use storage::dispatcher::Dispatcher;
    use storage::rbac::{Access, Auth};
    use tonic::Code;
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
    const BASE_EPOCH: u64 = 42;
    const NEXT_EPOCH: u64 = 43;

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

        fn read_signature(&self, bucket_ids: &[u64]) -> qdrant_sec::PrivateResultOramSignature {
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
        let ciphertext = BASE64URL_NOPAD.encode(ciphertext_bytes);
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(&Sha256::digest(ciphertext_bytes));
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
                Auth::new_internal(Access::full("private result ORAM gRPC route test")),
                None,
            )
            .await
            .unwrap();
    }

    #[test]
    fn manifest_proto_roundtrip_preserves_private_result_fields() {
        let fixture = PrivateResultRouteFixture::build();
        let proto = manifest_to_proto(fixture.manifest.clone());

        assert_eq!(proto.oram.as_ref().unwrap().kind, ORAM_KIND_PATH_ORAM);
        assert_eq!(manifest_from_proto(proto).unwrap(), fixture.manifest);
    }

    #[test]
    fn manifest_proto_rejects_unspecified_oram_and_missing_nested_fields() {
        let fixture = PrivateResultRouteFixture::build();
        let mut proto = manifest_to_proto(fixture.manifest.clone());
        proto.oram.as_mut().unwrap().kind = 0;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("kind"));

        let mut proto = manifest_to_proto(fixture.manifest);
        proto.oram = None;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest.oram"));

        let err = required::<grpc::PrivateResultOramManifest>(None, "manifest").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest"));

        let err =
            required::<grpc::PrivateResultOramSignature>(None, "commit_signature").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("commit_signature"));

        let err = required::<grpc::PrivateResultOramSignature>(None, "read_signature").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("read_signature"));
    }

    #[test]
    fn private_result_oram_uploads_and_reads_through_grpc_service() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let service = PrivateResultOramService::new(Arc::new(dispatcher.clone()), settings);

            let missing_manifest = PrivateResultOram::get_private_result_oram_manifest(
                &service,
                Request::new(grpc::GetPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(missing_manifest.code(), Code::NotFound);
            assert!(!missing_manifest.message().contains("private_result_oram"));

            let manifest_epoch = PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature.clone())),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(manifest_epoch.index_epoch, BASE_EPOCH);
            assert_eq!(manifest_epoch.root_hash, fixture.manifest.root_hash);

            let manifest_read = PrivateResultOram::get_private_result_oram_manifest(
                &service,
                Request::new(grpc::GetPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(
                manifest_read.manifest.unwrap().root_hash,
                fixture.manifest.root_hash
            );
            assert_eq!(manifest_read.signature.unwrap().key_id, SIGNING_KEY_ID);

            let bucket_epoch = PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(bucket_epoch.index_epoch, BASE_EPOCH);

            let session = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(session.collection_id, COLLECTION_ID);
            assert_eq!(session.index_epoch, BASE_EPOCH);

            let duplicate_session = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-2".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(duplicate_session.code(), Code::InvalidArgument);
            assert!(duplicate_session.message().contains("active session"));

            let read_bucket_ids = vec![0, 1, 3, 0, 1, 4];
            let read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(
                        fixture.read_signature(&read_bucket_ids),
                    )),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(
                read.proof.unwrap().kind,
                PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND
            );
            assert_eq!(read.buckets.len(), 6);
            assert_eq!(read.buckets[0].bucket_id, 0);

            let wrong_read_signature = fixture.read_signature(&[0, 1, 4, 0, 1, 3]);
            let invalid_read_signature = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(wrong_read_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(invalid_read_signature.code(), Code::InvalidArgument);
            assert!(
                invalid_read_signature
                    .message()
                    .contains("read_buckets signature verification failed")
            );
            assert!(
                !invalid_read_signature
                    .message()
                    .contains(&wrong_read_signature.sig)
            );

            let deduped_bucket_ids = vec![0, 1, 3, 4];
            let deduped_path_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: deduped_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(
                        fixture.read_signature(&deduped_bucket_ids),
                    )),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(deduped_path_read.code(), Code::InvalidArgument);
            assert!(deduped_path_read.message().contains("whole ORAM paths"));
            assert!(
                !deduped_path_read
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );

            let unknown_read_session_sentinel = "read-session-id-sentinel";
            let unknown_read = PrivateResultOram::read_private_result_oram_buckets(
                &service,
                Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: unknown_read_session_sentinel.to_string(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.manifest.root_hash.clone(),
                    bucket_ids: read_bucket_ids.clone(),
                    read_signature: Some(signature_to_proto(
                        fixture.read_signature(&read_bucket_ids),
                    )),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(unknown_read.code(), Code::InvalidArgument);
            assert!(
                unknown_read
                    .message()
                    .contains("session is missing or expired")
            );
            assert!(
                !unknown_read
                    .message()
                    .contains(unknown_read_session_sentinel),
                "{}",
                unknown_read.message()
            );

            let oversized_read_session_id = "s".repeat(129);
            let malformed_read_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_read_session_id.as_str(),
                malformed_read_session_id,
            ] {
                let err = PrivateResultOram::read_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::ReadPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: invalid_session_id.to_string(),
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.manifest.root_hash.clone(),
                        bucket_ids: read_bucket_ids.clone(),
                        read_signature: Some(signature_to_proto(
                            fixture.read_signature(&read_bucket_ids),
                        )),
                    }),
                )
                .await
                .unwrap_err();
                assert_eq!(err.code(), Code::InvalidArgument);
                assert!(err.message().contains("session_id is invalid"));
                assert!(
                    !err.message().contains(invalid_session_id),
                    "{}",
                    err.message()
                );
                assert!(
                    !err.message().contains("session is missing or expired"),
                    "{}",
                    err.message()
                );
            }

            let (updated_bucket, commit_signature, new_root_hash) = fixture.commit_bucket();
            let unknown_commit_session_sentinel = "commit-session-id-sentinel";
            let unknown_commit = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: unknown_commit_session_sentinel.to_string(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(unknown_commit.code(), Code::InvalidArgument);
            assert!(
                unknown_commit
                    .message()
                    .contains("session is missing or expired")
            );
            assert!(
                !unknown_commit
                    .message()
                    .contains(unknown_commit_session_sentinel),
                "{}",
                unknown_commit.message()
            );

            let oversized_commit_session_id = "s".repeat(129);
            let malformed_commit_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_commit_session_id.as_str(),
                malformed_commit_session_id,
            ] {
                let err = PrivateResultOram::commit_private_result_oram_buckets(
                    &service,
                    Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: invalid_session_id.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: fixture.manifest.root_hash.clone(),
                        new_root_hash: new_root_hash.clone(),
                        updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                        commit_signature: Some(signature_to_proto(commit_signature.clone())),
                    }),
                )
                .await
                .unwrap_err();
                assert_eq!(err.code(), Code::InvalidArgument);
                assert!(err.message().contains("session_id is invalid"));
                assert!(
                    !err.message().contains(invalid_session_id),
                    "{}",
                    err.message()
                );
                assert!(
                    !err.message().contains("session is missing or expired"),
                    "{}",
                    err.message()
                );
            }

            let committed = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash: new_root_hash.clone(),
                    updated_buckets: vec![bucket_to_proto(updated_bucket.clone())],
                    commit_signature: Some(signature_to_proto(commit_signature.clone())),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(committed.index_epoch, NEXT_EPOCH);
            assert_eq!(committed.root_hash, new_root_hash);

            let stale_commit = PrivateResultOram::commit_private_result_oram_buckets(
                &service,
                Request::new(grpc::CommitPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.manifest.root_hash.clone(),
                    new_root_hash,
                    updated_buckets: vec![bucket_to_proto(updated_bucket)],
                    commit_signature: Some(signature_to_proto(commit_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(stale_commit.code(), Code::InvalidArgument);
            assert!(stale_commit.message().contains("old epoch/root"));
            assert!(
                !stale_commit
                    .message()
                    .contains(&fixture.buckets[0].ciphertext)
            );

            let closed = PrivateResultOram::close_private_result_oram_session(
                &service,
                Request::new(grpc::ClosePrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: session.session_id.clone(),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);

            let missing_close_session_id = "close-session-id-sentinel";
            let missing_close = PrivateResultOram::close_private_result_oram_session(
                &service,
                Request::new(grpc::ClosePrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    session_id: missing_close_session_id.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(missing_close.code(), Code::InvalidArgument);
            assert!(
                missing_close
                    .message()
                    .contains("session is missing or already closed")
            );
            assert!(
                !missing_close.message().contains(missing_close_session_id),
                "{}",
                missing_close.message()
            );

            let oversized_close_session_id = "s".repeat(129);
            let malformed_close_session_id = "bad.session-id";
            for invalid_session_id in [
                oversized_close_session_id.as_str(),
                malformed_close_session_id,
            ] {
                let err = PrivateResultOram::close_private_result_oram_session(
                    &service,
                    Request::new(grpc::ClosePrivateResultOramSessionRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        session_id: invalid_session_id.to_string(),
                    }),
                )
                .await
                .unwrap_err();
                assert_eq!(err.code(), Code::InvalidArgument);
                assert!(err.message().contains("session_id is invalid"));
                assert!(
                    !err.message().contains(invalid_session_id),
                    "{}",
                    err.message()
                );
                assert!(
                    !err.message()
                        .contains("session is missing or already closed"),
                    "{}",
                    err.message()
                );
            }
        });
    }

    #[test]
    fn open_session_grpc_route_rejects_distributed_epoch_mode() {
        let _guard = route_e2e_guard();
        let fixture = PrivateResultRouteFixture::build();
        let settings = fixture.settings();
        let (_temp, dispatcher) = test_distributed_dispatcher();

        actix_web::rt::System::new().block_on(async {
            create_private_result_collection(&dispatcher).await;
            let service = PrivateResultOramService::new(Arc::new(dispatcher.clone()), settings);

            PrivateResultOram::upload_private_result_oram_manifest(
                &service,
                Request::new(grpc::UploadPrivateResultOramManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.signature)),
                }),
            )
            .await
            .unwrap();

            PrivateResultOram::upload_private_result_oram_buckets(
                &service,
                Request::new(grpc::UploadPrivateResultOramBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    index_epoch: fixture.manifest.index_epoch,
                    root_hash: fixture.manifest.root_hash.clone(),
                    buckets: fixture.buckets.into_iter().map(bucket_to_proto).collect(),
                }),
            )
            .await
            .unwrap();

            let err = PrivateResultOram::open_private_result_oram_session(
                &service,
                Request::new(grpc::OpenPrivateResultOramSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    client_id: "tenant-a/distributed-result-sdk-instance".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("consensus-backed epoch/root CAS"));
        });
    }
}
