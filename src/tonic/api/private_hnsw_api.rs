use std::sync::Arc;
use std::time::Instant;

use api::grpc::qdrant as grpc;
use api::grpc::qdrant::private_hnsw_oram_server::PrivateHnswOram;
use collection::operations::verification::new_unchecked_verification_pass;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PrivateHnswOramBucket,
    PrivateHnswOramManifest, PrivateHnswOramSignature, PrivateHnswParams, ResultPrivacyMode,
};
use storage::dispatcher::Dispatcher;
use tonic::{Request, Response, Status, async_trait};

use crate::common::private_hnsw::{
    PrivateHnswClientSignature, PrivateHnswReadPadding, do_close_private_hnsw_session,
    do_commit_private_hnsw_paths, do_get_private_hnsw_manifest, do_open_private_hnsw_session,
    do_read_private_hnsw_paths, do_upload_private_hnsw_buckets, do_upload_private_hnsw_manifest,
};
use crate::settings::Settings;
use crate::tonic::auth::extract_auth;

const DISTANCE_COSINE: i32 = 1;
const DISTANCE_DOT: i32 = 2;
const DISTANCE_EUCLID: i32 = 3;
const DISTANCE_MANHATTAN: i32 = 4;
const RESULT_PRIVACY_IDS_VISIBLE: i32 = 1;
const RESULT_PRIVACY_PRIVATE_PAYLOAD_ORAM_REQUIRED: i32 = 2;
const ORAM_KIND_PATH_ORAM: i32 = 1;

pub struct PrivateHnswOramService {
    dispatcher: Arc<Dispatcher>,
    settings: Settings,
}

impl PrivateHnswOramService {
    pub fn new(dispatcher: Arc<Dispatcher>, settings: Settings) -> Self {
        Self {
            dispatcher,
            settings,
        }
    }
}

#[async_trait]
impl PrivateHnswOram for PrivateHnswOramService {
    async fn get_private_hnsw_manifest(
        &self,
        mut request: Request<grpc::GetPrivateHnswManifestRequest>,
    ) -> Result<Response<grpc::GetPrivateHnswManifestResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection_and_vector(&request.collection_name, &request.vector_name)?;
        let pass = new_unchecked_verification_pass();

        let record = do_get_private_hnsw_manifest(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.vector_name,
        )
        .await?;

        Ok(Response::new(grpc::GetPrivateHnswManifestResponse {
            manifest: Some(manifest_to_proto(record.manifest)),
            signature: Some(signature_to_proto(record.signature)),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn upload_private_hnsw_manifest(
        &self,
        mut request: Request<grpc::UploadPrivateHnswManifestRequest>,
    ) -> Result<Response<grpc::PrivateHnswEpochResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection_and_vector(&request.collection_name, &request.vector_name)?;
        let manifest = manifest_from_proto(required(request.manifest, "manifest")?)?;
        let signature = signature_from_proto(required(request.signature, "signature")?);
        let pass = new_unchecked_verification_pass();

        let epoch = do_upload_private_hnsw_manifest(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.vector_name,
            manifest,
            signature,
        )
        .await?;

        Ok(Response::new(grpc::PrivateHnswEpochResponse {
            index_epoch: epoch.index_epoch,
            root_hash: epoch.root_hash,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn open_private_hnsw_session(
        &self,
        mut request: Request<grpc::OpenPrivateHnswSessionRequest>,
    ) -> Result<Response<grpc::OpenPrivateHnswSessionResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection_and_vector(&request.collection_name, &request.vector_name)?;
        let result_privacy = result_privacy_from_proto(request.result_privacy)?;
        let pass = new_unchecked_verification_pass();

        let session = do_open_private_hnsw_session(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.vector_name,
            request.client_id,
            request.desired_epoch,
            request.fixed_budget,
            result_privacy,
        )
        .await?;

        Ok(Response::new(grpc::OpenPrivateHnswSessionResponse {
            session_id: session.session_id,
            collection_id: session.collection_id,
            vector_name: session.vector_name,
            index_epoch: session.index_epoch,
            root_hash: session.root_hash,
            manifest: Some(manifest_to_proto(session.manifest)),
            lease_expires_unix: session.lease_expires_unix,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn upload_private_hnsw_buckets(
        &self,
        mut request: Request<grpc::UploadPrivateHnswBucketsRequest>,
    ) -> Result<Response<grpc::PrivateHnswEpochResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection_and_vector(&request.collection_name, &request.vector_name)?;
        let buckets = request
            .buckets
            .into_iter()
            .map(bucket_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let pass = new_unchecked_verification_pass();

        let epoch = do_upload_private_hnsw_buckets(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.vector_name,
            request.index_epoch,
            request.root_hash,
            buckets,
        )
        .await?;

        Ok(Response::new(grpc::PrivateHnswEpochResponse {
            index_epoch: epoch.index_epoch,
            root_hash: epoch.root_hash,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn read_private_hnsw_paths(
        &self,
        mut request: Request<grpc::OramReadPathsRequest>,
    ) -> Result<Response<grpc::OramReadPathsResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection_and_vector(&request.collection_name, &request.vector_name)?;
        let padding = padding_from_proto(required(request.padding, "padding")?);
        let client_signature =
            common_signature_from_proto(required(request.client_signature, "client_signature")?);
        let pass = new_unchecked_verification_pass();

        let response = do_read_private_hnsw_paths(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.vector_name,
            &request.session_id,
            request.index_epoch,
            &request.root_hash,
            request.paths,
            padding,
            client_signature,
        )
        .await?;

        Ok(Response::new(grpc::OramReadPathsResponse {
            index_epoch: response.index_epoch,
            root_hash: response.root_hash,
            buckets: response.buckets.into_iter().map(bucket_to_proto).collect(),
            proof: Some(grpc::OramReadProof {
                kind: response.proof.kind,
                value: response.proof.value,
            }),
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn commit_private_hnsw_paths(
        &self,
        mut request: Request<grpc::OramCommitRequest>,
    ) -> Result<Response<grpc::PrivateHnswEpochResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection_and_vector(&request.collection_name, &request.vector_name)?;
        let updated_buckets = request
            .updated_buckets
            .into_iter()
            .map(bucket_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let commit_signature =
            common_signature_from_proto(required(request.commit_signature, "commit_signature")?);
        let pass = new_unchecked_verification_pass();

        let epoch = do_commit_private_hnsw_paths(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.vector_name,
            &request.session_id,
            request.old_epoch,
            request.new_epoch,
            request.old_root_hash,
            request.new_root_hash,
            updated_buckets,
            commit_signature,
        )
        .await?;

        Ok(Response::new(grpc::PrivateHnswEpochResponse {
            index_epoch: epoch.index_epoch,
            root_hash: epoch.root_hash,
            time: timing.elapsed().as_secs_f64(),
        }))
    }

    async fn close_private_hnsw_session(
        &self,
        mut request: Request<grpc::ClosePrivateHnswSessionRequest>,
    ) -> Result<Response<grpc::ClosePrivateHnswSessionResponse>, Status> {
        let timing = Instant::now();
        let auth = extract_auth(&mut request);
        let request = request.into_inner();
        validate_collection_and_vector(&request.collection_name, &request.vector_name)?;
        let pass = new_unchecked_verification_pass();

        let closed = do_close_private_hnsw_session(
            self.dispatcher.toc(&auth, &pass),
            &auth,
            &self.settings,
            &request.collection_name,
            &request.vector_name,
            &request.session_id,
        )
        .await?;

        Ok(Response::new(grpc::ClosePrivateHnswSessionResponse {
            closed,
            time: timing.elapsed().as_secs_f64(),
        }))
    }
}

fn validate_collection_and_vector(collection_name: &str, vector_name: &str) -> Result<(), Status> {
    if collection_name.is_empty() || collection_name.len() > 255 {
        return Err(Status::invalid_argument(
            "collection_name must be non-empty and at most 255 bytes",
        ));
    }
    if vector_name.is_empty() || vector_name.len() > 128 {
        return Err(Status::invalid_argument(
            "vector_name must be non-empty and at most 128 bytes",
        ));
    }
    Ok(())
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, Status> {
    value.ok_or_else(|| Status::invalid_argument(format!("{field} is required")))
}

fn manifest_to_proto(manifest: PrivateHnswOramManifest) -> grpc::PrivateHnswManifest {
    grpc::PrivateHnswManifest {
        version: manifest.version as u32,
        provider: manifest.provider,
        binding: manifest.binding,
        collection_id: manifest.collection_id,
        vector_name: manifest.vector_name,
        key_id: manifest.key_id,
        rk_id: manifest.rk_id,
        rk_epoch: manifest.rk_epoch,
        dim: manifest.dim,
        distance: distance_to_proto(manifest.distance),
        hnsw: Some(grpc::PrivateHnswParams {
            m: manifest.hnsw.m,
            ef_construction: manifest.hnsw.ef_construction,
            max_layers: manifest.hnsw.max_layers,
            fixed_neighbor_slots: manifest.hnsw.fixed_neighbor_slots,
        }),
        oram: Some(grpc::OramParams {
            kind: oram_kind_to_proto(manifest.oram.kind),
            bucket_size: manifest.oram.bucket_size,
            block_size_bytes: manifest.oram.block_size_bytes,
            tree_height: manifest.oram.tree_height,
            path_batch_size: manifest.oram.path_batch_size,
        }),
        fixed_budget: Some(grpc::FixedBudgetParams {
            enabled: manifest.fixed_budget.enabled,
            upper_layer_steps: manifest.fixed_budget.upper_layer_steps,
            base_layer_steps: manifest.fixed_budget.base_layer_steps,
            paths_per_round: manifest.fixed_budget.paths_per_round,
            fixed_result_k: manifest.fixed_budget.fixed_result_k,
        }),
        index_epoch: manifest.index_epoch,
        root_hash: manifest.root_hash,
        bucket_count: manifest.bucket_count,
        logical_node_count: manifest.logical_node_count,
        dummy_node_count: manifest.dummy_node_count,
        result_privacy: result_privacy_to_proto(manifest.result_privacy),
        owner_signing_key_id: manifest.owner_signing_key_id,
        created_at_unix: manifest.created_at_unix,
    }
}

fn manifest_from_proto(
    manifest: grpc::PrivateHnswManifest,
) -> Result<PrivateHnswOramManifest, Status> {
    let version = u16::try_from(manifest.version)
        .map_err(|_| Status::invalid_argument("manifest.version exceeds u16"))?;
    let hnsw = required(manifest.hnsw, "manifest.hnsw")?;
    let oram = required(manifest.oram, "manifest.oram")?;
    let fixed_budget = required(manifest.fixed_budget, "manifest.fixed_budget")?;
    Ok(PrivateHnswOramManifest {
        version,
        provider: manifest.provider,
        binding: manifest.binding,
        collection_id: manifest.collection_id,
        vector_name: manifest.vector_name,
        key_id: manifest.key_id,
        rk_id: manifest.rk_id,
        rk_epoch: manifest.rk_epoch,
        dim: manifest.dim,
        distance: distance_from_proto(manifest.distance)?,
        hnsw: PrivateHnswParams {
            m: hnsw.m,
            ef_construction: hnsw.ef_construction,
            max_layers: hnsw.max_layers,
            fixed_neighbor_slots: hnsw.fixed_neighbor_slots,
        },
        oram: OramParams {
            kind: oram_kind_from_proto(oram.kind)?,
            bucket_size: oram.bucket_size,
            block_size_bytes: oram.block_size_bytes,
            tree_height: oram.tree_height,
            path_batch_size: oram.path_batch_size,
        },
        fixed_budget: FixedBudgetParams {
            enabled: fixed_budget.enabled,
            upper_layer_steps: fixed_budget.upper_layer_steps,
            base_layer_steps: fixed_budget.base_layer_steps,
            paths_per_round: fixed_budget.paths_per_round,
            fixed_result_k: fixed_budget.fixed_result_k,
        },
        index_epoch: manifest.index_epoch,
        root_hash: manifest.root_hash,
        bucket_count: manifest.bucket_count,
        logical_node_count: manifest.logical_node_count,
        dummy_node_count: manifest.dummy_node_count,
        result_privacy: result_privacy_from_proto(manifest.result_privacy)?,
        owner_signing_key_id: manifest.owner_signing_key_id,
        created_at_unix: manifest.created_at_unix,
    })
}

fn bucket_to_proto(bucket: PrivateHnswOramBucket) -> grpc::PrivateHnswBucket {
    grpc::PrivateHnswBucket {
        version: bucket.version as u32,
        bucket_id: bucket.bucket_id,
        index_epoch: bucket.index_epoch,
        ciphertext: bucket.ciphertext,
        ciphertext_sha256: bucket.ciphertext_sha256,
        bucket_commitment: bucket.bucket_commitment,
    }
}

fn bucket_from_proto(bucket: grpc::PrivateHnswBucket) -> Result<PrivateHnswOramBucket, Status> {
    let version = u16::try_from(bucket.version)
        .map_err(|_| Status::invalid_argument("bucket.version exceeds u16"))?;
    Ok(PrivateHnswOramBucket {
        version,
        bucket_id: bucket.bucket_id,
        index_epoch: bucket.index_epoch,
        ciphertext: bucket.ciphertext,
        ciphertext_sha256: bucket.ciphertext_sha256,
        bucket_commitment: bucket.bucket_commitment,
    })
}

fn signature_to_proto(signature: PrivateHnswOramSignature) -> grpc::PrivateHnswSignature {
    grpc::PrivateHnswSignature {
        alg: signature.alg,
        key_id: signature.key_id,
        sig: signature.sig,
    }
}

fn signature_from_proto(signature: grpc::PrivateHnswSignature) -> PrivateHnswOramSignature {
    PrivateHnswOramSignature {
        alg: signature.alg,
        key_id: signature.key_id,
        sig: signature.sig,
    }
}

fn common_signature_from_proto(
    signature: grpc::PrivateHnswSignature,
) -> PrivateHnswClientSignature {
    PrivateHnswClientSignature {
        alg: signature.alg,
        key_id: signature.key_id,
        sig: signature.sig,
    }
}

fn padding_from_proto(padding: grpc::OramReadPadding) -> PrivateHnswReadPadding {
    PrivateHnswReadPadding {
        requested_paths: padding.requested_paths,
        dummy_paths_included: padding.dummy_paths_included,
    }
}

fn distance_to_proto(distance: DistanceKind) -> i32 {
    match distance {
        DistanceKind::Cosine => DISTANCE_COSINE,
        DistanceKind::Dot => DISTANCE_DOT,
        DistanceKind::Euclid => DISTANCE_EUCLID,
        DistanceKind::Manhattan => DISTANCE_MANHATTAN,
    }
}

fn distance_from_proto(value: i32) -> Result<DistanceKind, Status> {
    match value {
        DISTANCE_COSINE => Ok(DistanceKind::Cosine),
        DISTANCE_DOT => Ok(DistanceKind::Dot),
        DISTANCE_EUCLID => Ok(DistanceKind::Euclid),
        DISTANCE_MANHATTAN => Ok(DistanceKind::Manhattan),
        _ => Err(Status::invalid_argument(
            "private HNSW ORAM distance is unspecified or unsupported",
        )),
    }
}

fn result_privacy_to_proto(result_privacy: ResultPrivacyMode) -> i32 {
    match result_privacy {
        ResultPrivacyMode::IdsVisible => RESULT_PRIVACY_IDS_VISIBLE,
        ResultPrivacyMode::PrivatePayloadOramRequired => {
            RESULT_PRIVACY_PRIVATE_PAYLOAD_ORAM_REQUIRED
        }
    }
}

fn result_privacy_from_proto(value: i32) -> Result<ResultPrivacyMode, Status> {
    match value {
        RESULT_PRIVACY_IDS_VISIBLE => Ok(ResultPrivacyMode::IdsVisible),
        RESULT_PRIVACY_PRIVATE_PAYLOAD_ORAM_REQUIRED => {
            Ok(ResultPrivacyMode::PrivatePayloadOramRequired)
        }
        _ => Err(Status::invalid_argument(
            "private HNSW ORAM result_privacy is unspecified or unsupported",
        )),
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
            "private HNSW ORAM kind is unspecified or unsupported",
        )),
    }
}

#[cfg(test)]
mod private_hnsw_grpc_tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use collection::private_hnsw_oram_store::{PrivateHnswOramEpochState, PrivateHnswOramStore};
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        DistanceKind, PrivateHnswClientError, PrivateHnswEncryptedPathBatch,
        PrivateHnswSearchParams, ResultPrivacyMode, encode_private_hnsw_oram_leaf_label,
        open_private_hnsw_oram_verified_path_batch, plan_private_hnsw_oram_commit,
        search_private_hnsw_oram_encrypted_verified,
    };
    use storage::rbac::{Access, AccessRequirements, Auth};
    use tonic::Code;

    use super::*;
    use crate::common::private_hnsw_wire_fixture::{
        BASE_EPOCH, COLLECTION_ID, COLLECTION_NAME, MAX_CIPHERTEXT_BYTES, NEXT_EPOCH,
        PrivateHnswRouteWireFixture, SESSION_ID, SIGNING_KEY_ID, VECTOR_NAME,
        create_private_hnsw_collection, create_private_hnsw_collection_with_private_result_oram,
        create_private_hnsw_collection_with_vector_name, route_e2e_guard, test_dispatcher,
        test_distributed_dispatcher,
    };

    fn sample_manifest() -> PrivateHnswOramManifest {
        PrivateHnswOramManifest {
            version: 1,
            provider: qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: qdrant_sec::PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            vector_name: "text".to_string(),
            key_id: "tenant-a/vector-private-rk".to_string(),
            rk_id: "tenant-a/vector-private-rk".to_string(),
            rk_epoch: 7,
            dim: 1536,
            distance: DistanceKind::Cosine,
            hnsw: PrivateHnswParams {
                m: 32,
                ef_construction: 128,
                max_layers: 16,
                fixed_neighbor_slots: 64,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 16384,
                tree_height: 24,
                path_batch_size: 8,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 32,
                base_layer_steps: 256,
                paths_per_round: 8,
                fixed_result_k: 10,
            },
            index_epoch: 42,
            root_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            bucket_count: 33_554_431,
            logical_node_count: 100,
            dummy_node_count: 8,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    #[test]
    fn manifest_proto_roundtrip_preserves_private_hnsw_fields() {
        let manifest = sample_manifest();
        let proto = manifest_to_proto(manifest.clone());

        assert_eq!(proto.distance, DISTANCE_COSINE);
        assert_eq!(proto.result_privacy, RESULT_PRIVACY_IDS_VISIBLE);
        assert_eq!(proto.oram.as_ref().unwrap().kind, ORAM_KIND_PATH_ORAM);
        assert_eq!(manifest_from_proto(proto).unwrap(), manifest);
    }

    #[test]
    fn manifest_proto_rejects_unspecified_enums_and_missing_nested_fields() {
        let mut proto = manifest_to_proto(sample_manifest());
        proto.distance = 0;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("distance"));

        let mut proto = manifest_to_proto(sample_manifest());
        proto.result_privacy = 0;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("result_privacy"));

        let mut proto = manifest_to_proto(sample_manifest());
        proto.hnsw = None;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest.hnsw"));

        let mut proto = manifest_to_proto(sample_manifest());
        proto.oram = None;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest.oram"));

        let mut proto = manifest_to_proto(sample_manifest());
        proto.oram.as_mut().unwrap().kind = 0;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("kind"));

        let mut proto = manifest_to_proto(sample_manifest());
        proto.fixed_budget = None;
        let err = manifest_from_proto(proto).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest.fixed_budget"));

        let err = required::<grpc::PrivateHnswManifest>(None, "manifest").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest"));

        let err = required::<grpc::OramReadPadding>(None, "padding").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("padding"));

        let err = required::<grpc::PrivateHnswSignature>(None, "client_signature").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("client_signature"));

        let err = required::<grpc::PrivateHnswSignature>(None, "commit_signature").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("commit_signature"));
    }

    #[test]
    fn proto_enum_conversions_reject_unknown_values_without_reflecting_value() {
        let unsupported = 987_654;

        let err = distance_from_proto(unsupported).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("distance"));
        assert!(!err.message().contains(&unsupported.to_string()));

        let err = result_privacy_from_proto(unsupported).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("result_privacy"));
        assert!(!err.message().contains(&unsupported.to_string()));

        let err = oram_kind_from_proto(unsupported).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("kind"));
        assert!(!err.message().contains(&unsupported.to_string()));
    }

    #[test]
    fn manifest_and_bucket_proto_reject_version_overflow_without_reflecting_value() {
        let mut manifest = manifest_to_proto(sample_manifest());
        manifest.version = u32::MAX;
        let err = manifest_from_proto(manifest).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("manifest.version"));
        assert!(!err.message().contains(&u32::MAX.to_string()));

        let err = bucket_from_proto(grpc::PrivateHnswBucket {
            version: u32::MAX,
            bucket_id: 1,
            index_epoch: 42,
            ciphertext: "ciphertext".to_string(),
            ciphertext_sha256: "sha".to_string(),
            bucket_commitment: "commitment".to_string(),
        })
        .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("bucket.version"));
        assert!(!err.message().contains(&u32::MAX.to_string()));
    }

    #[test]
    fn sdk_fixture_roundtrips_through_grpc_wire_requests_and_verified_path_response() {
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let upload_manifest = grpc::UploadPrivateHnswManifestRequest {
            collection_name: COLLECTION_NAME.to_string(),
            vector_name: VECTOR_NAME.to_string(),
            manifest: Some(manifest_to_proto(fixture.manifest.clone())),
            signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
        };
        assert_eq!(upload_manifest.collection_name, COLLECTION_NAME);
        assert_eq!(
            manifest_from_proto(required(upload_manifest.manifest, "manifest").unwrap()).unwrap(),
            fixture.manifest
        );
        assert_eq!(
            signature_from_proto(required(upload_manifest.signature, "signature").unwrap()),
            fixture.manifest_signature
        );

        let upload_buckets = grpc::UploadPrivateHnswBucketsRequest {
            collection_name: COLLECTION_NAME.to_string(),
            vector_name: VECTOR_NAME.to_string(),
            index_epoch: fixture.encrypted_build.index_epoch,
            root_hash: fixture.encrypted_build.root_hash.clone(),
            buckets: fixture
                .encrypted_build
                .buckets
                .clone()
                .into_iter()
                .map(bucket_to_proto)
                .collect(),
        };
        let restored_buckets = upload_buckets
            .buckets
            .clone()
            .into_iter()
            .map(bucket_from_proto)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(restored_buckets, fixture.encrypted_build.buckets);

        let open_session = grpc::OpenPrivateHnswSessionRequest {
            collection_name: COLLECTION_NAME.to_string(),
            vector_name: VECTOR_NAME.to_string(),
            client_id: "tenant-a/sdk-instance-1".to_string(),
            desired_epoch: BASE_EPOCH,
            fixed_budget: true,
            result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
        };
        assert_eq!(
            result_privacy_from_proto(open_session.result_privacy).unwrap(),
            ResultPrivacyMode::IdsVisible
        );

        let updated_by_bucket = RefCell::new(BTreeMap::new());
        let mut state = fixture.plaintext_build.state.clone();
        let mut remaps = [3].into_iter();
        let mut observed_read_paths = Vec::new();
        let result = search_private_hnsw_oram_encrypted_verified(
            &fixture.keys,
            fixture.base_context,
            fixture.encrypted_build.index_epoch,
            &fixture.encrypted_build.root_hash,
            fixture.encrypted_build.bucket_count,
            NEXT_EPOCH,
            &mut state,
            fixture.config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: fixture.encrypted_build.entry_node_id,
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let leaf_label =
                    encode_private_hnsw_oram_leaf_label(leaf, fixture.config.tree_height).unwrap();
                let paths = vec![leaf_label.clone()];
                let read_signature = fixture.sign_read_paths(&paths, 1, true);
                let read_request = grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: SESSION_ID.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(read_signature)),
                };
                let padding =
                    padding_from_proto(required(read_request.padding.clone(), "padding").unwrap());
                assert_eq!(padding.requested_paths, 1);
                assert!(padding.dummy_paths_included);
                let client_signature = common_signature_from_proto(
                    required(read_request.client_signature.clone(), "client_signature").unwrap(),
                );
                assert_eq!(client_signature.key_id, SIGNING_KEY_ID);
                observed_read_paths.push(read_request.paths.clone());

                let (_bucket_ids, batch) = fixture.read_batch_for_leaf(leaf);
                let read_response = grpc::OramReadPathsResponse {
                    index_epoch: batch.index_epoch,
                    root_hash: batch.root_hash.clone(),
                    buckets: batch.buckets.into_iter().map(bucket_to_proto).collect(),
                    proof: Some(grpc::OramReadProof {
                        kind: fixture.proof_kind(),
                        value: batch.proof_value,
                    }),
                    time: 0.0,
                };
                let proof = required(read_response.proof, "proof").unwrap();
                assert_eq!(proof.kind, fixture.proof_kind());
                let buckets = read_response
                    .buckets
                    .into_iter()
                    .map(bucket_from_proto)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: read_response.index_epoch,
                    root_hash: read_response.root_hash,
                    bucket_count: fixture.encrypted_build.bucket_count,
                    proof_value: proof.value,
                    buckets,
                })
            },
            |writeback_buckets| {
                let mut updated = updated_by_bucket.borrow_mut();
                for bucket in writeback_buckets {
                    updated.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();
        assert_eq!(result.hits[0].node_id, [1; 32]);
        assert_eq!(observed_read_paths, vec![vec![fixture.entry_leaf_label()]]);

        let updated_buckets = updated_by_bucket
            .into_inner()
            .into_values()
            .collect::<Vec<_>>();
        let commit_plan = plan_private_hnsw_oram_commit(
            BASE_EPOCH,
            NEXT_EPOCH,
            &fixture.encrypted_build.root_hash,
            &fixture.leaf_commitments,
            &updated_buckets,
        )
        .unwrap();
        let commit_signature = fixture.sign_commit(&commit_plan);
        let commit_request = grpc::OramCommitRequest {
            collection_name: COLLECTION_NAME.to_string(),
            vector_name: VECTOR_NAME.to_string(),
            session_id: SESSION_ID.to_string(),
            old_epoch: commit_plan.old_epoch,
            new_epoch: commit_plan.new_epoch,
            old_root_hash: commit_plan.old_root_hash.clone(),
            new_root_hash: commit_plan.new_root_hash.clone(),
            updated_buckets: updated_buckets.into_iter().map(bucket_to_proto).collect(),
            commit_signature: Some(signature_to_proto(commit_signature.clone())),
        };
        assert_eq!(commit_request.old_epoch, BASE_EPOCH);
        assert_eq!(commit_request.new_epoch, NEXT_EPOCH);
        assert_eq!(
            common_signature_from_proto(
                required(commit_request.commit_signature, "commit_signature").unwrap()
            )
            .sig,
            commit_signature.sig
        );
        let restored_commit_buckets = commit_request
            .updated_buckets
            .into_iter()
            .map(bucket_from_proto)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(!restored_commit_buckets.is_empty());
    }

    #[test]
    fn grpc_rejects_unsafe_configured_private_hnsw_vector_name_without_reflecting_it() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        let unsafe_vector_name = "secret vector sentinel";
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_vector_name(&dispatcher, unsafe_vector_name).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            let err = PrivateHnswOram::get_private_hnsw_manifest(
                &service,
                Request::new(grpc::GetPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: unsafe_vector_name.to_string(),
                }),
            )
            .await
            .unwrap_err();

            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message().contains("safe store path component"),
                "{}",
                err.message()
            );
            assert!(!err.message().contains(unsafe_vector_name));
            assert!(!err.message().contains("secret"));
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
        });
    }

    #[test]
    fn sdk_fixture_uploads_reads_and_commits_through_grpc_service() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let mut settings = fixture.route_settings();
        let alternate_manifest_key_id = "tenant-a/private-hnsw-signing-v2";
        settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["signature_public_keys"][alternate_manifest_key_id] =
            serde_json::json!(BASE64URL_NOPAD.encode(&[19_u8; 32]));
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            let err = PrivateHnswOram::get_private_hnsw_manifest(
                &service,
                Request::new(grpc::GetPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::NotFound);
            assert!(err.message().contains("manifest"));
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));

            let upload_root_before_manifest_sentinel = "AAAA";
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: upload_root_before_manifest_sentinel.to_string(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("root_hash must encode 32 bytes"));
            assert!(
                !err.message().contains(upload_root_before_manifest_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains("private_hnsw_oram"),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("manifest"), "{}", err.message());

            let malformed_bucket_hash_before_manifest_sentinel = "hnsw-grpc-upload-hash-sentinel";
            let mut malformed_bucket_hash_before_manifest_buckets =
                fixture.encrypted_build.buckets.clone();
            malformed_bucket_hash_before_manifest_buckets[0].ciphertext_sha256 =
                malformed_bucket_hash_before_manifest_sentinel.to_string();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: malformed_bucket_hash_before_manifest_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("ciphertext_sha256"));
            assert!(
                !err.message()
                    .contains(malformed_bucket_hash_before_manifest_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&fixture.encrypted_build.root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains("private_hnsw_oram"),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("manifest"), "{}", err.message());

            let malformed_bucket_commitment_before_manifest_sentinel =
                "hnsw-grpc-upload-commitment-sentinel";
            let mut malformed_bucket_commitment_before_manifest_buckets =
                fixture.encrypted_build.buckets.clone();
            malformed_bucket_commitment_before_manifest_buckets[0].bucket_commitment =
                malformed_bucket_commitment_before_manifest_sentinel.to_string();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: malformed_bucket_commitment_before_manifest_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("bucket_commitment"));
            assert!(
                !err.message()
                    .contains(malformed_bucket_commitment_before_manifest_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&fixture.encrypted_build.root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains("private_hnsw_oram"),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("manifest"), "{}", err.message());

            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::NotFound);
            assert!(err.message().contains("manifest"));
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));

            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: Vec::new(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("bucket upload must contain"));
            assert!(
                !err.message().contains(&fixture.encrypted_build.root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains("private_hnsw_oram"),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("manifest"), "{}", err.message());

            let mut duplicate_upload_before_manifest_buckets =
                fixture.encrypted_build.buckets.clone();
            assert!(
                duplicate_upload_before_manifest_buckets.len() >= 2,
                "route fixture must contain at least two ORAM buckets"
            );
            duplicate_upload_before_manifest_buckets[1] =
                duplicate_upload_before_manifest_buckets[0].clone();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: duplicate_upload_before_manifest_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("duplicate bucket"));
            assert!(
                !err.message().contains(&fixture.encrypted_build.root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains("private_hnsw_oram"),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("manifest"), "{}", err.message());

            let before_manifest_client_id = "tenant-a/sdk-instance-before-manifest";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: before_manifest_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::NotFound);
            assert!(err.message().contains("manifest"));
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            assert!(!err.message().contains(before_manifest_client_id));

            let auth = Auth::new_internal(Access::full("private HNSW ORAM manifest grpc test"));
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new(),
                    "private_hnsw_manifest_upload_layout_test",
                )
                .unwrap();
            let pass = new_unchecked_verification_pass();
            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let manifest_store = PrivateHnswOramStore::new(collection.path(), VECTOR_NAME).unwrap();
            let manifest_parent = manifest_store.root_path().parent().unwrap();
            std::fs::create_dir_all(manifest_parent).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                std::fs::set_permissions(manifest_parent, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            std::fs::write(manifest_store.root_path(), b"not-a-directory").unwrap();
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::Internal);
            assert!(err.message().contains("manifest store validation failed"));
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            std::fs::remove_file(manifest_store.root_path()).unwrap();

            let mut mismatched_collection_manifest = fixture.manifest.clone();
            mismatched_collection_manifest.collection_id = "other-collection".to_string();
            let mismatched_collection_signature =
                fixture.sign_manifest(&mismatched_collection_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_collection_manifest)),
                    signature: Some(signature_to_proto(mismatched_collection_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));

            let mut mismatched_vector_manifest = fixture.manifest.clone();
            mismatched_vector_manifest.vector_name = "title".to_string();
            let mismatched_vector_signature = fixture.sign_manifest(&mismatched_vector_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_vector_manifest)),
                    signature: Some(signature_to_proto(mismatched_vector_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));

            let mut mismatched_key_manifest = fixture.manifest.clone();
            mismatched_key_manifest.key_id = "tenant-b/vector-private-rk".to_string();
            let mismatched_key_signature = fixture.sign_manifest(&mismatched_key_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_key_manifest)),
                    signature: Some(signature_to_proto(mismatched_key_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));

            let mut mismatched_epoch_manifest = fixture.manifest.clone();
            mismatched_epoch_manifest.rk_epoch += 1;
            let mismatched_epoch_signature = fixture.sign_manifest(&mismatched_epoch_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_epoch_manifest)),
                    signature: Some(signature_to_proto(mismatched_epoch_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));

            let mut mismatched_dim_manifest = fixture.manifest.clone();
            mismatched_dim_manifest.dim += 1;
            let mismatched_dim_signature = fixture.sign_manifest(&mismatched_dim_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_dim_manifest)),
                    signature: Some(signature_to_proto(mismatched_dim_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));

            let mut mismatched_distance_manifest = fixture.manifest.clone();
            mismatched_distance_manifest.distance = DistanceKind::Cosine;
            let mismatched_distance_signature =
                fixture.sign_manifest(&mismatched_distance_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_distance_manifest)),
                    signature: Some(signature_to_proto(mismatched_distance_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert!(!err.message().contains("Cosine"));
            assert!(!err.message().contains("cosine"));

            let mut mismatched_bucket_count_manifest = fixture.manifest.clone();
            mismatched_bucket_count_manifest.bucket_count -= 1;
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_bucket_count_manifest)),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));

            let mut mismatched_privacy_manifest = fixture.manifest.clone();
            mismatched_privacy_manifest.result_privacy =
                ResultPrivacyMode::PrivatePayloadOramRequired;
            let mismatched_privacy_signature = fixture.sign_manifest(&mismatched_privacy_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_privacy_manifest)),
                    signature: Some(signature_to_proto(mismatched_privacy_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest result_privacy does not match runtime instance")
            );

            let mut mismatched_hnsw_manifest = fixture.manifest.clone();
            mismatched_hnsw_manifest.hnsw.m = 3;
            let mismatched_hnsw_signature = fixture.sign_manifest(&mismatched_hnsw_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_hnsw_manifest)),
                    signature: Some(signature_to_proto(mismatched_hnsw_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest hnsw does not match runtime instance")
            );

            let mut mismatched_oram_manifest = fixture.manifest.clone();
            mismatched_oram_manifest.oram.bucket_size = 4;
            let mismatched_oram_signature = fixture.sign_manifest(&mismatched_oram_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_oram_manifest)),
                    signature: Some(signature_to_proto(mismatched_oram_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest oram does not match runtime instance")
            );

            let mut mismatched_fixed_budget_manifest = fixture.manifest.clone();
            mismatched_fixed_budget_manifest.fixed_budget.fixed_result_k = 2;
            let mismatched_fixed_budget_signature =
                fixture.sign_manifest(&mismatched_fixed_budget_manifest);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(mismatched_fixed_budget_manifest)),
                    signature: Some(signature_to_proto(mismatched_fixed_budget_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest fixed_budget does not match runtime instance")
            );

            let signature_key_id_sentinel = "signature-key-id-sentinel";
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(grpc::PrivateHnswSignature {
                        alg: "ed25519".to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: fixture.manifest_signature.sig.clone(),
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(signature_key_id_sentinel),
                "{}",
                err.message()
            );

            let mut alternate_manifest_signature = fixture.manifest_signature.clone();
            alternate_manifest_signature.key_id = alternate_manifest_key_id.to_string();
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(alternate_manifest_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(alternate_manifest_key_id),
                "{}",
                err.message()
            );

            let manifest_signature_alg_sentinel = "manifest-signature-alg-sentinel";
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(grpc::PrivateHnswSignature {
                        alg: manifest_signature_alg_sentinel.to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: fixture.manifest_signature.sig.clone(),
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature algorithm must be ed25519")
            );
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(signature_key_id_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(manifest_signature_alg_sentinel),
                "{}",
                err.message()
            );

            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(grpc::PrivateHnswSignature {
                        alg: manifest_signature_alg_sentinel.to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: fixture.manifest_signature.sig.clone(),
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature algorithm must be ed25519")
            );
            assert!(
                !err.message().contains(manifest_signature_alg_sentinel),
                "{}",
                err.message()
            );

            let manifest_signature_sentinel = "manifest-signature!sentinel";
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(grpc::PrivateHnswSignature {
                        alg: "ed25519".to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: manifest_signature_sentinel.to_string(),
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(signature_key_id_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(manifest_signature_sentinel),
                "{}",
                err.message()
            );

            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(grpc::PrivateHnswSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: manifest_signature_sentinel.to_string(),
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert!(
                !err.message().contains(manifest_signature_sentinel),
                "{}",
                err.message()
            );

            let mut bad_manifest_signature = fixture.manifest_signature.clone();
            let replacement = if bad_manifest_signature.sig.starts_with('A') {
                "B"
            } else {
                "A"
            };
            bad_manifest_signature.sig.replace_range(0..1, replacement);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(bad_manifest_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));

            let manifest_epoch = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(manifest_epoch.index_epoch, BASE_EPOCH);
            assert_eq!(manifest_epoch.root_hash, fixture.encrypted_build.root_hash);
            let manifest_read = PrivateHnswOram::get_private_hnsw_manifest(
                &service,
                Request::new(grpc::GetPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(
                manifest_from_proto(required(manifest_read.manifest, "manifest").unwrap()).unwrap(),
                fixture.manifest,
            );
            assert_eq!(
                common_signature_from_proto(
                    required(manifest_read.signature, "signature").unwrap()
                )
                .sig,
                fixture.manifest_signature.sig,
            );
            let manifest_only_client_id = "tenant-a/sdk-instance-manifest-only";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: manifest_only_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::NotFound);
            assert!(
                err.message()
                    .contains("encrypted bucket data is unavailable")
            );
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            assert!(!err.message().contains(manifest_only_client_id));

            std::fs::write(manifest_store.root_path().join("manifest.json"), b"{").unwrap();
            let err = PrivateHnswOram::get_private_hnsw_manifest(
                &service,
                Request::new(grpc::GetPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("manifest store validation failed"));
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            manifest_store
                .write_manifest(&fixture.manifest, &fixture.manifest_signature)
                .unwrap();

            let current_epoch_path = manifest_store
                .root_path()
                .join("epochs")
                .join("current.json");
            let current_epoch_json = serde_json::to_vec_pretty(&PrivateHnswOramEpochState {
                index_epoch: BASE_EPOCH,
                root_hash: fixture.encrypted_build.root_hash.clone(),
            })
            .unwrap();
            std::fs::write(&current_epoch_path, b"{").unwrap();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("current epoch validation failed"));
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            std::fs::write(&current_epoch_path, &current_epoch_json).unwrap();

            let bucket_upload_wrong_root = BASE64URL_NOPAD.encode(&[9; 32]);
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: bucket_upload_wrong_root.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("bucket upload epoch/root does not match current manifest epoch")
            );
            assert!(
                !err.message().contains(&bucket_upload_wrong_root),
                "{}",
                err.message()
            );

            let bucket_upload_root_sentinel = "AAAA";
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: bucket_upload_root_sentinel.to_string(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("root_hash must encode 32 bytes"));
            assert!(
                !err.message().contains(bucket_upload_root_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains("bucket upload epoch/root does not match current manifest epoch"),
                "{}",
                err.message()
            );

            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: Vec::new(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("bucket upload must contain"));
            assert!(
                !err.message().contains(&fixture.encrypted_build.root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains("private_hnsw_oram"),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("manifest"), "{}", err.message());

            let mut hash_mismatch_buckets = fixture.encrypted_build.buckets.clone();
            let replacement = if hash_mismatch_buckets[0].ciphertext_sha256.starts_with('A') {
                "B"
            } else {
                "A"
            };
            hash_mismatch_buckets[0]
                .ciphertext_sha256
                .replace_range(0..1, replacement);
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: hash_mismatch_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("encrypted bucket store validation failed")
            );
            assert!(
                !err.message()
                    .contains(&hash_mismatch_buckets[0].ciphertext_sha256)
            );

            let mut merkle_mismatch_buckets = fixture.encrypted_build.buckets.clone();
            merkle_mismatch_buckets[0].bucket_commitment =
                data_encoding::BASE64URL_NOPAD.encode(&[9; 32]);
            let computed_mismatch_root = qdrant_sec::private_hnsw_oram_merkle_root_for_commitments(
                &merkle_mismatch_buckets
                    .iter()
                    .map(|bucket| bucket.bucket_commitment.clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert_ne!(computed_mismatch_root, fixture.encrypted_build.root_hash);
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: merkle_mismatch_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("initial upload bucket commitment context mismatch")
            );
            assert!(
                !err.message().contains(&computed_mismatch_root),
                "{}",
                err.message()
            );

            let upload_ciphertext_sentinel = "bucket-upload-ciphertext-sentinel";
            let mut malformed_upload_buckets = fixture.encrypted_build.buckets.clone();
            malformed_upload_buckets[0].ciphertext = upload_ciphertext_sentinel.to_string();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: malformed_upload_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("encrypted bucket store validation failed")
            );
            assert!(
                !err.message().contains(upload_ciphertext_sentinel),
                "{}",
                err.message()
            );

            let first_upload_bucket_path = manifest_store
                .root_path()
                .join("buckets")
                .join("00000000.bucket");
            assert!(
                !first_upload_bucket_path.exists(),
                "failed upload tests should not write bucket files before full preflight"
            );
            let late_upload_ciphertext_sentinel = "bucket-upload-late-ciphertext-sentinel";
            let mut late_malformed_upload_buckets = fixture.encrypted_build.buckets.clone();
            late_malformed_upload_buckets[1].ciphertext =
                late_upload_ciphertext_sentinel.to_string();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: late_malformed_upload_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("encrypted bucket store validation failed")
            );
            assert!(
                !err.message().contains(late_upload_ciphertext_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !first_upload_bucket_path.exists(),
                "bucket upload must preflight all bucket bodies before writing any bucket file"
            );

            let mut missing_bucket_set = fixture.encrypted_build.buckets.clone();
            missing_bucket_set.pop();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: missing_bucket_set
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("configured bucket count"));

            let mut duplicate_bucket_set = fixture.encrypted_build.buckets.clone();
            assert!(
                duplicate_bucket_set.len() >= 2,
                "route fixture must contain at least two ORAM buckets"
            );
            duplicate_bucket_set[1] = duplicate_bucket_set[0].clone();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: duplicate_bucket_set
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("duplicate bucket"));
            assert!(
                !err.message().contains(&fixture.encrypted_build.root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains("private_hnsw_oram"),
                "{}",
                err.message()
            );

            let auth = Auth::new_internal(Access::full("private HNSW ORAM upload grpc test"));
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new(),
                    "private_hnsw_bucket_upload_layout_test",
                )
                .unwrap();
            let pass = new_unchecked_verification_pass();
            let collection = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await
                .unwrap();
            let upload_store = PrivateHnswOramStore::new(collection.path(), VECTOR_NAME).unwrap();
            let upload_buckets_path = upload_store.root_path().join("buckets");
            std::fs::remove_dir_all(&upload_buckets_path).unwrap();
            std::fs::write(&upload_buckets_path, b"not-a-directory").unwrap();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::Internal);
            assert!(
                err.message()
                    .contains("encrypted bucket store validation failed")
            );
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            std::fs::remove_file(&upload_buckets_path).unwrap();
            upload_store.ensure_layout().unwrap();

            let bucket_epoch = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
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

            std::fs::write(&current_epoch_path, b"{").unwrap();
            let corrupt_epoch_client_id = "tenant-a/sdk-instance-corrupt-epoch";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: corrupt_epoch_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("current epoch validation failed"));
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            assert!(!err.message().contains(corrupt_epoch_client_id));
            std::fs::write(&current_epoch_path, &current_epoch_json).unwrap();

            let client_id_sentinel = "session-client-id-sentinel";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: format!("{client_id_sentinel}{}", "x".repeat(260)),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("client_id must be non-empty and at most 256 bytes")
            );
            assert!(
                !err.message().contains(client_id_sentinel),
                "{}",
                err.message()
            );

            let malformed_client_id_sentinel = "session-client-id!sentinel";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: malformed_client_id_sentinel.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("client_id is invalid"));
            assert!(
                !err.message().contains(malformed_client_id_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains("client_id must be non-empty and at most 256 bytes"),
                "{}",
                err.message()
            );

            let fixed_budget_client_id = "tenant-a/sdk-instance-fixed-budget-off";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: fixed_budget_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: false,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("strict mode requires fixed_budget=true")
            );
            assert!(
                !err.message().contains(fixed_budget_client_id),
                "{}",
                err.message()
            );

            let stale_epoch_client_id = "tenant-a/sdk-instance-stale-epoch";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: stale_epoch_client_id.to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("requested epoch"));
            assert!(!err.message().contains(&NEXT_EPOCH.to_string()));
            assert!(!err.message().contains(&BASE_EPOCH.to_string()));
            assert!(!err.message().contains(stale_epoch_client_id));

            let result_privacy_client_id = "tenant-a/sdk-instance-private-result";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: result_privacy_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(
                        ResultPrivacyMode::PrivatePayloadOramRequired,
                    ),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("requested result_privacy does not match manifest")
            );
            assert!(!err.message().contains(result_privacy_client_id));

            let auth = Auth::new_internal(Access::full("private HNSW ORAM grpc test"));
            let collection_pass = auth
                .check_collection_access(
                    COLLECTION_NAME,
                    AccessRequirements::new(),
                    "private_hnsw_active_session_upload_guard_test",
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
                crate::common::private_hnsw::begin_private_hnsw_collection_snapshot(
                    collection.name(),
                    &config,
                )
                .unwrap()
                .unwrap();
            let active_snapshot_client_id = "tenant-a/sdk-instance-active-snapshot";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: active_snapshot_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("active collection snapshot"));
            assert!(!err.message().contains(&fixture.encrypted_build.root_hash));
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains(active_snapshot_client_id));
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("active collection snapshot"));
            assert!(!err.message().contains(&fixture.manifest.root_hash));
            assert!(!err.message().contains("private_hnsw_oram"));
            let mut active_snapshot_bucket_upload = fixture.encrypted_build.buckets.clone();
            active_snapshot_bucket_upload[0].ciphertext =
                "active-snapshot-bucket-upload-ciphertext-sentinel".to_string();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: active_snapshot_bucket_upload
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("active collection snapshot"));
            assert!(
                !err.message()
                    .contains("active-snapshot-bucket-upload-ciphertext-sentinel")
            );
            assert!(
                !err.message().contains(&fixture.encrypted_build.root_hash),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("private_hnsw_oram"));
            drop(snapshot_guard);

            let session = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(session.collection_id, COLLECTION_ID);
            assert_eq!(session.index_epoch, BASE_EPOCH);
            let uploaded_store = PrivateHnswOramStore::new(collection.path(), VECTOR_NAME).unwrap();
            let search_run = fixture.run_single_search_collect_writeback();

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
                !active_snapshot_error.contains(&fixture.encrypted_build.root_hash),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains(&session.session_id),
                "{active_snapshot_error}"
            );
            assert!(
                !active_snapshot_error.contains("private_hnsw_oram"),
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
                !active_full_snapshot_error.contains(&fixture.encrypted_build.root_hash),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains(&session.session_id),
                "{active_full_snapshot_error}"
            );
            assert!(
                !active_full_snapshot_error.contains("private_hnsw_oram"),
                "{active_full_snapshot_error}"
            );

            let duplicate_session_client_id = "tenant-a/sdk-instance-2";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: duplicate_session_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("ConcurrentWriter"));
            assert!(!err.message().contains(duplicate_session_client_id));

            let (refreshed_manifest, refreshed_signature) =
                fixture.sign_manifest_refresh(&search_run.commit_plan);
            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(refreshed_manifest.clone())),
                    signature: Some(signature_to_proto(refreshed_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("requires no active session"));
            assert!(
                !err.message().contains(&refreshed_manifest.root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&session.session_id),
                "{}",
                err.message()
            );
            assert_eq!(
                uploaded_store.read_manifest().unwrap(),
                (fixture.manifest.clone(), fixture.manifest_signature.clone())
            );

            let mut active_guard_bucket_upload = fixture.encrypted_build.buckets.clone();
            active_guard_bucket_upload[0].ciphertext =
                "active-session-bucket-upload-ciphertext-sentinel".to_string();
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: active_guard_bucket_upload
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("requires no active session"));
            assert!(
                !err.message()
                    .contains("active-session-bucket-upload-ciphertext-sentinel"),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&fixture.encrypted_build.root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&session.session_id),
                "{}",
                err.message()
            );
            assert_eq!(
                uploaded_store
                    .read_bucket(
                        fixture.encrypted_build.buckets[0].bucket_id,
                        BASE_EPOCH,
                        fixture.encrypted_build.bucket_count,
                        MAX_CIPHERTEXT_BYTES,
                    )
                    .unwrap(),
                fixture.encrypted_build.buckets[0]
            );

            let epoch_root_mismatch_paths = vec![fixture.entry_leaf_label()];
            let epoch_root_mismatch_signature =
                fixture.sign_read_paths(&epoch_root_mismatch_paths, 1, true);
            let read_wrong_root = BASE64URL_NOPAD.encode(&[9; 32]);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: read_wrong_root.clone(),
                    paths: epoch_root_mismatch_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(epoch_root_mismatch_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("session epoch/root mismatch"));
            assert!(
                !err.message().contains(&read_wrong_root),
                "{}",
                err.message()
            );

            let malformed_read_root_sentinel = "AAAA";
            let malformed_read_root_paths = vec![fixture.entry_leaf_label()];
            let malformed_read_root_signature =
                fixture.sign_read_paths(&malformed_read_root_paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: malformed_read_root_sentinel.to_string(),
                    paths: malformed_read_root_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(malformed_read_root_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("root_hash must encode 32 bytes"));
            assert!(
                !err.message().contains(malformed_read_root_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains("session epoch/root mismatch"),
                "{}",
                err.message()
            );

            let path_label_sentinel = "qdrant-sec-private-hnsw-path-label-sentinel";
            let sentinel_paths = vec![path_label_sentinel.to_string()];
            let sentinel_signature = fixture.client_signature();
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: sentinel_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(sentinel_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert!(!err.message().contains(path_label_sentinel));
            assert!(
                !err.message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext)
            );
            let unauthenticated_path_label_sentinel = fixture.entry_leaf_label();
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![unauthenticated_path_label_sentinel.clone()],
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert!(!err.message().contains("leaf label"));
            assert!(
                !err.message().contains(&unauthenticated_path_label_sentinel),
                "{}",
                err.message()
            );
            let wrong_budget_paths = vec![fixture.entry_leaf_label()];
            let wrong_budget_signature = fixture.client_signature();
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: wrong_budget_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(wrong_budget_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("fixed path budget"));

            let missing_dummy_paths = vec![fixture.entry_leaf_label()];
            let missing_dummy_signature = fixture.client_signature();
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: missing_dummy_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: false,
                    }),
                    client_signature: Some(signature_to_proto(missing_dummy_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("fixed path budget"));

            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![fixture.entry_leaf_label()],
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));

            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![fixture.entry_leaf_label()],
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(grpc::PrivateHnswSignature {
                        alg: "ed25519".to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: fixture.client_signature().sig,
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(signature_key_id_sentinel),
                "{}",
                err.message()
            );

            let invalid_read_key_id_sentinel = "read-signature-key!sentinel";
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![fixture.entry_leaf_label()],
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(grpc::PrivateHnswSignature {
                        alg: "ed25519".to_string(),
                        key_id: invalid_read_key_id_sentinel.to_string(),
                        sig: fixture.client_signature().sig,
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("signature key_id is invalid"));
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(invalid_read_key_id_sentinel),
                "{}",
                err.message()
            );

            let signature_body_sentinel = "signature!sentinel";
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: vec![fixture.entry_leaf_label()],
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(grpc::PrivateHnswSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: signature_body_sentinel.to_string(),
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("signature must encode 64 bytes"));
            assert!(
                !err.message().contains(signature_body_sentinel),
                "{}",
                err.message()
            );

            let read_signature_alg_sentinel = "rsa-pss-hnsw-read-sentinel";
            let unsupported_read_paths = vec![fixture.entry_leaf_label()];
            let mut unsupported_read_signature =
                fixture.sign_read_paths(&unsupported_read_paths, 1, true);
            unsupported_read_signature.alg = read_signature_alg_sentinel.to_string();
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: unsupported_read_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(unsupported_read_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature algorithm must be ed25519")
            );
            assert!(
                !err.message().contains(read_signature_alg_sentinel),
                "{}",
                err.message()
            );

            let unknown_read_session_sentinel = "read-session-id-sentinel";
            let unknown_read_paths = vec![fixture.entry_leaf_label()];
            let unknown_read_signature = fixture.sign_read_paths(&unknown_read_paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: unknown_read_session_sentinel.to_string(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: unknown_read_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(unknown_read_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("session is missing or expired"));
            assert!(
                !err.message().contains(unknown_read_session_sentinel),
                "{}",
                err.message()
            );

            let oversized_read_session_id = "s".repeat(129);
            let malformed_read_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_read_session_id.as_str(),
                malformed_read_session_id,
            ] {
                let read_paths = vec![fixture.entry_leaf_label()];
                let read_signature = fixture.sign_read_paths(&read_paths, 1, true);
                let err = PrivateHnswOram::read_private_hnsw_paths(
                    &service,
                    Request::new(grpc::OramReadPathsRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        vector_name: VECTOR_NAME.to_string(),
                        session_id: invalid_session_id.to_string(),
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                        paths: read_paths,
                        padding: Some(grpc::OramReadPadding {
                            requested_paths: 1,
                            dummy_paths_included: true,
                        }),
                        client_signature: Some(signature_to_proto(read_signature)),
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

            let read_paths = vec![fixture.entry_leaf_label()];
            let read_signature = fixture.sign_read_paths(&read_paths, 1, true);
            let read_response = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: read_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(read_signature)),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            let proof = read_response.proof.unwrap();
            assert_eq!(proof.kind, fixture.proof_kind());
            let read_buckets = read_response
                .buckets
                .into_iter()
                .map(bucket_from_proto)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let opened_buckets = open_private_hnsw_oram_verified_path_batch(
                &fixture.keys,
                fixture.base_context,
                fixture.config,
                BASE_EPOCH,
                &fixture.encrypted_build.root_hash,
                fixture.encrypted_build.bucket_count,
                &proof.value,
                &read_buckets,
            )
            .unwrap();
            assert!(!opened_buckets.is_empty());

            let missing_bucket_id = read_buckets[0].bucket_id;
            let bucket_path = uploaded_store
                .root_path()
                .join("buckets")
                .join(format!("{missing_bucket_id:08}.bucket"));
            let original_bucket_bytes = std::fs::read(&bucket_path).unwrap();
            let mut mismatched_bucket = read_buckets[0].clone();
            mismatched_bucket.bucket_id =
                (missing_bucket_id + 1) % fixture.encrypted_build.bucket_count;
            mismatched_bucket.ciphertext =
                "private-hnsw-route-bucket-ciphertext-sentinel".to_string();
            std::fs::write(
                &bucket_path,
                serde_json::to_vec_pretty(&mismatched_bucket).unwrap(),
            )
            .unwrap();

            let mismatched_bucket_paths = vec![fixture.entry_leaf_label()];
            let mismatched_bucket_signature =
                fixture.sign_read_paths(&mismatched_bucket_paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: mismatched_bucket_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(mismatched_bucket_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::Internal);
            assert!(
                err.message()
                    .contains("encrypted bucket store validation failed")
            );
            assert!(
                !err.message()
                    .contains("private-hnsw-route-bucket-ciphertext-sentinel"),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&mismatched_bucket.ciphertext),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("private_hnsw_oram"));
            std::fs::write(&bucket_path, &original_bucket_bytes).unwrap();

            let mut proof_mismatched_bucket = read_buckets[0].clone();
            proof_mismatched_bucket.bucket_commitment =
                data_encoding::BASE64URL_NOPAD.encode(&[91; 32]);
            std::fs::write(
                &bucket_path,
                serde_json::to_vec_pretty(&proof_mismatched_bucket).unwrap(),
            )
            .unwrap();
            let proof_mismatch_paths = vec![fixture.entry_leaf_label()];
            let proof_mismatch_signature = fixture.sign_read_paths(&proof_mismatch_paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: proof_mismatch_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(proof_mismatch_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("bucket/proof consistency validation failed")
            );
            assert!(
                !err.message().contains(&proof_mismatched_bucket.ciphertext),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            std::fs::write(&bucket_path, &original_bucket_bytes).unwrap();

            let current_epoch_path = uploaded_store
                .root_path()
                .join("epochs")
                .join("current.json");
            let original_current_epoch_bytes = std::fs::read(&current_epoch_path).unwrap();
            let stale_current_root = data_encoding::BASE64URL_NOPAD.encode(&[88; 32]);
            std::fs::write(
                &current_epoch_path,
                serde_json::to_vec_pretty(&PrivateHnswOramEpochState {
                    index_epoch: BASE_EPOCH,
                    root_hash: stale_current_root.clone(),
                })
                .unwrap(),
            )
            .unwrap();
            let stale_current_read_paths = vec![fixture.entry_leaf_label()];
            let stale_current_read_signature =
                fixture.sign_read_paths(&stale_current_read_paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: stale_current_read_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(stale_current_read_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("read_paths current epoch/root does not match active session")
            );
            assert!(
                !err.message().contains(&stale_current_root),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(search_run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("commit current epoch/root does not match active session")
            );
            assert!(
                !err.message().contains(&stale_current_root),
                "{}",
                err.message()
            );
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            std::fs::write(&current_epoch_path, original_current_epoch_bytes).unwrap();
            let original_writeback_bucket = fixture
                .encrypted_build
                .buckets
                .iter()
                .find(|bucket| bucket.bucket_id == search_run.updated_buckets[0].bucket_id)
                .unwrap();
            let stored_writeback_bucket = uploaded_store
                .read_bucket(
                    search_run.updated_buckets[0].bucket_id,
                    BASE_EPOCH,
                    fixture.encrypted_build.bucket_count,
                    MAX_CIPHERTEXT_BYTES,
                )
                .unwrap();
            assert_eq!(&stored_writeback_bucket, original_writeback_bucket);
            let assert_pre_commit_state_unchanged = || {
                assert_eq!(
                    uploaded_store.read_current_epoch().unwrap(),
                    PrivateHnswOramEpochState {
                        index_epoch: BASE_EPOCH,
                        root_hash: fixture.encrypted_build.root_hash.clone(),
                    }
                );
                let stored_writeback_bucket = uploaded_store
                    .read_bucket(
                        search_run.updated_buckets[0].bucket_id,
                        BASE_EPOCH,
                        fixture.encrypted_build.bucket_count,
                        MAX_CIPHERTEXT_BYTES,
                    )
                    .unwrap();
                assert_eq!(&stored_writeback_bucket, original_writeback_bucket);
            };
            assert_pre_commit_state_unchanged();

            std::fs::remove_file(&bucket_path).unwrap();

            let missing_bucket_paths = vec![fixture.entry_leaf_label()];
            let missing_bucket_signature = fixture.sign_read_paths(&missing_bucket_paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: missing_bucket_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(missing_bucket_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::NotFound);
            assert!(
                err.message()
                    .contains("encrypted bucket data is unavailable")
            );
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            let original_missing_bucket = fixture
                .encrypted_build
                .buckets
                .iter()
                .find(|bucket| bucket.bucket_id == missing_bucket_id)
                .unwrap();
            uploaded_store
                .write_bucket(
                    original_missing_bucket,
                    BASE_EPOCH,
                    fixture.encrypted_build.bucket_count,
                    MAX_CIPHERTEXT_BYTES,
                )
                .unwrap();
            assert_pre_commit_state_unchanged();

            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(grpc::PrivateHnswSignature {
                        alg: "ed25519".to_string(),
                        key_id: signature_key_id_sentinel.to_string(),
                        sig: fixture.client_signature().sig,
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(signature_key_id_sentinel),
                "{}",
                err.message()
            );

            let invalid_commit_key_id_sentinel = "commit-signature-key!sentinel";
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(grpc::PrivateHnswSignature {
                        alg: "ed25519".to_string(),
                        key_id: invalid_commit_key_id_sentinel.to_string(),
                        sig: fixture.client_signature().sig,
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("signature key_id is invalid"));
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(invalid_commit_key_id_sentinel),
                "{}",
                err.message()
            );

            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(grpc::PrivateHnswSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: signature_body_sentinel.to_string(),
                    }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("signature must encode 64 bytes"));
            assert!(
                !err.message().contains(signature_body_sentinel),
                "{}",
                err.message()
            );

            let commit_signature_alg_sentinel = "rsa-pss-hnsw-commit-sentinel";
            let mut unsupported_commit_signature = search_run.commit_signature.clone();
            unsupported_commit_signature.alg = commit_signature_alg_sentinel.to_string();
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(unsupported_commit_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature algorithm must be ed25519")
            );
            assert!(
                !err.message().contains(commit_signature_alg_sentinel),
                "{}",
                err.message()
            );

            let unknown_commit_session_sentinel = "commit-session-id-sentinel";
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: unknown_commit_session_sentinel.to_string(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(search_run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("session is missing or expired"));
            assert!(
                !err.message().contains(unknown_commit_session_sentinel),
                "{}",
                err.message()
            );

            let oversized_commit_session_id = "s".repeat(129);
            let malformed_commit_session_id = "bad/session-id";
            for invalid_session_id in [
                oversized_commit_session_id.as_str(),
                malformed_commit_session_id,
            ] {
                let err = PrivateHnswOram::commit_private_hnsw_paths(
                    &service,
                    Request::new(grpc::OramCommitRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        vector_name: VECTOR_NAME.to_string(),
                        session_id: invalid_session_id.to_string(),
                        old_epoch: BASE_EPOCH,
                        new_epoch: NEXT_EPOCH,
                        old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                        new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                        updated_buckets: search_run
                            .updated_buckets
                            .clone()
                            .into_iter()
                            .map(bucket_to_proto)
                            .collect(),
                        commit_signature: Some(signature_to_proto(
                            search_run.commit_signature.clone(),
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

            let commit_wrong_old_root = BASE64URL_NOPAD.encode(&[9; 32]);
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_wrong_old_root.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("commit old epoch/root does not match active session")
            );
            assert!(
                !err.message().contains(&commit_wrong_old_root),
                "{}",
                err.message()
            );

            let commit_old_root_sentinel = "AAAA";
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: commit_old_root_sentinel.to_string(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("old_root_hash must encode 32 bytes"));
            assert!(
                !err.message().contains(commit_old_root_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains("commit old epoch/root does not match active session"),
                "{}",
                err.message()
            );

            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: BASE_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("new_epoch must be greater than old_epoch")
            );

            let commit_new_root_sentinel = "AAAA";
            let commit_wrong_new_root = BASE64URL_NOPAD.encode(&[17; 32]);
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: commit_wrong_new_root.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert!(!err.message().contains("new_root_hash"));
            assert!(
                !err.message().contains(&commit_wrong_new_root),
                "{}",
                err.message()
            );

            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: commit_new_root_sentinel.to_string(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("new_root_hash must encode 32 bytes"));
            assert!(
                !err.message().contains(commit_new_root_sentinel),
                "{}",
                err.message()
            );

            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: Vec::new(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("updated_buckets must contain"));

            let commit_hash_sentinel = "AAAA";
            let mut malformed_hash_buckets = search_run.updated_buckets.clone();
            malformed_hash_buckets[0].ciphertext_sha256 = commit_hash_sentinel.to_string();
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: malformed_hash_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("ciphertext_sha256"));
            assert!(
                !err.message().contains(commit_hash_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&search_run.commit_plan.old_root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&search_run.commit_plan.new_root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&search_run.updated_buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&fixture.client_signature().sig),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains("commit signature verification failed"),
                "{}",
                err.message()
            );

            let commit_commitment_sentinel = "AAAA";
            let mut malformed_commitment_buckets = search_run.updated_buckets.clone();
            malformed_commitment_buckets[0].bucket_commitment =
                commit_commitment_sentinel.to_string();
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: malformed_commitment_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("bucket_commitment"));
            assert!(
                !err.message().contains(commit_commitment_sentinel),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&search_run.commit_plan.old_root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&search_run.commit_plan.new_root_hash),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains(&search_run.updated_buckets[0].ciphertext),
                "{}",
                err.message()
            );
            assert!(
                !err.message().contains(&fixture.client_signature().sig),
                "{}",
                err.message()
            );
            assert!(
                !err.message()
                    .contains("commit signature verification failed"),
                "{}",
                err.message()
            );

            let duplicate_commit_bucket = search_run.updated_buckets[0].clone();
            let duplicate_commit_buckets = vec![
                duplicate_commit_bucket.clone(),
                duplicate_commit_bucket.clone(),
            ];
            let duplicate_commit_plan = qdrant_sec::PrivateHnswClientCommitPlan {
                old_epoch: BASE_EPOCH,
                new_epoch: NEXT_EPOCH,
                old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                leaf_commitments: search_run.commit_plan.leaf_commitments.clone(),
                updated_buckets: duplicate_commit_buckets
                    .iter()
                    .map(|bucket| qdrant_sec::PrivateHnswClientCommitBucketRef {
                        bucket_id: bucket.bucket_id,
                        ciphertext_sha256: bucket.ciphertext_sha256.clone(),
                    })
                    .collect(),
            };
            let duplicate_commit_signature = fixture.sign_commit_unchecked(&duplicate_commit_plan);
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: duplicate_commit_plan.old_root_hash,
                    new_root_hash: duplicate_commit_plan.new_root_hash,
                    updated_buckets: duplicate_commit_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(duplicate_commit_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert!(!err.message().contains("duplicate bucket id"));

            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: duplicate_commit_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));
            assert!(!err.message().contains("duplicate bucket id"));

            let mut oversized_writeback_buckets = search_run.updated_buckets.clone();
            while oversized_writeback_buckets.len() <= 3 {
                oversized_writeback_buckets.push(search_run.updated_buckets[0].clone());
            }
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: oversized_writeback_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("updated_buckets must contain"));

            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(fixture.client_signature())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("request validation failed"));

            let commit_ciphertext_sentinel = "commit-error-ciphertext-sentinel";
            let mut malformed_commit_buckets = search_run.updated_buckets.clone();
            malformed_commit_buckets[0].ciphertext = commit_ciphertext_sentinel.to_string();
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: malformed_commit_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(search_run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("bucket ciphertext validation failed")
            );
            assert!(
                !err.message().contains(commit_ciphertext_sentinel),
                "{}",
                err.message()
            );
            assert_pre_commit_state_unchanged();

            let mut wrong_commitment_buckets = search_run.updated_buckets.clone();
            wrong_commitment_buckets[0].bucket_commitment =
                data_encoding::BASE64URL_NOPAD.encode(&[99; 32]);
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: wrong_commitment_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(search_run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("commit bucket commitment context mismatch")
            );
            assert_pre_commit_state_unchanged();

            std::fs::remove_file(uploaded_store.root_path().join("merkle").join("nodes.dat"))
                .unwrap();
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(search_run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::NotFound);
            assert!(
                err.message()
                    .contains("encrypted bucket store metadata is unavailable")
            );
            assert!(!err.message().contains("private_hnsw_oram"));
            assert!(!err.message().contains("/tmp"));
            assert_pre_commit_state_unchanged();
            uploaded_store
                .write_merkle_tree_from_commitments(
                    BASE_EPOCH,
                    fixture.encrypted_build.root_hash.clone(),
                    fixture
                        .encrypted_build
                        .buckets
                        .iter()
                        .map(|bucket| bucket.bucket_commitment.clone())
                        .collect(),
                )
                .unwrap();

            let commit_epoch = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(search_run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(commit_epoch.index_epoch, NEXT_EPOCH);
            let (refreshed_manifest, refreshed_signature) =
                fixture.sign_manifest_refresh(&search_run.commit_plan);
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(search_run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("old epoch/root does not match active session")
            );

            let closed_session_id = session.session_id.clone();
            let closed = PrivateHnswOram::close_private_hnsw_session(
                &service,
                Request::new(grpc::ClosePrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: closed_session_id.clone(),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);

            let missing_close_session_id = "close-session-id-sentinel";
            let err = PrivateHnswOram::close_private_hnsw_session(
                &service,
                Request::new(grpc::ClosePrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: missing_close_session_id.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("session is missing or already closed")
            );
            assert!(
                !err.message().contains(missing_close_session_id),
                "{}",
                err.message()
            );

            let oversized_close_session_id = "s".repeat(129);
            let malformed_close_session_id = "bad.session-id";
            for invalid_session_id in [
                oversized_close_session_id.as_str(),
                malformed_close_session_id,
            ] {
                let err = PrivateHnswOram::close_private_hnsw_session(
                    &service,
                    Request::new(grpc::ClosePrivateHnswSessionRequest {
                        collection_name: COLLECTION_NAME.to_string(),
                        vector_name: VECTOR_NAME.to_string(),
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

            let closed_read_paths = vec![fixture.entry_leaf_label()];
            let closed_read_signature = fixture.sign_read_paths(&closed_read_paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: closed_session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: closed_read_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(closed_read_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("session is missing or expired"));

            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: closed_session_id,
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: search_run.commit_plan.old_root_hash.clone(),
                    new_root_hash: search_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: search_run
                        .updated_buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(search_run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("session is missing or expired"));

            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-2".to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest epoch/root does not match current epoch")
            );

            let refreshed_epoch = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(refreshed_manifest)),
                    signature: Some(signature_to_proto(refreshed_signature)),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(refreshed_epoch.index_epoch, NEXT_EPOCH);

            let reopened = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-2".to_string(),
                    desired_epoch: NEXT_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(reopened.index_epoch, NEXT_EPOCH);
            let closed = PrivateHnswOram::close_private_hnsw_session(
                &service,
                Request::new(grpc::ClosePrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: reopened.session_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);
        });
    }

    #[test]
    fn open_session_grpc_route_rejects_distributed_epoch_mode() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_distributed_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap();

            PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap();

            let distributed_client_id = "tenant-a/distributed-sdk-instance";
            let err = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: distributed_client_id.to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("consensus-backed epoch/root CAS"));
            assert!(!err.message().contains(distributed_client_id));
            assert!(!err.message().contains(&fixture.manifest.root_hash));
            assert!(!err.message().contains(&fixture.manifest_signature.sig));
            assert!(!err.message().contains(&fixture.encrypted_build.root_hash));
            assert!(
                !err.message()
                    .contains(&fixture.encrypted_build.buckets[0].ciphertext)
            );
        });
    }

    #[test]
    fn manifest_upload_grpc_route_rejects_reserved_result_private_runtime_mode() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let mut settings = fixture.route_settings();
        settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            let err = PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("requires a private-result-oram/v1 payload rule")
            );
            assert!(!err.message().contains(&fixture.manifest.root_hash));
            assert!(!err.message().contains(&fixture.manifest_signature.sig));
        });
    }

    #[test]
    fn manifest_upload_grpc_route_accepts_result_private_with_result_oram_binding() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded()
            .with_result_privacy(ResultPrivacyMode::PrivatePayloadOramRequired);
        let settings = fixture.route_settings_with_private_result_oram();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection_with_private_result_oram(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap();

            PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap();

            let session = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: "tenant-a/grpc-sdk-instance-private-result".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(
                        ResultPrivacyMode::PrivatePayloadOramRequired,
                    ),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(session.index_epoch, BASE_EPOCH);
            assert_eq!(session.collection_id, COLLECTION_ID);
            assert_eq!(
                manifest_from_proto(session.manifest.unwrap())
                    .unwrap()
                    .result_privacy,
                ResultPrivacyMode::PrivatePayloadOramRequired
            );

            let closed = PrivateHnswOram::close_private_hnsw_session(
                &service,
                Request::new(grpc::ClosePrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);
        });
    }

    #[test]
    fn manifest_read_grpc_route_revalidates_runtime_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let mut fixed_budget_drifted_settings = settings.clone();
        fixed_budget_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["fixed_budget"]["fixed_result_k"] = serde_json::json!(2);
        let mut hnsw_drifted_settings = settings.clone();
        hnsw_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["hnsw"]["m"] = serde_json::json!(3);
        let mut oram_drifted_settings = settings.clone();
        oram_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["oram"]["bucket_size"] = serde_json::json!(4);
        let mut reserved_privacy_settings = settings.clone();
        reserved_privacy_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());
            let fixed_budget_drifted_service = PrivateHnswOramService::new(
                Arc::new(dispatcher.clone()),
                fixed_budget_drifted_settings,
            );
            let hnsw_drifted_service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), hnsw_drifted_settings);
            let oram_drifted_service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), oram_drifted_settings);
            let reserved_privacy_service = PrivateHnswOramService::new(
                Arc::new(dispatcher.clone()),
                reserved_privacy_settings,
            );

            PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap();

            let assert_manifest_error_redacts = |message: &str| {
                assert!(!message.contains(&fixture.manifest.root_hash));
                assert!(!message.contains(&fixture.manifest_signature.sig));
            };

            let err = PrivateHnswOram::get_private_hnsw_manifest(
                &fixed_budget_drifted_service,
                Request::new(grpc::GetPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest fixed_budget does not match runtime instance")
            );
            assert_manifest_error_redacts(err.message());

            let err = PrivateHnswOram::get_private_hnsw_manifest(
                &hnsw_drifted_service,
                Request::new(grpc::GetPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest hnsw does not match runtime instance")
            );
            assert_manifest_error_redacts(err.message());

            let err = PrivateHnswOram::get_private_hnsw_manifest(
                &oram_drifted_service,
                Request::new(grpc::GetPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert_manifest_error_redacts(err.message());

            let err = PrivateHnswOram::get_private_hnsw_manifest(
                &reserved_privacy_service,
                Request::new(grpc::GetPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("requires a private-result-oram/v1 payload rule")
            );
            assert_manifest_error_redacts(err.message());
        });
    }

    #[test]
    fn bucket_upload_grpc_route_revalidates_runtime_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let mut fixed_budget_drifted_settings = settings.clone();
        fixed_budget_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["fixed_budget"]["fixed_result_k"] = serde_json::json!(2);
        let mut hnsw_drifted_settings = settings.clone();
        hnsw_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["hnsw"]["m"] = serde_json::json!(3);
        let mut oram_drifted_settings = settings.clone();
        oram_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["oram"]["bucket_size"] = serde_json::json!(4);
        let mut reserved_privacy_settings = settings.clone();
        reserved_privacy_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());
            let fixed_budget_drifted_service = PrivateHnswOramService::new(
                Arc::new(dispatcher.clone()),
                fixed_budget_drifted_settings,
            );
            let hnsw_drifted_service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), hnsw_drifted_settings);
            let oram_drifted_service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), oram_drifted_settings);
            let reserved_privacy_service = PrivateHnswOramService::new(
                Arc::new(dispatcher.clone()),
                reserved_privacy_settings,
            );

            PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap();

            let bucket_request = || grpc::UploadPrivateHnswBucketsRequest {
                collection_name: COLLECTION_NAME.to_string(),
                vector_name: VECTOR_NAME.to_string(),
                index_epoch: fixture.encrypted_build.index_epoch,
                root_hash: fixture.encrypted_build.root_hash.clone(),
                buckets: fixture
                    .encrypted_build
                    .buckets
                    .clone()
                    .into_iter()
                    .map(bucket_to_proto)
                    .collect(),
            };
            let assert_bucket_error_redacts = |message: &str| {
                assert!(!message.contains(&fixture.encrypted_build.root_hash));
                assert!(!message.contains(&fixture.encrypted_build.buckets[0].ciphertext));
            };
            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &fixed_budget_drifted_service,
                Request::new(bucket_request()),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest fixed_budget does not match runtime instance")
            );
            assert_bucket_error_redacts(err.message());

            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &hnsw_drifted_service,
                Request::new(bucket_request()),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest hnsw does not match runtime instance")
            );
            assert_bucket_error_redacts(err.message());

            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &oram_drifted_service,
                Request::new(bucket_request()),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert_bucket_error_redacts(err.message());

            let err = PrivateHnswOram::upload_private_hnsw_buckets(
                &reserved_privacy_service,
                Request::new(bucket_request()),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("requires a private-result-oram/v1 payload rule")
            );
            assert_bucket_error_redacts(err.message());

            PrivateHnswOram::upload_private_hnsw_buckets(&service, Request::new(bucket_request()))
                .await
                .unwrap();
        });
    }

    #[test]
    fn read_paths_grpc_service_preserves_fixed_size_bucket_sequence() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded_with_path_batch_size(2);
        let settings = fixture.route_settings();
        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap();
            PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap();
            let session = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap()
            .into_inner();

            let paths = vec![
                encode_private_hnsw_oram_leaf_label(0, fixture.config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(1, fixture.config.tree_height).unwrap(),
            ];
            let signature = fixture.sign_read_paths(&paths, 2, true);
            let read_response = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(signature)),
                }),
            )
            .await
            .unwrap()
            .into_inner();
            let expected_bucket_count = (fixture.manifest.oram.tree_height as usize + 1) * 2;
            assert_eq!(read_response.buckets.len(), expected_bucket_count);
            assert_eq!(
                read_response.buckets[0].bucket_id,
                read_response.buckets[3].bucket_id
            );
            assert_eq!(
                read_response.buckets[1].bucket_id,
                read_response.buckets[4].bucket_id
            );

            let proof_value = read_response.proof.as_ref().unwrap().value.clone();
            let parsed_proof: qdrant_sec::PrivateHnswOramMerkleProof =
                serde_json::from_str(&proof_value).unwrap();
            assert_eq!(parsed_proof.leaves.len(), expected_bucket_count);
            assert_eq!(
                parsed_proof.leaves[0].bucket_id,
                parsed_proof.leaves[3].bucket_id
            );
            assert_eq!(
                parsed_proof.leaves[1].bucket_id,
                parsed_proof.leaves[4].bucket_id
            );
            let read_buckets = read_response
                .buckets
                .into_iter()
                .map(bucket_from_proto)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let opened_buckets = open_private_hnsw_oram_verified_path_batch(
                &fixture.keys,
                fixture.base_context,
                fixture.config,
                BASE_EPOCH,
                &fixture.encrypted_build.root_hash,
                fixture.encrypted_build.bucket_count,
                &proof_value,
                &read_buckets,
            )
            .unwrap();
            assert_eq!(opened_buckets.len(), expected_bucket_count);

            let duplicate_path = fixture.entry_leaf_label();
            let duplicate_paths = vec![duplicate_path.clone(), duplicate_path.clone()];
            let invalid_duplicate_signature_sig = fixture.client_signature().sig;
            let invalid_duplicate_err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: duplicate_paths.clone(),
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(PrivateHnswOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: invalid_duplicate_signature_sig.clone(),
                    })),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(invalid_duplicate_err.code(), Code::InvalidArgument);
            assert!(
                invalid_duplicate_err
                    .message()
                    .contains("request validation failed")
            );
            assert!(
                !invalid_duplicate_err
                    .message()
                    .contains("duplicate path label")
            );
            assert!(!invalid_duplicate_err.message().contains(&duplicate_path));
            assert!(
                !invalid_duplicate_err
                    .message()
                    .contains(&session.session_id)
            );
            assert!(
                !invalid_duplicate_err
                    .message()
                    .contains(&fixture.encrypted_build.root_hash)
            );
            assert!(!invalid_duplicate_err.message().contains(SIGNING_KEY_ID));
            assert!(
                !invalid_duplicate_err
                    .message()
                    .contains(&invalid_duplicate_signature_sig)
            );

            let duplicate_signature = fixture.sign_read_paths(&duplicate_paths, 2, true);
            let duplicate_signature_key_id = duplicate_signature.key_id.clone();
            let duplicate_signature_sig = duplicate_signature.sig.clone();
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: duplicate_paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 2,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(duplicate_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(err.message().contains("duplicate path label"));
            assert!(!err.message().contains(&duplicate_path));
            assert!(!err.message().contains(&session.session_id));
            assert!(!err.message().contains(&fixture.encrypted_build.root_hash));
            assert!(!err.message().contains(&duplicate_signature_key_id));
            assert!(!err.message().contains(&duplicate_signature_sig));

            let closed = PrivateHnswOram::close_private_hnsw_session(
                &service,
                Request::new(grpc::ClosePrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);
        });
    }

    #[test]
    fn read_paths_rejects_active_session_after_runtime_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["fixed_budget"]["fixed_result_k"] = serde_json::json!(2);
        let mut hnsw_drifted_settings = settings.clone();
        hnsw_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["hnsw"]["m"] = serde_json::json!(3);
        let mut reserved_privacy_settings = settings.clone();
        reserved_privacy_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");

        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap();
            PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap();
            let session = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap()
            .into_inner();

            let drifted_service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), drifted_settings);
            let paths = vec![fixture.entry_leaf_label()];
            let signature = fixture.sign_read_paths(&paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &drifted_service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: paths.clone(),
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest fixed_budget does not match runtime instance")
            );
            assert!(!err.message().contains(&fixture.encrypted_build.root_hash));
            assert!(!err.message().contains(&session.session_id));
            assert!(!err.message().contains(&paths[0]));
            assert!(!err.message().contains(&signature.key_id));
            assert!(!err.message().contains(&signature.sig));

            let hnsw_drifted_service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), hnsw_drifted_settings);
            let hnsw_drift_paths = vec![fixture.entry_leaf_label()];
            let hnsw_drift_signature = fixture.sign_read_paths(&hnsw_drift_paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &hnsw_drifted_service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: hnsw_drift_paths.clone(),
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(hnsw_drift_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest hnsw does not match runtime instance")
            );
            assert!(!err.message().contains(&fixture.encrypted_build.root_hash));
            assert!(!err.message().contains(&session.session_id));
            assert!(!err.message().contains(&hnsw_drift_paths[0]));
            assert!(!err.message().contains(&hnsw_drift_signature.key_id));
            assert!(!err.message().contains(&hnsw_drift_signature.sig));

            let reserved_privacy_service = PrivateHnswOramService::new(
                Arc::new(dispatcher.clone()),
                reserved_privacy_settings,
            );
            let reserved_paths = vec![fixture.entry_leaf_label()];
            let reserved_signature = fixture.sign_read_paths(&reserved_paths, 1, true);
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &reserved_privacy_service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths: reserved_paths.clone(),
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(reserved_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("requires a private-result-oram/v1 payload rule")
            );
            assert!(!err.message().contains(&fixture.encrypted_build.root_hash));
            assert!(!err.message().contains(&session.session_id));
            assert!(!err.message().contains(&reserved_paths[0]));
            assert!(!err.message().contains(&reserved_signature.key_id));
            assert!(!err.message().contains(&reserved_signature.sig));

            let closed = PrivateHnswOram::close_private_hnsw_session(
                &service,
                Request::new(grpc::ClosePrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);
        });
    }

    #[test]
    fn commit_rejects_active_session_after_runtime_policy_drift() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let settings = fixture.route_settings();
        let mut drifted_settings = settings.clone();
        drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["oram"]["path_batch_size"] = serde_json::json!(2);
        drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["fixed_budget"]["paths_per_round"] = serde_json::json!(2);
        let mut hnsw_drifted_settings = settings.clone();
        hnsw_drifted_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["hnsw"]["m"] = serde_json::json!(3);
        let mut reserved_privacy_settings = settings.clone();
        reserved_privacy_settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["result_privacy"] = serde_json::json!("private_payload_oram_required");

        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap();
            PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap();
            let session = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap()
            .into_inner();

            let run = fixture.run_single_search_collect_writeback();
            let drifted_service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), drifted_settings);
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &drifted_service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.encrypted_build.root_hash.clone(),
                    new_root_hash: run.commit_plan.new_root_hash.clone(),
                    updated_buckets: run
                        .updated_buckets
                        .iter()
                        .cloned()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest oram does not match runtime instance")
            );
            assert!(!err.message().contains(&fixture.encrypted_build.root_hash));
            assert!(!err.message().contains(&run.commit_plan.new_root_hash));
            assert!(!err.message().contains(&session.session_id));
            assert!(!err.message().contains(&run.commit_signature.key_id));
            assert!(!err.message().contains(&run.commit_signature.sig));
            assert!(!err.message().contains(&run.updated_buckets[0].ciphertext));

            let hnsw_run = fixture.run_single_search_collect_writeback();
            let hnsw_drifted_service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), hnsw_drifted_settings);
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &hnsw_drifted_service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.encrypted_build.root_hash.clone(),
                    new_root_hash: hnsw_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: hnsw_run
                        .updated_buckets
                        .iter()
                        .cloned()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(hnsw_run.commit_signature.clone())),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("manifest hnsw does not match runtime instance")
            );
            assert!(!err.message().contains(&fixture.encrypted_build.root_hash));
            assert!(!err.message().contains(&hnsw_run.commit_plan.new_root_hash));
            assert!(!err.message().contains(&session.session_id));
            assert!(!err.message().contains(&hnsw_run.commit_signature.key_id));
            assert!(!err.message().contains(&hnsw_run.commit_signature.sig));
            assert!(
                !err.message()
                    .contains(&hnsw_run.updated_buckets[0].ciphertext)
            );

            let reserved_run = fixture.run_single_search_collect_writeback();
            let reserved_privacy_service = PrivateHnswOramService::new(
                Arc::new(dispatcher.clone()),
                reserved_privacy_settings,
            );
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &reserved_privacy_service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.encrypted_build.root_hash.clone(),
                    new_root_hash: reserved_run.commit_plan.new_root_hash.clone(),
                    updated_buckets: reserved_run
                        .updated_buckets
                        .iter()
                        .cloned()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(
                        reserved_run.commit_signature.clone(),
                    )),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("requires a private-result-oram/v1 payload rule")
            );
            assert!(!err.message().contains(&fixture.encrypted_build.root_hash));
            assert!(
                !err.message()
                    .contains(&reserved_run.commit_plan.new_root_hash)
            );
            assert!(!err.message().contains(&session.session_id));
            assert!(
                !err.message()
                    .contains(&reserved_run.commit_signature.key_id)
            );
            assert!(!err.message().contains(&reserved_run.commit_signature.sig));
            assert!(
                !err.message()
                    .contains(&reserved_run.updated_buckets[0].ciphertext)
            );

            let closed = PrivateHnswOram::close_private_hnsw_session(
                &service,
                Request::new(grpc::ClosePrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);
        });
    }

    #[test]
    fn read_paths_and_commit_require_manifest_owner_signing_key() {
        let _guard = route_e2e_guard();
        let fixture = PrivateHnswRouteWireFixture::build_uploaded();
        let mut settings = fixture.route_settings();
        let alternate_key_id = "tenant-a/private-hnsw-signing-v2";
        settings
            .crypto
            .instances
            .get_mut("docs_private_hnsw_v1")
            .unwrap()
            .options["signature_public_keys"][alternate_key_id] =
            serde_json::json!(BASE64URL_NOPAD.encode(&[19_u8; 32]));

        let (_temp, dispatcher) = test_dispatcher();
        actix_web::rt::System::new().block_on(async {
            create_private_hnsw_collection(&dispatcher).await;
            let service =
                PrivateHnswOramService::new(Arc::new(dispatcher.clone()), settings.clone());

            PrivateHnswOram::upload_private_hnsw_manifest(
                &service,
                Request::new(grpc::UploadPrivateHnswManifestRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    manifest: Some(manifest_to_proto(fixture.manifest.clone())),
                    signature: Some(signature_to_proto(fixture.manifest_signature.clone())),
                }),
            )
            .await
            .unwrap();
            PrivateHnswOram::upload_private_hnsw_buckets(
                &service,
                Request::new(grpc::UploadPrivateHnswBucketsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    index_epoch: fixture.encrypted_build.index_epoch,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    buckets: fixture
                        .encrypted_build
                        .buckets
                        .clone()
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                }),
            )
            .await
            .unwrap();
            let session = PrivateHnswOram::open_private_hnsw_session(
                &service,
                Request::new(grpc::OpenPrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    client_id: "tenant-a/sdk-instance-1".to_string(),
                    desired_epoch: BASE_EPOCH,
                    fixed_budget: true,
                    result_privacy: result_privacy_to_proto(ResultPrivacyMode::IdsVisible),
                }),
            )
            .await
            .unwrap()
            .into_inner();

            let paths = vec![fixture.entry_leaf_label()];
            let mut wrong_read_signature = fixture.sign_read_paths(&paths, 1, true);
            wrong_read_signature.key_id = alternate_key_id.to_string();
            let err = PrivateHnswOram::read_private_hnsw_paths(
                &service,
                Request::new(grpc::OramReadPathsRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    index_epoch: BASE_EPOCH,
                    root_hash: fixture.encrypted_build.root_hash.clone(),
                    paths,
                    padding: Some(grpc::OramReadPadding {
                        requested_paths: 1,
                        dummy_paths_included: true,
                    }),
                    client_signature: Some(signature_to_proto(wrong_read_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(alternate_key_id),
                "{}",
                err.message()
            );

            let run = fixture.run_single_search_collect_writeback();
            let mut wrong_commit_signature = run.commit_signature;
            wrong_commit_signature.key_id = alternate_key_id.to_string();
            let err = PrivateHnswOram::commit_private_hnsw_paths(
                &service,
                Request::new(grpc::OramCommitRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id.clone(),
                    old_epoch: BASE_EPOCH,
                    new_epoch: NEXT_EPOCH,
                    old_root_hash: fixture.encrypted_build.root_hash.clone(),
                    new_root_hash: run.commit_plan.new_root_hash,
                    updated_buckets: run
                        .updated_buckets
                        .into_iter()
                        .map(bucket_to_proto)
                        .collect(),
                    commit_signature: Some(signature_to_proto(wrong_commit_signature)),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert!(
                err.message()
                    .contains("signature key_id does not match manifest owner_signing_key_id")
            );
            assert!(!err.message().contains("not configured"));
            assert!(
                !err.message().contains(alternate_key_id),
                "{}",
                err.message()
            );

            let closed = PrivateHnswOram::close_private_hnsw_session(
                &service,
                Request::new(grpc::ClosePrivateHnswSessionRequest {
                    collection_name: COLLECTION_NAME.to_string(),
                    vector_name: VECTOR_NAME.to_string(),
                    session_id: session.session_id,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert!(closed.closed);
        });
    }
}
