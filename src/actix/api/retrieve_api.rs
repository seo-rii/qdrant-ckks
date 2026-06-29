use std::time::Duration;

use actix_web::{Responder, get, post, web};
use actix_web_validator::{Json, Path, Query};
use collection::operations::consistency_params::ReadConsistency;
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::types::{PointRequest, PointRequestInternal, ScrollRequest};
use common::counter::hardware_accumulator::HwMeasurementAcc;
use futures::TryFutureExt;
use itertools::Itertools;
use segment::types::{
    EncryptedPayloadReadMode, PayloadEncryptedReadPolicy, PointIdType, WithPayloadInterface,
};
use serde::Deserialize;
use shard::retrieve::record_internal::RecordInternal;
use storage::content_manager::collection_verification::{
    check_strict_mode, check_strict_mode_timeout,
};
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::Dispatcher;
use storage::rbac::{AccessRequirements, Auth};
use tokio::time::Instant;
use validator::Validate;

use super::CollectionPath;
use super::read_params::ReadParams;
use crate::actix::auth::ActixAuth;
use crate::actix::helpers::{
    get_request_hardware_counter, process_response, process_response_error,
};
use crate::common::query::{do_get_points, do_scroll_points};
use crate::settings::{ServiceConfig, Settings};

#[derive(Deserialize, Validate)]
struct PointPath {
    #[validate(length(min = 1))]
    // TODO: validate this is a valid ID type (usize or UUID)? Does currently error on deserialize.
    id: String,
}

#[derive(Deserialize, Validate)]
struct PointReadParams {
    #[serde(flatten)]
    #[validate(nested)]
    read: ReadParams,
    /// Optional single-point GET equivalent of `with_payload: {"encrypted_payload": ...}`.
    encrypted_payload: Option<EncryptedPayloadReadMode>,
}

impl PointReadParams {
    fn timeout(&self) -> Option<Duration> {
        self.read.timeout()
    }

    fn timeout_as_secs(&self) -> Option<usize> {
        self.read.timeout_as_secs()
    }

    fn consistency(&self) -> Option<ReadConsistency> {
        self.read.consistency
    }

    fn with_payload(&self) -> WithPayloadInterface {
        self.encrypted_payload
            .map(|encrypted_payload| {
                WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy { encrypted_payload })
            })
            .unwrap_or(WithPayloadInterface::Bool(true))
    }
}

#[derive(Deserialize, Validate)]
struct PayloadExportParams {
    #[serde(flatten)]
    #[validate(nested)]
    read: ReadParams,
    /// Export endpoints require an explicit encrypted payload policy to avoid accidental plaintext dumps.
    encrypted_payload: EncryptedPayloadReadMode,
}

impl PayloadExportParams {
    fn timeout(&self) -> Option<Duration> {
        self.read.timeout()
    }

    fn timeout_as_secs(&self) -> Option<usize> {
        self.read.timeout_as_secs()
    }

    fn consistency(&self) -> Option<ReadConsistency> {
        self.read.consistency
    }
}

fn prepare_payload_export_scroll_request(
    mut request: shard::scroll::ScrollRequestInternal,
    encrypted_payload: EncryptedPayloadReadMode,
) -> Result<shard::scroll::ScrollRequestInternal, StorageError> {
    if request.with_vector.is_enabled() {
        return Err(StorageError::bad_request(
            "payload export does not support with_vector; use raw/redacted/decrypted payload policy and fetch vectors through the appropriate vector read or private session API",
        ));
    }

    request.with_payload = Some(WithPayloadInterface::Encrypted(
        PayloadEncryptedReadPolicy { encrypted_payload },
    ));
    Ok(request)
}

async fn do_get_point(
    toc: &TableOfContent,
    collection_name: &str,
    point_id: PointIdType,
    with_payload: WithPayloadInterface,
    read_consistency: Option<ReadConsistency>,
    timeout: Option<Duration>,
    auth: Auth,
    hw_counter: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Option<RecordInternal>, StorageError> {
    let request = PointRequestInternal {
        ids: vec![point_id],
        with_payload: Some(with_payload),
        with_vector: true.into(),
    };

    let shard_selection = ShardSelectorInternal::All;

    do_get_points(
        toc,
        collection_name,
        request,
        read_consistency,
        timeout,
        shard_selection,
        auth,
        hw_counter,
        runtime_settings,
    )
    .await
    .map(|points| points.into_iter().next())
}

#[get("/collections/{collection_name}/points/{id}")]
async fn get_point(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    point: Path<PointPath>,
    params: Query<PointReadParams>,
    service_config: web::Data<ServiceConfig>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let pass = match check_strict_mode_timeout(
        params.timeout_as_secs(),
        &collection.collection_name,
        &dispatcher,
        &auth,
    )
    .await
    {
        Ok(p) => p,
        Err(err) => return process_response_error(err, Instant::now(), None),
    };

    let Ok(point_id) = point.id.parse::<PointIdType>() else {
        let err = StorageError::BadInput {
            description: format!("Can not recognize \"{}\" as point id", point.id),
        };
        return process_response_error(err, Instant::now(), None);
    };

    let request_hw_counter = get_request_hardware_counter(
        &dispatcher,
        collection.collection_name.clone(),
        service_config.hardware_reporting(),
        None,
    );
    let timing = Instant::now();

    let res = do_get_point(
        dispatcher.toc(&auth, &pass),
        &collection.collection_name,
        point_id,
        params.with_payload(),
        params.consistency(),
        params.timeout(),
        auth,
        request_hw_counter.get_counter(),
        Some(settings.get_ref()),
    )
    .await
    .and_then(|i| {
        i.ok_or_else(|| StorageError::NotFound {
            description: format!("Point with id {point_id} does not exists!"),
        })
    })
    .map(api::rest::Record::from);

    process_response(res, timing, request_hw_counter.to_rest_api())
}

#[post("/collections/{collection_name}/points")]
async fn get_points(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    request: Json<PointRequest>,
    params: Query<ReadParams>,
    service_config: web::Data<ServiceConfig>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let pass = match check_strict_mode_timeout(
        params.timeout_as_secs(),
        &collection.collection_name,
        &dispatcher,
        &auth,
    )
    .await
    {
        Ok(p) => p,
        Err(err) => return process_response_error(err, Instant::now(), None),
    };

    let PointRequest {
        point_request,
        shard_key,
    } = request.into_inner();

    let shard_selection = match shard_key {
        None => ShardSelectorInternal::All,
        Some(shard_keys) => ShardSelectorInternal::from(shard_keys),
    };

    let request_hw_counter = get_request_hardware_counter(
        &dispatcher,
        collection.collection_name.clone(),
        service_config.hardware_reporting(),
        None,
    );
    let timing = Instant::now();

    let res = do_get_points(
        dispatcher.toc(&auth, &pass),
        &collection.collection_name,
        point_request,
        params.consistency,
        params.timeout(),
        shard_selection,
        auth,
        request_hw_counter.get_counter(),
        Some(settings.get_ref()),
    )
    .map_ok(|response| {
        response
            .into_iter()
            .map(api::rest::Record::from)
            .collect_vec()
    })
    .await;

    process_response(res, timing, request_hw_counter.to_rest_api())
}

#[post("/collections/{collection_name}/points/scroll")]
async fn scroll_points(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    request: Json<ScrollRequest>,
    params: Query<ReadParams>,
    service_config: web::Data<ServiceConfig>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let ScrollRequest {
        scroll_request,
        shard_key,
    } = request.into_inner();

    let pass = match check_strict_mode(
        &scroll_request,
        params.timeout_as_secs(),
        &collection.collection_name,
        &dispatcher,
        &auth,
    )
    .await
    {
        Ok(pass) => pass,
        Err(err) => return process_response_error(err, Instant::now(), None),
    };

    let shard_selection = match shard_key {
        None => ShardSelectorInternal::All,
        Some(shard_keys) => ShardSelectorInternal::from(shard_keys),
    };

    let request_hw_counter = get_request_hardware_counter(
        &dispatcher,
        collection.collection_name.clone(),
        service_config.hardware_reporting(),
        None,
    );
    let timing = Instant::now();

    let res = do_scroll_points(
        dispatcher.toc(&auth, &pass),
        &collection.collection_name,
        scroll_request,
        params.consistency,
        params.timeout(),
        shard_selection,
        auth,
        request_hw_counter.get_counter(),
        Some(settings.get_ref()),
    )
    .await;

    process_response(res, timing, request_hw_counter.to_rest_api())
}

#[post("/collections/{collection_name}/points/export")]
async fn export_payload_points(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    request: Json<ScrollRequest>,
    params: Query<PayloadExportParams>,
    service_config: web::Data<ServiceConfig>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let ScrollRequest {
        scroll_request,
        shard_key,
    } = request.into_inner();
    let encrypted_payload = params.encrypted_payload;
    let scroll_request =
        match prepare_payload_export_scroll_request(scroll_request, encrypted_payload) {
            Ok(request) => request,
            Err(err) => return process_response_error(err, Instant::now(), None),
        };

    let audit_requirements = if encrypted_payload == EncryptedPayloadReadMode::Decrypted {
        AccessRequirements::new().payload_decrypt()
    } else {
        AccessRequirements::new()
    };
    let audit_method = match encrypted_payload {
        EncryptedPayloadReadMode::Raw => "export_raw_encrypted_payload",
        EncryptedPayloadReadMode::Redacted => "export_redacted_payload",
        EncryptedPayloadReadMode::Decrypted => "export_decrypted_payload",
    };
    if let Err(err) = auth.check_collection_access(
        &collection.collection_name,
        audit_requirements,
        audit_method,
    ) {
        return process_response_error(err, Instant::now(), None);
    }

    let pass = match check_strict_mode(
        &scroll_request,
        params.timeout_as_secs(),
        &collection.collection_name,
        &dispatcher,
        &auth,
    )
    .await
    {
        Ok(pass) => pass,
        Err(err) => return process_response_error(err, Instant::now(), None),
    };

    let shard_selection = match shard_key {
        None => ShardSelectorInternal::All,
        Some(shard_keys) => ShardSelectorInternal::from(shard_keys),
    };

    let request_hw_counter = get_request_hardware_counter(
        &dispatcher,
        collection.collection_name.clone(),
        service_config.hardware_reporting(),
        None,
    );
    let timing = Instant::now();

    let res = do_scroll_points(
        dispatcher.toc(&auth, &pass),
        &collection.collection_name,
        scroll_request,
        params.consistency(),
        params.timeout(),
        shard_selection,
        auth,
        request_hw_counter.get_counter(),
        Some(settings.get_ref()),
    )
    .await;

    process_response(res, timing, request_hw_counter.to_rest_api())
}

#[cfg(test)]
mod tests {
    use segment::types::WithVector;

    use super::*;

    #[test]
    fn point_read_params_support_encrypted_payload_query_mode() {
        let params: PointReadParams =
            serde_urlencoded::from_str("encrypted_payload=redacted").unwrap();

        assert_eq!(params.read, ReadParams::default());
        assert_eq!(
            params.with_payload(),
            WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                encrypted_payload: EncryptedPayloadReadMode::Redacted,
            }),
        );
    }

    #[test]
    fn point_read_params_support_decrypted_payload_query_mode() {
        let params: PointReadParams =
            serde_urlencoded::from_str("encrypted_payload=decrypted").unwrap();

        assert_eq!(params.read, ReadParams::default());
        assert_eq!(
            params.with_payload(),
            WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                encrypted_payload: EncryptedPayloadReadMode::Decrypted,
            }),
        );
    }

    #[test]
    fn point_read_params_keep_default_payload_enabled() {
        let params: PointReadParams = serde_urlencoded::from_str("consistency=majority").unwrap();

        assert_eq!(params.with_payload(), WithPayloadInterface::Bool(true));
    }

    #[test]
    fn payload_export_params_require_explicit_encrypted_payload_policy() {
        let missing = serde_urlencoded::from_str::<PayloadExportParams>("consistency=majority");
        assert!(missing.is_err());

        let params: PayloadExportParams =
            serde_urlencoded::from_str("encrypted_payload=decrypted").unwrap();
        assert_eq!(
            params.encrypted_payload,
            EncryptedPayloadReadMode::Decrypted
        );
    }

    #[test]
    fn payload_export_request_forces_encrypted_payload_policy_and_rejects_vectors() {
        let mut request = shard::scroll::ScrollRequestInternal::default();
        request.with_payload = Some(WithPayloadInterface::Bool(false));

        let request =
            prepare_payload_export_scroll_request(request, EncryptedPayloadReadMode::Redacted)
                .unwrap();
        assert_eq!(
            request.with_payload,
            Some(WithPayloadInterface::Encrypted(
                PayloadEncryptedReadPolicy {
                    encrypted_payload: EncryptedPayloadReadMode::Redacted,
                }
            )),
        );
        assert_eq!(request.with_vector, WithVector::Bool(false));

        let mut vector_request = shard::scroll::ScrollRequestInternal::default();
        vector_request.with_vector = WithVector::Bool(true);
        let err =
            prepare_payload_export_scroll_request(vector_request, EncryptedPayloadReadMode::Raw)
                .expect_err("payload export must not include vector data");
        assert!(
            err.to_string()
                .contains("payload export does not support with_vector"),
            "{err}",
        );
        assert!(err.to_string().contains("private session API"), "{err}",);
        assert!(!err.to_string().contains("normal read API"), "{err}");
    }
}
