use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use actix_web::http::StatusCode;
use actix_web::http::header::ContentType;
use actix_web::rt::time::Instant;
use actix_web::web::Data;
use actix_web::{HttpResponse, Responder, get, post, web};
use actix_web_validator::{Json, Path, Query};
use collection::operations::verification::new_unchecked_verification_pass;
use common::types::{DetailsLevel, TelemetryDetail};
use schemars::JsonSchema;
use segment::common::anonymize::Anonymize;
use serde::{Deserialize, Serialize};
use storage::content_manager::errors::StorageError;
use storage::dispatcher::Dispatcher;
use storage::rbac::AccessRequirements;
use tokio::sync::Mutex;
use validator::{Validate, ValidationError};

use super::CollectionPath;
use crate::actix::auth::ActixAuth;
use crate::actix::helpers::{self, process_response_error};
use crate::common::crypto::{
    generate_wrapped_runtime_resource_key_material,
    rewrap_runtime_resource_key_materials_by_master_key,
};
use crate::common::health;
use crate::common::metrics::MetricsData;
use crate::common::stacktrace::get_stack_trace;
use crate::common::telemetry::TelemetryCollector;
use crate::settings::{CryptoMaterialConfig, ServiceConfig, Settings};
use crate::tracing;

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct TelemetryParam {
    pub anonymize: Option<bool>,
    pub details_level: Option<usize>,
    pub per_collection: Option<bool>,
    #[validate(range(min = 1))]
    pub timeout: Option<u64>,
}

impl TelemetryParam {
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout.map(Duration::from_secs)
    }
}

#[get("/telemetry")]
fn telemetry(
    telemetry_collector: Data<Mutex<TelemetryCollector>>,
    params: Query<TelemetryParam>,
    ActixAuth(auth): ActixAuth,
) -> impl Future<Output = HttpResponse> {
    helpers::time(async move {
        let anonymize = params.anonymize.unwrap_or(false);
        let details_level = params
            .details_level
            .map_or(DetailsLevel::Level0, Into::into);

        let detail = TelemetryDetail {
            level: details_level,
            histograms: false,
            per_collection: params.per_collection.unwrap_or(false),
        };
        let telemetry_data = telemetry_collector
            .lock()
            .await
            .prepare_data(&auth, detail, None, params.timeout())
            .await?;
        let telemetry_data = if anonymize {
            telemetry_data.anonymize()
        } else {
            telemetry_data
        };
        Ok(telemetry_data)
    })
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct MetricsParam {
    pub anonymize: Option<bool>,
    pub per_collection: Option<bool>,
    #[validate(range(min = 1))]
    pub timeout: Option<u64>,
}

impl MetricsParam {
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout.map(Duration::from_secs)
    }
}

#[get("/metrics")]
async fn metrics(
    telemetry_collector: Data<Mutex<TelemetryCollector>>,
    params: Query<MetricsParam>,
    config: Data<ServiceConfig>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    if let Err(err) = auth
        .unlogged_access() // Do not log access to metrics, as it is too noizy
        .check_global_access(AccessRequirements::new())
    {
        return process_response_error(err, Instant::now(), None);
    }

    let anonymize = params.anonymize.unwrap_or(false);
    let per_collection = params.per_collection.unwrap_or(false);
    let telemetry_data = telemetry_collector
        .lock()
        .await
        .prepare_data(
            &auth,
            TelemetryDetail {
                level: DetailsLevel::Level4,
                histograms: true,
                per_collection,
            },
            None,
            params.timeout(),
        )
        .await;
    match telemetry_data {
        Err(err) => process_response_error(err, Instant::now(), None),
        Ok(telemetry_data) => {
            let telemetry_data = if anonymize {
                telemetry_data.anonymize()
            } else {
                telemetry_data
            };

            let metrics_prefix = config.metrics_prefix.as_deref();
            HttpResponse::Ok()
                .content_type(ContentType::plaintext())
                .body(
                    MetricsData::new_from_telemetry(telemetry_data, metrics_prefix)
                        .format_metrics(),
                )
        }
    }
}

#[get("/stacktrace")]
fn get_stacktrace(ActixAuth(auth): ActixAuth) -> impl Future<Output = HttpResponse> {
    helpers::time(async move {
        auth.check_global_access(AccessRequirements::new().manage(), "get_stacktrace")?;
        Ok(get_stack_trace())
    })
}

#[get("/healthz")]
async fn healthz() -> impl Responder {
    kubernetes_healthz()
}

#[get("/livez")]
async fn livez() -> impl Responder {
    kubernetes_healthz()
}

#[get("/readyz")]
async fn readyz(health_checker: web::Data<Option<Arc<health::HealthChecker>>>) -> impl Responder {
    let is_ready = match health_checker.as_ref() {
        Some(health_checker) => health_checker.check_ready().await,
        None => true,
    };

    let (status, body) = if is_ready {
        (StatusCode::OK, "all shards are ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "some shards are not ready")
    };

    HttpResponse::build(status)
        .content_type(ContentType::plaintext())
        .body(body)
}

/// Basic Kubernetes healthz endpoint
fn kubernetes_healthz() -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body("healthz check passed")
}

#[get("/logger")]
async fn get_logger_config(
    ActixAuth(auth): ActixAuth,
    handle: web::Data<tracing::LoggerHandle>,
) -> impl Responder {
    let timing = Instant::now();

    let future = async {
        let _ = auth.check_global_access(AccessRequirements::new(), "get_logger_config")?;
        let config = handle.get_config().await;
        Ok(config)
    };

    helpers::process_response(future.await, timing, None)
}

#[post("/logger")]
async fn update_logger_config(
    ActixAuth(auth): ActixAuth,
    handle: web::Data<tracing::LoggerHandle>,
    mut config: web::Json<tracing::LoggerConfig>,
) -> impl Responder {
    let timing = Instant::now();

    let future = async {
        let _ =
            auth.check_global_access(AccessRequirements::new().manage(), "update_logger_config")?;

        // Log file can only be set in Qdrant config file
        config.on_disk.log_file = None;

        handle
            .update_config(config.into_inner())
            .await
            .map_err(|err| StorageError::service_error(err.to_string()))?;

        Ok(true)
    };

    helpers::process_response(future.await, timing, None)
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct TruncateUnappliedWalParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<bool>,
}

#[post("/collections/{collection_name}/truncate_unapplied_wal")]
async fn truncate_unapplied_wal(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    params: Query<TruncateUnappliedWalParams>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let future = async move {
        let collection_pass = auth
            .check_global_access(AccessRequirements::new().manage(), "truncate_unapplied_wal")?
            .issue_pass(&collection.collection_name)
            .into_static();

        let pass = new_unchecked_verification_pass();
        let collection = dispatcher
            .toc(&auth, &pass)
            .get_collection(&collection_pass)
            .await?;

        collection
            .truncate_unapplied_wal()
            .await
            .map_err(StorageError::from)
    };
    helpers::time_or_accept(future, params.wait.unwrap_or(true)).await
}

fn validate_runtime_resource_key_rewrap_identifier(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(ValidationError::new("invalid_crypto_material_identifier"));
    }

    Ok(())
}

fn validate_runtime_resource_key_scope(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > 256 || value.contains('\0') {
        return Err(ValidationError::new("invalid_crypto_resource_key_scope"));
    }

    Ok(())
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct RuntimeResourceKeyGenerateRequest {
    #[validate(custom(function = "validate_runtime_resource_key_rewrap_identifier"))]
    pub material: String,
    #[validate(custom(function = "validate_runtime_resource_key_rewrap_identifier"))]
    pub wrapped_by: String,
    #[validate(range(min = 1))]
    pub rk_epoch: u64,
    #[validate(custom(function = "validate_runtime_resource_key_scope"))]
    pub scope: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct RuntimeResourceKeyRewrapRequest {
    #[validate(custom(function = "validate_runtime_resource_key_rewrap_identifier"))]
    pub old_wrapped_by: String,
    #[validate(custom(function = "validate_runtime_resource_key_rewrap_identifier"))]
    pub new_wrapped_by: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct RuntimeResourceKeyRewrapMaterialPatch {
    pub kind: String,
    pub wrapped_by: String,
    pub wrap_algorithm: String,
    pub nonce: String,
    pub wrapped_key_b64: String,
    pub rk_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    pub scope: String,
}

impl RuntimeResourceKeyRewrapMaterialPatch {
    fn from_material(
        material_ref: &str,
        material: CryptoMaterialConfig,
    ) -> Result<Self, StorageError> {
        Ok(Self {
            kind: material.kind,
            wrapped_by: material.wrapped_by.ok_or_else(|| {
                StorageError::service_error(format!(
                    "rewrapped material {material_ref} is missing wrapped_by"
                ))
            })?,
            wrap_algorithm: material.wrap_algorithm.ok_or_else(|| {
                StorageError::service_error(format!(
                    "rewrapped material {material_ref} is missing wrap_algorithm"
                ))
            })?,
            nonce: material.nonce.ok_or_else(|| {
                StorageError::service_error(format!(
                    "rewrapped material {material_ref} is missing nonce"
                ))
            })?,
            wrapped_key_b64: material.wrapped_key_b64.ok_or_else(|| {
                StorageError::service_error(format!(
                    "rewrapped material {material_ref} is missing wrapped_key_b64"
                ))
            })?,
            rk_epoch: material.rk_epoch.ok_or_else(|| {
                StorageError::service_error(format!(
                    "rewrapped material {material_ref} is missing rk_epoch"
                ))
            })?,
            state: material.state,
            scope: material.scope.ok_or_else(|| {
                StorageError::service_error(format!(
                    "rewrapped material {material_ref} is missing scope"
                ))
            })?,
        })
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct RuntimeResourceKeyGenerateResponse {
    pub wrapped_by: String,
    pub settings_mutated: bool,
    pub materials: BTreeMap<String, RuntimeResourceKeyRewrapMaterialPatch>,
}

fn build_runtime_resource_key_generate_response(
    settings: &Settings,
    request: RuntimeResourceKeyGenerateRequest,
) -> Result<RuntimeResourceKeyGenerateResponse, StorageError> {
    request.validate().map_err(|err| {
        StorageError::bad_request(format!(
            "crypto resource-key generation request is invalid: {err}"
        ))
    })?;
    let material = generate_wrapped_runtime_resource_key_material(
        &settings.crypto,
        &request.material,
        &request.wrapped_by,
        request.rk_epoch,
        &request.scope,
    )
    .map_err(|err| {
        StorageError::bad_request(format!("crypto resource-key generation failed: {err}"))
    })?;
    let materials = BTreeMap::from([(
        request.material.clone(),
        RuntimeResourceKeyRewrapMaterialPatch::from_material(&request.material, material)?,
    )]);

    Ok(RuntimeResourceKeyGenerateResponse {
        wrapped_by: request.wrapped_by,
        settings_mutated: false,
        materials,
    })
}

#[post("/crypto/resource-keys/generate")]
async fn generate_runtime_resource_key(
    settings: web::Data<Settings>,
    operation: Json<RuntimeResourceKeyGenerateRequest>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();

    let future = async {
        auth.check_global_access(
            AccessRequirements::new().manage(),
            "generate_runtime_resource_key",
        )?;
        build_runtime_resource_key_generate_response(settings.get_ref(), operation.into_inner())
    };

    helpers::process_response(future.await, timing, None)
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct RuntimeResourceKeyRewrapResponse {
    pub old_wrapped_by: String,
    pub new_wrapped_by: String,
    pub settings_mutated: bool,
    pub materials: BTreeMap<String, RuntimeResourceKeyRewrapMaterialPatch>,
}

fn build_runtime_resource_key_rewrap_response(
    settings: &Settings,
    request: RuntimeResourceKeyRewrapRequest,
) -> Result<RuntimeResourceKeyRewrapResponse, StorageError> {
    request.validate().map_err(|err| {
        StorageError::bad_request(format!(
            "crypto resource-key rewrap request is invalid: {err}"
        ))
    })?;
    let materials = rewrap_runtime_resource_key_materials_by_master_key(
        &settings.crypto,
        &request.old_wrapped_by,
        &request.new_wrapped_by,
    )
    .map_err(|err| StorageError::bad_request(format!("crypto resource-key rewrap failed: {err}")))?
    .into_iter()
    .map(|(material_ref, material)| {
        Ok((
            material_ref.clone(),
            RuntimeResourceKeyRewrapMaterialPatch::from_material(&material_ref, material)?,
        ))
    })
    .collect::<Result<BTreeMap<_, _>, StorageError>>()?;

    Ok(RuntimeResourceKeyRewrapResponse {
        old_wrapped_by: request.old_wrapped_by,
        new_wrapped_by: request.new_wrapped_by,
        settings_mutated: false,
        materials,
    })
}

#[post("/crypto/resource-keys/rewrap")]
async fn rewrap_runtime_resource_keys(
    settings: web::Data<Settings>,
    operation: Json<RuntimeResourceKeyRewrapRequest>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();

    let future = async {
        auth.check_global_access(
            AccessRequirements::new().manage(),
            "rewrap_runtime_resource_keys",
        )?;
        build_runtime_resource_key_rewrap_response(settings.get_ref(), operation.into_inner())
    };

    helpers::process_response(future.await, timing, None)
}

fn validate_runtime_resource_key_retirement_target(value: &str) -> Result<(), ValidationError> {
    match value {
        "disabled" | "destroyed" => Ok(()),
        _ => Err(ValidationError::new(
            "invalid_crypto_resource_key_retirement_target",
        )),
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct RuntimeResourceKeyRetireRequest {
    #[validate(length(min = 1))]
    pub materials: Vec<String>,
    #[validate(custom(function = "validate_runtime_resource_key_retirement_target"))]
    pub target_state: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct RuntimeResourceKeyRetireMaterialPatch {
    pub kind: String,
    pub rk_epoch: u64,
    pub state: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_key_b64: Option<String>,
}

impl RuntimeResourceKeyRetireMaterialPatch {
    fn from_retired_material(
        material_ref: &str,
        material: &CryptoMaterialConfig,
        target_state: &str,
    ) -> Result<Self, StorageError> {
        let rk_epoch = material.rk_epoch.ok_or_else(|| {
            StorageError::service_error(format!(
                "retired material {material_ref} is missing rk_epoch"
            ))
        })?;
        let scope = material.scope.clone().ok_or_else(|| {
            StorageError::service_error(format!("retired material {material_ref} is missing scope"))
        })?;

        if target_state == "destroyed" {
            return Ok(Self {
                kind: material.kind.clone(),
                rk_epoch,
                state: target_state.to_string(),
                scope,
                wrapped_by: None,
                wrap_algorithm: None,
                nonce: None,
                wrapped_key_b64: None,
            });
        }

        Ok(Self {
            kind: material.kind.clone(),
            rk_epoch,
            state: target_state.to_string(),
            scope,
            wrapped_by: Some(material.wrapped_by.clone().ok_or_else(|| {
                StorageError::service_error(format!(
                    "retired material {material_ref} is missing wrapped_by"
                ))
            })?),
            wrap_algorithm: Some(material.wrap_algorithm.clone().ok_or_else(|| {
                StorageError::service_error(format!(
                    "retired material {material_ref} is missing wrap_algorithm"
                ))
            })?),
            nonce: Some(material.nonce.clone().ok_or_else(|| {
                StorageError::service_error(format!(
                    "retired material {material_ref} is missing nonce"
                ))
            })?),
            wrapped_key_b64: Some(material.wrapped_key_b64.clone().ok_or_else(|| {
                StorageError::service_error(format!(
                    "retired material {material_ref} is missing wrapped_key_b64"
                ))
            })?),
        })
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct RuntimeResourceKeyRetireResponse {
    pub target_state: String,
    pub settings_mutated: bool,
    pub materials: BTreeMap<String, RuntimeResourceKeyRetireMaterialPatch>,
}

fn runtime_resource_key_is_referenced(
    settings: &Settings,
    material_ref: &str,
) -> Result<bool, StorageError> {
    for (instance_name, instance) in &settings.crypto.instances {
        if instance
            .materials
            .values()
            .any(|referenced_material| referenced_material == material_ref)
        {
            return Ok(true);
        }

        let Some(retired_materials) = instance.options.get("retired_materials") else {
            continue;
        };
        let Some(retired_materials) = retired_materials.as_array() else {
            return Err(StorageError::bad_request(format!(
                "runtime crypto instance {instance_name} has malformed retired_materials option"
            )));
        };
        for retired_material in retired_materials {
            let Some(retired_material) = retired_material.as_object() else {
                return Err(StorageError::bad_request(format!(
                    "runtime crypto instance {instance_name} has malformed retired_materials option"
                )));
            };
            let Some(retired_material) = retired_material
                .get("material")
                .and_then(serde_json::Value::as_str)
            else {
                return Err(StorageError::bad_request(format!(
                    "runtime crypto instance {instance_name} has malformed retired_materials option"
                )));
            };
            if retired_material == material_ref {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn build_runtime_resource_key_retire_response(
    settings: &Settings,
    request: RuntimeResourceKeyRetireRequest,
) -> Result<RuntimeResourceKeyRetireResponse, StorageError> {
    request.validate().map_err(|err| {
        StorageError::bad_request(format!(
            "crypto resource-key retirement request is invalid: {err}"
        ))
    })?;

    let mut seen_materials = HashSet::new();
    let mut materials = BTreeMap::new();
    for material_ref in &request.materials {
        validate_runtime_resource_key_rewrap_identifier(material_ref).map_err(|err| {
            StorageError::bad_request(format!(
                "crypto resource-key retirement material id is invalid: {err}"
            ))
        })?;
        if !seen_materials.insert(material_ref) {
            return Err(StorageError::bad_request(format!(
                "crypto resource-key retirement material {material_ref} is duplicated"
            )));
        }
        let material = settings.crypto.materials.get(material_ref).ok_or_else(|| {
            StorageError::bad_request(format!(
                "crypto resource-key retirement material {material_ref} is unknown"
            ))
        })?;
        if material.kind != "wrapped_symmetric_key_32" {
            return Err(StorageError::bad_request(format!(
                "crypto resource-key retirement material {material_ref} must be wrapped_symmetric_key_32",
            )));
        }
        if material.state.as_deref() != Some("retired") {
            return Err(StorageError::bad_request(format!(
                "crypto resource-key retirement material {material_ref} must already have state retired",
            )));
        }
        if runtime_resource_key_is_referenced(settings, material_ref)? {
            return Err(StorageError::bad_request(format!(
                "crypto resource-key retirement material {material_ref} is still referenced by a runtime crypto instance; remove active or retired_materials references after verified migration before retirement",
            )));
        }
        materials.insert(
            material_ref.clone(),
            RuntimeResourceKeyRetireMaterialPatch::from_retired_material(
                material_ref,
                material,
                &request.target_state,
            )?,
        );
    }

    Ok(RuntimeResourceKeyRetireResponse {
        target_state: request.target_state,
        settings_mutated: false,
        materials,
    })
}

#[post("/crypto/resource-keys/retire")]
async fn retire_runtime_resource_keys(
    settings: web::Data<Settings>,
    operation: Json<RuntimeResourceKeyRetireRequest>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();

    let future = async {
        auth.check_global_access(
            AccessRequirements::new().manage(),
            "retire_runtime_resource_keys",
        )?;
        build_runtime_resource_key_retire_response(settings.get_ref(), operation.into_inner())
    };

    helpers::process_response(future.await, timing, None)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        LocalMasterKeyProvider, MasterKeyProvider, RESOURCE_KEY_WRAP_ALGORITHM, SecretKey,
    };

    use super::*;
    use crate::settings::{CryptoInstanceConfig, CryptoSettings};

    fn resource_key_wrap_test_aad(
        material_name: &str,
        material: &CryptoMaterialConfig,
        wrapped_by: &str,
    ) -> Vec<u8> {
        let epoch = material
            .rk_epoch
            .map(|epoch| epoch.to_string())
            .unwrap_or_default();
        let scope = material.scope.as_deref().unwrap_or_default();
        let values = [
            "qdrant-sec",
            "v1",
            "resource-key-wrap",
            material_name,
            &epoch,
            scope,
            wrapped_by,
            RESOURCE_KEY_WRAP_ALGORITHM,
        ];

        let mut aad = Vec::new();
        for value in values {
            let bytes = value.as_bytes();
            aad.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            aad.extend_from_slice(bytes);
        }
        aad
    }

    fn wrapped_resource_key_material(
        material_name: &str,
        rk_secret: [u8; 32],
        rk_epoch: u64,
        state: Option<&str>,
    ) -> CryptoMaterialConfig {
        let wrapped_by = "tenant-a/mk-v1";
        let mut material = CryptoMaterialConfig {
            kind: "wrapped_symmetric_key_32".to_string(),
            wrapped_by: Some(wrapped_by.to_string()),
            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
            rk_epoch: Some(rk_epoch),
            state: state.map(ToString::to_string),
            scope: Some("collection:docs".to_string()),
            ..CryptoMaterialConfig::default()
        };
        let aad = resource_key_wrap_test_aad(material_name, &material, wrapped_by);
        let wrapped = LocalMasterKeyProvider::new(wrapped_by, SecretKey::from_bytes([91u8; 32]))
            .unwrap()
            .wrap_resource_key(&SecretKey::from_bytes(rk_secret), &aad)
            .unwrap();
        material.nonce = Some(wrapped.nonce);
        material.wrapped_key_b64 = Some(wrapped.wrapped_key);
        material
    }

    #[test]
    fn runtime_generate_response_returns_applyable_new_resource_key_patch() {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::new(),
            backends: HashMap::new(),
            materials: HashMap::from([(
                "tenant-a/mk-v1".to_string(),
                CryptoMaterialConfig {
                    kind: "wrapping_key_32".to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[91u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
        };

        let response = build_runtime_resource_key_generate_response(
            &settings,
            RuntimeResourceKeyGenerateRequest {
                material: "tenant-a/payload-rk-v4".to_string(),
                wrapped_by: "tenant-a/mk-v1".to_string(),
                rk_epoch: 4,
                scope: "collection:docs/payload:body".to_string(),
            },
        )
        .unwrap();

        assert!(!response.settings_mutated);
        assert_eq!(response.wrapped_by, "tenant-a/mk-v1");
        assert_eq!(
            settings
                .crypto
                .materials
                .contains_key("tenant-a/payload-rk-v4"),
            false,
            "generation endpoint must return a patch, not mutate runtime settings in place",
        );
        let patch = response.materials.get("tenant-a/payload-rk-v4").unwrap();
        assert_eq!(patch.kind, "wrapped_symmetric_key_32");
        assert_eq!(patch.wrapped_by, "tenant-a/mk-v1");
        assert_eq!(patch.wrap_algorithm, RESOURCE_KEY_WRAP_ALGORITHM);
        assert_eq!(patch.rk_epoch, 4);
        assert_eq!(patch.state.as_deref(), Some("active"));
        assert_eq!(patch.scope, "collection:docs/payload:body");
        assert!(!patch.nonce.is_empty());
        assert!(!patch.wrapped_key_b64.is_empty());
    }

    #[test]
    fn runtime_generate_response_rejects_duplicate_material_and_bad_epoch() {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::new(),
            backends: HashMap::new(),
            materials: HashMap::from([
                (
                    "tenant-a/mk-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: "wrapping_key_32".to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[91u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                ),
                (
                    "tenant-a/payload-rk-v4".to_string(),
                    wrapped_resource_key_material("tenant-a/payload-rk-v4", [93u8; 32], 4, None),
                ),
            ]),
        };

        let duplicate = build_runtime_resource_key_generate_response(
            &settings,
            RuntimeResourceKeyGenerateRequest {
                material: "tenant-a/payload-rk-v4".to_string(),
                wrapped_by: "tenant-a/mk-v1".to_string(),
                rk_epoch: 4,
                scope: "collection:docs/payload:body".to_string(),
            },
        )
        .expect_err("duplicate generated material id must fail");
        assert!(
            duplicate.to_string().contains("material already exists"),
            "{duplicate}",
        );

        let bad_epoch = build_runtime_resource_key_generate_response(
            &settings,
            RuntimeResourceKeyGenerateRequest {
                material: "tenant-a/payload-rk-v5".to_string(),
                wrapped_by: "tenant-a/mk-v1".to_string(),
                rk_epoch: 0,
                scope: "collection:docs/payload:body".to_string(),
            },
        )
        .expect_err("zero resource-key epoch must fail validation");
        assert!(
            bad_epoch
                .to_string()
                .contains("crypto resource-key generation request is invalid"),
            "{bad_epoch}",
        );
    }

    #[test]
    fn runtime_rewrap_response_returns_applyable_material_patch_without_mutating_settings() {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::new(),
            backends: HashMap::new(),
            materials: HashMap::from([
                (
                    "tenant-a/mk-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: "wrapping_key_32".to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[91u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                ),
                (
                    "tenant-a/mk-v2".to_string(),
                    CryptoMaterialConfig {
                        kind: "wrapping_key_32".to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[92u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                ),
                (
                    "tenant-a/payload-rk-v3".to_string(),
                    wrapped_resource_key_material("tenant-a/payload-rk-v3", [93u8; 32], 3, None),
                ),
                (
                    "tenant-a/payload-rk-v2".to_string(),
                    wrapped_resource_key_material(
                        "tenant-a/payload-rk-v2",
                        [94u8; 32],
                        2,
                        Some("retired"),
                    ),
                ),
                (
                    "tenant-a/destroyed-rk-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: "wrapped_symmetric_key_32".to_string(),
                        rk_epoch: Some(1),
                        state: Some("destroyed".to_string()),
                        scope: Some("collection:docs".to_string()),
                        ..CryptoMaterialConfig::default()
                    },
                ),
            ]),
        };

        let response = build_runtime_resource_key_rewrap_response(
            &settings,
            RuntimeResourceKeyRewrapRequest {
                old_wrapped_by: "tenant-a/mk-v1".to_string(),
                new_wrapped_by: "tenant-a/mk-v2".to_string(),
            },
        )
        .unwrap();

        assert!(!response.settings_mutated);
        assert_eq!(response.materials.len(), 2);
        assert_eq!(
            settings
                .crypto
                .materials
                .get("tenant-a/payload-rk-v3")
                .unwrap()
                .wrapped_by
                .as_deref(),
            Some("tenant-a/mk-v1"),
            "the endpoint must return a patch artifact, not mutate runtime settings in place",
        );

        let active = response.materials.get("tenant-a/payload-rk-v3").unwrap();
        assert_eq!(active.kind, "wrapped_symmetric_key_32");
        assert_eq!(active.wrapped_by, "tenant-a/mk-v2");
        assert_eq!(active.wrap_algorithm, RESOURCE_KEY_WRAP_ALGORITHM);
        assert_eq!(active.rk_epoch, 3);
        assert_eq!(active.scope, "collection:docs");
        assert_ne!(
            active.nonce,
            settings
                .crypto
                .materials
                .get("tenant-a/payload-rk-v3")
                .unwrap()
                .nonce
                .as_deref()
                .unwrap(),
        );

        let retired = response.materials.get("tenant-a/payload-rk-v2").unwrap();
        assert_eq!(retired.state.as_deref(), Some("retired"));
        assert_eq!(retired.rk_epoch, 2);
        assert!(!response.materials.contains_key("tenant-a/destroyed-rk-v1"));
    }

    #[test]
    fn runtime_rewrap_response_rejects_malformed_material_identifiers() {
        let settings = Settings::new(None).unwrap();

        for request in [
            RuntimeResourceKeyRewrapRequest {
                old_wrapped_by: "tenant a/mk-v1".to_string(),
                new_wrapped_by: "tenant-a/mk-v2".to_string(),
            },
            RuntimeResourceKeyRewrapRequest {
                old_wrapped_by: "tenant-a/mk-v1".to_string(),
                new_wrapped_by: "tenant-a/mk?2".to_string(),
            },
            RuntimeResourceKeyRewrapRequest {
                old_wrapped_by: String::new(),
                new_wrapped_by: "tenant-a/mk-v2".to_string(),
            },
        ] {
            let err = build_runtime_resource_key_rewrap_response(&settings, request)
                .expect_err("malformed material identifiers must fail before runtime lookup");
            assert!(
                err.to_string()
                    .contains("crypto resource-key rewrap request is invalid"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn runtime_retire_response_requires_unreferenced_retired_materials() {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_v1".to_string(),
                CryptoInstanceConfig {
                    provider: "payload/aes-256-gcm@v1".to_string(),
                    materials: HashMap::from([(
                        "sym_key".to_string(),
                        "tenant-a/payload-rk-v3".to_string(),
                    )]),
                    backend_ref: None,
                    options: serde_json::json!({
                        "retired_materials": [{
                            "material": "tenant-a/payload-rk-v2",
                            "material_fingerprint_id": "tenant-a/payload@v2"
                        }]
                    }),
                },
            )]),
            backends: HashMap::new(),
            materials: HashMap::from([
                (
                    "tenant-a/payload-rk-v3".to_string(),
                    wrapped_resource_key_material("tenant-a/payload-rk-v3", [93u8; 32], 3, None),
                ),
                (
                    "tenant-a/payload-rk-v2".to_string(),
                    wrapped_resource_key_material(
                        "tenant-a/payload-rk-v2",
                        [94u8; 32],
                        2,
                        Some("retired"),
                    ),
                ),
            ]),
        };

        let referenced = build_runtime_resource_key_retire_response(
            &settings,
            RuntimeResourceKeyRetireRequest {
                materials: vec!["tenant-a/payload-rk-v2".to_string()],
                target_state: "disabled".to_string(),
            },
        )
        .expect_err("referenced retired materials must not be retired by patch");
        assert!(
            referenced.to_string().contains("still referenced"),
            "unexpected error: {referenced}",
        );

        settings
            .crypto
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options = serde_json::json!({});
        let response = build_runtime_resource_key_retire_response(
            &settings,
            RuntimeResourceKeyRetireRequest {
                materials: vec!["tenant-a/payload-rk-v2".to_string()],
                target_state: "disabled".to_string(),
            },
        )
        .unwrap();

        assert!(!response.settings_mutated);
        let patch = response.materials.get("tenant-a/payload-rk-v2").unwrap();
        assert_eq!(patch.state, "disabled");
        assert_eq!(patch.rk_epoch, 2);
        assert_eq!(patch.scope, "collection:docs");
        assert!(patch.wrapped_by.is_some());
        assert_eq!(
            settings
                .crypto
                .materials
                .get("tenant-a/payload-rk-v2")
                .unwrap()
                .state
                .as_deref(),
            Some("retired"),
            "the endpoint must return a patch artifact, not mutate runtime settings in place",
        );
    }

    #[test]
    fn runtime_retire_response_destroy_patch_shreds_wrapped_material() {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::new(),
            backends: HashMap::new(),
            materials: HashMap::from([
                (
                    "tenant-a/payload-rk-v3".to_string(),
                    wrapped_resource_key_material("tenant-a/payload-rk-v3", [93u8; 32], 3, None),
                ),
                (
                    "tenant-a/payload-rk-v2".to_string(),
                    wrapped_resource_key_material(
                        "tenant-a/payload-rk-v2",
                        [94u8; 32],
                        2,
                        Some("retired"),
                    ),
                ),
            ]),
        };

        let active_err = build_runtime_resource_key_retire_response(
            &settings,
            RuntimeResourceKeyRetireRequest {
                materials: vec!["tenant-a/payload-rk-v3".to_string()],
                target_state: "destroyed".to_string(),
            },
        )
        .expect_err("active resource keys must not be destroyed through retirement");
        assert!(
            active_err
                .to_string()
                .contains("must already have state retired"),
            "unexpected error: {active_err}",
        );

        let response = build_runtime_resource_key_retire_response(
            &settings,
            RuntimeResourceKeyRetireRequest {
                materials: vec!["tenant-a/payload-rk-v2".to_string()],
                target_state: "destroyed".to_string(),
            },
        )
        .unwrap();
        let patch = response.materials.get("tenant-a/payload-rk-v2").unwrap();
        assert_eq!(patch.state, "destroyed");
        assert_eq!(patch.rk_epoch, 2);
        assert_eq!(patch.scope, "collection:docs");
        assert!(patch.wrapped_by.is_none());
        assert!(patch.wrap_algorithm.is_none());
        assert!(patch.nonce.is_none());
        assert!(patch.wrapped_key_b64.is_none());
    }
}

// Configure services
pub fn config_service_api(cfg: &mut web::ServiceConfig) {
    cfg.service(telemetry)
        .service(metrics)
        .service(get_stacktrace)
        .service(healthz)
        .service(livez)
        .service(readyz)
        .service(get_logger_config)
        .service(update_logger_config)
        .service(generate_runtime_resource_key)
        .service(rewrap_runtime_resource_keys)
        .service(retire_runtime_resource_keys)
        .service(truncate_unapplied_wal);
}

// Dedicated service for metrics
pub fn config_metrics_api(cfg: &mut web::ServiceConfig) {
    cfg.service(metrics);
}
