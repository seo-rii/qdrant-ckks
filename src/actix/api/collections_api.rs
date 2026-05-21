use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path as FsPath;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actix_web::rt::time::Instant;
use actix_web::{HttpResponse, Responder, delete, get, patch, post, put, web};
use actix_web_validator::{Json, Path, Query};
use collection::config::{
    CollectionConfigInternal, CryptoMigrationCheckpoint, CryptoMigrationPlan, CryptoMigrationState,
    EncryptionSelector,
};
use collection::operations::cluster_ops::ClusterOperations;
use collection::operations::types::CollectionError;
use collection::operations::verification::new_unchecked_verification_pass;
use serde::{Deserialize, Serialize};
use shard::operations::optimization::OptimizationsRequestOptions;
use storage::content_manager::collection_meta_ops::{
    ApplyCryptoMigrationPlan, ChangeAliasesOperation, CollectionMetaOperations, CreateCollection,
    CreateCollectionOperation, DeleteCollectionOperation, UpdateCollection,
    UpdateCollectionOperation,
};
use storage::content_manager::errors::StorageError;
use storage::dispatcher::Dispatcher;
use storage::rbac::AccessRequirements;
use validator::{Validate, ValidationError};

use super::CollectionPath;
use crate::actix::api::StrictCollectionPath;
use crate::actix::auth::ActixAuth;
use crate::actix::helpers::{self, process_response};
use crate::common::collections::*;
use crate::common::crypto::{
    validate_collection_crypto_runtime, validate_create_collection_crypto_runtime,
};
use crate::common::update::{
    do_decrypt_payloads_for_crypto_migration, do_reencrypt_stale_payloads_for_crypto_migration,
};
use crate::settings::Settings;

#[derive(Debug, Deserialize, Validate)]
pub struct WaitTimeout {
    #[validate(range(min = 1))]
    timeout: Option<u64>,
}

impl WaitTimeout {
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout.map(Duration::from_secs)
    }
}

#[get("/collections")]
async fn get_collections(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_list_collections(dispatcher.toc(&auth, &pass), &auth)).await
}

#[get("/aliases")]
async fn get_aliases(
    dispatcher: web::Data<Dispatcher>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_list_aliases(dispatcher.toc(&auth, &pass), &auth)).await
}

#[get("/collections/{collection_name}")]
async fn get_collection(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_get_collection(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection.collection_name,
        None,
    ))
    .await
}

#[get("/collections/{collection_name}/crypto/manifest")]
async fn get_collection_crypto_manifest(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let timing = Instant::now();
    let pass = new_unchecked_verification_pass();
    let collection_name = collection.collection_name.clone();

    let response = async {
        let collection_pass = auth.check_collection_access(
            &collection_name,
            AccessRequirements::new().manage(),
            "get_collection_crypto_manifest",
        )?;
        let collection = dispatcher
            .toc(&auth, &pass)
            .get_collection(&collection_pass)
            .await?;
        let config = collection.config_snapshot().await;
        build_collection_crypto_manifest_response(&collection_name, &config, settings.get_ref())
    };

    process_response(response.await, timing, None)
}

#[get("/collections/{collection_name}/exists")]
async fn get_collection_existence(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_collection_exists(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection.collection_name,
    ))
    .await
}

#[get("/collections/{collection_name}/aliases")]
async fn get_collection_aliases(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_list_collection_aliases(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection.collection_name,
    ))
    .await
}

#[put("/collections/{collection_name}")]
async fn create_collection(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<StrictCollectionPath>,
    operation: Json<CreateCollection>,
    settings: web::Data<Settings>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> HttpResponse {
    let timing = Instant::now();
    let collection_name = collection.collection_name.clone();
    let operation = operation.into_inner();
    if let Err(err) =
        validate_create_collection_crypto_runtime(settings.get_ref(), &collection_name, &operation)
    {
        return process_response::<bool>(Err(err), timing, None);
    }

    let create_collection_op = CreateCollectionOperation::new(collection_name, operation);

    let Ok(create_collection_op) = create_collection_op else {
        return process_response(create_collection_op, timing, None);
    };

    let response = dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::CreateCollection(create_collection_op),
            auth,
            query.timeout(),
        )
        .await;
    process_response(response, timing, None)
}

#[patch("/collections/{collection_name}")]
async fn update_collection(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    operation: Json<UpdateCollection>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let name = collection.collection_name.clone();
    let response = dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::UpdateCollection(UpdateCollectionOperation::new(
                name,
                operation.into_inner(),
            )),
            auth,
            query.timeout(),
        )
        .await;
    process_response(response, timing, None)
}

#[post("/collections/{collection_name}/crypto/migration/plan")]
async fn apply_crypto_migration_plan(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    operation: Json<CryptoMigrationPlan>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let plan = operation.into_inner();
    let response = if let Err(err) = validate_standalone_crypto_migration_plan(&plan) {
        Err(StorageError::bad_input(format!(
            "crypto migration plan is invalid: {err}"
        )))
    } else {
        dispatcher
            .submit_collection_meta_op(
                CollectionMetaOperations::ApplyCryptoMigration(ApplyCryptoMigrationPlan {
                    collection_name: collection.collection_name.clone(),
                    plan,
                }),
                auth,
                query.timeout(),
            )
            .await
    };
    process_response(response, timing, None)
}

fn validate_standalone_crypto_migration_plan(
    plan: &CryptoMigrationPlan,
) -> Result<(), ValidationError> {
    plan.validate_admin_plan()?;
    if plan.requires_verified_completion() {
        return Err(ValidationError::new(
            "crypto_migration_completion_requires_run_payloads",
        ));
    }

    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, Validate)]
pub struct RunPayloadCryptoMigration {
    pub active_rk_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_rk_id: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct RunPayloadCryptoMigrationResponse {
    pub checkpoints: Vec<CryptoMigrationCheckpoint>,
    pub completion_plan: CryptoMigrationPlan,
    pub completed: bool,
    pub dry_run: bool,
}

const PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE: &str = "payload_crypto_migration_last_run.json";

#[derive(Debug, Serialize)]
struct PayloadCryptoMigrationRunRecord {
    collection_name: String,
    stable_crypto_id: String,
    checkpoints: Vec<CryptoMigrationCheckpoint>,
    completion_plan: CryptoMigrationPlan,
    completed: bool,
    dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct CollectionCryptoManifestResponse {
    pub collection_name: String,
    pub stable_crypto_id: String,
    pub crypto_schema_version: u16,
    pub encryption_epoch: u64,
    pub migration_state: CryptoMigrationState,
    pub rules: Vec<CollectionCryptoManifestRule>,
    pub resource_keys: Vec<CollectionCryptoManifestResourceKey>,
}

#[derive(Debug, Serialize)]
pub struct CollectionCryptoManifestRule {
    pub rule_id: String,
    pub selector: String,
    pub instance: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_material: Option<String>,
    pub retired_materials: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_rk_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_rk_epoch: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CollectionCryptoManifestResourceKey {
    pub rk_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub material_ref: Option<String>,
    pub epoch: u64,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_by: Option<String>,
    pub used_by_rules: Vec<String>,
}

#[derive(Debug)]
struct CollectionCryptoManifestResourceKeyBuilder {
    material_ref: Option<String>,
    epoch: u64,
    state: String,
    scope: Option<String>,
    wrapped_by: Option<String>,
    used_by_rules: Vec<String>,
}

fn selector_kind(selector: &EncryptionSelector) -> &'static str {
    match selector {
        EncryptionSelector::PayloadPaths { .. } => "payload_paths",
        EncryptionSelector::VectorNames { .. } => "vector_names",
        EncryptionSelector::MetadataKeys { .. } => "metadata_keys",
    }
}

fn option_string<'a>(options: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    options.get(key).and_then(serde_json::Value::as_str)
}

fn option_u64(options: &serde_json::Value, key: &str) -> Option<u64> {
    options.get(key).and_then(serde_json::Value::as_u64)
}

fn add_manifest_material_resource_key(
    material_ref: &str,
    rule_id: &str,
    settings: &Settings,
    resource_keys: &mut BTreeMap<String, CollectionCryptoManifestResourceKeyBuilder>,
) -> Result<(), StorageError> {
    let Some(material) = settings.crypto.materials.get(material_ref) else {
        return Err(StorageError::bad_request(format!(
            "crypto manifest material {material_ref} is referenced by rule {rule_id} but is missing from runtime settings",
        )));
    };
    let Some(epoch) = material.rk_epoch else {
        return Err(StorageError::bad_request(format!(
            "crypto manifest material {material_ref} is referenced by rule {rule_id} but is missing rk_epoch",
        )));
    };
    let state = material
        .state
        .clone()
        .unwrap_or_else(|| "active".to_string());
    let entry = resource_keys
        .entry(material_ref.to_string())
        .or_insert_with(|| CollectionCryptoManifestResourceKeyBuilder {
            material_ref: Some(material_ref.to_string()),
            epoch,
            state,
            scope: material.scope.clone(),
            wrapped_by: material.wrapped_by.clone(),
            used_by_rules: Vec::new(),
        });

    if entry.epoch != epoch || entry.state != material.state.as_deref().unwrap_or("active") {
        return Err(StorageError::bad_request(format!(
            "crypto manifest material {material_ref} has inconsistent RK metadata across rules",
        )));
    }
    if !entry
        .used_by_rules
        .iter()
        .any(|existing| existing == rule_id)
    {
        entry.used_by_rules.push(rule_id.to_string());
    }

    Ok(())
}

fn add_manifest_client_resource_key(
    rk_id: &str,
    epoch: u64,
    rule_id: &str,
    resource_keys: &mut BTreeMap<String, CollectionCryptoManifestResourceKeyBuilder>,
) -> Result<(), StorageError> {
    let entry = resource_keys.entry(rk_id.to_string()).or_insert_with(|| {
        CollectionCryptoManifestResourceKeyBuilder {
            material_ref: None,
            epoch,
            state: "active".to_string(),
            scope: Some("client-envelope".to_string()),
            wrapped_by: None,
            used_by_rules: Vec::new(),
        }
    });

    if entry.epoch != epoch || entry.state != "active" {
        return Err(StorageError::bad_request(format!(
            "crypto manifest client RK {rk_id} has inconsistent policy metadata across rules",
        )));
    }
    if !entry
        .used_by_rules
        .iter()
        .any(|existing| existing == rule_id)
    {
        entry.used_by_rules.push(rule_id.to_string());
    }

    Ok(())
}

fn build_collection_crypto_manifest_response(
    collection_name: &str,
    config: &CollectionConfigInternal,
    settings: &Settings,
) -> Result<CollectionCryptoManifestResponse, StorageError> {
    let encryption = config.params.effective_encryption().ok_or_else(|| {
        StorageError::bad_request(format!(
            "collection {collection_name} does not have encryption configured",
        ))
    })?;
    validate_collection_crypto_runtime(settings, collection_name, &config.params)?;

    let stable_crypto_id = config.stable_crypto_id(collection_name)?;
    let mut rules = Vec::new();
    let mut resource_keys = BTreeMap::new();

    for rule in &encryption.rules {
        let instance = settings
            .crypto
            .instances
            .get(&rule.instance)
            .ok_or_else(|| {
                StorageError::bad_request(format!(
                    "collection {collection_name} references unknown crypto instance {}",
                    rule.instance
                ))
            })?;
        let active_material = instance.materials.get("sym_key").cloned();
        if let Some(material_ref) = active_material.as_deref() {
            add_manifest_material_resource_key(
                material_ref,
                &rule.id,
                settings,
                &mut resource_keys,
            )?;
        }

        let mut retired_materials = Vec::new();
        if let Some(retired) = instance.options.get("retired_materials") {
            let Some(retired) = retired.as_array() else {
                return Err(StorageError::bad_request(format!(
                    "collection {collection_name} crypto instance {} has malformed retired_materials",
                    rule.instance
                )));
            };
            for retired_entry in retired {
                let Some(material_ref) = retired_entry
                    .as_object()
                    .and_then(|entry| entry.get("material"))
                    .and_then(serde_json::Value::as_str)
                else {
                    return Err(StorageError::bad_request(format!(
                        "collection {collection_name} crypto instance {} has malformed retired_materials",
                        rule.instance
                    )));
                };
                add_manifest_material_resource_key(
                    material_ref,
                    &rule.id,
                    settings,
                    &mut resource_keys,
                )?;
                retired_materials.push(material_ref.to_string());
            }
        }

        let client_rk_id =
            option_string(&instance.options, "expected_rk_id").map(ToOwned::to_owned);
        let client_rk_epoch = match (
            option_u64(&instance.options, "min_rk_epoch"),
            option_u64(&instance.options, "max_rk_epoch"),
        ) {
            (Some(min), Some(max)) if min == max => Some(min),
            _ => None,
        };
        if let (Some(rk_id), Some(epoch)) = (client_rk_id.as_deref(), client_rk_epoch) {
            add_manifest_client_resource_key(rk_id, epoch, &rule.id, &mut resource_keys)?;
        }

        rules.push(CollectionCryptoManifestRule {
            rule_id: rule.id.clone(),
            selector: selector_kind(&rule.selector).to_string(),
            instance: rule.instance.clone(),
            provider: instance.provider.clone(),
            binding: rule.binding.clone(),
            active_material,
            retired_materials,
            client_rk_id,
            client_rk_epoch,
        });
    }

    Ok(CollectionCryptoManifestResponse {
        collection_name: collection_name.to_string(),
        stable_crypto_id,
        crypto_schema_version: encryption.crypto_schema_version,
        encryption_epoch: encryption.encryption_epoch,
        migration_state: encryption.migration_state,
        rules,
        resource_keys: resource_keys
            .into_iter()
            .map(|(rk_id, key)| CollectionCryptoManifestResourceKey {
                rk_id,
                material_ref: key.material_ref,
                epoch: key.epoch,
                state: key.state,
                scope: key.scope,
                wrapped_by: key.wrapped_by,
                used_by_rules: key.used_by_rules,
            })
            .collect(),
    })
}

fn payload_crypto_migration_completion_plan(
    migration_state: CryptoMigrationState,
    target_epoch: u64,
    request: RunPayloadCryptoMigration,
    checkpoints: Vec<CryptoMigrationCheckpoint>,
) -> Result<CryptoMigrationPlan, CollectionError> {
    validate_payload_crypto_migration_run_request(migration_state, &request)?;

    let retired_rk_id = if migration_state == CryptoMigrationState::Rotating {
        request.retired_rk_id
    } else {
        None
    };

    Ok(CryptoMigrationPlan {
        from: migration_state,
        to: payload_crypto_migration_completion_state(migration_state)?,
        target_epoch,
        active_rk_id: Some(request.active_rk_id),
        retired_rk_id,
        dry_run: request.dry_run,
        checkpoints,
    })
}

fn payload_crypto_migration_completion_state(
    migration_state: CryptoMigrationState,
) -> Result<CryptoMigrationState, CollectionError> {
    match migration_state {
        CryptoMigrationState::Encrypting | CryptoMigrationState::Rotating => {
            Ok(CryptoMigrationState::Active)
        }
        CryptoMigrationState::Decrypting => Ok(CryptoMigrationState::Disabled),
        CryptoMigrationState::Disabled | CryptoMigrationState::Active => {
            Err(CollectionError::bad_input(format!(
                "payload crypto migration run requires migration_state=encrypting, rotating, or decrypting; current state is {migration_state:?}",
            )))
        }
    }
}

fn validate_payload_crypto_migration_run_request(
    migration_state: CryptoMigrationState,
    request: &RunPayloadCryptoMigration,
) -> Result<(), CollectionError> {
    if request.active_rk_id.is_empty() {
        return Err(CollectionError::bad_input(
            "payload crypto migration run requires active_rk_id",
        ));
    }

    payload_crypto_migration_completion_state(migration_state)?;

    if migration_state == CryptoMigrationState::Rotating {
        if request.retired_rk_id.is_none() {
            return Err(CollectionError::bad_input(
                "payload crypto rotation run requires retired_rk_id for completion",
            ));
        }
    } else if request.retired_rk_id.is_some() {
        return Err(CollectionError::bad_input(
            "retired_rk_id is only valid while completing rotating payload crypto migration",
        ));
    }

    Ok(())
}

fn validate_payload_crypto_migration_run_request_for_config(
    migration_state: CryptoMigrationState,
    target_epoch: u64,
    request: &RunPayloadCryptoMigration,
    encryption: &collection::config::CollectionEncryptionConfig,
) -> Result<(), CollectionError> {
    validate_payload_crypto_migration_run_request(migration_state, request)?;
    let preflight_plan = CryptoMigrationPlan {
        from: migration_state,
        to: payload_crypto_migration_completion_state(migration_state)?,
        target_epoch,
        active_rk_id: Some(request.active_rk_id.clone()),
        retired_rk_id: if migration_state == CryptoMigrationState::Rotating {
            Some(request.retired_rk_id.clone().ok_or_else(|| {
                CollectionError::bad_input(
                    "payload crypto rotation run requires retired_rk_id for completion",
                )
            })?)
        } else {
            None
        },
        dry_run: false,
        checkpoints: vec![CryptoMigrationCheckpoint {
            shard_id: 0,
            total_points: 1,
            processed_points: 1,
            rewritten_points: 1,
            changed_points: 0,
            status: collection::config::CryptoMigrationCheckpointStatus::Verified,
        }],
    };
    preflight_plan
        .validate_admin_plan_for_config(encryption)
        .map_err(|err| {
            CollectionError::bad_input(format!(
                "payload crypto migration request is invalid for current config: {err}"
            ))
        })
}

fn persist_payload_crypto_migration_run_record(
    collection_path: &FsPath,
    record: &PayloadCryptoMigrationRunRecord,
) -> Result<(), StorageError> {
    validate_payload_crypto_migration_record_directory(collection_path)?;
    let record_path = collection_path.join(PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE);
    validate_payload_crypto_migration_record_target(&record_path)?;
    let temp_suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_path = collection_path.join(format!(
        ".{PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE}.{}.{}.tmp",
        std::process::id(),
        temp_suffix,
    ));
    let bytes = serde_json::to_vec_pretty(record).map_err(|err| {
        StorageError::service_error(format!(
            "failed to serialize payload crypto migration run record: {err}"
        ))
    })?;
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .apply_private_payload_crypto_migration_record_open_options()
            .open(&temp_path)
            .map_err(|err| {
                StorageError::service_error(format!(
                    "failed to create payload crypto migration run record {temp_path:?}: {err}"
                ))
            })?;
        file.write_all(&bytes).map_err(|err| {
            StorageError::service_error(format!(
                "failed to write payload crypto migration run record {temp_path:?}: {err}"
            ))
        })?;
        file.sync_all().map_err(|err| {
            StorageError::service_error(format!(
                "failed to sync payload crypto migration run record {temp_path:?}: {err}"
            ))
        })?;
    }
    fs::rename(&temp_path, &record_path).map_err(|err| {
        StorageError::service_error(format!(
            "failed to replace payload crypto migration run record {record_path:?}: {err}"
        ))
    })?;
    set_private_payload_crypto_migration_record_permissions(&record_path)?;
    if let Ok(parent) = fs::File::open(collection_path) {
        parent.sync_all().map_err(|err| {
            StorageError::service_error(format!(
                "failed to sync payload crypto migration run record parent {collection_path:?}: {err}"
            ))
        })?;
    }
    Ok(())
}

trait PayloadCryptoMigrationRecordOpenOptionsExt {
    fn apply_private_payload_crypto_migration_record_open_options(&mut self) -> &mut Self;
}

impl PayloadCryptoMigrationRecordOpenOptionsExt for fs::OpenOptions {
    fn apply_private_payload_crypto_migration_record_open_options(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            self.mode(0o600)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        }

        #[cfg(not(unix))]
        {
            self
        }
    }
}

fn validate_payload_crypto_migration_record_directory(
    collection_path: &FsPath,
) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(collection_path).map_err(|err| {
        StorageError::service_error(format!(
            "failed to inspect payload crypto migration run record directory {collection_path:?}: {err}",
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::service_error(format!(
            "payload crypto migration run record directory must be a regular non-symlink directory: {collection_path:?}",
        )));
    }

    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(StorageError::service_error(format!(
            "payload crypto migration run record directory must not be group/world-writable: {collection_path:?}",
        )));
    }

    Ok(())
}

fn validate_payload_crypto_migration_record_target(
    record_path: &FsPath,
) -> Result<(), StorageError> {
    let Ok(metadata) = fs::symlink_metadata(record_path) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::service_error(format!(
            "payload crypto migration run record target must be a regular non-symlink file: {record_path:?}",
        )));
    }

    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StorageError::service_error(format!(
            "payload crypto migration run record target must not be group/world-accessible: {record_path:?}",
        )));
    }

    Ok(())
}

fn set_private_payload_crypto_migration_record_permissions(
    record_path: &FsPath,
) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(record_path)
            .map_err(|err| {
                StorageError::service_error(format!(
                    "failed to inspect payload crypto migration run record {record_path:?}: {err}",
                ))
            })?
            .permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(record_path, permissions).map_err(|err| {
            StorageError::service_error(format!(
                "failed to restrict payload crypto migration run record permissions {record_path:?}: {err}",
            ))
        })?;
    }

    Ok(())
}

#[post("/collections/{collection_name}/crypto/migration/run-payloads")]
async fn run_payloads_for_crypto_migration(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    operation: Json<RunPayloadCryptoMigration>,
    settings: web::Data<Settings>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let pass = new_unchecked_verification_pass();
    let collection_name = collection.collection_name.clone();

    let response = async {
        let collection_pass = auth.check_collection_access(
            &collection_name,
            AccessRequirements::new().manage(),
            "run_payloads_for_crypto_migration",
        )?;
        let collection = dispatcher
            .toc(&auth, &pass)
            .get_collection(&collection_pass)
            .await?;
        let config = collection.config_snapshot().await;
        let encryption = config.params.effective_encryption().ok_or_else(|| {
            CollectionError::bad_input(format!(
                "payload crypto migration for collection {collection_name} requires an encrypted collection",
            ))
        })?;
        let migration_state = encryption.migration_state;
        let target_epoch = encryption.encryption_epoch;
        let request = operation.into_inner();
        let dry_run = request.dry_run;

        validate_payload_crypto_migration_run_request_for_config(
            migration_state,
            target_epoch,
            &request,
            &encryption,
        )
        .map_err(StorageError::from)?;

        let checkpoints = match migration_state {
            CryptoMigrationState::Encrypting | CryptoMigrationState::Rotating => {
                do_reencrypt_stale_payloads_for_crypto_migration(
                    dispatcher.toc(&auth, &pass),
                    &collection_name,
                    settings.get_ref(),
                    &auth,
                    dry_run,
                )
                .await?
            }
            CryptoMigrationState::Decrypting => {
                do_decrypt_payloads_for_crypto_migration(
                    dispatcher.toc(&auth, &pass),
                    &collection_name,
                    settings.get_ref(),
                    &auth,
                    dry_run,
                )
                .await?
            }
            CryptoMigrationState::Disabled | CryptoMigrationState::Active => {
                return Err(StorageError::bad_input(format!(
                    "payload crypto migration run for collection {collection_name} requires migration_state=encrypting, rotating, or decrypting; current state is {migration_state:?}",
                )));
            }
        };

        let completion_plan = payload_crypto_migration_completion_plan(
            migration_state,
            target_epoch,
            request,
            checkpoints,
        )
        .map_err(StorageError::from)?;
        let completed_plan_is_valid = if dry_run {
            let mut applyable_plan = completion_plan.clone();
            applyable_plan.dry_run = false;
            applyable_plan.validate_admin_plan_for_config(&encryption)
        } else {
            completion_plan.validate_admin_plan_for_config(&encryption)
        };
        completed_plan_is_valid.map_err(|err| {
            StorageError::bad_input(format!(
                "payload crypto migration completion plan is invalid: {err}",
            ))
        })?;
        let completed = if dry_run {
            false
        } else {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::ApplyCryptoMigration(ApplyCryptoMigrationPlan {
                        collection_name: collection_name.clone(),
                        plan: completion_plan.clone(),
                    }),
                    auth,
                    query.timeout(),
                )
                .await?
        };
        persist_payload_crypto_migration_run_record(
            collection.path(),
            &PayloadCryptoMigrationRunRecord {
                collection_name: collection_name.clone(),
                stable_crypto_id: config.stable_crypto_id(&collection_name).map_err(StorageError::from)?,
                checkpoints: completion_plan.checkpoints.clone(),
                completion_plan: completion_plan.clone(),
                completed,
                dry_run,
            },
        )?;

        Ok(RunPayloadCryptoMigrationResponse {
            checkpoints: completion_plan.checkpoints.clone(),
            completion_plan,
            completed,
            dry_run,
        })
    }
    .await;

    process_response(response, timing, None)
}

#[delete("/collections/{collection_name}")]
async fn delete_collection(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let response = dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::DeleteCollection(DeleteCollectionOperation(
                collection.collection_name.clone(),
            )),
            auth,
            query.timeout(),
        )
        .await;
    process_response(response, timing, None)
}

#[post("/collections/aliases")]
async fn update_aliases(
    dispatcher: web::Data<Dispatcher>,
    operation: Json<ChangeAliasesOperation>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let response = dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::ChangeAliases(operation.0),
            auth,
            query.timeout(),
        )
        .await;
    process_response(response, timing, None)
}

#[get("/collections/{collection_name}/cluster")]
async fn get_cluster_info(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    // No request to verify
    let pass = new_unchecked_verification_pass();

    helpers::time(do_get_collection_cluster(
        dispatcher.toc(&auth, &pass),
        &auth,
        &collection.collection_name,
    ))
    .await
}

#[post("/collections/{collection_name}/cluster")]
async fn update_collection_cluster(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    operation: Json<ClusterOperations>,
    Query(query): Query<WaitTimeout>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let wait_timeout = query.timeout();
    let response = do_update_collection_cluster(
        &dispatcher.into_inner(),
        collection.collection_name.clone(),
        operation.0,
        auth,
        wait_timeout,
    )
    .await;
    process_response(response, timing, None)
}

#[derive(Deserialize, Clone, Validate)]
struct OptimizationsParam {
    with: Option<String>,
    completed_limit: Option<u64>,
}

const DEFAULT_OPTIMIZATIONS_COMPLETED_LIMIT: u64 = 16;

impl TryFrom<&OptimizationsParam> for OptimizationsRequestOptions {
    type Error = CollectionError;

    fn try_from(
        params: &OptimizationsParam,
    ) -> Result<OptimizationsRequestOptions, CollectionError> {
        let OptimizationsParam {
            with,
            completed_limit,
        } = params;
        let completed_limit =
            completed_limit.unwrap_or(DEFAULT_OPTIMIZATIONS_COMPLETED_LIMIT) as usize;
        let mut options = OptimizationsRequestOptions {
            queued: false,
            completed_limit: None,
            idle_segments: false,
        };
        for field in with.as_deref().unwrap_or("").split(',') {
            match field.trim() {
                "" => (),
                "queued" => options.queued = true,
                "completed" => options.completed_limit = Some(completed_limit),
                "idle_segments" => options.idle_segments = true,
                _ => Err(CollectionError::bad_input(format!(
                    "Unknown field in 'with' parameter: {field}"
                )))?,
            }
        }
        Ok(options)
    }
}

#[get("/collections/{collection_name}/optimizations")]
fn get_optimizations(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    ActixAuth(auth): ActixAuth,
    params: Query<OptimizationsParam>,
) -> impl Future<Output = HttpResponse> {
    helpers::time(async move {
        let options = OptimizationsRequestOptions::try_from(&params.into_inner())?;
        let pass = new_unchecked_verification_pass();
        let collection_pass = auth.check_collection_access(
            &collection.collection_name,
            AccessRequirements::new(),
            "get_optimizations",
        )?;
        Ok(dispatcher
            .toc(&auth, &pass)
            .get_collection(&collection_pass)
            .await?
            .optimizations(options)
            .await?)
    })
}

// Configure services
pub fn config_collections_api(cfg: &mut web::ServiceConfig) {
    // Ordering of services is important for correct path pattern matching
    // See: <https://github.com/qdrant/qdrant/issues/3543>
    cfg.service(update_aliases)
        .service(get_collections)
        .service(get_collection)
        .service(get_collection_crypto_manifest)
        .service(get_collection_existence)
        .service(create_collection)
        .service(update_collection)
        .service(apply_crypto_migration_plan)
        .service(run_payloads_for_crypto_migration)
        .service(delete_collection)
        .service(get_aliases)
        .service(get_collection_aliases)
        .service(get_cluster_info)
        .service(get_optimizations)
        .service(update_collection_cluster);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use actix_web::web::Query;
    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationCheckpointStatus,
        EncryptionRuleRef, EncryptionSelector, WalConfig,
    };
    use collection::optimizers_builder::OptimizersConfig;
    use segment::types::HnswConfig;
    use serde_json::{Value, json};
    use uuid::Uuid;

    use super::*;
    use crate::settings::{CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings};

    #[test]
    fn timeout_is_deserialized() {
        let timeout: WaitTimeout = Query::from_query("").unwrap().0;
        assert!(timeout.timeout.is_none());
        let timeout: WaitTimeout = Query::from_query("timeout=10").unwrap().0;
        assert_eq!(timeout.timeout, Some(10))
    }

    #[actix_web::test]
    async fn legacy_partial_payload_migration_endpoints_are_not_registered() {
        let app =
            actix_web::test::init_service(actix_web::App::new().configure(config_collections_api))
                .await;

        for path in [
            "/collections/docs/crypto/migration/rewrite-payloads",
            "/collections/docs/crypto/migration/decrypt-payloads",
        ] {
            let request = actix_web::test::TestRequest::post().uri(path).to_request();
            let response = actix_web::test::call_service(&app, request).await;
            assert_eq!(
                response.status(),
                actix_web::http::StatusCode::NOT_FOUND,
                "{path} must not remain as a partial migration mutation endpoint",
            );
        }
    }

    fn verified_checkpoint() -> CryptoMigrationCheckpoint {
        CryptoMigrationCheckpoint {
            shard_id: 0,
            total_points: 3,
            processed_points: 3,
            rewritten_points: 3,
            changed_points: 2,
            status: CryptoMigrationCheckpointStatus::Verified,
        }
    }

    fn payload_crypto_migration_run_test_record() -> PayloadCryptoMigrationRunRecord {
        let completion_plan = payload_crypto_migration_completion_plan(
            CryptoMigrationState::Rotating,
            4,
            RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: false,
            },
            vec![verified_checkpoint()],
        )
        .unwrap();

        PayloadCryptoMigrationRunRecord {
            collection_name: "docs".to_string(),
            stable_crypto_id: "12345678-90ab-cdef-1234-567890abcdef".to_string(),
            checkpoints: completion_plan.checkpoints.clone(),
            completion_plan,
            completed: true,
            dry_run: false,
        }
    }

    fn migration_config(state: CryptoMigrationState, epoch: u64) -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("rk/docs/4".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: epoch,
            migration_state: state,
            rules: vec![EncryptionRuleRef {
                id: "body_conf".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["body".to_string()],
                },
                instance: "docs_payload_v1".to_string(),
                binding: Some("payload-field/v1".to_string()),
            }],
        }
    }

    fn config_with_encryption(encryption: CollectionEncryptionConfig) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                encryption: Some(encryption),
                ..CollectionParams::empty()
            },
            hnsw_config: HnswConfig::default(),
            optimizer_config: OptimizersConfig {
                deleted_threshold: 0.1,
                vacuum_min_vector_number: 1000,
                default_segment_number: 0,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: None,
                indexing_threshold: Some(100_000),
                flush_interval_sec: 60,
                max_optimization_threads: Some(0),
                prevent_unoptimized: None,
            },
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(Uuid::from_u128(0x1234567890abcdef1234567890abcdef)),
            metadata: None,
        }
    }

    fn crypto_settings_for_manifest() -> Settings {
        Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([
                    (
                        "docs_payload_v1".to_string(),
                        CryptoInstanceConfig {
                            provider: "payload/aes-256-gcm@v1".to_string(),
                            materials: HashMap::from([(
                                "sym_key".to_string(),
                                "tenant-a/server-rk-v4".to_string(),
                            )]),
                            backend_ref: None,
                            options: json!({
                                "key_id": "tenant-a:docs",
                                "material_fingerprint_id": "tenant-a/server-rk-v4@fp",
                                "retired_materials": [{
                                    "material": "tenant-a/server-rk-v3",
                                    "material_fingerprint_id": "tenant-a/server-rk-v3@fp",
                                }],
                            }),
                        },
                    ),
                    (
                        "docs_client_v1".to_string(),
                        CryptoInstanceConfig {
                            provider: "payload/client-aead@v1".to_string(),
                            materials: HashMap::new(),
                            backend_ref: None,
                            options: json!({
                                "key_id": "tenant-a:docs",
                                "key_id_required": true,
                                "expected_rk_id": "tenant-a:docs",
                                "min_rk_epoch": 4,
                                "max_rk_epoch": 4,
                                "signature_public_keys": {
                                    "tenant-a/client-signing-v1": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
                                },
                            }),
                        },
                    ),
                ]),
                materials: HashMap::from([
                    (
                        "tenant-a/server-rk-v4".to_string(),
                        CryptoMaterialConfig {
                            kind: "symmetric_key_32".to_string(),
                            source: Some("inline".to_string()),
                            value_b64: Some(
                                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_string(),
                            ),
                            rk_epoch: Some(4),
                            state: Some("active".to_string()),
                            scope: Some("collection:docs".to_string()),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (
                        "tenant-a/server-rk-v3".to_string(),
                        CryptoMaterialConfig {
                            kind: "symmetric_key_32".to_string(),
                            source: Some("inline".to_string()),
                            value_b64: Some(
                                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_string(),
                            ),
                            rk_epoch: Some(3),
                            state: Some("retired".to_string()),
                            scope: Some("collection:docs".to_string()),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                ]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        }
    }

    fn manifest_encryption_config() -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:docs".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 4,
            migration_state: CryptoMigrationState::Active,
            rules: vec![
                EncryptionRuleRef {
                    id: "body_server".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                },
                EncryptionRuleRef {
                    id: "body_client".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["client_body".to_string()],
                    },
                    instance: "docs_client_v1".to_string(),
                    binding: Some("client-payload-envelope/v1".to_string()),
                },
            ],
        }
    }

    #[test]
    fn payload_crypto_migration_run_builds_completion_plan_for_rotation() {
        let plan = payload_crypto_migration_completion_plan(
            CryptoMigrationState::Rotating,
            4,
            RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: false,
            },
            vec![verified_checkpoint()],
        )
        .unwrap();

        assert_eq!(plan.from, CryptoMigrationState::Rotating);
        assert_eq!(plan.to, CryptoMigrationState::Active);
        assert_eq!(plan.target_epoch, 4);
        assert_eq!(plan.active_rk_id.as_deref(), Some("rk/docs/4"));
        assert_eq!(plan.retired_rk_id.as_deref(), Some("rk/docs/3"));
        plan.validate_admin_plan().unwrap();
    }

    #[test]
    fn payload_crypto_migration_dry_run_completion_plan_is_not_applyable() {
        let plan = payload_crypto_migration_completion_plan(
            CryptoMigrationState::Rotating,
            4,
            RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: true,
            },
            vec![verified_checkpoint()],
        )
        .unwrap();

        assert!(plan.dry_run);
        let err = plan
            .validate_admin_plan()
            .expect_err("dry-run completion plans must not be directly applyable");
        assert_eq!(
            err.code.as_ref(),
            "crypto_migration_completion_cannot_be_dry_run"
        );
    }

    #[test]
    fn standalone_crypto_migration_plan_rejects_completion_transitions() {
        let completion_plan = payload_crypto_migration_completion_plan(
            CryptoMigrationState::Rotating,
            4,
            RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: false,
            },
            vec![verified_checkpoint()],
        )
        .unwrap();
        completion_plan.validate_admin_plan().unwrap();

        let err = validate_standalone_crypto_migration_plan(&completion_plan)
            .expect_err("standalone endpoint must not close migration state");
        assert_eq!(
            err.code.as_ref(),
            "crypto_migration_completion_requires_run_payloads"
        );

        let start_plan = CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 4,
            active_rk_id: Some("rk/docs/4".to_string()),
            retired_rk_id: Some("rk/docs/3".to_string()),
            checkpoints: Vec::new(),
            dry_run: false,
        };
        validate_standalone_crypto_migration_plan(&start_plan).unwrap();
    }

    #[test]
    fn payload_crypto_migration_run_rejects_invalid_rk_ids_for_state() {
        assert!(
            payload_crypto_migration_completion_plan(
                CryptoMigrationState::Rotating,
                4,
                RunPayloadCryptoMigration {
                    active_rk_id: "rk/docs/4".to_string(),
                    retired_rk_id: None,
                    dry_run: false,
                },
                vec![verified_checkpoint()],
            )
            .is_err()
        );

        assert!(
            payload_crypto_migration_completion_plan(
                CryptoMigrationState::Decrypting,
                3,
                RunPayloadCryptoMigration {
                    active_rk_id: "rk/docs/3".to_string(),
                    retired_rk_id: Some("rk/docs/2".to_string()),
                    dry_run: false,
                },
                vec![verified_checkpoint()],
            )
            .is_err()
        );

        assert!(
            payload_crypto_migration_completion_plan(
                CryptoMigrationState::Active,
                3,
                RunPayloadCryptoMigration {
                    active_rk_id: "rk/docs/3".to_string(),
                    retired_rk_id: None,
                    dry_run: false,
                },
                vec![verified_checkpoint()],
            )
            .is_err()
        );
    }

    #[test]
    fn payload_crypto_migration_run_preflights_request_before_rewrite() {
        let rotating = migration_config(CryptoMigrationState::Rotating, 4);

        let missing_retired = validate_payload_crypto_migration_run_request_for_config(
            CryptoMigrationState::Rotating,
            4,
            &RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: None,
                dry_run: false,
            },
            &rotating,
        );
        assert!(
            missing_retired.is_err(),
            "rotation run must reject missing retired_rk_id before rewriting payloads",
        );

        let malformed_active_rk = validate_payload_crypto_migration_run_request_for_config(
            CryptoMigrationState::Rotating,
            4,
            &RunPayloadCryptoMigration {
                active_rk_id: "rk docs 4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: false,
            },
            &rotating,
        );
        assert!(
            malformed_active_rk.is_err(),
            "migration run must reject malformed active_rk_id before rewriting payloads",
        );

        validate_payload_crypto_migration_run_request_for_config(
            CryptoMigrationState::Rotating,
            4,
            &RunPayloadCryptoMigration {
                active_rk_id: "rk/docs/4".to_string(),
                retired_rk_id: Some("rk/docs/3".to_string()),
                dry_run: false,
            },
            &rotating,
        )
        .unwrap();
    }

    #[test]
    fn payload_crypto_migration_run_record_persists_completion_plan_for_resume() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let record = payload_crypto_migration_run_test_record();

        persist_payload_crypto_migration_run_record(dir.path(), &record).unwrap();
        let record_path = dir.path().join(PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE);

        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&record_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "payload migration run record must be private"
        );

        let persisted: Value =
            serde_json::from_slice(&std::fs::read(record_path).unwrap()).unwrap();
        assert_eq!(persisted["collection_name"], "docs");
        assert_eq!(
            persisted["stable_crypto_id"],
            "12345678-90ab-cdef-1234-567890abcdef"
        );
        assert_eq!(persisted["completed"], true);
        assert_eq!(persisted["dry_run"], false);
        assert_eq!(persisted["completion_plan"]["from"], "rotating");
        assert_eq!(persisted["completion_plan"]["to"], "active");
        assert_eq!(persisted["checkpoints"][0]["status"], "verified");
    }

    #[cfg(unix)]
    #[test]
    fn payload_crypto_migration_run_record_rejects_symlink_target() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-symlink-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let target_path = dir.path().join("attacker-controlled-record.json");
        std::fs::write(&target_path, b"{}").unwrap();
        let record_path = dir.path().join(PAYLOAD_CRYPTO_MIGRATION_LAST_RUN_FILE);
        symlink(&target_path, &record_path).unwrap();

        let err = persist_payload_crypto_migration_run_record(
            dir.path(),
            &payload_crypto_migration_run_test_record(),
        )
        .expect_err("payload migration run record must reject symlink target");
        assert!(
            err.to_string().contains("non-symlink file"),
            "unexpected error: {err}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn payload_crypto_migration_run_record_rejects_writable_directory() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-payload-migration-record-dir-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let mut permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        permissions.set_mode(0o722);
        std::fs::set_permissions(dir.path(), permissions).unwrap();

        let err = persist_payload_crypto_migration_run_record(
            dir.path(),
            &payload_crypto_migration_run_test_record(),
        )
        .expect_err("payload migration run record must reject writable collection directory");
        assert!(
            err.to_string().contains("group/world-writable"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn collection_crypto_manifest_reports_non_secret_runtime_key_manifest() {
        let settings = crypto_settings_for_manifest();
        let config = config_with_encryption(manifest_encryption_config());

        let manifest = build_collection_crypto_manifest_response("docs", &config, &settings)
            .expect("valid collection crypto runtime must build a manifest");

        assert_eq!(manifest.collection_name, "docs");
        assert_eq!(
            manifest.stable_crypto_id,
            "12345678-90ab-cdef-1234-567890abcdef"
        );
        assert_eq!(manifest.encryption_epoch, 4);
        assert_eq!(manifest.rules.len(), 2);
        assert_eq!(manifest.resource_keys.len(), 3);

        let active = manifest
            .resource_keys
            .iter()
            .find(|key| key.rk_id == "tenant-a/server-rk-v4")
            .unwrap();
        assert_eq!(
            active.material_ref.as_deref(),
            Some("tenant-a/server-rk-v4")
        );
        assert_eq!(active.epoch, 4);
        assert_eq!(active.state, "active");
        assert_eq!(active.scope.as_deref(), Some("collection:docs"));
        assert_eq!(active.wrapped_by, None);
        assert_eq!(active.used_by_rules, vec!["body_server".to_string()]);

        let retired = manifest
            .resource_keys
            .iter()
            .find(|key| key.rk_id == "tenant-a/server-rk-v3")
            .unwrap();
        assert_eq!(retired.epoch, 3);
        assert_eq!(retired.state, "retired");

        let client = manifest
            .resource_keys
            .iter()
            .find(|key| key.rk_id == "tenant-a:docs")
            .unwrap();
        assert_eq!(client.material_ref, None);
        assert_eq!(client.epoch, 4);
        assert_eq!(client.scope.as_deref(), Some("client-envelope"));
        assert_eq!(client.used_by_rules, vec!["body_client".to_string()]);
    }

    #[test]
    fn collection_crypto_manifest_fails_closed_on_runtime_mismatch() {
        let mut settings = crypto_settings_for_manifest();
        settings
            .crypto
            .materials
            .get_mut("tenant-a/server-rk-v4")
            .unwrap()
            .rk_epoch = None;
        let config = config_with_encryption(manifest_encryption_config());

        let err = build_collection_crypto_manifest_response("docs", &config, &settings)
            .expect_err("manifest must not hide runtime RK metadata mismatch");

        assert!(
            err.to_string()
                .contains("server-side AEAD material must set rk_epoch")
                || err.to_string().contains("missing rk_epoch"),
            "{err}",
        );
    }
}
