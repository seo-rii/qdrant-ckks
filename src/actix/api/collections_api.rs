use std::time::Duration;

use actix_web::rt::time::Instant;
use actix_web::{HttpResponse, Responder, delete, get, patch, post, put, web};
use actix_web_validator::{Json, Path, Query};
use collection::config::{CryptoMigrationCheckpoint, CryptoMigrationPlan, CryptoMigrationState};
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
use validator::Validate;

use super::CollectionPath;
use crate::actix::api::StrictCollectionPath;
use crate::actix::auth::ActixAuth;
use crate::actix::helpers::{self, process_response};
use crate::common::collections::*;
use crate::common::crypto::validate_create_collection_crypto_runtime;
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
    let response = dispatcher
        .submit_collection_meta_op(
            CollectionMetaOperations::ApplyCryptoMigration(ApplyCryptoMigrationPlan {
                collection_name: collection.collection_name.clone(),
                plan: operation.into_inner(),
            }),
            auth,
            query.timeout(),
        )
        .await;
    process_response(response, timing, None)
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
        dry_run: false,
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
        completion_plan
            .validate_admin_plan_for_config(&encryption)
            .map_err(|err| {
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

#[post("/collections/{collection_name}/crypto/migration/rewrite-payloads")]
async fn rewrite_payloads_for_crypto_migration(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let pass = new_unchecked_verification_pass();
    let response = do_reencrypt_stale_payloads_for_crypto_migration(
        dispatcher.toc(&auth, &pass),
        &collection.collection_name,
        settings.get_ref(),
        &auth,
        false,
    )
    .await;
    process_response(response, timing, None)
}

#[post("/collections/{collection_name}/crypto/migration/decrypt-payloads")]
async fn decrypt_payloads_for_crypto_migration(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let timing = Instant::now();
    let pass = new_unchecked_verification_pass();
    let response = do_decrypt_payloads_for_crypto_migration(
        dispatcher.toc(&auth, &pass),
        &collection.collection_name,
        settings.get_ref(),
        &auth,
        false,
    )
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
        .service(get_collection_existence)
        .service(create_collection)
        .service(update_collection)
        .service(apply_crypto_migration_plan)
        .service(run_payloads_for_crypto_migration)
        .service(rewrite_payloads_for_crypto_migration)
        .service(decrypt_payloads_for_crypto_migration)
        .service(delete_collection)
        .service(get_aliases)
        .service(get_collection_aliases)
        .service(get_cluster_info)
        .service(get_optimizations)
        .service(update_collection_cluster);
}

#[cfg(test)]
mod tests {
    use actix_web::web::Query;
    use collection::config::{
        CollectionEncryptionConfig, CryptoMigrationCheckpointStatus, EncryptionRuleRef,
        EncryptionSelector,
    };

    use super::*;

    #[test]
    fn timeout_is_deserialized() {
        let timeout: WaitTimeout = Query::from_query("").unwrap().0;
        assert!(timeout.timeout.is_none());
        let timeout: WaitTimeout = Query::from_query("timeout=10").unwrap().0;
        assert_eq!(timeout.timeout, Some(10))
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
}
