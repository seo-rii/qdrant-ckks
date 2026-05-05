use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use api::rest::models::InferenceUsage;
use api::rest::*;
use collection::collection::Collection;
use collection::config::CollectionParams;
use collection::operations::conversions::write_ordering_from_proto;
use collection::operations::point_ops::*;
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::types::{
    CollectionError, CollectionResult, CollectionUpdateProvenance, UpdateResult,
};
use collection::operations::vector_ops::*;
use collection::operations::verification::*;
use collection::shards::shard::ShardId;
use common::counter::hardware_accumulator::HwMeasurementAcc;
use qdrant_sec::{
    ClientPayloadNonceReplayKey, ClientPayloadVerifiedEnvelopeKey, ENCRYPTED_VECTOR_SIDECAR_FIELD,
    PayloadEncryptionError,
};
use schemars::JsonSchema;
use segment::data_types::vectors::DEFAULT_VECTOR_NAME;
use segment::json_path::{JsonPath, JsonPathItem};
use segment::types::{Filter, Payload, PayloadFieldSchema, PayloadKeyType, StrictModeConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_with::DurationSeconds;
use shard::operations::payload_ops::*;
use shard::operations::*;
use storage::content_manager::collection_meta_ops::*;
use storage::content_manager::collection_verification::check_strict_mode;
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::Dispatcher;
use storage::rbac::{Access, AccessRequirements, Auth, CollectionMultipass};
use validator::Validate;

use crate::common::crypto::{
    PayloadWriteSetupError, payload_write_plan_for_collection_with_crypto_id,
    vector_write_plan_for_collection_with_crypto_id,
};
use crate::common::inference::params::InferenceParams;
use crate::common::inference::service::InferenceType;
use crate::common::inference::update_requests::*;
use crate::common::strict_mode::*;
use crate::settings::Settings;

#[serde_with::serde_as]
#[derive(Copy, Clone, Debug, Deserialize, Serialize, Validate)]
pub struct UpdateParams {
    #[serde(default)]
    pub wait: bool,
    #[serde(default)]
    pub ordering: WriteOrdering,
    #[serde_as(as = "Option<DurationSeconds<String>>")]
    pub timeout: Option<Duration>,
}

impl UpdateParams {
    pub fn from_grpc(
        wait: Option<bool>,
        ordering: Option<api::grpc::qdrant::WriteOrdering>,
        timeout: Option<u64>,
    ) -> tonic::Result<Self> {
        let params = Self {
            wait: wait.unwrap_or(false),
            ordering: write_ordering_from_proto(ordering)?,
            timeout: timeout.map(Duration::from_secs),
        };

        Ok(params)
    }

    pub(crate) fn timeout_as_secs(&self) -> Option<usize> {
        self.timeout.map(|timeout| timeout.as_secs() as usize)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct InternalUpdateParams {
    pub shard_id: Option<ShardId>,
    pub clock_tag: Option<ClockTag>,
    /// When present, fully overrides the `wait` boolean from the public API message.
    /// When absent, falls back to the `wait` boolean (backward compatible with older nodes).
    pub wait_override: Option<collection::shards::shard_trait::WaitUntil>,
}

impl InternalUpdateParams {
    pub fn from_grpc(
        shard_id: Option<ShardId>,
        clock_tag: Option<api::grpc::qdrant::ClockTag>,
        wait_override: Option<i32>,
    ) -> Self {
        Self {
            shard_id,
            clock_tag: clock_tag.map(ClockTag::from),
            wait_override: wait_override
                .and_then(|v| api::grpc::qdrant::WaitUntil::try_from(v).ok())
                .map(collection::shards::shard_trait::WaitUntil::from),
        }
    }
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct UpdateOperations {
    #[validate(nested)]
    pub operations: Vec<UpdateOperation>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum UpdateOperation {
    Upsert(UpsertOperation),
    Delete(DeleteOperation),
    SetPayload(SetPayloadOperation),
    OverwritePayload(OverwritePayloadOperation),
    DeletePayload(DeletePayloadOperation),
    ClearPayload(ClearPayloadOperation),
    UpdateVectors(UpdateVectorsOperation),
    DeleteVectors(DeleteVectorsOperation),
}

impl Validate for UpdateOperation {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            UpdateOperation::Upsert(op) => op.validate(),
            UpdateOperation::Delete(op) => op.validate(),
            UpdateOperation::SetPayload(op) => op.validate(),
            UpdateOperation::OverwritePayload(op) => op.validate(),
            UpdateOperation::DeletePayload(op) => op.validate(),
            UpdateOperation::ClearPayload(op) => op.validate(),
            UpdateOperation::UpdateVectors(op) => op.validate(),
            UpdateOperation::DeleteVectors(op) => op.validate(),
        }
    }
}

impl StrictModeVerification for UpdateOperation {
    fn query_limit(&self) -> Option<usize> {
        None
    }

    fn indexed_filter_read(&self) -> Option<&segment::types::Filter> {
        None
    }

    fn indexed_filter_write(&self) -> Option<&segment::types::Filter> {
        None
    }

    fn request_exact(&self) -> Option<bool> {
        None
    }

    fn request_search_params(&self) -> Option<&segment::types::SearchParams> {
        None
    }

    async fn check_strict_mode(
        &self,
        collection: &Collection,
        strict_mode_config: &StrictModeConfig,
    ) -> CollectionResult<()> {
        match self {
            UpdateOperation::Upsert(op) => {
                op.upsert
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::Delete(op) => {
                op.delete
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::SetPayload(op) => {
                op.set_payload
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::OverwritePayload(op) => {
                op.overwrite_payload
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::DeletePayload(op) => {
                op.delete_payload
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::ClearPayload(op) => {
                op.clear_payload
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::UpdateVectors(op) => {
                op.update_vectors
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
            UpdateOperation::DeleteVectors(op) => {
                op.delete_vectors
                    .check_strict_mode(collection, strict_mode_config)
                    .await
            }
        }
    }
}

impl StrictModeVerification for CreateFieldIndex {
    async fn check_custom(
        &self,
        collection: &Collection,
        strict_mode_config: &StrictModeConfig,
    ) -> CollectionResult<()> {
        if let Some(max_payload_index_count) = strict_mode_config.max_payload_index_count {
            let collection_info = collection.info(&ShardSelectorInternal::All).await?;
            if collection_info.payload_schema.len() >= max_payload_index_count {
                return Err(CollectionError::strict_mode(
                    format!(
                        "Collection already has the maximum number of payload indices ({max_payload_index_count})"
                    ),
                    "Please delete an existing index before creating a new one.",
                ));
            }
        }
        Ok(())
    }

    fn indexed_filter_write(&self) -> Option<&Filter> {
        None
    }

    fn query_limit(&self) -> Option<usize> {
        None
    }

    fn indexed_filter_read(&self) -> Option<&Filter> {
        None
    }

    fn request_exact(&self) -> Option<bool> {
        None
    }

    fn request_search_params(&self) -> Option<&segment::types::SearchParams> {
        None
    }
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct UpsertOperation {
    #[validate(nested)]
    upsert: PointInsertOperations,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct DeleteOperation {
    #[validate(nested)]
    delete: PointsSelector,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct SetPayloadOperation {
    #[validate(nested)]
    set_payload: SetPayload,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct OverwritePayloadOperation {
    #[validate(nested)]
    overwrite_payload: SetPayload,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct DeletePayloadOperation {
    #[validate(nested)]
    delete_payload: DeletePayload,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct ClearPayloadOperation {
    #[validate(nested)]
    clear_payload: PointsSelector,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct UpdateVectorsOperation {
    #[validate(nested)]
    update_vectors: UpdateVectors,
}

#[derive(Deserialize, Serialize, JsonSchema, Validate)]
pub struct DeleteVectorsOperation {
    #[validate(nested)]
    delete_vectors: DeleteVectors,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct CreateFieldIndex {
    pub field_name: PayloadKeyType,
    #[serde(alias = "field_type")]
    #[validate(nested)]
    pub field_schema: Option<PayloadFieldSchema>,
}

#[expect(clippy::too_many_arguments)]
pub async fn do_upsert_points(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: PointInsertOperations,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    inference_params: InferenceParams,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<(UpdateResult, Option<models::InferenceUsage>), StorageError> {
    do_upsert_points_with_replay_cache(
        toc_provider,
        collection_name,
        operation,
        internal_params,
        params,
        auth,
        inference_params,
        hw_measurement_acc,
        runtime_settings,
        None,
    )
    .await
}

#[expect(clippy::too_many_arguments)]
async fn do_upsert_points_with_replay_cache(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: PointInsertOperations,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    inference_params: InferenceParams,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<(UpdateResult, Option<models::InferenceUsage>), StorageError> {
    use point_ops::UpdateMode;
    use segment::types::Filter;

    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let (operation, mut update_provenance) = maybe_encrypt_upsert_payloads(
        toc,
        &collection_name,
        operation,
        &auth,
        runtime_settings,
        client_nonce_replay_cache,
    )
    .await?;

    let (mut operation, shard_key, usage, update_filter, update_mode) = match operation {
        PointInsertOperations::PointsBatch(batch) => {
            let PointsBatch {
                batch,
                shard_key,
                update_filter,
                update_mode,
            } = batch;
            let (batch, usage) = convert_batch(batch, inference_params).await?;
            let operation = PointInsertOperationsInternal::PointsBatch(batch);
            let update_mode = update_mode.map(rest_update_mode_to_internal);
            (operation, shard_key, usage, update_filter, update_mode)
        }
        PointInsertOperations::PointsList(list) => {
            let PointsList {
                points,
                shard_key,
                update_filter,
                update_mode,
            } = list;
            let (list, usage) =
                convert_point_struct(points, InferenceType::Update, inference_params).await?;
            let operation = PointInsertOperationsInternal::PointsList(list);
            let update_mode = update_mode.map(rest_update_mode_to_internal);
            (operation, shard_key, usage, update_filter, update_mode)
        }
    };
    let vector_provenance = maybe_encrypt_upsert_vectors(
        toc,
        &collection_name,
        &mut operation,
        &auth,
        runtime_settings,
    )
    .await?;
    if vector_provenance.allows_vector_sidecars() {
        update_provenance = update_provenance.with_runtime_encrypted_vectors();
    }

    // Decide which operation to use based on update_filter and update_mode
    let operation = match (update_filter, update_mode) {
        // If update_filter is provided, always use conditional upsert
        (Some(condition), mode) => CollectionUpdateOperations::PointOperation(
            PointOperations::UpsertPointsConditional(ConditionalInsertOperationInternal {
                points_op: operation,
                condition,
                update_mode: mode,
            }),
        ),
        // If update_mode is InsertOnly or UpdateOnly, use conditional upsert with empty filter
        (None, Some(UpdateMode::InsertOnly)) | (None, Some(UpdateMode::UpdateOnly)) => {
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPointsConditional(
                ConditionalInsertOperationInternal {
                    points_op: operation,
                    condition: Filter::default(), // Empty filter matches all existing points
                    update_mode,
                },
            ))
        }
        // Default: regular upsert
        (None, None) | (None, Some(UpdateMode::Upsert)) => {
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(operation))
        }
    };

    let result = update(
        toc,
        &collection_name,
        operation,
        internal_params,
        params,
        shard_key,
        auth,
        hw_measurement_acc,
        update_provenance,
    )
    .await?;

    Ok((result, usage))
}

/// Convert REST UpdateMode to internal UpdateMode
fn rest_update_mode_to_internal(mode: api::rest::schema::UpdateMode) -> point_ops::UpdateMode {
    match mode {
        api::rest::schema::UpdateMode::Upsert => point_ops::UpdateMode::Upsert,
        api::rest::schema::UpdateMode::InsertOnly => point_ops::UpdateMode::InsertOnly,
        api::rest::schema::UpdateMode::UpdateOnly => point_ops::UpdateMode::UpdateOnly,
    }
}

pub async fn do_delete_points(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    points: PointsSelector,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(&points, &collection_name, params.timeout_as_secs(), &auth)
        .await?;

    let (operation, shard_key) = match points {
        PointsSelector::PointIdsSelector(PointIdsList { points, shard_key }) => {
            (PointOperations::DeletePoints { ids: points }, shard_key)
        }
        PointsSelector::FilterSelector(FilterSelector { filter, shard_key }) => {
            (PointOperations::DeletePointsByFilter(filter), shard_key)
        }
    };

    let operation = CollectionUpdateOperations::PointOperation(operation);

    update(
        toc,
        &collection_name,
        operation,
        internal_params,
        params,
        shard_key,
        auth,
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

#[expect(clippy::too_many_arguments)]
pub async fn do_update_vectors(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: UpdateVectors,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    inference_params: InferenceParams,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<(UpdateResult, Option<models::InferenceUsage>), StorageError> {
    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let UpdateVectors {
        points,
        shard_key,
        update_filter,
    } = operation;

    let (mut points, usage) =
        convert_point_vectors(points, InferenceType::Update, inference_params).await?;
    let (sidecar_payload_updates, vector_provenance) = maybe_encrypt_update_vectors(
        toc,
        &collection_name,
        &mut points,
        update_filter.as_ref(),
        &auth,
        runtime_settings,
    )
    .await?;

    let mut result = None;
    for payload in sidecar_payload_updates {
        let operation =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: payload.payload,
                points: payload.points,
                filter: payload.filter,
                key: payload.key,
            }));
        result = Some(
            update(
                toc,
                &collection_name,
                operation,
                internal_params,
                params,
                shard_key.clone(),
                auth.clone(),
                hw_measurement_acc.clone(),
                CollectionUpdateProvenance::runtime_encrypted_vectors(),
            )
            .await?,
        );
    }

    if !points.is_empty() {
        let operation = CollectionUpdateOperations::VectorOperation(
            VectorOperations::UpdateVectors(UpdateVectorsOp {
                points,
                update_filter,
            }),
        );

        result = Some(
            update(
                toc,
                &collection_name,
                operation,
                internal_params,
                params,
                shard_key,
                auth,
                hw_measurement_acc,
                vector_provenance,
            )
            .await?,
        );
    }

    let Some(result) = result else {
        return Err(StorageError::bad_request("No vectors provided"));
    };

    Ok((result, usage))
}

pub async fn do_delete_vectors(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: DeleteVectors,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    // TODO: Is this cancel safe!?

    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let DeleteVectors {
        vector,
        filter,
        points,
        shard_key,
    } = operation;

    let vector_names: Vec<_> = vector.into_iter().collect();
    let (vector_names, encrypted_sidecar_keys) =
        split_encrypted_vector_delete_names(toc, &collection_name, &auth, vector_names).await?;

    let mut result = None;

    if let Some(filter) = filter.clone() {
        if !encrypted_sidecar_keys.is_empty() {
            let operation = CollectionUpdateOperations::PayloadOperation(
                PayloadOps::DeletePayload(DeletePayloadOp {
                    keys: encrypted_sidecar_keys.clone(),
                    points: None,
                    filter: Some(filter.clone()),
                }),
            );

            result = Some(
                update(
                    toc,
                    &collection_name,
                    operation,
                    internal_params,
                    params,
                    shard_key.clone(),
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    CollectionUpdateProvenance::runtime_encrypted_vectors(),
                )
                .await?,
            );
        }
        if !vector_names.is_empty() {
            let vectors_operation =
                VectorOperations::DeleteVectorsByFilter(filter, vector_names.clone());

            let operation = CollectionUpdateOperations::VectorOperation(vectors_operation);

            result = Some(
                update(
                    toc,
                    &collection_name,
                    operation,
                    internal_params,
                    params,
                    shard_key.clone(),
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    CollectionUpdateProvenance::client_plaintext(),
                )
                .await?,
            );
        }
    }

    if let Some(points) = points.clone() {
        if !encrypted_sidecar_keys.is_empty() {
            let operation = CollectionUpdateOperations::PayloadOperation(
                PayloadOps::DeletePayload(DeletePayloadOp {
                    keys: encrypted_sidecar_keys,
                    points: Some(points.clone()),
                    filter: None,
                }),
            );

            result = Some(
                update(
                    toc,
                    &collection_name,
                    operation,
                    internal_params,
                    params,
                    shard_key.clone(),
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    CollectionUpdateProvenance::runtime_encrypted_vectors(),
                )
                .await?,
            );
        }
        if !vector_names.is_empty() {
            let vectors_operation = VectorOperations::DeleteVectors(points.into(), vector_names);
            let operation = CollectionUpdateOperations::VectorOperation(vectors_operation);

            result = Some(
                update(
                    toc,
                    &collection_name,
                    operation,
                    internal_params,
                    params,
                    shard_key,
                    auth,
                    hw_measurement_acc,
                    CollectionUpdateProvenance::client_plaintext(),
                )
                .await?,
            );
        }
    }

    result.ok_or_else(|| StorageError::bad_request("No filter or points provided"))
}

pub async fn do_set_payload(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: SetPayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<UpdateResult, StorageError> {
    do_set_payload_with_replay_cache(
        toc_provider,
        collection_name,
        operation,
        internal_params,
        params,
        auth,
        hw_measurement_acc,
        runtime_settings,
        None,
    )
    .await
}

#[expect(clippy::too_many_arguments)]
async fn do_set_payload_with_replay_cache(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: SetPayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let (operations, update_provenance) = maybe_encrypt_point_payload_update(
        toc,
        &collection_name,
        operation,
        &auth,
        runtime_settings,
        "set_payload",
        client_nonce_replay_cache,
    )
    .await?;

    let mut last_result = None;
    for operation in operations.into_operations() {
        let SetPayload {
            points,
            payload,
            filter,
            shard_key,
            key,
        } = operation;

        let operation =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload,
                points,
                filter,
                key,
            }));

        last_result = Some(
            update(
                toc,
                &collection_name,
                operation,
                internal_params,
                params,
                shard_key,
                auth.clone(),
                hw_measurement_acc.clone(),
                update_provenance.clone(),
            )
            .await?,
        );
    }

    last_result.ok_or_else(|| StorageError::bad_request("No points provided"))
}

pub async fn do_overwrite_payload(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: SetPayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<UpdateResult, StorageError> {
    do_overwrite_payload_with_replay_cache(
        toc_provider,
        collection_name,
        operation,
        internal_params,
        params,
        auth,
        hw_measurement_acc,
        runtime_settings,
        None,
    )
    .await
}

#[expect(clippy::too_many_arguments)]
async fn do_overwrite_payload_with_replay_cache(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: SetPayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let (operations, update_provenance) = maybe_encrypt_point_payload_update(
        toc,
        &collection_name,
        operation,
        &auth,
        runtime_settings,
        "overwrite_payload",
        client_nonce_replay_cache,
    )
    .await?;

    let mut last_result = None;
    for operation in operations.into_operations() {
        let SetPayload {
            points,
            payload,
            filter,
            shard_key,
            key: _,
        } = operation;

        let operation = CollectionUpdateOperations::PayloadOperation(PayloadOps::OverwritePayload(
            SetPayloadOp {
                payload,
                points,
                filter,
                // overwrite operation doesn't support payload selector
                key: None,
            },
        ));

        last_result = Some(
            update(
                toc,
                &collection_name,
                operation,
                internal_params,
                params,
                shard_key,
                auth.clone(),
                hw_measurement_acc.clone(),
                update_provenance.clone(),
            )
            .await?,
        );
    }

    last_result.ok_or_else(|| StorageError::bad_request("No points provided"))
}

pub async fn do_delete_payload(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    operation: DeletePayload,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(
            &operation,
            &collection_name,
            params.timeout_as_secs(),
            &auth,
        )
        .await?;

    let DeletePayload {
        keys,
        points,
        filter,
        shard_key,
    } = operation;

    let operation =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(DeletePayloadOp {
            keys,
            points,
            filter,
        }));

    update(
        toc,
        &collection_name,
        operation,
        internal_params,
        params,
        shard_key,
        auth,
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

pub async fn do_clear_payload(
    toc_provider: impl CheckedTocProvider,
    collection_name: String,
    points: PointsSelector,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    let toc = toc_provider
        .check_strict_mode(&points, &collection_name, params.timeout_as_secs(), &auth)
        .await?;

    let (point_operation, shard_key) = match points {
        PointsSelector::PointIdsSelector(PointIdsList { points, shard_key }) => {
            (PayloadOps::ClearPayload { points }, shard_key)
        }
        PointsSelector::FilterSelector(FilterSelector { filter, shard_key }) => {
            (PayloadOps::ClearPayloadByFilter(filter), shard_key)
        }
    };

    let operation = CollectionUpdateOperations::PayloadOperation(point_operation);

    update(
        toc,
        &collection_name,
        operation,
        internal_params,
        params,
        shard_key,
        auth,
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

#[expect(clippy::too_many_arguments)]
pub async fn do_batch_update_points(
    toc_provider: impl CheckedTocProvider + Clone,
    collection_name: String,
    operations: Vec<UpdateOperation>,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    inference_params: InferenceParams,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<(Vec<UpdateResult>, Option<InferenceUsage>), StorageError> {
    // Check strict mode for all batch operations, *before applying* them
    let mut toc = None;

    for operation in &operations {
        toc = toc_provider
            .check_strict_mode(operation, &collection_name, params.timeout_as_secs(), &auth)
            .await?
            .into();
    }

    let Some(toc) = toc else {
        // Batch is empty, return empty result vector
        return Ok((Vec::new(), None));
    };

    // Pass unchecked ToC provider into `do_*` functions, because we already checked strict mode
    let toc_provider = UncheckedTocProvider::new_unchecked(toc);

    let mut results = Vec::with_capacity(operations.len());
    let mut inference_usage = InferenceUsage::default();
    let mut seen_client_nonces = std::collections::HashSet::new();

    for operation in operations {
        let current_update_result = match operation {
            UpdateOperation::Upsert(operation) => {
                let (result, usage) = do_upsert_points_with_replay_cache(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.upsert,
                    internal_params,
                    params,
                    auth.clone(),
                    inference_params.clone(),
                    hw_measurement_acc.clone(),
                    runtime_settings,
                    Some(&mut seen_client_nonces),
                )
                .await?;

                inference_usage.merge_opt(usage);
                result
            }
            UpdateOperation::Delete(operation) => {
                do_delete_points(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.delete,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            UpdateOperation::SetPayload(operation) => {
                do_set_payload_with_replay_cache(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.set_payload,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    runtime_settings,
                    Some(&mut seen_client_nonces),
                )
                .await?
            }
            UpdateOperation::OverwritePayload(operation) => {
                do_overwrite_payload_with_replay_cache(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.overwrite_payload,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                    runtime_settings,
                    Some(&mut seen_client_nonces),
                )
                .await?
            }
            UpdateOperation::DeletePayload(operation) => {
                do_delete_payload(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.delete_payload,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            UpdateOperation::ClearPayload(operation) => {
                do_clear_payload(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.clear_payload,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            UpdateOperation::UpdateVectors(operation) => {
                let (result, usage) = do_update_vectors(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.update_vectors,
                    internal_params,
                    params,
                    auth.clone(),
                    inference_params.clone(),
                    hw_measurement_acc.clone(),
                    runtime_settings,
                )
                .await?;

                inference_usage.merge_opt(usage);
                result
            }
            UpdateOperation::DeleteVectors(operation) => {
                do_delete_vectors(
                    toc_provider.clone(),
                    collection_name.clone(),
                    operation.delete_vectors,
                    internal_params,
                    params,
                    auth.clone(),
                    hw_measurement_acc.clone(),
                )
                .await?
            }
        };

        results.push(current_update_result);
    }

    Ok((results, inference_usage.into_non_empty()))
}

pub async fn do_create_index(
    dispatcher: Arc<Dispatcher>,
    collection_name: String,
    operation: CreateFieldIndex,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    // TODO: Is this cancel safe!?

    // Check strict mode before submitting consensus operation
    let pass = check_strict_mode(
        &operation,
        // Use per-request timeout from params if provided
        params.timeout_as_secs(),
        &collection_name,
        &dispatcher,
        &auth,
    )
    .await?;

    let Some(field_schema) = operation.field_schema else {
        return Err(StorageError::bad_request(
            "Can't auto-detect field type, please specify `field_schema` in the request",
        ));
    };

    let consensus_op = CollectionMetaOperations::CreatePayloadIndex(CreatePayloadIndex {
        collection_name: collection_name.clone(),
        field_name: operation.field_name.clone(),
        field_schema: field_schema.clone(),
    });

    let toc = dispatcher.toc(&auth, &pass).clone();

    ensure_payload_index_allowed_by_encryption(&toc, &collection_name, &operation.field_name)
        .await?;

    // TODO: Is `submit_collection_meta_op` cancel-safe!? Should be, I think?.. 🤔
    dispatcher
        .submit_collection_meta_op(consensus_op, auth, params.timeout)
        .await?;

    // This function is required as long as we want to maintain interface compatibility
    // for `wait` parameter and return type.
    // The idea is to migrate from the point-like interface to consensus-like interface in the next few versions

    do_create_index_internal(
        toc,
        collection_name,
        operation.field_name,
        Some(field_schema),
        internal_params,
        params,
        hw_measurement_acc,
    )
    .await
}

pub async fn do_create_index_internal(
    toc: Arc<TableOfContent>,
    collection_name: String,
    field_name: PayloadKeyType,
    field_schema: Option<PayloadFieldSchema>,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    ensure_payload_index_allowed_by_encryption(&toc, &collection_name, &field_name).await?;

    let operation = CollectionUpdateOperations::FieldIndexOperation(
        FieldIndexOperations::CreateIndex(CreateIndex {
            field_name,
            field_schema,
        }),
    );

    update(
        &toc,
        &collection_name,
        operation,
        internal_params,
        params,
        None,
        Auth::new_internal(Access::full("Internal API")),
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

pub async fn do_delete_index(
    dispatcher: Arc<Dispatcher>,
    collection_name: String,
    index_name: JsonPath,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    // TODO: Is this cancel safe!?

    let consensus_op = CollectionMetaOperations::DropPayloadIndex(DropPayloadIndex {
        collection_name: collection_name.clone(),
        field_name: index_name.clone(),
    });

    // Nothing to verify here.
    let pass = new_unchecked_verification_pass();

    let toc = dispatcher.toc(&auth, &pass).clone();

    // TODO: Is `submit_collection_meta_op` cancel-safe!? Should be, I think?.. 🤔
    dispatcher
        .submit_collection_meta_op(
            consensus_op,
            auth,
            // Use per-request timeout from params if provided
            params.timeout,
        )
        .await?;

    do_delete_index_internal(
        toc,
        collection_name,
        index_name,
        internal_params,
        params,
        hw_measurement_acc,
    )
    .await
}

pub async fn do_delete_index_internal(
    toc: Arc<TableOfContent>,
    collection_name: String,
    index_name: JsonPath,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<UpdateResult, StorageError> {
    let operation = CollectionUpdateOperations::FieldIndexOperation(
        FieldIndexOperations::DeleteIndex(index_name),
    );

    update(
        &toc,
        &collection_name,
        operation,
        internal_params,
        params,
        None,
        Auth::new_internal(Access::full("Internal API")),
        hw_measurement_acc,
        CollectionUpdateProvenance::client_plaintext(),
    )
    .await
}

async fn ensure_payload_index_allowed_by_encryption(
    toc: &TableOfContent,
    collection_name: &str,
    field_name: &JsonPath,
) -> Result<(), StorageError> {
    let multipass = CollectionMultipass;
    let collection_pass = multipass.issue_pass(collection_name);
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Ok(());
    };

    if field_name.first_key == ENCRYPTED_VECTOR_SIDECAR_FIELD {
        return Err(StorageError::bad_input(format!(
            "cannot create payload index on encrypted vector sidecar field '{field_name}'",
        )));
    }

    for rule in &encryption.rules {
        let collection::config::EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
            continue;
        };
        for encrypted_path in paths {
            let encrypted_json_path = encrypted_path.parse::<JsonPath>().map_err(|err| {
                StorageError::bad_input(format!(
                    "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                ))
            })?;
            if field_name.compatible(&encrypted_json_path) {
                return Err(StorageError::bad_input(format!(
                    "cannot create payload index on encrypted payload field '{field_name}' because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                )));
            }
        }
    }

    Ok(())
}

#[expect(clippy::too_many_arguments)]
pub async fn update(
    toc: &TableOfContent,
    collection_name: &str,
    operation: CollectionUpdateOperations,
    internal_params: InternalUpdateParams,
    params: UpdateParams,
    shard_key: Option<ShardKeySelector>,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
    update_provenance: CollectionUpdateProvenance,
) -> Result<UpdateResult, StorageError> {
    let InternalUpdateParams {
        shard_id,
        clock_tag,
        wait_override,
    } = internal_params;

    let UpdateParams {
        wait,
        ordering,
        timeout: _,
    } = params;

    // Use wait_override if present, otherwise fall back to the wait boolean
    let wait =
        wait_override.unwrap_or_else(|| collection::shards::shard_trait::WaitUntil::from(wait));

    let shard_selector = match operation {
        CollectionUpdateOperations::PointOperation(point_ops::PointOperations::SyncPoints(_)) => {
            debug_assert_eq!(
                shard_key, None,
                "Sync points operations can't specify shard key"
            );

            match shard_id {
                Some(shard_id) => ShardSelectorInternal::ShardId(shard_id),
                None => {
                    debug_assert!(false, "Sync operation is supposed to select shard directly");
                    ShardSelectorInternal::Empty
                }
            }
        }

        CollectionUpdateOperations::FieldIndexOperation(_) => {
            debug_assert_eq!(
                shard_key, None,
                "Field index operations can't specify shard key"
            );

            match shard_id {
                Some(shard_id) => ShardSelectorInternal::ShardId(shard_id),
                None => ShardSelectorInternal::All,
            }
        }

        _ => get_shard_selector_for_update(shard_id, shard_key),
    };

    toc.update(
        collection_name,
        OperationWithClockTag::new(operation, clock_tag),
        wait,
        params.timeout,
        ordering,
        shard_selector,
        auth,
        hw_measurement_acc,
        update_provenance,
    )
    .await
}

/// Converts a pair of parameters into a shard selector
/// suitable for update operations.
///
/// The key difference from selector for search operations is that
/// empty shard selector in case of update means default shard,
/// while empty shard selector in case of search means all shards.
///
/// Parameters:
/// - shard_selection: selection of the exact shard ID, always have priority over shard_key
/// - shard_key: selection of the shard key, can be a single key or a list of keys
///
/// Returns:
/// - ShardSelectorInternal - resolved shard selector
fn get_shard_selector_for_update(
    shard_selection: Option<ShardId>,
    shard_key: Option<ShardKeySelector>,
) -> ShardSelectorInternal {
    match (shard_selection, shard_key) {
        (Some(shard_selection), None) => ShardSelectorInternal::ShardId(shard_selection),
        (Some(shard_selection), Some(_)) => {
            debug_assert!(
                false,
                "Shard selection and shard key are mutually exclusive"
            );
            ShardSelectorInternal::ShardId(shard_selection)
        }
        (None, Some(shard_key)) => ShardSelectorInternal::from(shard_key),
        (None, None) => ShardSelectorInternal::Empty,
    }
}

async fn maybe_encrypt_upsert_payloads(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    mut operation: PointInsertOperations,
    auth: &Auth,
    runtime_settings: Option<&Settings>,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<(PointInsertOperations, CollectionUpdateProvenance), StorageError> {
    let Some(runtime_settings) = runtime_settings else {
        ensure_payload_runtime_available_for_upsert(toc, collection_name, &operation, auth).await?;
        return Ok((operation, CollectionUpdateProvenance::client_plaintext()));
    };

    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "upsert_points")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(|err| StorageError::bad_input(err.to_string()))?;
    let Some(plan) = payload_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )
    .map_err(|err| {
        StorageError::service_error(format!(
            "payload encryption runtime for collection {collection_name} is invalid: {err}"
        ))
    })?
    else {
        return Ok((operation, CollectionUpdateProvenance::client_plaintext()));
    };
    let mut local_seen_client_nonces = std::collections::HashSet::new();
    let seen_client_nonces = client_nonce_replay_cache.unwrap_or(&mut local_seen_client_nonces);
    let seen_client_nonces_before = seen_client_nonces.clone();
    let mut verified_client_envelope_keys = std::collections::HashSet::new();

    match &mut operation {
        PointInsertOperations::PointsList(list) => {
            for point in &mut list.points {
                if let Some(payload) = &mut point.payload {
                    let outcome = plan
                        .process_payload_with_replay_cache(
                            &point.id.to_string(),
                            payload,
                            &mut *seen_client_nonces,
                        )
                        .map_err(|err| {
                            payload_write_error_to_storage_error(collection_name, err)
                        })?;
                    verified_client_envelope_keys.extend(outcome.verified_client_envelope_keys);
                }
            }
        }
        PointInsertOperations::PointsBatch(batch) => {
            if let Some(payloads) = batch.batch.payloads.as_mut() {
                for (point_id, payload) in batch.batch.ids.iter().zip(payloads.iter_mut()) {
                    if let Some(payload) = payload {
                        let outcome = plan
                            .process_payload_with_replay_cache(
                                &point_id.to_string(),
                                payload,
                                &mut *seen_client_nonces,
                            )
                            .map_err(|err| {
                                payload_write_error_to_storage_error(collection_name, err)
                            })?;
                        verified_client_envelope_keys.extend(outcome.verified_client_envelope_keys);
                    }
                }
            }
        }
    }
    let update_provenance = payload_update_provenance(
        plan.has_server_encrypt_rules(),
        verified_client_envelope_keys,
    );
    record_process_client_nonce_replay_cache(
        toc,
        &collection_crypto_id,
        seen_client_nonces,
        &seen_client_nonces_before,
    )
    .await?;

    Ok((operation, update_provenance))
}

async fn maybe_encrypt_upsert_vectors(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    operation: &mut PointInsertOperationsInternal,
    auth: &Auth,
    runtime_settings: Option<&Settings>,
) -> Result<CollectionUpdateProvenance, StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "upsert_points")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(|err| StorageError::bad_input(err.to_string()))?;

    let Some(runtime_settings) = runtime_settings else {
        if upsert_vectors_touch_encrypted_config(operation, &collection_config.params)? {
            return Err(StorageError::bad_input(format!(
                "CKKS vector encryption runtime for collection {collection_name} is required before writing encrypted vectors",
            )));
        }
        return Ok(CollectionUpdateProvenance::client_plaintext());
    };

    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )?
    else {
        return Ok(CollectionUpdateProvenance::client_plaintext());
    };

    let mut encrypted = 0;
    match operation {
        PointInsertOperationsInternal::PointsList(points) => {
            for point in points {
                encrypted += encrypt_vectors_for_point(
                    &plan,
                    collection_name,
                    &point.id.to_string(),
                    &mut point.vector,
                    &mut point.payload,
                )?;
            }
        }
        PointInsertOperationsInternal::PointsBatch(batch) => {
            encrypted += encrypt_vectors_for_batch(
                &plan,
                collection_name,
                &batch.ids,
                &mut batch.vectors,
                &mut batch.payloads,
            )?;
        }
    }

    if encrypted == 0 {
        Ok(CollectionUpdateProvenance::client_plaintext())
    } else {
        Ok(CollectionUpdateProvenance::runtime_encrypted_vectors())
    }
}

async fn maybe_encrypt_update_vectors(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    points: &mut Vec<collection::operations::vector_ops::PointVectorsPersisted>,
    update_filter: Option<&Filter>,
    auth: &Auth,
    runtime_settings: Option<&Settings>,
) -> Result<(Vec<SetPayload>, CollectionUpdateProvenance), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "update_vectors")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(|err| StorageError::bad_input(err.to_string()))?;

    let Some(runtime_settings) = runtime_settings else {
        if point_vectors_touch_encrypted_config(points, &collection_config.params)? {
            return Err(StorageError::bad_input(format!(
                "CKKS vector encryption runtime for collection {collection_name} is required before writing encrypted vectors",
            )));
        }
        return Ok((Vec::new(), CollectionUpdateProvenance::client_plaintext()));
    };

    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )?
    else {
        return Ok((Vec::new(), CollectionUpdateProvenance::client_plaintext()));
    };

    let mut sidecar_updates = Vec::new();
    for point in points.iter_mut() {
        let mut payload = None;
        let encrypted = encrypt_vectors_for_point(
            &plan,
            collection_name,
            &point.id.to_string(),
            &mut point.vector,
            &mut payload,
        )?;
        if encrypted > 0 {
            sidecar_updates.push(SetPayload {
                points: Some(vec![point.id]),
                payload: payload.unwrap_or_default(),
                filter: update_filter.cloned(),
                shard_key: None,
                key: None,
            });
        }
    }
    points.retain(|point| !point.vector.is_empty());

    let provenance = if sidecar_updates.is_empty() {
        CollectionUpdateProvenance::client_plaintext()
    } else {
        CollectionUpdateProvenance::runtime_encrypted_vectors()
    };
    Ok((sidecar_updates, provenance))
}

fn upsert_vectors_touch_encrypted_config(
    operation: &PointInsertOperationsInternal,
    params: &CollectionParams,
) -> Result<bool, StorageError> {
    match operation {
        PointInsertOperationsInternal::PointsList(points) => {
            points.iter().try_fold(false, |touches, point| {
                Ok(touches || vector_struct_touches_encrypted_config(&point.vector, params)?)
            })
        }
        PointInsertOperationsInternal::PointsBatch(batch) => {
            batch_vectors_touch_encrypted_config(&batch.vectors, params)
        }
    }
}

fn point_vectors_touch_encrypted_config(
    points: &[collection::operations::vector_ops::PointVectorsPersisted],
    params: &CollectionParams,
) -> Result<bool, StorageError> {
    points.iter().try_fold(false, |touches, point| {
        Ok(touches || vector_struct_touches_encrypted_config(&point.vector, params)?)
    })
}

fn vector_struct_touches_encrypted_config(
    vector: &VectorStructPersisted,
    params: &CollectionParams,
) -> Result<bool, StorageError> {
    let Some(encryption) = params.effective_encryption() else {
        return Ok(false);
    };
    for rule in &encryption.rules {
        let collection::config::EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        for encrypted_name in names {
            let touches = match vector {
                VectorStructPersisted::Single(_) | VectorStructPersisted::MultiDense(_) => {
                    encrypted_name == DEFAULT_VECTOR_NAME
                }
                VectorStructPersisted::Named(vectors) => vectors.contains_key(encrypted_name),
            };
            if touches {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn batch_vectors_touch_encrypted_config(
    vectors: &BatchVectorStructPersisted,
    params: &CollectionParams,
) -> Result<bool, StorageError> {
    let Some(encryption) = params.effective_encryption() else {
        return Ok(false);
    };
    for rule in &encryption.rules {
        let collection::config::EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        for encrypted_name in names {
            let touches = match vectors {
                BatchVectorStructPersisted::Single(_)
                | BatchVectorStructPersisted::MultiDense(_) => {
                    encrypted_name == DEFAULT_VECTOR_NAME
                }
                BatchVectorStructPersisted::Named(vectors) => vectors.contains_key(encrypted_name),
            };
            if touches {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn encrypt_vectors_for_point(
    plan: &crate::common::crypto::VectorWritePlan,
    collection_name: &str,
    point_id: &str,
    vector: &mut VectorStructPersisted,
    payload: &mut Option<Payload>,
) -> Result<usize, StorageError> {
    match vector {
        VectorStructPersisted::Single(values) => {
            if !plan.contains_vector_name(DEFAULT_VECTOR_NAME) {
                return Ok(0);
            }
            let values = std::mem::take(values);
            let envelope = plan
                .encrypt_dense_vector_payload_value(
                    collection_name,
                    point_id,
                    DEFAULT_VECTOR_NAME,
                    &values,
                )?
                .expect("default vector was selected");
            insert_encrypted_vector_sidecar(payload, DEFAULT_VECTOR_NAME, envelope)?;
            *vector = VectorStructPersisted::Named(HashMap::new());
            Ok(1)
        }
        VectorStructPersisted::MultiDense(_) => {
            if plan.contains_vector_name(DEFAULT_VECTOR_NAME) {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{DEFAULT_VECTOR_NAME}' only supports dense vectors; multi-dense vector encryption is not implemented",
                )));
            }
            Ok(0)
        }
        VectorStructPersisted::Named(vectors) => {
            let encrypted_names: Vec<_> = vectors
                .keys()
                .filter(|name| plan.contains_vector_name(name))
                .cloned()
                .collect();
            let mut encrypted = 0;
            for vector_name in encrypted_names {
                let vector = vectors.remove(&vector_name).expect("key came from map");
                let VectorPersisted::Dense(values) = vector else {
                    return Err(StorageError::bad_input(format!(
                        "encrypted vector '{vector_name}' only supports dense vectors; sparse and multi-dense vector encryption is not implemented",
                    )));
                };
                let envelope = plan
                    .encrypt_dense_vector_payload_value(
                        collection_name,
                        point_id,
                        &vector_name,
                        &values,
                    )?
                    .expect("vector was selected");
                insert_encrypted_vector_sidecar(payload, &vector_name, envelope)?;
                encrypted += 1;
            }
            Ok(encrypted)
        }
    }
}

fn encrypt_vectors_for_batch(
    plan: &crate::common::crypto::VectorWritePlan,
    collection_name: &str,
    ids: &[segment::types::PointIdType],
    vectors: &mut BatchVectorStructPersisted,
    payloads: &mut Option<Vec<Option<Payload>>>,
) -> Result<usize, StorageError> {
    match vectors {
        BatchVectorStructPersisted::Single(batch_values) => {
            if !plan.contains_vector_name(DEFAULT_VECTOR_NAME) {
                return Ok(0);
            }
            if batch_values.len() != ids.len() {
                return Err(StorageError::bad_input(
                    "batch vector count must match point id count",
                ));
            }
            let batch_values = std::mem::take(batch_values);
            ensure_batch_payloads(payloads, ids.len())?;
            let payloads = payloads.as_mut().expect("payloads were created");
            for ((point_id, values), payload) in ids.iter().zip(batch_values).zip(payloads) {
                let envelope = plan
                    .encrypt_dense_vector_payload_value(
                        collection_name,
                        &point_id.to_string(),
                        DEFAULT_VECTOR_NAME,
                        &values,
                    )?
                    .expect("default vector was selected");
                insert_encrypted_vector_sidecar(payload, DEFAULT_VECTOR_NAME, envelope)?;
            }
            *vectors = BatchVectorStructPersisted::Named(HashMap::new());
            Ok(ids.len())
        }
        BatchVectorStructPersisted::MultiDense(_) => {
            if plan.contains_vector_name(DEFAULT_VECTOR_NAME) {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{DEFAULT_VECTOR_NAME}' only supports dense vectors; multi-dense vector encryption is not implemented",
                )));
            }
            Ok(0)
        }
        BatchVectorStructPersisted::Named(named) => {
            let encrypted_names: Vec<_> = named
                .keys()
                .filter(|name| plan.contains_vector_name(name))
                .cloned()
                .collect();
            if encrypted_names.is_empty() {
                return Ok(0);
            }
            ensure_batch_payloads(payloads, ids.len())?;
            let payloads = payloads.as_mut().expect("payloads were created");
            let mut encrypted = 0;
            for vector_name in encrypted_names {
                let values = named.remove(&vector_name).expect("key came from map");
                if values.len() != ids.len() {
                    return Err(StorageError::bad_input(format!(
                        "batch vector count for '{vector_name}' must match point id count",
                    )));
                }
                for ((point_id, value), payload) in ids.iter().zip(values).zip(&mut *payloads) {
                    let VectorPersisted::Dense(values) = value else {
                        return Err(StorageError::bad_input(format!(
                            "encrypted vector '{vector_name}' only supports dense vectors; sparse and multi-dense vector encryption is not implemented",
                        )));
                    };
                    let envelope = plan
                        .encrypt_dense_vector_payload_value(
                            collection_name,
                            &point_id.to_string(),
                            &vector_name,
                            &values,
                        )?
                        .expect("vector was selected");
                    insert_encrypted_vector_sidecar(payload, &vector_name, envelope)?;
                    encrypted += 1;
                }
            }
            Ok(encrypted)
        }
    }
}

fn ensure_batch_payloads(
    payloads: &mut Option<Vec<Option<Payload>>>,
    len: usize,
) -> Result<(), StorageError> {
    match payloads {
        Some(payloads) if payloads.len() != len => Err(StorageError::bad_input(
            "batch payload count must match point id count",
        )),
        Some(_) => Ok(()),
        None => {
            *payloads = Some(vec![None; len]);
            Ok(())
        }
    }
}

fn insert_encrypted_vector_sidecar(
    payload: &mut Option<Payload>,
    vector_name: &str,
    envelope: Value,
) -> Result<(), StorageError> {
    let payload = payload.get_or_insert_with(Payload::default);
    let sidecar = payload
        .0
        .entry(ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(sidecar) = sidecar.as_object_mut() else {
        return Err(StorageError::bad_input(format!(
            "reserved encrypted vector sidecar field '{ENCRYPTED_VECTOR_SIDECAR_FIELD}' is already set to a non-object value",
        )));
    };
    sidecar.insert(vector_name.to_string(), envelope);
    Ok(())
}

async fn split_encrypted_vector_delete_names(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    auth: &Auth,
    vector_names: Vec<String>,
) -> Result<(Vec<String>, Vec<JsonPath>), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "delete_vectors")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Ok((vector_names, Vec::new()));
    };

    let encrypted_names: std::collections::HashSet<_> = encryption
        .rules
        .iter()
        .filter_map(|rule| match &rule.selector {
            collection::config::EncryptionSelector::VectorNames { names } => Some(names),
            _ => None,
        })
        .flat_map(|names| names.iter().cloned())
        .collect();

    let mut plaintext_vector_names = Vec::new();
    let mut encrypted_sidecar_keys = Vec::new();
    for vector_name in vector_names {
        if encrypted_names.contains(&vector_name) {
            encrypted_sidecar_keys.push(JsonPath {
                first_key: ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
                rest: vec![JsonPathItem::Key(vector_name)],
            });
        } else {
            plaintext_vector_names.push(vector_name);
        }
    }

    Ok((plaintext_vector_names, encrypted_sidecar_keys))
}

enum PayloadUpdatePlan {
    Single(SetPayload),
    Fanout(Vec<SetPayload>),
}

impl PayloadUpdatePlan {
    fn into_operations(self) -> Vec<SetPayload> {
        match self {
            Self::Single(operation) => vec![operation],
            Self::Fanout(operations) => operations,
        }
    }
}

async fn maybe_encrypt_point_payload_update(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    mut operation: SetPayload,
    auth: &Auth,
    runtime_settings: Option<&Settings>,
    operation_name: &str,
    client_nonce_replay_cache: Option<&mut std::collections::HashSet<ClientPayloadNonceReplayKey>>,
) -> Result<(PayloadUpdatePlan, CollectionUpdateProvenance), StorageError> {
    let Some(runtime_settings) = runtime_settings else {
        ensure_payload_runtime_available_for_payload_update(
            toc,
            collection_name,
            &operation,
            auth,
            operation_name,
        )
        .await?;
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    };

    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), operation_name)?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let collection_crypto_id = collection_config
        .stable_crypto_id(collection_name)
        .map_err(|err| StorageError::bad_input(err.to_string()))?;
    let Some(plan) = payload_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &collection_config.params,
    )
    .map_err(|err| {
        StorageError::service_error(format!(
            "payload encryption runtime for collection {collection_name} is invalid: {err}"
        ))
    })?
    else {
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    };
    let mut local_seen_client_nonces = std::collections::HashSet::new();
    let seen_client_nonces = client_nonce_replay_cache.unwrap_or(&mut local_seen_client_nonces);
    let seen_client_nonces_before = seen_client_nonces.clone();

    let touches_encrypted_payload =
        plan.touches_selected_fields(&operation.payload, operation.key.as_ref());

    if operation.filter.is_some() {
        if touches_encrypted_payload {
            return Err(StorageError::bad_input(format!(
                "{operation_name} with a filter cannot update encrypted payload fields in collection {collection_name}; use point-specific upsert/set_payload so encryption can bind AAD to each point id",
            )));
        }
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    }

    if operation.key.is_some() {
        if touches_encrypted_payload {
            return Err(StorageError::bad_input(format!(
                "{operation_name} with a key path cannot update encrypted payload fields in collection {collection_name}; use a full point-specific payload update so the selected encrypted fields can be sealed with their canonical field paths",
            )));
        }
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    }

    let Some(points) = operation.points.as_ref() else {
        if touches_encrypted_payload {
            return Err(StorageError::bad_input(format!(
                "{operation_name} cannot update encrypted payload fields without point ids in collection {collection_name}; send point-specific updates so encryption can bind AAD to each point id",
            )));
        }
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    };

    if points.is_empty() {
        if touches_encrypted_payload {
            return Err(StorageError::bad_input(format!(
                "{operation_name} cannot update encrypted payload fields without point ids in collection {collection_name}; send point-specific updates so encryption can bind AAD to each point id",
            )));
        }
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    }

    if points.len() > 1 && touches_encrypted_payload {
        if plan.has_client_envelope_rules() {
            return Err(StorageError::bad_input(format!(
                "{operation_name} cannot reuse client-side encrypted payload envelopes across multiple point ids in collection {collection_name}; send one point-specific update per client envelope",
            )));
        }
        let mut encrypted_operations = Vec::with_capacity(points.len());
        for point_id in points {
            let mut payload = operation.payload.clone();
            plan.encrypt_payload_with_replay_cache(
                &point_id.to_string(),
                &mut payload,
                &mut *seen_client_nonces,
            )
            .map_err(|err| payload_write_error_to_storage_error(collection_name, err))?;
            encrypted_operations.push(SetPayload {
                points: Some(vec![point_id.clone()]),
                payload,
                filter: None,
                shard_key: operation.shard_key.clone(),
                key: None,
            });
        }
        record_process_client_nonce_replay_cache(
            toc,
            &collection_crypto_id,
            seen_client_nonces,
            &seen_client_nonces_before,
        )
        .await?;
        return Ok((
            PayloadUpdatePlan::Fanout(encrypted_operations),
            CollectionUpdateProvenance::runtime_encrypted_payloads(),
        ));
    }

    let Some(point_id) = points.first() else {
        return Ok((
            PayloadUpdatePlan::Single(operation),
            CollectionUpdateProvenance::client_plaintext(),
        ));
    };

    let outcome = plan
        .process_payload_with_replay_cache(
            &point_id.to_string(),
            &mut operation.payload,
            &mut *seen_client_nonces,
        )
        .map_err(|err| payload_write_error_to_storage_error(collection_name, err))?;
    let update_provenance = payload_update_provenance(
        plan.has_server_encrypt_rules(),
        outcome.verified_client_envelope_keys,
    );
    record_process_client_nonce_replay_cache(
        toc,
        &collection_crypto_id,
        seen_client_nonces,
        &seen_client_nonces_before,
    )
    .await?;

    Ok((PayloadUpdatePlan::Single(operation), update_provenance))
}

fn payload_update_provenance(
    has_server_encrypt_rules: bool,
    verified_client_envelope_keys: std::collections::HashSet<ClientPayloadVerifiedEnvelopeKey>,
) -> CollectionUpdateProvenance {
    match (
        has_server_encrypt_rules,
        verified_client_envelope_keys.is_empty(),
    ) {
        (true, false) => {
            CollectionUpdateProvenance::runtime_encrypted_payloads_and_verified_client_envelopes(
                verified_client_envelope_keys,
            )
        }
        (true, true) => CollectionUpdateProvenance::runtime_encrypted_payloads(),
        (false, false) => CollectionUpdateProvenance::runtime_verified_client_envelopes(
            verified_client_envelope_keys,
        ),
        (false, true) => CollectionUpdateProvenance::client_plaintext(),
    }
}

async fn record_process_client_nonce_replay_cache(
    toc: &Arc<TableOfContent>,
    collection_crypto_id: &str,
    seen_client_nonces: &std::collections::HashSet<ClientPayloadNonceReplayKey>,
    seen_client_nonces_before: &std::collections::HashSet<ClientPayloadNonceReplayKey>,
) -> Result<(), StorageError> {
    toc.record_client_payload_nonce_replay_keys(
        collection_crypto_id,
        seen_client_nonces
            .difference(seen_client_nonces_before)
            .map(client_nonce_replay_cache_key),
    )
    .await
}

fn client_nonce_replay_cache_key(key: &ClientPayloadNonceReplayKey) -> String {
    key.cache_key()
}

async fn ensure_payload_runtime_available_for_upsert(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    operation: &PointInsertOperations,
    auth: &Auth,
) -> Result<(), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), "upsert_points")?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Ok(());
    };

    let mut touches_encrypted_payload = false;
    match operation {
        PointInsertOperations::PointsList(list) => {
            for point in &list.points {
                if let Some(payload) = &point.payload
                    && payload_touches_encrypted_config(&encryption, payload, None)?
                {
                    touches_encrypted_payload = true;
                    break;
                }
            }
        }
        PointInsertOperations::PointsBatch(batch) => {
            if let Some(payloads) = batch.batch.payloads.as_ref() {
                for payload in payloads.iter().flatten() {
                    if payload_touches_encrypted_config(&encryption, payload, None)? {
                        touches_encrypted_payload = true;
                        break;
                    }
                }
            }
        }
    }

    if touches_encrypted_payload {
        return Err(StorageError::bad_input(format!(
            "payload encryption runtime for collection {collection_name} is required before writing encrypted payload fields",
        )));
    }

    Ok(())
}

async fn ensure_payload_runtime_available_for_payload_update(
    toc: &Arc<TableOfContent>,
    collection_name: &str,
    operation: &SetPayload,
    auth: &Auth,
    operation_name: &str,
) -> Result<(), StorageError> {
    let collection_pass =
        auth.check_collection_access(collection_name, AccessRequirements::new(), operation_name)?;
    let collection = toc.get_collection(&collection_pass).await?;
    let collection_config = collection.config_snapshot().await;
    let Some(encryption) = collection_config.params.effective_encryption() else {
        return Ok(());
    };

    if payload_touches_encrypted_config(&encryption, &operation.payload, operation.key.as_ref())? {
        return Err(StorageError::bad_input(format!(
            "payload encryption runtime for collection {collection_name} is required before writing encrypted payload fields",
        )));
    }

    Ok(())
}

fn payload_touches_encrypted_config(
    encryption: &collection::config::CollectionEncryptionConfig,
    payload: &segment::types::Payload,
    key: Option<&JsonPath>,
) -> Result<bool, StorageError> {
    for rule in &encryption.rules {
        let collection::config::EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
            continue;
        };
        for encrypted_path in paths {
            let encrypted_json_path = encrypted_path.parse::<JsonPath>().map_err(|err| {
                StorageError::bad_input(format!(
                    "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                ))
            })?;
            if let Some(key) = key {
                if key.compatible(&encrypted_json_path) {
                    return Ok(true);
                }
            } else if !encrypted_json_path.value_get(&payload.0).is_empty() {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn payload_write_error_to_storage_error(
    collection_name: &str,
    err: PayloadWriteSetupError,
) -> StorageError {
    match err {
        PayloadWriteSetupError::Payload(PayloadEncryptionError::ClientNonceReplay) => {
            StorageError::bad_input(format!(
                "failed to encrypt payload for collection {collection_name}: client envelope nonce was already used; regenerate the client-side envelope with a fresh nonce before retrying",
            ))
        }
        PayloadWriteSetupError::Payload(payload_err) => StorageError::bad_input(format!(
            "failed to encrypt payload for collection {collection_name}: {payload_err}",
        )),
        err => StorageError::service_error(format!(
            "payload encryption runtime for collection {collection_name} is invalid: {err}",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::num::NonZeroUsize;
    use std::sync::Arc;

    use collection::config::{
        CollectionEncryptionConfig, CollectionParams, CryptoMigrationState, EncryptionRuleRef,
        EncryptionSelector,
    };
    use collection::operations::types::PointRequestInternal;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::optimizers_builder::OptimizersConfig;
    use collection::shards::channel_service::ChannelService;
    use common::budget::ResourceBudget;
    use common::load_concurrency::LoadConcurrencyConfig;
    use common::mmap;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        CLIENT_ENCRYPTED_PAYLOAD_MARKER, ENCRYPTED_CKKS_VECTOR_MARKER,
        ENCRYPTED_VECTOR_SIDECAR_FIELD, VECTOR_ENVELOPE_BINDING, client_payload_signature_message,
        is_client_encrypted_payload_value, is_encrypted_ckks_vector_payload_value,
        is_encrypted_payload_value,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use segment::data_types::vectors::DEFAULT_VECTOR_NAME;
    use segment::types::{Condition, Distance, FieldCondition, WithPayloadInterface, WithVector};
    use serde_json::json;
    use storage::content_manager::collection_meta_ops::{
        CollectionMetaOperations, CreateCollectionOperation,
    };
    use storage::types::{PerformanceConfig, StorageConfig};
    use tempfile::Builder;
    use tokio::runtime::Runtime;
    use uuid::Uuid;

    use super::*;
    use crate::common::crypto::{PayloadWriteSetupError, payload_write_plan_for_collection};
    use crate::settings::{
        CryptoBackendConfig, CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings, Settings,
    };

    fn payload_runtime_settings() -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto.instances = HashMap::from([(
            "docs_payload_v1".to_string(),
            CryptoInstanceConfig {
                provider: "payload/aes-256-gcm@v1".to_string(),
                materials: HashMap::from([(
                    "sym_key".to_string(),
                    "tenant-a/payload-v1".to_string(),
                )]),
                backend_ref: None,
                options: json!({
                    "key_id": "tenant-a:docs",
                    "material_fingerprint_id": "tenant-a/payload@v1",
                }),
            },
        )]);
        settings.crypto.materials = HashMap::from([(
            "tenant-a/payload-v1".to_string(),
            crate::settings::CryptoMaterialConfig {
                kind: "symmetric_key_32".to_string(),
                source: Some("inline".to_string()),
                env: None,
                path: None,
                value_b64: Some(BASE64URL_NOPAD.encode(&[5u8; 32])),
                ..crate::settings::CryptoMaterialConfig::default()
            },
        )]);
        settings
    }

    #[cfg(unix)]
    fn fake_openfhe_bridge() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;

        let dir = Builder::new()
            .prefix("openfhe-sidecar")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let script_path = dir.path().join("openfhe-bridge");
        fs::write(
            &script_path,
            r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r request
case "$request" in
  *'"operation":"score_plaintext_query"'*'"ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"'*)
    printf '{"version":1,"score":9.0}\n'
    ;;
  *'"operation":"score_plaintext_query"'*'"ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"'*)
    printf '{"version":1,"score":4.0}\n'
    ;;
  *'"operation":"score_plaintext_query"'*)
    printf '{"version":1,"score":1.0}\n'
    ;;
  *'"scheme":"openfhe-ckks"'*'"point_id":"1"'*)
    printf '{"version":1,"ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6MQ"}\n'
    ;;
  *'"scheme":"openfhe-ckks"'*'"point_id":"2"'*)
    printf '{"version":1,"ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ6Mg"}\n'
    ;;
  *'"scheme":"openfhe-ckks"'*)
    printf '{"version":1,"ciphertext":"ZmFrZS1ja2tzLWNpcGhlcnRleHQ"}\n'
    ;;
  *) exit 7 ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&script_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&script_path, permissions).unwrap();
        dir
    }

    fn vector_runtime_settings(bridge_path: &std::path::Path) -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_vector_v1".to_string(),
                CryptoInstanceConfig {
                    provider: "vector/openfhe-ckks@v1".to_string(),
                    materials: HashMap::from([(
                        "sym_key".to_string(),
                        "tenant-a/vector-v1".to_string(),
                    )]),
                    backend_ref: Some("openfhe_local".to_string()),
                    options: json!({
                        "key_id": "tenant-a:vector",
                        "material_fingerprint_id": "tenant-a/vector@v1",
                        "profile": qdrant_sec::CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                        "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                        "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                    }),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/vector-v1".to_string(),
                CryptoMaterialConfig {
                    kind: "symmetric_key_32".to_string(),
                    source: Some("inline".to_string()),
                    env: None,
                    path: None,
                    value_b64: Some(BASE64URL_NOPAD.encode(&[8u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::from([(
                "openfhe_local".to_string(),
                CryptoBackendConfig {
                    kind: "process".to_string(),
                    program: Some(bridge_path.display().to_string()),
                    sha256_b64: None,
                    size: None,
                    timeout_ms: Some(5_000),
                },
            )]),
        };
        settings
    }

    fn encrypted_vector_params() -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:vector".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "vector_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some(VECTOR_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_moves_dense_vector_into_encrypted_sidecar() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            "docs-crypto-id",
            &params,
        )
        .unwrap()
        .unwrap();
        let mut vector = VectorStructPersisted::Named(HashMap::from([(
            "embedding".to_string(),
            VectorPersisted::Dense(vec![0.125, -42.5]),
        )]));
        let mut payload = None;

        let encrypted =
            encrypt_vectors_for_point(&plan, "docs", "point-1", &mut vector, &mut payload).unwrap();

        assert_eq!(encrypted, 1);
        assert!(matches!(vector, VectorStructPersisted::Named(ref vectors) if vectors.is_empty()));
        let payload = payload.unwrap();
        let sidecar = payload
            .0
            .get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            .and_then(Value::as_object)
            .unwrap();
        let encrypted_embedding = sidecar.get("embedding").unwrap();
        assert!(is_encrypted_ckks_vector_payload_value(encrypted_embedding));
        assert!(
            encrypted_embedding
                .get(ENCRYPTED_CKKS_VECTOR_MARKER)
                .is_some()
        );
        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(!serialized.contains("0.125"));
        assert!(!serialized.contains("-42.5"));
    }

    #[cfg(unix)]
    #[test]
    fn vector_write_plan_rejects_sparse_encrypted_vector() {
        let bridge = fake_openfhe_bridge();
        let settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
        let params = encrypted_vector_params();
        let plan = vector_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            "docs-crypto-id",
            &params,
        )
        .unwrap()
        .unwrap();
        let mut vector = VectorStructPersisted::Named(HashMap::from([(
            "embedding".to_string(),
            VectorPersisted::empty_sparse(),
        )]));
        let mut payload = None;

        let err = encrypt_vectors_for_point(&plan, "docs", "point-1", &mut vector, &mut payload)
            .unwrap_err();

        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("only supports dense vectors")
        ));
    }

    #[test]
    fn client_nonce_replay_error_tells_clients_to_regenerate_envelope() {
        let err = payload_write_error_to_storage_error(
            "docs",
            PayloadWriteSetupError::Payload(PayloadEncryptionError::ClientNonceReplay),
        );

        let message = err.to_string();
        assert!(message.contains("client envelope nonce was already used"));
        assert!(message.contains("regenerate the client-side envelope"));
        assert!(message.contains("fresh nonce before retrying"));
    }

    fn encrypted_params() -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    #[test]
    fn encrypts_points_list_payloads_before_upsert() {
        let settings = payload_runtime_settings();
        let plan = payload_write_plan_for_collection(&settings, "docs", &encrypted_params())
            .unwrap()
            .unwrap();
        let mut operation = PointInsertOperations::PointsList(api::rest::schema::PointsList {
            points: vec![api::rest::PointStruct {
                id: 1.into(),
                vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                payload: Some(segment::types::Payload(
                    json!({ "body": "secret body" })
                        .as_object()
                        .unwrap()
                        .clone(),
                )),
            }],
            shard_key: None,
            update_filter: None,
            update_mode: None,
        });

        match &mut operation {
            PointInsertOperations::PointsList(list) => {
                for point in &mut list.points {
                    if let Some(payload) = &mut point.payload {
                        plan.encrypt_payload(&point.id.to_string(), payload)
                            .unwrap();
                    }
                }
            }
            PointInsertOperations::PointsBatch(_) => unreachable!(),
        }

        match operation {
            PointInsertOperations::PointsList(list) => {
                let body = list.points.into_iter().next().unwrap().payload.unwrap();
                assert!(is_encrypted_payload_value(body.0.get("body").unwrap()));
            }
            PointInsertOperations::PointsBatch(_) => unreachable!(),
        }
    }

    #[test]
    fn encrypts_batch_payloads_before_upsert() {
        let settings = payload_runtime_settings();
        let plan = payload_write_plan_for_collection(&settings, "docs", &encrypted_params())
            .unwrap()
            .unwrap();
        let mut operation = PointInsertOperations::PointsBatch(api::rest::schema::PointsBatch {
            batch: api::rest::schema::Batch {
                ids: vec![1.into()],
                vectors: api::rest::schema::BatchVectorStruct::Single(vec![vec![0.1, 0.2]]),
                payloads: Some(vec![Some(segment::types::Payload(
                    json!({ "body": "batch secret" })
                        .as_object()
                        .unwrap()
                        .clone(),
                ))]),
            },
            shard_key: None,
            update_filter: None,
            update_mode: None,
        });

        match &mut operation {
            PointInsertOperations::PointsBatch(batch) => {
                for (point_id, payload) in batch
                    .batch
                    .ids
                    .iter()
                    .zip(batch.batch.payloads.as_mut().unwrap().iter_mut())
                {
                    if let Some(payload) = payload {
                        plan.encrypt_payload(&point_id.to_string(), payload)
                            .unwrap();
                    }
                }
            }
            PointInsertOperations::PointsList(_) => unreachable!(),
        }

        match operation {
            PointInsertOperations::PointsBatch(batch) => {
                let payload = batch
                    .batch
                    .payloads
                    .unwrap()
                    .into_iter()
                    .next()
                    .unwrap()
                    .unwrap();
                assert!(is_encrypted_payload_value(payload.0.get("body").unwrap()));
            }
            PointInsertOperations::PointsList(_) => unreachable!(),
        }
    }

    #[test]
    fn payload_write_plan_rejects_client_supplied_envelope() {
        let settings = payload_runtime_settings();
        let plan = payload_write_plan_for_collection(&settings, "docs", &encrypted_params())
            .unwrap()
            .unwrap();
        let mut payload = segment::types::Payload(
            json!({ "body": "client supplied secret" })
                .as_object()
                .unwrap()
                .clone(),
        );

        plan.encrypt_payload("1", &mut payload).unwrap();

        assert!(matches!(
            plan.encrypt_payload("1", &mut payload),
            Err(PayloadWriteSetupError::Payload(
                qdrant_sec::PayloadEncryptionError::AlreadyEncrypted(field)
            )) if field == "body"
        ));
    }

    #[test]
    fn payload_write_plan_detects_key_path_overlap_with_encrypted_fields() {
        let settings = payload_runtime_settings();
        let plan = payload_write_plan_for_collection(&settings, "docs", &encrypted_params())
            .unwrap()
            .unwrap();
        let payload =
            segment::types::Payload(json!({ "title": "public" }).as_object().unwrap().clone());
        let encrypted_key = "body".parse::<JsonPath>().unwrap();
        let encrypted_child_key = "body.text".parse::<JsonPath>().unwrap();
        let public_key = "title".parse::<JsonPath>().unwrap();

        assert!(plan.touches_selected_fields(&payload, Some(&encrypted_key)));
        assert!(plan.touches_selected_fields(&payload, Some(&encrypted_child_key)));
        assert!(!plan.touches_selected_fields(&payload, Some(&public_key)));
    }

    #[test]
    fn do_upsert_points_encrypts_payload_before_storage() {
        let runtime = Runtime::new().unwrap();
        let storage_dir = Builder::new().prefix("storage").tempdir().unwrap();
        let storage_config = StorageConfig {
            storage_path: storage_dir.path().to_path_buf(),
            snapshots_path: storage_dir.path().join("snapshots"),
            snapshots_config: Default::default(),
            temp_path: None,
            on_disk_payload: false,
            optimizers: OptimizersConfig {
                deleted_threshold: 0.5,
                vacuum_min_vector_number: 100,
                default_segment_number: 2,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: Some(100),
                indexing_threshold: Some(100),
                flush_interval_sec: 2,
                max_optimization_threads: Some(2),
                prevent_unoptimized: None,
            },
            optimizers_overwrite: None,
            wal: Default::default(),
            performance: PerformanceConfig {
                max_search_threads: 1,
                max_optimization_runtime_threads: 1,
                optimizer_cpu_budget: 0,
                optimizer_io_budget: 0,
                update_rate_limit: None,
                search_timeout_sec: None,
                incoming_shard_transfers_limit: Some(1),
                outgoing_shard_transfers_limit: Some(1),
                async_scorer: None,
                load_concurrency: LoadConcurrencyConfig::default(),
            },
            hnsw_index: Default::default(),
            hnsw_global_config: Default::default(),
            mmap_advice: mmap::Advice::Random,
            node_type: Default::default(),
            update_queue_size: Default::default(),
            handle_collection_load_errors: false,
            recovery_mode: None,
            update_concurrency: Some(NonZeroUsize::new(2).unwrap()),
            shard_transfer_method: None,
            collection: None,
            max_collections: None,
        };
        let search_runtime = Runtime::new().unwrap();
        let update_runtime = Runtime::new().unwrap();
        let general_runtime = Runtime::new().unwrap();
        let toc = Arc::new(TableOfContent::new(
            &storage_config,
            search_runtime,
            update_runtime,
            general_runtime,
            ResourceBudget::default(),
            ChannelService::new(6333, false, None, None),
            0,
            None,
        ));
        let dispatcher = Dispatcher::new(toc.clone());
        let auth = Auth::new_internal(Access::full("For test"));

        runtime.block_on(async {
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "docs".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
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
                                encryption: encrypted_params().encryption,
                                ckks: None,
                                strict_mode_config: None,
                                uuid: None,
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "vector_docs".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
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
                                    key_id: Some("tenant-a:vector".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 0,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "vector_conf".to_string(),
                                        selector: EncryptionSelector::VectorNames {
                                            names: vec![DEFAULT_VECTOR_NAME.to_string()],
                                        },
                                        instance: "docs_vector_v1".to_string(),
                                        binding: Some("vector-envelope/v1".to_string()),
                                    }],
                                }),
                                ckks: None,
                                strict_mode_config: None,
                                uuid: None,
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();

            let bridge = fake_openfhe_bridge();
            let vector_settings = vector_runtime_settings(&bridge.path().join("openfhe-bridge"));
            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.7, -0.25]),
                        payload: None,
                    }, api::rest::PointStruct {
                        id: 2.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                        payload: None,
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();

            let vector_collection_pass = auth
                .check_collection_access("vector_docs", AccessRequirements::new(), "test")
                .unwrap();
            let vector_collection = toc.get_collection(&vector_collection_pass).await.unwrap();
            let retrieved = vector_collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![1.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let sidecar = retrieved[0]
                .payload
                .as_ref()
                .and_then(|payload| payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD))
                .and_then(Value::as_object)
                .unwrap();
            let encrypted_default_vector = sidecar.get(DEFAULT_VECTOR_NAME).unwrap();
            assert!(is_encrypted_ckks_vector_payload_value(encrypted_default_vector));
            let serialized_vector_payload = serde_json::to_string(&retrieved[0].payload).unwrap();
            assert!(!serialized_vector_payload.contains("0.7"));
            assert!(!serialized_vector_payload.contains("-0.25"));

            let search_result = crate::common::query::do_core_search_points(
                &toc,
                "vector_docs",
                SearchRequestInternal {
                    vector: vec![0.0, 0.0].into(),
                    with_payload: Some(WithPayloadInterface::Bool(false)),
                    with_vector: Some(WithVector::Bool(false)),
                    filter: None,
                    params: None,
                    limit: 1,
                    offset: None,
                    score_threshold: None,
                }
                .into(),
                None,
                ShardSelectorInternal::All,
                auth.clone(),
                None,
                HwMeasurementAcc::disposable(),
                Some(&vector_settings),
            )
            .await
            .unwrap();
            assert_eq!(search_result.len(), 1);
            assert_eq!(search_result[0].id, 1.into());
            assert_eq!(search_result[0].score, 9.0);

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 2.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                        payload: None,
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("encrypted vector")
                        && description.contains("runtime")
            ));

            let err = do_update_vectors(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                UpdateVectors {
                    points: vec![PointVectors {
                        id: 1.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                    }],
                    shard_key: None,
                    update_filter: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("encrypted vector")
                        && description.contains("runtime")
            ));

            do_delete_vectors(
                UncheckedTocProvider::new_unchecked(&toc),
                "vector_docs".to_string(),
                DeleteVectors {
                    points: Some(vec![1.into()]),
                    filter: None,
                    vector: std::iter::once(DEFAULT_VECTOR_NAME.to_string()).collect(),
                    shard_key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap();

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 99.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.9, 0.9]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": "missing runtime secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("payload encryption runtime")
                        && description.contains("required")
            ));

            let err = do_set_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    payload: segment::types::Payload(
                        json!({ "body": "missing runtime set secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    points: Some(vec![99.into()]),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("payload encryption runtime")
                        && description.contains("required")
            ));

            let err = do_overwrite_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    payload: segment::types::Payload(
                        json!({ "body": "missing runtime overwrite secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    points: Some(vec![99.into()]),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("payload encryption runtime")
                        && description.contains("required")
            ));

            let operation = PointInsertOperations::PointsList(api::rest::schema::PointsList {
                points: vec![api::rest::PointStruct {
                    id: 1.into(),
                    vector: api::rest::VectorStruct::Single(vec![0.1, 0.2]),
                    payload: Some(segment::types::Payload(
                        json!({ "body": "public ingress secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    )),
                }],
                shard_key: None,
                update_filter: None,
                update_mode: None,
            });

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                operation,
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            let collection_pass = auth
                .check_collection_access("docs", AccessRequirements::new(), "test")
                .unwrap();
            let collection = toc.get_collection(&collection_pass).await.unwrap();
            let retrieved = collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![1.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let payload = retrieved[0].payload.as_ref().unwrap();
            let body = payload.0.get("body").unwrap();
            assert!(is_encrypted_payload_value(body));
            assert_ne!(body, &json!("public ingress secret"));
            let upsert_body = body.clone();

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 2.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.3, 0.4]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": upsert_body.clone() })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("failed to encrypt payload")
                        && description.contains("already encrypted")
            ));

            do_set_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    points: Some(vec![1.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": "public set payload secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            let retrieved = collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![1.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let body = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap();
            assert!(is_encrypted_payload_value(body));
            assert_ne!(body, &json!("public set payload secret"));
            assert_ne!(body, &upsert_body);

            do_overwrite_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    points: Some(vec![1.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": "public overwrite payload secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            let retrieved = collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![1.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let body = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap();
            assert!(is_encrypted_payload_value(body));
            assert_ne!(body, &json!("public overwrite payload secret"));

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 2.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.5, 0.6]),
                        payload: Some(segment::types::Payload(
                            json!({ "title": "point 2 public" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            do_set_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    points: Some(vec![1.into(), 2.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": "multi point secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            let retrieved = collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![1.into(), 2.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let multi_point_body_1 = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap()
                .clone();
            let multi_point_body_2 = retrieved[1]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap()
                .clone();
            assert!(is_encrypted_payload_value(&multi_point_body_1));
            assert!(is_encrypted_payload_value(&multi_point_body_2));
            assert_ne!(multi_point_body_1, json!("multi point secret"));
            assert_ne!(multi_point_body_2, json!("multi point secret"));
            assert_ne!(multi_point_body_1, multi_point_body_2);

            do_overwrite_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                SetPayload {
                    points: Some(vec![1.into(), 2.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": "multi point overwrite secret" })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&payload_runtime_settings()),
            )
            .await
            .unwrap();

            let retrieved = collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![1.into(), 2.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let multi_point_overwrite_body_1 = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap()
                .clone();
            let multi_point_overwrite_body_2 = retrieved[1]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap()
                .clone();
            assert!(is_encrypted_payload_value(&multi_point_overwrite_body_1));
            assert!(is_encrypted_payload_value(&multi_point_overwrite_body_2));
            assert_ne!(
                multi_point_overwrite_body_1,
                json!("multi point overwrite secret")
            );
            assert_ne!(
                multi_point_overwrite_body_2,
                json!("multi point overwrite secret")
            );
            assert_ne!(multi_point_overwrite_body_1, multi_point_overwrite_body_2);

            let unsupported_updates = [
                (
                    SetPayload {
                        points: None,
                        payload: segment::types::Payload(
                            json!({ "body": "missing point id secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        filter: None,
                        shard_key: None,
                        key: None,
                    },
                    "without point ids",
                ),
                (
                    SetPayload {
                        points: Some(vec![1.into()]),
                        payload: segment::types::Payload(
                            json!({ "body": "filter secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        filter: Some(Filter::default()),
                        shard_key: None,
                        key: None,
                    },
                    "with a filter cannot update encrypted payload fields",
                ),
                (
                    SetPayload {
                        points: Some(vec![1.into()]),
                        payload: segment::types::Payload(
                            json!({ "value": "key path secret" })
                                .as_object()
                                .unwrap()
                                .clone(),
                        ),
                        filter: None,
                        shard_key: None,
                        key: Some("body".parse().unwrap()),
                    },
                    "with a key path cannot update encrypted payload fields",
                ),
            ];
            for (operation, expected_error) in unsupported_updates {
                let err = do_set_payload(
                    UncheckedTocProvider::new_unchecked(&toc),
                    "docs".to_string(),
                    operation,
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                    Some(&payload_runtime_settings()),
                )
                .await
                .unwrap_err();
                assert!(matches!(
                    err,
                    StorageError::BadInput { description }
                        if description.contains(expected_error)
                ));
            }

            let signing_rng = SystemRandom::new();
            let signing_pkcs8 = Ed25519KeyPair::generate_pkcs8(&signing_rng).unwrap();
            let signing_key = Ed25519KeyPair::from_pkcs8(signing_pkcs8.as_ref()).unwrap();
            let signed_client_body = |collection_id: &str, point_id: &str| {
                let client_ciphertext = BASE64URL_NOPAD.encode(&[42u8; 16]);
                let mut body = {
                    let mut marker = serde_json::Map::new();
                    marker.insert(
                        CLIENT_ENCRYPTED_PAYLOAD_MARKER.to_string(),
                        json!({
                            "version": 1,
                            "kind": "payload_text",
                            "algorithm": "AES-256-GCM",
                            "key_id": "tenant-a/client-rk-2026-04",
                            "rk_id": "tenant-a/client-rk-2026-04",
                            "rk_epoch": 3,
                            "kdf_domain": "qdrant-sec/client-payload-text/v1",
                            "aad": {
                                "collection_id": collection_id,
                                "point_id": point_id,
                                "field_path": "body",
                                "schema_version": 1
                            },
                            "nonce": "AAAAAAAAAAAAAAAA",
                            "ciphertext": client_ciphertext,
                            "signature": {
                                "alg": "ed25519",
                                "key_id": "tenant-a/client-signing-v1",
                                "sig": ""
                            }
                        }),
                    );
                    serde_json::Value::Object(marker)
                };
                let message = client_payload_signature_message(&body, "body").unwrap();
                let signature = signing_key.sign(&message);
                body.get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .get_mut("signature")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(
                        "sig".to_string(),
                        serde_json::Value::String(BASE64URL_NOPAD.encode(signature.as_ref())),
                    );
                body
            };
            let mut client_settings = Settings::new(None).unwrap();
            client_settings.crypto.instances = HashMap::from([(
                "docs_payload_client_v1".to_string(),
                CryptoInstanceConfig {
                    provider: "payload/client-aead@v1".to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: json!({
                        "key_id": "tenant-a/client-rk-2026-04",
                        "expected_rk_id": "tenant-a/client-rk-2026-04",
                        "min_rk_epoch": 3,
                        "max_rk_epoch": 3,
                        "signature_key_id": "tenant-a/client-signing-v1",
                        "signature_public_key_b64": BASE64URL_NOPAD
                            .encode(signing_key.public_key().as_ref()),
                    }),
                },
            )]);
            let client_docs_uuid = Uuid::from_u128(0x2234567890abcdef1234567890abcdef);
            let client_docs_uuid_string = client_docs_uuid.to_string();
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "client_docs".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
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
                                    key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 3,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "body_client_conf".to_string(),
                                        selector: EncryptionSelector::PayloadPaths {
                                            paths: vec!["body".to_string()],
                                        },
                                        instance: "docs_payload_client_v1".to_string(),
                                        binding: Some("client-payload-envelope/v1".to_string()),
                                    }],
                                }),
                                ckks: None,
                                strict_mode_config: None,
                                uuid: Some(client_docs_uuid),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();
            let client_uuid = Uuid::from_u128(0x1234567890abcdef1234567890abcdef);
            let client_uuid_string = client_uuid.to_string();
            dispatcher
                .submit_collection_meta_op(
                    CollectionMetaOperations::CreateCollection(
                        CreateCollectionOperation::new(
                            "client_uuid_docs".to_string(),
                            CreateCollection {
                                vectors: VectorParamsBuilder::new(2, Distance::Dot).build().into(),
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
                                    key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                                    crypto_schema_version: 1,
                                    encryption_epoch: 3,
                                    migration_state: CryptoMigrationState::Active,
                                    rules: vec![EncryptionRuleRef {
                                        id: "body_client_conf".to_string(),
                                        selector: EncryptionSelector::PayloadPaths {
                                            paths: vec!["body".to_string()],
                                        },
                                        instance: "docs_payload_client_v1".to_string(),
                                        binding: Some("client-payload-envelope/v1".to_string()),
                                    }],
                                }),
                                ckks: None,
                                strict_mode_config: None,
                                uuid: Some(client_uuid),
                                metadata: None,
                            },
                        )
                        .unwrap(),
                    ),
                    auth.clone(),
                    None,
                )
                .await
                .unwrap();
            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 10.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.7, 0.8]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body(&client_docs_uuid_string, "10") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap();
            let client_collection_pass = auth
                .check_collection_access("client_docs", AccessRequirements::new(), "test")
                .unwrap();
            let client_collection = toc.get_collection(&client_collection_pass).await.unwrap();
            let retrieved = client_collection
                .retrieve(
                    PointRequestInternal {
                        ids: vec![10.into()],
                        with_payload: Some(WithPayloadInterface::Bool(true)),
                        with_vector: false.into(),
                    },
                    None,
                    &ShardSelectorInternal::All,
                    None,
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap();
            let body = retrieved[0]
                .payload
                .as_ref()
                .unwrap()
                .0
                .get("body")
                .unwrap();
            assert!(is_client_encrypted_payload_value(body));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 13.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.4, 0.4]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body(&client_docs_uuid_string, "13") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("nonce was already used in this collection")
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_uuid_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 20.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.2, 0.1]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body("client_uuid_docs", "20") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("collection_id")
            ));

            do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_uuid_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 20.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.2, 0.1]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body(&client_uuid_string, "20") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap();
            let client_uuid_collection_pass = auth
                .check_collection_access("client_uuid_docs", AccessRequirements::new(), "test")
                .unwrap();
            let client_uuid_collection = toc
                .get_collection(&client_uuid_collection_pass)
                .await
                .unwrap();

            let err = do_set_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                SetPayload {
                    points: Some(vec![10.into(), 11.into()]),
                    payload: segment::types::Payload(
                        json!({ "body": signed_client_body(&client_docs_uuid_string, "10") })
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    filter: None,
                    shard_key: None,
                    key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot reuse client-side encrypted payload envelopes")
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![
                        api::rest::PointStruct {
                            id: 11.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.8, 0.9]),
                            payload: Some(segment::types::Payload(
                                json!({ "body": signed_client_body(&client_docs_uuid_string, "11") })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            )),
                        },
                        api::rest::PointStruct {
                            id: 12.into(),
                            vector: api::rest::VectorStruct::Single(vec![0.9, 1.0]),
                            payload: Some(segment::types::Payload(
                                json!({ "body": signed_client_body(&client_docs_uuid_string, "12") })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            )),
                        },
                    ],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("nonce was already used")
            ));

            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                vec![
                    UpdateOperation::Upsert(UpsertOperation {
                        upsert: PointInsertOperations::PointsList(api::rest::schema::PointsList {
                            points: vec![api::rest::PointStruct {
                                id: 11.into(),
                                vector: api::rest::VectorStruct::Single(vec![0.8, 0.9]),
                                payload: Some(segment::types::Payload(
                                    json!({ "body": signed_client_body(&client_docs_uuid_string, "11") })
                                        .as_object()
                                        .unwrap()
                                        .clone(),
                                )),
                            }],
                            shard_key: None,
                            update_filter: None,
                            update_mode: None,
                        }),
                    }),
                    UpdateOperation::Upsert(UpsertOperation {
                        upsert: PointInsertOperations::PointsList(api::rest::schema::PointsList {
                            points: vec![api::rest::PointStruct {
                                id: 12.into(),
                                vector: api::rest::VectorStruct::Single(vec![0.9, 1.0]),
                                payload: Some(segment::types::Payload(
                                    json!({ "body": signed_client_body(&client_docs_uuid_string, "12") })
                                        .as_object()
                                        .unwrap()
                                        .clone(),
                                )),
                            }],
                            shard_key: None,
                            update_filter: None,
                            update_mode: None,
                        }),
                    }),
                ],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("nonce was already used")
            ));

            let err = do_batch_update_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                vec![
                    UpdateOperation::SetPayload(SetPayloadOperation {
                        set_payload: SetPayload {
                            points: Some(vec![10.into()]),
                            payload: segment::types::Payload(
                                json!({ "body": signed_client_body(&client_docs_uuid_string, "10") })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            ),
                            filter: None,
                            shard_key: None,
                            key: None,
                        },
                    }),
                    UpdateOperation::SetPayload(SetPayloadOperation {
                        set_payload: SetPayload {
                            points: Some(vec![10.into()]),
                            payload: segment::types::Payload(
                                json!({ "body": signed_client_body(&client_docs_uuid_string, "10") })
                                    .as_object()
                                    .unwrap()
                                    .clone(),
                            ),
                            filter: None,
                            shard_key: None,
                            key: None,
                        },
                    }),
                ],
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                Some(&client_settings),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("nonce was already used")
            ));

            let err = do_upsert_points(
                UncheckedTocProvider::new_unchecked(&toc),
                "client_docs".to_string(),
                PointInsertOperations::PointsList(api::rest::schema::PointsList {
                    points: vec![api::rest::PointStruct {
                        id: 11.into(),
                        vector: api::rest::VectorStruct::Single(vec![0.8, 0.9]),
                        payload: Some(segment::types::Payload(
                            json!({ "body": signed_client_body(&client_docs_uuid_string, "11") })
                                .as_object()
                                .unwrap()
                                .clone(),
                        )),
                    }],
                    shard_key: None,
                    update_filter: None,
                    update_mode: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                InferenceParams::default(),
                HwMeasurementAcc::disposable(),
                None,
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("payload encryption runtime")
                        && description.contains("required")
            ));

            let encrypted_filter = || {
                Filter::new_must(Condition::Field(FieldCondition::new_match(
                    "body".parse().unwrap(),
                    serde_json::from_str(r#"{ "value": "secret body" }"#).unwrap(),
                )))
            };
            let err = do_delete_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                DeletePayload {
                    keys: vec!["tag".parse().unwrap()],
                    points: None,
                    filter: Some(encrypted_filter()),
                    shard_key: None,
                },
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot filter on encrypted payload field")
                        && description.contains("body")
            ));

            let err = do_clear_payload(
                UncheckedTocProvider::new_unchecked(&toc),
                "docs".to_string(),
                PointsSelector::FilterSelector(FilterSelector {
                    filter: encrypted_filter(),
                    shard_key: None,
                }),
                InternalUpdateParams::default(),
                UpdateParams {
                    wait: true,
                    ordering: WriteOrdering::default(),
                    timeout: None,
                },
                auth.clone(),
                HwMeasurementAcc::disposable(),
            )
            .await
            .unwrap_err();
            assert!(matches!(
                err,
                StorageError::BadInput { description }
                    if description.contains("cannot filter on encrypted payload field")
                        && description.contains("body")
            ));

            for indexed_field in ["body", "body.keyword"] {
                let err = do_create_index(
                    dispatcher.clone().into(),
                    "docs".to_string(),
                    CreateFieldIndex {
                        field_name: indexed_field.parse().unwrap(),
                        field_schema: Some(PayloadFieldSchema::FieldType(
                            segment::types::PayloadSchemaType::Keyword,
                        )),
                    },
                    InternalUpdateParams::default(),
                    UpdateParams {
                        wait: true,
                        ordering: WriteOrdering::default(),
                        timeout: None,
                    },
                    auth.clone(),
                    HwMeasurementAcc::disposable(),
                )
                .await
                .unwrap_err();
                assert!(matches!(
                    err,
                    StorageError::BadInput { description }
                        if (description.contains("encrypted payload field")
                            && description.contains("body")
                            && description.contains("blind index"))
                ));
            }

            let snapshot_temp_dir = Builder::new().prefix("snapshot-temp").tempdir().unwrap();
            let snapshot = collection
                .create_snapshot(snapshot_temp_dir.path(), 0)
                .await
                .unwrap();
            assert!(collection.snapshots_path().join(&snapshot.name).exists());

            let client_snapshot_temp_dir = Builder::new()
                .prefix("client-snapshot-temp")
                .tempdir()
                .unwrap();
            let client_snapshot = client_collection
                .create_snapshot(client_snapshot_temp_dir.path(), 0)
                .await
                .unwrap();
            assert!(
                client_collection
                    .snapshots_path()
                    .join(&client_snapshot.name)
                    .exists()
            );

            client_collection.stop_gracefully().await;
            client_uuid_collection.stop_gracefully().await;
            collection.stop_gracefully().await;
        });

        for sentinel in [
            "public ingress secret",
            "public set payload secret",
            "public overwrite payload secret",
            "multi point secret",
            "multi point overwrite secret",
        ] {
            let sentinel = sentinel.as_bytes();
            let mut pending = vec![storage_dir.path().to_path_buf()];
            while let Some(path) = pending.pop() {
                let metadata = fs::metadata(&path).unwrap();
                if metadata.is_dir() {
                    for entry in fs::read_dir(&path).unwrap() {
                        pending.push(entry.unwrap().path());
                    }
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }

                let bytes = fs::read(&path).unwrap();
                assert!(
                    !bytes
                        .windows(sentinel.len())
                        .any(|window| window == sentinel),
                    "plaintext sentinel leaked into {}",
                    path.display(),
                );
            }
        }
    }
}
