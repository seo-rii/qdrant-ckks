use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::types::DeferredBehavior;
use data_encoding::BASE64URL_NOPAD;
use futures::stream::FuturesUnordered;
use futures::{StreamExt as _, TryFutureExt, TryStreamExt as _, future};
use itertools::Itertools;
use qdrant_sec::{
    CKKS_SCHEME, CLIENT_CKKS_VECTOR_MARKER, CLIENT_PAYLOAD_ENVELOPE_BINDING,
    ClientPayloadNonceReplayKey, ClientPayloadValidationContext, ENCRYPTED_CKKS_VECTOR_MARKER,
    ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector, METADATA_EXACT_MATCH_TOKEN_BINDING,
    METADATA_VALUE_BINDING, METADATA_VALUE_ENVELOPE_KIND, PAYLOAD_FIELD_BINDING,
    PAYLOAD_TEXT_ENVELOPE_KIND, ServerPayloadValidationContext, ServerPayloadVerifiedEnvelopeKey,
    ckks_vector_sidecar_envelope_key, client_ckks_vector_sidecar_envelope_key,
    client_payload_envelope_key, client_payload_nonce_replay_key,
    is_client_encrypted_payload_value, is_encrypted_payload_value, server_payload_envelope_key,
    validate_client_payload_value_after_runtime_verification,
    validate_server_payload_value_after_runtime_encryption,
    validate_server_payload_value_for_peer_replay,
};
use segment::data_types::order_by::{Direction, OrderBy};
use segment::data_types::vectors::DEFAULT_VECTOR_NAME;
use segment::index::query_optimization::rescore_formula::parsed_formula::ParsedFormula;
use segment::json_path::{JsonPath, JsonPathItem};
use segment::types::{
    AnyVariants, Condition, EncryptedPayloadReadMode, ExtendedPointId, Filter, Match, Payload,
    PayloadSelector, ScoredPoint, ShardKey, ValueVariants, WithPayload, WithPayloadInterface,
    WithVector,
};
use shard::count::CountRequestInternal;
use shard::retrieve::record_internal::RecordInternal;
use shard::scroll::ScrollRequestInternal;

use super::Collection;
use crate::config::{
    CollectionEncryptionConfig, CryptoMigrationCheckpoint, CryptoMigrationCheckpointStatus,
    CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, encrypted_vector_return_request,
    encryption_rule_uses_private_hnsw_oram, encryption_rule_uses_private_result_oram,
    private_hnsw_oram_api_required_message, private_result_oram_api_required_message,
    private_result_oram_payload_selector_overlap_message,
};
use crate::operations::consistency_params::ReadConsistency;
use crate::operations::loggable::Loggable;
use crate::operations::payload_ops::{PayloadOps, SetPayloadOp};
use crate::operations::point_ops::{
    BatchVectorStructPersisted, PointInsertOperationsInternal, PointOperations,
    VectorStructPersisted, WriteOrdering,
};
use crate::operations::shard_selector_internal::ShardSelectorInternal;
use crate::operations::types::*;
use crate::operations::vector_ops::VectorOperations;
use crate::operations::{CollectionUpdateOperations, OperationWithClockTag};
use crate::shards::shard::ShardId;
use crate::shards::shard_trait::WaitUntil;

const METADATA_BLIND_INDEX_MATCH_ANY_MAX_TOKENS: usize = 64;
const METADATA_BLIND_INDEX_FILTER_MAX_TOKENS: usize = 256;
const CKKS_VECTOR_SIDECAR_NONCE_B64_LEN: usize = 16;
const CKKS_VECTOR_SIDECAR_CIPHERTEXT_MAX_BYTES: usize = 16 * 1024 * 1024;
const CKKS_VECTOR_SIDECAR_CIPHERTEXT_MAX_B64_LEN: usize =
    (CKKS_VECTOR_SIDECAR_CIPHERTEXT_MAX_BYTES + 2) / 3 * 4;

fn crypto_migration_regular_operation_error(
    migration_state: CryptoMigrationState,
    operation_kind: &str,
) -> CollectionError {
    CollectionError::bad_input(format!(
        "collection encryption migration is {migration_state:?}; regular {operation_kind} require migration_state=active and crypto migration jobs must use the dedicated migration path",
    ))
}

fn ensure_crypto_migration_state_allows_regular_operation(
    migration_state: CryptoMigrationState,
    operation_kind: &str,
) -> CollectionResult<()> {
    if migration_state != CryptoMigrationState::Active {
        return Err(crypto_migration_regular_operation_error(
            migration_state,
            operation_kind,
        ));
    }
    Ok(())
}

fn plaintext_vector_write_error_for_encryption_rule(
    encrypted_name: &str,
    rule: &EncryptionRuleRef,
    peer_update: bool,
) -> CollectionError {
    if encryption_rule_uses_private_hnsw_oram(rule) {
        let prefix = if peer_update {
            "peer update cannot write plaintext vector for private HNSW ORAM vector".to_string()
        } else {
            "cannot write plaintext vector for private HNSW ORAM vector".to_string()
        };
        return CollectionError::bad_input(format!(
            "{prefix}; {}",
            private_hnsw_oram_api_required_message(encrypted_name),
        ));
    }

    if peer_update {
        CollectionError::bad_input(
            "peer update cannot write plaintext vector for encrypted vector rule",
        )
    } else {
        CollectionError::bad_input(
            "cannot write plaintext vector for encrypted vector rule; configure runtime CKKS \
             vector encryption before writing this vector",
        )
    }
}

fn peer_client_encrypted_payload_replay_violation(
    value: &serde_json::Value,
    allow_client_envelope: bool,
) -> Option<CollectionError> {
    (allow_client_envelope && is_client_encrypted_payload_value(value)).then(|| {
        CollectionError::bad_input(
            "peer client encrypted payload marker requires a runtime verifier manifest and cluster-wide nonce ledger before peer replay is supported",
        )
    })
}

fn private_hnsw_oram_read_only_point_operation_violation<'a>(
    operation: &CollectionUpdateOperations,
    encryption: &'a CollectionEncryptionConfig,
) -> Option<&'a str> {
    match operation {
        CollectionUpdateOperations::PointOperation(PointOperations::DeletePoints { .. })
        | CollectionUpdateOperations::PointOperation(PointOperations::DeletePointsByFilter(_))
        | CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(_)) => {}
        _ => return None,
    }

    encryption
        .rules
        .iter()
        .filter(|rule| encryption_rule_uses_private_hnsw_oram(rule))
        .find_map(|rule| match &rule.selector {
            EncryptionSelector::VectorNames { names } => names.first().map(String::as_str),
            EncryptionSelector::PayloadPaths { .. } | EncryptionSelector::MetadataKeys { .. } => {
                None
            }
        })
}

fn reject_private_hnsw_oram_read_only_point_operation(
    operation: &CollectionUpdateOperations,
    encryption: &CollectionEncryptionConfig,
    peer_update: bool,
) -> CollectionResult<()> {
    let Some(vector_name) =
        private_hnsw_oram_read_only_point_operation_violation(operation, encryption)
    else {
        return Ok(());
    };

    let prefix = if peer_update {
        "peer update cannot modify read-only private HNSW ORAM vector"
    } else {
        "cannot modify read-only private HNSW ORAM vector"
    };
    Err(CollectionError::bad_input(format!(
        "{prefix}; {}",
        private_hnsw_oram_api_required_message(vector_name),
    )))
}

fn encrypted_vector_return_error(
    encryption: &CollectionEncryptionConfig,
    with_vector: &WithVector,
) -> Option<CollectionError> {
    let request = encrypted_vector_return_request(encryption, with_vector)?;
    let encrypted_name = request.vector_name();
    if encryption.rules.iter().any(|rule| {
        encryption_rule_uses_private_hnsw_oram(rule)
            && matches!(
                &rule.selector,
                EncryptionSelector::VectorNames { names }
                    if names.iter().any(|name| name == encrypted_name)
            )
    }) {
        return Some(CollectionError::bad_input(format!(
            "{} Point-level vector reads are not exposed for this provider.",
            private_hnsw_oram_api_required_message(encrypted_name),
        )));
    }

    Some(CollectionError::bad_input(
        "cannot return encrypted vector; CKKS vector ciphertext read path returns payload sidecar only",
    ))
}

fn encrypted_vector_search_error(
    encryption: &CollectionEncryptionConfig,
    vector_name: &str,
    operation: &str,
) -> Option<CollectionError> {
    for rule in &encryption.rules {
        let EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        if !names.iter().any(|name| name == vector_name) {
            continue;
        }

        let message = if encryption_rule_uses_private_hnsw_oram(rule) {
            private_hnsw_oram_api_required_message(vector_name)
        } else {
            format!(
                "cannot {operation} encrypted vector through direct collection {operation}; use the runtime CKKS sidecar {operation} entrypoint",
            )
        };
        return Some(CollectionError::bad_input(message));
    }

    None
}

fn encrypted_vector_filter_error(rule: &EncryptionRuleRef, filter_vector: &str) -> CollectionError {
    if encryption_rule_uses_private_hnsw_oram(rule) {
        return CollectionError::bad_input(format!(
            "cannot filter on private HNSW ORAM vector; {}",
            private_hnsw_oram_api_required_message(filter_vector),
        ));
    }

    CollectionError::bad_input(
        "cannot filter on encrypted vector; use CKKS sidecar vector search APIs instead",
    )
}

fn reject_private_result_oram_payload_point_operation(
    operation: &CollectionUpdateOperations,
    encryption: &CollectionEncryptionConfig,
    peer_update: bool,
) -> CollectionResult<()> {
    let Some(payload_path) =
        private_result_oram_payload_operation_violation(operation, encryption)?
    else {
        return Ok(());
    };

    let prefix = if peer_update {
        "peer update cannot modify private result ORAM payload field"
    } else {
        "cannot modify private result ORAM payload field"
    };
    Err(CollectionError::bad_input(format!(
        "{prefix}; {}",
        private_result_oram_api_required_message(payload_path),
    )))
}

fn private_result_oram_payload_operation_violation<'a>(
    operation: &CollectionUpdateOperations,
    encryption: &'a CollectionEncryptionConfig,
) -> CollectionResult<Option<&'a str>> {
    for rule in encryption
        .rules
        .iter()
        .filter(|rule| encryption_rule_uses_private_result_oram(rule))
    {
        let EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
            continue;
        };
        for payload_path in paths {
            let protected_path = payload_path.parse::<JsonPath>().map_err(|_| {
                CollectionError::bad_input("private result ORAM payload field path is invalid")
            })?;
            if private_result_oram_payload_operation_touches_path(operation, &protected_path) {
                return Ok(Some(payload_path.as_str()));
            }
        }
    }

    Ok(None)
}

fn private_result_oram_payload_operation_touches_path(
    operation: &CollectionUpdateOperations,
    protected_path: &JsonPath,
) -> bool {
    match operation {
        CollectionUpdateOperations::PointOperation(point_operation) => match point_operation {
            PointOperations::UpsertPoints(_)
            | PointOperations::UpsertPointsConditional(
                shard::operations::point_ops::ConditionalInsertOperationInternal {
                    points_op: _,
                    condition: _,
                    update_mode: _,
                },
            ) => true,
            PointOperations::SyncPoints(_) => true,
            PointOperations::DeletePoints { .. } => true,
            PointOperations::DeletePointsByFilter(_) => true,
        },
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(operation)) => {
            private_result_oram_payload_touches_path(
                &operation.payload,
                operation.key.as_ref(),
                protected_path,
            )
        }
        CollectionUpdateOperations::PayloadOperation(PayloadOps::OverwritePayload(operation)) => {
            operation.key.is_none()
                || private_result_oram_payload_touches_path(
                    &operation.payload,
                    operation.key.as_ref(),
                    protected_path,
                )
        }
        CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(operation)) => {
            operation
                .keys
                .iter()
                .any(|key| key.compatible(protected_path))
        }
        CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayload { .. }) => true,
        CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(_)) => true,
        CollectionUpdateOperations::VectorOperation(_)
        | CollectionUpdateOperations::FieldIndexOperation(_) => false,
        #[cfg(feature = "staging")]
        CollectionUpdateOperations::StagingOperation(_) => false,
    }
}

fn private_result_oram_raw_payload_read_violation<'a>(
    with_payload: &WithPayloadInterface,
    encryption: &'a CollectionEncryptionConfig,
) -> CollectionResult<Option<&'a str>> {
    if !with_payload.is_required()
        || with_payload.encrypted_payload_read_mode() == EncryptedPayloadReadMode::Redacted
    {
        return Ok(None);
    }

    for rule in encryption
        .rules
        .iter()
        .filter(|rule| encryption_rule_uses_private_result_oram(rule))
    {
        let EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
            continue;
        };
        for payload_path in paths {
            let protected_path = payload_path.parse::<JsonPath>().map_err(|_| {
                CollectionError::bad_input("private result ORAM payload field path is invalid")
            })?;
            if private_result_oram_with_payload_touches_path(with_payload, &protected_path) {
                return Ok(Some(payload_path.as_str()));
            }
        }
    }

    Ok(None)
}

fn private_result_oram_with_payload_touches_path(
    with_payload: &WithPayloadInterface,
    protected_path: &JsonPath,
) -> bool {
    match with_payload {
        WithPayloadInterface::Bool(enabled) => *enabled,
        WithPayloadInterface::Encrypted(_) => true,
        WithPayloadInterface::Fields(fields) => {
            fields.iter().any(|field| field.compatible(protected_path))
        }
        WithPayloadInterface::Selector(PayloadSelector::Include(selector)) => selector
            .include
            .iter()
            .any(|field| field.compatible(protected_path)),
        WithPayloadInterface::Selector(PayloadSelector::Exclude(selector)) => !selector
            .exclude
            .iter()
            .any(|field| field.check_exclude_pattern(protected_path)),
    }
}

fn private_result_oram_payload_touches_path(
    payload: &Payload,
    key: Option<&JsonPath>,
    protected_path: &JsonPath,
) -> bool {
    if let Some(key) = key {
        return key.compatible(protected_path);
    }

    if payload.0.keys().any(|key| {
        key.parse::<JsonPath>()
            .is_ok_and(|payload_path| payload_path.compatible(protected_path))
    }) {
        return true;
    }

    !protected_path.value_get(&payload.0).is_empty()
}

fn parse_payload_selector_guard_path(
    rule: &EncryptionRuleRef,
    encrypted_path: &str,
) -> CollectionResult<JsonPath> {
    encrypted_path.parse::<JsonPath>().map_err(|_| {
        if encryption_rule_uses_private_result_oram(rule) {
            CollectionError::bad_input("private result ORAM payload field path is invalid")
        } else {
            CollectionError::bad_input("encrypted payload field path is invalid")
        }
    })
}

impl Collection {
    pub(crate) async fn backfill_client_payload_nonce_replay_cache_from_storage(
        &self,
    ) -> CollectionResult<()> {
        let (collection_crypto_id, encrypted_paths) = {
            let collection_config = self.collection_config.read().await;
            let Some(encryption) = collection_config.params.effective_encryption() else {
                return Ok(());
            };

            let encrypted_paths = encryption
                .rules
                .iter()
                .filter(|rule| rule.binding.as_deref() == Some(CLIENT_PAYLOAD_ENVELOPE_BINDING))
                .filter_map(|rule| match &rule.selector {
                    EncryptionSelector::PayloadPaths { paths } => Some(paths),
                    _ => None,
                })
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            if encrypted_paths.is_empty() {
                return Ok(());
            }

            (
                collection_config.stable_crypto_id(self.name())?,
                encrypted_paths,
            )
        };

        let encrypted_paths = encrypted_paths
            .into_iter()
            .map(|path| {
                path.parse::<JsonPath>()
                    .map(|json_path| (path, json_path))
                    .map_err(|_| {
                        CollectionError::bad_input("encrypted payload field path is invalid")
                    })
            })
            .collect::<CollectionResult<Vec<_>>>()?;

        const BATCH_SIZE: usize = 1024;
        let mut scanned_keys = HashSet::new();
        let mut cache_keys = Vec::new();
        let with_payload = WithPayloadInterface::Bool(true);
        let with_vector = WithVector::Bool(false);
        let shard_holder = self.shards_holder.read().await;

        for shard in shard_holder.all_shards() {
            let mut next_offset = Some(ExtendedPointId::NumId(0));
            while let Some(current_offset) = next_offset {
                let mut records = shard
                    .local_scroll_by_id(
                        Some(current_offset),
                        BATCH_SIZE + 1,
                        &with_payload,
                        &with_vector,
                        None,
                        None,
                        None,
                        HwMeasurementAcc::disposable(),
                        DeferredBehavior::IncludeAll,
                    )
                    .await?;
                if records.is_empty() {
                    break;
                }

                next_offset = if records.len() > BATCH_SIZE {
                    records.pop().map(|record| record.id)
                } else {
                    None
                };

                for record in &records {
                    let Some(payload) = record.payload.as_ref() else {
                        continue;
                    };
                    let point_id = record.id.to_string();
                    for (encrypted_path, encrypted_json_path) in &encrypted_paths {
                        for value in encrypted_json_path.value_get(&payload.0) {
                            let envelope_key =
                                match client_payload_envelope_key(value, encrypted_path).map_err(
                                    |_err| {
                                        CollectionError::service_error(
                                            "stored client encrypted payload marker is invalid for nonce replay cache backfill",
                                        )
                                    },
                                )? {
                                    Some(envelope_key) => envelope_key,
                                    None if is_client_encrypted_payload_value(value) => {
                                        return Err(CollectionError::service_error(
                                            "stored client encrypted payload marker is incomplete for nonce replay cache backfill",
                                        ));
                                    }
                                    None => continue,
                                };
                            if !envelope_key.matches_binding(
                                &collection_crypto_id,
                                &point_id,
                                encrypted_path,
                            ) {
                                return Err(CollectionError::service_error(
                                    "stored client encrypted payload marker has AAD that does not match collection, point, and field binding; refuse to load replay cache backfill",
                                ));
                            }
                            let Some(key) =
                                client_payload_nonce_replay_key(value, encrypted_path).map_err(
                                    |_err| {
                                        CollectionError::service_error(
                                            "stored client encrypted payload marker is invalid for nonce replay cache backfill",
                                        )
                                    },
                                )?
                            else {
                                continue;
                            };
                            let cache_key =
                                client_nonce_replay_cache_key(&collection_crypto_id, &key);
                            if !scanned_keys.insert(cache_key.clone()) {
                                return Err(CollectionError::service_error(
                                    "stored client encrypted payload nonce was reused; refuse to load replay cache backfill",
                                ));
                            }
                            cache_keys.push(cache_key);
                        }
                    }
                }

                if next_offset.is_none() {
                    break;
                }
            }
        }

        let backfilled = self
            .backfill_client_payload_nonce_replay_keys(cache_keys)
            .await?;
        if backfilled > 0 {
            log::info!("Backfilled client encrypted payload nonce replay cache entries",);
        }

        Ok(())
    }

    pub async fn rewrite_payloads_for_crypto_migration<F, R>(
        &self,
        rewrite_payload: F,
    ) -> CollectionResult<Vec<CryptoMigrationCheckpoint>>
    where
        F: FnMut(&ExtendedPointId, &mut Payload) -> CollectionResult<R>,
        R: Into<CryptoPayloadMigrationRewrite>,
    {
        self.rewrite_payloads_for_crypto_migration_inner(false, rewrite_payload)
            .await
    }

    pub async fn dry_run_payloads_for_crypto_migration<F, R>(
        &self,
        rewrite_payload: F,
    ) -> CollectionResult<Vec<CryptoMigrationCheckpoint>>
    where
        F: FnMut(&ExtendedPointId, &mut Payload) -> CollectionResult<R>,
        R: Into<CryptoPayloadMigrationRewrite>,
    {
        self.rewrite_payloads_for_crypto_migration_inner(true, rewrite_payload)
            .await
    }

    async fn rewrite_payloads_for_crypto_migration_inner<F, R>(
        &self,
        dry_run: bool,
        mut rewrite_payload: F,
    ) -> CollectionResult<Vec<CryptoMigrationCheckpoint>>
    where
        F: FnMut(&ExtendedPointId, &mut Payload) -> CollectionResult<R>,
        R: Into<CryptoPayloadMigrationRewrite>,
    {
        let _migration_guard = self.crypto_payload_migration_lock.try_lock().map_err(|_| {
            CollectionError::bad_input(
                "crypto payload migration is already running for this collection; retry after the current migration run finishes",
            )
        })?;
        let (
            migration_state,
            key_id,
            crypto_schema_version,
            encryption_epoch,
            collection_crypto_id,
            server_rewrite_paths,
            blind_index_paths,
        ) = {
            let collection_config = self.collection_config.read().await;
            let encryption = collection_config
                .params
                .effective_encryption()
                .ok_or_else(|| {
                    CollectionError::bad_input(
                        "crypto payload migration requires an encrypted collection",
                    )
                })?;
            let mut server_rewrite_paths = Vec::new();
            let mut blind_index_paths = Vec::new();
            for rule in &encryption.rules {
                match (&rule.selector, rule.binding.as_deref()) {
                    (
                        EncryptionSelector::PayloadPaths { paths },
                        None | Some(PAYLOAD_FIELD_BINDING),
                    ) => {
                        for path in paths {
                            let path_string = path.clone();
                            let json_path = path.parse::<JsonPath>().map_err(|_| {
                                CollectionError::bad_input(
                                    "payload encrypted field path is invalid",
                                )
                            })?;
                            server_rewrite_paths.push((
                                path_string,
                                json_path,
                                PAYLOAD_TEXT_ENVELOPE_KIND,
                            ));
                        }
                    }
                    (EncryptionSelector::MetadataKeys { keys }, Some(METADATA_VALUE_BINDING)) => {
                        for path in keys {
                            let path_string = path.clone();
                            let json_path = path.parse::<JsonPath>().map_err(|_| {
                                CollectionError::bad_input(
                                    "metadata encrypted field path is invalid",
                                )
                            })?;
                            server_rewrite_paths.push((
                                path_string,
                                json_path,
                                METADATA_VALUE_ENVELOPE_KIND,
                            ));
                        }
                    }
                    (
                        EncryptionSelector::MetadataKeys { keys },
                        Some(METADATA_EXACT_MATCH_TOKEN_BINDING),
                    ) => {
                        for path in keys {
                            let path_string = path.clone();
                            let json_path = path.parse::<JsonPath>().map_err(|_| {
                                CollectionError::bad_input(
                                    "metadata blind-index field path is invalid",
                                )
                            })?;
                            blind_index_paths.push((path_string, json_path));
                        }
                    }
                    _ => {}
                }
            }
            (
                encryption.migration_state,
                encryption.key_id.clone(),
                encryption.crypto_schema_version,
                encryption.encryption_epoch,
                collection_config.stable_crypto_id(self.name())?,
                server_rewrite_paths,
                blind_index_paths,
            )
        };
        if !matches!(
            migration_state,
            CryptoMigrationState::Encrypting
                | CryptoMigrationState::Rotating
                | CryptoMigrationState::Decrypting
        ) {
            return Err(CollectionError::bad_input(format!(
                "crypto payload migration requires migration_state=encrypting, rotating, or decrypting; current state is {migration_state:?}",
            )));
        }

        const BATCH_SIZE: usize = 1024;
        let with_payload = WithPayloadInterface::Bool(true);
        let with_vector = WithVector::Bool(false);
        let shard_holder = self.shards_holder.read().await;
        let mut checkpoints = Vec::new();

        for (shard_id, shard) in shard_holder.get_shards() {
            let mut total_points = 0_u64;
            let mut processed_points = 0_u64;
            let mut rewritten_points = 0_u64;
            let mut changed_points = 0_u64;
            let mut next_offset = Some(ExtendedPointId::NumId(0));

            while let Some(current_offset) = next_offset {
                let mut records = shard
                    .local_scroll_by_id(
                        Some(current_offset),
                        BATCH_SIZE + 1,
                        &with_payload,
                        &with_vector,
                        None,
                        None,
                        None,
                        HwMeasurementAcc::disposable(),
                        DeferredBehavior::IncludeAll,
                    )
                    .await?;
                if records.is_empty() {
                    break;
                }

                next_offset = if records.len() > BATCH_SIZE {
                    records.pop().map(|record| record.id)
                } else {
                    None
                };

                for record in records {
                    total_points += 1;
                    processed_points += 1;

                    let Some(mut payload) = record.payload else {
                        rewritten_points += 1;
                        continue;
                    };
                    let original_payload = payload.clone();
                    let rewrite = rewrite_payload(&record.id, &mut payload)?.into();
                    let changed = rewrite.changed;
                    let payload_changed = changed > 0 || payload != original_payload;
                    // Migration completion checkpoints represent verified
                    // coverage, not only points that needed byte changes. A
                    // rerun over already-current data must still be usable as
                    // the completion proof.
                    rewritten_points += 1;
                    let mut original_client_envelopes = std::collections::BTreeMap::new();
                    let mut updated_client_envelopes = std::collections::BTreeMap::new();
                    for (payload, envelopes) in [
                        (&original_payload, &mut original_client_envelopes),
                        (&payload, &mut updated_client_envelopes),
                    ] {
                        let mut stack = payload
                            .0
                            .iter()
                            .map(|(key, value)| (key.clone(), value))
                            .collect::<Vec<_>>();
                        while let Some((path, value)) = stack.pop() {
                            if is_client_encrypted_payload_value(value) {
                                envelopes.insert(path, value.clone());
                                continue;
                            }
                            match value {
                                serde_json::Value::Object(object) => {
                                    for (key, child) in object {
                                        stack.push((format!("{path}.{key}"), child));
                                    }
                                }
                                serde_json::Value::Array(items) => {
                                    for (index, child) in items.iter().enumerate() {
                                        stack.push((format!("{path}[{index}]"), child));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    if original_client_envelopes != updated_client_envelopes {
                        return Err(CollectionError::bad_input(
                            "crypto payload migration must not add, remove, or mutate client-side encrypted payload envelopes",
                        ));
                    }
                    if original_payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
                        != payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
                    {
                        return Err(CollectionError::bad_input(
                            "crypto payload migration must not add, remove, or mutate encrypted vector sidecar payloads",
                        ));
                    }
                    for (_blind_index_path, json_path) in &blind_index_paths {
                        let original_values = json_path
                            .value_get(&original_payload.0)
                            .into_iter()
                            .cloned()
                            .collect::<Vec<_>>();
                        let updated_values = json_path
                            .value_get(&payload.0)
                            .into_iter()
                            .cloned()
                            .collect::<Vec<_>>();
                        if original_values != updated_values {
                            return Err(CollectionError::bad_input(
                                "crypto payload migration must not add, remove, or mutate metadata blind-index token field",
                            ));
                        }
                    }
                    let mut original_non_migrated_payload = original_payload.0.clone();
                    let mut updated_non_migrated_payload = payload.0.clone();
                    for (server_rewrite_path, json_path, envelope_kind) in &server_rewrite_paths {
                        let original_values = json_path.value_get(&original_payload.0);
                        let updated_values = json_path.value_get(&payload.0);
                        if original_values.len() != updated_values.len() {
                            return Err(CollectionError::bad_input(
                                "crypto payload migration must not add or remove server-side encrypted field",
                            ));
                        }
                        match migration_state {
                            CryptoMigrationState::Encrypting | CryptoMigrationState::Rotating => {
                                for value in &updated_values {
                                    let Some(envelope_key) = server_payload_envelope_key(
                                        value,
                                        &collection_crypto_id,
                                        &record.id.to_string(),
                                        server_rewrite_path,
                                    )
                                    .map_err(|_| {
                                        CollectionError::bad_input(format!(
                                            "crypto payload migration must leave server-side encrypted field as an encrypted marker during {migration_state:?}",
                                        ))
                                    })?
                                    else {
                                        return Err(CollectionError::bad_input(format!(
                                            "crypto payload migration must leave server-side encrypted field as an encrypted marker during {migration_state:?}",
                                        )));
                                    };
                                    let Some(verified_envelope_key) = rewrite
                                        .verified_server_envelope_keys
                                        .iter()
                                        .find(|verified| verified.envelope_key() == &envelope_key)
                                    else {
                                        return Err(CollectionError::bad_input(format!(
                                            "crypto payload migration must provide a runtime server-envelope proof for server-side encrypted field during {migration_state:?}",
                                        )));
                                    };
                                    validate_server_payload_value_after_runtime_encryption(
                                        value,
                                        &collection_crypto_id,
                                        &record.id.to_string(),
                                        ServerPayloadValidationContext {
                                            field_path: server_rewrite_path,
                                            expected_kind: Some(*envelope_kind),
                                            key_id: key_id.as_deref(),
                                            crypto_schema_version,
                                            encryption_epoch,
                                        },
                                        verified_envelope_key,
                                    )
                                    .map_err(|_| {
                                        CollectionError::bad_input(format!(
                                            "crypto payload migration must leave server-side encrypted field as an encrypted marker during {migration_state:?}",
                                        ))
                                    })?;
                                }
                            }
                            CryptoMigrationState::Decrypting => {
                                if updated_values
                                    .iter()
                                    .any(|value| is_encrypted_payload_value(value))
                                {
                                    return Err(CollectionError::bad_input(format!(
                                        "crypto payload migration must decrypt server-side encrypted field during decrypting migration",
                                    )));
                                }
                            }
                            CryptoMigrationState::Disabled | CryptoMigrationState::Active => {}
                        }
                        json_path.value_remove(&mut original_non_migrated_payload);
                        json_path.value_remove(&mut updated_non_migrated_payload);
                    }
                    if original_non_migrated_payload != updated_non_migrated_payload {
                        return Err(CollectionError::bad_input(
                            "crypto payload migration must not mutate payload fields outside server-side encrypted migration selectors",
                        ));
                    }
                    if !payload_changed {
                        continue;
                    }
                    changed_points += 1;
                    if dry_run {
                        continue;
                    }

                    let operation = CollectionUpdateOperations::PayloadOperation(
                        PayloadOps::OverwritePayload(SetPayloadOp {
                            payload,
                            points: Some(vec![record.id]),
                            filter: None,
                            key: None,
                        }),
                    );
                    shard
                        .update_local(
                            OperationWithClockTag::from(operation),
                            WaitUntil::Visible,
                            None,
                            HwMeasurementAcc::disposable(),
                            false,
                        )
                        .await?;
                }

                if next_offset.is_none() {
                    break;
                }
            }

            checkpoints.push(CryptoMigrationCheckpoint {
                shard_id,
                total_points,
                processed_points,
                rewritten_points,
                changed_points,
                status: CryptoMigrationCheckpointStatus::Verified,
            });
        }

        Ok(checkpoints)
    }

    /// Apply collection update operation to all local shards.
    /// Return None if there are no local shards
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe.
    pub async fn update_all_local(
        &self,
        operation: CollectionUpdateOperations,
        wait: WaitUntil,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<Option<UpdateResult>> {
        let shard_holder = self.shards_holder.clone().read_owned().await;

        let results = self
            .update_runtime
            .spawn(async move {
                // `ShardReplicaSet::update_local` is *not* cancel safe, so we *have to* execute *all*
                // `update_local` requests to completion.
                //
                // Note that `futures::try_join_all`/`TryStreamExt::try_collect` *cancel* pending
                // requests if any of them returns an error, so we *have to* use
                // `futures::join_all`/`TryStreamExt::collect` instead!

                let local_updates: FuturesUnordered<_> = shard_holder
                    .all_shards()
                    .map(|shard| {
                        // The operation *can't* have a clock tag!
                        //
                        // We update *all* shards with a single operation, but each shard has it's own clock,
                        // so it's *impossible* to assign any single clock tag to this operation.
                        shard.update_local(
                            OperationWithClockTag::from(operation.clone()),
                            wait,
                            None,
                            hw_measurement_acc.clone(),
                            false,
                        )
                    })
                    .collect();

                let results: Vec<_> = local_updates.collect().await;

                results
            })
            .await?;

        let mut result = None;

        for collection_result in results {
            let update_result = collection_result?;

            if result.is_none() && update_result.is_some() {
                result = update_result;
            }
        }

        Ok(result)
    }

    /// Handle collection updates from peers.
    ///
    /// Shard transfer aware.
    ///
    /// # Cancel safety
    ///
    /// This method is cancel safe.
    async fn ensure_peer_update_crypto_invariants(
        &self,
        operation: &CollectionUpdateOperations,
    ) -> CollectionResult<()> {
        let (encryption, collection_crypto_id) = {
            let collection_config = self.collection_config.read().await;
            (
                collection_config.params.effective_encryption(),
                collection_config.stable_crypto_id(self.name())?,
            )
        };
        let Some(encryption) = encryption else {
            return Ok(());
        };

        reject_private_hnsw_oram_read_only_point_operation(operation, &encryption, true)?;
        reject_private_result_oram_payload_point_operation(operation, &encryption, true)?;

        match operation {
            CollectionUpdateOperations::PointOperation(
                PointOperations::UpsertPointsConditional(operation),
            ) => {
                self.ensure_filter_does_not_touch_encrypted_payload(Some(&operation.condition))
                    .await?
            }
            CollectionUpdateOperations::PointOperation(PointOperations::DeletePointsByFilter(
                filter,
            )) => {
                self.ensure_filter_does_not_touch_encrypted_payload(Some(filter))
                    .await?
            }
            CollectionUpdateOperations::PayloadOperation(
                PayloadOps::SetPayload(operation) | PayloadOps::OverwritePayload(operation),
            ) => {
                self.ensure_filter_does_not_touch_encrypted_payload(operation.filter.as_ref())
                    .await?;
            }
            CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(operation)) => {
                self.ensure_filter_does_not_touch_encrypted_payload(operation.filter.as_ref())
                    .await?;
            }
            CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(
                filter,
            )) => {
                self.ensure_filter_does_not_touch_encrypted_payload(Some(filter))
                    .await?
            }
            CollectionUpdateOperations::VectorOperation(VectorOperations::UpdateVectors(
                operation,
            )) => {
                self.ensure_filter_does_not_touch_encrypted_payload(
                    operation.update_filter.as_ref(),
                )
                .await?;
            }
            CollectionUpdateOperations::VectorOperation(
                VectorOperations::DeleteVectorsByFilter(filter, _),
            ) => {
                self.ensure_filter_does_not_touch_encrypted_payload(Some(filter))
                    .await?
            }
            _ => {}
        }

        let encrypted_vector_names = encryption
            .rules
            .iter()
            .flat_map(|rule| match &rule.selector {
                EncryptionSelector::VectorNames { names } => names.clone(),
                EncryptionSelector::PayloadPaths { .. }
                | EncryptionSelector::MetadataKeys { .. } => Vec::new(),
            })
            .collect::<HashSet<_>>();
        let encrypted_vector_key_id = encryption.key_id.as_deref();

        let validate_vector_sidecar_payload = |payload: &Payload,
                                               point_id: Option<&str>|
         -> CollectionResult<bool> {
            let Some(value) = payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD) else {
                return Ok(false);
            };
            let Some(point_id) = point_id else {
                return Err(CollectionError::bad_input(
                    "encrypted vector sidecar replay requires point-specific binding",
                ));
            };
            let Some(sidecar) = value.as_object() else {
                return Err(CollectionError::bad_input(
                    "encrypted vector sidecar must be an object",
                ));
            };
            for (vector_name, encrypted) in sidecar {
                if !encrypted_vector_names.contains(vector_name) {
                    return Err(CollectionError::bad_input(
                        "peer encrypted vector sidecar entry is not configured as an encrypted vector",
                    ));
                }
                let Some(marker) = encrypted
                    .as_object()
                    .and_then(|object| object.get(ENCRYPTED_CKKS_VECTOR_MARKER))
                else {
                    return Err(CollectionError::bad_input(
                        "peer encrypted vector sidecar entry is malformed",
                    ));
                };
                let encrypted_vector: EncryptedCkksVector = serde_json::from_value(marker.clone())
                    .map_err(|_| {
                        CollectionError::bad_input(
                            "peer encrypted vector sidecar entry is malformed",
                        )
                    })?;
                if let Some(key_id) = encrypted_vector_key_id
                    && encrypted_vector.envelope.key_id != key_id
                {
                    return Err(CollectionError::bad_input(
                        "peer encrypted vector sidecar entry key id does not match this collection",
                    ));
                }
                let Some(sidecar_key) = ckks_vector_sidecar_envelope_key(
                    encrypted,
                    &collection_crypto_id,
                    point_id,
                    vector_name,
                )
                .map_err(|_| {
                    CollectionError::bad_input(
                        "peer encrypted vector sidecar entry is invalid for this collection",
                    )
                })?
                else {
                    return Err(CollectionError::bad_input(
                        "peer encrypted vector sidecar entry is missing marker",
                    ));
                };
                if !sidecar_key.matches_binding(&collection_crypto_id, point_id, vector_name) {
                    return Err(CollectionError::bad_input(
                        "peer encrypted vector sidecar entry does not match collection, point, and vector binding",
                    ));
                }
            }
            Ok(true)
        };

        let validate_payload_path = |payload: &Payload,
                                     key: Option<&JsonPath>,
                                     point_id: Option<&str>,
                                     encrypted_path: &JsonPath,
                                     encrypted_path_str: &str,
                                     expected_envelope_kind: &str,
                                     allow_client_envelope: bool|
         -> CollectionResult<bool> {
            if let Some(key) = key {
                return Ok(key.compatible(encrypted_path));
            }

            for value in encrypted_path.value_get(&payload.0) {
                let Some(point_id) = point_id else {
                    return Err(CollectionError::bad_input(
                        "peer encrypted payload marker requires point-specific binding",
                    ));
                };
                if is_encrypted_payload_value(value) {
                    validate_server_payload_value_for_peer_replay(
                        value,
                        &collection_crypto_id,
                        point_id,
                        ServerPayloadValidationContext {
                            field_path: encrypted_path_str,
                            expected_kind: Some(expected_envelope_kind),
                            key_id: encryption.key_id.as_deref(),
                            crypto_schema_version: encryption.crypto_schema_version,
                            encryption_epoch: encryption.encryption_epoch,
                        },
                    )
                    .map_err(|_| {
                        CollectionError::bad_input(
                            "peer encrypted payload marker is invalid for this collection",
                        )
                    })?;
                    continue;
                }
                if let Some(err) =
                    peer_client_encrypted_payload_replay_violation(value, allow_client_envelope)
                {
                    return Err(err);
                }
                return Ok(true);
            }

            Ok(false)
        };

        let reject_payload_delete_for_encrypted_path =
            |keys: &[JsonPath], protected_path: &JsonPath, _protected_path_str: &str| {
                for key in keys {
                    if key.compatible(protected_path) {
                        return Err(CollectionError::bad_input(
                            "peer update cannot delete encrypted payload field via delete_payload",
                        ));
                    }
                }
                Ok(())
            };
        let vector_write_touches_encrypted_name =
            |vector: &VectorStructPersisted, encrypted_name: &str| match vector {
                VectorStructPersisted::Single(_) | VectorStructPersisted::MultiDense(_) => {
                    encrypted_name == DEFAULT_VECTOR_NAME
                }
                VectorStructPersisted::Named(vectors) => vectors.contains_key(encrypted_name),
            };

        if !encrypted_vector_names.is_empty() {
            match operation {
                CollectionUpdateOperations::PointOperation(point_operation) => {
                    match point_operation {
                        PointOperations::UpsertPoints(insert_operation)
                        | PointOperations::UpsertPointsConditional(
                            shard::operations::point_ops::ConditionalInsertOperationInternal {
                                points_op: insert_operation,
                                condition: _,
                                update_mode: _,
                            },
                        ) => match insert_operation {
                            PointInsertOperationsInternal::PointsBatch(batch) => {
                                if let Some(payloads) = batch.payloads.as_ref() {
                                    for (id, payload) in batch.ids.iter().zip(payloads).filter_map(
                                        |(id, payload)| {
                                            payload
                                                .as_ref()
                                                .map(|payload| (id.to_string(), payload))
                                        },
                                    ) {
                                        validate_vector_sidecar_payload(
                                            payload,
                                            Some(id.as_str()),
                                        )?;
                                    }
                                }
                            }
                            PointInsertOperationsInternal::PointsList(points) => {
                                for (id, payload) in points.iter().filter_map(|point| {
                                    point
                                        .payload
                                        .as_ref()
                                        .map(|payload| (point.id.to_string(), payload))
                                }) {
                                    validate_vector_sidecar_payload(payload, Some(id.as_str()))?;
                                }
                            }
                        },
                        PointOperations::SyncPoints(sync_operation) => {
                            for (id, payload) in sync_operation.points.iter().filter_map(|point| {
                                point
                                    .payload
                                    .as_ref()
                                    .map(|payload| (point.id.to_string(), payload))
                            }) {
                                validate_vector_sidecar_payload(payload, Some(id.as_str()))?;
                            }
                        }
                        PointOperations::DeletePoints { .. }
                        | PointOperations::DeletePointsByFilter(_) => {}
                    }
                }
                CollectionUpdateOperations::PayloadOperation(
                    PayloadOps::SetPayload(operation) | PayloadOps::OverwritePayload(operation),
                ) => {
                    let point_id = operation
                        .points
                        .as_ref()
                        .and_then(|points| (points.len() == 1).then(|| points[0].to_string()));
                    validate_vector_sidecar_payload(&operation.payload, point_id.as_deref())?;
                }
                CollectionUpdateOperations::PayloadOperation(
                    PayloadOps::ClearPayload { .. } | PayloadOps::ClearPayloadByFilter(_),
                ) => {
                    return Err(CollectionError::bad_input(
                        "peer update cannot clear encrypted vector sidecar",
                    ));
                }
                CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(
                    operation,
                )) => {
                    if operation
                        .keys
                        .iter()
                        .any(|key| key.first_key == ENCRYPTED_VECTOR_SIDECAR_FIELD)
                    {
                        return Err(CollectionError::bad_input(
                            "peer update cannot delete encrypted vector sidecar",
                        ));
                    }
                }
                CollectionUpdateOperations::VectorOperation(_)
                | CollectionUpdateOperations::FieldIndexOperation(_) => {}
                #[cfg(feature = "staging")]
                CollectionUpdateOperations::StagingOperation(_) => {}
            }
        }

        for rule in &encryption.rules {
            match &rule.selector {
                EncryptionSelector::PayloadPaths { paths } => {
                    let allow_client_envelope =
                        rule.binding.as_deref() == Some(CLIENT_PAYLOAD_ENVELOPE_BINDING);
                    for encrypted_path in paths {
                        let encrypted_json_path =
                            parse_payload_selector_guard_path(rule, encrypted_path)?;
                        let touches_encrypted_payload = match operation {
                            CollectionUpdateOperations::PointOperation(point_operation) => {
                                match point_operation {
                                    PointOperations::UpsertPoints(insert_operation)
                                    | PointOperations::UpsertPointsConditional(
                                        shard::operations::point_ops::ConditionalInsertOperationInternal {
                                            points_op: insert_operation,
                                            condition: _,
                                            update_mode: _,
                                        },
                                    ) => match insert_operation {
                                        PointInsertOperationsInternal::PointsBatch(batch) => {
                                            let mut touches = false;
                                            if let Some(payloads) = batch.payloads.as_ref() {
                                                for (id, payload) in batch
                                                    .ids
                                                    .iter()
                                                    .zip(payloads)
                                                    .filter_map(|(id, payload)| {
                                                        payload
                                                            .as_ref()
                                                            .map(|payload| (id.to_string(), payload))
                                                    })
                                                {
                                                    validate_vector_sidecar_payload(
                                                        payload,
                                                        Some(id.as_str()),
                                                    )?;
                                                    if validate_payload_path(
                                                        payload,
                                                        None,
                                                        Some(id.as_str()),
                                                        &encrypted_json_path,
                                                        encrypted_path,
                                                        PAYLOAD_TEXT_ENVELOPE_KIND,
                                                        allow_client_envelope,
                                                    )? {
                                                        touches = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            touches
                                        }
                                        PointInsertOperationsInternal::PointsList(points) => {
                                            let mut touches = false;
                                            for (id, payload) in points.iter().filter_map(|point| {
                                                point
                                                    .payload
                                                    .as_ref()
                                                    .map(|payload| (point.id.to_string(), payload))
                                            }) {
                                                validate_vector_sidecar_payload(
                                                    payload,
                                                    Some(id.as_str()),
                                                )?;
                                                if validate_payload_path(
                                                    payload,
                                                    None,
                                                    Some(id.as_str()),
                                                    &encrypted_json_path,
                                                    encrypted_path,
                                                    PAYLOAD_TEXT_ENVELOPE_KIND,
                                                    allow_client_envelope,
                                                )? {
                                                    touches = true;
                                                    break;
                                                }
                                            }
                                            touches
                                        }
                                    },
                                    PointOperations::SyncPoints(sync_operation) => {
                                        let mut touches = false;
                                        for (id, payload) in sync_operation
                                            .points
                                            .iter()
                                            .filter_map(|point| {
                                                point
                                                    .payload
                                                    .as_ref()
                                                    .map(|payload| (point.id.to_string(), payload))
                                            })
                                        {
                                            validate_vector_sidecar_payload(
                                                payload,
                                                Some(id.as_str()),
                                            )?;
                                            if validate_payload_path(
                                                payload,
                                                None,
                                                Some(id.as_str()),
                                                &encrypted_json_path,
                                                encrypted_path,
                                                PAYLOAD_TEXT_ENVELOPE_KIND,
                                                allow_client_envelope,
                                            )? {
                                                touches = true;
                                                break;
                                            }
                                        }
                                        touches
                                    }
                                    PointOperations::DeletePoints { .. }
                                    | PointOperations::DeletePointsByFilter(_) => false,
                                }
                            }
                            CollectionUpdateOperations::PayloadOperation(
                                PayloadOps::SetPayload(operation)
                                | PayloadOps::OverwritePayload(operation),
                            ) => {
                                validate_vector_sidecar_payload(
                                    &operation.payload,
                                    operation
                                        .points
                                        .as_ref()
                                        .and_then(|points| {
                                            (points.len() == 1).then(|| points[0].to_string())
                                        })
                                        .as_deref(),
                                )?;
                                let point_id = operation.points.as_ref().and_then(|points| {
                                    (points.len() == 1).then(|| points[0].to_string())
                                });
                                validate_payload_path(
                                    &operation.payload,
                                    operation.key.as_ref(),
                                    point_id.as_deref(),
                                    &encrypted_json_path,
                                    encrypted_path,
                                    PAYLOAD_TEXT_ENVELOPE_KIND,
                                    allow_client_envelope,
                                )?
                            }
                            CollectionUpdateOperations::PayloadOperation(
                                PayloadOps::DeletePayload(operation),
                            ) => {
                                reject_payload_delete_for_encrypted_path(
                                    &operation.keys,
                                    &encrypted_json_path,
                                    encrypted_path,
                                )?;
                                false
                            }
                            CollectionUpdateOperations::PayloadOperation(
                                PayloadOps::ClearPayload { .. }
                                | PayloadOps::ClearPayloadByFilter(_),
                            ) => true,
                            CollectionUpdateOperations::VectorOperation(_)
                            | CollectionUpdateOperations::FieldIndexOperation(_) => false,
                            #[cfg(feature = "staging")]
                            CollectionUpdateOperations::StagingOperation(_) => false,
                        };
                        if touches_encrypted_payload {
                            return Err(CollectionError::bad_input(
                                "peer update cannot write plaintext payload for encrypted field",
                            ));
                        }
                    }
                }
                EncryptionSelector::VectorNames { names } => {
                    for encrypted_name in names {
                        let touches_encrypted_vector = match operation {
                            CollectionUpdateOperations::PointOperation(point_operation) => {
                                match point_operation {
                                    PointOperations::UpsertPoints(insert_operation)
                                    | PointOperations::UpsertPointsConditional(
                                        shard::operations::point_ops::ConditionalInsertOperationInternal {
                                            points_op: insert_operation,
                                            condition: _,
                                            update_mode: _,
                                        },
                                    ) => match insert_operation {
                                        PointInsertOperationsInternal::PointsBatch(batch) => {
                                            match &batch.vectors {
                                                BatchVectorStructPersisted::Single(_)
                                                | BatchVectorStructPersisted::MultiDense(_) => {
                                                    encrypted_name == DEFAULT_VECTOR_NAME
                                                }
                                                BatchVectorStructPersisted::Named(vectors) => {
                                                    vectors.contains_key(encrypted_name)
                                                }
                                            }
                                        }
                                        PointInsertOperationsInternal::PointsList(points) => {
                                            points.iter().any(|point| {
                                                vector_write_touches_encrypted_name(
                                                    &point.vector,
                                                    encrypted_name,
                                                )
                                            })
                                        }
                                    },
                                    PointOperations::SyncPoints(sync_operation) => {
                                        sync_operation.points.iter().any(|point| {
                                            vector_write_touches_encrypted_name(
                                                &point.vector,
                                                encrypted_name,
                                            )
                                        })
                                    }
                                    PointOperations::DeletePoints { .. }
                                    | PointOperations::DeletePointsByFilter(_) => false,
                                }
                            }
                            CollectionUpdateOperations::VectorOperation(
                                VectorOperations::UpdateVectors(operation),
                            ) => operation.points.iter().any(|point| {
                                vector_write_touches_encrypted_name(
                                    &point.vector,
                                    encrypted_name,
                                )
                            }),
                            CollectionUpdateOperations::VectorOperation(
                                VectorOperations::DeleteVectors(_, vector_names)
                                | VectorOperations::DeleteVectorsByFilter(_, vector_names),
                            ) => vector_names.iter().any(|name| name == encrypted_name),
                            CollectionUpdateOperations::PayloadOperation(_)
                            | CollectionUpdateOperations::FieldIndexOperation(_) => false,
                            #[cfg(feature = "staging")]
                            CollectionUpdateOperations::StagingOperation(_) => false,
                        };
                        if touches_encrypted_vector {
                            return Err(plaintext_vector_write_error_for_encryption_rule(
                                encrypted_name,
                                rule,
                                true,
                            ));
                        }
                    }
                }
                EncryptionSelector::MetadataKeys { keys } => {
                    for metadata_key in keys {
                        let metadata_path = metadata_key.parse::<JsonPath>().map_err(|_| {
                            CollectionError::bad_input("encrypted metadata field path is invalid")
                        })?;
                        match operation {
                            CollectionUpdateOperations::PayloadOperation(
                                PayloadOps::DeletePayload(operation),
                            ) => {
                                reject_payload_delete_for_encrypted_path(
                                    &operation.keys,
                                    &metadata_path,
                                    metadata_key,
                                )?;
                            }
                            CollectionUpdateOperations::PayloadOperation(
                                PayloadOps::ClearPayload { .. }
                                | PayloadOps::ClearPayloadByFilter(_),
                            ) => {
                                return Err(CollectionError::bad_input(
                                    "peer update cannot clear encrypted metadata field",
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn update_from_peer(
        &self,
        operation: OperationWithClockTag,
        shard_selection: ShardId,
        wait: WaitUntil,
        timeout: Option<Duration>,
        ordering: WriteOrdering,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<UpdateResult> {
        self.ensure_crypto_migration_allows_regular_operation("peer writes")
            .await?;
        self.ensure_peer_update_crypto_invariants(&operation.operation)
            .await?;

        let shard_holder = self.shards_holder.clone().read_owned().await;

        let result = self.update_runtime.spawn(async move {
            let Some(shard) = shard_holder.get_shard(shard_selection) else {
                return Ok(None);
            };

            match ordering {
                WriteOrdering::Weak => shard.update_local(operation, wait, timeout, hw_measurement_acc.clone(), false).await,
                WriteOrdering::Medium | WriteOrdering::Strong => {
                    if let Some(clock_tag) = operation.clock_tag {
                        log::warn!(
                            "Received update operation forwarded from another peer with {ordering:?} \
                             with non-`None` clock tag {clock_tag:?} (operation: {})",
                             operation.operation.to_log_value(),
                        );
                    }

                    shard
                        .update_with_consistency(operation.operation, wait, timeout, ordering, false, hw_measurement_acc)
                        .await
                        .map(Some)
                }
            }
        })
        .await??;

        if let Some(result) = result {
            Ok(result)
        } else {
            // Special error type needed to handle creation of partial shards
            // In all other scenarios, equivalent to `service_error`
            Err(CollectionError::pre_condition_failed(format!(
                "No target shard {shard_selection} found for update"
            )))
        }
    }

    /// # Cancel safety
    ///
    /// This method is cancel safe.
    pub async fn update_from_client(
        &self,
        operation: CollectionUpdateOperations,
        wait: WaitUntil,
        timeout: Option<Duration>,
        ordering: WriteOrdering,
        shard_keys_selection: Option<ShardKey>,
        hw_measurement_acc: HwMeasurementAcc,
        update_provenance: CollectionUpdateProvenance,
    ) -> CollectionResult<UpdateResult> {
        let (encryption, collection_crypto_id) = {
            let collection_config = self.collection_config.read().await;
            (
                collection_config.params.effective_encryption(),
                collection_config.stable_crypto_id(self.name())?,
            )
        };
        if let Some(encryption) = encryption.as_ref()
            && let Err(err) = ensure_crypto_migration_state_allows_regular_operation(
                encryption.migration_state,
                "writes",
            )
        {
            return Err(err);
        }
        if let Some(encryption) = encryption.as_ref() {
            reject_private_hnsw_oram_read_only_point_operation(&operation, encryption, false)?;
            reject_private_result_oram_payload_point_operation(&operation, encryption, false)?;
        }
        if encryption.is_some() {
            match &operation {
                CollectionUpdateOperations::PointOperation(
                    PointOperations::UpsertPointsConditional(operation),
                ) => {
                    self.ensure_filter_does_not_touch_encrypted_payload(Some(&operation.condition))
                        .await?
                }
                CollectionUpdateOperations::PointOperation(
                    PointOperations::DeletePointsByFilter(filter),
                ) => {
                    self.ensure_filter_does_not_touch_encrypted_payload(Some(filter))
                        .await?
                }
                CollectionUpdateOperations::PayloadOperation(
                    PayloadOps::SetPayload(operation) | PayloadOps::OverwritePayload(operation),
                ) => {
                    self.ensure_filter_does_not_touch_encrypted_payload(operation.filter.as_ref())
                        .await?;
                }
                CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(
                    operation,
                )) => {
                    self.ensure_filter_does_not_touch_encrypted_payload(operation.filter.as_ref())
                        .await?;
                }
                CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(
                    filter,
                )) => {
                    self.ensure_filter_does_not_touch_encrypted_payload(Some(filter))
                        .await?
                }
                CollectionUpdateOperations::VectorOperation(VectorOperations::UpdateVectors(
                    operation,
                )) => {
                    self.ensure_filter_does_not_touch_encrypted_payload(
                        operation.update_filter.as_ref(),
                    )
                    .await?;
                }
                CollectionUpdateOperations::VectorOperation(
                    VectorOperations::DeleteVectorsByFilter(filter, _),
                ) => {
                    self.ensure_filter_does_not_touch_encrypted_payload(Some(filter))
                        .await?
                }
                _ => {}
            }
        }
        let encrypted_vector_names = encryption
            .as_ref()
            .map(|encryption| {
                encryption
                    .rules
                    .iter()
                    .flat_map(|rule| match &rule.selector {
                        EncryptionSelector::VectorNames { names } => names.clone(),
                        EncryptionSelector::PayloadPaths { .. }
                        | EncryptionSelector::MetadataKeys { .. } => Vec::new(),
                    })
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let encrypted_vector_key_id = encryption
            .as_ref()
            .and_then(|encryption| encryption.key_id.clone());

        let payload_write_touches_vector_sidecar = |payload: &Payload,
                                                    key: Option<&JsonPath>,
                                                    point_id: Option<&str>|
         -> CollectionResult<bool> {
            if let Some(key) = key {
                if key.first_key == ENCRYPTED_VECTOR_SIDECAR_FIELD {
                    return Err(CollectionError::bad_input(
                        "encrypted vector sidecar must be written as a full runtime-generated sidecar payload",
                    ));
                }
                return Ok(false);
            }

            let mut touches = false;
            if let Some(value) = payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD) {
                touches = true;
                let Some(sidecar) = value.as_object() else {
                    return Err(CollectionError::bad_input(
                        "encrypted vector sidecar must be an object",
                    ));
                };
                for (vector_name, encrypted) in sidecar {
                    if !encrypted_vector_names.contains(vector_name) {
                        return Err(CollectionError::bad_input(
                            "encrypted vector sidecar entry is not configured as an encrypted vector",
                        ));
                    }
                    let Some(point_id) = point_id else {
                        return Err(CollectionError::bad_input(
                            "encrypted vector sidecar entry requires point-specific runtime vector encryption before collection write",
                        ));
                    };
                    let Some(marker_object) = encrypted.as_object() else {
                        return Err(CollectionError::bad_input(
                            "encrypted vector sidecar entry is malformed",
                        ));
                    };
                    if let Some(marker) = marker_object.get(ENCRYPTED_CKKS_VECTOR_MARKER) {
                        let encrypted_vector: EncryptedCkksVector =
                            serde_json::from_value(marker.clone()).map_err(|_| {
                                CollectionError::bad_input(
                                    "encrypted vector sidecar entry is malformed",
                                )
                            })?;
                        if encrypted_vector.version != 1 {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry has unsupported version",
                            ));
                        }
                        if encrypted_vector.scheme != CKKS_SCHEME {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry has unsupported scheme",
                            ));
                        }
                        if let Some(key_id) = encrypted_vector_key_id.as_deref()
                            && encrypted_vector.envelope.key_id != key_id
                        {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry key id does not match this collection",
                            ));
                        }
                        if encrypted_vector.envelope.algorithm != "AES-256-GCM" {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry has unsupported envelope algorithm",
                            ));
                        }
                        if encrypted_vector.envelope.material_fingerprint.is_empty() {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry is missing material fingerprint",
                            ));
                        }
                        if encrypted_vector.envelope.nonce.len()
                            != CKKS_VECTOR_SIDECAR_NONCE_B64_LEN
                        {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry nonce must be 12 bytes",
                            ));
                        }
                        let nonce = BASE64URL_NOPAD
                            .decode(encrypted_vector.envelope.nonce.as_bytes())
                            .map_err(|_| {
                                CollectionError::bad_input(
                                    "encrypted vector sidecar entry nonce is not base64url",
                                )
                            })?;
                        if nonce.len() != 12 {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry nonce must be 12 bytes",
                            ));
                        }
                        if encrypted_vector.envelope.ciphertext.len()
                            > CKKS_VECTOR_SIDECAR_CIPHERTEXT_MAX_B64_LEN
                        {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry ciphertext exceeds maximum size",
                            ));
                        }
                        let ciphertext = BASE64URL_NOPAD
                            .decode(encrypted_vector.envelope.ciphertext.as_bytes())
                            .map_err(|_| {
                                CollectionError::bad_input(
                                    "encrypted vector sidecar entry ciphertext is not base64url",
                                )
                            })?;
                        if ciphertext.len() < 16 {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry ciphertext is too short",
                            ));
                        }
                        if ciphertext.len() > CKKS_VECTOR_SIDECAR_CIPHERTEXT_MAX_BYTES {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry ciphertext exceeds maximum size",
                            ));
                        }
                        let Some(sidecar_key) = ckks_vector_sidecar_envelope_key(
                            encrypted,
                            &collection_crypto_id,
                            point_id,
                            vector_name,
                        )
                        .map_err(|_| {
                            CollectionError::bad_input(
                                "encrypted vector sidecar entry is invalid for this collection",
                            )
                        })?
                        else {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry requires runtime vector encryption before collection write",
                            ));
                        };
                        let Some(_verified_sidecar_key) = update_provenance
                            .verified_vector_sidecar_key_for_binding(
                                &sidecar_key,
                                &collection_crypto_id,
                                point_id,
                                vector_name,
                            )
                        else {
                            return Err(CollectionError::bad_input(
                                "encrypted vector sidecar entry requires runtime vector encryption before collection write",
                            ));
                        };
                    } else if marker_object.contains_key(CLIENT_CKKS_VECTOR_MARKER) {
                        let Some(sidecar_key) =
                            client_ckks_vector_sidecar_envelope_key(encrypted, vector_name)
                                .map_err(|_| {
                                    CollectionError::bad_input(
                                        "client encrypted vector sidecar entry is invalid for this collection",
                                    )
                                })?
                        else {
                            return Err(CollectionError::bad_input(
                                "client encrypted vector sidecar entry requires runtime client vector verification before collection write",
                            ));
                        };
                        let Some(_verified_sidecar_key) = update_provenance
                            .verified_client_vector_sidecar_key_for_binding(
                                &sidecar_key,
                                &collection_crypto_id,
                                point_id,
                                vector_name,
                            )
                        else {
                            return Err(CollectionError::bad_input(
                                "client encrypted vector sidecar entry requires runtime client vector verification before collection write",
                            ));
                        };
                    } else {
                        return Err(CollectionError::bad_input(
                            "encrypted vector sidecar entry is malformed",
                        ));
                    }
                }
            }
            Ok(touches)
        };
        let validate_payload_delete_does_not_mutate_vector_sidecar =
            |keys: &[JsonPath],
             points: Option<&[segment::types::PointIdType]>,
             filter: Option<&Filter>|
             -> CollectionResult<()> {
                let target = ckks_vector_sidecar_delete_target(points, filter);
                for key in keys {
                    if key.first_key != ENCRYPTED_VECTOR_SIDECAR_FIELD {
                        continue;
                    }
                    let Some(target) = target.as_ref() else {
                        return Err(CollectionError::bad_input(
                            "encrypted vector sidecar can only be removed by targeted runtime delete_vectors operations",
                        ));
                    };
                    if !update_provenance.allows_vector_sidecar_delete_key(
                        &collection_crypto_id,
                        key,
                        target,
                    ) {
                        return Err(CollectionError::bad_input(
                            "encrypted vector sidecar can only be removed by runtime delete_vectors operations",
                        ));
                    }
                }
                Ok(())
            };
        let touches_vector_sidecar = match &operation {
            CollectionUpdateOperations::PointOperation(point_operation) => match point_operation {
                PointOperations::UpsertPoints(insert_operation)
                | PointOperations::UpsertPointsConditional(
                    shard::operations::point_ops::ConditionalInsertOperationInternal {
                        points_op: insert_operation,
                        condition: _,
                        update_mode: _,
                    },
                ) => match insert_operation {
                    PointInsertOperationsInternal::PointsBatch(batch) => {
                        let mut touches = false;
                        if let Some(payloads) = batch.payloads.as_ref() {
                            for (id, payload) in
                                batch.ids.iter().zip(payloads).filter_map(|(id, payload)| {
                                    payload.as_ref().map(|payload| (id.to_string(), payload))
                                })
                            {
                                if payload_write_touches_vector_sidecar(
                                    payload,
                                    None,
                                    Some(id.as_str()),
                                )? {
                                    touches = true;
                                    break;
                                }
                            }
                        }
                        touches
                    }
                    PointInsertOperationsInternal::PointsList(points) => points
                        .iter()
                        .filter_map(|point| {
                            point
                                .payload
                                .as_ref()
                                .map(|payload| (point.id.to_string(), payload))
                        })
                        .try_fold(false, |touches, (id, payload)| {
                            Ok::<bool, CollectionError>(
                                touches
                                    || payload_write_touches_vector_sidecar(
                                        payload,
                                        None,
                                        Some(id.as_str()),
                                    )?,
                            )
                        })?,
                },
                PointOperations::SyncPoints(sync_operation) => sync_operation
                    .points
                    .iter()
                    .filter_map(|point| {
                        point
                            .payload
                            .as_ref()
                            .map(|payload| (point.id.to_string(), payload))
                    })
                    .try_fold(false, |touches, (id, payload)| {
                        Ok::<bool, CollectionError>(
                            touches
                                || payload_write_touches_vector_sidecar(
                                    payload,
                                    None,
                                    Some(id.as_str()),
                                )?,
                        )
                    })?,
                PointOperations::DeletePoints { .. } | PointOperations::DeletePointsByFilter(_) => {
                    false
                }
            },
            CollectionUpdateOperations::PayloadOperation(
                PayloadOps::SetPayload(operation) | PayloadOps::OverwritePayload(operation),
            ) => {
                let point_id = operation
                    .points
                    .as_ref()
                    .and_then(|points| (points.len() == 1).then(|| points[0].to_string()));
                payload_write_touches_vector_sidecar(
                    &operation.payload,
                    operation.key.as_ref(),
                    point_id.as_deref(),
                )?
            }
            CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(operation)) => {
                validate_payload_delete_does_not_mutate_vector_sidecar(
                    &operation.keys,
                    operation.points.as_deref(),
                    operation.filter.as_ref(),
                )?;
                false
            }
            CollectionUpdateOperations::PayloadOperation(
                PayloadOps::ClearPayload { .. } | PayloadOps::ClearPayloadByFilter(_),
            ) => {
                if !encrypted_vector_names.is_empty() {
                    return Err(CollectionError::bad_input(
                        "encrypted vector sidecar cannot be removed by clear_payload; use delete_vectors for encrypted vector names",
                    ));
                }
                false
            }
            CollectionUpdateOperations::VectorOperation(_)
            | CollectionUpdateOperations::FieldIndexOperation(_) => false,
            #[cfg(feature = "staging")]
            CollectionUpdateOperations::StagingOperation(_) => false,
        };
        if touches_vector_sidecar && !update_provenance.allows_vector_sidecars() {
            return Err(CollectionError::bad_input(
                "encrypted vector sidecar requires runtime CKKS vector encryption before collection write",
            ));
        }
        if let Some(encryption) = encryption {
            let mut seen_client_nonces = std::collections::HashSet::new();
            let client_payload_envelope_rules_present = encryption.rules.iter().any(|rule| {
                matches!(rule.selector, EncryptionSelector::PayloadPaths { .. })
                    && rule.binding.as_deref() == Some(CLIENT_PAYLOAD_ENVELOPE_BINDING)
            });
            let payload_write_touches_metadata_blind_index =
                |payload: &Payload,
                 key: Option<&JsonPath>,
                 point_id: Option<&str>,
                 metadata_path: &JsonPath,
                 metadata_key: &str|
                 -> CollectionResult<bool> {
                    if let Some(key) = key {
                        if key.compatible(metadata_path) {
                            return Err(CollectionError::bad_input(
                                "metadata blind-index field must be written as a full payload object so its token can be validated",
                            ));
                        }
                        return Ok(false);
                    }

                    let mut touches = false;
                    for value in metadata_path.value_get(&payload.0) {
                        validate_metadata_blind_index_json_value(value, metadata_key)?;
                        if client_payload_envelope_rules_present {
                            let Some(point_id) = point_id else {
                                return Err(CollectionError::bad_input(
                                    "metadata blind-index field cannot be written for client-side encrypted payload collections without point-specific runtime envelope verification",
                                ));
                            };
                            let Some(token) = value.as_str() else {
                                return Err(CollectionError::bad_input(
                                    "metadata blind-index field must contain a base64url-no-padding HMAC-SHA256 token string",
                                ));
                            };
                            if !update_provenance.has_verified_client_blind_index_binding(
                                &collection_crypto_id,
                                point_id,
                                metadata_key,
                                token,
                            ) {
                                return Err(CollectionError::bad_input(
                                    "metadata blind-index field cannot be written for client-side encrypted payload collections until the client envelope signature binds the token manifest",
                                ));
                            }
                        }
                        touches = true;
                    }
                    Ok(touches)
                };
            let mut payload_write_touches_encrypted_path = |payload: &Payload,
                                                            key: Option<&JsonPath>,
                                                            point_id: Option<&str>,
                                                            encrypted_path: &JsonPath,
                                                            encrypted_path_str: &str,
                                                            expected_envelope_kind: &str,
                                                            allow_client_envelope: bool|
             -> CollectionResult<bool> {
                if let Some(key) = key {
                    return Ok(key.compatible(encrypted_path));
                }

                for value in encrypted_path.value_get(&payload.0) {
                    if is_encrypted_payload_value(value) {
                        let Some(point_id) = point_id else {
                            return Err(CollectionError::bad_input(
                                "encrypted payload marker requires point-specific runtime payload encryption before collection write",
                            ));
                        };
                        let Some(envelope_key) = server_payload_envelope_key(
                            value,
                            &collection_crypto_id,
                            point_id,
                            encrypted_path_str,
                        )
                        .map_err(|_| {
                            CollectionError::bad_input(
                                "encrypted payload marker is invalid for this collection",
                            )
                        })?
                        else {
                            return Err(CollectionError::bad_input(
                                "encrypted payload marker requires runtime payload encryption before collection write",
                            ));
                        };
                        let Some(verified_envelope_key) = update_provenance
                            .verified_server_envelope_key_for_binding(
                                &envelope_key,
                                &collection_crypto_id,
                                point_id,
                                encrypted_path_str,
                            )
                        else {
                            return Err(CollectionError::bad_input(
                                "encrypted payload marker requires runtime payload encryption before collection write",
                            ));
                        };
                        validate_server_payload_value_after_runtime_encryption(
                            value,
                            &collection_crypto_id,
                            point_id,
                            ServerPayloadValidationContext {
                                field_path: encrypted_path_str,
                                expected_kind: Some(expected_envelope_kind),
                                key_id: encryption.key_id.as_deref(),
                                crypto_schema_version: encryption.crypto_schema_version,
                                encryption_epoch: encryption.encryption_epoch,
                            },
                            &verified_envelope_key,
                        )
                        .map_err(|_| {
                            CollectionError::bad_input(
                                "encrypted payload marker is invalid for this collection",
                            )
                        })?;
                        continue;
                    }
                    if allow_client_envelope && is_client_encrypted_payload_value(value) {
                        let Some(envelope_key) = client_payload_envelope_key(
                            value,
                            encrypted_path_str,
                        )
                        .map_err(|_| {
                            CollectionError::bad_input(
                                "client encrypted payload marker is invalid for this collection",
                            )
                        })?
                        else {
                            return Err(CollectionError::bad_input(
                                "client encrypted payload marker requires runtime envelope verification before collection write",
                            ));
                        };
                        let Some(point_id) = point_id else {
                            return Err(CollectionError::bad_input(
                                "client encrypted payload marker requires point-specific runtime envelope verification before collection write",
                            ));
                        };
                        let Some(verified_envelope_key) = update_provenance
                            .verified_client_envelope_key_for_binding(
                                &envelope_key,
                                &collection_crypto_id,
                                point_id,
                                encrypted_path_str,
                            )
                        else {
                            return Err(CollectionError::bad_input(
                                "client encrypted payload marker requires runtime envelope verification before collection write",
                            ));
                        };
                        validate_client_payload_value_after_runtime_verification(
                            value,
                            ClientPayloadValidationContext {
                                collection_id: &collection_crypto_id,
                                point_id,
                                field_path: encrypted_path_str,
                                expected_key_id: encryption.key_id.as_deref(),
                                expected_rk_id: encryption.key_id.as_deref(),
                                min_rk_epoch: Some(encryption.encryption_epoch),
                                max_rk_epoch: Some(encryption.encryption_epoch),
                                key_id_required: true,
                                signature_required: true,
                                signature_verification: None,
                            },
                            &verified_envelope_key,
                        )
                        .map_err(|_| {
                            CollectionError::bad_input(
                                "client encrypted payload marker is invalid for this collection",
                            )
                        })?;
                        let Some(nonce_replay_key) = client_payload_nonce_replay_key(
                            value,
                            encrypted_path_str,
                        )
                        .map_err(|_| {
                            CollectionError::bad_input(
                                "client encrypted payload marker is invalid for this collection",
                            )
                        })?
                        else {
                            return Ok(true);
                        };
                        if !seen_client_nonces.insert(nonce_replay_key) {
                            return Err(CollectionError::bad_input(
                                "client encrypted payload marker is invalid for this collection: payload field client envelope nonce was already used in this write request; regenerate the client-side envelope with a fresh nonce before retrying",
                            ));
                        }
                        continue;
                    }
                    return Ok(true);
                }

                Ok(false)
            };
            let reject_payload_delete_for_encrypted_path = |keys: &[JsonPath],
                                                            protected_path: &JsonPath,
                                                            _protected_path_str: &str,
                                                            protected_kind: &str|
             -> CollectionResult<()> {
                for key in keys {
                    if key.compatible(protected_path) {
                        return Err(CollectionError::bad_input(format!(
                            "cannot delete {protected_kind} via delete_payload; use a crypto-aware update or migration path",
                        )));
                    }
                }
                Ok(())
            };
            let reject_payload_clear_for_encrypted_path = |_protected_path_str: &str,
                                                           protected_kind: &str|
             -> CollectionResult<()> {
                Err(CollectionError::bad_input(format!(
                    "cannot clear payloads containing {protected_kind}; use a crypto-aware update or migration path",
                )))
            };
            let vector_write_touches_encrypted_name =
                |vector: &VectorStructPersisted, encrypted_name: &str| match vector {
                    VectorStructPersisted::Single(_) | VectorStructPersisted::MultiDense(_) => {
                        encrypted_name == DEFAULT_VECTOR_NAME
                    }
                    VectorStructPersisted::Named(vectors) => vectors.contains_key(encrypted_name),
                };

            for rule in &encryption.rules {
                match &rule.selector {
                    EncryptionSelector::PayloadPaths { paths } => {
                        let allow_client_envelope =
                            rule.binding.as_deref() == Some(CLIENT_PAYLOAD_ENVELOPE_BINDING);
                        for encrypted_path in paths {
                            let encrypted_json_path =
                                parse_payload_selector_guard_path(rule, encrypted_path)?;

                            let touches_encrypted_payload = match &operation {
                                CollectionUpdateOperations::PointOperation(point_operation) => {
                                    match point_operation {
                                        PointOperations::UpsertPoints(insert_operation)
                                        | PointOperations::UpsertPointsConditional(
                                            shard::operations::point_ops::ConditionalInsertOperationInternal {
                                                points_op: insert_operation,
                                                condition: _,
                                                update_mode: _,
                                            },
                                        ) => match insert_operation {
                                            PointInsertOperationsInternal::PointsBatch(batch) => {
                                                let mut touches = false;
                                                if let Some(payloads) = batch.payloads.as_ref() {
                                                    for (id, payload) in batch
                                                        .ids
                                                        .iter()
                                                        .zip(payloads)
                                                        .filter_map(|(id, payload)| {
                                                            payload.as_ref().map(|payload| {
                                                                (id.to_string(), payload)
                                                            })
                                                        })
                                                    {
                                                        if payload_write_touches_encrypted_path(
                                                            payload,
                                                            None,
                                                            Some(id.as_str()),
                                                            &encrypted_json_path,
                                                            encrypted_path,
                                                            PAYLOAD_TEXT_ENVELOPE_KIND,
                                                            allow_client_envelope,
                                                        )? {
                                                            touches = true;
                                                            break;
                                                        }
                                                    }
                                                }
                                                touches
                                            }
                                            PointInsertOperationsInternal::PointsList(points) => {
                                                let mut touches = false;
                                                for (id, payload) in points
                                                    .iter()
                                                    .filter_map(|point| {
                                                        point
                                                            .payload
                                                            .as_ref()
                                                            .map(|payload| {
                                                                (point.id.to_string(), payload)
                                                            })
                                                    })
                                                {
                                                    if payload_write_touches_encrypted_path(
                                                        payload,
                                                        None,
                                                        Some(id.as_str()),
                                                        &encrypted_json_path,
                                                        encrypted_path,
                                                        PAYLOAD_TEXT_ENVELOPE_KIND,
                                                        allow_client_envelope,
                                                    )? {
                                                        touches = true;
                                                        break;
                                                    }
                                                }
                                                touches
                                            }
                                        },
                                        PointOperations::SyncPoints(sync_operation) => {
                                            let mut touches = false;
                                            for (id, payload) in sync_operation
                                                .points
                                                .iter()
                                                .filter_map(|point| {
                                                    point
                                                        .payload
                                                        .as_ref()
                                                        .map(|payload| (point.id.to_string(), payload))
                                                })
                                            {
                                                if payload_write_touches_encrypted_path(
                                                    payload,
                                                    None,
                                                    Some(id.as_str()),
                                                    &encrypted_json_path,
                                                    encrypted_path,
                                                    PAYLOAD_TEXT_ENVELOPE_KIND,
                                                    allow_client_envelope,
                                                )? {
                                                    touches = true;
                                                    break;
                                                }
                                            }
                                            touches
                                        }
                                        PointOperations::DeletePoints { .. }
                                        | PointOperations::DeletePointsByFilter(_) => false,
                                    }
                                }
                                CollectionUpdateOperations::PayloadOperation(
                                    PayloadOps::SetPayload(operation)
                                    | PayloadOps::OverwritePayload(operation),
                                ) => {
                                    let point_id = operation.points.as_ref().and_then(|points| {
                                        (points.len() == 1).then(|| points[0].to_string())
                                    });
                                    payload_write_touches_encrypted_path(
                                        &operation.payload,
                                        operation.key.as_ref(),
                                        point_id.as_deref(),
                                        &encrypted_json_path,
                                        encrypted_path,
                                        PAYLOAD_TEXT_ENVELOPE_KIND,
                                        allow_client_envelope,
                                    )?
                                }
                                CollectionUpdateOperations::PayloadOperation(
                                    PayloadOps::DeletePayload(operation),
                                ) => {
                                    reject_payload_delete_for_encrypted_path(
                                        &operation.keys,
                                        &encrypted_json_path,
                                        encrypted_path,
                                        "encrypted payload field",
                                    )?;
                                    false
                                }
                                CollectionUpdateOperations::PayloadOperation(
                                    PayloadOps::ClearPayload { .. }
                                    | PayloadOps::ClearPayloadByFilter(_),
                                ) => {
                                    reject_payload_clear_for_encrypted_path(
                                        encrypted_path,
                                        "encrypted payload field",
                                    )?;
                                    false
                                }
                                CollectionUpdateOperations::VectorOperation(_)
                                | CollectionUpdateOperations::FieldIndexOperation(_) => false,
                                #[cfg(feature = "staging")]
                                CollectionUpdateOperations::StagingOperation(_) => false,
                            };

                            if touches_encrypted_payload {
                                return Err(CollectionError::bad_input(
                                    "cannot write plaintext payload for encrypted field; configure runtime payload encryption before writing this field",
                                ));
                            }
                        }
                    }
                    EncryptionSelector::VectorNames { names } => {
                        for encrypted_name in names {
                            let touches_encrypted_vector = match &operation {
                                CollectionUpdateOperations::PointOperation(point_operation) => {
                                    match point_operation {
                                        PointOperations::UpsertPoints(insert_operation)
                                        | PointOperations::UpsertPointsConditional(
                                            shard::operations::point_ops::ConditionalInsertOperationInternal {
                                                points_op: insert_operation,
                                                condition: _,
                                                update_mode: _,
                                            },
                                        ) => match insert_operation {
                                            PointInsertOperationsInternal::PointsBatch(batch) => {
                                                match &batch.vectors {
                                                    BatchVectorStructPersisted::Single(_)
                                                    | BatchVectorStructPersisted::MultiDense(_) => {
                                                        encrypted_name == DEFAULT_VECTOR_NAME
                                                    }
                                                    BatchVectorStructPersisted::Named(vectors) => {
                                                        vectors.contains_key(encrypted_name)
                                                    }
                                                }
                                            }
                                            PointInsertOperationsInternal::PointsList(points) => {
                                                points.iter().any(|point| {
                                                    vector_write_touches_encrypted_name(
                                                        &point.vector,
                                                        encrypted_name,
                                                    )
                                                })
                                            }
                                        },
                                        PointOperations::SyncPoints(sync_operation) => {
                                            sync_operation.points.iter().any(|point| {
                                                vector_write_touches_encrypted_name(
                                                    &point.vector,
                                                    encrypted_name,
                                                )
                                            })
                                        }
                                        PointOperations::DeletePoints { .. }
                                        | PointOperations::DeletePointsByFilter(_) => false,
                                    }
                                }
                                CollectionUpdateOperations::VectorOperation(
                                    VectorOperations::UpdateVectors(operation),
                                ) => operation.points.iter().any(|point| {
                                    vector_write_touches_encrypted_name(
                                        &point.vector,
                                        encrypted_name,
                                    )
                                }),
                                CollectionUpdateOperations::VectorOperation(
                                    VectorOperations::DeleteVectors(_, vector_names)
                                    | VectorOperations::DeleteVectorsByFilter(_, vector_names),
                                ) => vector_names.iter().any(|name| name == encrypted_name),
                                CollectionUpdateOperations::PayloadOperation(_)
                                | CollectionUpdateOperations::FieldIndexOperation(_) => false,
                                #[cfg(feature = "staging")]
                                CollectionUpdateOperations::StagingOperation(_) => false,
                            };

                            if touches_encrypted_vector {
                                return Err(plaintext_vector_write_error_for_encryption_rule(
                                    encrypted_name,
                                    rule,
                                    false,
                                ));
                            }
                        }
                    }
                    EncryptionSelector::MetadataKeys { keys } => {
                        for metadata_key in keys {
                            let metadata_path = metadata_key.parse::<JsonPath>().map_err(|_| {
                                CollectionError::bad_input(
                                    "metadata blind-index field path is invalid",
                                )
                            })?;

                            if rule.binding.as_deref() == Some(METADATA_VALUE_BINDING) {
                                let touches_encrypted_metadata = match &operation {
                                    CollectionUpdateOperations::PointOperation(point_operation) => {
                                        match point_operation {
                                            PointOperations::UpsertPoints(insert_operation)
                                            | PointOperations::UpsertPointsConditional(
                                                shard::operations::point_ops::ConditionalInsertOperationInternal {
                                                    points_op: insert_operation,
                                                    condition: _,
                                                    update_mode: _,
                                                },
                                            ) => match insert_operation {
                                                PointInsertOperationsInternal::PointsBatch(batch) => {
                                                    let mut touches = false;
                                                    if let Some(payloads) = batch.payloads.as_ref()
                                                    {
                                                        for (id, payload) in batch
                                                            .ids
                                                            .iter()
                                                            .zip(payloads)
                                                            .filter_map(|(id, payload)| {
                                                                payload.as_ref().map(|payload| {
                                                                    (id.to_string(), payload)
                                                                })
                                                            })
                                                        {
                                                            if payload_write_touches_encrypted_path(
                                                                payload,
                                                                None,
                                                                Some(id.as_str()),
                                                                &metadata_path,
                                                                metadata_key,
                                                                METADATA_VALUE_ENVELOPE_KIND,
                                                                false,
                                                            )? {
                                                                touches = true;
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    touches
                                                }
                                                PointInsertOperationsInternal::PointsList(
                                                    points,
                                                ) => {
                                                    let mut touches = false;
                                                    for (id, payload) in
                                                        points.iter().filter_map(|point| {
                                                            point.payload.as_ref().map(|payload| {
                                                                (point.id.to_string(), payload)
                                                            })
                                                        })
                                                    {
                                                        if payload_write_touches_encrypted_path(
                                                            payload,
                                                            None,
                                                            Some(id.as_str()),
                                                            &metadata_path,
                                                            metadata_key,
                                                            METADATA_VALUE_ENVELOPE_KIND,
                                                            false,
                                                        )? {
                                                            touches = true;
                                                            break;
                                                        }
                                                    }
                                                    touches
                                                }
                                            },
                                            PointOperations::SyncPoints(sync_operation) => {
                                                let mut touches = false;
                                                for (id, payload) in sync_operation
                                                    .points
                                                    .iter()
                                                    .filter_map(|point| {
                                                        point.payload.as_ref().map(|payload| {
                                                            (point.id.to_string(), payload)
                                                        })
                                                    })
                                                {
                                                    if payload_write_touches_encrypted_path(
                                                        payload,
                                                        None,
                                                        Some(id.as_str()),
                                                        &metadata_path,
                                                        metadata_key,
                                                        METADATA_VALUE_ENVELOPE_KIND,
                                                        false,
                                                    )? {
                                                        touches = true;
                                                        break;
                                                    }
                                                }
                                                touches
                                            }
                                            PointOperations::DeletePoints { .. }
                                            | PointOperations::DeletePointsByFilter(_) => false,
                                        }
                                    }
                                    CollectionUpdateOperations::PayloadOperation(
                                        PayloadOps::SetPayload(operation)
                                        | PayloadOps::OverwritePayload(operation),
                                    ) => {
                                        let point_id =
                                            operation.points.as_ref().and_then(|points| {
                                                (points.len() == 1)
                                                    .then(|| points[0].to_string())
                                            });
                                        payload_write_touches_encrypted_path(
                                            &operation.payload,
                                            operation.key.as_ref(),
                                            point_id.as_deref(),
                                            &metadata_path,
                                            metadata_key,
                                            METADATA_VALUE_ENVELOPE_KIND,
                                            false,
                                        )?
                                    }
                                    CollectionUpdateOperations::PayloadOperation(
                                        PayloadOps::DeletePayload(operation),
                                    ) => {
                                        reject_payload_delete_for_encrypted_path(
                                            &operation.keys,
                                            &metadata_path,
                                            metadata_key,
                                            "encrypted metadata value field",
                                        )?;
                                        false
                                    }
                                    CollectionUpdateOperations::PayloadOperation(
                                        PayloadOps::ClearPayload { .. }
                                        | PayloadOps::ClearPayloadByFilter(_),
                                    ) => {
                                        reject_payload_clear_for_encrypted_path(
                                            metadata_key,
                                            "encrypted metadata value field",
                                        )?;
                                        false
                                    }
                                    CollectionUpdateOperations::VectorOperation(_)
                                    | CollectionUpdateOperations::FieldIndexOperation(_) => false,
                                    #[cfg(feature = "staging")]
                                    CollectionUpdateOperations::StagingOperation(_) => false,
                                };

                                if touches_encrypted_metadata {
                                    return Err(CollectionError::bad_input(
                                        "cannot write plaintext metadata value for encrypted field; configure runtime metadata value encryption before writing this field",
                                    ));
                                }
                                continue;
                            }

                            match &operation {
                                CollectionUpdateOperations::PointOperation(point_operation) => {
                                    match point_operation {
                                        PointOperations::UpsertPoints(insert_operation)
                                        | PointOperations::UpsertPointsConditional(
                                            shard::operations::point_ops::ConditionalInsertOperationInternal {
                                                points_op: insert_operation,
                                                condition: _,
                                                update_mode: _,
                                            },
                                        ) => match insert_operation {
                                            PointInsertOperationsInternal::PointsBatch(batch) => {
                                                if let Some(payloads) = batch.payloads.as_ref() {
                                                    for (id, payload) in
                                                        batch.ids.iter().zip(payloads).filter_map(
                                                            |(id, payload)| {
                                                                payload
                                                                    .as_ref()
                                                                    .map(|payload| (id, payload))
                                                            },
                                                        )
                                                    {
                                                        let point_id = id.to_string();
                                                        payload_write_touches_metadata_blind_index(
                                                            payload,
                                                            None,
                                                            Some(point_id.as_str()),
                                                            &metadata_path,
                                                            metadata_key,
                                                        )?;
                                                    }
                                                }
                                            }
                                            PointInsertOperationsInternal::PointsList(points) => {
                                                for (id, payload) in points
                                                    .iter()
                                                    .filter_map(|point| {
                                                        point
                                                            .payload
                                                            .as_ref()
                                                            .map(|payload| (&point.id, payload))
                                                    })
                                                {
                                                    let point_id = id.to_string();
                                                    payload_write_touches_metadata_blind_index(
                                                        payload,
                                                        None,
                                                        Some(point_id.as_str()),
                                                        &metadata_path,
                                                        metadata_key,
                                                    )?;
                                                }
                                            }
                                        },
                                        PointOperations::SyncPoints(sync_operation) => {
                                            for (id, payload) in sync_operation
                                                .points
                                                .iter()
                                                .filter_map(|point| {
                                                    point
                                                        .payload
                                                        .as_ref()
                                                        .map(|payload| (&point.id, payload))
                                                })
                                            {
                                                let point_id = id.to_string();
                                                payload_write_touches_metadata_blind_index(
                                                    payload,
                                                    None,
                                                    Some(point_id.as_str()),
                                                    &metadata_path,
                                                    metadata_key,
                                                )?;
                                            }
                                        }
                                        PointOperations::DeletePoints { .. }
                                        | PointOperations::DeletePointsByFilter(_) => {}
                                    }
                                }
                                CollectionUpdateOperations::PayloadOperation(
                                    PayloadOps::SetPayload(operation)
                                    | PayloadOps::OverwritePayload(operation),
                                ) => {
                                    let single_point_id =
                                        operation.points.as_ref().and_then(|points| {
                                            (points.len() == 1).then(|| points[0].to_string())
                                        });
                                    payload_write_touches_metadata_blind_index(
                                        &operation.payload,
                                        operation.key.as_ref(),
                                        single_point_id.as_deref(),
                                        &metadata_path,
                                        metadata_key,
                                    )?;
                                }
                                CollectionUpdateOperations::PayloadOperation(
                                    PayloadOps::DeletePayload(operation),
                                ) => {
                                    reject_payload_delete_for_encrypted_path(
                                        &operation.keys,
                                        &metadata_path,
                                        metadata_key,
                                        "metadata blind-index field",
                                    )?;
                                }
                                CollectionUpdateOperations::PayloadOperation(
                                    PayloadOps::ClearPayload { .. }
                                    | PayloadOps::ClearPayloadByFilter(_),
                                ) => {
                                    reject_payload_clear_for_encrypted_path(
                                        metadata_key,
                                        "metadata blind-index field",
                                    )?;
                                }
                                CollectionUpdateOperations::VectorOperation(_)
                                | CollectionUpdateOperations::FieldIndexOperation(_) => {}
                                #[cfg(feature = "staging")]
                                CollectionUpdateOperations::StagingOperation(_) => {}
                            }
                        }
                    }
                }
            }

            if !seen_client_nonces.is_empty() {
                self.record_client_payload_nonce_replay_keys(
                    seen_client_nonces
                        .iter()
                        .map(|key| client_nonce_replay_cache_key(&collection_crypto_id, key)),
                )
                .await?;
            }
        }

        let shard_holder = self.shards_holder.clone().read_owned().await;
        let start_time = std::time::Instant::now();

        let results = self
            .update_runtime
            .spawn(async move {
                let updates = FuturesUnordered::new();
                let operations = shard_holder.split_by_shard(operation, &shard_keys_selection)?;

                for (shard, operation) in operations {
                    let operation = shard_holder.split_by_mode(shard.shard_id, operation);

                    let hw_acc = hw_measurement_acc.clone();
                    updates.push(async move {
                        let mut result = UpdateResult {
                            operation_id: None,
                            status: UpdateStatus::Acknowledged,
                            clock_tag: None,
                        };

                        for operation in operation.update_all {
                            result = shard
                                .update_with_consistency(
                                    operation,
                                    wait,
                                    timeout,
                                    ordering,
                                    false,
                                    hw_acc.clone(),
                                )
                                .await?;
                        }

                        for operation in operation.update_only_existing {
                            let res = shard
                                .update_with_consistency(
                                    operation,
                                    wait,
                                    timeout,
                                    ordering,
                                    true,
                                    hw_acc.clone(),
                                )
                                .await;

                            if let Err(err) = &res
                                && err.is_missing_point()
                            {
                                continue;
                            }

                            result = res?;
                        }

                        CollectionResult::Ok(result)
                    });
                }

                let results: Vec<_> = updates.collect().await;

                CollectionResult::Ok(results)
            })
            .await??;

        if results.is_empty() {
            return Err(CollectionError::bad_request(
                "Empty update request".to_string(),
            ));
        }

        let with_error = results.iter().filter(|result| result.is_err()).count();

        // one request per shard
        let result_len = results.len();

        if with_error > 0 {
            let Some(first_err) = results.into_iter().find(|result| result.is_err()) else {
                return Err(CollectionError::service_error(
                    "update aggregation expected at least one shard error",
                ));
            };
            // inconsistent if only a subset of the requests fail - one request per shard.
            if with_error < result_len {
                first_err.map_err(|err| {
                    // compute final status code based on the first error
                    // e.g. a partially successful batch update failing because of bad input is a client error
                    CollectionError::InconsistentShardFailure {
                        shards_total: result_len as u32, // report only the number of shards that took part in the update
                        shards_failed: with_error as u32,
                        first_err: Box::new(err),
                    }
                })
            } else {
                // all requests per shard failed - propagate first error (assume there are all the same)
                first_err
            }
        } else {
            // If client-side timeout is specified, we can return `WaitTimeout` status as-is.
            // Otherwise, we fall back to timeout error.

            let is_user_timeout = timeout.is_some();

            let results: Vec<_> = results.into_iter().flatten().collect();
            // Aggregate status: WaitTimeout > .. > ClockRejected
            let status = results
                .iter()
                .map(|res| res.status)
                .max_by_key(|s| s.priority())
                .unwrap_or(UpdateStatus::Acknowledged);

            if !is_user_timeout && results.iter().any(|res| res.status.is_timeout()) {
                // if user didn't specify timeout, but one of the shards timed out,
                // we need to return timeout error

                let total_timeout_shards = results
                    .iter()
                    .filter(|result| result.status.is_timeout())
                    .count();

                let elapsed_sec = start_time.elapsed().as_secs_f32();

                return Err(CollectionError::Timeout {
                    description: format!(
                        "Update operation timed out in {elapsed_sec:.2} seconds on {total_timeout_shards} out of {result_len} shards."
                    ),
                });
            }

            let max_operation_id = results
                .into_iter()
                .map(|r| r.operation_id)
                .max()
                .unwrap_or(None);

            Ok(UpdateResult {
                operation_id: max_operation_id,
                status,
                clock_tag: None, // clock_tag is not used in the user response
            })
        }
    }

    /// # Cancel safety
    ///
    /// This method is cancel safe.
    pub async fn update_from_client_simple(
        &self,
        operation: CollectionUpdateOperations,
        wait: bool,
        timeout: Option<Duration>,
        ordering: WriteOrdering,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<UpdateResult> {
        self.update_from_client(
            operation,
            WaitUntil::from(wait),
            timeout,
            ordering,
            None,
            hw_measurement_acc,
            CollectionUpdateProvenance::client_plaintext(),
        )
        .await
    }

    pub(crate) async fn ensure_crypto_migration_allows_regular_operation(
        &self,
        operation_kind: &str,
    ) -> CollectionResult<()> {
        let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        else {
            return Ok(());
        };
        ensure_crypto_migration_state_allows_regular_operation(
            encryption.migration_state,
            operation_kind,
        )
    }

    pub async fn scroll_by(
        &self,
        mut request: ScrollRequestInternal,
        read_consistency: Option<ReadConsistency>,
        shard_selection: &ShardSelectorInternal,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<ScrollResult> {
        let default_request = ScrollRequestInternal::default();

        let default_limit = default_request.limit.ok_or_else(|| {
            CollectionError::service_error("scroll default request is missing a limit")
        })?;
        let mut limit = request.limit.unwrap_or(default_limit);

        self.ensure_crypto_migration_allows_regular_operation("reads")
            .await?;
        self.ensure_filter_does_not_touch_encrypted_payload(request.filter.as_ref())
            .await?;

        let order_by = request.order_by.clone().map(OrderBy::from);
        self.ensure_order_by_does_not_touch_encrypted_payload(order_by.as_ref())
            .await?;
        self.ensure_with_vector_does_not_touch_encrypted_vector(&request.with_vector)
            .await?;
        let encrypted_payload_read_mode = request
            .with_payload
            .as_ref()
            .map(WithPayloadInterface::encrypted_payload_read_mode)
            .unwrap_or(EncryptedPayloadReadMode::Raw);
        ensure_encrypted_payload_read_mode_is_supported(encrypted_payload_read_mode)?;
        self.ensure_private_result_oram_payload_read_is_not_raw(request.with_payload.as_ref())
            .await?;
        if limit == 0 {
            return Err(CollectionError::BadRequest {
                description: "Limit cannot be 0".to_string(),
            });
        }

        let local_only = shard_selection.is_shard_id();

        // `order_by` does not support offset
        if order_by.is_none() {
            // Needed to return next page offset.
            limit = limit.saturating_add(1);
            request.limit = Some(limit);
        }

        let request = Arc::new(request);

        let mut retrieved_points: Vec<_> = {
            let shards_holder = self.shards_holder.read().await;
            let target_shards = shards_holder.select_shards(shard_selection)?;

            let scroll_futures = target_shards.into_iter().map(|(shard, shard_key)| {
                let shard_key = shard_key.cloned();
                shard
                    .scroll_by(
                        request.clone(),
                        read_consistency,
                        local_only,
                        timeout,
                        hw_measurement_acc.clone(),
                    )
                    .and_then(move |mut records| async move {
                        if shard_key.is_none() {
                            return Ok(records);
                        }
                        for point in &mut records {
                            point.shard_key.clone_from(&shard_key);
                        }
                        Ok(records)
                    })
            });
            future::try_join_all(scroll_futures).await?
        };
        let redaction_plan = self
            .encrypted_payload_redaction_plan_for_mode(encrypted_payload_read_mode)
            .await?;
        for records in &mut retrieved_points {
            apply_encrypted_payload_read_mode_to_records(
                records,
                encrypted_payload_read_mode,
                redaction_plan.as_ref(),
            );
        }

        let retrieved_iter = retrieved_points.into_iter();

        let mut points = match &order_by {
            None => retrieved_iter
                .flatten()
                .sorted_unstable_by_key(|point| point.id)
                // Add each point only once, deduplicate point IDs
                .dedup_by(|a, b| a.id == b.id)
                .take(limit)
                .map(api::rest::Record::from)
                .collect_vec(),
            Some(order_by) => {
                retrieved_iter
                    // Get top results
                    .kmerge_by(|a, b| match order_by.direction() {
                        Direction::Asc => (a.order_value, a.id) < (b.order_value, b.id),
                        Direction::Desc => (a.order_value, a.id) > (b.order_value, b.id),
                    })
                    .dedup_by(|record_a, record_b| {
                        (record_a.order_value, record_a.id) == (record_b.order_value, record_b.id)
                    })
                    .map(api::rest::Record::from)
                    .take(limit)
                    .collect_vec()
            }
        };

        let next_page_offset = if points.len() < limit || order_by.is_some() {
            // This was the last page
            None
        } else {
            // remove extra point, it would be a first point of the next page
            let Some(point) = points.pop() else {
                return Err(CollectionError::service_error(
                    "scroll next page offset requested but result set is empty",
                ));
            };
            Some(point.id)
        };
        Ok(ScrollResult {
            points,
            next_page_offset,
        })
    }

    pub async fn count(
        &self,
        request: CountRequestInternal,
        read_consistency: Option<ReadConsistency>,
        shard_selection: &ShardSelectorInternal,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<CountResult> {
        self.ensure_crypto_migration_allows_regular_operation("reads")
            .await?;
        self.ensure_filter_does_not_touch_encrypted_payload(request.filter.as_ref())
            .await?;

        let shards_holder = self.shards_holder.read().await;
        let shards = shards_holder.select_shards(shard_selection)?;

        let request = Arc::new(request);

        let mut requests: FuturesUnordered<_> = shards
            .into_iter()
            // `count` requests received through internal gRPC *always* have `shard_selection`
            .map(|(shard, _shard_key)| {
                shard.count(
                    Arc::clone(&request),
                    read_consistency,
                    timeout,
                    shard_selection.is_shard_id(),
                    hw_measurement_acc.clone(),
                    DeferredBehavior::Exclude,
                )
            })
            .collect();

        let mut count = 0;
        while let Some(response) = requests.try_next().await? {
            count += response.count;
        }

        Ok(CountResult { count })
    }

    pub(crate) async fn ensure_with_vector_does_not_touch_encrypted_vector(
        &self,
        with_vector: &WithVector,
    ) -> CollectionResult<()> {
        if !with_vector.is_enabled() {
            return Ok(());
        }
        let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        else {
            return Ok(());
        };

        if let Some(err) = encrypted_vector_return_error(&encryption, with_vector) {
            return Err(err);
        }

        Ok(())
    }

    pub async fn retrieve(
        &self,
        request: PointRequestInternal,
        read_consistency: Option<ReadConsistency>,
        shard_selection: &ShardSelectorInternal,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<Vec<RecordInternal>> {
        self.ensure_crypto_migration_allows_regular_operation("reads")
            .await?;
        self.ensure_with_vector_does_not_touch_encrypted_vector(&request.with_vector)
            .await?;
        let with_payload_interface = request
            .with_payload
            .as_ref()
            .unwrap_or(&WithPayloadInterface::Bool(false));
        let encrypted_payload_read_mode = with_payload_interface.encrypted_payload_read_mode();
        ensure_encrypted_payload_read_mode_is_supported(encrypted_payload_read_mode)?;
        self.ensure_private_result_oram_payload_read_is_not_raw(request.with_payload.as_ref())
            .await?;
        if request.ids.is_empty() {
            return Ok(Vec::new());
        }
        let with_payload = WithPayload::from(with_payload_interface);
        let ids_len = request.ids.len();
        let request = Arc::new(request);

        let shard_holder = self.shards_holder.read().await;
        let target_shards = shard_holder.select_shards(shard_selection)?;
        let mut all_shard_collection_requests = target_shards
            .into_iter()
            .map(|(shard, shard_key)| {
                // Explicitly borrow `request` and `with_payload`, so we can use them in `async move`
                // block below without unnecessarily cloning anything
                let request = &request;
                let with_payload = &with_payload;

                let hw_acc = hw_measurement_acc.clone();

                async move {
                    let mut records = shard
                        .retrieve(
                            request.clone(),
                            with_payload,
                            &request.with_vector,
                            read_consistency,
                            timeout,
                            shard_selection.is_shard_id(),
                            hw_acc,
                        )
                        .await?;

                    if shard_key.is_none() {
                        return Ok(records);
                    }

                    for point in &mut records {
                        point.shard_key.clone_from(&shard_key.cloned());
                    }

                    CollectionResult::Ok(records)
                }
            })
            .collect::<FuturesUnordered<_>>();

        // pre-allocate hashmap with capped capacity to protect from malevolent input
        let mut covered_point_ids = HashMap::with_capacity(ids_len.min(1024));
        while let Some(response) = all_shard_collection_requests.try_next().await? {
            for point in response {
                // Add each point only once, deduplicate point IDs
                covered_point_ids.insert(point.id, point);
            }
        }

        // Collect points in the same order as they were requested
        let mut points: Vec<RecordInternal> = request
            .ids
            .iter()
            .filter_map(|id| covered_point_ids.remove(id))
            .collect();
        let redaction_plan = self
            .encrypted_payload_redaction_plan_for_mode(encrypted_payload_read_mode)
            .await?;
        apply_encrypted_payload_read_mode_to_records(
            &mut points,
            encrypted_payload_read_mode,
            redaction_plan.as_ref(),
        );

        Ok(points)
    }

    pub async fn ensure_filter_does_not_touch_encrypted_payload(
        &self,
        filter: Option<&Filter>,
    ) -> CollectionResult<()> {
        let Some(filter) = filter else {
            return Ok(());
        };
        let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        else {
            return Ok(());
        };

        if let Some(sidecar_path) = encrypted_vector_sidecar_path(&encryption)?
            && filter_touches_encrypted_payload(filter, &sidecar_path).is_some()
        {
            return Err(CollectionError::bad_input(
                "cannot filter on encrypted vector sidecar field; use encrypted vector search APIs instead",
            ));
        }

        for rule in &encryption.rules {
            match &rule.selector {
                EncryptionSelector::PayloadPaths { paths } => {
                    for encrypted_path in paths {
                        let encrypted_json_path =
                            parse_payload_selector_guard_path(rule, encrypted_path)?;
                        if let Some(filter_path) =
                            filter_touches_encrypted_payload(filter, &encrypted_json_path)
                        {
                            if encryption_rule_uses_private_result_oram(rule) {
                                return Err(CollectionError::bad_input(
                                    private_result_oram_payload_selector_overlap_message(
                                        filter_path,
                                        encrypted_path,
                                    ),
                                ));
                            }
                            return Err(CollectionError::bad_input(
                                "cannot filter on encrypted payload field because it overlaps an encrypted payload selector; configure a blind index provider instead",
                            ));
                        }
                    }
                }
                EncryptionSelector::VectorNames { names } => {
                    for encrypted_name in names {
                        if let Some(filter_vector) =
                            filter_touches_encrypted_vector(filter, encrypted_name)
                        {
                            return Err(encrypted_vector_filter_error(rule, filter_vector));
                        }
                    }
                }
                EncryptionSelector::MetadataKeys { keys } => {
                    for metadata_key in keys {
                        let metadata_path = metadata_key.parse::<JsonPath>().map_err(|_| {
                            CollectionError::bad_input("metadata blind-index field path is invalid")
                        })?;
                        if rule.binding.as_deref() == Some(METADATA_VALUE_BINDING) {
                            if filter_touches_encrypted_payload(filter, &metadata_path).is_some() {
                                return Err(CollectionError::bad_input(
                                    "cannot filter on encrypted metadata value field because it overlaps an encrypted metadata selector; configure a blind index provider instead",
                                ));
                            }
                            continue;
                        }
                        validate_filter_metadata_blind_index_tokens(
                            filter,
                            &metadata_path,
                            metadata_key,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn ensure_order_by_does_not_touch_encrypted_payload(
        &self,
        order_by: Option<&OrderBy>,
    ) -> CollectionResult<()> {
        let Some(order_by) = order_by else {
            return Ok(());
        };
        let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        else {
            return Ok(());
        };

        if let Some(sidecar_path) = encrypted_vector_sidecar_path(&encryption)?
            && order_by.key.compatible(&sidecar_path)
        {
            return Err(CollectionError::bad_input(
                "cannot order by encrypted vector sidecar field; use encrypted vector search APIs instead",
            ));
        }

        for rule in &encryption.rules {
            match &rule.selector {
                EncryptionSelector::PayloadPaths { paths } => {
                    for encrypted_path in paths {
                        let encrypted_json_path =
                            parse_payload_selector_guard_path(rule, encrypted_path)?;
                        if order_by.key.compatible(&encrypted_json_path) {
                            if encryption_rule_uses_private_result_oram(rule) {
                                return Err(CollectionError::bad_input(
                                    private_result_oram_payload_selector_overlap_message(
                                        &order_by.key,
                                        encrypted_path,
                                    ),
                                ));
                            }
                            return Err(CollectionError::bad_input(
                                "cannot order by encrypted payload field because it overlaps an encrypted payload selector; configure a blind index provider instead",
                            ));
                        }
                    }
                }
                EncryptionSelector::MetadataKeys { keys } => {
                    for metadata_key in keys {
                        let metadata_path = parse_metadata_blind_index_path(metadata_key)?;
                        if rule.binding.as_deref() == Some(METADATA_VALUE_BINDING) {
                            if order_by.key.compatible(&metadata_path) {
                                return Err(CollectionError::bad_input(
                                    "cannot order by encrypted metadata value field because it overlaps an encrypted metadata selector; configure a blind index provider instead",
                                ));
                            }
                            continue;
                        }
                        if order_by.key.compatible(&metadata_path) {
                            return Err(CollectionError::bad_input(
                                "cannot order by metadata blind-index field; blind-index token fields support exact-match filters only",
                            ));
                        }
                    }
                }
                EncryptionSelector::VectorNames { .. } => {}
            }
        }

        Ok(())
    }

    pub(crate) async fn ensure_group_by_does_not_touch_encrypted_payload(
        &self,
        group_by: &JsonPath,
    ) -> CollectionResult<()> {
        let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        else {
            return Ok(());
        };

        if let Some(sidecar_path) = encrypted_vector_sidecar_path(&encryption)?
            && group_by.compatible(&sidecar_path)
        {
            return Err(CollectionError::bad_input(
                "cannot group by encrypted vector sidecar field; use encrypted vector search APIs instead",
            ));
        }

        for rule in &encryption.rules {
            match &rule.selector {
                EncryptionSelector::PayloadPaths { paths } => {
                    for encrypted_path in paths {
                        let encrypted_json_path =
                            parse_payload_selector_guard_path(rule, encrypted_path)?;
                        if group_by.compatible(&encrypted_json_path) {
                            if encryption_rule_uses_private_result_oram(rule) {
                                return Err(CollectionError::bad_input(
                                    private_result_oram_payload_selector_overlap_message(
                                        group_by,
                                        encrypted_path,
                                    ),
                                ));
                            }
                            return Err(CollectionError::bad_input(
                                "cannot group by encrypted payload field because it overlaps an encrypted payload selector; configure a blind index provider instead",
                            ));
                        }
                    }
                }
                EncryptionSelector::MetadataKeys { keys } => {
                    for metadata_key in keys {
                        let metadata_path = parse_metadata_blind_index_path(metadata_key)?;
                        if rule.binding.as_deref() == Some(METADATA_VALUE_BINDING) {
                            if group_by.compatible(&metadata_path) {
                                return Err(CollectionError::bad_input(
                                    "cannot group by encrypted metadata value field because it overlaps an encrypted metadata selector; configure a blind index provider instead",
                                ));
                            }
                            continue;
                        }
                        if group_by.compatible(&metadata_path) {
                            return Err(CollectionError::bad_input(
                                "cannot group by metadata blind-index field; blind-index token fields support exact-match filters only",
                            ));
                        }
                    }
                }
                EncryptionSelector::VectorNames { .. } => {}
            }
        }

        Ok(())
    }

    pub(crate) async fn ensure_formula_does_not_touch_encrypted_payload(
        &self,
        formula: Option<&ParsedFormula>,
    ) -> CollectionResult<()> {
        let Some(formula) = formula else {
            return Ok(());
        };
        let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        else {
            return Ok(());
        };

        if let Some(sidecar_path) = encrypted_vector_sidecar_path(&encryption)? {
            if formula
                .payload_vars
                .iter()
                .find(|payload_var| payload_var.compatible(&sidecar_path))
                .is_some()
            {
                return Err(CollectionError::bad_input(
                    "cannot use encrypted vector sidecar field in formula; use encrypted vector search APIs instead",
                ));
            }

            if formula
                .conditions
                .iter()
                .find_map(|condition| condition_touches_encrypted_payload(condition, &sidecar_path))
                .is_some()
            {
                return Err(CollectionError::bad_input(
                    "cannot use formula condition on encrypted vector sidecar field; use encrypted vector search APIs instead",
                ));
            }
        }

        for rule in &encryption.rules {
            match &rule.selector {
                EncryptionSelector::PayloadPaths { paths } => {
                    for encrypted_path in paths {
                        let encrypted_json_path =
                            parse_payload_selector_guard_path(rule, encrypted_path)?;

                        if let Some(formula_path) = formula
                            .payload_vars
                            .iter()
                            .find(|payload_var| payload_var.compatible(&encrypted_json_path))
                        {
                            if encryption_rule_uses_private_result_oram(rule) {
                                return Err(CollectionError::bad_input(
                                    private_result_oram_payload_selector_overlap_message(
                                        formula_path,
                                        encrypted_path,
                                    ),
                                ));
                            }
                            return Err(CollectionError::bad_input(
                                "cannot use encrypted payload field in formula because it overlaps an encrypted payload selector; configure a blind index provider instead",
                            ));
                        }

                        if let Some(condition_path) =
                            formula.conditions.iter().find_map(|condition| {
                                condition_touches_encrypted_payload(condition, &encrypted_json_path)
                            })
                        {
                            if encryption_rule_uses_private_result_oram(rule) {
                                return Err(CollectionError::bad_input(
                                    private_result_oram_payload_selector_overlap_message(
                                        condition_path,
                                        encrypted_path,
                                    ),
                                ));
                            }
                            return Err(CollectionError::bad_input(
                                "cannot use formula condition on encrypted payload field because it overlaps an encrypted payload selector; configure a blind index provider instead",
                            ));
                        }
                    }
                }
                EncryptionSelector::MetadataKeys { keys } => {
                    for metadata_key in keys {
                        let metadata_path = parse_metadata_blind_index_path(metadata_key)?;

                        if rule.binding.as_deref() == Some(METADATA_VALUE_BINDING) {
                            if formula
                                .payload_vars
                                .iter()
                                .find(|payload_var| payload_var.compatible(&metadata_path))
                                .is_some()
                            {
                                return Err(CollectionError::bad_input(
                                    "cannot use encrypted metadata value field in formula because it overlaps an encrypted metadata selector; configure a blind index provider instead",
                                ));
                            }

                            if formula
                                .conditions
                                .iter()
                                .find_map(|condition| {
                                    condition_touches_encrypted_payload(condition, &metadata_path)
                                })
                                .is_some()
                            {
                                return Err(CollectionError::bad_input(
                                    "cannot use formula condition on encrypted metadata value field because it overlaps an encrypted metadata selector; configure a blind index provider instead",
                                ));
                            }
                            continue;
                        }

                        if formula
                            .payload_vars
                            .iter()
                            .find(|payload_var| payload_var.compatible(&metadata_path))
                            .is_some()
                        {
                            return Err(CollectionError::bad_input(
                                "cannot use metadata blind-index field in formula; blind-index token fields support exact-match filters only",
                            ));
                        }

                        if formula
                            .conditions
                            .iter()
                            .find_map(|condition| {
                                condition_touches_encrypted_payload(condition, &metadata_path)
                            })
                            .is_some()
                        {
                            return Err(CollectionError::bad_input(
                                "cannot use formula condition on metadata blind-index field; blind-index token fields support exact-match filters only",
                            ));
                        }
                    }
                }
                EncryptionSelector::VectorNames { .. } => {}
            }
        }

        Ok(())
    }
}

pub struct CryptoPayloadMigrationRewrite {
    pub changed: usize,
    pub verified_server_envelope_keys: Vec<ServerPayloadVerifiedEnvelopeKey>,
}

impl CryptoPayloadMigrationRewrite {
    pub fn new(changed: usize) -> Self {
        Self {
            changed,
            verified_server_envelope_keys: Vec::new(),
        }
    }

    pub fn with_server_envelope_keys(
        changed: usize,
        verified_server_envelope_keys: impl IntoIterator<Item = ServerPayloadVerifiedEnvelopeKey>,
    ) -> Self {
        Self {
            changed,
            verified_server_envelope_keys: verified_server_envelope_keys.into_iter().collect(),
        }
    }
}

impl From<usize> for CryptoPayloadMigrationRewrite {
    fn from(changed: usize) -> Self {
        Self::new(changed)
    }
}

impl From<(usize, Vec<ServerPayloadVerifiedEnvelopeKey>)> for CryptoPayloadMigrationRewrite {
    fn from(
        (changed, verified_server_envelope_keys): (usize, Vec<ServerPayloadVerifiedEnvelopeKey>),
    ) -> Self {
        Self::with_server_envelope_keys(changed, verified_server_envelope_keys)
    }
}

pub(super) fn ensure_encrypted_payload_read_mode_is_supported(
    mode: EncryptedPayloadReadMode,
) -> CollectionResult<()> {
    match mode {
        EncryptedPayloadReadMode::Raw | EncryptedPayloadReadMode::Redacted => Ok(()),
        EncryptedPayloadReadMode::Decrypted => Err(CollectionError::bad_input(
            "encrypted payload read mode 'decrypted' is only supported in the API runtime layer with runtime crypto settings and privileged access; collection-internal reads must use 'raw' or 'redacted'",
        )),
    }
}

#[derive(Debug, Default)]
pub(super) struct PayloadRedactionPlan {
    encrypted_payload_paths: Vec<(JsonPath, PayloadRedactionKind)>,
    redact_vector_sidecar: bool,
}

#[derive(Debug)]
enum PayloadRedactionKind {
    AnyValue,
}

impl PayloadRedactionPlan {
    fn is_empty(&self) -> bool {
        self.encrypted_payload_paths.is_empty() && !self.redact_vector_sidecar
    }
}

impl Collection {
    pub(crate) async fn ensure_private_result_oram_payload_read_is_not_raw(
        &self,
        with_payload: Option<&WithPayloadInterface>,
    ) -> CollectionResult<()> {
        let Some(with_payload) = with_payload else {
            return Ok(());
        };
        let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        else {
            return Ok(());
        };
        let Some(payload_path) =
            private_result_oram_raw_payload_read_violation(with_payload, &encryption)?
        else {
            return Ok(());
        };

        Err(CollectionError::bad_input(format!(
            "cannot read private result ORAM payload field through ordinary collection payload reads; {}",
            private_result_oram_api_required_message(payload_path),
        )))
    }

    pub(crate) async fn ensure_vector_search_does_not_touch_encrypted_vector(
        &self,
        vector_name: &str,
        operation: &str,
    ) -> CollectionResult<()> {
        let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        else {
            return Ok(());
        };

        if let Some(err) = encrypted_vector_search_error(&encryption, vector_name, operation) {
            return Err(err);
        }

        Ok(())
    }

    pub(super) async fn encrypted_payload_redaction_plan_for_mode(
        &self,
        mode: EncryptedPayloadReadMode,
    ) -> CollectionResult<Option<PayloadRedactionPlan>> {
        if mode == EncryptedPayloadReadMode::Decrypted {
            return Ok(None);
        }
        let redact_encrypted_values = mode == EncryptedPayloadReadMode::Redacted;

        let collection_config = self.collection_config.read().await;
        let Some(encryption) = collection_config.params.effective_encryption() else {
            return Ok(None);
        };

        payload_redaction_plan_for_encryption(redact_encrypted_values, &encryption)
    }
}

fn payload_redaction_plan_for_encryption(
    redact_encrypted_values: bool,
    encryption: &CollectionEncryptionConfig,
) -> CollectionResult<Option<PayloadRedactionPlan>> {
    let mut plan = PayloadRedactionPlan::default();
    for rule in &encryption.rules {
        match (&rule.selector, rule.binding.as_deref()) {
            (EncryptionSelector::PayloadPaths { paths }, _)
            | (EncryptionSelector::MetadataKeys { keys: paths }, Some(METADATA_VALUE_BINDING)) => {
                if redact_encrypted_values {
                    for path in paths {
                        let json_path = if encryption_rule_uses_private_result_oram(rule) {
                            path.parse::<JsonPath>().map_err(|_| {
                                CollectionError::bad_input(
                                    "private result ORAM payload field path is invalid",
                                )
                            })?
                        } else {
                            path.parse::<JsonPath>().map_err(|_| {
                                CollectionError::bad_input(
                                    "encrypted payload field path is invalid",
                                )
                            })?
                        };
                        plan.encrypted_payload_paths
                            .push((json_path, PayloadRedactionKind::AnyValue));
                    }
                }
            }
            (
                EncryptionSelector::MetadataKeys { keys },
                Some(METADATA_EXACT_MATCH_TOKEN_BINDING),
            ) => {
                for key in keys {
                    let json_path = key.parse::<JsonPath>().map_err(|_| {
                        CollectionError::bad_input("metadata blind-index field path is invalid")
                    })?;
                    plan.encrypted_payload_paths
                        .push((json_path, PayloadRedactionKind::AnyValue));
                }
            }
            (EncryptionSelector::VectorNames { .. }, _) if redact_encrypted_values => {
                plan.redact_vector_sidecar = true;
            }
            (EncryptionSelector::MetadataKeys { .. }, _) => {}
            (EncryptionSelector::VectorNames { .. }, _) => {}
        }
    }

    Ok((!plan.is_empty()).then_some(plan))
}

pub(super) fn apply_encrypted_payload_read_mode_to_scored_points(
    points: &mut [ScoredPoint],
    _mode: EncryptedPayloadReadMode,
    redaction_plan: Option<&PayloadRedactionPlan>,
) {
    let Some(redaction_plan) = redaction_plan else {
        return;
    };

    for point in points {
        if let Some(payload) = &mut point.payload {
            redact_encrypted_payload_values(payload, redaction_plan);
        }
    }
}

fn apply_encrypted_payload_read_mode_to_records(
    records: &mut [RecordInternal],
    _mode: EncryptedPayloadReadMode,
    redaction_plan: Option<&PayloadRedactionPlan>,
) {
    let Some(redaction_plan) = redaction_plan else {
        return;
    };

    for record in records {
        if let Some(payload) = &mut record.payload {
            redact_encrypted_payload_values(payload, redaction_plan);
        }
    }
}

fn redact_encrypted_payload_values(payload: &mut Payload, redaction_plan: &PayloadRedactionPlan) {
    for (encrypted_path, kind) in &redaction_plan.encrypted_payload_paths {
        if let Some(value) = payload.0.get_mut(&encrypted_path.first_key) {
            redact_encrypted_json_value_at_path(value, &encrypted_path.rest, kind);
        }

        let literal_path_keys = payload
            .0
            .keys()
            .filter(|key| key.as_str() != encrypted_path.first_key)
            .filter(|key| {
                key.parse::<JsonPath>()
                    .is_ok_and(|payload_path| payload_path.compatible(encrypted_path))
            })
            .cloned()
            .collect::<Vec<_>>();

        for key in literal_path_keys {
            if let Some(value) = payload.0.get_mut(&key) {
                redact_encrypted_json_value_at_path(value, &[], kind);
            }
        }
    }

    if redaction_plan.redact_vector_sidecar
        && let Some(value) = payload.0.get_mut(ENCRYPTED_VECTOR_SIDECAR_FIELD)
    {
        *value = encrypted_payload_redaction_value();
    }
}

fn redact_encrypted_json_value_at_path(
    value: &mut serde_json::Value,
    path: &[JsonPathItem],
    kind: &PayloadRedactionKind,
) {
    let Some((head, tail)) = path.split_first() else {
        if matches!(kind, PayloadRedactionKind::AnyValue) {
            *value = encrypted_payload_redaction_value();
        }
        return;
    };

    match (head, value) {
        (JsonPathItem::Key(key), serde_json::Value::Object(object)) => {
            if let Some(value) = object.get_mut(key) {
                redact_encrypted_json_value_at_path(value, tail, kind);
            }
        }
        (JsonPathItem::Index(index), serde_json::Value::Array(values)) => {
            if let Some(value) = values.get_mut(*index) {
                redact_encrypted_json_value_at_path(value, tail, kind);
            }
        }
        (JsonPathItem::WildcardIndex, serde_json::Value::Array(values)) => {
            for value in values {
                redact_encrypted_json_value_at_path(value, tail, kind);
            }
        }
        _ => {}
    }
}

fn encrypted_payload_redaction_value() -> serde_json::Value {
    serde_json::json!({
        "$qdrant_sec_redacted": true,
        "reason": "encrypted_payload",
    })
}

fn encrypted_vector_sidecar_path(
    encryption: &crate::config::CollectionEncryptionConfig,
) -> CollectionResult<Option<JsonPath>> {
    if !encryption
        .rules
        .iter()
        .any(|rule| matches!(rule.selector, EncryptionSelector::VectorNames { .. }))
    {
        return Ok(None);
    }

    format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
        .parse::<JsonPath>()
        .map(Some)
        .map_err(|_| CollectionError::bad_input("encrypted vector sidecar field path is invalid"))
}

fn client_nonce_replay_cache_key(
    collection_crypto_id: &str,
    key: &ClientPayloadNonceReplayKey,
) -> String {
    key.cache_key_for_collection(collection_crypto_id)
}

fn validate_metadata_blind_index_json_value(
    value: &serde_json::Value,
    metadata_key: &str,
) -> CollectionResult<()> {
    let Some(token) = value.as_str() else {
        return Err(CollectionError::bad_input(
            "metadata blind-index field must contain a base64url-no-padding HMAC-SHA256 token string",
        ));
    };
    validate_metadata_blind_index_token(token, metadata_key)
}

fn validate_metadata_blind_index_token(token: &str, _metadata_key: &str) -> CollectionResult<()> {
    const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
    if token.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(CollectionError::bad_input(
            "metadata blind-index field token must decode to 32 bytes",
        ));
    }
    let token = BASE64URL_NOPAD.decode(token.as_bytes()).map_err(|_| {
        CollectionError::bad_input(
            "metadata blind-index field token must be base64url-no-padding encoded",
        )
    })?;
    if token.len() != 32 {
        return Err(CollectionError::bad_input(
            "metadata blind-index field token must decode to 32 bytes",
        ));
    }
    Ok(())
}

fn parse_metadata_blind_index_path(metadata_key: &str) -> CollectionResult<JsonPath> {
    metadata_key
        .parse::<JsonPath>()
        .map_err(|_| CollectionError::bad_input("metadata blind-index field path is invalid"))
}

fn validate_filter_metadata_blind_index_tokens(
    filter: &Filter,
    metadata_path: &JsonPath,
    metadata_key: &str,
) -> CollectionResult<()> {
    let mut token_count = 0;
    validate_filter_metadata_blind_index_tokens_with_polarity(
        filter,
        metadata_path,
        metadata_key,
        false,
        &mut token_count,
    )
}

fn validate_filter_metadata_blind_index_tokens_with_polarity(
    filter: &Filter,
    metadata_path: &JsonPath,
    metadata_key: &str,
    negative_context: bool,
    token_count: &mut usize,
) -> CollectionResult<()> {
    for condition in filter.must.iter().chain(filter.should.iter()).flatten() {
        validate_condition_metadata_blind_index_tokens(
            condition,
            metadata_path,
            metadata_key,
            negative_context,
            token_count,
        )?;
    }
    if let Some(min_should) = filter.min_should.as_ref() {
        for condition in &min_should.conditions {
            validate_condition_metadata_blind_index_tokens(
                condition,
                metadata_path,
                metadata_key,
                negative_context,
                token_count,
            )?;
        }
    }
    for condition in filter.must_not.iter().flatten() {
        validate_condition_metadata_blind_index_tokens(
            condition,
            metadata_path,
            metadata_key,
            true,
            token_count,
        )?;
    }
    Ok(())
}

fn validate_condition_metadata_blind_index_tokens(
    condition: &Condition,
    metadata_path: &JsonPath,
    metadata_key: &str,
    negative_context: bool,
    token_count: &mut usize,
) -> CollectionResult<()> {
    match condition {
        Condition::Field(field_condition) if field_condition.key.compatible(metadata_path) => {
            if negative_context {
                return Err(CollectionError::bad_input(
                    "metadata blind-index field filters must use positive exact-match token strings",
                ));
            }
            if field_condition.range.is_some()
                || field_condition.geo_bounding_box.is_some()
                || field_condition.geo_radius.is_some()
                || field_condition.geo_polygon.is_some()
                || field_condition.values_count.is_some()
                || field_condition.is_empty.is_some()
                || field_condition.is_null.is_some()
            {
                return Err(CollectionError::bad_input(
                    "metadata blind-index field filters must use exact-match token strings only",
                ));
            }
            let Some(match_condition) = field_condition.r#match.as_ref() else {
                return Err(CollectionError::bad_input(
                    "metadata blind-index field filters must use exact-match token strings",
                ));
            };
            match match_condition {
                Match::Value(value) => match &value.value {
                    ValueVariants::String(token) => {
                        validate_metadata_blind_index_filter_token(token, metadata_key, token_count)
                    }
                    ValueVariants::Integer(_) | ValueVariants::Bool(_) => {
                        Err(CollectionError::bad_input(
                            "metadata blind-index field filters must use string tokens",
                        ))
                    }
                },
                Match::Any(any) => match &any.any {
                    AnyVariants::Strings(tokens) => {
                        if tokens.len() > METADATA_BLIND_INDEX_MATCH_ANY_MAX_TOKENS {
                            return Err(CollectionError::bad_input(format!(
                                "metadata blind-index field filters must include at most {METADATA_BLIND_INDEX_MATCH_ANY_MAX_TOKENS} token strings per match.any",
                            )));
                        }
                        if token_count.saturating_add(tokens.len())
                            > METADATA_BLIND_INDEX_FILTER_MAX_TOKENS
                        {
                            return Err(CollectionError::bad_input(format!(
                                "metadata blind-index field filters must include at most {METADATA_BLIND_INDEX_FILTER_MAX_TOKENS} token strings",
                            )));
                        }
                        for token in tokens {
                            validate_metadata_blind_index_filter_token(
                                token,
                                metadata_key,
                                token_count,
                            )?;
                        }
                        Ok(())
                    }
                    AnyVariants::Integers(_) => Err(CollectionError::bad_input(
                        "metadata blind-index field filters must use string tokens",
                    )),
                },
                Match::Except(_) => Err(CollectionError::bad_input(
                    "metadata blind-index field filters must use positive exact-match token strings",
                )),
                Match::Text(_) | Match::TextAny(_) | Match::Phrase(_) => {
                    Err(CollectionError::bad_input(
                        "metadata blind-index field filters must use exact-match token strings",
                    ))
                }
            }
        }
        Condition::Field(_)
        | Condition::HasId(_)
        | Condition::HasVector(_)
        | Condition::CustomIdChecker(_) => Ok(()),
        Condition::IsEmpty(is_empty) if is_empty.is_empty.key.compatible(metadata_path) => {
            Err(CollectionError::bad_input(
                "metadata blind-index field filters must use exact-match token strings",
            ))
        }
        Condition::IsNull(is_null) if is_null.is_null.key.compatible(metadata_path) => {
            Err(CollectionError::bad_input(
                "metadata blind-index field filters must use exact-match token strings",
            ))
        }
        Condition::IsEmpty(_) | Condition::IsNull(_) => Ok(()),
        Condition::Nested(nested) => {
            if nested.raw_key().compatible(metadata_path) {
                return Err(CollectionError::bad_input(
                    "metadata blind-index field filters must use exact-match token strings",
                ));
            }
            validate_filter_metadata_blind_index_tokens_with_polarity(
                nested.filter(),
                metadata_path,
                metadata_key,
                negative_context,
                token_count,
            )
        }
        Condition::Filter(filter) => validate_filter_metadata_blind_index_tokens_with_polarity(
            filter,
            metadata_path,
            metadata_key,
            negative_context,
            token_count,
        ),
    }
}

fn validate_metadata_blind_index_filter_token(
    token: &str,
    metadata_key: &str,
    token_count: &mut usize,
) -> CollectionResult<()> {
    if *token_count >= METADATA_BLIND_INDEX_FILTER_MAX_TOKENS {
        return Err(CollectionError::bad_input(format!(
            "metadata blind-index field filters must include at most {METADATA_BLIND_INDEX_FILTER_MAX_TOKENS} token strings",
        )));
    }
    *token_count += 1;
    validate_metadata_blind_index_token(token, metadata_key)
}

fn filter_touches_encrypted_payload<'a>(
    filter: &'a Filter,
    encrypted_path: &JsonPath,
) -> Option<&'a JsonPath> {
    filter
        .iter_conditions()
        .find_map(|condition| condition_touches_encrypted_payload(condition, encrypted_path))
}

fn condition_touches_encrypted_payload<'a>(
    condition: &'a Condition,
    encrypted_path: &JsonPath,
) -> Option<&'a JsonPath> {
    let touches = |key: &'a JsonPath| key.compatible(encrypted_path).then_some(key);

    match condition {
        Condition::Field(field_condition) => touches(&field_condition.key),
        Condition::IsEmpty(is_empty) => touches(&is_empty.is_empty.key),
        Condition::IsNull(is_null) => touches(&is_null.is_null.key),
        Condition::Nested(nested) => touches(nested.raw_key())
            .or_else(|| filter_touches_encrypted_payload(nested.filter(), encrypted_path)),
        Condition::Filter(filter) => filter_touches_encrypted_payload(filter, encrypted_path),
        Condition::HasId(_) | Condition::HasVector(_) | Condition::CustomIdChecker(_) => None,
    }
}

fn filter_touches_encrypted_vector<'a>(
    filter: &'a Filter,
    encrypted_name: &str,
) -> Option<&'a str> {
    filter
        .iter_conditions()
        .find_map(|condition| condition_touches_encrypted_vector(condition, encrypted_name))
}

fn condition_touches_encrypted_vector<'a>(
    condition: &'a Condition,
    encrypted_name: &str,
) -> Option<&'a str> {
    match condition {
        Condition::HasVector(has_vector) if has_vector.has_vector == encrypted_name => {
            Some(has_vector.has_vector.as_str())
        }
        Condition::Nested(nested) => {
            filter_touches_encrypted_vector(nested.filter(), encrypted_name)
        }
        Condition::Filter(filter) => filter_touches_encrypted_vector(filter, encrypted_name),
        Condition::Field(_)
        | Condition::IsEmpty(_)
        | Condition::IsNull(_)
        | Condition::HasId(_)
        | Condition::HasVector(_)
        | Condition::CustomIdChecker(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use segment::types::{
        FieldCondition, IsEmptyCondition, Match, PayloadEncryptedReadPolicy,
        PayloadSelectorExclude, PayloadSelectorInclude, ValueVariants, ValuesCount,
    };

    use super::*;
    use crate::config::{CollectionEncryptionConfig, EncryptionRuleRef};
    use crate::operations::point_ops::PointStructPersisted;

    fn blind_index_token(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn blind_index_filter(key: &str, r#match: Match) -> Filter {
        Filter::new_must(Condition::Field(FieldCondition::new_match(
            key.parse().unwrap(),
            r#match,
        )))
    }

    fn params_with_encrypted_vector_name(name: &str) -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:vector".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 3,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "vector_conf".to_string(),
                selector: EncryptionSelector::VectorNames {
                    names: vec![name.to_string()],
                },
                instance: "docs_vector_v1".to_string(),
                binding: Some("vector-envelope/v1".to_string()),
            }],
        }
    }

    fn private_hnsw_vector_rule(name: &str) -> EncryptionRuleRef {
        EncryptionRuleRef {
            id: "private_hnsw_vector".to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec![name.to_string()],
            },
            instance: "docs_private_hnsw_v1".to_string(),
            binding: Some(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING.to_string()),
        }
    }

    fn private_hnsw_encryption(name: &str) -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:vector-private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![private_hnsw_vector_rule(name)],
        }
    }

    fn private_result_oram_payload_rule(path: &str) -> EncryptionRuleRef {
        EncryptionRuleRef {
            id: "private_result_payload".to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec![path.to_string()],
            },
            instance: "docs_private_result_oram_v1".to_string(),
            binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
        }
    }

    fn private_result_oram_encryption(path: &str) -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:result-private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![private_result_oram_payload_rule(path)],
        }
    }

    #[test]
    fn private_hnsw_plaintext_vector_write_error_uses_session_api() {
        let rule = private_hnsw_vector_rule("embedding");

        let err = plaintext_vector_write_error_for_encryption_rule("embedding", &rule, false);
        let message = format!("{err}");
        assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
        assert!(message.contains("/private-hnsw/{vector}/session"));
        assert!(!message.contains("embedding"));
        assert!(!message.contains("CKKS vector encryption"));

        let peer_err = plaintext_vector_write_error_for_encryption_rule("embedding", &rule, true);
        let peer_message = format!("{peer_err}");
        assert!(peer_message.contains("peer update"));
        assert!(peer_message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
        assert!(peer_message.contains("/private-hnsw/{vector}/session"));
        assert!(!peer_message.contains("embedding"));
        assert!(!peer_message.contains("CKKS vector encryption"));
    }

    #[test]
    fn private_hnsw_vector_return_error_uses_session_api() {
        let encryption = private_hnsw_encryption("embedding");

        for with_vector in [
            WithVector::Bool(true),
            WithVector::Selector(vec!["plain".to_string(), "embedding".to_string()]),
        ] {
            let err = encrypted_vector_return_error(&encryption, &with_vector).unwrap();
            let message = format!("{err}");
            assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
            assert!(message.contains("/private-hnsw/{vector}/session"));
            assert!(!message.contains("embedding"));
            assert!(message.contains("Point-level vector reads"));
            assert!(!message.contains("CKKS vector ciphertext read path"));
        }
    }

    #[test]
    fn ckks_vector_return_error_keeps_ciphertext_read_path_message_without_vector_name() {
        let vector_name = "ckks_return_secret_embedding";
        let encryption = params_with_encrypted_vector_name(vector_name);

        let err = encrypted_vector_return_error(
            &encryption,
            &WithVector::Selector(vec![vector_name.to_string()]),
        )
        .unwrap();
        let message = format!("{err}");
        assert!(message.contains("cannot return encrypted vector"));
        assert!(message.contains("CKKS vector ciphertext read path"));
        assert!(!message.contains(vector_name), "{message}");
        assert!(!message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
    }

    #[test]
    fn private_hnsw_vector_search_error_uses_session_api() {
        let encryption = private_hnsw_encryption("embedding");

        let err = encrypted_vector_search_error(&encryption, "embedding", "search").unwrap();
        let message = format!("{err}");
        assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
        assert!(message.contains("/private-hnsw/{vector}/session"));
        assert!(!message.contains("embedding"), "{message}");
        assert!(!message.contains("runtime CKKS sidecar"), "{message}");

        assert!(encrypted_vector_search_error(&encryption, "public", "search").is_none());
    }

    #[test]
    fn private_hnsw_filter_error_uses_session_api() {
        let rule = private_hnsw_vector_rule("embedding");

        let err = encrypted_vector_filter_error(&rule, "embedding");
        let message = format!("{err}");
        assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
        assert!(message.contains("/private-hnsw/{vector}/session"));
        assert!(!message.contains("embedding"));
        assert!(!message.contains("CKKS sidecar"));
    }

    const PRIVATE_ORAM_POINT_ALIAS_SENTINELS: &[&str] = &[
        "clientStateBackups",
        "encryptedClientStateBackups",
        "clientStateCiphertext",
        "clientStateCiphertextHash",
        "clientStateCiphertextHashes",
        "client_state_ciphertext",
        "client_state_ciphertext_hash",
        "client_state_ciphertext_hashes",
        "encrypted_client_state",
        "encrypted_client_state_backup",
        "encrypted_client_state_snapshot",
        "encryptedClientStateCiphertext",
        "encrypted_client_state_ciphertext",
        "encryptedClientStateCiphertextHash",
        "encryptedClientStateCiphertextHashes",
        "encrypted_client_state_ciphertext_hash",
        "encrypted_client_state_ciphertext_hashes",
        "oramPositionMapBackups",
        "oram_position_map_backups",
        "positionMapBackups",
        "position_map_backups",
        "stashBackups",
        "stateCiphertext",
        "stateCiphertextHash",
        "stateCiphertextHashes",
        "state_ciphertext",
        "state_ciphertext_hash",
        "state_ciphertext_hashes",
        "tokenPositionMapBackups",
        "token_position_map_backups",
    ];

    #[test]
    fn private_hnsw_point_errors_redact_backup_alias_vector_name() {
        for &vector_name in PRIVATE_ORAM_POINT_ALIAS_SENTINELS {
            let rule = private_hnsw_vector_rule(vector_name);
            let encryption = private_hnsw_encryption(vector_name);

            let messages = [
                plaintext_vector_write_error_for_encryption_rule(vector_name, &rule, false)
                    .to_string(),
                encrypted_vector_return_error(
                    &encryption,
                    &WithVector::Selector(vec![vector_name.to_string()]),
                )
                .unwrap()
                .to_string(),
                encrypted_vector_search_error(&encryption, vector_name, "search")
                    .unwrap()
                    .to_string(),
                encrypted_vector_filter_error(&rule, vector_name).to_string(),
            ];

            for message in messages {
                assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
                assert!(message.contains("/private-hnsw/{vector}/session"));
                assert!(!message.contains(vector_name), "{message}");
                for &sentinel in PRIVATE_ORAM_POINT_ALIAS_SENTINELS {
                    assert!(!message.contains(sentinel), "{message}");
                }
            }
        }
    }

    #[test]
    fn ckks_point_errors_redact_vector_names() {
        let vector_name = "ckks_point_ops_secret_embedding";
        let rule = EncryptionRuleRef {
            id: "vector_conf".to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec![vector_name.to_string()],
            },
            instance: "docs_vector_v1".to_string(),
            binding: Some("vector-envelope/v1".to_string()),
        };
        let encryption = CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:vector-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![rule.clone()],
        };

        let messages = [
            plaintext_vector_write_error_for_encryption_rule(vector_name, &rule, false).to_string(),
            plaintext_vector_write_error_for_encryption_rule(vector_name, &rule, true).to_string(),
            encrypted_vector_return_error(
                &encryption,
                &WithVector::Selector(vec![vector_name.to_string()]),
            )
            .unwrap()
            .to_string(),
            encrypted_vector_search_error(&encryption, vector_name, "search")
                .unwrap()
                .to_string(),
            encrypted_vector_filter_error(&rule, vector_name).to_string(),
        ];

        for message in messages {
            assert!(!message.contains(vector_name), "{message}");
            assert!(!message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
        }
    }

    #[test]
    fn peer_client_payload_replay_requires_runtime_verifier_without_value_leaks() {
        let mut marker = serde_json::Map::new();
        marker.insert(
            qdrant_sec::CLIENT_ENCRYPTED_PAYLOAD_MARKER.to_string(),
            serde_json::json!({
                "version": 1,
                "kind": PAYLOAD_TEXT_ENVELOPE_KIND,
                "algorithm": "AES-256-GCM",
                "key_id": "tenant-a:client-rk",
                "rk_id": "tenant-a:client-rk",
                "rk_epoch": 3,
                "kdf_domain": "qdrant-sec/client-payload-text/v1",
                "aad": {
                    "collection_id": "collection-crypto-id",
                    "point_id": "1",
                    "field_path": "document.body",
                    "schema_version": 1
                },
                "nonce": BASE64URL_NOPAD.encode(&[1_u8; 12]),
                "ciphertext": BASE64URL_NOPAD.encode(b"client-payload-ciphertext-sentinel"),
                "signature": {
                    "alg": "ed25519",
                    "key_id": "tenant-a:client-signing-v1",
                    "sig": BASE64URL_NOPAD.encode(&[3_u8; 64])
                }
            }),
        );
        let value = serde_json::Value::Object(marker);

        assert!(peer_client_encrypted_payload_replay_violation(&value, false).is_none());
        let err = peer_client_encrypted_payload_replay_violation(&value, true)
            .expect("peer client payload replay must fail closed");
        let message = err.to_string();
        assert!(
            message.contains("runtime verifier manifest and cluster-wide nonce ledger"),
            "{message}",
        );
        for sentinel in [
            qdrant_sec::CLIENT_ENCRYPTED_PAYLOAD_MARKER,
            "tenant-a:client-rk",
            "tenant-a:client-signing-v1",
            "client-payload-ciphertext-sentinel",
            &BASE64URL_NOPAD.encode(&[3_u8; 64]),
        ] {
            assert!(!message.contains(sentinel), "{message}");
        }

        assert!(
            peer_client_encrypted_payload_replay_violation(&serde_json::json!("public"), true)
                .is_none()
        );
    }

    #[test]
    fn private_result_oram_filter_overlap_detects_parent_child_and_nested_paths() {
        let protected_path = "document.body".parse::<JsonPath>().unwrap();
        let private_filters = [
            (
                Filter::new_must(Condition::Field(FieldCondition::new_match(
                    "document".parse().unwrap(),
                    "secret".to_string().into(),
                ))),
                "document",
            ),
            (
                Filter::new_must(Condition::Field(FieldCondition::new_match(
                    "document.body".parse().unwrap(),
                    "secret".to_string().into(),
                ))),
                "document.body",
            ),
            (
                Filter::new_must(Condition::Field(FieldCondition::new_match(
                    "document.body.lang".parse().unwrap(),
                    "secret".to_string().into(),
                ))),
                "document.body.lang",
            ),
            (
                Filter::new_must(Condition::IsEmpty(IsEmptyCondition::from(
                    "document.body.lang".parse::<JsonPath>().unwrap(),
                ))),
                "document.body.lang",
            ),
            (
                Filter::new_must(Condition::new_nested(
                    "document".parse().unwrap(),
                    Filter::new_must(Condition::Field(FieldCondition::new_match(
                        "title".parse().unwrap(),
                        "public".to_string().into(),
                    ))),
                )),
                "document",
            ),
        ];

        for (filter, expected_path) in private_filters {
            let touched = filter_touches_encrypted_payload(&filter, &protected_path)
                .expect("private result ORAM filter path should fail closed");
            assert_eq!(touched.to_string(), expected_path);
        }

        let public_filter = Filter::new_must(Condition::Field(FieldCondition::new_match(
            "document.title".parse().unwrap(),
            "public".to_string().into(),
        )));
        assert!(filter_touches_encrypted_payload(&public_filter, &protected_path).is_none());
    }

    #[test]
    fn private_hnsw_read_only_point_operations_require_session_api() {
        let encryption = private_hnsw_encryption("embedding");
        let operations = [
            (
                CollectionUpdateOperations::PointOperation(PointOperations::DeletePoints {
                    ids: vec![1.into()],
                }),
                "delete points",
            ),
            (
                CollectionUpdateOperations::PointOperation(PointOperations::DeletePointsByFilter(
                    Filter::new(),
                )),
                "delete points by filter",
            ),
            (
                CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(
                    shard::operations::point_ops::PointSyncOperation {
                        from_id: None,
                        to_id: None,
                        points: vec![],
                    },
                )),
                "sync points",
            ),
        ];

        for (operation, expected_kind) in operations {
            let err =
                reject_private_hnsw_oram_read_only_point_operation(&operation, &encryption, false)
                    .unwrap_err();
            let message = format!("{err}");
            assert!(
                message.contains("cannot modify read-only private HNSW ORAM vector"),
                "{message}"
            );
            assert!(!message.contains(expected_kind), "{message}");
            assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
            assert!(message.contains("/private-hnsw/{vector}/session"));
            assert!(!message.contains("embedding"), "{message}");

            let peer_err =
                reject_private_hnsw_oram_read_only_point_operation(&operation, &encryption, true)
                    .unwrap_err();
            let peer_message = format!("{peer_err}");
            assert!(peer_message.contains("peer update"), "{peer_message}");
            assert!(
                peer_message.contains("cannot modify read-only private HNSW ORAM vector"),
                "{peer_message}"
            );
            assert!(!peer_message.contains(expected_kind), "{peer_message}");
            assert!(peer_message.contains("/private-hnsw/{vector}/session"));
            assert!(!peer_message.contains("embedding"), "{peer_message}");
        }
    }

    #[test]
    fn private_result_oram_payload_writes_require_session_api() {
        let encryption = private_result_oram_encryption("document.body");
        let payload = Payload(
            serde_json::json!({
                "document": {
                    "body": "plaintext result payload",
                    "title": "public",
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let public_payload = Payload(
            serde_json::json!({
                "summary": "public",
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let public_document_payload = Payload(
            serde_json::json!({
                "document": {
                    "title": "public",
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let private_point_id = 987_654_321_u64;
        let public_point_id = 876_543_210_u64;
        let point = PointStructPersisted {
            id: private_point_id.into(),
            vector: VectorStructPersisted::Single(vec![0.0]),
            payload: Some(payload.clone()),
        };
        let public_point = PointStructPersisted {
            id: public_point_id.into(),
            vector: VectorStructPersisted::Single(vec![0.0]),
            payload: Some(public_payload.clone()),
        };
        reject_private_result_oram_payload_point_operation(
            &CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: public_payload.clone(),
                points: Some(vec![private_point_id.into()]),
                filter: None,
                key: None,
            })),
            &encryption,
            false,
        )
        .expect("public set payload merge should not touch private result ORAM payload path");
        let operations = vec![
            (
                CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                    PointInsertOperationsInternal::PointsList(vec![point.clone()]),
                )),
                "upsert points",
            ),
            (
                CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                    PointInsertOperationsInternal::PointsList(vec![public_point.clone()]),
                )),
                "upsert points",
            ),
            (
                CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(
                    shard::operations::point_ops::PointSyncOperation {
                        from_id: None,
                        to_id: None,
                        points: vec![point],
                    },
                )),
                "sync points",
            ),
            (
                CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(
                    shard::operations::point_ops::PointSyncOperation {
                        from_id: None,
                        to_id: None,
                        points: vec![public_point],
                    },
                )),
                "sync points",
            ),
            (
                CollectionUpdateOperations::PointOperation(PointOperations::DeletePoints {
                    ids: vec![private_point_id.into()],
                }),
                "delete points",
            ),
            (
                CollectionUpdateOperations::PointOperation(PointOperations::DeletePointsByFilter(
                    Filter::new(),
                )),
                "delete points by filter",
            ),
            (
                CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(
                    SetPayloadOp {
                        payload: payload.clone(),
                        points: Some(vec![private_point_id.into()]),
                        filter: None,
                        key: None,
                    },
                )),
                "set payload",
            ),
            (
                CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(
                    SetPayloadOp {
                        payload: public_document_payload,
                        points: Some(vec![private_point_id.into()]),
                        filter: None,
                        key: None,
                    },
                )),
                "set payload",
            ),
            (
                CollectionUpdateOperations::PayloadOperation(PayloadOps::OverwritePayload(
                    SetPayloadOp {
                        payload: payload.clone(),
                        points: Some(vec![private_point_id.into()]),
                        filter: None,
                        key: None,
                    },
                )),
                "overwrite payload",
            ),
            (
                CollectionUpdateOperations::PayloadOperation(PayloadOps::OverwritePayload(
                    SetPayloadOp {
                        payload: public_payload,
                        points: Some(vec![private_point_id.into()]),
                        filter: None,
                        key: None,
                    },
                )),
                "overwrite payload",
            ),
            (
                CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(
                    crate::operations::payload_ops::DeletePayloadOp {
                        keys: vec!["document.body".parse().unwrap()],
                        points: Some(vec![private_point_id.into()]),
                        filter: None,
                    },
                )),
                "delete payload",
            ),
            (
                CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayload {
                    points: vec![private_point_id.into()],
                }),
                "clear payload",
            ),
            (
                CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(
                    Filter::new(),
                )),
                "clear payload by filter",
            ),
        ];

        for (operation, expected_kind) in operations {
            let err =
                reject_private_result_oram_payload_point_operation(&operation, &encryption, false)
                    .unwrap_err();
            let message = format!("{err}");
            assert!(
                message.contains("cannot modify private result ORAM payload field"),
                "{message}"
            );
            assert!(!message.contains(expected_kind), "{message}");
            assert!(
                message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                "{message}"
            );
            assert!(
                message.contains("/private-result-oram/session"),
                "{message}"
            );
            assert!(!message.contains("runtime payload encryption"), "{message}");
            assert!(!message.contains("document.body"), "{message}");
            assert!(!message.contains("plaintext result payload"), "{message}");
            assert!(!message.contains("987654321"), "{message}");
            assert!(!message.contains("876543210"), "{message}");

            let peer_err =
                reject_private_result_oram_payload_point_operation(&operation, &encryption, true)
                    .unwrap_err();
            let peer_message = format!("{peer_err}");
            assert!(peer_message.contains("peer update"), "{peer_message}");
            assert!(
                peer_message.contains("cannot modify private result ORAM payload field"),
                "{peer_message}"
            );
            assert!(!peer_message.contains(expected_kind), "{peer_message}");
            assert!(
                peer_message.contains("/private-result-oram/session"),
                "{peer_message}"
            );
            assert!(!peer_message.contains("document.body"), "{peer_message}");
            assert!(
                !peer_message.contains("plaintext result payload"),
                "{peer_message}"
            );
            assert!(!peer_message.contains("987654321"), "{peer_message}");
            assert!(!peer_message.contains("876543210"), "{peer_message}");
        }
    }

    #[test]
    fn private_result_oram_payload_raw_reads_require_session_api() {
        let encryption = private_result_oram_encryption("document.body");
        let protected_path = "document.body".parse::<JsonPath>().unwrap();

        let raw_read_cases = [
            WithPayloadInterface::Bool(true),
            WithPayloadInterface::Fields(vec!["document".parse().unwrap()]),
            WithPayloadInterface::Fields(vec!["document.body".parse().unwrap()]),
            WithPayloadInterface::Fields(vec!["document.body.lang".parse().unwrap()]),
            WithPayloadInterface::Selector(PayloadSelector::Include(PayloadSelectorInclude::new(
                vec!["document".parse().unwrap()],
            ))),
            WithPayloadInterface::Selector(PayloadSelector::Include(PayloadSelectorInclude::new(
                vec!["document.body.lang".parse().unwrap()],
            ))),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(PayloadSelectorExclude::new(
                vec!["document.title".parse().unwrap()],
            ))),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(PayloadSelectorExclude::new(
                vec!["document.body.lang".parse().unwrap()],
            ))),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(PayloadSelectorExclude::new(
                Vec::new(),
            ))),
            WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                encrypted_payload: EncryptedPayloadReadMode::Raw,
            }),
            WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                encrypted_payload: EncryptedPayloadReadMode::Decrypted,
            }),
        ];

        for with_payload in raw_read_cases {
            let violation =
                private_result_oram_raw_payload_read_violation(&with_payload, &encryption).unwrap();
            assert_eq!(violation, Some("document.body"));
            assert!(private_result_oram_with_payload_touches_path(
                &with_payload,
                &protected_path
            ));
            let message = format!(
                "cannot read private result ORAM payload field through ordinary collection payload reads; {}",
                private_result_oram_api_required_message(violation.unwrap()),
            );
            assert!(
                message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
                "{message}"
            );
            assert!(
                message.contains("/private-result-oram/session"),
                "{message}"
            );
            assert!(!message.contains("document"), "{message}");
            assert!(!message.contains("document.body"), "{message}");
            assert!(!message.contains("document.body.lang"), "{message}");
            assert!(!message.contains("document.title"), "{message}");
        }

        let allowed_cases = [
            WithPayloadInterface::Bool(false),
            WithPayloadInterface::Fields(vec!["document.title".parse().unwrap()]),
            WithPayloadInterface::Selector(PayloadSelector::Include(PayloadSelectorInclude::new(
                vec!["document.title".parse().unwrap()],
            ))),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(PayloadSelectorExclude::new(
                vec!["document".parse().unwrap()],
            ))),
            WithPayloadInterface::Selector(PayloadSelector::Exclude(PayloadSelectorExclude::new(
                vec!["document.body".parse().unwrap()],
            ))),
            WithPayloadInterface::Encrypted(PayloadEncryptedReadPolicy {
                encrypted_payload: EncryptedPayloadReadMode::Redacted,
            }),
        ];

        for with_payload in allowed_cases {
            let violation =
                private_result_oram_raw_payload_read_violation(&with_payload, &encryption).unwrap();
            assert_eq!(violation, None);
        }
    }

    #[test]
    fn private_result_oram_point_errors_redact_backup_alias_payload_path() {
        for &payload_path in PRIVATE_ORAM_POINT_ALIAS_SENTINELS {
            let encryption = private_result_oram_encryption(payload_path);
            let delete_private_payload = CollectionUpdateOperations::PayloadOperation(
                PayloadOps::DeletePayload(crate::operations::payload_ops::DeletePayloadOp {
                    keys: vec![payload_path.parse().unwrap()],
                    points: Some(vec![1.into()]),
                    filter: None,
                }),
            );

            let write_message = reject_private_result_oram_payload_point_operation(
                &delete_private_payload,
                &encryption,
                false,
            )
            .unwrap_err()
            .to_string();
            assert!(write_message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
            assert!(write_message.contains("/private-result-oram/session"));
            assert!(!write_message.contains(payload_path), "{write_message}");
            for &sentinel in PRIVATE_ORAM_POINT_ALIAS_SENTINELS {
                assert!(!write_message.contains(sentinel), "{write_message}");
            }

            let violation = private_result_oram_raw_payload_read_violation(
                &WithPayloadInterface::Fields(vec![payload_path.parse().unwrap()]),
                &encryption,
            )
            .unwrap();
            assert_eq!(violation, Some(payload_path));

            let read_message = format!(
                "cannot read private result ORAM payload field through ordinary collection payload reads; {}",
                private_result_oram_api_required_message(violation.unwrap()),
            );
            assert!(read_message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
            assert!(read_message.contains("/private-result-oram/session"));
            assert!(!read_message.contains(payload_path), "{read_message}");
            for &sentinel in PRIVATE_ORAM_POINT_ALIAS_SENTINELS {
                assert!(!read_message.contains(sentinel), "{read_message}");
            }
        }
    }

    #[test]
    fn private_result_oram_invalid_payload_path_errors_are_sanitized() {
        let secret_path = "document.body[private-result-secret";
        let encryption = private_result_oram_encryption(secret_path);

        let err = private_result_oram_raw_payload_read_violation(
            &WithPayloadInterface::Bool(true),
            &encryption,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-secret"), "{err}");

        let update = CollectionUpdateOperations::PointOperation(PointOperations::DeletePoints {
            ids: vec![1.into()],
        });
        let err = private_result_oram_payload_operation_violation(&update, &encryption)
            .unwrap_err()
            .to_string();
        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-secret"), "{err}");

        let err = payload_redaction_plan_for_encryption(true, &encryption)
            .unwrap_err()
            .to_string();
        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-secret"), "{err}");
        assert!(!err.contains("JsonPath"), "{err}");
    }

    #[test]
    fn private_result_oram_selector_guard_invalid_path_errors_are_sanitized() {
        let secret_path = "document.body[private-result-selector-secret";
        let rule = private_result_oram_payload_rule(secret_path);

        let err = parse_payload_selector_guard_path(&rule, secret_path)
            .unwrap_err()
            .to_string();

        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-selector-secret"), "{err}");
        assert!(!err.contains("JsonPath"), "{err}");
    }

    #[test]
    fn crypto_migration_state_guard_rejects_peer_writes_outside_active() {
        ensure_crypto_migration_state_allows_regular_operation(
            CryptoMigrationState::Active,
            "peer writes",
        )
        .unwrap();

        for state in [
            CryptoMigrationState::Disabled,
            CryptoMigrationState::Encrypting,
            CryptoMigrationState::Rotating,
            CryptoMigrationState::Decrypting,
        ] {
            let err = ensure_crypto_migration_state_allows_regular_operation(state, "peer writes")
                .unwrap_err();
            assert!(
                format!("{err}").contains("regular peer writes require migration_state=active")
            );
        }
    }

    #[test]
    fn encrypted_vector_sidecar_path_matches_quoted_sidecar_children() {
        let encryption = params_with_encrypted_vector_name("embedding");
        let sidecar_path = encrypted_vector_sidecar_path(&encryption)
            .unwrap()
            .expect("vector rules must expose the sidecar path");

        for path in [
            format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\""),
            format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\".embedding"),
        ] {
            let path = path.parse::<JsonPath>().unwrap();
            assert!(path.compatible(&sidecar_path));
        }

        let unrelated = "group".parse::<JsonPath>().unwrap();
        assert!(!unrelated.compatible(&sidecar_path));
    }

    #[test]
    fn metadata_blind_index_filter_allows_exact_match_token_strings() {
        let metadata_path = "body__blind_eq".parse::<JsonPath>().unwrap();
        let metadata_key = "body__blind_eq";
        let first_token = blind_index_token(1);
        let second_token = blind_index_token(2);

        validate_filter_metadata_blind_index_tokens(
            &blind_index_filter(metadata_key, first_token.clone().into()),
            &metadata_path,
            metadata_key,
        )
        .unwrap();

        validate_filter_metadata_blind_index_tokens(
            &blind_index_filter(
                metadata_key,
                Match::from(vec![first_token, second_token.clone()]),
            ),
            &metadata_path,
            metadata_key,
        )
        .unwrap();
    }

    #[test]
    fn metadata_blind_index_filter_rejects_non_exact_match_conditions() {
        let metadata_path = "body__blind_eq".parse::<JsonPath>().unwrap();
        let metadata_key = "body__blind_eq";
        let token = blind_index_token(3);

        for filter in [
            blind_index_filter(metadata_key, Match::new_text("plaintext")),
            blind_index_filter(metadata_key, Match::new_value(ValueVariants::Integer(42))),
            blind_index_filter(
                metadata_key,
                serde_json::from_value(serde_json::json!({ "except": [token.clone()] })).unwrap(),
            ),
            Filter::new_must_not(Condition::Field(FieldCondition::new_match(
                metadata_key.parse().unwrap(),
                token.clone().into(),
            ))),
            Filter::new_must(Condition::Filter(Filter::new_must_not(Condition::Field(
                FieldCondition::new_match(metadata_key.parse().unwrap(), token.clone().into()),
            )))),
            Filter::new_must(Condition::IsEmpty(IsEmptyCondition::from(
                metadata_key.parse::<JsonPath>().unwrap(),
            ))),
        ] {
            let err =
                validate_filter_metadata_blind_index_tokens(&filter, &metadata_path, metadata_key)
                    .unwrap_err();
            assert!(format!("{err}").contains("metadata blind-index field"));
        }
    }

    #[test]
    fn metadata_blind_index_filter_rejects_mixed_field_predicates() {
        let metadata_path = "body__blind_eq".parse::<JsonPath>().unwrap();
        let metadata_key = "body__blind_eq";
        let token = blind_index_token(4);
        let mut field_condition =
            FieldCondition::new_match(metadata_key.parse().unwrap(), token.into());
        field_condition.values_count = Some(ValuesCount {
            lt: None,
            gt: None,
            gte: Some(1),
            lte: None,
        });

        let err = validate_filter_metadata_blind_index_tokens(
            &Filter::new_must(Condition::Field(field_condition)),
            &metadata_path,
            metadata_key,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("exact-match token strings only"));
    }

    #[test]
    fn metadata_blind_index_filter_rejects_malformed_tokens() {
        let metadata_path = "body__blind_eq".parse::<JsonPath>().unwrap();
        let metadata_key = "body__blind_eq";

        for token in [
            "not base64!".to_string(),
            BASE64URL_NOPAD.encode(&[7_u8; 31]),
            BASE64URL_NOPAD.encode(&[7_u8; 33]),
            "A".repeat(1024),
        ] {
            let filter = blind_index_filter(metadata_key, token.to_string().into());
            let err =
                validate_filter_metadata_blind_index_tokens(&filter, &metadata_path, metadata_key)
                    .unwrap_err();
            assert!(format!("{err}").contains("metadata blind-index field"));
        }
    }

    #[test]
    fn metadata_blind_index_filter_rejects_oversized_token_lists() {
        let metadata_path = "body__blind_eq".parse::<JsonPath>().unwrap();
        let metadata_key = "body__blind_eq";
        let too_many_any_tokens = (0..=METADATA_BLIND_INDEX_MATCH_ANY_MAX_TOKENS)
            .map(|idx| blind_index_token(idx as u8))
            .collect::<Vec<_>>();

        let err = validate_filter_metadata_blind_index_tokens(
            &blind_index_filter(metadata_key, Match::from(too_many_any_tokens)),
            &metadata_path,
            metadata_key,
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains(&format!(
                "at most {METADATA_BLIND_INDEX_MATCH_ANY_MAX_TOKENS}"
            )),
            "{err}"
        );

        let too_many_total_tokens = (0..=METADATA_BLIND_INDEX_FILTER_MAX_TOKENS)
            .map(|idx| {
                Condition::Field(FieldCondition::new_match(
                    metadata_key.parse().unwrap(),
                    blind_index_token(idx as u8).into(),
                ))
            })
            .collect::<Vec<_>>();
        let err = validate_filter_metadata_blind_index_tokens(
            &Filter {
                must: Some(too_many_total_tokens),
                ..Filter::new()
            },
            &metadata_path,
            metadata_key,
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains(&format!("at most {METADATA_BLIND_INDEX_FILTER_MAX_TOKENS}")),
            "{err}"
        );
    }

    #[test]
    fn metadata_blind_index_payload_write_requires_token_shape() {
        let metadata_key = "body__blind_eq";
        validate_metadata_blind_index_json_value(
            &serde_json::Value::String(blind_index_token(9)),
            metadata_key,
        )
        .unwrap();

        for value in [
            serde_json::json!("not base64!"),
            serde_json::json!(BASE64URL_NOPAD.encode(&[9_u8; 31])),
            serde_json::json!(BASE64URL_NOPAD.encode(&[9_u8; 33])),
            serde_json::json!("A".repeat(1024)),
            serde_json::json!(42),
        ] {
            let err = validate_metadata_blind_index_json_value(&value, metadata_key).unwrap_err();
            assert!(format!("{err}").contains("metadata blind-index field"));
        }
    }

    #[test]
    fn encrypted_payload_redaction_redacts_plaintext_invariant_violation() {
        let mut payload = Payload(
            serde_json::json!({
                "document": {
                    "body": "plaintext invariant violation",
                    "title": "public",
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let redaction_plan = PayloadRedactionPlan {
            encrypted_payload_paths: vec![(
                "document.body".parse().unwrap(),
                PayloadRedactionKind::AnyValue,
            )],
            redact_vector_sidecar: false,
        };

        redact_encrypted_payload_values(&mut payload, &redaction_plan);

        assert_eq!(
            payload.0.get("document").unwrap().get("body").unwrap(),
            &encrypted_payload_redaction_value(),
        );
        assert_eq!(
            payload.0.get("document").unwrap().get("title").unwrap(),
            &serde_json::json!("public"),
        );
    }

    #[test]
    fn encrypted_payload_redaction_keeps_marker_shaped_values_outside_configured_paths() {
        let server_marker_like = serde_json::json!({
            qdrant_sec::ENCRYPTED_PAYLOAD_MARKER: {
                "kind": "payload_text",
                "ciphertext": "ordinary user payload marker-shaped object",
            }
        });
        let client_marker_like = serde_json::json!({
            qdrant_sec::CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                "kind": "payload_text",
                "ciphertext": "ordinary client marker-shaped object",
            }
        });
        let mut payload = Payload(
            serde_json::json!({
                "document": {
                    "body": "configured encrypted value",
                },
                "notes": server_marker_like.clone(),
                "nested": {
                    "client": client_marker_like.clone(),
                },
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let redaction_plan = PayloadRedactionPlan {
            encrypted_payload_paths: vec![(
                "document.body".parse().unwrap(),
                PayloadRedactionKind::AnyValue,
            )],
            redact_vector_sidecar: false,
        };

        redact_encrypted_payload_values(&mut payload, &redaction_plan);

        assert_eq!(
            payload.0.get("document").unwrap().get("body").unwrap(),
            &encrypted_payload_redaction_value(),
        );
        assert_eq!(payload.0.get("notes").unwrap(), &server_marker_like);
        assert_eq!(
            payload.0.get("nested").unwrap().get("client").unwrap(),
            &client_marker_like,
        );
    }

    #[test]
    fn private_result_oram_redacted_reads_redact_configured_payload_path() {
        let encryption = private_result_oram_encryption("document.body");
        let redaction_plan = payload_redaction_plan_for_encryption(true, &encryption)
            .expect("private result ORAM redaction plan should build")
            .expect("private result ORAM redacted reads need a redaction plan");

        let mut points = [ScoredPoint {
            id: 1.into(),
            version: 0,
            score: 0.0,
            payload: Some(Payload(
                serde_json::json!({
                    "document": {
                        "body": "private result payload bytes sentinel",
                        "title": "public title",
                    },
                })
                .as_object()
                .unwrap()
                .clone(),
            )),
            vector: None,
            shard_key: None,
            order_value: None,
        }];

        apply_encrypted_payload_read_mode_to_scored_points(
            &mut points,
            EncryptedPayloadReadMode::Redacted,
            Some(&redaction_plan),
        );

        let payload = points[0].payload.as_ref().unwrap();
        assert_eq!(
            payload.0.get("document").unwrap().get("body").unwrap(),
            &encrypted_payload_redaction_value(),
        );
        assert_eq!(
            payload
                .0
                .get("document")
                .unwrap()
                .get("title")
                .unwrap()
                .as_str(),
            Some("public title"),
        );

        assert!(
            payload_redaction_plan_for_encryption(false, &encryption)
                .unwrap()
                .is_none(),
            "raw private result ORAM reads are blocked before redaction planning",
        );
    }

    #[test]
    fn private_result_oram_redacted_reads_redact_literal_json_path_payload_keys() {
        let encryption = private_result_oram_encryption("document.body");
        let redaction_plan = payload_redaction_plan_for_encryption(true, &encryption)
            .expect("private result ORAM redaction plan should build")
            .expect("private result ORAM redacted reads need a redaction plan");

        let mut points = [ScoredPoint {
            id: 1.into(),
            version: 0,
            score: 0.0,
            payload: Some(Payload(
                serde_json::json!({
                    "document.body": "literal private result payload bytes sentinel",
                    "document.body.lang": "literal private result child sentinel",
                    "document.title": "literal public title",
                    "document": {
                        "title": "nested public title",
                    },
                })
                .as_object()
                .unwrap()
                .clone(),
            )),
            vector: None,
            shard_key: None,
            order_value: None,
        }];

        apply_encrypted_payload_read_mode_to_scored_points(
            &mut points,
            EncryptedPayloadReadMode::Redacted,
            Some(&redaction_plan),
        );

        let payload = points[0].payload.as_ref().unwrap();
        assert_eq!(
            payload.0.get("document.body").unwrap(),
            &encrypted_payload_redaction_value(),
        );
        assert_eq!(
            payload.0.get("document.body.lang").unwrap(),
            &encrypted_payload_redaction_value(),
        );
        assert_eq!(
            payload.0.get("document.title").unwrap().as_str(),
            Some("literal public title"),
        );
        assert_eq!(
            payload
                .0
                .get("document")
                .unwrap()
                .get("title")
                .unwrap()
                .as_str(),
            Some("nested public title"),
        );
    }

    #[test]
    fn raw_payload_reads_redact_blind_index_tokens_by_default() {
        let token = blind_index_token(31);
        let mut points = [ScoredPoint {
            id: 1.into(),
            version: 0,
            score: 0.0,
            payload: Some(Payload(
                serde_json::json!({
                    "body__blind_eq": token,
                    "document": { "body": "raw encrypted marker would stay raw" },
                })
                .as_object()
                .unwrap()
                .clone(),
            )),
            vector: None,
            shard_key: None,
            order_value: None,
        }];
        let redaction_plan = PayloadRedactionPlan {
            encrypted_payload_paths: vec![(
                "body__blind_eq".parse().unwrap(),
                PayloadRedactionKind::AnyValue,
            )],
            redact_vector_sidecar: false,
        };

        apply_encrypted_payload_read_mode_to_scored_points(
            &mut points,
            EncryptedPayloadReadMode::Raw,
            Some(&redaction_plan),
        );

        let payload = points[0].payload.as_ref().unwrap();
        assert_eq!(
            payload.0.get("body__blind_eq").unwrap(),
            &encrypted_payload_redaction_value(),
        );
        assert_eq!(
            payload
                .0
                .get("document")
                .unwrap()
                .get("body")
                .unwrap()
                .as_str(),
            Some("raw encrypted marker would stay raw"),
        );
    }
}
