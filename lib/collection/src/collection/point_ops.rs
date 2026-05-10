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
    CKKS_SCHEME, CLIENT_PAYLOAD_ENVELOPE_BINDING, ClientPayloadNonceReplayKey,
    ClientPayloadValidationContext, ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_VECTOR_SIDECAR_FIELD,
    EncryptedCkksVector, ServerPayloadValidationContext, ckks_vector_sidecar_envelope_key,
    client_payload_envelope_key, client_payload_nonce_replay_key,
    is_client_encrypted_payload_value, is_encrypted_payload_value, server_payload_envelope_key,
    validate_client_payload_value_after_runtime_verification,
    validate_server_payload_value_after_runtime_encryption,
};
use segment::data_types::order_by::{Direction, OrderBy};
use segment::data_types::vectors::DEFAULT_VECTOR_NAME;
use segment::index::query_optimization::rescore_formula::parsed_formula::ParsedFormula;
use segment::json_path::JsonPath;
use segment::types::{
    Condition, ExtendedPointId, Filter, Payload, ShardKey, WithPayload, WithPayloadInterface,
    WithVector,
};
use shard::count::CountRequestInternal;
use shard::retrieve::record_internal::RecordInternal;
use shard::scroll::ScrollRequestInternal;

use super::Collection;
use crate::config::EncryptionSelector;
use crate::operations::consistency_params::ReadConsistency;
use crate::operations::payload_ops::PayloadOps;
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
                    .map_err(|err| {
                        CollectionError::bad_input(format!(
                            "encrypted payload field path is invalid: {err:?}",
                        ))
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
                                    |err| {
                                        CollectionError::service_error(format!(
                                            "stored client encrypted payload marker for field '{encrypted_path}' is invalid for nonce replay cache backfill: {err}",
                                        ))
                                    },
                                )? {
                                    Some(envelope_key) => envelope_key,
                                    None if is_client_encrypted_payload_value(value) => {
                                        return Err(CollectionError::service_error(format!(
                                            "stored client encrypted payload marker for field '{encrypted_path}' is incomplete for nonce replay cache backfill",
                                        )));
                                    }
                                    None => continue,
                                };
                            if !envelope_key.matches_binding(
                                &collection_crypto_id,
                                &point_id,
                                encrypted_path,
                            ) {
                                return Err(CollectionError::service_error(format!(
                                    "stored client encrypted payload marker for field '{encrypted_path}' has AAD that does not match collection, point, and field binding; refuse to load replay cache backfill",
                                )));
                            }
                            let Some(key) =
                                client_payload_nonce_replay_key(value, encrypted_path).map_err(
                                    |err| {
                                        CollectionError::service_error(format!(
                                            "stored client encrypted payload marker for field '{encrypted_path}' is invalid for nonce replay cache backfill: {err}",
                                        ))
                                    },
                                )?
                            else {
                                continue;
                            };
                            let cache_key =
                                client_nonce_replay_cache_key(&collection_crypto_id, &key);
                            if !scanned_keys.insert(cache_key.clone()) {
                                return Err(CollectionError::service_error(format!(
                                    "stored client encrypted payload nonce was reused for field '{encrypted_path}'; refuse to load replay cache backfill",
                                )));
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
            log::info!(
                "Backfilled {backfilled} client encrypted payload nonce replay cache entries for collection {}",
                self.name(),
            );
        }

        Ok(())
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
    pub async fn update_from_peer(
        &self,
        operation: OperationWithClockTag,
        shard_selection: ShardId,
        wait: WaitUntil,
        timeout: Option<Duration>,
        ordering: WriteOrdering,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<UpdateResult> {
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
                             with non-`None` clock tag {clock_tag:?} (operation: {:#?})",
                             operation.operation,
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
                    return Err(CollectionError::bad_input(format!(
                        "encrypted vector sidecar '{ENCRYPTED_VECTOR_SIDECAR_FIELD}' must be written as a full runtime-generated sidecar payload",
                    )));
                }
                return Ok(false);
            }

            let mut touches = false;
            if let Some(value) = payload.0.get(ENCRYPTED_VECTOR_SIDECAR_FIELD) {
                touches = true;
                let Some(sidecar) = value.as_object() else {
                    return Err(CollectionError::bad_input(format!(
                        "encrypted vector sidecar '{ENCRYPTED_VECTOR_SIDECAR_FIELD}' must be an object",
                    )));
                };
                for (vector_name, encrypted) in sidecar {
                    if !encrypted_vector_names.contains(vector_name) {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' is not configured as an encrypted vector",
                        )));
                    }
                    let Some(marker) = encrypted
                        .as_object()
                        .and_then(|object| object.get(ENCRYPTED_CKKS_VECTOR_MARKER))
                    else {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' is malformed",
                        )));
                    };
                    let encrypted_vector: EncryptedCkksVector = serde_json::from_value(
                        marker.clone(),
                    )
                    .map_err(|err| {
                        CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' is malformed: {err}",
                        ))
                    })?;
                    if encrypted_vector.version != 1 {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' has unsupported version {}",
                            encrypted_vector.version,
                        )));
                    }
                    if encrypted_vector.scheme != CKKS_SCHEME {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' has unsupported scheme '{}'",
                            encrypted_vector.scheme,
                        )));
                    }
                    if let Some(key_id) = encrypted_vector_key_id.as_deref()
                        && encrypted_vector.envelope.key_id != key_id
                    {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' key id does not match this collection",
                        )));
                    }
                    if encrypted_vector.envelope.algorithm != "AES-256-GCM" {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' has unsupported envelope algorithm '{}'",
                            encrypted_vector.envelope.algorithm,
                        )));
                    }
                    if encrypted_vector.envelope.material_fingerprint.is_empty() {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' is missing material fingerprint",
                        )));
                    }
                    let nonce = BASE64URL_NOPAD
                        .decode(encrypted_vector.envelope.nonce.as_bytes())
                        .map_err(|_| {
                            CollectionError::bad_input(format!(
                                "encrypted vector sidecar entry '{vector_name}' nonce is not base64url",
                            ))
                        })?;
                    if nonce.len() != 12 {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' nonce must be 12 bytes",
                        )));
                    }
                    let ciphertext = BASE64URL_NOPAD
                        .decode(encrypted_vector.envelope.ciphertext.as_bytes())
                        .map_err(|_| {
                            CollectionError::bad_input(format!(
                                "encrypted vector sidecar entry '{vector_name}' ciphertext is not base64url",
                            ))
                        })?;
                    if ciphertext.len() < 16 {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' ciphertext is too short",
                        )));
                    }
                    let Some(point_id) = point_id else {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' requires point-specific runtime vector encryption before collection write",
                        )));
                    };
                    let Some(sidecar_key) = ckks_vector_sidecar_envelope_key(
                        encrypted,
                        &collection_crypto_id,
                        point_id,
                        vector_name,
                    )
                    .map_err(|err| {
                        CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' is invalid for this collection: {err}",
                        ))
                    })?
                    else {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' requires runtime vector encryption before collection write",
                        )));
                    };
                    if !update_provenance.allows_vector_sidecar_key_for_binding(
                        &sidecar_key,
                        &collection_crypto_id,
                        point_id,
                        vector_name,
                    ) {
                        return Err(CollectionError::bad_input(format!(
                            "encrypted vector sidecar entry '{vector_name}' requires runtime vector encryption before collection write",
                        )));
                    }
                }
            }
            Ok(touches)
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
            CollectionUpdateOperations::PayloadOperation(_)
            | CollectionUpdateOperations::VectorOperation(_)
            | CollectionUpdateOperations::FieldIndexOperation(_) => false,
            #[cfg(feature = "staging")]
            CollectionUpdateOperations::StagingOperation(_) => false,
        };
        if touches_vector_sidecar && !update_provenance.allows_vector_sidecars() {
            return Err(CollectionError::bad_input(format!(
                "encrypted vector sidecar '{ENCRYPTED_VECTOR_SIDECAR_FIELD}' requires runtime CKKS vector encryption before collection write",
            )));
        }
        if let Some(encryption) = encryption {
            let mut seen_client_nonces = std::collections::HashSet::new();
            let mut payload_write_touches_encrypted_path = |payload: &Payload,
                                                            key: Option<&JsonPath>,
                                                            point_id: Option<&str>,
                                                            encrypted_path: &JsonPath,
                                                            encrypted_path_str: &str,
                                                            allow_client_envelope: bool|
             -> CollectionResult<bool> {
                if let Some(key) = key {
                    return Ok(key.compatible(encrypted_path));
                }

                for value in encrypted_path.value_get(&payload.0) {
                    if is_encrypted_payload_value(value) {
                        let Some(point_id) = point_id else {
                            return Err(CollectionError::bad_input(format!(
                                "encrypted payload marker for field '{encrypted_path_str}' requires point-specific runtime payload encryption before collection write",
                            )));
                        };
                        let Some(envelope_key) = server_payload_envelope_key(
                            value,
                            &collection_crypto_id,
                            point_id,
                            encrypted_path_str,
                        )
                        .map_err(|err| {
                            CollectionError::bad_input(format!(
                                "encrypted payload marker for field '{encrypted_path_str}' is invalid for this collection: {err}",
                            ))
                        })?
                        else {
                            return Err(CollectionError::bad_input(format!(
                                "encrypted payload marker for field '{encrypted_path_str}' requires runtime payload encryption before collection write",
                            )));
                        };
                        let Some(verified_envelope_key) = update_provenance
                            .verified_server_envelope_key_for_binding(
                                &envelope_key,
                                &collection_crypto_id,
                                point_id,
                                encrypted_path_str,
                            )
                        else {
                            return Err(CollectionError::bad_input(format!(
                                "encrypted payload marker for field '{encrypted_path_str}' requires runtime payload encryption before collection write",
                            )));
                        };
                        validate_server_payload_value_after_runtime_encryption(
                            value,
                            &collection_crypto_id,
                            point_id,
                            ServerPayloadValidationContext {
                                field_path: encrypted_path_str,
                                key_id: encryption.key_id.as_deref(),
                                crypto_schema_version: encryption.crypto_schema_version,
                                encryption_epoch: encryption.encryption_epoch,
                            },
                            &verified_envelope_key,
                        )
                        .map_err(|err| {
                            CollectionError::bad_input(format!(
                                "encrypted payload marker for field '{encrypted_path_str}' is invalid for this collection: {err}",
                            ))
                        })?;
                        continue;
                    }
                    if allow_client_envelope && is_client_encrypted_payload_value(value) {
                        let Some(envelope_key) =
                            client_payload_envelope_key(value, encrypted_path_str)
                                .map_err(|err| {
                                    CollectionError::bad_input(format!(
                                        "client encrypted payload marker for field '{encrypted_path_str}' is invalid for this collection: {err}",
                                    ))
                                })?
                        else {
                            return Err(CollectionError::bad_input(format!(
                                "client encrypted payload marker for field '{encrypted_path_str}' requires runtime envelope verification before collection write",
                            )));
                        };
                        let Some(point_id) = point_id else {
                            return Err(CollectionError::bad_input(format!(
                                "client encrypted payload marker for field '{encrypted_path_str}' requires point-specific runtime envelope verification before collection write",
                            )));
                        };
                        let Some(verified_envelope_key) = update_provenance
                            .verified_client_envelope_key_for_binding(
                                &envelope_key,
                                &collection_crypto_id,
                                point_id,
                                encrypted_path_str,
                            )
                        else {
                            return Err(CollectionError::bad_input(format!(
                                "client encrypted payload marker for field '{encrypted_path_str}' requires runtime envelope verification before collection write",
                            )));
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
                        .map_err(|err| {
                            CollectionError::bad_input(format!(
                                "client encrypted payload marker for field '{encrypted_path_str}' is invalid for this collection: {err}",
                            ))
                        })?;
                        let Some(nonce_replay_key) =
                            client_payload_nonce_replay_key(value, encrypted_path_str).map_err(
                                |err| {
                                    CollectionError::bad_input(format!(
                                        "client encrypted payload marker for field '{encrypted_path_str}' is invalid for this collection: {err}",
                                    ))
                                },
                            )?
                        else {
                            return Ok(true);
                        };
                        if !seen_client_nonces.insert(nonce_replay_key) {
                            return Err(CollectionError::bad_input(format!(
                                "client encrypted payload marker for field '{encrypted_path_str}' is invalid for this collection: payload field client envelope nonce was already used in this write request; regenerate the client-side envelope with a fresh nonce before retrying",
                            )));
                        }
                        continue;
                    }
                    return Ok(true);
                }

                Ok(false)
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
                                encrypted_path.parse::<JsonPath>().map_err(|err| {
                                    CollectionError::bad_input(format!(
                                        "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                                    ))
                                })?;

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
                                        allow_client_envelope,
                                    )?
                                }
                                CollectionUpdateOperations::VectorOperation(_)
                                | CollectionUpdateOperations::PayloadOperation(
                                    PayloadOps::DeletePayload(_)
                                    | PayloadOps::ClearPayload { .. }
                                    | PayloadOps::ClearPayloadByFilter(_),
                                )
                                | CollectionUpdateOperations::FieldIndexOperation(_) => false,
                                #[cfg(feature = "staging")]
                                CollectionUpdateOperations::StagingOperation(_) => false,
                            };

                            if touches_encrypted_payload {
                                return Err(CollectionError::bad_input(format!(
                                    "cannot write plaintext payload for encrypted field '{encrypted_path}'; configure runtime payload encryption before writing this field",
                                )));
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
                                return Err(CollectionError::bad_input(format!(
                                    "cannot write plaintext vector '{encrypted_name}' for encrypted vector rule; configure runtime CKKS vector encryption before writing this vector",
                                )));
                            }
                        }
                    }
                    EncryptionSelector::MetadataKeys { .. } => {}
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
            let first_err = results.into_iter().find(|result| result.is_err()).unwrap();
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

            let max_operation_id = results.into_iter().map(|r| r.operation_id).max().unwrap(); // We checked that results is not empty above

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

    pub async fn scroll_by(
        &self,
        mut request: ScrollRequestInternal,
        read_consistency: Option<ReadConsistency>,
        shard_selection: &ShardSelectorInternal,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<ScrollResult> {
        let default_request = ScrollRequestInternal::default();

        let mut limit = request
            .limit
            .unwrap_or_else(|| default_request.limit.unwrap());

        if limit == 0 {
            return Err(CollectionError::BadRequest {
                description: "Limit cannot be 0".to_string(),
            });
        }
        self.ensure_filter_does_not_touch_encrypted_payload(request.filter.as_ref())
            .await?;

        let order_by = request.order_by.clone().map(OrderBy::from);
        self.ensure_order_by_does_not_touch_encrypted_payload(order_by.as_ref())
            .await?;
        self.ensure_with_vector_does_not_touch_encrypted_vector(&request.with_vector)
            .await?;

        let local_only = shard_selection.is_shard_id();

        // `order_by` does not support offset
        if order_by.is_none() {
            // Needed to return next page offset.
            limit = limit.saturating_add(1);
            request.limit = Some(limit);
        }

        let request = Arc::new(request);

        let retrieved_points: Vec<_> = {
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
            Some(points.pop().unwrap().id)
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

        for rule in &encryption.rules {
            let EncryptionSelector::VectorNames { names } = &rule.selector else {
                continue;
            };
            match with_vector {
                WithVector::Bool(true) => {
                    if let Some(encrypted_name) = names.first() {
                        return Err(CollectionError::bad_input(format!(
                            "cannot return encrypted vector '{encrypted_name}'; CKKS vector ciphertext read path is not implemented",
                        )));
                    }
                }
                WithVector::Selector(vector_names) => {
                    for requested_name in vector_names {
                        if names.iter().any(|name| name == requested_name) {
                            return Err(CollectionError::bad_input(format!(
                                "cannot return encrypted vector '{requested_name}'; CKKS vector ciphertext read path is not implemented",
                            )));
                        }
                    }
                }
                WithVector::Bool(false) => {}
            }
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
        if request.ids.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_with_vector_does_not_touch_encrypted_vector(&request.with_vector)
            .await?;
        let with_payload_interface = request
            .with_payload
            .as_ref()
            .unwrap_or(&WithPayloadInterface::Bool(false));
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
        let points = request
            .ids
            .iter()
            .filter_map(|id| covered_point_ids.remove(id))
            .collect();

        Ok(points)
    }

    pub(crate) async fn ensure_filter_does_not_touch_encrypted_payload(
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
            && let Some(filter_path) = filter_touches_encrypted_payload(filter, &sidecar_path)
        {
            return Err(CollectionError::bad_input(format!(
                "cannot filter on encrypted vector sidecar field '{filter_path}'; use encrypted vector search APIs instead",
            )));
        }

        for rule in &encryption.rules {
            match &rule.selector {
                EncryptionSelector::PayloadPaths { paths } => {
                    for encrypted_path in paths {
                        let encrypted_json_path =
                            encrypted_path.parse::<JsonPath>().map_err(|err| {
                                CollectionError::bad_input(format!(
                                    "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                                ))
                            })?;
                        if let Some(filter_path) =
                            filter_touches_encrypted_payload(filter, &encrypted_json_path)
                        {
                            return Err(CollectionError::bad_input(format!(
                                "cannot filter on encrypted payload field '{filter_path}' because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                            )));
                        }
                    }
                }
                EncryptionSelector::VectorNames { names } => {
                    for encrypted_name in names {
                        if let Some(filter_vector) =
                            filter_touches_encrypted_vector(filter, encrypted_name)
                        {
                            return Err(CollectionError::bad_input(format!(
                                "cannot filter on encrypted vector '{filter_vector}' because CKKS-native vector search is not implemented",
                            )));
                        }
                    }
                }
                EncryptionSelector::MetadataKeys { .. } => {}
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
            return Err(CollectionError::bad_input(format!(
                "cannot order by encrypted vector sidecar field '{}'; use encrypted vector search APIs instead",
                order_by.key,
            )));
        }

        for rule in &encryption.rules {
            let EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
                continue;
            };

            for encrypted_path in paths {
                let encrypted_json_path = encrypted_path.parse::<JsonPath>().map_err(|err| {
                    CollectionError::bad_input(format!(
                        "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                    ))
                })?;
                if order_by.key.compatible(&encrypted_json_path) {
                    return Err(CollectionError::bad_input(format!(
                        "cannot order by encrypted payload field '{}' because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                        order_by.key,
                    )));
                }
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
            return Err(CollectionError::bad_input(format!(
                "cannot group by encrypted vector sidecar field '{group_by}'; use encrypted vector search APIs instead",
            )));
        }

        for rule in &encryption.rules {
            let EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
                continue;
            };

            for encrypted_path in paths {
                let encrypted_json_path = encrypted_path.parse::<JsonPath>().map_err(|err| {
                    CollectionError::bad_input(format!(
                        "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                    ))
                })?;
                if group_by.compatible(&encrypted_json_path) {
                    return Err(CollectionError::bad_input(format!(
                        "cannot group by encrypted payload field '{group_by}' because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                    )));
                }
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
            if let Some(formula_path) = formula
                .payload_vars
                .iter()
                .find(|payload_var| payload_var.compatible(&sidecar_path))
            {
                return Err(CollectionError::bad_input(format!(
                    "cannot use encrypted vector sidecar field '{formula_path}' in formula; use encrypted vector search APIs instead",
                )));
            }

            if let Some(condition_path) = formula
                .conditions
                .iter()
                .find_map(|condition| condition_touches_encrypted_payload(condition, &sidecar_path))
            {
                return Err(CollectionError::bad_input(format!(
                    "cannot use formula condition on encrypted vector sidecar field '{condition_path}'; use encrypted vector search APIs instead",
                )));
            }
        }

        for rule in &encryption.rules {
            let EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
                continue;
            };

            for encrypted_path in paths {
                let encrypted_json_path = encrypted_path.parse::<JsonPath>().map_err(|err| {
                    CollectionError::bad_input(format!(
                        "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                    ))
                })?;

                if let Some(formula_path) = formula
                    .payload_vars
                    .iter()
                    .find(|payload_var| payload_var.compatible(&encrypted_json_path))
                {
                    return Err(CollectionError::bad_input(format!(
                        "cannot use encrypted payload field '{formula_path}' in formula because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                    )));
                }

                if let Some(condition_path) = formula.conditions.iter().find_map(|condition| {
                    condition_touches_encrypted_payload(condition, &encrypted_json_path)
                }) {
                    return Err(CollectionError::bad_input(format!(
                        "cannot use formula condition on encrypted payload field '{condition_path}' because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                    )));
                }
            }
        }

        Ok(())
    }
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
        .map_err(|err| {
            CollectionError::bad_input(format!(
                "encrypted vector sidecar field path '{ENCRYPTED_VECTOR_SIDECAR_FIELD}' is invalid: {err:?}",
            ))
        })
}

fn client_nonce_replay_cache_key(
    collection_crypto_id: &str,
    key: &ClientPayloadNonceReplayKey,
) -> String {
    key.cache_key_for_collection(collection_crypto_id)
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
