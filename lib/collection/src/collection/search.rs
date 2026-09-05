use std::mem;
use std::sync::Arc;
use std::time::Duration;

use ahash::{AHashMap, AHashSet};
use common::counter::hardware_accumulator::HwMeasurementAcc;
use futures::{TryFutureExt, future};
use itertools::{Either, Itertools};
use segment::types::{
    EncryptedPayloadReadMode, ExtendedPointId, Filter, Order, ScoredPoint, WithPayloadInterface,
    WithVector,
};
use shard::retrieve::record_internal::RecordInternal;
use shard::search::CoreSearchRequestBatch;
use tokio::time::Instant;

use super::Collection;
use super::point_ops::{
    apply_encrypted_payload_read_mode_to_scored_points,
    ensure_encrypted_payload_read_mode_is_supported,
};
use crate::config::{
    CollectionEncryptionConfig, EncryptionSelector, encryption_rule_uses_private_hnsw_oram,
    private_hnsw_oram_api_required_message,
};
use crate::events::SlowQueryEvent;
use crate::operations::consistency_params::ReadConsistency;
use crate::operations::shard_selector_internal::ShardSelectorInternal;
use crate::operations::types::*;

impl Collection {
    #[cfg(feature = "testing")]
    pub async fn search(
        &self,
        request: CoreSearchRequest,
        read_consistency: Option<ReadConsistency>,
        shard_selection: &ShardSelectorInternal,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<Vec<ScoredPoint>> {
        if request.limit == 0 {
            self.core_search_batch(
                CoreSearchRequestBatch {
                    searches: vec![request],
                },
                read_consistency,
                shard_selection.clone(),
                timeout,
                hw_measurement_acc,
            )
            .await?;
            return Ok(vec![]);
        }
        // search is a special case of search_batch with a single batch
        let request_batch = CoreSearchRequestBatch {
            searches: vec![request],
        };
        let results = self
            .core_search_batch(
                request_batch,
                read_consistency,
                shard_selection.clone(),
                timeout,
                hw_measurement_acc,
            )
            .await?;
        results
            .into_iter()
            .next()
            .ok_or_else(|| CollectionError::service_error("search batch returned no result"))
    }

    pub async fn core_search_batch(
        &self,
        request: CoreSearchRequestBatch,
        read_consistency: Option<ReadConsistency>,
        shard_selection: ShardSelectorInternal,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<Vec<Vec<ScoredPoint>>> {
        let start = Instant::now();
        self.ensure_crypto_migration_allows_regular_operation("reads")
            .await?;
        for search in &request.searches {
            self.ensure_with_vector_does_not_touch_encrypted_vector(
                &search.with_vector.clone().unwrap_or_default(),
            )
            .await?;
            self.ensure_filter_does_not_touch_encrypted_payload(search.filter.as_ref())
                .await?;
        }
        let encrypted_payload_read_modes = request
            .searches
            .iter()
            .map(|search| {
                search
                    .with_payload
                    .as_ref()
                    .map(WithPayloadInterface::encrypted_payload_read_mode)
                    .unwrap_or(EncryptedPayloadReadMode::Raw)
            })
            .collect_vec();
        for mode in &encrypted_payload_read_modes {
            ensure_encrypted_payload_read_mode_is_supported(*mode)?;
        }
        if let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        {
            for search in &request.searches {
                let vector_name = search.query.get_vector_name();
                if let Some(err) = encrypted_direct_search_error(&encryption, vector_name) {
                    return Err(err);
                }
            }
        }
        for search in &request.searches {
            self.ensure_private_result_oram_payload_read_is_not_raw(search.with_payload.as_ref())
                .await?;
        }
        // shortcuts batch if all requests with limit=0
        if request.searches.iter().all(|s| s.limit == 0) {
            return Ok(vec![]);
        }

        let is_payload_required = request
            .searches
            .iter()
            .all(|s| s.with_payload.as_ref().is_some_and(|p| p.is_required()));
        let with_vectors = request
            .searches
            .iter()
            .all(|s| s.with_vector.as_ref().is_some_and(|wv| wv.is_enabled()));

        let metadata_required = is_payload_required || with_vectors;

        let sum_limits: usize = request.searches.iter().map(|s| s.limit).sum();
        let sum_offsets: usize = request.searches.iter().map(|s| s.offset).sum();

        // Number of records we need to retrieve to fill the search result.
        let require_transfers = self.shards_holder.read().await.len() * (sum_limits + sum_offsets);
        // Actually used number of records.
        let used_transfers = sum_limits;

        let is_required_transfer_large_enough = require_transfers
            > used_transfers.saturating_mul(super::query::PAYLOAD_TRANSFERS_FACTOR_THRESHOLD);

        if metadata_required && is_required_transfer_large_enough {
            // If there is a significant offset, we need to retrieve the whole result
            // set without payload first and then retrieve the payload.
            // It is required to do this because the payload might be too large to send over the
            // network.
            let mut without_payload_requests = Vec::with_capacity(request.searches.len());
            for search in &request.searches {
                let mut without_payload_request = search.clone();
                without_payload_request
                    .with_payload
                    .replace(WithPayloadInterface::Bool(false));
                without_payload_request
                    .with_vector
                    .replace(WithVector::Bool(false));
                without_payload_requests.push(without_payload_request);
            }
            let without_payload_batch = CoreSearchRequestBatch {
                searches: without_payload_requests,
            };
            let without_payload_results = self
                .do_core_search_batch(
                    without_payload_batch,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?;
            // update timeout
            let timeout = timeout.map(|t| t.saturating_sub(start.elapsed()));
            let filled_results = without_payload_results
                .into_iter()
                .zip(request.searches.into_iter())
                .map(|(without_payload_result, req)| {
                    self.fill_search_result_with_payload(
                        without_payload_result,
                        req.with_payload.clone(),
                        req.with_vector.unwrap_or_default(),
                        read_consistency,
                        &shard_selection,
                        timeout,
                        hw_measurement_acc.clone(),
                    )
                });
            future::try_join_all(filled_results).await
        } else {
            // Raw reads keep encrypted envelopes but must still strip blind-index tokens, exactly
            // like scroll/retrieve do, so a plan is built for every requested mode.
            let redacted_plan = if encrypted_payload_read_modes
                .iter()
                .any(|mode| *mode == EncryptedPayloadReadMode::Redacted)
            {
                self.encrypted_payload_redaction_plan_for_mode(EncryptedPayloadReadMode::Redacted)
                    .await?
            } else {
                None
            };
            let raw_plan = if encrypted_payload_read_modes
                .iter()
                .any(|mode| *mode == EncryptedPayloadReadMode::Raw)
            {
                self.encrypted_payload_redaction_plan_for_mode(EncryptedPayloadReadMode::Raw)
                    .await?
            } else {
                None
            };
            let mut result = self
                .do_core_search_batch(
                    request,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc,
                )
                .await?;
            for (points, mode) in result.iter_mut().zip(encrypted_payload_read_modes) {
                let redaction_plan = match mode {
                    EncryptedPayloadReadMode::Redacted => redacted_plan.as_ref(),
                    EncryptedPayloadReadMode::Raw => raw_plan.as_ref(),
                    _ => None,
                };
                apply_encrypted_payload_read_mode_to_scored_points(points, mode, redaction_plan);
            }
            Ok(result)
        }
    }

    async fn do_core_search_batch(
        &self,
        request: CoreSearchRequestBatch,
        read_consistency: Option<ReadConsistency>,
        shard_selection: &ShardSelectorInternal,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<Vec<Vec<ScoredPoint>>> {
        let request = Arc::new(request);

        let instant = Instant::now();

        // query all shards concurrently
        let all_searches_res = {
            let shard_holder = self.shards_holder.read().await;
            let target_shards = shard_holder.select_shards(shard_selection)?;
            let all_searches = target_shards.into_iter().map(|(shard, shard_key)| {
                let shard_key = shard_key.cloned();
                shard
                    .core_search(
                        request.clone(),
                        read_consistency,
                        shard_selection.is_shard_id(),
                        timeout,
                        hw_measurement_acc.clone(),
                    )
                    .and_then(move |mut records| async move {
                        if shard_key.is_none() {
                            return Ok(records);
                        }
                        for batch in &mut records {
                            for point in batch {
                                point.shard_key.clone_from(&shard_key);
                            }
                        }
                        Ok(records)
                    })
            });
            future::try_join_all(all_searches).await?
        };

        let result = self
            .merge_from_shards(
                all_searches_res,
                request.clone(),
                !shard_selection.is_shard_id(),
            )
            .await;

        let filters_refs = request.searches.iter().map(|req| req.filter.as_ref());

        self.post_process_if_slow_request(instant.elapsed(), filters_refs);

        result
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn fill_search_result_with_payload(
        &self,
        search_result: Vec<ScoredPoint>,
        with_payload: Option<WithPayloadInterface>,
        with_vector: WithVector,
        read_consistency: Option<ReadConsistency>,
        shard_selection: &ShardSelectorInternal,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<Vec<ScoredPoint>> {
        // short-circuit if not needed
        if let (&Some(WithPayloadInterface::Bool(false)), &WithVector::Bool(false)) =
            (&with_payload, &with_vector)
        {
            return Ok(search_result
                .into_iter()
                .map(|point| ScoredPoint {
                    payload: None,
                    vector: None,
                    ..point
                })
                .collect());
        };

        let retrieve_request = PointRequestInternal {
            ids: search_result.iter().map(|x| x.id).collect(),
            with_payload,
            with_vector,
        };
        let retrieved_records = self
            .retrieve(
                retrieve_request,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await?;

        let mut records_map: AHashMap<ExtendedPointId, RecordInternal> = retrieved_records
            .into_iter()
            .map(|rec| (rec.id, rec))
            .collect();
        let enriched_result = search_result
            .into_iter()
            .filter_map(|mut scored_point| {
                // Points might get deleted between search and retrieve.
                // But it's not a problem, because we don't want to return deleted points.
                // So we just filter out them.
                records_map.remove(&scored_point.id).map(|record| {
                    scored_point.payload = record.payload;
                    scored_point.vector = record.vector;
                    scored_point
                })
            })
            .collect();
        Ok(enriched_result)
    }

    async fn merge_from_shards(
        &self,
        mut all_searches_res: Vec<Vec<Vec<ScoredPoint>>>,
        request: Arc<CoreSearchRequestBatch>,
        is_client_request: bool,
    ) -> CollectionResult<Vec<Vec<ScoredPoint>>> {
        let batch_size = request.searches.len();

        let collection_params = self.collection_config.read().await.params.clone();

        // Merge results from shards in order and deduplicate based on point ID
        let mut top_results: Vec<Vec<ScoredPoint>> = Vec::with_capacity(batch_size);
        let mut seen_ids = AHashSet::new();

        for (batch_index, request) in request.searches.iter().enumerate() {
            let order = if request.query.is_distance_scored() {
                collection_params
                    .get_distance(request.query.get_vector_name())?
                    .distance_order()
            } else {
                // Score comes from special handling of the distances in a way that it doesn't
                // directly represent distance anymore, so the order is always `LargeBetter`
                Order::LargeBetter
            };

            let results_from_shards = all_searches_res
                .iter_mut()
                .map(|res| res.get_mut(batch_index).map_or(Vec::new(), mem::take));

            let merged_iter = match order {
                Order::LargeBetter => Either::Left(results_from_shards.kmerge_by(|a, b| a > b)),
                Order::SmallBetter => Either::Right(results_from_shards.kmerge_by(|a, b| a < b)),
            }
            .filter(|point| seen_ids.insert(point.id));

            // Skip `offset` only for client requests
            // to avoid applying `offset` twice in distributed mode.
            let top_res = if is_client_request && request.offset > 0 {
                merged_iter
                    .skip(request.offset)
                    .take(request.limit)
                    .collect()
            } else {
                merged_iter.take(request.offset + request.limit).collect()
            };

            top_results.push(top_res);

            seen_ids.clear();
        }

        Ok(top_results)
    }

    pub fn post_process_if_slow_request<'a>(
        &self,
        duration: Duration,
        filters: impl IntoIterator<Item = Option<&'a Filter>>,
    ) {
        if duration > crate::problems::UnindexedField::slow_query_threshold() {
            let filters = filters.into_iter().flatten().cloned().collect_vec();

            let schema = self.payload_index_schema.read().schema.clone();

            issues::publish(SlowQueryEvent {
                collection_id: self.id.clone(),
                filters,
                schema,
            });
        }
    }
}

fn encrypted_direct_search_error(
    encryption: &CollectionEncryptionConfig,
    vector_name: &str,
) -> Option<CollectionError> {
    for rule in &encryption.rules {
        let EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        if names.iter().any(|name| name == vector_name) {
            let message = if encryption_rule_uses_private_hnsw_oram(rule) {
                private_hnsw_oram_api_required_message(vector_name)
            } else {
                "cannot search encrypted vector through direct collection search; use the runtime CKKS sidecar search entrypoint".to_string()
            };
            return Some(CollectionError::bad_input(message));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef};

    fn private_hnsw_search_encryption(vector_name: &str) -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a/vector-private-rk".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "docs_text_private_hnsw".to_string(),
                selector: EncryptionSelector::VectorNames {
                    names: vec![vector_name.to_string()],
                },
                instance: "docs_text_private_hnsw".to_string(),
                binding: Some(qdrant_sec::PRIVATE_HNSW_ORAM_BINDING.to_string()),
            }],
        }
    }

    #[test]
    fn private_hnsw_direct_search_error_uses_session_api_without_vector_name() {
        let private_vector = "client_state_direct_search_private_hnsw";
        let encryption = private_hnsw_search_encryption(private_vector);

        let err = encrypted_direct_search_error(&encryption, private_vector)
            .expect("private HNSW direct search must be rejected");
        let message = err.to_string();

        assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
        assert!(message.contains("/private-hnsw/{vector}/session"));
        assert!(!message.contains(private_vector), "{message}");
        assert!(!message.contains("client_state"), "{message}");
        assert!(encrypted_direct_search_error(&encryption, "public").is_none());
    }
}
