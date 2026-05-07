use std::time::Duration;

use api::rest::{RecommendStrategy, SearchGroupsRequestInternal, SearchRequestInternal};
use collection::collection::distance_matrix::*;
use collection::common::batching::batch_requests;
use collection::config::EncryptionSelector;
use collection::grouping::group_by::GroupRequest;
use collection::operations::consistency_params::ReadConsistency;
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::types::*;
use collection::operations::universal_query::collection_query::*;
use collection::recommendations::avg_vector_for_recommendation;
use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::math::scaled_fast_sigmoid;
use qdrant_sec::{
    ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector,
};
use segment::data_types::groups::GroupId;
use segment::data_types::vectors::{
    DEFAULT_VECTOR_NAME, Named, NamedQuery, VectorInternal, VectorRef,
};
use segment::json_path::JsonPath;
use segment::types::{
    Order, PayloadContainer, ScoredPoint, SearchParams, WithPayloadInterface, WithVector,
};
use segment::utils::scored_point_ties::ScoredPointTies;
use segment::vector_storage::query::ContextPair;
use shard::query::query_enum::QueryEnum;
use shard::retrieve::record_internal::RecordInternal;
use shard::scroll::ScrollRequestInternal;
use shard::search::CoreSearchRequestBatch;
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::rbac::{AccessRequirements, Auth};

use crate::common::crypto::vector_write_plan_for_collection_with_crypto_id;
use crate::settings::Settings;

#[allow(clippy::too_many_arguments)]
pub async fn do_core_search_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: CoreSearchRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let batch_res = do_core_search_batch_points(
        toc,
        collection_name,
        CoreSearchRequestBatch {
            searches: vec![request],
        },
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
        runtime_settings,
    )
    .await?;
    batch_res
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::service_error("Empty search result"))
}

pub async fn do_search_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    requests: Vec<(CoreSearchRequest, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let requests = batch_requests::<
        (CoreSearchRequest, ShardSelectorInternal),
        ShardSelectorInternal,
        Vec<CoreSearchRequest>,
        Vec<_>,
    >(
        requests,
        |(_, shard_selector)| shard_selector,
        |(request, _), core_reqs| {
            core_reqs.push(request);
            Ok(())
        },
        |shard_selector, core_requests, res| {
            if core_requests.is_empty() {
                return Ok(());
            }

            let core_batch = CoreSearchRequestBatch {
                searches: core_requests,
            };

            let req = do_core_search_batch_points(
                toc,
                collection_name,
                core_batch,
                read_consistency,
                shard_selector,
                auth.clone(),
                timeout,
                hw_measurement_acc.clone(),
                runtime_settings,
            );
            res.push(req);
            Ok(())
        },
    )?;

    let results = futures::future::try_join_all(requests).await?;
    let flatten_results: Vec<Vec<_>> = results.into_iter().flatten().collect();
    Ok(flatten_results)
}

#[allow(clippy::too_many_arguments)]
pub async fn do_core_search_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: CoreSearchRequestBatch,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    if let Some(settings) = runtime_settings
        && let Some(results) = try_ckks_vector_search_batch_points(
            toc,
            collection_name,
            &request,
            read_consistency,
            &shard_selection,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
        )
        .await?
    {
        return Ok(results);
    }

    toc.core_search_batch(
        collection_name,
        request,
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_search_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: &CoreSearchRequestBatch,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
) -> Result<Option<Vec<Vec<ScoredPoint>>>, StorageError> {
    if request.searches.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_search",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let mut has_encrypted_search = false;
    let mut has_plain_search = false;
    for search in &request.searches {
        if plan.contains_vector_name(search.query.get_vector_name()) {
            has_encrypted_search = true;
        } else {
            has_plain_search = true;
        }
    }

    if !has_encrypted_search {
        return Ok(None);
    }
    if has_plain_search {
        return Err(StorageError::bad_input(
            "cannot mix CKKS encrypted vector search with plaintext vector search in the same batch",
        ));
    }

    let mut results = Vec::with_capacity(request.searches.len());
    for search in &request.searches {
        results.push(
            ckks_vector_search_points(
                &collection,
                collection_name,
                search,
                &plan,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?,
        );
    }

    Ok(Some(results))
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_search_points(
    collection: &collection::collection::Collection,
    collection_name: &str,
    search: &CoreSearchRequest,
    plan: &crate::common::crypto::VectorWritePlan,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<ScoredPoint>, StorageError> {
    enum CkksSidecarScoring<'a> {
        Nearest {
            query_values: &'a [f32],
        },
        RecommendBestScore {
            positives: Vec<&'a [f32]>,
            negatives: Vec<&'a [f32]>,
        },
        RecommendSumScores {
            positives: Vec<&'a [f32]>,
            negatives: Vec<&'a [f32]>,
        },
        Discover {
            target: &'a [f32],
            pairs: Vec<(&'a [f32], &'a [f32])>,
        },
    }

    let (vector_name, scoring) = match &search.query {
        QueryEnum::Nearest(named_query) => {
            let VectorInternal::Dense(query_values) = &named_query.query else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{}' only supports dense query vectors",
                    named_query.get_name(),
                )));
            };
            (
                named_query.get_name(),
                CkksSidecarScoring::Nearest { query_values },
            )
        }
        QueryEnum::RecommendBestScore(named_query) => (
            named_query.get_name(),
            CkksSidecarScoring::RecommendBestScore {
                positives: query_vectors_as_dense_slices(
                    &named_query.query.positives,
                    named_query.get_name(),
                    "positive",
                )?,
                negatives: query_vectors_as_dense_slices(
                    &named_query.query.negatives,
                    named_query.get_name(),
                    "negative",
                )?,
            },
        ),
        QueryEnum::RecommendSumScores(named_query) => (
            named_query.get_name(),
            CkksSidecarScoring::RecommendSumScores {
                positives: query_vectors_as_dense_slices(
                    &named_query.query.positives,
                    named_query.get_name(),
                    "positive",
                )?,
                negatives: query_vectors_as_dense_slices(
                    &named_query.query.negatives,
                    named_query.get_name(),
                    "negative",
                )?,
            },
        ),
        QueryEnum::Discover(named_query) => {
            let VectorInternal::Dense(target) = &named_query.query.target else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{}' discover cannot resolve point-id or non-dense target examples because plaintext vectors are not stored",
                    named_query.get_name(),
                )));
            };
            (
                named_query.get_name(),
                CkksSidecarScoring::Discover {
                    target,
                    pairs: query_context_pairs_as_dense_slices(
                        &named_query.query.pairs,
                        named_query.get_name(),
                    )?,
                },
            )
        }
        _ => {
            return Err(StorageError::bad_input(format!(
                "encrypted vector '{}' only supports dense nearest-neighbor search, raw-dense recommend, and raw-dense discover over the CKKS sidecar",
                search.query.get_vector_name(),
            )));
        }
    };
    let distance = plan.distance_for_vector(vector_name).ok_or_else(|| {
        StorageError::service_error(format!(
            "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
        ))
    })?;
    let score_order = match &scoring {
        CkksSidecarScoring::Nearest { .. } => distance.distance_order(),
        CkksSidecarScoring::RecommendBestScore {
            positives,
            negatives,
        }
        | CkksSidecarScoring::RecommendSumScores {
            positives,
            negatives,
        } => {
            if positives.is_empty() && negatives.is_empty() {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' recommend requires at least one raw dense example",
                )));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' recommend best-score and sum-scores require a large-better metric such as dot or cosine",
                )));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::Discover { .. } => {
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' discover with sidecar scoring requires a large-better metric such as dot or cosine",
                )));
            }
            Order::LargeBetter
        }
    };
    let with_vector = search.with_vector.clone().unwrap_or_default();
    if with_vector.is_enabled() {
        return Err(StorageError::bad_input(format!(
            "cannot return encrypted vector '{vector_name}'; CKKS vector ciphertext read path returns payload sidecar only",
        )));
    }
    if let Some(params) = search.params.as_ref()
        && !ckks_search_params_supported(params)
    {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' uses brute-force CKKS sidecar scoring and does not support HNSW, quantization, indexed_only, or ACORN search params",
        )));
    }

    let mut next_offset = None;
    let mut scored_by_id = std::collections::HashMap::<_, ScoredPoint>::new();
    const BATCH_SIZE: usize = 512;

    loop {
        let scroll_result = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: next_offset,
                    limit: Some(BATCH_SIZE),
                    filter: search.filter.clone(),
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: WithVector::Bool(false),
                    order_by: None,
                },
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;

        let mut encrypted_records = Vec::new();
        for record in scroll_result.points {
            let Some(payload) = record.payload.as_ref() else {
                continue;
            };
            let Some(encrypted) = encrypted_vector_from_payload(payload, vector_name)? else {
                continue;
            };
            let point_id = record.id.to_string();
            encrypted_records.push((record.id, record.shard_key, point_id, encrypted));
        }

        if !encrypted_records.is_empty() {
            let encrypted_items = encrypted_records
                .iter()
                .map(|(_, _, point_id, encrypted)| (point_id.clone(), encrypted.clone()))
                .collect::<Vec<_>>();
            let scores = match &scoring {
                CkksSidecarScoring::Nearest { query_values } => plan
                    .score_plaintext_query_batch(
                        collection_name,
                        vector_name,
                        &encrypted_items,
                        query_values,
                    )?
                    .ok_or_else(|| {
                        StorageError::service_error(format!(
                            "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                        ))
                    })?,
                CkksSidecarScoring::RecommendBestScore {
                    positives,
                    negatives,
                } => {
                    let mut positive_scores = vec![f32::NEG_INFINITY; encrypted_items.len()];
                    for query_values in positives {
                        let batch_scores = plan
                            .score_plaintext_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                query_values,
                            )?
                            .ok_or_else(|| {
                                StorageError::service_error(format!(
                                    "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                                ))
                            })?;
                        for (current, score) in positive_scores.iter_mut().zip(batch_scores) {
                            *current = current.max(score);
                        }
                    }

                    let mut negative_scores = vec![f32::NEG_INFINITY; encrypted_items.len()];
                    for query_values in negatives {
                        let batch_scores = plan
                            .score_plaintext_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                query_values,
                            )?
                            .ok_or_else(|| {
                                StorageError::service_error(format!(
                                    "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                                ))
                            })?;
                        for (current, score) in negative_scores.iter_mut().zip(batch_scores) {
                            *current = current.max(score);
                        }
                    }

                    positive_scores
                        .into_iter()
                        .zip(negative_scores)
                        .map(|(positive, negative)| {
                            if positive > negative {
                                scaled_fast_sigmoid(positive)
                            } else {
                                -scaled_fast_sigmoid(negative)
                            }
                        })
                        .collect()
                }
                CkksSidecarScoring::RecommendSumScores {
                    positives,
                    negatives,
                } => {
                    let mut total_scores = vec![0.0; encrypted_items.len()];
                    for query_values in positives {
                        let batch_scores = plan
                            .score_plaintext_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                query_values,
                            )?
                            .ok_or_else(|| {
                                StorageError::service_error(format!(
                                    "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                                ))
                            })?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total += score;
                        }
                    }
                    for query_values in negatives {
                        let batch_scores = plan
                            .score_plaintext_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                query_values,
                            )?
                            .ok_or_else(|| {
                                StorageError::service_error(format!(
                                    "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                                ))
                            })?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total -= score;
                        }
                    }
                    total_scores
                }
                CkksSidecarScoring::Discover { target, pairs } => {
                    let target_scores = plan
                        .score_plaintext_query_batch(
                            collection_name,
                            vector_name,
                            &encrypted_items,
                            target,
                        )?
                        .ok_or_else(|| {
                            StorageError::service_error(format!(
                                "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                            ))
                        })?;
                    let mut rank_scores = vec![0i32; encrypted_items.len()];
                    for (positive, negative) in pairs {
                        let positive_scores = plan
                            .score_plaintext_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                positive,
                            )?
                            .ok_or_else(|| {
                                StorageError::service_error(format!(
                                    "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                                ))
                            })?;
                        let negative_scores = plan
                            .score_plaintext_query_batch(
                                collection_name,
                                vector_name,
                                &encrypted_items,
                                negative,
                            )?
                            .ok_or_else(|| {
                                StorageError::service_error(format!(
                                    "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                                ))
                            })?;
                        for ((rank, positive), negative) in rank_scores
                            .iter_mut()
                            .zip(positive_scores)
                            .zip(negative_scores)
                        {
                            *rank += match positive.total_cmp(&negative) {
                                std::cmp::Ordering::Greater => 1,
                                std::cmp::Ordering::Less => -1,
                                std::cmp::Ordering::Equal => 0,
                            };
                        }
                    }
                    target_scores
                        .into_iter()
                        .zip(rank_scores)
                        .map(|(target_score, rank)| {
                            rank as f32 + scaled_fast_sigmoid(target_score)
                        })
                        .collect()
                }
            };
            for ((id, shard_key, _point_id, _encrypted), score) in
                encrypted_records.into_iter().zip(scores)
            {
                if !ckks_score_passes_threshold(score_order, score, search.score_threshold) {
                    continue;
                }
                let scored_point = ScoredPoint {
                    id,
                    version: 0,
                    score,
                    payload: None,
                    vector: None,
                    shard_key,
                    order_value: None,
                };
                match scored_by_id.entry(scored_point.id) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        if ckks_scored_point_is_better(score_order, &scored_point, entry.get()) {
                            entry.insert(scored_point);
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(scored_point);
                    }
                }
            }
        }

        let Some(offset) = scroll_result.next_page_offset else {
            break;
        };
        next_offset = Some(offset);
    }

    let mut scored = scored_by_id.into_values().collect::<Vec<_>>();
    sort_ckks_scored_points(score_order, &mut scored);
    let mut top = scored
        .into_iter()
        .skip(search.offset)
        .take(search.limit)
        .collect::<Vec<_>>();

    let with_payload = search
        .with_payload
        .clone()
        .unwrap_or(WithPayloadInterface::Bool(false));
    if top.is_empty() || (!with_payload.is_required() && !with_vector.is_enabled()) {
        return Ok(top);
    }

    let records = collection
        .retrieve(
            PointRequestInternal {
                ids: top.iter().map(|point| point.id).collect(),
                with_payload: Some(with_payload),
                with_vector,
            },
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc,
        )
        .await?;
    let mut records_by_id = records
        .into_iter()
        .map(|record| (record.id, record))
        .collect::<std::collections::HashMap<_, _>>();
    for point in &mut top {
        if let Some(record) = records_by_id.remove(&point.id) {
            point.payload = record.payload;
            point.vector = record.vector;
            point.shard_key = record.shard_key.or_else(|| point.shard_key.clone());
        }
    }

    Ok(top)
}

fn ckks_score_passes_threshold(order: Order, score: f32, score_threshold: Option<f32>) -> bool {
    score_threshold.is_none_or(|threshold| match order {
        Order::LargeBetter => score > threshold,
        Order::SmallBetter => score < threshold,
    })
}

fn ckks_scored_point_is_better(
    order: Order,
    candidate: &ScoredPoint,
    current: &ScoredPoint,
) -> bool {
    match order {
        Order::LargeBetter => ScoredPointTies(candidate) > ScoredPointTies(current),
        Order::SmallBetter => ScoredPointTies(candidate) < ScoredPointTies(current),
    }
}

fn sort_ckks_scored_points(order: Order, scored: &mut [ScoredPoint]) {
    scored.sort_unstable_by(|a, b| match order {
        Order::LargeBetter => ScoredPointTies(b).cmp(&ScoredPointTies(a)),
        Order::SmallBetter => ScoredPointTies(a).cmp(&ScoredPointTies(b)),
    });
}

fn query_vectors_as_dense_slices<'a>(
    vectors: &'a [VectorInternal],
    vector_name: &str,
    role: &str,
) -> Result<Vec<&'a [f32]>, StorageError> {
    vectors
        .iter()
        .map(|vector| match vector {
            VectorInternal::Dense(values) => Ok(values.as_slice()),
            _ => Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' recommend only supports raw dense {role} examples",
            ))),
        })
        .collect()
}

fn query_context_pairs_as_dense_slices<'a>(
    pairs: &'a [ContextPair<VectorInternal>],
    vector_name: &str,
) -> Result<Vec<(&'a [f32], &'a [f32])>, StorageError> {
    pairs
        .iter()
        .map(|pair| {
            let VectorInternal::Dense(positive) = &pair.positive else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' discover only supports raw dense positive context examples",
                )));
            };
            let VectorInternal::Dense(negative) = &pair.negative else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' discover only supports raw dense negative context examples",
                )));
            };
            Ok((positive.as_slice(), negative.as_slice()))
        })
        .collect()
}

fn ckks_search_params_supported(params: &SearchParams) -> bool {
    params.hnsw_ef.is_none()
        && params.quantization.is_none()
        && !params.indexed_only
        && params.acorn.is_none()
}

fn encrypted_vector_from_payload(
    payload: &segment::types::Payload,
    vector_name: &str,
) -> Result<Option<EncryptedCkksVector>, StorageError> {
    let Some(sidecar) = payload
        .0
        .get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let Some(value) = sidecar.get(vector_name) else {
        return Ok(None);
    };
    let Some(marker) = value
        .as_object()
        .and_then(|object| object.get(ENCRYPTED_CKKS_VECTOR_MARKER))
    else {
        return Err(StorageError::service_error(format!(
            "stored CKKS vector sidecar entry '{vector_name}' is malformed",
        )));
    };
    serde_json::from_value(marker.clone())
        .map(Some)
        .map_err(|err| {
            StorageError::service_error(format!(
                "stored CKKS vector sidecar entry '{vector_name}' failed to parse: {err}",
            ))
        })
}

#[allow(clippy::too_many_arguments)]
pub async fn do_search_point_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: SearchGroupsRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<GroupsResult, StorageError> {
    if let Some(settings) = runtime_settings
        && let Some(result) = try_ckks_vector_search_groups(
            toc,
            collection_name,
            &request,
            read_consistency,
            &shard_selection,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
        )
        .await?
    {
        return Ok(result);
    }

    ensure_encrypted_vector_group_request_is_unsupported(
        toc,
        collection_name,
        search_group_vector_name(&request.vector),
        &auth,
    )
    .await?;

    toc.group(
        collection_name,
        GroupRequest::from(request),
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_search_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: &SearchGroupsRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
) -> Result<Option<GroupsResult>, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_search_groups",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let vector_name = search_group_vector_name(&request.vector);
    if !plan.contains_vector_name(vector_name) {
        return Ok(None);
    }
    if request.group_request.with_lookup.is_some() {
        return Err(StorageError::bad_input(format!(
            "cannot use with_lookup for grouped search over encrypted vector '{vector_name}'; CKKS sidecar grouped lookup is not implemented",
        )));
    }
    if request.with_vector.clone().unwrap_or_default().is_enabled() {
        return Err(StorageError::bad_input(format!(
            "cannot return encrypted vector '{vector_name}'; CKKS vector ciphertext read path returns payload sidecar only",
        )));
    }
    ensure_group_path_does_not_touch_encrypted_vector_sidecar(&request.group_request.group_by)?;

    let group_by = request.group_request.group_by.clone();
    let search_request = CoreSearchRequest::from(SearchRequestInternal {
        vector: request.vector.clone(),
        filter: request.filter.clone(),
        params: request.params.clone(),
        limit: usize::MAX,
        offset: Some(0),
        with_payload: Some(WithPayloadInterface::Bool(true)),
        with_vector: Some(WithVector::Bool(false)),
        score_threshold: request.score_threshold,
    });
    ckks_vector_group_points(
        &collection,
        collection_name,
        &search_request,
        &plan,
        &group_by,
        request.group_request.limit as usize,
        request.group_request.group_size as usize,
        request
            .with_payload
            .clone()
            .unwrap_or(WithPayloadInterface::Bool(false)),
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await
    .map(Some)
}

fn ensure_group_path_does_not_touch_encrypted_vector_sidecar(
    group_by: &JsonPath,
) -> Result<(), StorageError> {
    let Ok(sidecar_path) = ENCRYPTED_VECTOR_SIDECAR_FIELD.parse::<JsonPath>() else {
        return Ok(());
    };
    if group_by.compatible(&sidecar_path) {
        return Err(StorageError::bad_input(format!(
            "cannot group by encrypted vector sidecar field '{group_by}'; use a plaintext group field",
        )));
    }

    Ok(())
}

fn group_ckks_search_points(
    scored: Vec<ScoredPoint>,
    group_by: &JsonPath,
    group_limit: usize,
    group_size: usize,
) -> Vec<(GroupId, Vec<ScoredPoint>)> {
    let mut groups = Vec::<(GroupId, Vec<ScoredPoint>)>::new();
    for point in scored {
        let Some(payload) = point.payload.as_ref() else {
            continue;
        };
        let values = payload
            .get_value(group_by)
            .into_iter()
            .flat_map(|value| match value {
                serde_json::Value::Array(values) => values.iter().collect(),
                value => vec![value],
            });
        for value in values {
            let Ok(group_id) = GroupId::try_from(value) else {
                continue;
            };
            if let Some((_, hits)) = groups.iter_mut().find(|(id, _)| *id == group_id) {
                if hits.len() < group_size && !hits.iter().any(|hit| hit.id == point.id) {
                    hits.push(point.clone());
                }
                continue;
            }
            if groups.len() >= group_limit {
                continue;
            }
            groups.push((group_id, vec![point.clone()]));
        }
        if groups.len() >= group_limit && groups.iter().all(|(_, hits)| hits.len() >= group_size) {
            break;
        }
    }
    groups
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_group_points(
    collection: &collection::collection::Collection,
    collection_name: &str,
    search_request: &CoreSearchRequest,
    plan: &crate::common::crypto::VectorWritePlan,
    group_by: &JsonPath,
    group_limit: usize,
    group_size: usize,
    with_payload: WithPayloadInterface,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<GroupsResult, StorageError> {
    let scored = ckks_vector_search_points(
        collection,
        collection_name,
        search_request,
        plan,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;

    let grouped = group_ckks_search_points(scored, group_by, group_limit, group_size);
    let ids = grouped
        .iter()
        .flat_map(|(_, points)| points.iter().map(|point| point.id))
        .collect::<Vec<_>>();
    let records = if ids.is_empty() {
        Vec::new()
    } else {
        collection
            .retrieve(
                PointRequestInternal {
                    ids,
                    with_payload: Some(with_payload),
                    with_vector: WithVector::Bool(false),
                },
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await?
    };
    let records_by_id = records
        .into_iter()
        .map(|record| (record.id, record))
        .collect::<std::collections::HashMap<_, _>>();

    let groups = grouped
        .into_iter()
        .map(|(id, mut hits)| {
            for hit in &mut hits {
                if let Some(record) = records_by_id.get(&hit.id) {
                    hit.payload.clone_from(&record.payload);
                    hit.vector.clone_from(&record.vector);
                    hit.shard_key = record.shard_key.clone().or_else(|| hit.shard_key.clone());
                }
            }
            PointGroup {
                hits: hits.into_iter().map(api::rest::ScoredPoint::from).collect(),
                id,
                lookup: None,
            }
        })
        .collect();

    Ok(GroupsResult { groups })
}

#[allow(clippy::too_many_arguments)]
pub async fn do_recommend_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: RecommendRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let results = do_recommend_batch_points(
        toc,
        collection_name,
        vec![(request, shard_selection)],
        read_consistency,
        auth,
        timeout,
        hw_measurement_acc,
        runtime_settings,
    )
    .await?;
    results
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::service_error("Empty recommend result"))
}

#[allow(clippy::too_many_arguments)]
pub async fn do_recommend_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    requests: Vec<(RecommendRequestInternal, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    if let Some(settings) = runtime_settings
        && let Some(results) = try_ckks_vector_recommend_batch_points(
            toc,
            collection_name,
            &requests,
            read_consistency,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
        )
        .await?
    {
        return Ok(results);
    }

    toc.recommend_batch(
        collection_name,
        requests,
        read_consistency,
        auth,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_recommend_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    requests: &[(RecommendRequestInternal, ShardSelectorInternal)],
    read_consistency: Option<ReadConsistency>,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
) -> Result<Option<Vec<Vec<ScoredPoint>>>, StorageError> {
    if requests.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_recommend",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let mut has_encrypted_recommend = false;
    let mut has_plain_recommend = false;
    let mut core_requests = Vec::with_capacity(requests.len());
    for (request, shard_selection) in requests {
        let vector_name = recommend_vector_name(request);
        if !plan.contains_vector_name(&vector_name) {
            has_plain_recommend = true;
            core_requests.push(None);
            continue;
        }

        has_encrypted_recommend = true;
        core_requests.push(Some((
            recommend_request_as_ckks_search_request(request, &vector_name)?,
            shard_selection.clone(),
        )));
    }

    if !has_encrypted_recommend {
        return Ok(None);
    }
    if has_plain_recommend {
        return Err(StorageError::bad_input(
            "cannot mix CKKS encrypted vector recommend with plaintext vector recommend in the same batch",
        ));
    }

    let mut results = Vec::with_capacity(core_requests.len());
    for request in core_requests {
        let Some((request, shard_selection)) = request else {
            unreachable!("plain recommend was rejected above");
        };
        results.push(
            ckks_vector_search_points(
                &collection,
                collection_name,
                &request,
                &plan,
                read_consistency,
                &shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?,
        );
    }

    Ok(Some(results))
}

fn recommend_request_as_ckks_search_request(
    request: &RecommendRequestInternal,
    vector_name: &str,
) -> Result<CoreSearchRequest, StorageError> {
    if request.lookup_from.is_some() {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' recommend does not support lookup_from or point-id examples; provide raw dense vectors",
        )));
    }
    let positive = recommend_examples_as_dense_vectors(&request.positive, vector_name, "positive")?;
    let negative = recommend_examples_as_dense_vectors(&request.negative, vector_name, "negative")?;
    let query = match request.strategy.unwrap_or_default() {
        RecommendStrategy::AverageVector => {
            let search_vector = avg_vector_for_recommendation(
                positive.iter().map(VectorRef::from),
                negative.iter().map(VectorRef::from).peekable(),
            )
            .map_err(|err| StorageError::bad_input(err.to_string()))?;
            QueryEnum::Nearest(NamedQuery::new(search_vector, vector_name.to_string()))
        }
        RecommendStrategy::BestScore => QueryEnum::RecommendBestScore(NamedQuery::new(
            segment::vector_storage::query::RecoQuery::new(positive, negative),
            vector_name.to_string(),
        )),
        RecommendStrategy::SumScores => QueryEnum::RecommendSumScores(NamedQuery::new(
            segment::vector_storage::query::RecoQuery::new(positive, negative),
            vector_name.to_string(),
        )),
    };

    Ok(CoreSearchRequest {
        query,
        filter: request.filter.clone(),
        params: request.params.clone(),
        limit: request.limit,
        offset: request.offset.unwrap_or_default(),
        with_payload: request.with_payload.clone(),
        with_vector: request.with_vector.clone(),
        score_threshold: request.score_threshold,
    })
}

fn recommend_examples_as_dense_vectors(
    examples: &[RecommendExample],
    vector_name: &str,
    role: &str,
) -> Result<Vec<VectorInternal>, StorageError> {
    examples
        .iter()
        .map(|example| match example {
            RecommendExample::Dense(vector) => Ok(VectorInternal::Dense(vector.clone())),
            RecommendExample::Sparse(_) => Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' recommend only supports raw dense {role} examples",
            ))),
            RecommendExample::PointId(_) => Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' recommend cannot resolve point-id {role} examples because plaintext vectors are not stored",
            ))),
        })
        .collect()
}

fn recommend_vector_name(request: &RecommendRequestInternal) -> String {
    request
        .using
        .as_ref()
        .map(UsingVector::as_name)
        .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string())
}

#[allow(clippy::too_many_arguments)]
pub async fn do_recommend_point_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: RecommendGroupsRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<GroupsResult, StorageError> {
    if let Some(settings) = runtime_settings
        && let Some(result) = try_ckks_vector_recommend_groups(
            toc,
            collection_name,
            &request,
            read_consistency,
            &shard_selection,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
        )
        .await?
    {
        return Ok(result);
    }

    let vector_name = request
        .using
        .as_ref()
        .map(UsingVector::as_name)
        .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string());
    ensure_encrypted_vector_group_request_is_unsupported(toc, collection_name, &vector_name, &auth)
        .await?;

    toc.group(
        collection_name,
        GroupRequest::from(request),
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_recommend_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: &RecommendGroupsRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
) -> Result<Option<GroupsResult>, StorageError> {
    let vector_name = request
        .using
        .as_ref()
        .map(UsingVector::as_name)
        .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string());
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_recommend_groups",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };
    if !plan.contains_vector_name(&vector_name) {
        return Ok(None);
    }

    let recommend_request = RecommendRequestInternal {
        positive: request.positive.clone(),
        negative: request.negative.clone(),
        strategy: request.strategy,
        filter: request.filter.clone(),
        params: request.params.clone(),
        limit: usize::MAX,
        offset: Some(0),
        with_payload: Some(WithPayloadInterface::Bool(true)),
        with_vector: Some(WithVector::Bool(false)),
        score_threshold: request.score_threshold,
        using: request.using.clone(),
        lookup_from: request.lookup_from.clone(),
    };
    let core_request = recommend_request_as_ckks_search_request(&recommend_request, &vector_name)?;
    if request.group_request.with_lookup.is_some() {
        return Err(StorageError::bad_input(format!(
            "cannot use with_lookup for grouped recommend over encrypted vector '{vector_name}'; CKKS sidecar grouped lookup is not implemented",
        )));
    }
    if request.with_vector.clone().unwrap_or_default().is_enabled() {
        return Err(StorageError::bad_input(format!(
            "cannot return encrypted vector '{vector_name}'; CKKS vector ciphertext read path returns payload sidecar only",
        )));
    }
    ensure_group_path_does_not_touch_encrypted_vector_sidecar(&request.group_request.group_by)?;

    ckks_vector_group_points(
        &collection,
        collection_name,
        &core_request,
        &plan,
        &request.group_request.group_by,
        request.group_request.limit as usize,
        request.group_request.group_size as usize,
        request
            .with_payload
            .clone()
            .unwrap_or(WithPayloadInterface::Bool(false)),
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await
    .map(Some)
}

#[allow(clippy::too_many_arguments)]
pub async fn do_discover_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: DiscoverRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let results = do_discover_batch_points(
        toc,
        collection_name,
        vec![(request, shard_selection)],
        read_consistency,
        auth,
        timeout,
        hw_measurement_acc,
        runtime_settings,
    )
    .await?;
    results
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::service_error("Empty discover result"))
}

pub async fn do_discover_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    requests: Vec<(DiscoverRequestInternal, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    if let Some(settings) = runtime_settings
        && let Some(results) = try_ckks_vector_discover_batch_points(
            toc,
            collection_name,
            &requests,
            read_consistency,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
        )
        .await?
    {
        return Ok(results);
    }

    toc.discover_batch(
        collection_name,
        requests,
        read_consistency,
        auth,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_discover_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    requests: &[(DiscoverRequestInternal, ShardSelectorInternal)],
    read_consistency: Option<ReadConsistency>,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
) -> Result<Option<Vec<Vec<ScoredPoint>>>, StorageError> {
    if requests.is_empty() {
        return Ok(Some(Vec::new()));
    }

    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_discover",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let mut has_encrypted_discover = false;
    let mut has_plain_discover = false;
    let mut core_requests = Vec::with_capacity(requests.len());
    for (request, shard_selection) in requests {
        let vector_name = discover_vector_name(request);
        if !plan.contains_vector_name(&vector_name) {
            has_plain_discover = true;
            core_requests.push(None);
            continue;
        }

        has_encrypted_discover = true;
        core_requests.push(Some((
            discover_request_as_ckks_search_request(request, &vector_name)?,
            shard_selection.clone(),
        )));
    }

    if !has_encrypted_discover {
        return Ok(None);
    }
    if has_plain_discover {
        return Err(StorageError::bad_input(
            "cannot mix CKKS encrypted vector discover with plaintext vector discover in the same batch",
        ));
    }

    let mut results = Vec::with_capacity(core_requests.len());
    for request in core_requests {
        let Some((request, shard_selection)) = request else {
            unreachable!("plain discover was rejected above");
        };
        results.push(
            ckks_vector_search_points(
                &collection,
                collection_name,
                &request,
                &plan,
                read_consistency,
                &shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?,
        );
    }

    Ok(Some(results))
}

fn discover_request_as_ckks_search_request(
    request: &DiscoverRequestInternal,
    vector_name: &str,
) -> Result<CoreSearchRequest, StorageError> {
    if request.lookup_from.is_some() {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' discover does not support lookup_from or point-id examples; provide a raw dense target vector",
        )));
    }
    let Some(target) = request.target.as_ref() else {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' discover requires a raw dense target vector",
        )));
    };
    let RecommendExample::Dense(query_values) = target else {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' discover cannot resolve point-id or sparse target examples because plaintext vectors are not stored",
        )));
    };
    let pairs = request
        .context
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|pair| {
            let RecommendExample::Dense(positive) = &pair.positive else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' discover cannot resolve point-id or sparse positive context examples because plaintext vectors are not stored",
                )));
            };
            let RecommendExample::Dense(negative) = &pair.negative else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' discover cannot resolve point-id or sparse negative context examples because plaintext vectors are not stored",
                )));
            };
            Ok(ContextPair {
                positive: VectorInternal::Dense(positive.clone()),
                negative: VectorInternal::Dense(negative.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CoreSearchRequest {
        query: QueryEnum::Discover(NamedQuery::new(
            segment::vector_storage::query::DiscoverQuery::new(
                VectorInternal::Dense(query_values.clone()),
                pairs,
            ),
            vector_name.to_string(),
        )),
        filter: request.filter.clone(),
        params: request.params.clone(),
        limit: request.limit,
        offset: request.offset.unwrap_or_default(),
        with_payload: request.with_payload.clone(),
        with_vector: request.with_vector.clone(),
        score_threshold: None,
    })
}

fn discover_vector_name(request: &DiscoverRequestInternal) -> String {
    request
        .using
        .as_ref()
        .map(UsingVector::as_name)
        .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string())
}

#[allow(clippy::too_many_arguments)]
pub async fn do_count_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: CountRequestInternal,
    read_consistency: Option<ReadConsistency>,
    timeout: Option<Duration>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CountResult, StorageError> {
    toc.count(
        collection_name,
        request,
        read_consistency,
        timeout,
        shard_selection,
        auth,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn do_get_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: PointRequestInternal,
    read_consistency: Option<ReadConsistency>,
    timeout: Option<Duration>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<RecordInternal>, StorageError> {
    toc.retrieve(
        collection_name,
        request,
        read_consistency,
        timeout,
        shard_selection,
        auth,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn do_scroll_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: ScrollRequestInternal,
    read_consistency: Option<ReadConsistency>,
    timeout: Option<Duration>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<ScrollResult, StorageError> {
    toc.scroll(
        collection_name,
        request,
        read_consistency,
        timeout,
        shard_selection,
        auth,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn do_query_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: CollectionQueryRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let requests = vec![(request, shard_selection)];
    let batch_res = do_query_batch_points(
        toc,
        collection_name,
        requests,
        read_consistency,
        auth,
        timeout,
        hw_measurement_acc,
        runtime_settings,
    )
    .await?;
    batch_res
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::service_error("Empty query result"))
}

#[allow(clippy::too_many_arguments)]
pub async fn do_query_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    requests: Vec<(CollectionQueryRequest, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    if let Some(settings) = runtime_settings {
        let collection_pass = auth.check_collection_access(
            collection_name,
            AccessRequirements::new(),
            "ckks_vector_query",
        )?;
        let collection = toc.get_collection(&collection_pass).await?;
        let config = collection.config_snapshot().await;
        let collection_crypto_id = config.stable_crypto_id(collection_name)?;
        if let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
            settings,
            collection_name,
            &collection_crypto_id,
            &config.params,
        )? {
            let mut has_encrypted_query = false;
            let mut has_plain_query = false;
            let mut core_requests = Vec::with_capacity(requests.len());

            for (request, shard_selection) in &requests {
                let mut prefetches = request.prefetch.iter().collect::<Vec<_>>();
                while let Some(prefetch) = prefetches.pop() {
                    if plan.contains_vector_name(&prefetch.using) {
                        return Err(StorageError::bad_input(format!(
                            "encrypted vector '{}' only supports root nearest-neighbor dense query; prefetch/fusion/MMR over CKKS ciphertext are not implemented",
                            prefetch.using,
                        )));
                    }
                    prefetches.extend(prefetch.prefetch.iter());
                }

                if !plan.contains_vector_name(&request.using) {
                    has_plain_query = true;
                    core_requests.push(None);
                    continue;
                }

                has_encrypted_query = true;
                if !request.prefetch.is_empty() {
                    return Err(StorageError::bad_input(format!(
                        "encrypted vector '{}' only supports root nearest-neighbor dense query; prefetch/fusion/MMR over CKKS ciphertext are not implemented",
                        request.using,
                    )));
                }
                if request.lookup_from.is_some() {
                    return Err(StorageError::bad_input(format!(
                        "encrypted vector '{}' query does not support lookup_from; provide a plaintext dense query vector",
                        request.using,
                    )));
                }
                let query = ckks_query_as_core_query(&request.query, &request.using)?;

                core_requests.push(Some((
                    CoreSearchRequest {
                        query,
                        filter: request.filter.clone(),
                        params: request.params.clone(),
                        limit: request.limit,
                        offset: request.offset,
                        with_payload: Some(request.with_payload.clone()),
                        with_vector: Some(request.with_vector.clone()),
                        score_threshold: request.score_threshold,
                    },
                    shard_selection.clone(),
                )));
            }

            if has_encrypted_query {
                if has_plain_query {
                    return Err(StorageError::bad_input(
                        "cannot mix CKKS encrypted vector query with plaintext vector query in the same batch",
                    ));
                }

                let mut results = Vec::with_capacity(core_requests.len());
                for request in core_requests {
                    let Some((request, shard_selection)) = request else {
                        unreachable!("plain query was rejected above");
                    };
                    results.push(
                        ckks_vector_search_points(
                            &collection,
                            collection_name,
                            &request,
                            &plan,
                            read_consistency,
                            &shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?,
                    );
                }
                return Ok(results);
            }
        }
    }

    toc.query_batch(
        collection_name,
        requests,
        read_consistency,
        auth,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn do_query_point_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: CollectionQueryGroupsRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<GroupsResult, StorageError> {
    if let Some(settings) = runtime_settings
        && let Some(result) = try_ckks_vector_query_groups(
            toc,
            collection_name,
            &request,
            read_consistency,
            &shard_selection,
            &auth,
            timeout,
            hw_measurement_acc.clone(),
            settings,
        )
        .await?
    {
        return Ok(result);
    }

    ensure_encrypted_vector_group_request_is_unsupported(
        toc,
        collection_name,
        &request.using,
        &auth,
    )
    .await?;
    let mut prefetches: Vec<&CollectionPrefetch> = request.prefetch.iter().collect();
    while let Some(prefetch) = prefetches.pop() {
        ensure_encrypted_vector_group_request_is_unsupported(
            toc,
            collection_name,
            &prefetch.using,
            &auth,
        )
        .await?;
        prefetches.extend(prefetch.prefetch.iter());
    }

    toc.group(
        collection_name,
        GroupRequest::from(request),
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn try_ckks_vector_query_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: &CollectionQueryGroupsRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: &Settings,
) -> Result<Option<GroupsResult>, StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "ckks_vector_query_groups",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
        runtime_settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?
    else {
        return Ok(None);
    };

    let mut prefetches = request.prefetch.iter().collect::<Vec<_>>();
    while let Some(prefetch) = prefetches.pop() {
        if plan.contains_vector_name(&prefetch.using) {
            return Err(StorageError::bad_input(format!(
                "encrypted vector '{}' only supports root nearest-neighbor dense query groups; prefetch/fusion/MMR over CKKS ciphertext are not implemented",
                prefetch.using,
            )));
        }
        prefetches.extend(prefetch.prefetch.iter());
    }
    if !plan.contains_vector_name(&request.using) {
        return Ok(None);
    }
    if !request.prefetch.is_empty() {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{}' only supports root nearest-neighbor dense query groups; prefetch/fusion/MMR over CKKS ciphertext are not implemented",
            request.using,
        )));
    }
    if request.lookup_from.is_some() {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{}' query groups do not support lookup_from; provide a plaintext dense query vector",
            request.using,
        )));
    }
    if request.with_lookup.is_some() {
        return Err(StorageError::bad_input(format!(
            "cannot use with_lookup for grouped query over encrypted vector '{}'; CKKS sidecar grouped lookup is not implemented",
            request.using,
        )));
    }

    let search_request = CoreSearchRequest {
        query: ckks_query_as_core_query(&request.query, &request.using)?,
        filter: request.filter.clone(),
        params: request.params.clone(),
        limit: usize::MAX,
        offset: 0,
        with_payload: Some(WithPayloadInterface::Bool(true)),
        with_vector: Some(WithVector::Bool(false)),
        score_threshold: request.score_threshold,
    };
    ensure_group_path_does_not_touch_encrypted_vector_sidecar(&request.group_by)?;
    ckks_vector_group_points(
        &collection,
        collection_name,
        &search_request,
        &plan,
        &request.group_by,
        request.limit,
        request.group_size,
        request.with_payload.clone(),
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await
    .map(Some)
}

fn ckks_query_as_core_query(
    query: &Option<Query>,
    vector_name: &str,
) -> Result<QueryEnum, StorageError> {
    match query {
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Vector(
            VectorInternal::Dense(query_values),
        )))) => Ok(QueryEnum::Nearest(NamedQuery::new(
            VectorInternal::Dense(query_values.clone()),
            vector_name.to_string(),
        ))),
        Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend))) => {
            ckks_recommend_query_as_dense_search_vector(recommend, vector_name).map(|values| {
                QueryEnum::Nearest(NamedQuery::new(
                    VectorInternal::Dense(values),
                    vector_name.to_string(),
                ))
            })
        }
        Some(Query::Vector(VectorQuery::RecommendBestScore(recommend))) => {
            ckks_recommend_query_as_core_recommend(recommend, vector_name).map(|query| {
                QueryEnum::RecommendBestScore(NamedQuery::new(query, vector_name.to_string()))
            })
        }
        Some(Query::Vector(VectorQuery::RecommendSumScores(recommend))) => {
            ckks_recommend_query_as_core_recommend(recommend, vector_name).map(|query| {
                QueryEnum::RecommendSumScores(NamedQuery::new(query, vector_name.to_string()))
            })
        }
        Some(Query::Vector(VectorQuery::Discover(discover))) => {
            ckks_discover_query_as_core_discover(discover, vector_name)
                .map(|query| QueryEnum::Discover(NamedQuery::new(query, vector_name.to_string())))
        }
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(_)))) => {
            Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' query cannot resolve point-id query vectors because plaintext vectors are not stored",
            )))
        }
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Vector(_)))) => {
            Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' only supports dense query vectors",
            )))
        }
        _ => Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' only supports nearest-neighbor dense query, raw-dense recommend, or raw-dense discover",
        ))),
    }
}

fn ckks_recommend_query_as_dense_search_vector(
    recommend: &segment::vector_storage::query::RecoQuery<VectorInputInternal>,
    vector_name: &str,
) -> Result<Vec<f32>, StorageError> {
    let positive = vector_inputs_as_dense_vectors(&recommend.positives, vector_name, "positive")?;
    let negative = vector_inputs_as_dense_vectors(&recommend.negatives, vector_name, "negative")?;
    let search_vector = avg_vector_for_recommendation(
        positive.iter().map(VectorRef::from),
        negative.iter().map(VectorRef::from).peekable(),
    )
    .map_err(|err| StorageError::bad_input(err.to_string()))?;
    let VectorInternal::Dense(query_values) = search_vector else {
        return Err(StorageError::service_error(
            "CKKS sidecar recommend query conversion produced non-dense query",
        ));
    };
    Ok(query_values)
}

fn vector_inputs_as_dense_vectors(
    inputs: &[VectorInputInternal],
    vector_name: &str,
    role: &str,
) -> Result<Vec<VectorInternal>, StorageError> {
    inputs
        .iter()
        .map(|input| match input {
            VectorInputInternal::Vector(VectorInternal::Dense(vector)) => {
                Ok(VectorInternal::Dense(vector.clone()))
            }
            VectorInputInternal::Vector(_) => Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' query only supports raw dense {role} examples",
            ))),
            VectorInputInternal::Id(_) => Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' query cannot resolve point-id {role} examples because plaintext vectors are not stored",
            ))),
        })
        .collect()
}

fn ckks_recommend_query_as_core_recommend(
    recommend: &segment::vector_storage::query::RecoQuery<VectorInputInternal>,
    vector_name: &str,
) -> Result<segment::vector_storage::query::RecoQuery<VectorInternal>, StorageError> {
    let positive = vector_inputs_as_dense_vectors(&recommend.positives, vector_name, "positive")?;
    let negative = vector_inputs_as_dense_vectors(&recommend.negatives, vector_name, "negative")?;
    Ok(segment::vector_storage::query::RecoQuery::new(
        positive, negative,
    ))
}

fn ckks_discover_query_as_core_discover(
    discover: &segment::vector_storage::query::DiscoverQuery<VectorInputInternal>,
    vector_name: &str,
) -> Result<segment::vector_storage::query::DiscoverQuery<VectorInternal>, StorageError> {
    let VectorInputInternal::Vector(VectorInternal::Dense(target)) = &discover.target else {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' discover cannot resolve point-id or non-dense target examples because plaintext vectors are not stored",
        )));
    };
    let pairs = discover
        .pairs
        .iter()
        .map(|pair| {
            let VectorInputInternal::Vector(VectorInternal::Dense(positive)) = &pair.positive else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' discover cannot resolve point-id or non-dense positive context examples because plaintext vectors are not stored",
                )));
            };
            let VectorInputInternal::Vector(VectorInternal::Dense(negative)) = &pair.negative else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' discover cannot resolve point-id or non-dense negative context examples because plaintext vectors are not stored",
                )));
            };
            Ok(ContextPair {
                positive: VectorInternal::Dense(positive.clone()),
                negative: VectorInternal::Dense(negative.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(segment::vector_storage::query::DiscoverQuery::new(
        VectorInternal::Dense(target.clone()),
        pairs,
    ))
}

fn search_group_vector_name(vector: &api::rest::NamedVectorStruct) -> &str {
    match vector {
        api::rest::NamedVectorStruct::Default(_) => DEFAULT_VECTOR_NAME,
        api::rest::NamedVectorStruct::Dense(vector) => &vector.name,
        api::rest::NamedVectorStruct::Sparse(vector) => &vector.name,
    }
}

async fn ensure_encrypted_vector_group_request_is_unsupported(
    toc: &TableOfContent,
    collection_name: &str,
    vector_name: &str,
    auth: &Auth,
) -> Result<(), StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "encrypted_vector_group_guard",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    if let Some(encryption) = config.params.effective_encryption() {
        for rule in &encryption.rules {
            let EncryptionSelector::VectorNames { names } = &rule.selector else {
                continue;
            };
            if names.iter().any(|name| name == vector_name) {
                return Err(StorageError::bad_input(format!(
                    "cannot group by search over encrypted vector '{vector_name}'; CKKS-native vector search is not implemented for grouped requests in this branch",
                )));
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn do_search_points_matrix(
    toc: &TableOfContent,
    collection_name: &str,
    request: CollectionSearchMatrixRequest,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CollectionSearchMatrixResponse, StorageError> {
    toc.search_points_matrix(
        collection_name,
        request,
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[cfg(test)]
mod tests {
    use segment::types::Distance;
    use serde_json::json;

    use super::*;

    fn scored_point(id: u64, score: f32) -> ScoredPoint {
        ScoredPoint {
            id: id.into(),
            version: 0,
            score,
            payload: None,
            vector: None,
            shard_key: None,
            order_value: None,
        }
    }

    fn scored_point_with_payload(id: u64, score: f32, payload: serde_json::Value) -> ScoredPoint {
        let mut point = scored_point(id, score);
        point.payload = Some(segment::types::Payload(
            payload.as_object().unwrap().clone(),
        ));
        point
    }

    #[test]
    fn ckks_sidecar_search_uses_distance_order_for_ranking() {
        let mut dot = vec![scored_point(1, 9.0), scored_point(2, 4.0)];
        sort_ckks_scored_points(Distance::Dot.distance_order(), &mut dot);
        assert_eq!(dot[0].id, 1.into());
        assert_eq!(dot[1].id, 2.into());

        let mut euclid = vec![scored_point(1, 9.0), scored_point(2, 4.0)];
        sort_ckks_scored_points(Distance::Euclid.distance_order(), &mut euclid);
        assert_eq!(euclid[0].id, 2.into());
        assert_eq!(euclid[1].id, 1.into());
    }

    #[test]
    fn ckks_sidecar_search_uses_distance_order_for_thresholds() {
        assert!(ckks_score_passes_threshold(
            Distance::Dot.distance_order(),
            9.0,
            Some(5.0)
        ));
        assert!(!ckks_score_passes_threshold(
            Distance::Dot.distance_order(),
            4.0,
            Some(5.0)
        ));

        assert!(ckks_score_passes_threshold(
            Distance::Euclid.distance_order(),
            4.0,
            Some(5.0)
        ));
        assert!(!ckks_score_passes_threshold(
            Distance::Euclid.distance_order(),
            9.0,
            Some(5.0)
        ));
    }

    #[test]
    fn ckks_sidecar_search_replaces_duplicates_using_distance_order() {
        assert!(ckks_scored_point_is_better(
            Distance::Dot.distance_order(),
            &scored_point(1, 9.0),
            &scored_point(1, 4.0),
        ));
        assert!(ckks_scored_point_is_better(
            Distance::Euclid.distance_order(),
            &scored_point(1, 4.0),
            &scored_point(1, 9.0),
        ));
    }

    #[test]
    fn ckks_sidecar_search_rejects_unsupported_search_params() {
        let exact_params = SearchParams {
            exact: true,
            ..SearchParams::default()
        };
        assert!(ckks_search_params_supported(&exact_params));

        let hnsw_params = SearchParams {
            hnsw_ef: Some(128),
            ..SearchParams::default()
        };
        assert!(!ckks_search_params_supported(&hnsw_params));

        let indexed_only_params = SearchParams {
            indexed_only: true,
            ..SearchParams::default()
        };
        assert!(!ckks_search_params_supported(&indexed_only_params));
    }

    #[test]
    fn ckks_sidecar_grouping_uses_ranked_group_order_and_size() {
        let group_by = "group".parse::<JsonPath>().unwrap();
        let groups = group_ckks_search_points(
            vec![
                scored_point_with_payload(1, 9.0, json!({ "group": "a" })),
                scored_point_with_payload(2, 8.0, json!({ "group": "a" })),
                scored_point_with_payload(3, 7.0, json!({ "group": "b" })),
                scored_point_with_payload(4, 6.0, json!({ "group": "c" })),
            ],
            &group_by,
            2,
            1,
        );

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0, GroupId::from("a"));
        assert_eq!(groups[0].1.len(), 1);
        assert_eq!(groups[0].1[0].id, 1.into());
        assert_eq!(groups[1].0, GroupId::from("b"));
        assert_eq!(groups[1].1[0].id, 3.into());
    }

    #[test]
    fn ckks_sidecar_grouping_allows_plain_group_path() {
        let group_by = "group".parse::<JsonPath>().unwrap();
        ensure_group_path_does_not_touch_encrypted_vector_sidecar(&group_by).unwrap();
    }
}
