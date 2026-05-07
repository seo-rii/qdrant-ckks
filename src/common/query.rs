use std::time::Duration;

use api::rest::SearchGroupsRequestInternal;
use collection::collection::distance_matrix::*;
use collection::common::batching::batch_requests;
use collection::grouping::group_by::GroupRequest;
use collection::operations::consistency_params::ReadConsistency;
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::types::*;
use collection::operations::universal_query::collection_query::*;
use common::counter::hardware_accumulator::HwMeasurementAcc;
use qdrant_sec::{
    ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector,
};
use segment::data_types::vectors::{Named, NamedQuery, VectorInternal};
use segment::types::{
    Distance, Order, ScoredPoint, SearchParams, WithPayloadInterface, WithVector,
};
use segment::utils::scored_point_ties::ScoredPointTies;
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
    let QueryEnum::Nearest(named_query) = &search.query else {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{}' only supports nearest-neighbor dense query search; recommend, discover, context, and MMR over CKKS ciphertext are not implemented",
            search.query.get_vector_name(),
        )));
    };
    let VectorInternal::Dense(query_values) = &named_query.query else {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{}' only supports dense query vectors",
            named_query.get_name(),
        )));
    };
    let vector_name = named_query.get_name();
    let distance = plan.distance_for_vector(vector_name).ok_or_else(|| {
        StorageError::service_error(format!(
            "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
        ))
    })?;
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
            let scores = plan
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
            for ((id, shard_key, _point_id, _encrypted), score) in
                encrypted_records.into_iter().zip(scores)
            {
                if !ckks_score_passes_threshold(distance, score, search.score_threshold) {
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
                        if ckks_scored_point_is_better(distance, &scored_point, entry.get()) {
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
    sort_ckks_scored_points(distance, &mut scored);
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

fn ckks_score_passes_threshold(
    distance: Distance,
    score: f32,
    score_threshold: Option<f32>,
) -> bool {
    score_threshold.is_none_or(|threshold| distance.check_threshold(score, threshold))
}

fn ckks_scored_point_is_better(
    distance: Distance,
    candidate: &ScoredPoint,
    current: &ScoredPoint,
) -> bool {
    match distance.distance_order() {
        Order::LargeBetter => ScoredPointTies(candidate) > ScoredPointTies(current),
        Order::SmallBetter => ScoredPointTies(candidate) < ScoredPointTies(current),
    }
}

fn sort_ckks_scored_points(distance: Distance, scored: &mut [ScoredPoint]) {
    scored.sort_unstable_by(|a, b| match distance.distance_order() {
        Order::LargeBetter => ScoredPointTies(b).cmp(&ScoredPointTies(a)),
        Order::SmallBetter => ScoredPointTies(a).cmp(&ScoredPointTies(b)),
    });
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
) -> Result<GroupsResult, StorageError> {
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
pub async fn do_recommend_point_groups(
    toc: &TableOfContent,
    collection_name: &str,
    request: RecommendGroupsRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<GroupsResult, StorageError> {
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

pub async fn do_discover_batch_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: DiscoverRequestBatch,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let requests = request
        .searches
        .into_iter()
        .map(|req| {
            let shard_selector = match req.shard_key {
                None => ShardSelectorInternal::All,
                Some(shard_key) => ShardSelectorInternal::from(shard_key),
            };

            (req.discover_request, shard_selector)
        })
        .collect();

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
                let Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Vector(
                    VectorInternal::Dense(query_values),
                )))) = &request.query
                else {
                    return Err(StorageError::bad_input(format!(
                        "encrypted vector '{}' only supports nearest-neighbor dense query vectors",
                        request.using,
                    )));
                };

                core_requests.push(Some((
                    CoreSearchRequest {
                        query: QueryEnum::Nearest(NamedQuery::new(
                            VectorInternal::Dense(query_values.clone()),
                            request.using.clone(),
                        )),
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
) -> Result<GroupsResult, StorageError> {
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

    #[test]
    fn ckks_sidecar_search_uses_distance_order_for_ranking() {
        let mut dot = vec![scored_point(1, 9.0), scored_point(2, 4.0)];
        sort_ckks_scored_points(Distance::Dot, &mut dot);
        assert_eq!(dot[0].id, 1.into());
        assert_eq!(dot[1].id, 2.into());

        let mut euclid = vec![scored_point(1, 9.0), scored_point(2, 4.0)];
        sort_ckks_scored_points(Distance::Euclid, &mut euclid);
        assert_eq!(euclid[0].id, 2.into());
        assert_eq!(euclid[1].id, 1.into());
    }

    #[test]
    fn ckks_sidecar_search_uses_distance_order_for_thresholds() {
        assert!(ckks_score_passes_threshold(Distance::Dot, 9.0, Some(5.0)));
        assert!(!ckks_score_passes_threshold(Distance::Dot, 4.0, Some(5.0)));

        assert!(ckks_score_passes_threshold(
            Distance::Euclid,
            4.0,
            Some(5.0)
        ));
        assert!(!ckks_score_passes_threshold(
            Distance::Euclid,
            9.0,
            Some(5.0)
        ));
    }

    #[test]
    fn ckks_sidecar_search_replaces_duplicates_using_distance_order() {
        assert!(ckks_scored_point_is_better(
            Distance::Dot,
            &scored_point(1, 9.0),
            &scored_point(1, 4.0),
        ));
        assert!(ckks_scored_point_is_better(
            Distance::Euclid,
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
}
