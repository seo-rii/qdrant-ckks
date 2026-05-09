use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime};

use api::rest::{RecommendStrategy, SearchGroupsRequestInternal, SearchRequestInternal};
use collection::collection::distance_matrix::*;
use collection::common::batching::batch_requests;
use collection::config::EncryptionSelector;
use collection::grouping::group_by::GroupRequest;
use collection::lookup::lookup_ids;
use collection::lookup::types::PseudoId;
use collection::operations::consistency_params::ReadConsistency;
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::types::*;
use collection::operations::universal_query::collection_query::*;
use collection::operations::universal_query::shard_query::FusionInternal;
use collection::recommendations::avg_vector_for_recommendation;
use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::math::scaled_fast_sigmoid;
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CKKS_SCHEME, ENCRYPTED_CKKS_VECTOR_MARKER,
    ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector,
};
use segment::common::reciprocal_rank_fusion::rrf_scoring;
use segment::common::score_fusion::{ScoreFusion, score_fusion};
use segment::data_types::groups::GroupId;
use segment::data_types::vectors::{
    DEFAULT_VECTOR_NAME, Named, NamedQuery, VectorInternal, VectorRef,
};
use segment::json_path::JsonPath;
use segment::types::{
    Filter, Order, PayloadContainer, PointIdType, ScoredPoint, SearchParams, ShardKey,
    WithPayloadInterface, WithVector,
};
use segment::utils::scored_point_ties::ScoredPointTies;
use segment::vector_storage::query::ContextPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shard::query::query_enum::QueryEnum;
use shard::retrieve::record_internal::RecordInternal;
use shard::scroll::ScrollRequestInternal;
use shard::search::CoreSearchRequestBatch;
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::rbac::{AccessRequirements, Auth};

use crate::common::crypto::vector_write_plan_for_collection_with_crypto_id;
use crate::settings::Settings;

#[derive(Clone)]
struct CkksSidecarSearchRecord {
    id: PointIdType,
    shard_key: Option<ShardKey>,
    point_id: String,
    encrypted: EncryptedCkksVector,
}

enum CkksSidecarScoring<'a> {
    Nearest {
        query_values: &'a [f32],
    },
    NearestResolved {
        query: CkksSidecarQuerySource<'a>,
    },
    StoredNearest {
        query_point_id: String,
        query_encrypted: EncryptedCkksVector,
    },
    NearestMmr {
        query: CkksSidecarQuerySource<'a>,
        lambda: f32,
        candidates_limit: usize,
    },
    RecommendAverageVectorResolved {
        positives: Vec<CkksSidecarQuerySource<'a>>,
        negatives: Vec<CkksSidecarQuerySource<'a>>,
    },
    RecommendBestScore {
        positives: Vec<&'a [f32]>,
        negatives: Vec<&'a [f32]>,
    },
    RecommendBestScoreResolved {
        positives: Vec<CkksSidecarQuerySource<'a>>,
        negatives: Vec<CkksSidecarQuerySource<'a>>,
    },
    RecommendSumScores {
        positives: Vec<&'a [f32]>,
        negatives: Vec<&'a [f32]>,
    },
    RecommendSumScoresResolved {
        positives: Vec<CkksSidecarQuerySource<'a>>,
        negatives: Vec<CkksSidecarQuerySource<'a>>,
    },
    Discover {
        target: &'a [f32],
        pairs: Vec<(&'a [f32], &'a [f32])>,
    },
    DiscoverResolved {
        target: CkksSidecarQuerySource<'a>,
        pairs: Vec<(CkksSidecarQuerySource<'a>, CkksSidecarQuerySource<'a>)>,
    },
    Context {
        pairs: Vec<(&'a [f32], &'a [f32])>,
    },
    ContextResolved {
        pairs: Vec<(CkksSidecarQuerySource<'a>, CkksSidecarQuerySource<'a>)>,
    },
}

enum CkksSidecarQuerySource<'a> {
    Dense(&'a [f32]),
    ClientEncrypted {
        context_digest: &'a str,
        slots: usize,
        ciphertext: Vec<u8>,
    },
    Stored {
        point_id: String,
        encrypted: EncryptedCkksVector,
    },
}

#[derive(Clone, Copy)]
enum CkksSidecarHnswQuery<'a> {
    Dense(&'a [f32]),
    ClientEncrypted {
        context_digest: &'a str,
        slots: usize,
        ciphertext: &'a [u8],
    },
    Stored {
        query_point_id: &'a str,
        query_encrypted: &'a EncryptedCkksVector,
    },
}

const CKKS_SIDECAR_HNSW_GRAPH_CACHE_CAPACITY: usize = 16;
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR: &str = "ckks_sidecar_hnsw_graphs";
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_VERSION: u8 = 1;
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES: u64 = 64 * 1024 * 1024;
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_FILES: usize = 32;
const CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

static CKKS_SIDECAR_HNSW_GRAPH_CACHE: LazyLock<Mutex<CkksSidecarHnswGraphCache>> =
    LazyLock::new(|| Mutex::new(CkksSidecarHnswGraphCache::default()));

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CkksSidecarHnswGraphCacheKey {
    collection_identity: String,
    vector_name: String,
    score_order: &'static str,
    m: usize,
    records_fingerprint: String,
}

#[derive(Clone, Debug)]
struct CkksSidecarHnswGraph {
    links: Arc<Vec<Vec<usize>>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CkksSidecarHnswGraphDisk {
    version: u8,
    collection_identity: String,
    vector_name: String,
    score_order: String,
    m: usize,
    records_fingerprint: String,
    links: Vec<Vec<usize>>,
}

#[derive(Default)]
struct CkksSidecarHnswGraphCache {
    entries: HashMap<CkksSidecarHnswGraphCacheKey, Arc<CkksSidecarHnswGraph>>,
    order: VecDeque<CkksSidecarHnswGraphCacheKey>,
}

impl CkksSidecarHnswGraphCache {
    fn get(&mut self, key: &CkksSidecarHnswGraphCacheKey) -> Option<Arc<CkksSidecarHnswGraph>> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: CkksSidecarHnswGraphCacheKey, graph: Arc<CkksSidecarHnswGraph>) {
        if self.entries.contains_key(&key) {
            self.entries.insert(key, graph);
            return;
        }

        while self.entries.len() >= CKKS_SIDECAR_HNSW_GRAPH_CACHE_CAPACITY {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&evicted);
        }

        self.order.push_back(key.clone());
        self.entries.insert(key, graph);
    }
}

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
        hw_measurement_acc.clone(),
        runtime_settings,
    )
    .await?;
    batch_res
        .into_iter()
        .next()
        .ok_or_else(|| StorageError::service_error("Empty search result"))
}

#[allow(clippy::too_many_arguments)]
pub async fn do_search_points(
    toc: &TableOfContent,
    collection_name: &str,
    request: SearchRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: ShardSelectorInternal,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<ScoredPoint>, StorageError> {
    if let Some(query_request) = ckks_legacy_search_as_query_request(&request) {
        return do_query_points(
            toc,
            collection_name,
            query_request,
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
            runtime_settings,
        )
        .await;
    }

    do_core_search_points(
        toc,
        collection_name,
        request.into(),
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc,
        runtime_settings,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn do_search_batch_points_from_rest(
    toc: &TableOfContent,
    collection_name: &str,
    requests: Vec<(SearchRequestInternal, ShardSelectorInternal)>,
    read_consistency: Option<ReadConsistency>,
    auth: Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let mut results = Vec::with_capacity(requests.len());
    for (request, shard_selection) in requests {
        results.push(
            do_search_points(
                toc,
                collection_name,
                request,
                read_consistency,
                shard_selection,
                auth.clone(),
                timeout,
                hw_measurement_acc.clone(),
                runtime_settings,
            )
            .await?,
        );
    }
    Ok(results)
}

#[allow(dead_code)]
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

fn ckks_legacy_search_as_query_request(
    request: &SearchRequestInternal,
) -> Option<CollectionQueryRequest> {
    let api::rest::NamedVectorStruct::CkksEncryptedQuery(query) = &request.vector else {
        return None;
    };
    Some(CollectionQueryRequest {
        prefetch: Vec::new(),
        query: Some(Query::Vector(VectorQuery::Nearest(
            VectorInputInternal::CkksEncryptedQuery(CkksEncryptedQueryInput {
                version: query.envelope.version,
                scheme: query.envelope.scheme.clone(),
                security_profile: query.envelope.security_profile.clone(),
                context_digest: query.envelope.context_digest.clone(),
                slots: query.envelope.slots,
                ciphertext: query.envelope.ciphertext.clone(),
            }),
        ))),
        using: query
            .name
            .clone()
            .unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_string()),
        filter: request.filter.clone(),
        score_threshold: request.score_threshold,
        limit: request.limit,
        offset: request.offset.unwrap_or_default(),
        params: request.params.clone(),
        with_vector: request.with_vector.clone().unwrap_or_default(),
        with_payload: request
            .with_payload
            .clone()
            .unwrap_or(WithPayloadInterface::Bool(false)),
        lookup_from: None,
    })
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

    for search in &request.searches {
        let with_vector = search.with_vector.clone().unwrap_or_default();
        ensure_with_vector_does_not_request_encrypted_vectors(
            toc,
            collection_name,
            &with_vector,
            &auth,
            "search",
        )
        .await?;
    }

    toc.core_search_batch(
        collection_name,
        request,
        read_consistency,
        shard_selection,
        auth,
        timeout,
        hw_measurement_acc.clone(),
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
    for search in &request.searches {
        if plan.contains_vector_name(search.query.get_vector_name()) {
            has_encrypted_search = true;
        }
    }

    if !has_encrypted_search {
        return Ok(None);
    }

    let mut results = Vec::with_capacity(request.searches.len());
    for search in &request.searches {
        if plan.contains_vector_name(search.query.get_vector_name()) {
            results.push(
                ckks_vector_search_points(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    search,
                    &plan,
                    read_consistency,
                    shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?,
            );
        } else {
            let with_vector = search.with_vector.clone().unwrap_or_default();
            ensure_with_vector_does_not_request_encrypted_vectors(
                toc,
                collection_name,
                &with_vector,
                auth,
                "search",
            )
            .await?;
            let mut plain_results = toc
                .core_search_batch(
                    collection_name,
                    CoreSearchRequestBatch {
                        searches: vec![search.clone()],
                    },
                    read_consistency,
                    shard_selection.clone(),
                    auth.clone(),
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?;
            results.push(plain_results.pop().ok_or_else(|| {
                StorageError::service_error(
                    "plaintext search result missing from mixed CKKS vector batch",
                )
            })?);
        }
    }

    Ok(Some(results))
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_search_points(
    collection: &collection::collection::Collection,
    collection_name: &str,
    collection_crypto_id: &str,
    search: &CoreSearchRequest,
    plan: &crate::common::crypto::VectorWritePlan,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<ScoredPoint>, StorageError> {
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
        QueryEnum::Context(named_query) => (
            named_query.get_name(),
            CkksSidecarScoring::Context {
                pairs: query_context_pairs_as_dense_slices(
                    &named_query.query.pairs,
                    named_query.get_name(),
                )?,
            },
        ),
        _ => {
            return Err(StorageError::bad_input(format!(
                "encrypted vector '{}' only supports dense nearest-neighbor search, raw-dense recommend, raw-dense discover, and raw-dense context over the CKKS sidecar",
                search.query.get_vector_name(),
            )));
        }
    };
    ckks_vector_search_points_with_scoring(
        collection,
        collection_name,
        collection_crypto_id,
        vector_name,
        scoring,
        search.filter.clone(),
        search.params.clone(),
        search.limit,
        search.offset,
        search.with_payload.clone(),
        search.with_vector.clone(),
        search.score_threshold,
        plan,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_search_points_with_scoring(
    collection: &collection::collection::Collection,
    collection_name: &str,
    collection_crypto_id: &str,
    vector_name: &str,
    scoring: CkksSidecarScoring<'_>,
    filter: Option<Filter>,
    params: Option<SearchParams>,
    limit: usize,
    offset: usize,
    with_payload: Option<WithPayloadInterface>,
    with_vector: Option<WithVector>,
    score_threshold: Option<f32>,
    plan: &crate::common::crypto::VectorWritePlan,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<ScoredPoint>, StorageError> {
    let distance = plan.distance_for_vector(vector_name).ok_or_else(|| {
        StorageError::service_error(format!(
            "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
        ))
    })?;
    let score_order = match &scoring {
        CkksSidecarScoring::Nearest { .. }
        | CkksSidecarScoring::NearestResolved { .. }
        | CkksSidecarScoring::StoredNearest { .. } => distance.distance_order(),
        CkksSidecarScoring::NearestMmr { .. } => {
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' MMR requires a large-better metric such as dot or cosine",
                )));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::RecommendAverageVectorResolved {
            positives,
            negatives: _,
        } => {
            if positives.is_empty() {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' average-vector recommend requires at least one positive example",
                )));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' average-vector point-id recommend requires a large-better metric such as dot or cosine",
                )));
            }
            Order::LargeBetter
        }
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
        CkksSidecarScoring::RecommendBestScoreResolved {
            positives,
            negatives,
        }
        | CkksSidecarScoring::RecommendSumScoresResolved {
            positives,
            negatives,
        } => {
            if positives.is_empty() && negatives.is_empty() {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' recommend requires at least one example",
                )));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' recommend best-score and sum-scores require a large-better metric such as dot or cosine",
                )));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::Discover { .. } | CkksSidecarScoring::DiscoverResolved { .. } => {
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' discover with sidecar scoring requires a large-better metric such as dot or cosine",
                )));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::Context { pairs } => {
            if pairs.is_empty() {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' context query requires at least one raw dense context pair",
                )));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' context query with sidecar scoring requires a large-better metric such as dot or cosine",
                )));
            }
            Order::LargeBetter
        }
        CkksSidecarScoring::ContextResolved { pairs } => {
            if pairs.is_empty() {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' context query requires at least one context pair",
                )));
            }
            if distance.distance_order() != Order::LargeBetter {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' context query with sidecar scoring requires a large-better metric such as dot or cosine",
                )));
            }
            Order::LargeBetter
        }
    };
    let with_vector = with_vector.unwrap_or_default();
    if with_vector.is_enabled() {
        return Err(StorageError::bad_input(format!(
            "cannot return encrypted vector '{vector_name}'; CKKS vector ciphertext read path returns payload sidecar only",
        )));
    }
    if let Some(params) = params.as_ref()
        && !ckks_search_params_supported(params)
    {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' uses CKKS sidecar scoring and does not support quantization, indexed_only, or ACORN search params",
        )));
    }
    let hnsw_ef = params
        .as_ref()
        .and_then(|params| (!params.exact).then_some(params.hnsw_ef).flatten());
    if hnsw_ef.is_some()
        && !matches!(
            &scoring,
            CkksSidecarScoring::Nearest { .. }
                | CkksSidecarScoring::StoredNearest { .. }
                | CkksSidecarScoring::NearestResolved {
                    query: CkksSidecarQuerySource::ClientEncrypted { .. },
                }
        )
    {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' HNSW sidecar search currently supports only dense, client-encrypted, or point-id nearest-neighbor queries",
        )));
    }

    let mut next_offset = None;
    let mut scored_by_id = std::collections::HashMap::<_, ScoredPoint>::new();
    let mut encrypted_by_id =
        std::collections::HashMap::<PointIdType, (String, EncryptedCkksVector)>::new();
    let mut hnsw_records = Vec::new();
    const BATCH_SIZE: usize = 512;

    loop {
        let scroll_result = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: next_offset,
                    limit: Some(BATCH_SIZE),
                    filter: filter.clone(),
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
            encrypted_records.push(CkksSidecarSearchRecord {
                id: record.id,
                shard_key: record.shard_key,
                point_id,
                encrypted,
            });
        }

        if hnsw_ef.is_some() {
            hnsw_records.extend(encrypted_records);
            let Some(offset) = scroll_result.next_page_offset else {
                break;
            };
            next_offset = Some(offset);
            continue;
        }

        if !encrypted_records.is_empty() {
            let encrypted_items = encrypted_records
                .iter()
                .map(|record| (record.point_id.clone(), record.encrypted.clone()))
                .collect::<Vec<_>>();
            let scores = match &scoring {
                CkksSidecarScoring::Nearest { query_values } => plan
                    .score_encrypted_query_batch(
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
                CkksSidecarScoring::NearestResolved { query } => {
                    ckks_score_query_source_batch(
                        collection_name,
                        vector_name,
                        plan,
                        query,
                        &encrypted_items,
                    )?
                }
                CkksSidecarScoring::StoredNearest {
                    query_point_id,
                    query_encrypted,
                } => plan
                    .score_stored_query_batch(
                        collection_name,
                        vector_name,
                        query_point_id,
                        query_encrypted,
                        &encrypted_items,
                    )?
                    .ok_or_else(|| {
                        StorageError::service_error(format!(
                            "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                        ))
                    })?,
                CkksSidecarScoring::NearestMmr { query, .. } => {
                    ckks_score_query_source_batch(
                        collection_name,
                        vector_name,
                        plan,
                        query,
                        &encrypted_items,
                    )?
                }
                CkksSidecarScoring::RecommendBestScore {
                    positives,
                    negatives,
                } => {
                    let mut positive_scores = vec![f32::NEG_INFINITY; encrypted_items.len()];
                    for query_values in positives {
                        let batch_scores = plan
                            .score_encrypted_query_batch(
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
                            .score_encrypted_query_batch(
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
                CkksSidecarScoring::RecommendAverageVectorResolved {
                    positives,
                    negatives,
                } => {
                    let mut total_scores = vec![0.0; encrypted_items.len()];
                    let positive_weight = 1.0 / positives.len() as f32;
                    for source in positives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total += score * positive_weight;
                        }
                    }
                    if !negatives.is_empty() {
                        let negative_weight = 1.0 / negatives.len() as f32;
                        for source in negatives {
                            let batch_scores = ckks_score_query_source_batch(
                                collection_name,
                                vector_name,
                                plan,
                                source,
                                &encrypted_items,
                            )?;
                            for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                                *total -= score * negative_weight;
                            }
                        }
                    }
                    total_scores
                }
                CkksSidecarScoring::RecommendBestScoreResolved {
                    positives,
                    negatives,
                } => {
                    let mut positive_scores = vec![f32::NEG_INFINITY; encrypted_items.len()];
                    for source in positives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
                        for (current, score) in positive_scores.iter_mut().zip(batch_scores) {
                            *current = current.max(score);
                        }
                    }

                    let mut negative_scores = vec![f32::NEG_INFINITY; encrypted_items.len()];
                    for source in negatives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
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
                            .score_encrypted_query_batch(
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
                            .score_encrypted_query_batch(
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
                CkksSidecarScoring::RecommendSumScoresResolved {
                    positives,
                    negatives,
                } => {
                    let mut total_scores = vec![0.0; encrypted_items.len()];
                    for source in positives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total += score;
                        }
                    }
                    for source in negatives {
                        let batch_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            source,
                            &encrypted_items,
                        )?;
                        for (total, score) in total_scores.iter_mut().zip(batch_scores) {
                            *total -= score;
                        }
                    }
                    total_scores
                }
                CkksSidecarScoring::Discover { target, pairs } => {
                    let target_scores = plan
                        .score_encrypted_query_batch(
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
                            .score_encrypted_query_batch(
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
                            .score_encrypted_query_batch(
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
                CkksSidecarScoring::DiscoverResolved { target, pairs } => {
                    let target_scores = ckks_score_query_source_batch(
                        collection_name,
                        vector_name,
                        plan,
                        target,
                        &encrypted_items,
                    )?;
                    let mut rank_scores = vec![0i32; encrypted_items.len()];
                    for (positive, negative) in pairs {
                        let positive_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            positive,
                            &encrypted_items,
                        )?;
                        let negative_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            negative,
                            &encrypted_items,
                        )?;
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
                CkksSidecarScoring::Context { pairs } => {
                    let mut rank_scores = vec![0i32; encrypted_items.len()];
                    for (positive, negative) in pairs {
                        let positive_scores = plan
                            .score_encrypted_query_batch(
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
                            .score_encrypted_query_batch(
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
                    rank_scores.into_iter().map(|rank| rank as f32).collect()
                }
                CkksSidecarScoring::ContextResolved { pairs } => {
                    let mut rank_scores = vec![0i32; encrypted_items.len()];
                    for (positive, negative) in pairs {
                        let positive_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            positive,
                            &encrypted_items,
                        )?;
                        let negative_scores = ckks_score_query_source_batch(
                            collection_name,
                            vector_name,
                            plan,
                            negative,
                            &encrypted_items,
                        )?;
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
                    rank_scores.into_iter().map(|rank| rank as f32).collect()
                }
            };
            for (record, score) in encrypted_records.into_iter().zip(scores) {
                if !ckks_score_passes_threshold(score_order, score, score_threshold) {
                    continue;
                }
                encrypted_by_id.insert(
                    record.id,
                    (record.point_id.clone(), record.encrypted.clone()),
                );
                let scored_point = ScoredPoint {
                    id: record.id,
                    version: 0,
                    score,
                    payload: None,
                    vector: None,
                    shard_key: record.shard_key,
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

    if let Some(hnsw_ef) = hnsw_ef {
        let hnsw_query = match &scoring {
            CkksSidecarScoring::Nearest { query_values } => {
                CkksSidecarHnswQuery::Dense(query_values)
            }
            CkksSidecarScoring::NearestResolved {
                query:
                    CkksSidecarQuerySource::ClientEncrypted {
                        context_digest,
                        slots,
                        ciphertext,
                    },
            } => CkksSidecarHnswQuery::ClientEncrypted {
                context_digest,
                slots: *slots,
                ciphertext,
            },
            CkksSidecarScoring::StoredNearest {
                query_point_id,
                query_encrypted,
            } => CkksSidecarHnswQuery::Stored {
                query_point_id,
                query_encrypted,
            },
            _ => unreachable!(
                "non-nearest or unsupported CKKS HNSW sidecar search was rejected before scrolling"
            ),
        };
        for scored_point in ckks_sidecar_hnsw_search_points(
            collection_name,
            collection_crypto_id,
            vector_name,
            collection.path(),
            plan,
            &hnsw_records,
            hnsw_query,
            score_order,
            score_threshold,
            hnsw_ef,
            offset.saturating_add(limit),
        )? {
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

    if let CkksSidecarScoring::NearestMmr {
        lambda,
        candidates_limit,
        ..
    } = &scoring
    {
        let mut candidates = scored_by_id.into_values().collect::<Vec<_>>();
        sort_ckks_scored_points(score_order, &mut candidates);
        candidates.truncate((*candidates_limit).max(limit));
        let mut selected = Vec::new();
        if !candidates.is_empty() && limit > 0 {
            selected.push(0usize);
            let mut remaining = (1..candidates.len()).collect::<Vec<_>>();
            while selected.len() < limit && !remaining.is_empty() {
                let mut best_position = 0usize;
                let mut best_score = f32::NEG_INFINITY;
                for (position, candidate_idx) in remaining.iter().copied().enumerate() {
                    let Some((candidate_point_id, candidate_encrypted)) =
                        encrypted_by_id.get(&candidates[candidate_idx].id)
                    else {
                        continue;
                    };
                    let candidate_item =
                        vec![(candidate_point_id.clone(), candidate_encrypted.clone())];
                    let mut max_similarity = f32::NEG_INFINITY;
                    for selected_idx in &selected {
                        let Some((selected_point_id, selected_encrypted)) =
                            encrypted_by_id.get(&candidates[*selected_idx].id)
                        else {
                            continue;
                        };
                        let similarity = plan
                            .score_stored_query_batch(
                                collection_name,
                                vector_name,
                                selected_point_id,
                                selected_encrypted,
                                &candidate_item,
                            )?
                            .ok_or_else(|| {
                                StorageError::service_error(format!(
                                    "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                                ))
                            })?
                            .into_iter()
                            .next()
                            .ok_or_else(|| {
                                StorageError::service_error(
                                    "CKKS MMR sidecar scoring returned no candidate score",
                                )
                            })?;
                        max_similarity = max_similarity.max(similarity);
                    }
                    let mmr_score = *lambda * candidates[candidate_idx].score
                        - (1.0 - *lambda) * max_similarity;
                    if mmr_score > best_score {
                        best_score = mmr_score;
                        best_position = position;
                    }
                }
                selected.push(remaining.swap_remove(best_position));
            }
        }

        let mut top = selected
            .into_iter()
            .filter_map(|idx| candidates.get(idx).cloned())
            .collect::<Vec<_>>();
        ckks_fill_scored_points_payload_or_vectors(
            collection,
            &mut top,
            with_payload.unwrap_or(WithPayloadInterface::Bool(false)),
            with_vector,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc,
        )
        .await?;

        return Ok(top);
    }

    let mut scored = scored_by_id.into_values().collect::<Vec<_>>();
    sort_ckks_scored_points(score_order, &mut scored);
    let mut top = scored
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    ckks_fill_scored_points_payload_or_vectors(
        collection,
        &mut top,
        with_payload.unwrap_or(WithPayloadInterface::Bool(false)),
        with_vector,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await?;

    Ok(top)
}

#[allow(clippy::too_many_arguments)]
async fn ckks_fill_scored_points_payload_or_vectors(
    collection: &collection::collection::Collection,
    points: &mut [ScoredPoint],
    with_payload: WithPayloadInterface,
    with_vector: WithVector,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<(), StorageError> {
    if points.is_empty() || (!with_payload.is_required() && !with_vector.is_enabled()) {
        return Ok(());
    }

    let records = collection
        .retrieve(
            PointRequestInternal {
                ids: points.iter().map(|point| point.id).collect(),
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
    for point in points {
        if let Some(record) = records_by_id.remove(&point.id) {
            point.payload = record.payload;
            point.vector = record.vector;
            point.shard_key = record.shard_key.or_else(|| point.shard_key.clone());
        }
    }

    Ok(())
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

fn ckks_sidecar_hnsw_add_bounded_undirected_link(
    links: &mut [Vec<usize>],
    first: usize,
    second: usize,
    max_degree: usize,
) {
    if first == second {
        return;
    }
    ckks_sidecar_hnsw_add_bounded_directed_link(links, first, second, max_degree);
    ckks_sidecar_hnsw_add_bounded_directed_link(links, second, first, max_degree);
}

fn ckks_sidecar_hnsw_add_bounded_directed_link(
    links: &mut [Vec<usize>],
    from: usize,
    to: usize,
    max_degree: usize,
) {
    let removed = {
        let neighbors = &mut links[from];
        if neighbors.contains(&to) {
            return;
        }
        neighbors.push(to);
        if neighbors.len() <= max_degree {
            return;
        }
        neighbors.remove(0)
    };
    links[removed].retain(|neighbor| *neighbor != from);
}

fn ckks_sidecar_hnsw_add_unbounded_undirected_link(
    links: &mut [Vec<usize>],
    first: usize,
    second: usize,
) {
    if first == second {
        return;
    }
    if !links[first].contains(&second) {
        links[first].push(second);
    }
    if !links[second].contains(&first) {
        links[second].push(first);
    }
}

fn ckks_sidecar_hnsw_add_connectivity_backbone(links: &mut [Vec<usize>]) {
    for idx in 1..links.len() {
        ckks_sidecar_hnsw_add_unbounded_undirected_link(links, idx - 1, idx);
    }
}

fn ckks_sidecar_hnsw_links_are_reciprocal(links: &[Vec<usize>]) -> bool {
    links.iter().enumerate().all(|(from, neighbors)| {
        let mut unique_neighbors = std::collections::HashSet::with_capacity(neighbors.len());
        neighbors.iter().all(|neighbor| {
            *neighbor < links.len()
                && unique_neighbors.insert(*neighbor)
                && links[*neighbor].iter().any(|candidate| *candidate == from)
        })
    })
}

fn ckks_sidecar_hnsw_links_are_connected(links: &[Vec<usize>]) -> bool {
    if links.is_empty() {
        return true;
    }

    let mut visited = vec![false; links.len()];
    let mut stack = vec![0usize];
    while let Some(idx) = stack.pop() {
        if visited[idx] {
            continue;
        }
        visited[idx] = true;
        for neighbor in &links[idx] {
            if !visited[*neighbor] {
                stack.push(*neighbor);
            }
        }
    }

    visited.into_iter().all(|seen| seen)
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

fn ckks_score_query_source_batch(
    collection_name: &str,
    vector_name: &str,
    plan: &crate::common::crypto::VectorWritePlan,
    source: &CkksSidecarQuerySource<'_>,
    encrypted_items: &[(String, EncryptedCkksVector)],
) -> Result<Vec<f32>, StorageError> {
    let scores = match source {
        CkksSidecarQuerySource::Dense(query_values) => plan.score_encrypted_query_batch(
            collection_name,
            vector_name,
            encrypted_items,
            query_values,
        )?,
        CkksSidecarQuerySource::ClientEncrypted {
            context_digest,
            slots,
            ciphertext,
        } => plan.score_client_encrypted_query_batch(
            collection_name,
            vector_name,
            encrypted_items,
            context_digest,
            *slots,
            ciphertext,
        )?,
        CkksSidecarQuerySource::Stored {
            point_id,
            encrypted,
        } => plan.score_stored_query_batch(
            collection_name,
            vector_name,
            point_id,
            encrypted,
            encrypted_items,
        )?,
    };

    scores.ok_or_else(|| {
        StorageError::service_error(format!(
            "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
        ))
    })
}

fn ckks_client_encrypted_query_source<'a>(
    vector_name: &str,
    input: &'a CkksEncryptedQueryInput,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    ckks_client_encrypted_query_source_from_parts(
        vector_name,
        input.version,
        &input.scheme,
        &input.security_profile,
        &input.context_digest,
        input.slots,
        &input.ciphertext,
    )
}

fn ckks_rest_client_encrypted_query_source<'a>(
    vector_name: &str,
    input: &'a api::rest::NamedCkksEncryptedQueryVector,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    ckks_client_encrypted_query_source_from_parts(
        vector_name,
        input.envelope.version,
        &input.envelope.scheme,
        &input.envelope.security_profile,
        &input.envelope.context_digest,
        input.envelope.slots,
        &input.envelope.ciphertext,
    )
}

fn ckks_client_encrypted_query_source_from_parts<'a>(
    vector_name: &str,
    version: u8,
    scheme: &str,
    security_profile: &str,
    context_digest_b64: &'a str,
    slots: usize,
    ciphertext_b64: &str,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    if version != 1 {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' client CKKS query version must be 1",
        )));
    }
    if scheme != CKKS_SCHEME {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' client CKKS query scheme must be {CKKS_SCHEME}",
        )));
    }
    if security_profile != CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50 {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' client CKKS query profile must be {CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50}",
        )));
    }
    if slots == 0 {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' client CKKS query slots must be greater than 0",
        )));
    }
    let context_digest = BASE64URL_NOPAD
        .decode(context_digest_b64.as_bytes())
        .map_err(|err| {
            StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' client CKKS query context digest is not base64url: {err}",
            ))
        })?;
    if context_digest.len() != 32 {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' client CKKS query context digest must decode to 32 bytes",
        )));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|err| {
            StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' client CKKS query ciphertext is not base64url: {err}",
            ))
        })?;
    if ciphertext.is_empty() {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' client CKKS query ciphertext must not be empty",
        )));
    }

    Ok(CkksSidecarQuerySource::ClientEncrypted {
        context_digest: context_digest_b64,
        slots,
        ciphertext,
    })
}

fn ckks_search_params_supported(params: &SearchParams) -> bool {
    params.quantization.is_none() && !params.indexed_only && params.acorn.is_none()
}

fn ckks_sidecar_hnsw_score_order_cache_tag(score_order: Order) -> &'static str {
    match score_order {
        Order::LargeBetter => "large",
        Order::SmallBetter => "small",
    }
}

fn ckks_sidecar_hnsw_records_fingerprint(records: &[CkksSidecarSearchRecord]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((records.len() as u64).to_be_bytes());
    for record in records {
        hasher.update(record.point_id.as_bytes());
        hasher.update([0]);
        hasher.update(record.encrypted.version.to_be_bytes());
        hasher.update(record.encrypted.scheme.as_bytes());
        hasher.update([0]);

        let envelope = &record.encrypted.envelope;
        hasher.update(envelope.version.to_be_bytes());
        hasher.update(envelope.algorithm.as_bytes());
        hasher.update([0]);
        hasher.update(envelope.key_id.as_bytes());
        hasher.update([0]);
        hasher.update(envelope.material_fingerprint.as_bytes());
        hasher.update([0]);
        hasher.update(envelope.rk_id.as_bytes());
        hasher.update([0]);
        match envelope.rk_epoch {
            Some(epoch) => {
                hasher.update([1]);
                hasher.update(epoch.to_be_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update(envelope.nonce.as_bytes());
        hasher.update([0]);
        hasher.update(envelope.ciphertext.as_bytes());
        hasher.update([0xff]);
    }

    let digest = hasher.finalize();
    BASE64URL_NOPAD.encode(digest.as_ref())
}

fn ckks_sidecar_hnsw_graph_cache_file_name(key: &CkksSidecarHnswGraphCacheKey) -> String {
    let mut hasher = Sha256::new();
    for value in [
        key.collection_identity.as_str(),
        key.vector_name.as_str(),
        key.score_order,
        key.records_fingerprint.as_str(),
    ] {
        let bytes = value.as_bytes();
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.update((key.m as u64).to_be_bytes());
    let digest = hasher.finalize();
    format!("{}.json", BASE64URL_NOPAD.encode(digest.as_ref()))
}

fn ckks_sidecar_hnsw_graph_cache_path(
    collection_path: &Path,
    key: &CkksSidecarHnswGraphCacheKey,
) -> PathBuf {
    collection_path
        .join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR)
        .join(ckks_sidecar_hnsw_graph_cache_file_name(key))
}

fn ckks_sidecar_hnsw_existing_cache_directory_is_safe(
    directory: &Path,
) -> Result<bool, StorageError> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(StorageError::service_error(format!(
                "failed to inspect CKKS sidecar HNSW graph cache directory {directory:?}: {err}",
            )));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(StorageError::service_error(format!(
            "CKKS sidecar HNSW graph cache directory {directory:?} must not be a symlink",
        )));
    }
    if !metadata.is_dir() {
        return Err(StorageError::service_error(format!(
            "CKKS sidecar HNSW graph cache directory {directory:?} must be a directory",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StorageError::service_error(format!(
                "CKKS sidecar HNSW graph cache directory {directory:?} must not be group/world accessible",
            )));
        }
    }

    Ok(true)
}

fn ckks_sidecar_hnsw_load_persisted_graph(
    collection_path: &Path,
    key: &CkksSidecarHnswGraphCacheKey,
    records_len: usize,
) -> Result<Option<Arc<CkksSidecarHnswGraph>>, StorageError> {
    let directory = collection_path.join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
    if !ckks_sidecar_hnsw_existing_cache_directory_is_safe(&directory)? {
        return Ok(None);
    }
    let path = directory.join(ckks_sidecar_hnsw_graph_cache_file_name(key));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(StorageError::service_error(format!(
                "failed to inspect CKKS sidecar HNSW graph cache {path:?}: {err}",
            )));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(StorageError::service_error(format!(
            "CKKS sidecar HNSW graph cache {path:?} must not be a symlink",
        )));
    }
    if !metadata.is_file() {
        return Err(StorageError::service_error(format!(
            "CKKS sidecar HNSW graph cache {path:?} must be a regular file",
        )));
    }
    if metadata.len() > CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES {
        return Err(StorageError::service_error(format!(
            "CKKS sidecar HNSW graph cache {path:?} exceeds maximum size",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StorageError::service_error(format!(
                "CKKS sidecar HNSW graph cache {path:?} must not be group/world accessible",
            )));
        }
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let file = options.open(&path).map_err(|err| {
        StorageError::service_error(format!(
            "failed to open CKKS sidecar HNSW graph cache {path:?}: {err}",
        ))
    })?;
    let mut content = String::with_capacity(metadata.len() as usize);
    let mut limited_file = file.take(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES + 1);
    limited_file.read_to_string(&mut content).map_err(|err| {
        StorageError::service_error(format!(
            "failed to read CKKS sidecar HNSW graph cache {path:?}: {err}",
        ))
    })?;
    if content.len() as u64 > CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES {
        return Err(StorageError::service_error(format!(
            "CKKS sidecar HNSW graph cache {path:?} exceeds maximum size",
        )));
    }
    let disk: CkksSidecarHnswGraphDisk = serde_json::from_str(&content).map_err(|err| {
        StorageError::service_error(format!(
            "failed to parse CKKS sidecar HNSW graph cache {path:?}: {err}",
        ))
    })?;
    if disk.version != CKKS_SIDECAR_HNSW_GRAPH_CACHE_VERSION
        || disk.collection_identity != key.collection_identity
        || disk.vector_name != key.vector_name
        || disk.score_order != key.score_order
        || disk.m != key.m
        || disk.records_fingerprint != key.records_fingerprint
    {
        return Ok(None);
    }
    if disk.links.len() != records_len
        || disk
            .links
            .iter()
            .any(|neighbors| neighbors.iter().any(|neighbor| *neighbor >= records_len))
        || disk
            .links
            .iter()
            .enumerate()
            .any(|(idx, neighbors)| neighbors.iter().any(|neighbor| *neighbor == idx))
        || !ckks_sidecar_hnsw_links_are_reciprocal(&disk.links)
        || !ckks_sidecar_hnsw_links_are_connected(&disk.links)
    {
        return Ok(None);
    }

    Ok(Some(Arc::new(CkksSidecarHnswGraph {
        links: Arc::new(disk.links),
    })))
}

fn ckks_sidecar_hnsw_persist_graph(
    collection_path: &Path,
    key: &CkksSidecarHnswGraphCacheKey,
    graph: &CkksSidecarHnswGraph,
) -> Result<(), StorageError> {
    let directory = collection_path.join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
    if !ckks_sidecar_hnsw_existing_cache_directory_is_safe(&directory)? {
        fs::create_dir_all(&directory).map_err(|err| {
            StorageError::service_error(format!(
                "failed to create CKKS sidecar HNSW graph cache directory {directory:?}: {err}",
            ))
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|err| {
            StorageError::service_error(format!(
                "failed to set CKKS sidecar HNSW graph cache directory permissions {directory:?}: {err}",
            ))
        })?;
    }
    ckks_sidecar_hnsw_existing_cache_directory_is_safe(&directory)?;

    let path = ckks_sidecar_hnsw_graph_cache_path(collection_path, key);
    let temp_path = path.with_extension("json.tmp");
    let disk = CkksSidecarHnswGraphDisk {
        version: CKKS_SIDECAR_HNSW_GRAPH_CACHE_VERSION,
        collection_identity: key.collection_identity.clone(),
        vector_name: key.vector_name.clone(),
        score_order: key.score_order.to_string(),
        m: key.m,
        records_fingerprint: key.records_fingerprint.clone(),
        links: graph.links.as_ref().clone(),
    };
    let content = serde_json::to_vec(&disk).map_err(|err| {
        StorageError::service_error(format!(
            "failed to serialize CKKS sidecar HNSW graph cache {path:?}: {err}",
        ))
    })?;

    match fs::symlink_metadata(&temp_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StorageError::service_error(format!(
                "CKKS sidecar HNSW graph cache temp file {temp_path:?} must not be a symlink",
            )));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(StorageError::service_error(format!(
                "CKKS sidecar HNSW graph cache temp file {temp_path:?} must be a regular file",
            )));
        }
        Ok(_) => {
            fs::remove_file(&temp_path).map_err(|err| {
                StorageError::service_error(format!(
                    "failed to remove stale CKKS sidecar HNSW graph cache temp file {temp_path:?}: {err}",
                ))
            })?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(StorageError::service_error(format!(
                "failed to inspect CKKS sidecar HNSW graph cache temp file {temp_path:?}: {err}",
            )));
        }
    }

    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temp_path).map_err(|err| {
        StorageError::service_error(format!(
            "failed to create CKKS sidecar HNSW graph cache {temp_path:?}: {err}",
        ))
    })?;
    file.write_all(&content).map_err(|err| {
        StorageError::service_error(format!(
            "failed to write CKKS sidecar HNSW graph cache {temp_path:?}: {err}",
        ))
    })?;
    file.flush().map_err(|err| {
        StorageError::service_error(format!(
            "failed to flush CKKS sidecar HNSW graph cache {temp_path:?}: {err}",
        ))
    })?;
    file.sync_all().map_err(|err| {
        StorageError::service_error(format!(
            "failed to sync CKKS sidecar HNSW graph cache {temp_path:?}: {err}",
        ))
    })?;
    fs::rename(&temp_path, &path).map_err(|err| {
        StorageError::service_error(format!(
            "failed to replace CKKS sidecar HNSW graph cache {path:?}: {err}",
        ))
    })?;
    ckks_sidecar_hnsw_prune_persisted_graphs(&directory, &path)?;
    ckks_sidecar_hnsw_sync_parent(&path).map_err(|err| {
        StorageError::service_error(format!(
            "failed to sync CKKS sidecar HNSW graph cache directory for {path:?}: {err}",
        ))
    })
}

fn ckks_sidecar_hnsw_prune_persisted_graphs(
    directory: &Path,
    keep_path: &Path,
) -> Result<(), StorageError> {
    struct CacheFile {
        path: PathBuf,
        len: u64,
        modified: SystemTime,
    }

    let keep_len = match fs::symlink_metadata(keep_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(StorageError::service_error(format!(
                "CKKS sidecar HNSW graph cache keep file {keep_path:?} must not be a symlink",
            )));
        }
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => 0,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => {
            return Err(StorageError::service_error(format!(
                "failed to inspect CKKS sidecar HNSW graph cache keep file {keep_path:?}: {err}",
            )));
        }
    };
    let mut files = Vec::new();
    let entries = fs::read_dir(directory).map_err(|err| {
        StorageError::service_error(format!(
            "failed to read CKKS sidecar HNSW graph cache directory {directory:?}: {err}",
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            StorageError::service_error(format!(
                "failed to read CKKS sidecar HNSW graph cache directory entry {directory:?}: {err}",
            ))
        })?;
        let path = entry.path();
        if path == keep_path
            || path.extension().and_then(|extension| extension.to_str()) != Some("json")
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|err| {
            StorageError::service_error(format!(
                "failed to inspect CKKS sidecar HNSW graph cache file {path:?}: {err}",
            ))
        })?;
        if !metadata.is_file() && !metadata.file_type().is_symlink() {
            continue;
        }
        files.push(CacheFile {
            path,
            len: metadata.len(),
            modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        });
    }

    files.sort_unstable_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.path.cmp(&right.path))
    });

    let mut kept_files = 1usize;
    let mut kept_bytes = keep_len;
    for file in files {
        let keep_file = kept_files < CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_FILES
            && kept_bytes.saturating_add(file.len) <= CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_TOTAL_BYTES;
        if keep_file {
            kept_files += 1;
            kept_bytes = kept_bytes.saturating_add(file.len);
            continue;
        }
        fs::remove_file(&file.path).map_err(|err| {
            StorageError::service_error(format!(
                "failed to prune CKKS sidecar HNSW graph cache file {:?}: {err}",
                file.path,
            ))
        })?;
    }

    Ok(())
}

#[cfg(unix)]
fn ckks_sidecar_hnsw_sync_parent(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn ckks_sidecar_hnsw_sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ckks_sidecar_score_hnsw_query_batch(
    collection_name: &str,
    vector_name: &str,
    plan: &crate::common::crypto::VectorWritePlan,
    query: CkksSidecarHnswQuery<'_>,
    encrypted_items: &[(String, EncryptedCkksVector)],
) -> Result<Vec<f32>, StorageError> {
    let scores = match query {
        CkksSidecarHnswQuery::Dense(query_values) => plan.score_encrypted_query_batch(
            collection_name,
            vector_name,
            encrypted_items,
            query_values,
        )?,
        CkksSidecarHnswQuery::ClientEncrypted {
            context_digest,
            slots,
            ciphertext,
        } => plan.score_client_encrypted_query_batch(
            collection_name,
            vector_name,
            encrypted_items,
            context_digest,
            slots,
            ciphertext,
        )?,
        CkksSidecarHnswQuery::Stored {
            query_point_id,
            query_encrypted,
        } => plan.score_stored_query_batch(
            collection_name,
            vector_name,
            query_point_id,
            query_encrypted,
            encrypted_items,
        )?,
    };

    scores.ok_or_else(|| {
        StorageError::service_error(format!(
            "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
        ))
    })
}

#[allow(clippy::too_many_arguments)]
fn ckks_sidecar_hnsw_search_points(
    collection_name: &str,
    collection_crypto_id: &str,
    vector_name: &str,
    collection_path: &Path,
    plan: &crate::common::crypto::VectorWritePlan,
    records: &[CkksSidecarSearchRecord],
    query: CkksSidecarHnswQuery<'_>,
    score_order: Order,
    score_threshold: Option<f32>,
    hnsw_ef: usize,
    top: usize,
) -> Result<Vec<ScoredPoint>, StorageError> {
    if records.is_empty() || top == 0 {
        return Ok(Vec::new());
    }
    if records.len() == 1 {
        let encrypted_items = [(records[0].point_id.clone(), records[0].encrypted.clone())];
        let scores = ckks_sidecar_score_hnsw_query_batch(
            collection_name,
            vector_name,
            plan,
            query,
            &encrypted_items,
        )?;
        let score = scores[0];
        if !ckks_score_passes_threshold(score_order, score, score_threshold) {
            return Ok(Vec::new());
        }
        return Ok(vec![ScoredPoint {
            id: records[0].id,
            version: 0,
            score,
            payload: None,
            vector: None,
            shard_key: records[0].shard_key.clone(),
            order_value: None,
        }]);
    }

    let ef = hnsw_ef.max(top).max(1).min(records.len());
    if records.len() <= ef {
        let encrypted_items = records
            .iter()
            .map(|record| (record.point_id.clone(), record.encrypted.clone()))
            .collect::<Vec<_>>();
        let scores = ckks_sidecar_score_hnsw_query_batch(
            collection_name,
            vector_name,
            plan,
            query,
            &encrypted_items,
        )?;
        let mut scored = records
            .iter()
            .zip(scores)
            .filter_map(|(record, score)| {
                ckks_score_passes_threshold(score_order, score, score_threshold).then(|| {
                    ScoredPoint {
                        id: record.id,
                        version: 0,
                        score,
                        payload: None,
                        vector: None,
                        shard_key: record.shard_key.clone(),
                        order_value: None,
                    }
                })
            })
            .collect::<Vec<_>>();
        sort_ckks_scored_points(score_order, &mut scored);
        scored.truncate(top);
        return Ok(scored);
    }

    let m = 16.min(records.len().saturating_sub(1)).max(1);
    let cache_key = CkksSidecarHnswGraphCacheKey {
        collection_identity: collection_crypto_id.to_string(),
        vector_name: vector_name.to_string(),
        score_order: ckks_sidecar_hnsw_score_order_cache_tag(score_order),
        m,
        records_fingerprint: ckks_sidecar_hnsw_records_fingerprint(records),
    };
    let graph = {
        let mut cache = CKKS_SIDECAR_HNSW_GRAPH_CACHE.lock().map_err(|_| {
            StorageError::service_error("CKKS sidecar HNSW graph cache mutex was poisoned")
        })?;
        cache.get(&cache_key)
    };
    let graph = match graph {
        Some(graph) => graph,
        None => {
            let persisted_graph =
                ckks_sidecar_hnsw_load_persisted_graph(collection_path, &cache_key, records.len());
            let persisted_graph = match persisted_graph {
                Ok(graph) => graph,
                Err(err) => {
                    log::warn!(
                        "Ignoring unreadable CKKS sidecar HNSW graph cache for collection {collection_name}, vector {vector_name}: {err}",
                    );
                    None
                }
            };
            if let Some(graph) = persisted_graph {
                let mut cache = CKKS_SIDECAR_HNSW_GRAPH_CACHE.lock().map_err(|_| {
                    StorageError::service_error("CKKS sidecar HNSW graph cache mutex was poisoned")
                })?;
                cache.insert(cache_key, graph.clone());
                graph
            } else {
                let mut links = vec![Vec::<usize>::new(); records.len()];
                for idx in 1..records.len() {
                    let candidates = (0..idx)
                        .map(|candidate| {
                            (
                                records[candidate].point_id.clone(),
                                records[candidate].encrypted.clone(),
                            )
                        })
                        .collect::<Vec<_>>();
                    let scores = plan
                        .score_stored_query_batch(
                            collection_name,
                            vector_name,
                            &records[idx].point_id,
                            &records[idx].encrypted,
                            &candidates,
                        )?
                        .ok_or_else(|| {
                            StorageError::service_error(format!(
                                "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                            ))
                        })?;
                    let mut neighbors = scores
                        .into_iter()
                        .enumerate()
                        .map(|(candidate, score)| ScoredPoint {
                            id: PointIdType::NumId(candidate as u64),
                            version: 0,
                            score,
                            payload: None,
                            vector: None,
                            shard_key: None,
                            order_value: None,
                        })
                        .collect::<Vec<_>>();
                    sort_ckks_scored_points(score_order, &mut neighbors);
                    for neighbor in neighbors.into_iter().take(m) {
                        let candidate = match neighbor.id {
                            PointIdType::NumId(candidate) => candidate as usize,
                            PointIdType::Uuid(_) => unreachable!("candidate indexes are numeric"),
                        };
                        ckks_sidecar_hnsw_add_bounded_undirected_link(
                            &mut links,
                            idx,
                            candidate,
                            m * 2,
                        );
                    }
                }
                ckks_sidecar_hnsw_add_connectivity_backbone(&mut links);

                let graph = Arc::new(CkksSidecarHnswGraph {
                    links: Arc::new(links),
                });
                if let Err(err) =
                    ckks_sidecar_hnsw_persist_graph(collection_path, &cache_key, &graph)
                {
                    log::warn!(
                        "Failed to persist CKKS sidecar HNSW graph cache for collection {collection_name}, vector {vector_name}: {err}",
                    );
                }
                let mut cache = CKKS_SIDECAR_HNSW_GRAPH_CACHE.lock().map_err(|_| {
                    StorageError::service_error("CKKS sidecar HNSW graph cache mutex was poisoned")
                })?;
                cache.insert(cache_key, graph.clone());
                graph
            }
        }
    };

    let mut visited = vec![false; records.len()];
    let mut frontier = vec![0usize];
    let mut scored = Vec::<ScoredPoint>::new();

    while !frontier.is_empty() && scored.len() < ef {
        frontier.sort_unstable();
        frontier.dedup();
        frontier.retain(|candidate| {
            let fresh = !visited[*candidate];
            visited[*candidate] = true;
            fresh
        });
        if frontier.is_empty() {
            break;
        }

        let encrypted_items = frontier
            .iter()
            .map(|candidate| {
                (
                    records[*candidate].point_id.clone(),
                    records[*candidate].encrypted.clone(),
                )
            })
            .collect::<Vec<_>>();
        let scores = ckks_sidecar_score_hnsw_query_batch(
            collection_name,
            vector_name,
            plan,
            query,
            &encrypted_items,
        )?;

        let mut batch = frontier
            .into_iter()
            .zip(scores)
            .map(|(candidate, score)| ScoredPoint {
                id: PointIdType::NumId(candidate as u64),
                version: 0,
                score,
                payload: None,
                vector: None,
                shard_key: None,
                order_value: None,
            })
            .collect::<Vec<_>>();
        sort_ckks_scored_points(score_order, &mut batch);
        frontier = Vec::new();
        for point in batch {
            let candidate = match point.id {
                PointIdType::NumId(candidate) => candidate as usize,
                PointIdType::Uuid(_) => unreachable!("candidate indexes are numeric"),
            };
            if ckks_score_passes_threshold(score_order, point.score, score_threshold) {
                scored.push(ScoredPoint {
                    id: records[candidate].id,
                    version: 0,
                    score: point.score,
                    payload: None,
                    vector: None,
                    shard_key: records[candidate].shard_key.clone(),
                    order_value: None,
                });
            }
            for neighbor in &graph.links[candidate] {
                if !visited[*neighbor] {
                    frontier.push(*neighbor);
                }
            }
            if scored.len() >= ef {
                break;
            }
        }
    }

    sort_ckks_scored_points(score_order, &mut scored);
    scored.truncate(top);
    Ok(scored)
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

    let with_vector = request.with_vector.clone().unwrap_or_default();
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &with_vector,
        &auth,
        "search groups",
    )
    .await?;
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
        hw_measurement_acc.clone(),
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
    if request.with_vector.clone().unwrap_or_default().is_enabled() {
        return Err(StorageError::bad_input(format!(
            "cannot return encrypted vector '{vector_name}'; CKKS vector ciphertext read path returns payload sidecar only",
        )));
    }
    ensure_group_path_does_not_touch_encrypted_vector_sidecar(&request.group_request.group_by)?;

    let group_by = request.group_request.group_by.clone();
    if let api::rest::NamedVectorStruct::CkksEncryptedQuery(query) = &request.vector {
        let query = ckks_rest_client_encrypted_query_source(vector_name, query)?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            vector_name,
            CkksSidecarScoring::NearestResolved { query },
            request.filter.clone(),
            request.params.clone(),
            request.score_threshold,
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
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.group_request.with_lookup.clone().map(Into::into),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

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
    let result = ckks_vector_group_points(
        &collection,
        collection_name,
        &collection_crypto_id,
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
        hw_measurement_acc.clone(),
    )
    .await?;
    attach_ckks_group_lookup(
        toc,
        result,
        request.group_request.with_lookup.clone().map(Into::into),
        read_consistency,
        shard_selection,
        auth,
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
    collection_crypto_id: &str,
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
        collection_crypto_id,
        search_request,
        plan,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;

    ckks_vector_group_scored_points(
        collection,
        scored,
        group_by,
        group_limit,
        group_size,
        with_payload,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_group_points_with_scoring(
    collection: &collection::collection::Collection,
    collection_name: &str,
    collection_crypto_id: &str,
    vector_name: &str,
    scoring: CkksSidecarScoring<'_>,
    filter: Option<Filter>,
    params: Option<SearchParams>,
    score_threshold: Option<f32>,
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
    let scored = ckks_vector_search_points_with_scoring(
        collection,
        collection_name,
        collection_crypto_id,
        vector_name,
        scoring,
        filter,
        params,
        usize::MAX,
        0,
        Some(WithPayloadInterface::Bool(true)),
        Some(WithVector::Bool(false)),
        score_threshold,
        plan,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;

    ckks_vector_group_scored_points(
        collection,
        scored,
        group_by,
        group_limit,
        group_size,
        with_payload,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_group_scored_points(
    collection: &collection::collection::Collection,
    scored: Vec<ScoredPoint>,
    group_by: &JsonPath,
    group_limit: usize,
    group_size: usize,
    with_payload: WithPayloadInterface,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<GroupsResult, StorageError> {
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
async fn attach_ckks_group_lookup(
    toc: &TableOfContent,
    mut result: GroupsResult,
    with_lookup: Option<collection::lookup::WithLookup>,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<GroupsResult, StorageError> {
    let Some(with_lookup) = with_lookup else {
        return Ok(result);
    };
    let lookup = with_lookup;
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        &lookup.collection_name,
        &lookup.with_vectors.clone().unwrap_or_default(),
        auth,
        "group lookup",
    )
    .await?;
    let pseudo_ids = result
        .groups
        .iter()
        .map(|group| PseudoId::from(group.id.clone()))
        .collect::<Vec<_>>();
    let mut lookups: std::collections::HashMap<PseudoId, RecordInternal> = lookup_ids(
        lookup,
        pseudo_ids,
        |name| async move {
            let collection_pass = auth
                .check_collection_access(&name, AccessRequirements::new(), "group_lookup")
                .ok()?;
            toc.get_collection(&collection_pass).await.ok()
        },
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await?;

    for group in &mut result.groups {
        group.lookup = lookups
            .remove(&PseudoId::from(group.id.clone()))
            .map(api::rest::Record::from);
    }

    Ok(result)
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

    for (request, _) in &requests {
        let with_vector = request.with_vector.clone().unwrap_or_default();
        ensure_with_vector_does_not_request_encrypted_vectors(
            toc,
            collection_name,
            &with_vector,
            &auth,
            "recommend",
        )
        .await?;
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
    let mut core_requests = Vec::with_capacity(requests.len());
    enum CkksResolvedRecommendRequest<'a> {
        Plain(RecommendRequestInternal, ShardSelectorInternal),
        Core(CoreSearchRequest, ShardSelectorInternal),
        StoredNearest {
            vector_name: String,
            query_point_id: String,
            query_encrypted: EncryptedCkksVector,
            filter: Option<Filter>,
            params: Option<SearchParams>,
            limit: usize,
            offset: usize,
            with_payload: Option<WithPayloadInterface>,
            with_vector: Option<WithVector>,
            score_threshold: Option<f32>,
            shard_selection: ShardSelectorInternal,
        },
        Scoring {
            vector_name: String,
            scoring: CkksSidecarScoring<'a>,
            filter: Option<Filter>,
            params: Option<SearchParams>,
            limit: usize,
            offset: usize,
            with_payload: Option<WithPayloadInterface>,
            with_vector: Option<WithVector>,
            score_threshold: Option<f32>,
            shard_selection: ShardSelectorInternal,
        },
    }

    for (request, shard_selection) in requests {
        let vector_name = recommend_vector_name(request);
        if !plan.contains_vector_name(&vector_name) {
            core_requests.push(Some(CkksResolvedRecommendRequest::Plain(
                request.clone(),
                shard_selection.clone(),
            )));
            continue;
        }

        has_encrypted_recommend = true;
        if let Some(point_id) = recommend_request_single_positive_point_id(request) {
            let query_encrypted = ckks_vector_sidecar_for_point_id(
                &collection,
                &vector_name,
                point_id,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            core_requests.push(Some(CkksResolvedRecommendRequest::StoredNearest {
                vector_name,
                query_point_id: point_id.to_string(),
                query_encrypted,
                filter: request.filter.clone(),
                params: request.params.clone(),
                limit: request.limit,
                offset: request.offset.unwrap_or_default(),
                with_payload: request.with_payload.clone(),
                with_vector: request.with_vector.clone(),
                score_threshold: None,
                shard_selection: shard_selection.clone(),
            }));
        } else if recommend_request_needs_sidecar_resolution(request) {
            let scoring = recommend_request_as_ckks_resolved_scoring(
                &collection,
                &vector_name,
                request,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            core_requests.push(Some(CkksResolvedRecommendRequest::Scoring {
                vector_name,
                scoring,
                filter: request.filter.clone(),
                params: request.params.clone(),
                limit: request.limit,
                offset: request.offset.unwrap_or_default(),
                with_payload: request.with_payload.clone(),
                with_vector: request.with_vector.clone(),
                score_threshold: request.score_threshold,
                shard_selection: shard_selection.clone(),
            }));
        } else {
            core_requests.push(Some(CkksResolvedRecommendRequest::Core(
                recommend_request_as_ckks_search_request(request, &vector_name)?,
                shard_selection.clone(),
            )));
        }
    }

    if !has_encrypted_recommend {
        return Ok(None);
    }

    let mut results = Vec::with_capacity(core_requests.len());
    for request in core_requests {
        let Some(request) = request else {
            unreachable!("plain recommend requests are represented explicitly");
        };
        let result = match request {
            CkksResolvedRecommendRequest::Plain(request, shard_selection) => {
                let with_vector = request.with_vector.clone().unwrap_or_default();
                ensure_with_vector_does_not_request_encrypted_vectors(
                    toc,
                    collection_name,
                    &with_vector,
                    auth,
                    "recommend",
                )
                .await?;
                let mut plain_results = toc
                    .recommend_batch(
                        collection_name,
                        vec![(request, shard_selection)],
                        read_consistency,
                        auth.clone(),
                        timeout,
                        hw_measurement_acc.clone(),
                    )
                    .await?;
                plain_results.pop().ok_or_else(|| {
                    StorageError::service_error(
                        "plaintext recommend result missing from mixed CKKS vector batch",
                    )
                })?
            }
            CkksResolvedRecommendRequest::Core(request, shard_selection) => {
                ckks_vector_search_points(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &request,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            CkksResolvedRecommendRequest::StoredNearest {
                vector_name,
                query_point_id,
                query_encrypted,
                filter,
                params,
                limit,
                offset,
                with_payload,
                with_vector,
                score_threshold,
                shard_selection,
            } => {
                ckks_vector_search_points_with_scoring(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &vector_name,
                    CkksSidecarScoring::StoredNearest {
                        query_point_id,
                        query_encrypted,
                    },
                    filter,
                    params,
                    limit,
                    offset,
                    with_payload,
                    with_vector,
                    score_threshold,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            CkksResolvedRecommendRequest::Scoring {
                vector_name,
                scoring,
                filter,
                params,
                limit,
                offset,
                with_payload,
                with_vector,
                score_threshold,
                shard_selection,
            } => {
                ckks_vector_search_points_with_scoring(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &vector_name,
                    scoring,
                    filter,
                    params,
                    limit,
                    offset,
                    with_payload,
                    with_vector,
                    score_threshold,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
        };
        results.push(result);
    }

    Ok(Some(results))
}

fn recommend_request_single_positive_point_id(
    request: &RecommendRequestInternal,
) -> Option<PointIdType> {
    if request.lookup_from.is_some()
        || !request.negative.is_empty()
        || request.strategy.unwrap_or_default() != RecommendStrategy::AverageVector
        || request.positive.len() != 1
    {
        return None;
    }

    let RecommendExample::PointId(point_id) = request.positive[0] else {
        return None;
    };
    Some(point_id)
}

fn recommend_examples_contain_point_id(examples: &[RecommendExample]) -> bool {
    examples
        .iter()
        .any(|example| matches!(example, RecommendExample::PointId(_)))
}

fn recommend_request_needs_sidecar_resolution(request: &RecommendRequestInternal) -> bool {
    recommend_examples_contain_point_id(&request.positive)
        || recommend_examples_contain_point_id(&request.negative)
}

#[allow(clippy::too_many_arguments)]
async fn recommend_examples_as_ckks_query_sources<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    role: &str,
    examples: &'a [RecommendExample],
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<CkksSidecarQuerySource<'a>>, StorageError> {
    let mut sources = Vec::with_capacity(examples.len());
    for example in examples {
        sources.push(
            recommend_example_as_ckks_query_source(
                collection,
                vector_name,
                role,
                example,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?,
        );
    }
    Ok(sources)
}

#[allow(clippy::too_many_arguments)]
async fn recommend_request_as_ckks_resolved_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    request: &'a RecommendRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    if request.lookup_from.is_some() {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' recommend does not support lookup_from; provide examples from the same encrypted vector sidecar",
        )));
    }
    let positives = recommend_examples_as_ckks_query_sources(
        collection,
        vector_name,
        "positive",
        &request.positive,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    let negatives = recommend_examples_as_ckks_query_sources(
        collection,
        vector_name,
        "negative",
        &request.negative,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await?;

    match request.strategy.unwrap_or_default() {
        RecommendStrategy::BestScore => Ok(CkksSidecarScoring::RecommendBestScoreResolved {
            positives,
            negatives,
        }),
        RecommendStrategy::SumScores => Ok(CkksSidecarScoring::RecommendSumScoresResolved {
            positives,
            negatives,
        }),
        RecommendStrategy::AverageVector => {
            Ok(CkksSidecarScoring::RecommendAverageVectorResolved {
                positives,
                negatives,
            })
        }
    }
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
    let with_vector = request.with_vector.clone().unwrap_or_default();
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &with_vector,
        &auth,
        "recommend groups",
    )
    .await?;
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
    if request.with_vector.clone().unwrap_or_default().is_enabled() {
        return Err(StorageError::bad_input(format!(
            "cannot return encrypted vector '{vector_name}'; CKKS vector ciphertext read path returns payload sidecar only",
        )));
    }
    ensure_group_path_does_not_touch_encrypted_vector_sidecar(&request.group_request.group_by)?;

    if let Some(point_id) = recommend_request_single_positive_point_id(&recommend_request) {
        let query_encrypted = ckks_vector_sidecar_for_point_id(
            &collection,
            &vector_name,
            point_id,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &vector_name,
            CkksSidecarScoring::StoredNearest {
                query_point_id: point_id.to_string(),
                query_encrypted,
            },
            recommend_request.filter.clone(),
            recommend_request.params.clone(),
            recommend_request.score_threshold,
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
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.group_request.with_lookup.clone().map(Into::into),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    if recommend_request_needs_sidecar_resolution(&recommend_request) {
        let scoring = recommend_request_as_ckks_resolved_scoring(
            &collection,
            &vector_name,
            &recommend_request,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &vector_name,
            scoring,
            recommend_request.filter.clone(),
            recommend_request.params.clone(),
            recommend_request.score_threshold,
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
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.group_request.with_lookup.clone().map(Into::into),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    let core_request = recommend_request_as_ckks_search_request(&recommend_request, &vector_name)?;
    let result = ckks_vector_group_points(
        &collection,
        collection_name,
        &collection_crypto_id,
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
        hw_measurement_acc.clone(),
    )
    .await?;
    attach_ckks_group_lookup(
        toc,
        result,
        request.group_request.with_lookup.clone().map(Into::into),
        read_consistency,
        shard_selection,
        auth,
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

    for (request, _) in &requests {
        let with_vector = request.with_vector.clone().unwrap_or_default();
        ensure_with_vector_does_not_request_encrypted_vectors(
            toc,
            collection_name,
            &with_vector,
            &auth,
            "discover",
        )
        .await?;
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
    let mut core_requests = Vec::with_capacity(requests.len());
    enum CkksResolvedDiscoverRequest<'a> {
        Plain(DiscoverRequestInternal, ShardSelectorInternal),
        Core(CoreSearchRequest, ShardSelectorInternal),
        Resolved {
            vector_name: String,
            scoring: CkksSidecarScoring<'a>,
            filter: Option<Filter>,
            params: Option<SearchParams>,
            limit: usize,
            offset: usize,
            with_payload: Option<WithPayloadInterface>,
            with_vector: Option<WithVector>,
            score_threshold: Option<f32>,
            shard_selection: ShardSelectorInternal,
        },
    }

    for (request, shard_selection) in requests {
        let vector_name = discover_vector_name(request);
        if !plan.contains_vector_name(&vector_name) {
            core_requests.push(Some(CkksResolvedDiscoverRequest::Plain(
                request.clone(),
                shard_selection.clone(),
            )));
            continue;
        }

        has_encrypted_discover = true;
        if discover_request_needs_sidecar_resolution(request) {
            if request.lookup_from.is_some() {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' discover does not support lookup_from; provide examples from the same encrypted vector sidecar",
                )));
            }
            let scoring = discover_request_as_ckks_resolved_scoring(
                &collection,
                &vector_name,
                request,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            core_requests.push(Some(CkksResolvedDiscoverRequest::Resolved {
                vector_name,
                scoring,
                filter: request.filter.clone(),
                params: request.params.clone(),
                limit: request.limit,
                offset: request.offset.unwrap_or_default(),
                with_payload: request.with_payload.clone(),
                with_vector: request.with_vector.clone(),
                score_threshold: None,
                shard_selection: shard_selection.clone(),
            }));
        } else {
            core_requests.push(Some(CkksResolvedDiscoverRequest::Core(
                discover_request_as_ckks_search_request(request, &vector_name)?,
                shard_selection.clone(),
            )));
        }
    }

    if !has_encrypted_discover {
        return Ok(None);
    }

    let mut results = Vec::with_capacity(core_requests.len());
    for request in core_requests {
        let Some(request) = request else {
            unreachable!("plain discover requests are represented explicitly");
        };
        let result = match request {
            CkksResolvedDiscoverRequest::Plain(request, shard_selection) => {
                let with_vector = request.with_vector.clone().unwrap_or_default();
                ensure_with_vector_does_not_request_encrypted_vectors(
                    toc,
                    collection_name,
                    &with_vector,
                    auth,
                    "discover",
                )
                .await?;
                let mut plain_results = toc
                    .discover_batch(
                        collection_name,
                        vec![(request, shard_selection)],
                        read_consistency,
                        auth.clone(),
                        timeout,
                        hw_measurement_acc.clone(),
                    )
                    .await?;
                plain_results.pop().ok_or_else(|| {
                    StorageError::service_error(
                        "plaintext discover result missing from mixed CKKS vector batch",
                    )
                })?
            }
            CkksResolvedDiscoverRequest::Core(request, shard_selection) => {
                ckks_vector_search_points(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &request,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
            CkksResolvedDiscoverRequest::Resolved {
                vector_name,
                scoring,
                filter,
                params,
                limit,
                offset,
                with_payload,
                with_vector,
                score_threshold,
                shard_selection,
            } => {
                ckks_vector_search_points_with_scoring(
                    &collection,
                    collection_name,
                    &collection_crypto_id,
                    &vector_name,
                    scoring,
                    filter,
                    params,
                    limit,
                    offset,
                    with_payload,
                    with_vector,
                    score_threshold,
                    &plan,
                    read_consistency,
                    &shard_selection,
                    timeout,
                    hw_measurement_acc.clone(),
                )
                .await?
            }
        };
        results.push(result);
    }

    Ok(Some(results))
}

fn discover_request_needs_sidecar_resolution(request: &DiscoverRequestInternal) -> bool {
    request
        .target
        .as_ref()
        .is_some_and(|target| matches!(target, RecommendExample::PointId(_)))
        || request
            .context
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|pair| {
                matches!(pair.positive, RecommendExample::PointId(_))
                    || matches!(pair.negative, RecommendExample::PointId(_))
            })
}

#[allow(clippy::too_many_arguments)]
async fn recommend_example_as_ckks_query_source<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    role: &str,
    example: &'a RecommendExample,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    match example {
        RecommendExample::Dense(values) => Ok(CkksSidecarQuerySource::Dense(values)),
        RecommendExample::PointId(point_id) => {
            let encrypted = ckks_vector_sidecar_for_point_id(
                collection,
                vector_name,
                *point_id,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await?;
            Ok(CkksSidecarQuerySource::Stored {
                point_id: point_id.to_string(),
                encrypted,
            })
        }
        RecommendExample::Sparse(_) => Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' discover only supports raw dense or point-id {role} examples",
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
async fn discover_request_as_ckks_resolved_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    request: &'a DiscoverRequestInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    let Some(target) = request.target.as_ref() else {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' discover requires a raw dense or point-id target vector",
        )));
    };
    let target = recommend_example_as_ckks_query_source(
        collection,
        vector_name,
        "target",
        target,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    let mut pairs = Vec::new();
    for pair in request.context.as_deref().unwrap_or_default() {
        let positive = recommend_example_as_ckks_query_source(
            collection,
            vector_name,
            "positive context",
            &pair.positive,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let negative = recommend_example_as_ckks_query_source(
            collection,
            vector_name,
            "negative context",
            &pair.negative,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        pairs.push((positive, negative));
    }

    Ok(CkksSidecarScoring::DiscoverResolved { target, pairs })
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
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &request.with_vector,
        &auth,
        "retrieve",
    )
    .await?;

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
    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &request.with_vector,
        &auth,
        "scroll",
    )
    .await?;

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

async fn ensure_with_vector_does_not_request_encrypted_vectors(
    toc: &TableOfContent,
    collection_name: &str,
    with_vector: &WithVector,
    auth: &Auth,
    operation: &str,
) -> Result<(), StorageError> {
    if !with_vector.is_enabled() {
        return Ok(());
    }

    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "encrypted_vector_read_guard",
    )?;
    let collection = toc.get_collection(&collection_pass).await?;
    let config = collection.config_snapshot().await;
    let Some(encryption) = config.params.effective_encryption() else {
        return Ok(());
    };

    let encrypted_names = encryption
        .rules
        .iter()
        .filter_map(|rule| match &rule.selector {
            EncryptionSelector::VectorNames { names } => Some(names),
            _ => None,
        })
        .flat_map(|names| names.iter().map(String::as_str))
        .collect::<std::collections::HashSet<_>>();
    if encrypted_names.is_empty() {
        return Ok(());
    }

    match with_vector {
        WithVector::Bool(false) => Ok(()),
        WithVector::Bool(true) => Err(StorageError::bad_input(format!(
            "cannot {operation} encrypted vectors for collection '{collection_name}'; CKKS vector ciphertext read path returns payload sidecar only",
        ))),
        WithVector::Selector(vector_names) => {
            if let Some(vector_name) = vector_names
                .iter()
                .map(String::as_str)
                .find(|vector_name| encrypted_names.contains(vector_name))
            {
                return Err(StorageError::bad_input(format!(
                    "cannot {operation} encrypted vector '{vector_name}'; CKKS vector ciphertext read path returns payload sidecar only",
                )));
            }
            Ok(())
        }
    }
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
async fn ckks_vector_sidecar_for_point_id(
    collection: &collection::collection::Collection,
    vector_name: &str,
    point_id: PointIdType,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<EncryptedCkksVector, StorageError> {
    let records = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![point_id],
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: WithVector::Bool(false),
            },
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc,
        )
        .await?;

    let record = records
        .into_iter()
        .find(|record| record.id == point_id)
        .ok_or_else(|| {
            StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' query point id {point_id} was not found",
            ))
        })?;
    let payload = record.payload.as_ref().ok_or_else(|| {
        StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' query point id {point_id} has no payload sidecar",
        ))
    })?;

    encrypted_vector_from_payload(payload, vector_name)?.ok_or_else(|| {
        StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' query point id {point_id} has no CKKS vector sidecar",
        ))
    })
}

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_input_as_query_source<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    role: &str,
    input: &'a VectorInputInternal,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarQuerySource<'a>, StorageError> {
    match input {
        VectorInputInternal::Vector(VectorInternal::Dense(values)) => {
            Ok(CkksSidecarQuerySource::Dense(values))
        }
        VectorInputInternal::Vector(_) => Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' context query only supports raw dense or point-id {role} examples",
        ))),
        VectorInputInternal::CkksEncryptedQuery(input) => {
            ckks_client_encrypted_query_source(vector_name, input)
        }
        VectorInputInternal::Id(point_id) => {
            let encrypted = ckks_vector_sidecar_for_point_id(
                collection,
                vector_name,
                *point_id,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await?;
            Ok(CkksSidecarQuerySource::Stored {
                point_id: point_id.to_string(),
                encrypted,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn ckks_context_query_as_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    context: &'a segment::vector_storage::query::ContextQuery<VectorInputInternal>,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    let mut pairs = Vec::with_capacity(context.pairs.len());
    for pair in &context.pairs {
        let positive = ckks_vector_input_as_query_source(
            collection,
            vector_name,
            "positive",
            &pair.positive,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let negative = ckks_vector_input_as_query_source(
            collection,
            vector_name,
            "negative",
            &pair.negative,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        pairs.push((positive, negative));
    }

    Ok(CkksSidecarScoring::ContextResolved { pairs })
}

fn vector_inputs_contain_point_id(inputs: &[VectorInputInternal]) -> bool {
    inputs
        .iter()
        .any(|input| matches!(input, VectorInputInternal::Id(_)))
}

fn reco_query_single_positive_point_id(
    recommend: &segment::vector_storage::query::RecoQuery<VectorInputInternal>,
) -> Option<PointIdType> {
    if !recommend.negatives.is_empty() || recommend.positives.len() != 1 {
        return None;
    }
    let VectorInputInternal::Id(point_id) = recommend.positives[0] else {
        return None;
    };
    Some(point_id)
}

fn reco_query_needs_sidecar_resolution(
    recommend: &segment::vector_storage::query::RecoQuery<VectorInputInternal>,
) -> bool {
    vector_inputs_contain_point_id(&recommend.positives)
        || vector_inputs_contain_point_id(&recommend.negatives)
}

#[allow(clippy::too_many_arguments)]
async fn vector_inputs_as_ckks_query_sources<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    role: &str,
    inputs: &'a [VectorInputInternal],
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<Vec<CkksSidecarQuerySource<'a>>, StorageError> {
    let mut sources = Vec::with_capacity(inputs.len());
    for input in inputs {
        sources.push(
            ckks_vector_input_as_query_source(
                collection,
                vector_name,
                role,
                input,
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?,
        );
    }
    Ok(sources)
}

#[allow(clippy::too_many_arguments)]
async fn ckks_reco_query_as_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    recommend: &'a segment::vector_storage::query::RecoQuery<VectorInputInternal>,
    strategy: RecommendStrategy,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    let positives = vector_inputs_as_ckks_query_sources(
        collection,
        vector_name,
        "positive",
        &recommend.positives,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    let negatives = vector_inputs_as_ckks_query_sources(
        collection,
        vector_name,
        "negative",
        &recommend.negatives,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc,
    )
    .await?;

    match strategy {
        RecommendStrategy::BestScore => Ok(CkksSidecarScoring::RecommendBestScoreResolved {
            positives,
            negatives,
        }),
        RecommendStrategy::SumScores => Ok(CkksSidecarScoring::RecommendSumScoresResolved {
            positives,
            negatives,
        }),
        RecommendStrategy::AverageVector => {
            Ok(CkksSidecarScoring::RecommendAverageVectorResolved {
                positives,
                negatives,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn ckks_discover_query_as_scoring<'a>(
    collection: &collection::collection::Collection,
    vector_name: &str,
    discover: &'a segment::vector_storage::query::DiscoverQuery<VectorInputInternal>,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CkksSidecarScoring<'a>, StorageError> {
    let target = ckks_vector_input_as_query_source(
        collection,
        vector_name,
        "target",
        &discover.target,
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    let mut pairs = Vec::with_capacity(discover.pairs.len());
    for pair in &discover.pairs {
        let positive = ckks_vector_input_as_query_source(
            collection,
            vector_name,
            "positive context",
            &pair.positive,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let negative = ckks_vector_input_as_query_source(
            collection,
            vector_name,
            "negative context",
            &pair.negative,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        pairs.push((positive, negative));
    }

    Ok(CkksSidecarScoring::DiscoverResolved { target, pairs })
}

#[allow(clippy::too_many_arguments)]
async fn ckks_resolve_query_prefetches(
    toc: &TableOfContent,
    collection_name: &str,
    prefetches: &[CollectionPrefetch],
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    auth: &Auth,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
    runtime_settings: Option<&Settings>,
) -> Result<Vec<Vec<ScoredPoint>>, StorageError> {
    let mut intermediates = Vec::with_capacity(prefetches.len());
    for prefetch in prefetches {
        let prefetch_request = CollectionQueryRequest {
            prefetch: prefetch.prefetch.clone(),
            query: prefetch.query.clone(),
            using: prefetch.using.clone(),
            filter: prefetch.filter.clone(),
            score_threshold: prefetch
                .score_threshold
                .as_ref()
                .map(|score| score.into_inner()),
            limit: prefetch.limit,
            offset: 0,
            params: prefetch.params.clone(),
            with_vector: WithVector::Bool(false),
            with_payload: WithPayloadInterface::Bool(false),
            lookup_from: prefetch.lookup_from.clone(),
        };
        intermediates.push(
            Box::pin(do_query_points(
                toc,
                collection_name,
                prefetch_request,
                read_consistency,
                shard_selection.clone(),
                auth.clone(),
                timeout,
                hw_measurement_acc.clone(),
                runtime_settings,
            ))
            .await?,
        );
    }

    Ok(intermediates)
}

fn ckks_prefetch_candidate_filter(sources: &[Vec<ScoredPoint>]) -> Option<Filter> {
    if sources.is_empty() {
        return None;
    }

    Some(
        Filter::new().with_point_ids(
            sources
                .iter()
                .flat_map(|source| source.iter().map(|point| point.id)),
        ),
    )
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
            enum CkksResolvedQueryRequest<'a> {
                Ready(Vec<ScoredPoint>),
                Plain(CollectionQueryRequest, ShardSelectorInternal),
                Core(CoreSearchRequest, ShardSelectorInternal),
                StoredNearest {
                    vector_name: String,
                    query_point_id: String,
                    query_encrypted: EncryptedCkksVector,
                    filter: Option<Filter>,
                    params: Option<SearchParams>,
                    limit: usize,
                    offset: usize,
                    with_payload: WithPayloadInterface,
                    with_vector: WithVector,
                    score_threshold: Option<f32>,
                    shard_selection: ShardSelectorInternal,
                },
                Scoring {
                    vector_name: String,
                    scoring: CkksSidecarScoring<'a>,
                    filter: Option<Filter>,
                    params: Option<SearchParams>,
                    limit: usize,
                    offset: usize,
                    with_payload: WithPayloadInterface,
                    with_vector: WithVector,
                    score_threshold: Option<f32>,
                    shard_selection: ShardSelectorInternal,
                },
            }

            let mut has_encrypted_query = false;
            let mut core_requests = Vec::with_capacity(requests.len());

            for (request, shard_selection) in &requests {
                let root_uses_encrypted_vector = plan.contains_vector_name(&request.using);
                let mut prefetches = request.prefetch.iter().collect::<Vec<_>>();
                let mut has_encrypted_prefetch = false;
                while let Some(prefetch) = prefetches.pop() {
                    if plan.contains_vector_name(&prefetch.using) {
                        has_encrypted_prefetch = true;
                    }
                    prefetches.extend(prefetch.prefetch.iter());
                }
                if has_encrypted_prefetch {
                    if let Some(Query::Fusion(fusion)) = &request.query {
                        if request.with_vector.is_enabled() {
                            return Err(StorageError::bad_input(
                                "cannot return encrypted vectors from CKKS prefetch fusion; CKKS vector ciphertext read path returns payload sidecar only",
                            ));
                        }

                        let intermediates = ckks_resolve_query_prefetches(
                            toc,
                            collection_name,
                            &request.prefetch,
                            read_consistency,
                            shard_selection,
                            &auth,
                            timeout,
                            hw_measurement_acc.clone(),
                            runtime_settings,
                        )
                        .await?;
                        let mut fused = match fusion {
                            FusionInternal::Rrf { k, weights } => {
                                let weights_slice = weights.as_ref().map(|weights| {
                                    weights.iter().map(|w| w.into_inner()).collect::<Vec<_>>()
                                });
                                rrf_scoring(intermediates, *k, weights_slice.as_deref())
                                    .map_err(|err| StorageError::bad_input(err.to_string()))?
                            }
                            FusionInternal::Dbsf => {
                                score_fusion(intermediates, ScoreFusion::dbsf())
                            }
                        };
                        if let Some(score_threshold) = request.score_threshold {
                            fused = fused
                                .into_iter()
                                .take_while(|point| point.score >= score_threshold)
                                .collect();
                        }
                        let mut top = fused
                            .into_iter()
                            .skip(request.offset)
                            .take(request.limit)
                            .collect::<Vec<_>>();
                        ckks_fill_scored_points_payload_or_vectors(
                            &collection,
                            &mut top,
                            request.with_payload.clone(),
                            WithVector::Bool(false),
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        has_encrypted_query = true;
                        core_requests.push(Some(CkksResolvedQueryRequest::Ready(top)));
                        continue;
                    }
                }

                let prefetch_candidate_filter = if has_encrypted_prefetch
                    || (root_uses_encrypted_vector && !request.prefetch.is_empty())
                {
                    let intermediates = ckks_resolve_query_prefetches(
                        toc,
                        collection_name,
                        &request.prefetch,
                        read_consistency,
                        shard_selection,
                        &auth,
                        timeout,
                        hw_measurement_acc.clone(),
                        runtime_settings,
                    )
                    .await?;
                    has_encrypted_query = true;
                    ckks_prefetch_candidate_filter(&intermediates)
                } else {
                    None
                };
                let has_prefetch_candidate_filter = prefetch_candidate_filter.is_some();
                let effective_filter =
                    Filter::merge_opts(request.filter.clone(), prefetch_candidate_filter);

                if !root_uses_encrypted_vector {
                    let mut request = request.clone();
                    if has_prefetch_candidate_filter {
                        request.prefetch.clear();
                        request.filter = effective_filter;
                    }
                    core_requests.push(Some(CkksResolvedQueryRequest::Plain(
                        request,
                        shard_selection.clone(),
                    )));
                    continue;
                }

                has_encrypted_query = true;
                if request.lookup_from.is_some() {
                    return Err(StorageError::bad_input(format!(
                        "encrypted vector '{}' query does not support lookup_from; provide a raw dense query vector or a point id with an encrypted sidecar",
                        request.using,
                    )));
                }
                let resolved_request = match &request.query {
                    Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::CkksEncryptedQuery(input),
                    ))) => {
                        let query = ckks_client_encrypted_query_source(&request.using, input)?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring: CkksSidecarScoring::NearestResolved { query },
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(
                        point_id,
                    )))) => {
                        let query_encrypted = ckks_vector_sidecar_for_point_id(
                            &collection,
                            &request.using,
                            *point_id,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::StoredNearest {
                            vector_name: request.using.clone(),
                            query_point_id: point_id.to_string(),
                            query_encrypted,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend)))
                        if reco_query_single_positive_point_id(recommend).is_some() =>
                    {
                        let point_id = reco_query_single_positive_point_id(recommend)
                            .expect("checked by match guard");
                        let query_encrypted = ckks_vector_sidecar_for_point_id(
                            &collection,
                            &request.using,
                            point_id,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::StoredNearest {
                            vector_name: request.using.clone(),
                            query_point_id: point_id.to_string(),
                            query_encrypted,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend)))
                        if reco_query_needs_sidecar_resolution(recommend) =>
                    {
                        let scoring = ckks_reco_query_as_scoring(
                            &collection,
                            &request.using,
                            recommend,
                            RecommendStrategy::AverageVector,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::RecommendBestScore(recommend)))
                        if reco_query_needs_sidecar_resolution(recommend) =>
                    {
                        let scoring = ckks_reco_query_as_scoring(
                            &collection,
                            &request.using,
                            recommend,
                            RecommendStrategy::BestScore,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::RecommendSumScores(recommend)))
                        if reco_query_needs_sidecar_resolution(recommend) =>
                    {
                        let scoring = ckks_reco_query_as_scoring(
                            &collection,
                            &request.using,
                            recommend,
                            RecommendStrategy::SumScores,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::NearestWithMmr(nearest_with_mmr))) => {
                        let query = ckks_vector_input_as_query_source(
                            &collection,
                            &request.using,
                            "MMR nearest",
                            &nearest_with_mmr.nearest,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring: CkksSidecarScoring::NearestMmr {
                                query,
                                lambda: nearest_with_mmr
                                    .mmr
                                    .diversity
                                    .map(|diversity| 1.0 - diversity)
                                    .unwrap_or(0.5),
                                candidates_limit: nearest_with_mmr
                                    .mmr
                                    .candidates_limit
                                    .unwrap_or(request.limit),
                            },
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::Context(context))) => {
                        let scoring = ckks_context_query_as_scoring(
                            &collection,
                            &request.using,
                            context,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    Some(Query::Vector(VectorQuery::Discover(discover))) => {
                        let scoring = ckks_discover_query_as_scoring(
                            &collection,
                            &request.using,
                            discover,
                            read_consistency,
                            shard_selection,
                            timeout,
                            hw_measurement_acc.clone(),
                        )
                        .await?;
                        CkksResolvedQueryRequest::Scoring {
                            vector_name: request.using.clone(),
                            scoring,
                            filter: effective_filter.clone(),
                            params: request.params.clone(),
                            limit: request.limit,
                            offset: request.offset,
                            with_payload: request.with_payload.clone(),
                            with_vector: request.with_vector.clone(),
                            score_threshold: request.score_threshold,
                            shard_selection: shard_selection.clone(),
                        }
                    }
                    _ => {
                        let query = ckks_query_as_core_query(&request.query, &request.using)?;
                        CkksResolvedQueryRequest::Core(
                            CoreSearchRequest {
                                query,
                                filter: effective_filter.clone(),
                                params: request.params.clone(),
                                limit: request.limit,
                                offset: request.offset,
                                with_payload: Some(request.with_payload.clone()),
                                with_vector: Some(request.with_vector.clone()),
                                score_threshold: request.score_threshold,
                            },
                            shard_selection.clone(),
                        )
                    }
                };

                core_requests.push(Some(resolved_request));
            }

            if has_encrypted_query {
                let mut results = Vec::with_capacity(core_requests.len());
                for request in core_requests {
                    let Some(request) = request else {
                        unreachable!("plain query requests are represented explicitly");
                    };
                    let result = match request {
                        CkksResolvedQueryRequest::Ready(result) => result,
                        CkksResolvedQueryRequest::Plain(request, shard_selection) => {
                            ensure_with_vector_does_not_request_encrypted_vectors(
                                toc,
                                collection_name,
                                &request.with_vector,
                                &auth,
                                "query",
                            )
                            .await?;
                            let mut plain_results = toc
                                .query_batch(
                                    collection_name,
                                    vec![(request, shard_selection)],
                                    read_consistency,
                                    auth.clone(),
                                    timeout,
                                    hw_measurement_acc.clone(),
                                )
                                .await?;
                            plain_results.pop().ok_or_else(|| {
                                StorageError::service_error(
                                    "plaintext query result missing from mixed CKKS vector batch",
                                )
                            })?
                        }
                        CkksResolvedQueryRequest::Core(request, shard_selection) => {
                            ckks_vector_search_points(
                                &collection,
                                collection_name,
                                &collection_crypto_id,
                                &request,
                                &plan,
                                read_consistency,
                                &shard_selection,
                                timeout,
                                hw_measurement_acc.clone(),
                            )
                            .await?
                        }
                        CkksResolvedQueryRequest::StoredNearest {
                            vector_name,
                            query_point_id,
                            query_encrypted,
                            filter,
                            params,
                            limit,
                            offset,
                            with_payload,
                            with_vector,
                            score_threshold,
                            shard_selection,
                        } => {
                            ckks_vector_search_points_with_scoring(
                                &collection,
                                collection_name,
                                &collection_crypto_id,
                                &vector_name,
                                CkksSidecarScoring::StoredNearest {
                                    query_point_id,
                                    query_encrypted,
                                },
                                filter,
                                params,
                                limit,
                                offset,
                                Some(with_payload),
                                Some(with_vector),
                                score_threshold,
                                &plan,
                                read_consistency,
                                &shard_selection,
                                timeout,
                                hw_measurement_acc.clone(),
                            )
                            .await?
                        }
                        CkksResolvedQueryRequest::Scoring {
                            vector_name,
                            scoring,
                            filter,
                            params,
                            limit,
                            offset,
                            with_payload,
                            with_vector,
                            score_threshold,
                            shard_selection,
                        } => {
                            ckks_vector_search_points_with_scoring(
                                &collection,
                                collection_name,
                                &collection_crypto_id,
                                &vector_name,
                                scoring,
                                filter,
                                params,
                                limit,
                                offset,
                                Some(with_payload),
                                Some(with_vector),
                                score_threshold,
                                &plan,
                                read_consistency,
                                &shard_selection,
                                timeout,
                                hw_measurement_acc.clone(),
                            )
                            .await?
                        }
                    };
                    results.push(result);
                }
                return Ok(results);
            }
        }
    }

    for (request, _) in &requests {
        ensure_with_vector_does_not_request_encrypted_vectors(
            toc,
            collection_name,
            &request.with_vector,
            &auth,
            "query",
        )
        .await?;
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

    ensure_with_vector_does_not_request_encrypted_vectors(
        toc,
        collection_name,
        &request.with_vector,
        &auth,
        "query groups",
    )
    .await?;
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
    let mut has_encrypted_prefetch = false;
    while let Some(prefetch) = prefetches.pop() {
        if plan.contains_vector_name(&prefetch.using) {
            has_encrypted_prefetch = true;
        }
        prefetches.extend(prefetch.prefetch.iter());
    }
    let root_uses_encrypted_vector = plan.contains_vector_name(&request.using);
    if has_encrypted_prefetch {
        if let Some(Query::Fusion(fusion)) = &request.query {
            if request.with_vector.is_enabled() {
                return Err(StorageError::bad_input(
                    "cannot return encrypted vectors from CKKS prefetch fusion groups; CKKS vector ciphertext read path returns payload sidecar only",
                ));
            }
            ensure_group_path_does_not_touch_encrypted_vector_sidecar(&request.group_by)?;

            let intermediates = ckks_resolve_query_prefetches(
                toc,
                collection_name,
                &request.prefetch,
                read_consistency,
                shard_selection,
                auth,
                timeout,
                hw_measurement_acc.clone(),
                Some(runtime_settings),
            )
            .await?;
            let mut fused = match fusion {
                FusionInternal::Rrf { k, weights } => {
                    let weights_slice = weights
                        .as_ref()
                        .map(|weights| weights.iter().map(|w| w.into_inner()).collect::<Vec<_>>());
                    rrf_scoring(intermediates, *k, weights_slice.as_deref())
                        .map_err(|err| StorageError::bad_input(err.to_string()))?
                }
                FusionInternal::Dbsf => score_fusion(intermediates, ScoreFusion::dbsf()),
            };
            if let Some(score_threshold) = request.score_threshold {
                fused = fused
                    .into_iter()
                    .take_while(|point| point.score >= score_threshold)
                    .collect();
            }
            ckks_fill_scored_points_payload_or_vectors(
                &collection,
                &mut fused,
                WithPayloadInterface::Bool(true),
                WithVector::Bool(false),
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            let result = ckks_vector_group_scored_points(
                &collection,
                fused,
                &request.group_by,
                request.limit,
                request.group_size,
                request.with_payload.clone(),
                read_consistency,
                shard_selection,
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;
            return attach_ckks_group_lookup(
                toc,
                result,
                request.with_lookup.clone(),
                read_consistency,
                shard_selection,
                auth,
                timeout,
                hw_measurement_acc,
            )
            .await
            .map(Some);
        }
    }

    let prefetch_candidate_filter =
        if has_encrypted_prefetch || (root_uses_encrypted_vector && !request.prefetch.is_empty()) {
            let intermediates = ckks_resolve_query_prefetches(
                toc,
                collection_name,
                &request.prefetch,
                read_consistency,
                shard_selection,
                auth,
                timeout,
                hw_measurement_acc.clone(),
                Some(runtime_settings),
            )
            .await?;
            ckks_prefetch_candidate_filter(&intermediates)
        } else {
            None
        };
    let has_prefetch_candidate_filter = prefetch_candidate_filter.is_some();
    let effective_filter = Filter::merge_opts(request.filter.clone(), prefetch_candidate_filter);

    if !root_uses_encrypted_vector {
        if has_prefetch_candidate_filter {
            let request = CollectionQueryGroupsRequest {
                prefetch: Vec::new(),
                query: request.query.clone(),
                using: request.using.clone(),
                filter: effective_filter,
                params: request.params.clone(),
                score_threshold: request.score_threshold,
                with_vector: request.with_vector.clone(),
                with_payload: request.with_payload.clone(),
                lookup_from: request.lookup_from.clone(),
                group_by: request.group_by.clone(),
                group_size: request.group_size,
                limit: request.limit,
                with_lookup: request.with_lookup.clone(),
            };
            ensure_group_path_does_not_touch_encrypted_vector_sidecar(&request.group_by)?;
            return toc
                .group(
                    collection_name,
                    GroupRequest::from(request),
                    read_consistency,
                    shard_selection.clone(),
                    auth.clone(),
                    timeout,
                    hw_measurement_acc,
                )
                .await
                .map(Some);
        }
        return Ok(None);
    }
    if request.lookup_from.is_some() {
        return Err(StorageError::bad_input(format!(
            "encrypted vector '{}' query groups do not support lookup_from; provide a plaintext dense query vector",
            request.using,
        )));
    }
    ensure_group_path_does_not_touch_encrypted_vector_sidecar(&request.group_by)?;

    if let Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend))) = &request.query
        && let Some(point_id) = reco_query_single_positive_point_id(recommend)
    {
        let query_encrypted = ckks_vector_sidecar_for_point_id(
            &collection,
            &request.using,
            point_id,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            CkksSidecarScoring::StoredNearest {
                query_point_id: point_id.to_string(),
                query_encrypted,
            },
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::RecommendAverageVector(recommend))) = &request.query
        && reco_query_needs_sidecar_resolution(recommend)
    {
        let scoring = ckks_reco_query_as_scoring(
            &collection,
            &request.using,
            recommend,
            RecommendStrategy::AverageVector,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::RecommendBestScore(recommend))) = &request.query
        && reco_query_needs_sidecar_resolution(recommend)
    {
        let scoring = ckks_reco_query_as_scoring(
            &collection,
            &request.using,
            recommend,
            RecommendStrategy::BestScore,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::RecommendSumScores(recommend))) = &request.query
        && reco_query_needs_sidecar_resolution(recommend)
    {
        let scoring = ckks_reco_query_as_scoring(
            &collection,
            &request.using,
            recommend,
            RecommendStrategy::SumScores,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::Discover(discover))) = &request.query {
        let scoring = ckks_discover_query_as_scoring(
            &collection,
            &request.using,
            discover,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::Context(context))) = &request.query {
        let scoring = ckks_context_query_as_scoring(
            &collection,
            &request.using,
            context,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            scoring,
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::CkksEncryptedQuery(
        input,
    )))) = &request.query
    {
        let query = ckks_client_encrypted_query_source(&request.using, input)?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            CkksSidecarScoring::NearestResolved { query },
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(point_id)))) =
        &request.query
    {
        let query_encrypted = ckks_vector_sidecar_for_point_id(
            &collection,
            &request.using,
            *point_id,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            CkksSidecarScoring::StoredNearest {
                query_point_id: point_id.to_string(),
                query_encrypted,
            },
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    if let Some(Query::Vector(VectorQuery::NearestWithMmr(nearest_with_mmr))) = &request.query {
        let query = ckks_vector_input_as_query_source(
            &collection,
            &request.using,
            "MMR nearest",
            &nearest_with_mmr.nearest,
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        let result = ckks_vector_group_points_with_scoring(
            &collection,
            collection_name,
            &collection_crypto_id,
            &request.using,
            CkksSidecarScoring::NearestMmr {
                query,
                lambda: nearest_with_mmr
                    .mmr
                    .diversity
                    .map(|diversity| 1.0 - diversity)
                    .unwrap_or(0.5),
                candidates_limit: nearest_with_mmr
                    .mmr
                    .candidates_limit
                    .unwrap_or(request.limit),
            },
            effective_filter.clone(),
            request.params.clone(),
            request.score_threshold,
            &plan,
            &request.group_by,
            request.limit,
            request.group_size,
            request.with_payload.clone(),
            read_consistency,
            shard_selection,
            timeout,
            hw_measurement_acc.clone(),
        )
        .await?;
        return attach_ckks_group_lookup(
            toc,
            result,
            request.with_lookup.clone(),
            read_consistency,
            shard_selection,
            auth,
            timeout,
            hw_measurement_acc,
        )
        .await
        .map(Some);
    }

    let search_request = CoreSearchRequest {
        query: ckks_query_as_core_query(&request.query, &request.using)?,
        filter: effective_filter.clone(),
        params: request.params.clone(),
        limit: usize::MAX,
        offset: 0,
        with_payload: Some(WithPayloadInterface::Bool(true)),
        with_vector: Some(WithVector::Bool(false)),
        score_threshold: request.score_threshold,
    };
    let result = ckks_vector_group_points(
        &collection,
        collection_name,
        &collection_crypto_id,
        &search_request,
        &plan,
        &request.group_by,
        request.limit,
        request.group_size,
        request.with_payload.clone(),
        read_consistency,
        shard_selection,
        timeout,
        hw_measurement_acc.clone(),
    )
    .await?;
    attach_ckks_group_lookup(
        toc,
        result,
        request.with_lookup.clone(),
        read_consistency,
        shard_selection,
        auth,
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
        Some(Query::Vector(VectorQuery::Context(context))) => {
            ckks_context_query_as_core_context(context, vector_name)
                .map(|query| QueryEnum::Context(NamedQuery::new(query, vector_name.to_string())))
        }
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Id(_)))) => {
            Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' query cannot resolve point-id query vectors because plaintext vectors are not stored",
            )))
        }
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::CkksEncryptedQuery(_)))) => {
            Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' client CKKS query requires CKKS sidecar scoring",
            )))
        }
        Some(Query::Vector(VectorQuery::Nearest(VectorInputInternal::Vector(_)))) => {
            Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' only supports dense query vectors",
            )))
        }
        _ => Err(StorageError::bad_input(format!(
            "encrypted vector '{vector_name}' only supports nearest-neighbor dense query, raw-dense recommend, raw-dense discover, or raw-dense context",
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
            VectorInputInternal::CkksEncryptedQuery(_) => Err(StorageError::bad_input(format!(
                "encrypted vector '{vector_name}' query does not support client CKKS encrypted {role} examples in recommend/discover/context inputs",
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

fn ckks_context_query_as_core_context(
    context: &segment::vector_storage::query::ContextQuery<VectorInputInternal>,
    vector_name: &str,
) -> Result<segment::vector_storage::query::ContextQuery<VectorInternal>, StorageError> {
    let pairs = context
        .pairs
        .iter()
        .map(|pair| {
            let VectorInputInternal::Vector(VectorInternal::Dense(positive)) = &pair.positive else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' context query cannot resolve point-id or non-dense positive examples because plaintext vectors are not stored",
                )));
            };
            let VectorInputInternal::Vector(VectorInternal::Dense(negative)) = &pair.negative else {
                return Err(StorageError::bad_input(format!(
                    "encrypted vector '{vector_name}' context query cannot resolve point-id or non-dense negative examples because plaintext vectors are not stored",
                )));
            };
            Ok(ContextPair {
                positive: VectorInternal::Dense(positive.clone()),
                negative: VectorInternal::Dense(negative.clone()),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(segment::vector_storage::query::ContextQuery::new(pairs))
}

fn search_group_vector_name(vector: &api::rest::NamedVectorStruct) -> &str {
    match vector {
        api::rest::NamedVectorStruct::Default(_) => DEFAULT_VECTOR_NAME,
        api::rest::NamedVectorStruct::CkksEncryptedQuery(vector) => {
            vector.name.as_deref().unwrap_or(DEFAULT_VECTOR_NAME)
        }
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
    ensure_encrypted_vector_name_is_unsupported(
        toc,
        collection_name,
        vector_name,
        auth,
        "group by search over",
        "runtime OpenFHE settings are required for CKKS sidecar grouped search",
    )
    .await
}

async fn ensure_encrypted_vector_name_is_unsupported(
    toc: &TableOfContent,
    collection_name: &str,
    vector_name: &str,
    auth: &Auth,
    operation: &str,
    reason: &str,
) -> Result<(), StorageError> {
    let collection_pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "encrypted_vector_operation_guard",
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
                    "cannot {operation} encrypted vector '{vector_name}'; {reason}",
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
    runtime_settings: Option<&Settings>,
) -> Result<CollectionSearchMatrixResponse, StorageError> {
    if let Some(settings) = runtime_settings {
        let collection_pass = auth.check_collection_access(
            collection_name,
            AccessRequirements::new(),
            "ckks_vector_search_matrix",
        )?;
        let collection = toc.get_collection(&collection_pass).await?;
        let config = collection.config_snapshot().await;
        let collection_crypto_id = config.stable_crypto_id(collection_name)?;
        if let Some(plan) = vector_write_plan_for_collection_with_crypto_id(
            settings,
            collection_name,
            &collection_crypto_id,
            &config.params,
        )? && plan.contains_vector_name(&request.using)
        {
            return ckks_vector_search_points_matrix(
                &collection,
                collection_name,
                &request,
                &plan,
                read_consistency,
                &shard_selection,
                timeout,
                hw_measurement_acc,
            )
            .await;
        }
    }

    ensure_encrypted_vector_name_is_unsupported(
        toc,
        collection_name,
        &request.using,
        &auth,
        "search matrix using",
        "runtime OpenFHE settings are required for CKKS sidecar matrix search",
    )
    .await?;

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

#[allow(clippy::too_many_arguments)]
async fn ckks_vector_search_points_matrix(
    collection: &collection::collection::Collection,
    collection_name: &str,
    request: &CollectionSearchMatrixRequest,
    plan: &crate::common::crypto::VectorWritePlan,
    read_consistency: Option<ReadConsistency>,
    shard_selection: &ShardSelectorInternal,
    timeout: Option<Duration>,
    hw_measurement_acc: HwMeasurementAcc,
) -> Result<CollectionSearchMatrixResponse, StorageError> {
    if request.sample_size == 0 || request.limit_per_sample == 0 {
        return Ok(CollectionSearchMatrixResponse::default());
    }

    let vector_name = request.using.as_str();
    let distance = plan.distance_for_vector(vector_name).ok_or_else(|| {
        StorageError::service_error(format!(
            "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
        ))
    })?;
    let score_order = distance.distance_order();
    let mut next_offset = None;
    let mut sampled = Vec::with_capacity(request.sample_size);
    const BATCH_SIZE: usize = 512;

    while sampled.len() < request.sample_size {
        let scroll_result = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: next_offset,
                    limit: Some(BATCH_SIZE),
                    filter: request.filter.clone(),
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

        for record in scroll_result.points {
            let Some(payload) = record.payload.as_ref() else {
                continue;
            };
            let Some(encrypted) = encrypted_vector_from_payload(payload, vector_name)? else {
                continue;
            };
            sampled.push(CkksSidecarSearchRecord {
                id: record.id,
                shard_key: record.shard_key,
                point_id: record.id.to_string(),
                encrypted,
            });
            if sampled.len() >= request.sample_size {
                break;
            }
        }

        let Some(offset) = scroll_result.next_page_offset else {
            break;
        };
        next_offset = Some(offset);
    }

    if sampled.len() < 2 {
        return Ok(CollectionSearchMatrixResponse::default());
    }

    sampled.sort_unstable_by_key(|record| record.id);
    let sample_ids = sampled.iter().map(|record| record.id).collect::<Vec<_>>();
    let encrypted_items = sampled
        .iter()
        .map(|record| (record.point_id.clone(), record.encrypted.clone()))
        .collect::<Vec<_>>();
    let mut nearests = Vec::with_capacity(sampled.len());

    for query in &sampled {
        let scores = plan
            .score_stored_query_batch(
                collection_name,
                vector_name,
                &query.point_id,
                &query.encrypted,
                &encrypted_items,
            )?
            .ok_or_else(|| {
                StorageError::service_error(format!(
                    "CKKS vector search plan lost rule for encrypted vector '{vector_name}'",
                ))
            })?;
        let mut scored = sampled
            .iter()
            .zip(scores)
            .filter_map(|(record, score)| {
                (record.id != query.id).then(|| ScoredPoint {
                    id: record.id,
                    version: 0,
                    score,
                    payload: None,
                    vector: None,
                    shard_key: record.shard_key.clone(),
                    order_value: None,
                })
            })
            .collect::<Vec<_>>();
        sort_ckks_scored_points(score_order, &mut scored);
        scored.truncate(request.limit_per_sample);
        nearests.push(scored);
    }

    Ok(CollectionSearchMatrixResponse {
        sample_ids,
        nearests,
    })
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
        assert!(ckks_search_params_supported(&hnsw_params));

        let indexed_only_params = SearchParams {
            indexed_only: true,
            ..SearchParams::default()
        };
        assert!(!ckks_search_params_supported(&indexed_only_params));

        let quantization_params = SearchParams {
            quantization: Some(segment::types::QuantizationSearchParams::default()),
            ..SearchParams::default()
        };
        assert!(!ckks_search_params_supported(&quantization_params));

        let acorn_params = SearchParams {
            acorn: Some(segment::types::AcornSearchParams::default()),
            ..SearchParams::default()
        };
        assert!(!ckks_search_params_supported(&acorn_params));
    }

    #[test]
    fn ckks_sidecar_hnsw_links_remain_reciprocal_when_pruned() {
        let mut links = vec![Vec::<usize>::new(); 4];
        ckks_sidecar_hnsw_add_bounded_undirected_link(&mut links, 1, 0, 2);
        ckks_sidecar_hnsw_add_bounded_undirected_link(&mut links, 2, 0, 2);
        ckks_sidecar_hnsw_add_bounded_undirected_link(&mut links, 3, 0, 2);

        assert_eq!(links[0], vec![2, 3]);
        assert!(!links[1].contains(&0));
        assert!(!links[0].contains(&1));
        assert!(links[2].contains(&0));
        assert!(links[3].contains(&0));
    }

    #[test]
    fn ckks_sidecar_hnsw_connectivity_backbone_restores_pruned_graph() {
        let mut links = vec![Vec::<usize>::new(); 4];
        ckks_sidecar_hnsw_add_bounded_undirected_link(&mut links, 1, 0, 2);
        ckks_sidecar_hnsw_add_bounded_undirected_link(&mut links, 2, 0, 2);
        ckks_sidecar_hnsw_add_bounded_undirected_link(&mut links, 3, 0, 2);

        assert!(!ckks_sidecar_hnsw_links_are_connected(&links));
        ckks_sidecar_hnsw_add_connectivity_backbone(&mut links);

        assert!(ckks_sidecar_hnsw_links_are_reciprocal(&links));
        assert!(ckks_sidecar_hnsw_links_are_connected(&links));
    }

    fn ckks_sidecar_test_record(point_id: u64, ciphertext: &str) -> CkksSidecarSearchRecord {
        CkksSidecarSearchRecord {
            id: point_id.into(),
            shard_key: None,
            point_id: point_id.to_string(),
            encrypted: EncryptedCkksVector {
                version: 1,
                scheme: qdrant_sec::CKKS_SCHEME.to_string(),
                envelope: qdrant_sec::EncryptedEnvelope {
                    version: 1,
                    algorithm: "AES-256-GCM".to_string(),
                    key_id: "test-key".to_string(),
                    material_fingerprint: "test-material".to_string(),
                    rk_id: "test-rk".to_string(),
                    rk_epoch: Some(1),
                    nonce: "AAAAAAAAAAAAAAAA".to_string(),
                    ciphertext: ciphertext.to_string(),
                },
            },
        }
    }

    #[test]
    fn ckks_sidecar_hnsw_records_fingerprint_tracks_ciphertext_changes() {
        let first = ckks_sidecar_hnsw_records_fingerprint(&[
            ckks_sidecar_test_record(1, "ciphertext-a"),
            ckks_sidecar_test_record(2, "ciphertext-b"),
        ]);
        let changed = ckks_sidecar_hnsw_records_fingerprint(&[
            ckks_sidecar_test_record(1, "ciphertext-a"),
            ckks_sidecar_test_record(2, "ciphertext-c"),
        ]);

        assert_ne!(first, changed);
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_key_uses_collection_identity() {
        let first = CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid-a".to_string(),
            vector_name: "vector".to_string(),
            score_order: "large",
            m: 16,
            records_fingerprint: "fingerprint-a".to_string(),
        };
        let second = CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid-b".to_string(),
            ..first.clone()
        };

        assert_ne!(
            ckks_sidecar_hnsw_graph_cache_file_name(&first),
            ckks_sidecar_hnsw_graph_cache_file_name(&second),
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_graph_cache_evicts_old_entries() {
        let mut cache = CkksSidecarHnswGraphCache::default();
        let original_key = ckks_sidecar_test_graph_cache_key("original");
        let original_graph = Arc::new(CkksSidecarHnswGraph {
            links: Arc::new(vec![vec![1], vec![0]]),
        });
        cache.insert(original_key.clone(), original_graph.clone());
        assert!(Arc::ptr_eq(
            &cache.get(&original_key).unwrap(),
            &original_graph
        ));

        for idx in 0..CKKS_SIDECAR_HNSW_GRAPH_CACHE_CAPACITY {
            cache.insert(
                ckks_sidecar_test_graph_cache_key(format!("fresh-{idx}")),
                Arc::new(CkksSidecarHnswGraph {
                    links: Arc::new(Vec::new()),
                }),
            );
        }

        assert!(cache.get(&original_key).is_none());
    }

    fn ckks_sidecar_test_graph_cache_key(
        records_fingerprint: impl Into<String>,
    ) -> CkksSidecarHnswGraphCacheKey {
        CkksSidecarHnswGraphCacheKey {
            collection_identity: "collection-uuid".to_string(),
            vector_name: "vector".to_string(),
            score_order: "large",
            m: 16,
            records_fingerprint: records_fingerprint.into(),
        }
    }

    fn ckks_sidecar_test_graph_disk(
        key: &CkksSidecarHnswGraphCacheKey,
        links: Vec<Vec<usize>>,
    ) -> CkksSidecarHnswGraphDisk {
        CkksSidecarHnswGraphDisk {
            version: CKKS_SIDECAR_HNSW_GRAPH_CACHE_VERSION,
            collection_identity: key.collection_identity.clone(),
            vector_name: key.vector_name.clone(),
            score_order: key.score_order.to_string(),
            m: key.m,
            records_fingerprint: key.records_fingerprint.clone(),
            links,
        }
    }

    fn set_ckks_sidecar_test_private_directory_permissions(directory: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn write_ckks_sidecar_test_graph_disk(
        collection_path: &Path,
        key: &CkksSidecarHnswGraphCacheKey,
        disk: &CkksSidecarHnswGraphDisk,
    ) -> PathBuf {
        let path = ckks_sidecar_hnsw_graph_cache_path(collection_path, key);
        let directory = path.parent().unwrap();
        std::fs::create_dir_all(directory).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(directory);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        let mut file = options.open(&path).unwrap();
        file.write_all(&serde_json::to_vec(disk).unwrap()).unwrap();
        path
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_roundtrips_by_cache_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let graph = CkksSidecarHnswGraph {
            links: Arc::new(vec![vec![1], vec![0, 2], vec![1]]),
        };

        ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap();
        let loaded = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 3)
            .unwrap()
            .unwrap();
        assert_eq!(*loaded.links, *graph.links);

        let stale_key = CkksSidecarHnswGraphCacheKey {
            records_fingerprint: "fingerprint-b".to_string(),
            ..key
        };
        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &stale_key, 3)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_metadata_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let mut disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1], vec![0]]);
        disk.collection_identity = "other-collection-uuid".to_string();
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_out_of_range_links() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![2], vec![0]]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_asymmetric_links() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1], Vec::new()]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_duplicate_links() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1, 1], vec![0]]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_self_loops() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![0, 1], vec![0]]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 2)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_ignores_disconnected_links() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let disk = ckks_sidecar_test_graph_disk(&key, vec![vec![1], vec![0], Vec::new()]);
        write_ckks_sidecar_test_graph_disk(dir.path(), &key, &disk);

        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 3)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_symlink_cache_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_directory = cache_path.parent().unwrap();
        std::fs::create_dir_all(cache_directory).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_directory);
        let target_path = dir.path().join("target.json");
        std::fs::write(&target_path, "{}").unwrap();
        symlink(&target_path, &cache_path).unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 0).unwrap_err();
        assert!(format!("{err}").contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_symlink_cache_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let target_dir = dir.path().join("target-cache-dir");
        std::fs::create_dir(&target_dir).unwrap();
        symlink(
            &target_dir,
            dir.path().join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR),
        )
        .unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 0).unwrap_err();
        assert!(format!("{err}").contains("cache directory"));
        assert!(format!("{err}").contains("must not be a symlink"));

        let graph = CkksSidecarHnswGraph {
            links: Arc::new(vec![Vec::new()]),
        };
        let err = ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap_err();
        assert!(format!("{err}").contains("cache directory"));
        assert!(format!("{err}").contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_group_accessible_cache_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let cache_dir = dir.path().join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
        std::fs::create_dir(&cache_dir).unwrap();
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o750)).unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 0).unwrap_err();
        assert!(format!("{err}").contains("cache directory"));
        assert!(format!("{err}").contains("must not be group/world accessible"));

        let graph = CkksSidecarHnswGraph {
            links: Arc::new(vec![Vec::new()]),
        };
        let err = ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap_err();
        assert!(format!("{err}").contains("cache directory"));
        assert!(format!("{err}").contains("must not be group/world accessible"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_group_accessible_cache_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let graph = CkksSidecarHnswGraph {
            links: Arc::new(vec![Vec::new()]),
        };
        ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap();
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        std::fs::set_permissions(&cache_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 1).unwrap_err();
        assert!(format!("{err}").contains("must not be group/world accessible"));
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_oversized_cache_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("fingerprint-a");
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_directory = cache_path.parent().unwrap();
        std::fs::create_dir_all(cache_directory).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_directory);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        let file = options.open(&cache_path).unwrap();
        file.set_len(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_BYTES + 1)
            .unwrap();

        let err = ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &key, 0).unwrap_err();
        assert!(format!("{err}").contains("exceeds maximum size"));
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prunes_old_cache_files() {
        let dir = tempfile::tempdir().unwrap();
        let graph = CkksSidecarHnswGraph {
            links: Arc::new(vec![Vec::new()]),
        };
        let mut newest_key = None;
        for idx in 0..(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_FILES + 5) {
            let key = ckks_sidecar_test_graph_cache_key(format!("fingerprint-{idx}"));
            ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap();
            newest_key = Some(key);
        }

        let cache_dir = dir.path().join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
        let cache_files = std::fs::read_dir(cache_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("json")
            })
            .count();
        assert!(cache_files <= CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_FILES);

        let newest_key = newest_key.unwrap();
        assert!(
            ckks_sidecar_hnsw_load_persisted_graph(dir.path(), &newest_key, 1)
                .unwrap()
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prune_rejects_symlink_keep_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("keep");
        let keep_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_dir = keep_path.parent().unwrap();
        std::fs::create_dir_all(cache_dir).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_dir);
        let target_path = dir.path().join("target.json");
        std::fs::write(&target_path, "{}").unwrap();
        symlink(&target_path, &keep_path).unwrap();

        let err = ckks_sidecar_hnsw_prune_persisted_graphs(cache_dir, &keep_path).unwrap_err();
        assert!(format!("{err}").contains("keep file"));
        assert!(format!("{err}").contains("must not be a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_rejects_symlink_temp_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let key = ckks_sidecar_test_graph_cache_key("temp-symlink");
        let cache_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &key);
        let cache_dir = cache_path.parent().unwrap();
        std::fs::create_dir_all(cache_dir).unwrap();
        set_ckks_sidecar_test_private_directory_permissions(cache_dir);
        let temp_path = cache_path.with_extension("json.tmp");
        let target_path = dir.path().join("target.tmp");
        std::fs::write(&target_path, "{}").unwrap();
        symlink(&target_path, &temp_path).unwrap();

        let graph = CkksSidecarHnswGraph {
            links: Arc::new(vec![Vec::new()]),
        };
        let err = ckks_sidecar_hnsw_persist_graph(dir.path(), &key, &graph).unwrap_err();
        assert!(format!("{err}").contains("temp file"));
        assert!(format!("{err}").contains("must not be a symlink"));
        assert!(!cache_path.exists());
    }

    #[test]
    fn ckks_sidecar_hnsw_persisted_graph_prunes_by_total_size() {
        let dir = tempfile::tempdir().unwrap();
        let keep_key = ckks_sidecar_test_graph_cache_key("keep");
        let keep_graph = CkksSidecarHnswGraph {
            links: Arc::new(vec![Vec::new()]),
        };
        ckks_sidecar_hnsw_persist_graph(dir.path(), &keep_key, &keep_graph).unwrap();
        let cache_dir = dir.path().join(CKKS_SIDECAR_HNSW_GRAPH_CACHE_DIR);
        let keep_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &keep_key);

        for idx in 0..4 {
            let old_key = ckks_sidecar_test_graph_cache_key(format!("old-{idx}"));
            let old_path = ckks_sidecar_hnsw_graph_cache_path(dir.path(), &old_key);
            let old_directory = old_path.parent().unwrap();
            std::fs::create_dir_all(old_directory).unwrap();
            set_ckks_sidecar_test_private_directory_permissions(old_directory);
            let mut options = std::fs::OpenOptions::new();
            options.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;

                options.mode(0o600);
            }
            let file = options.open(&old_path).unwrap();
            file.set_len(CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_TOTAL_BYTES / 2)
                .unwrap();
        }

        ckks_sidecar_hnsw_prune_persisted_graphs(&cache_dir, &keep_path).unwrap();
        let total_bytes = std::fs::read_dir(cache_dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.metadata().unwrap().len())
            .sum::<u64>();
        assert!(total_bytes <= CKKS_SIDECAR_HNSW_GRAPH_CACHE_MAX_TOTAL_BYTES);
        assert!(keep_path.exists());
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
