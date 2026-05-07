use actix_web::{Responder, post, web};
use actix_web_validator::{Json, Path, Query};
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::types::{
    RecommendGroupsRequest, RecommendRequest, RecommendRequestBatch,
};
use itertools::Itertools;
use storage::content_manager::collection_verification::{
    check_strict_mode, check_strict_mode_batch,
};
use storage::dispatcher::Dispatcher;
use tokio::time::Instant;

use super::CollectionPath;
use super::read_params::ReadParams;
use crate::actix::auth::ActixAuth;
use crate::actix::helpers::{self, get_request_hardware_counter, process_response_error};
use crate::settings::{ServiceConfig, Settings};

#[post("/collections/{collection_name}/points/recommend")]
async fn recommend_points(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    request: Json<RecommendRequest>,
    params: Query<ReadParams>,
    service_config: web::Data<ServiceConfig>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let RecommendRequest {
        recommend_request,
        shard_key,
    } = request.into_inner();

    let pass = match check_strict_mode(
        &recommend_request,
        params.timeout_as_secs(),
        &collection.collection_name,
        &dispatcher,
        &auth,
    )
    .await
    {
        Ok(pass) => pass,
        Err(err) => return process_response_error(err, Instant::now(), None),
    };

    let shard_selection = match shard_key {
        None => ShardSelectorInternal::All,
        Some(shard_keys) => shard_keys.into(),
    };

    let request_hw_counter = get_request_hardware_counter(
        &dispatcher,
        collection.collection_name.clone(),
        service_config.hardware_reporting(),
        None,
    );

    let timing = Instant::now();

    let toc = dispatcher.toc(&auth, &pass);
    let result = crate::common::query::do_recommend_points(
        toc,
        &collection.collection_name,
        recommend_request,
        params.consistency,
        shard_selection,
        auth,
        params.timeout(),
        request_hw_counter.get_counter(),
        Some(settings.get_ref()),
    )
    .await
    .map(|scored_points| {
        scored_points
            .into_iter()
            .map(api::rest::ScoredPoint::from)
            .collect_vec()
    });

    helpers::process_response(result, timing, request_hw_counter.to_rest_api())
}

fn recommend_batch_requests(
    request: RecommendRequestBatch,
) -> Vec<(
    collection::operations::types::RecommendRequestInternal,
    ShardSelectorInternal,
)> {
    let requests = request
        .searches
        .into_iter()
        .map(|req| {
            let shard_selector = match req.shard_key {
                None => ShardSelectorInternal::All,
                Some(shard_key) => ShardSelectorInternal::from(shard_key),
            };

            (req.recommend_request, shard_selector)
        })
        .collect();
    requests
}

#[post("/collections/{collection_name}/points/recommend/batch")]
async fn recommend_batch_points(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    request: Json<RecommendRequestBatch>,
    params: Query<ReadParams>,
    service_config: web::Data<ServiceConfig>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let pass = match check_strict_mode_batch(
        request.searches.iter().map(|i| &i.recommend_request),
        params.timeout_as_secs(),
        Some(request.searches.len()),
        &collection.collection_name,
        &dispatcher,
        &auth,
    )
    .await
    {
        Ok(pass) => pass,
        Err(err) => return process_response_error(err, Instant::now(), None),
    };

    let request_hw_counter = get_request_hardware_counter(
        &dispatcher,
        collection.collection_name.clone(),
        service_config.hardware_reporting(),
        None,
    );
    let timing = Instant::now();

    let result = crate::common::query::do_recommend_batch_points(
        dispatcher.toc(&auth, &pass),
        &collection.collection_name,
        recommend_batch_requests(request.into_inner()),
        params.consistency,
        auth,
        params.timeout(),
        request_hw_counter.get_counter(),
        Some(settings.get_ref()),
    )
    .await
    .map(|batch_scored_points| {
        batch_scored_points
            .into_iter()
            .map(|scored_points| {
                scored_points
                    .into_iter()
                    .map(api::rest::ScoredPoint::from)
                    .collect_vec()
            })
            .collect_vec()
    });

    helpers::process_response(result, timing, request_hw_counter.to_rest_api())
}

#[post("/collections/{collection_name}/points/recommend/groups")]
async fn recommend_point_groups(
    dispatcher: web::Data<Dispatcher>,
    collection: Path<CollectionPath>,
    request: Json<RecommendGroupsRequest>,
    params: Query<ReadParams>,
    service_config: web::Data<ServiceConfig>,
    settings: web::Data<Settings>,
    ActixAuth(auth): ActixAuth,
) -> impl Responder {
    let RecommendGroupsRequest {
        recommend_group_request,
        shard_key,
    } = request.into_inner();

    let pass = match check_strict_mode(
        &recommend_group_request,
        params.timeout_as_secs(),
        &collection.collection_name,
        &dispatcher,
        &auth,
    )
    .await
    {
        Ok(pass) => pass,
        Err(err) => return process_response_error(err, Instant::now(), None),
    };

    let shard_selection = match shard_key {
        None => ShardSelectorInternal::All,
        Some(shard_keys) => shard_keys.into(),
    };

    let request_hw_counter = get_request_hardware_counter(
        &dispatcher,
        collection.collection_name.clone(),
        service_config.hardware_reporting(),
        None,
    );
    let timing = Instant::now();

    let result = crate::common::query::do_recommend_point_groups(
        dispatcher.toc(&auth, &pass),
        &collection.collection_name,
        recommend_group_request,
        params.consistency,
        shard_selection,
        auth,
        params.timeout(),
        request_hw_counter.get_counter(),
        Some(settings.get_ref()),
    )
    .await;

    helpers::process_response(result, timing, request_hw_counter.to_rest_api())
}
// Configure services
pub fn config_recommend_api(cfg: &mut web::ServiceConfig) {
    cfg.service(recommend_points)
        .service(recommend_batch_points)
        .service(recommend_point_groups);
}
