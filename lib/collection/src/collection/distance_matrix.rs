use std::time::Duration;

use ahash::AHashSet;
use api::rest::{
    SearchMatrixOffsetsResponse, SearchMatrixPair, SearchMatrixPairsResponse,
    SearchMatrixRequestInternal,
};
use common::counter::hardware_accumulator::HwMeasurementAcc;
use segment::data_types::vectors::DEFAULT_VECTOR_NAME;
use segment::types::{
    Condition, Filter, HasIdCondition, HasVectorCondition, PointIdType, ScoredPoint, VectorNameBuf,
    WithPayloadInterface, WithVector,
};

use crate::collection::Collection;
use crate::config::{
    CollectionEncryptionConfig, EncryptionSelector, encryption_rule_uses_private_hnsw_oram,
    private_hnsw_oram_api_required_message,
};
use crate::operations::consistency_params::ReadConsistency;
use crate::operations::shard_selector_internal::ShardSelectorInternal;
use crate::operations::types::{CollectionError, CollectionResult};
use crate::operations::universal_query::collection_query::{
    CollectionQueryRequest, Query, VectorInputInternal, VectorQuery,
};
use crate::operations::universal_query::shard_query::{
    SampleInternal, ScoringQuery, ShardQueryRequest,
};

#[derive(Debug, Default)]
pub struct CollectionSearchMatrixResponse {
    pub sample_ids: Vec<PointIdType>,    // sampled point ids
    pub nearests: Vec<Vec<ScoredPoint>>, // nearest points for each sampled point
}

/// Internal representation of the distance matrix request, used to convert from REST and gRPC.
pub struct CollectionSearchMatrixRequest {
    pub sample_size: usize,
    pub limit_per_sample: usize,
    pub filter: Option<Filter>,
    pub using: VectorNameBuf,
}

impl CollectionSearchMatrixRequest {
    pub const DEFAULT_LIMIT_PER_SAMPLE: usize = 3;
    pub const DEFAULT_SAMPLE: usize = 10;
}

impl From<SearchMatrixRequestInternal> for CollectionSearchMatrixRequest {
    fn from(request: SearchMatrixRequestInternal) -> Self {
        let SearchMatrixRequestInternal {
            sample,
            limit,
            filter,
            using,
        } = request;
        Self {
            sample_size: sample.unwrap_or(CollectionSearchMatrixRequest::DEFAULT_SAMPLE),
            limit_per_sample: limit
                .unwrap_or(CollectionSearchMatrixRequest::DEFAULT_LIMIT_PER_SAMPLE),
            filter,
            using: using.unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_owned()),
        }
    }
}

impl From<CollectionSearchMatrixResponse> for SearchMatrixOffsetsResponse {
    fn from(response: CollectionSearchMatrixResponse) -> Self {
        let CollectionSearchMatrixResponse {
            sample_ids,
            nearests,
        } = response;
        let offset_by_id = sample_ids
            .iter()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect::<std::collections::HashMap<_, _>>();
        let mut offsets_row = Vec::with_capacity(sample_ids.len());
        let mut offsets_col = Vec::with_capacity(sample_ids.len());
        for (row_offset, scored_points) in nearests.iter().enumerate() {
            for p in scored_points {
                offsets_row.push(row_offset as u64);
                offsets_col.push(offset_by_id[&p.id] as u64);
            }
        }
        let scores = nearests
            .into_iter()
            .flat_map(|row| row.into_iter().map(|p| p.score))
            .collect();
        Self {
            offsets_row,
            offsets_col,
            scores,
            ids: sample_ids,
        }
    }
}

impl From<CollectionSearchMatrixResponse> for SearchMatrixPairsResponse {
    fn from(response: CollectionSearchMatrixResponse) -> Self {
        let CollectionSearchMatrixResponse {
            sample_ids,
            nearests,
        } = response;

        let pairs_len = nearests.iter().map(|n| n.len()).sum();
        let mut pairs = Vec::with_capacity(pairs_len);

        for (a, scored_points) in sample_ids.into_iter().zip(nearests.into_iter()) {
            for scored_point in scored_points {
                pairs.push(SearchMatrixPair {
                    a,
                    b: scored_point.id,
                    score: scored_point.score,
                });
            }
        }

        Self { pairs }
    }
}

impl From<CollectionSearchMatrixResponse> for api::grpc::qdrant::SearchMatrixPairs {
    fn from(response: CollectionSearchMatrixResponse) -> Self {
        let rest_result = SearchMatrixPairsResponse::from(response);
        let pairs = rest_result.pairs.into_iter().map(From::from).collect();
        Self { pairs }
    }
}

impl From<CollectionSearchMatrixResponse> for api::grpc::qdrant::SearchMatrixOffsets {
    fn from(response: CollectionSearchMatrixResponse) -> Self {
        let rest_result = SearchMatrixOffsetsResponse::from(response);
        Self {
            offsets_row: rest_result.offsets_row,
            offsets_col: rest_result.offsets_col,
            scores: rest_result.scores,
            ids: rest_result.ids.into_iter().map(From::from).collect(),
        }
    }
}

impl Collection {
    pub async fn search_points_matrix(
        &self,
        request: CollectionSearchMatrixRequest,
        shard_selection: ShardSelectorInternal,
        read_consistency: Option<ReadConsistency>,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<CollectionSearchMatrixResponse> {
        let start = std::time::Instant::now();
        let CollectionSearchMatrixRequest {
            sample_size,
            limit_per_sample,
            filter,
            using,
        } = request;
        self.ensure_crypto_migration_allows_regular_operation("reads")
            .await?;

        let config = self.collection_config.read().await;
        config.params.check_vector_exists(&using)?;
        if let Some(encryption) = config.params.effective_encryption() {
            if let Some(err) = encrypted_search_matrix_error(&encryption, &using) {
                return Err(err);
            }
        }
        drop(config);

        if limit_per_sample == 0 || sample_size == 0 {
            return Ok(Default::default());
        }

        // make sure the vector is present in the point
        let has_vector = Filter::new_must(Condition::HasVector(HasVectorCondition::from(
            using.clone(),
        )));

        // merge user's filter with the has_vector filter
        let filter = Some(
            filter
                .map(|filter| filter.merge(&has_vector))
                .unwrap_or(has_vector),
        );

        // sample random points
        let sampling_query = ShardQueryRequest {
            prefetches: vec![],
            query: Some(ScoringQuery::Sample(SampleInternal::Random)),
            filter,
            score_threshold: None,
            limit: sample_size,
            offset: 0,
            params: None,
            with_vector: WithVector::Selector(vec![using.clone()]), // retrieve the vector
            with_payload: Default::default(),
        };

        let mut sampled_points = self
            .query(
                sampling_query,
                read_consistency,
                shard_selection.clone(),
                timeout,
                hw_measurement_acc.clone(),
            )
            .await?;

        // if we have less than 2 points, we can't build a matrix
        if sampled_points.len() < 2 {
            return Ok(CollectionSearchMatrixResponse::default());
        }

        sampled_points.truncate(sample_size);
        // sort by id for a deterministic order
        sampled_points.sort_unstable_by_key(|p| p.id);

        // collect the sampled point ids in the same order
        let sampled_point_ids: Vec<_> = sampled_points.iter().map(|p| p.id).collect();

        // filter to only include the sampled points in the search
        // use the same filter for all requests to leverage batch search
        let filter = Filter::new_must(Condition::HasId(HasIdCondition::from(
            sampled_point_ids.iter().copied().collect::<AHashSet<_>>(),
        )));

        // Perform nearest neighbor search for each sampled point
        let mut queries = Vec::with_capacity(sampled_points.len());

        for point in sampled_points {
            let Some(vector) = point
                .vector
                .as_ref()
                .and_then(|v| v.get(&using))
                .map(|v| v.to_owned())
            else {
                return Err(CollectionError::service_error(format!(
                    "sampled point {} does not contain vector {using}",
                    point.id,
                )));
            };

            // nearest query on the sample vector
            let query = Query::Vector(VectorQuery::Nearest(VectorInputInternal::Vector(vector)));

            let query_request = CollectionQueryRequest {
                prefetch: vec![],
                query: Some(query),
                using: using.clone(),
                filter: Some(filter.clone()),
                score_threshold: None,
                limit: limit_per_sample + 1, // +1 to exclude the point itself afterward
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
                lookup_from: None,
            };

            queries.push((query_request, shard_selection.clone()));
        }

        // update timeout
        let timeout = timeout.map(|timeout| timeout.saturating_sub(start.elapsed()));

        // We know by construction that lookup_from is not used in the queries
        // so can use placeholder closure here
        let collection_by_name = |_name: String| async move { None };

        // run batch search request
        let mut nearest = self
            .query_batch(
                queries,
                collection_by_name,
                read_consistency,
                timeout,
                hw_measurement_acc,
            )
            .await?;

        // postprocess the results to account for overlapping samples
        for (scores, sample_id) in nearest.iter_mut().zip(sampled_point_ids.iter()) {
            // need to remove the sample_id from the results
            if let Some(sample_pos) = scores.iter().position(|p| p.id == *sample_id) {
                scores.remove(sample_pos);
            } else {
                // if not found pop lowest score
                if scores.len() == limit_per_sample + 1 {
                    // if we have enough results, remove the last one
                    scores.pop();
                }
            }
        }

        Ok(CollectionSearchMatrixResponse {
            sample_ids: sampled_point_ids,
            nearests: nearest,
        })
    }
}

fn encrypted_search_matrix_error(
    encryption: &CollectionEncryptionConfig,
    using: &str,
) -> Option<CollectionError> {
    for rule in &encryption.rules {
        let EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
        if names.iter().any(|name| name == using) {
            let message = if encryption_rule_uses_private_hnsw_oram(rule) {
                private_hnsw_oram_api_required_message(using)
            } else {
                "cannot build direct collection search matrix for encrypted vector; use the runtime CKKS sidecar matrix entrypoint".to_string()
            };
            return Some(CollectionError::bad_input(message));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use segment::types::ScoredPoint;

    use super::*;
    use crate::config::{CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef};

    fn make_scored_point(id: u64, score: f32) -> ScoredPoint {
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

    // 3 samples, 2 results per sample
    fn fixture_response() -> CollectionSearchMatrixResponse {
        CollectionSearchMatrixResponse {
            sample_ids: vec![1.into(), 2.into(), 3.into()],
            nearests: vec![
                vec![make_scored_point(1, 0.2), make_scored_point(2, 0.1)],
                vec![make_scored_point(2, 0.4), make_scored_point(3, 0.3)],
                vec![make_scored_point(1, 0.6), make_scored_point(3, 0.5)],
            ],
        }
    }

    #[test]
    fn test_matrix_pairs_response_conversion() {
        let response = fixture_response();
        let expected = SearchMatrixPairsResponse {
            pairs: vec![
                SearchMatrixPair::new(1, 1, 0.2),
                SearchMatrixPair::new(1, 2, 0.1),
                SearchMatrixPair::new(2, 2, 0.4),
                SearchMatrixPair::new(2, 3, 0.3),
                SearchMatrixPair::new(3, 1, 0.6),
                SearchMatrixPair::new(3, 3, 0.5),
            ],
        };

        let actual = SearchMatrixPairsResponse::from(response);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_matrix_offsets_response_conversion() {
        let response = fixture_response();
        let expected = SearchMatrixOffsetsResponse {
            offsets_row: vec![0, 0, 1, 1, 2, 2],
            offsets_col: vec![0, 1, 1, 2, 0, 2],
            scores: vec![0.2, 0.1, 0.4, 0.3, 0.6, 0.5],
            ids: vec![1.into(), 2.into(), 3.into()],
        };

        let actual = SearchMatrixOffsetsResponse::from(response);
        assert_eq!(actual, expected);
    }

    fn private_hnsw_matrix_encryption(vector_name: &str) -> CollectionEncryptionConfig {
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
    fn private_hnsw_search_matrix_error_uses_session_api_without_vector_name() {
        let private_vector = "client_state_matrix_private_hnsw";
        let encryption = private_hnsw_matrix_encryption(private_vector);

        let err = encrypted_search_matrix_error(&encryption, private_vector)
            .expect("private HNSW matrix request must be rejected");
        let message = err.to_string();

        assert!(message.contains(qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER));
        assert!(message.contains("/private-hnsw/{vector}/session"));
        assert!(!message.contains(private_vector), "{message}");
        assert!(!message.contains("client_state"), "{message}");
        assert!(encrypted_search_matrix_error(&encryption, "public").is_none());
    }
}
