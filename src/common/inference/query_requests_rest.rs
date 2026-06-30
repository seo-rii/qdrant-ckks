use api::rest::models::InferenceUsage;
use api::rest::schema as rest;
use collection::lookup::WithLookup;
use collection::operations::universal_query::collection_query::{
    CkksEncryptedQueryInput, CollectionPrefetch, CollectionQueryGroupsRequest,
    CollectionQueryRequest, FeedbackInternal, FeedbackStrategy, Mmr, NearestWithMmr, Query,
    VectorInputInternal, VectorQuery,
};
use collection::operations::universal_query::formula::FormulaInternal;
use collection::operations::universal_query::shard_query::{FusionInternal, SampleInternal};
use ordered_float::OrderedFloat;
use segment::data_types::order_by::OrderBy;
use segment::data_types::vectors::{DEFAULT_VECTOR_NAME, MultiDenseVectorInternal, VectorInternal};
use segment::vector_storage::query::{
    ContextPair, ContextQuery, DiscoverQuery, FeedbackItem, RecoQuery,
};
use storage::content_manager::errors::{StorageError, StorageResult};
use validator::Validate as _;

use crate::common::inference::batch_processing::{
    collect_query_groups_request, collect_query_request,
};
use crate::common::inference::infer_processing::BatchAccumInferred;
use crate::common::inference::params::InferenceParams;
use crate::common::inference::service::{InferenceData, InferenceType};

pub struct CollectionQueryRequestWithUsage {
    pub request: CollectionQueryRequest,
    pub usage: Option<InferenceUsage>,
}

pub struct CollectionQueryGroupsRequestWithUsage {
    pub request: CollectionQueryGroupsRequest,
    pub usage: Option<InferenceUsage>,
}

pub async fn convert_query_groups_request_from_rest(
    request: rest::QueryGroupsRequestInternal,
    inference_params: InferenceParams,
) -> Result<CollectionQueryGroupsRequestWithUsage, StorageError> {
    let batch = collect_query_groups_request(&request);
    let rest::QueryGroupsRequestInternal {
        prefetch,
        query,
        using,
        filter,
        score_threshold,
        params,
        with_vector,
        with_payload,
        lookup_from,
        group_request,
    } = request;

    let (inferred, usage) =
        BatchAccumInferred::from_batch_accum(batch, InferenceType::Search, &inference_params)
            .await?;
    let query = query
        .map(|q| convert_query_with_inferred(q, &inferred))
        .transpose()?;

    let prefetch = prefetch
        .map(|prefetches| {
            prefetches
                .into_iter()
                .map(|p| convert_prefetch_with_inferred(p, &inferred))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let collection_query_groups_request = CollectionQueryGroupsRequest {
        prefetch,
        query,
        using: using.unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_owned()),
        filter,
        score_threshold,
        params,
        with_vector: with_vector.unwrap_or(CollectionQueryRequest::DEFAULT_WITH_VECTOR),
        with_payload: with_payload.unwrap_or(CollectionQueryRequest::DEFAULT_WITH_PAYLOAD),
        lookup_from,
        limit: group_request
            .limit
            .unwrap_or(CollectionQueryRequest::DEFAULT_LIMIT),
        group_by: group_request.group_by,
        group_size: group_request
            .group_size
            .unwrap_or(CollectionQueryRequest::DEFAULT_GROUP_SIZE),
        with_lookup: group_request.with_lookup.map(WithLookup::from),
    };

    Ok(CollectionQueryGroupsRequestWithUsage {
        request: collection_query_groups_request,
        usage,
    })
}

pub async fn convert_query_request_from_rest(
    request: rest::QueryRequestInternal,
    inference_params: &InferenceParams,
) -> Result<CollectionQueryRequestWithUsage, StorageError> {
    let batch = collect_query_request(&request);
    let (inferred, usage) =
        BatchAccumInferred::from_batch_accum(batch, InferenceType::Search, inference_params)
            .await?;

    let rest::QueryRequestInternal {
        prefetch,
        query,
        using,
        filter,
        score_threshold,
        params,
        limit,
        offset,
        with_vector,
        with_payload,
        lookup_from,
    } = request;

    let prefetch = prefetch
        .map(|prefetches| {
            prefetches
                .into_iter()
                .map(|p| convert_prefetch_with_inferred(p, &inferred))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let query = query
        .map(|q| convert_query_with_inferred(q, &inferred))
        .transpose()?;

    let collection_query_request = CollectionQueryRequest {
        prefetch,
        query,
        using: using.unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_owned()),
        filter,
        score_threshold,
        limit: limit.unwrap_or(CollectionQueryRequest::DEFAULT_LIMIT),
        offset: offset.unwrap_or(CollectionQueryRequest::DEFAULT_OFFSET),
        params,
        with_vector: with_vector.unwrap_or(CollectionQueryRequest::DEFAULT_WITH_VECTOR),
        with_payload: with_payload.unwrap_or(CollectionQueryRequest::DEFAULT_WITH_PAYLOAD),
        lookup_from,
    };
    Ok(CollectionQueryRequestWithUsage {
        request: collection_query_request,
        usage,
    })
}

fn convert_vector_input_with_inferred(
    vector: rest::VectorInput,
    inferred: &BatchAccumInferred,
) -> Result<VectorInputInternal, StorageError> {
    match vector {
        rest::VectorInput::Id(id) => Ok(VectorInputInternal::Id(id)),
        rest::VectorInput::DenseVector(dense) => {
            Ok(VectorInputInternal::Vector(VectorInternal::Dense(dense)))
        }
        rest::VectorInput::SparseVector(sparse) => {
            Ok(VectorInputInternal::Vector(VectorInternal::Sparse(sparse)))
        }
        rest::VectorInput::MultiDenseVector(multi_dense) => Ok(VectorInputInternal::Vector(
            VectorInternal::MultiDense(MultiDenseVectorInternal::new_unchecked(multi_dense)),
        )),
        rest::VectorInput::Document(doc) => {
            let data = InferenceData::Document(doc);
            let vector = inferred.get_vector(&data).ok_or_else(|| {
                StorageError::inference_error("Missing inferred vector for document")
            })?;
            Ok(VectorInputInternal::InferredVector(VectorInternal::from(
                vector.clone(),
            )))
        }
        rest::VectorInput::Image(img) => {
            let data = InferenceData::Image(img);
            let vector = inferred.get_vector(&data).ok_or_else(|| {
                StorageError::inference_error("Missing inferred vector for image")
            })?;
            Ok(VectorInputInternal::InferredVector(VectorInternal::from(
                vector.clone(),
            )))
        }
        rest::VectorInput::CkksEncryptedQuery(query) => {
            query
                .validate()
                .map_err(|_| StorageError::bad_input("Invalid CKKS encrypted query vector"))?;
            Ok(VectorInputInternal::CkksEncryptedQuery(
                CkksEncryptedQueryInput {
                    version: query.envelope.version,
                    scheme: query.envelope.scheme,
                    security_profile: query.envelope.security_profile,
                    collection_id: query.envelope.collection_id,
                    vector_name: query.envelope.vector_name,
                    key_id: query.envelope.key_id,
                    rk_id: query.envelope.rk_id,
                    rk_epoch: query.envelope.rk_epoch,
                    query_nonce: query.envelope.query_nonce,
                    context_digest: query.envelope.context_digest,
                    slots: query.envelope.slots,
                    ciphertext_sha256: query.envelope.ciphertext_sha256,
                    ciphertext: query.envelope.ciphertext,
                    signature_alg: query.envelope.signature.alg,
                    signature_key_id: query.envelope.signature.key_id,
                    signature_b64: query.envelope.signature.sig,
                },
            ))
        }
        rest::VectorInput::Object(obj) => {
            let data = InferenceData::Object(obj);
            let vector = inferred.get_vector(&data).ok_or_else(|| {
                StorageError::inference_error("Missing inferred vector for object")
            })?;
            Ok(VectorInputInternal::InferredVector(VectorInternal::from(
                vector.clone(),
            )))
        }
    }
}

fn convert_query_with_inferred(
    query: rest::QueryInterface,
    inferred: &BatchAccumInferred,
) -> StorageResult<Query> {
    let query = rest::Query::from(query);
    match query {
        rest::Query::Nearest(rest::NearestQuery { nearest, mmr }) => {
            let vector = convert_vector_input_with_inferred(nearest, inferred)?;

            if let Some(mmr) = mmr {
                let mmr = Mmr {
                    diversity: mmr.diversity,
                    candidates_limit: mmr.candidates_limit,
                };
                Ok(Query::Vector(VectorQuery::NearestWithMmr(NearestWithMmr {
                    nearest: vector,
                    mmr,
                })))
            } else {
                Ok(Query::Vector(VectorQuery::Nearest(vector)))
            }
        }
        rest::Query::Recommend(recommend) => {
            let rest::RecommendInput {
                positive,
                negative,
                strategy,
            } = recommend.recommend;
            let positives = positive
                .into_iter()
                .flatten()
                .map(|v| convert_vector_input_with_inferred(v, inferred))
                .collect::<Result<Vec<_>, _>>()?;
            let negatives = negative
                .into_iter()
                .flatten()
                .map(|v| convert_vector_input_with_inferred(v, inferred))
                .collect::<Result<Vec<_>, _>>()?;
            let reco_query = RecoQuery::new(positives, negatives);
            match strategy.unwrap_or_default() {
                rest::RecommendStrategy::AverageVector => Ok(Query::Vector(
                    VectorQuery::RecommendAverageVector(reco_query),
                )),
                rest::RecommendStrategy::BestScore => {
                    Ok(Query::Vector(VectorQuery::RecommendBestScore(reco_query)))
                }
                rest::RecommendStrategy::SumScores => {
                    Ok(Query::Vector(VectorQuery::RecommendSumScores(reco_query)))
                }
            }
        }
        rest::Query::Discover(discover) => {
            let rest::DiscoverInput { target, context } = discover.discover;
            let target = convert_vector_input_with_inferred(target, inferred)?;
            let context = context
                .into_iter()
                .flatten()
                .map(|pair| context_pair_from_rest_with_inferred(pair, inferred))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Query::Vector(VectorQuery::Discover(DiscoverQuery::new(
                target, context,
            ))))
        }
        rest::Query::Context(context) => {
            let rest::ContextInput(context) = context.context;
            let context = context
                .into_iter()
                .flatten()
                .map(|pair| context_pair_from_rest_with_inferred(pair, inferred))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Query::Vector(VectorQuery::Context(ContextQuery::new(
                context,
            ))))
        }
        rest::Query::OrderBy(order_by) => Ok(Query::OrderBy(OrderBy::from(order_by.order_by))),
        rest::Query::Fusion(fusion) => Ok(Query::Fusion(FusionInternal::from(fusion.fusion))),
        rest::Query::Rrf(rrf) => Ok(Query::Fusion(FusionInternal::from(rrf.rrf))),
        rest::Query::Formula(formula) => Ok(Query::Formula(FormulaInternal::from(formula))),
        rest::Query::Sample(sample) => Ok(Query::Sample(SampleInternal::from(sample.sample))),
        rest::Query::RelevanceFeedback(relevance_feedback) => {
            let rest::RelevanceFeedbackInput {
                target,
                feedback,
                strategy,
            } = relevance_feedback.relevance_feedback;

            let target = convert_vector_input_with_inferred(target, inferred)?;
            let feedback = feedback
                .into_iter()
                .map(|item| {
                    Ok(FeedbackItem {
                        vector: convert_vector_input_with_inferred(item.example, inferred)?,
                        score: item.score.into(),
                    })
                })
                .collect::<StorageResult<Vec<_>>>()?;

            let strategy = FeedbackStrategy::from(strategy);

            Ok(Query::Vector(VectorQuery::Feedback(FeedbackInternal {
                target,
                feedback,
                strategy,
            })))
        }
    }
}

fn convert_prefetch_with_inferred(
    prefetch: rest::Prefetch,
    inferred: &BatchAccumInferred,
) -> Result<CollectionPrefetch, StorageError> {
    let rest::Prefetch {
        prefetch,
        query,
        using,
        filter,
        score_threshold,
        params,
        limit,
        lookup_from,
    } = prefetch;

    let query = query
        .map(|q| convert_query_with_inferred(q, inferred))
        .transpose()?;
    let nested_prefetches = prefetch
        .map(|prefetches| {
            prefetches
                .into_iter()
                .map(|p| convert_prefetch_with_inferred(p, inferred))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(CollectionPrefetch {
        prefetch: nested_prefetches,
        query,
        using: using.unwrap_or_else(|| DEFAULT_VECTOR_NAME.to_owned()),
        filter,
        score_threshold: score_threshold.map(OrderedFloat),
        limit: limit.unwrap_or(CollectionQueryRequest::DEFAULT_LIMIT),
        params,
        lookup_from,
    })
}

fn context_pair_from_rest_with_inferred(
    value: rest::ContextPair,
    inferred: &BatchAccumInferred,
) -> Result<ContextPair<VectorInputInternal>, StorageError> {
    let rest::ContextPair { positive, negative } = value;
    Ok(ContextPair {
        positive: convert_vector_input_with_inferred(positive, inferred)?,
        negative: convert_vector_input_with_inferred(negative, inferred)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use api::rest::schema::{
        CkksEncryptedQuerySignature, CkksEncryptedQueryVector, CkksEncryptedQueryVectorEnvelope,
        Document, Image, InferenceObject, NearestQuery,
    };
    use collection::operations::point_ops::VectorPersisted;
    use data_encoding::BASE64URL_NOPAD;
    use serde_json::json;

    use super::*;

    fn create_test_document(text: &str) -> Document {
        Document {
            text: text.to_string(),
            model: "test-model".to_string(),
            options: Default::default(),
        }
    }

    fn create_test_image(url: &str) -> Image {
        Image {
            image: json!({"data": url.to_string()}),
            model: "test-model".to_string(),
            options: Default::default(),
        }
    }

    fn create_test_object(data: &str) -> InferenceObject {
        InferenceObject {
            object: json!({"data": data}),
            model: "test-model".to_string(),
            options: Default::default(),
        }
    }

    fn create_test_inferred_batch() -> BatchAccumInferred {
        let mut objects = HashMap::new();

        let doc = InferenceData::Document(create_test_document("test"));
        let img = InferenceData::Image(create_test_image("test.jpg"));
        let obj = InferenceData::Object(create_test_object("test"));

        let dense_vector = vec![1.0, 2.0, 3.0];
        let vector_persisted = VectorPersisted::Dense(dense_vector);

        objects.insert(doc, vector_persisted.clone());
        objects.insert(img, vector_persisted.clone());
        objects.insert(obj, vector_persisted);

        BatchAccumInferred { objects }
    }

    #[test]
    fn test_convert_vector_input_with_inferred_dense() {
        let inferred = create_test_inferred_batch();
        let vector = rest::VectorInput::DenseVector(vec![1.0, 2.0, 3.0]);

        let result = convert_vector_input_with_inferred(vector, &inferred).unwrap();
        match result {
            VectorInputInternal::Vector(VectorInternal::Dense(values)) => {
                assert_eq!(values, vec![1.0, 2.0, 3.0]);
            }
            _ => panic!("Expected dense vector"),
        }
    }

    #[test]
    fn test_convert_vector_input_with_client_ckks_query() {
        let inferred = create_test_inferred_batch();
        let vector = rest::VectorInput::CkksEncryptedQuery(CkksEncryptedQueryVector {
            envelope: CkksEncryptedQueryVectorEnvelope {
                version: 1,
                scheme: "openfhe-ckks".to_string(),
                security_profile: "ckks-128-n16384-d4-scale50".to_string(),
                collection_id: "docs-crypto-id".to_string(),
                vector_name: "embedding".to_string(),
                key_id: "tenant-a:vector".to_string(),
                rk_id: "tenant-a/vector-v1".to_string(),
                rk_epoch: 1,
                query_nonce: BASE64URL_NOPAD.encode(&[7_u8; 12]),
                context_digest: BASE64URL_NOPAD.encode(&[3_u8; 32]),
                slots: 2,
                ciphertext_sha256: "MFUx3MUOvKMc8dWzHp_HbtUfZrO23VoDDGU5rmUy-Xk".to_string(),
                ciphertext: BASE64URL_NOPAD.encode(b"ciphertext"),
                signature: CkksEncryptedQuerySignature {
                    alg: "ed25519".to_string(),
                    key_id: "tenant-a:query-signing-v1".to_string(),
                    sig: BASE64URL_NOPAD.encode(&[4_u8; 64]),
                },
            },
        });

        let result = convert_vector_input_with_inferred(vector, &inferred).unwrap();
        match result {
            VectorInputInternal::CkksEncryptedQuery(query) => {
                assert_eq!(query.version, 1);
                assert_eq!(query.scheme, "openfhe-ckks");
                assert_eq!(query.slots, 2);
                assert_eq!(query.query_nonce, BASE64URL_NOPAD.encode(&[7_u8; 12]));
                assert_eq!(query.ciphertext, BASE64URL_NOPAD.encode(b"ciphertext"));
            }
            _ => panic!("Expected client CKKS encrypted query"),
        }
    }

    #[test]
    fn test_convert_vector_input_rejects_invalid_client_ckks_query() {
        let inferred = create_test_inferred_batch();
        let vector = rest::VectorInput::CkksEncryptedQuery(CkksEncryptedQueryVector {
            envelope: CkksEncryptedQueryVectorEnvelope {
                version: 1,
                scheme: "openfhe-ckks".to_string(),
                security_profile: "ckks-128-n16384-d4-scale50".to_string(),
                collection_id: "docs-crypto-id".to_string(),
                vector_name: "embedding".to_string(),
                key_id: "tenant-a:vector".to_string(),
                rk_id: "tenant-a/vector-v1".to_string(),
                rk_epoch: 1,
                query_nonce: BASE64URL_NOPAD.encode(&[7_u8; 12]),
                context_digest: "not base64url!".to_string(),
                slots: 2,
                ciphertext_sha256: "MFUx3MUOvKMc8dWzHp_HbtUfZrO23VoDDGU5rmUy-Xk".to_string(),
                ciphertext: BASE64URL_NOPAD.encode(b"ciphertext"),
                signature: CkksEncryptedQuerySignature {
                    alg: "ed25519".to_string(),
                    key_id: "tenant-a:query-signing-v1".to_string(),
                    sig: BASE64URL_NOPAD.encode(&[4_u8; 64]),
                },
            },
        });

        let err = convert_vector_input_with_inferred(vector, &inferred).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("Invalid CKKS encrypted query vector"));
        assert!(!rendered.contains("not base64url!"));
        assert!(!rendered.contains("context_digest"));
    }

    #[test]
    fn test_convert_vector_input_with_inferred_document() {
        let inferred = create_test_inferred_batch();
        let doc = create_test_document("test");
        let vector = rest::VectorInput::Document(doc);

        let result = convert_vector_input_with_inferred(vector, &inferred).unwrap();
        match result {
            VectorInputInternal::InferredVector(VectorInternal::Dense(values)) => {
                assert_eq!(values, vec![1.0, 2.0, 3.0]);
            }
            _ => panic!("Expected inference-derived dense vector"),
        }
    }

    #[test]
    fn test_convert_vector_input_with_inferred_missing() {
        let inferred = create_test_inferred_batch();
        let doc = create_test_document("missing");
        let vector = rest::VectorInput::Document(doc);

        let result = convert_vector_input_with_inferred(vector, &inferred);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing inferred vector"),
        );
    }

    #[test]
    fn test_context_pair_from_rest_with_inferred() {
        let inferred = create_test_inferred_batch();
        let pair = rest::ContextPair {
            positive: rest::VectorInput::DenseVector(vec![1.0, 2.0, 3.0]),
            negative: rest::VectorInput::Document(create_test_document("test")),
        };

        let result = context_pair_from_rest_with_inferred(pair, &inferred).unwrap();
        match (result.positive, result.negative) {
            (
                VectorInputInternal::Vector(VectorInternal::Dense(pos)),
                VectorInputInternal::InferredVector(VectorInternal::Dense(neg)),
            ) => {
                assert_eq!(pos, vec![1.0, 2.0, 3.0]);
                assert_eq!(neg, vec![1.0, 2.0, 3.0]);
            }
            _ => panic!("Expected dense vectors"),
        }
    }

    #[test]
    fn test_convert_query_with_inferred_nearest() {
        let inferred = create_test_inferred_batch();
        let nearest = NearestQuery {
            nearest: rest::VectorInput::Document(create_test_document("test")),
            mmr: None,
        };
        let query = rest::QueryInterface::Query(rest::Query::Nearest(nearest));

        let result = convert_query_with_inferred(query, &inferred).unwrap();
        match result {
            Query::Vector(VectorQuery::Nearest(vector)) => match vector {
                VectorInputInternal::InferredVector(VectorInternal::Dense(values)) => {
                    assert_eq!(values, vec![1.0, 2.0, 3.0]);
                }
                _ => panic!("Expected inference-derived dense vector"),
            },
            _ => panic!("Expected nearest query"),
        }
    }
}
