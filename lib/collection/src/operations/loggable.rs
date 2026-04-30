use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;

use segment::data_types::facets::FacetParams;
use serde::Serialize;
use serde_json::Value;
use shard::count::CountRequestInternal;
use shard::operations::CollectionUpdateOperations;
use shard::scroll::ScrollRequestInternal;

use crate::operations::types::PointRequestInternal;
use crate::operations::universal_query::shard_query::ShardQueryRequest;

pub trait Loggable {
    fn to_log_value(&self) -> serde_json::Value;

    fn request_name(&self) -> &'static str;

    /// Hash of the query, which is going to be used for approximate deduplication and counting.
    fn request_hash(&self) -> u64;
}

impl Loggable for CollectionUpdateOperations {
    fn to_log_value(&self) -> Value {
        to_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "points-update"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl Loggable for Vec<ShardQueryRequest> {
    fn to_log_value(&self) -> Value {
        to_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "query"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl Loggable for ScrollRequestInternal {
    fn to_log_value(&self) -> Value {
        to_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "scroll"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl<T: Loggable> Loggable for Arc<T> {
    fn to_log_value(&self) -> Value {
        self.as_ref().to_log_value()
    }

    fn request_name(&self) -> &'static str {
        self.as_ref().request_name()
    }

    fn request_hash(&self) -> u64 {
        self.as_ref().request_hash()
    }
}

impl Loggable for FacetParams {
    fn to_log_value(&self) -> Value {
        to_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "facet"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl Loggable for CountRequestInternal {
    fn to_log_value(&self) -> Value {
        to_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "count"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

impl Loggable for PointRequestInternal {
    fn to_log_value(&self) -> Value {
        to_redacted_log_value(self)
    }

    fn request_name(&self) -> &'static str {
        "retrieve"
    }

    fn request_hash(&self) -> u64 {
        redacted_request_hash(self.request_name(), &self.to_log_value())
    }
}

fn to_redacted_log_value(value: &impl Serialize) -> Value {
    let mut value = serde_json::to_value(value).unwrap_or_default();
    redact_sensitive_log_fields(&mut value);
    value
}

fn redact_sensitive_log_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if matches!(
                    key.as_str(),
                    "payload"
                        | "payloads"
                        | "vector"
                        | "vectors"
                        | "value"
                        | "values"
                        | "match"
                        | "range"
                        | "geo_bounding_box"
                        | "geo_radius"
                        | "geo_polygon"
                        | "Vector"
                        | "Mmr"
                ) {
                    *value = Value::String("[redacted]".to_string());
                } else {
                    redact_sensitive_log_fields(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_sensitive_log_fields(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn redacted_request_hash(request_name: &str, log_value: &Value) -> u64 {
    let mut hasher = DefaultHasher::new();
    request_name.hash(&mut hasher);
    serde_json::to_string(log_value)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use segment::types::{
        Condition, FieldCondition, Filter, Payload, WithPayloadInterface, WithVector,
    };
    use serde_json::json;
    use shard::count::CountRequestInternal;
    use shard::operations::point_ops::{
        PointInsertOperationsInternal, PointOperations, PointStructPersisted, VectorStructPersisted,
    };
    use shard::query::query_enum::QueryEnum;
    use shard::query::{MmrInternal, ScoringQuery, ShardQueryRequest};

    use super::*;

    #[test]
    fn update_log_value_redacts_payloads_and_vectors() {
        let operation = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::PointsList(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![12345.125, -23456.25]),
                payload: Some(Payload(
                    json!({ "body": "qdrant-sec-log-plaintext-sentinel" })
                        .as_object()
                        .unwrap()
                        .clone(),
                )),
            }]),
        ));

        let log_value = operation.to_log_value();
        let serialized = serde_json::to_string(&log_value).unwrap();

        assert!(!serialized.contains("qdrant-sec-log-plaintext-sentinel"));
        assert!(!serialized.contains("12345.125"));
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn update_request_hash_uses_redacted_payloads_and_vectors() {
        let update = |payload: &str, vector: Vec<f32>| {
            CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
                PointInsertOperationsInternal::PointsList(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vector),
                    payload: Some(Payload(
                        json!({ "body": payload }).as_object().unwrap().clone(),
                    )),
                }]),
            ))
        };
        let first = update("secret-a", vec![1.0, 2.0]);
        let second = update("secret-b", vec![3.0, 4.0]);

        assert_eq!(first.to_log_value(), second.to_log_value());
        assert_eq!(first.request_hash(), second.request_hash());
    }

    #[test]
    fn query_log_value_redacts_payload_filter_literals() {
        let request = CountRequestInternal {
            filter: Some(Filter::new_must(Condition::Field(
                FieldCondition::new_match(
                    "document.body".parse().unwrap(),
                    serde_json::from_value(json!({
                        "value": "qdrant-sec-filter-log-sentinel",
                    }))
                    .unwrap(),
                ),
            ))),
            exact: true,
        };

        let log_value = request.to_log_value();
        let serialized = serde_json::to_string(&log_value).unwrap();

        assert!(!serialized.contains("qdrant-sec-filter-log-sentinel"));
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn query_request_hash_uses_redacted_filter_literals() {
        let request = |literal: &str| CountRequestInternal {
            filter: Some(Filter::new_must(Condition::Field(
                FieldCondition::new_match(
                    "document.body".parse().unwrap(),
                    serde_json::from_value(json!({ "value": literal })).unwrap(),
                ),
            ))),
            exact: true,
        };
        let first = request("secret-a");
        let second = request("secret-b");

        assert_eq!(first.to_log_value(), second.to_log_value());
        assert_eq!(first.request_hash(), second.request_hash());
    }

    #[test]
    fn query_log_value_redacts_query_vectors() {
        let request = vec![ShardQueryRequest {
            prefetches: vec![],
            query: Some(ScoringQuery::Vector(QueryEnum::from(vec![
                98765.125, -87654.25,
            ]))),
            filter: None,
            score_threshold: None,
            limit: 10,
            offset: 0,
            params: None,
            with_vector: WithVector::Bool(false),
            with_payload: WithPayloadInterface::Bool(false),
        }];

        let log_value = request.to_log_value();
        let serialized = serde_json::to_string(&log_value).unwrap();

        assert!(!serialized.contains("98765.125"));
        assert!(!serialized.contains("-87654.25"));
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn query_request_hash_uses_redacted_query_vectors() {
        let request = |vector: Vec<f32>| {
            vec![ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Vector(QueryEnum::from(vector))),
                filter: None,
                score_threshold: None,
                limit: 10,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
            }]
        };
        let first = request(vec![1.0, 2.0]);
        let second = request(vec![3.0, 4.0]);

        assert_eq!(first.to_log_value(), second.to_log_value());
        assert_eq!(first.request_hash(), second.request_hash());
    }

    #[test]
    fn mmr_query_log_value_redacts_query_vector() {
        let request = vec![ShardQueryRequest {
            prefetches: vec![],
            query: Some(ScoringQuery::Mmr(MmrInternal {
                vector: vec![54321.125, -12345.25].into(),
                using: "embedding".to_string(),
                lambda: ordered_float::OrderedFloat(0.5),
                candidates_limit: 20,
            })),
            filter: None,
            score_threshold: None,
            limit: 10,
            offset: 0,
            params: None,
            with_vector: WithVector::Bool(false),
            with_payload: WithPayloadInterface::Bool(false),
        }];

        let log_value = request.to_log_value();
        let serialized = serde_json::to_string(&log_value).unwrap();

        assert!(!serialized.contains("54321.125"));
        assert!(!serialized.contains("-12345.25"));
        assert!(serialized.contains("[redacted]"));
    }
}
