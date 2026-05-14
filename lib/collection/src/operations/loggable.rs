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
                let key = key.as_str();
                let key_lowercase;
                let key = if key.bytes().any(|byte| byte.is_ascii_uppercase()) {
                    key_lowercase = key.to_ascii_lowercase();
                    key_lowercase.as_str()
                } else {
                    key
                };
                if matches!(
                    key,
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
                        | "ciphertext"
                        | "ciphertexts"
                        | "encrypted_query"
                        | "encrypted_queries"
                        | "nonce"
                        | "nonces"
                        | "signature"
                        | "signatures"
                        | "sig"
                        | "public_key"
                        | "public_keys"
                        | "public_key_b64"
                        | "signature_public_key_b64"
                        | "crypto_context"
                        | "crypto_contexts"
                        | "context_digest"
                        | "context_digests"
                        | "wrapped_key"
                        | "wrapped_keys"
                        | "wrapped_key_b64"
                        | "wrapped_keys_b64"
                        | "value_b64"
                        | "values_b64"
                        | "secret"
                        | "secret_b64"
                        | "key_material"
                        | "key_material_b64"
                        | "master_key_b64"
                        | "master_key"
                        | "resource_key"
                        | "resource_key_b64"
                        | "wrapping_key"
                        | "wrapping_key_b64"
                        | "authorization"
                        | "api_key"
                        | "x_api_key"
                        | "x-api-key"
                        | "cookie"
                        | "set_cookie"
                        | "set-cookie"
                        | "token"
                        | "access_token"
                        | "refresh_token"
                        | "bearer_token"
                        | "id_token"
                        | "jwt"
                        | "session"
                        | "session_token"
                        | "vault_token"
                        | "x_vault_token"
                        | "x-vault-token"
                        | "client_secret"
                        | "credential"
                        | "credentials"
                        | "password"
                        | "private_key"
                        | "private_key_b64"
                        | "secret_key"
                        | "secret_key_b64"
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
    fn redaction_removes_encrypted_envelope_material() {
        let mut value = json!({
            "client_payload": {
                "$qdrant_client_aead": {
                    "key_id": "tenant-a/payload-rk",
                    "rk_id": "tenant-a/payload-rk",
                    "nonce": "qdrant-sec-log-nonce-sentinel",
                    "ciphertext": "qdrant-sec-log-ciphertext-sentinel",
                    "signature": {
                        "alg": "ed25519",
                        "key_id": "tenant-a/signing-key",
                        "sig": "qdrant-sec-log-signature-sentinel"
                    }
                }
            },
            "ckks_query": {
                "context_digest": "qdrant-sec-log-context-digest-sentinel",
                "encrypted_query": "qdrant-sec-log-encrypted-query-sentinel",
                "public_key": "qdrant-sec-log-public-key-sentinel",
                "crypto_context": "qdrant-sec-log-crypto-context-sentinel"
            }
        });

        redact_sensitive_log_fields(&mut value);
        let serialized = serde_json::to_string(&value).unwrap();

        assert!(!serialized.contains("qdrant-sec-log-nonce-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-ciphertext-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-signature-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-context-digest-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-encrypted-query-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-public-key-sentinel"));
        assert!(!serialized.contains("qdrant-sec-log-crypto-context-sentinel"));
        assert!(serialized.contains("tenant-a/payload-rk"));
    }

    #[test]
    fn encrypted_envelope_request_hash_uses_redacted_material() {
        let envelope = |nonce: &str, ciphertext: &str, signature: &str| {
            let mut value = json!({
                "client_payload": {
                    "$qdrant_client_aead": {
                        "key_id": "tenant-a/payload-rk",
                        "rk_id": "tenant-a/payload-rk",
                        "nonce": nonce,
                        "ciphertext": ciphertext,
                        "signature": {
                            "alg": "ed25519",
                            "key_id": "tenant-a/signing-key",
                            "sig": signature
                        }
                    }
                }
            });
            redact_sensitive_log_fields(&mut value);
            value
        };

        let first = envelope("nonce-a", "ciphertext-a", "signature-a");
        let second = envelope("nonce-b", "ciphertext-b", "signature-b");

        assert_eq!(first, second);
        assert_eq!(
            redacted_request_hash("encrypted-envelope", &first),
            redacted_request_hash("encrypted-envelope", &second),
        );
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

    #[test]
    fn log_value_redacts_crypto_envelope_fields_recursively() {
        let mut value = json!({
            "outer": {
                "ciphertext": "qdrant-sec-ciphertext-log-sentinel",
                "ciphertexts": [
                    "qdrant-sec-ciphertexts-log-sentinel-a",
                    "qdrant-sec-ciphertexts-log-sentinel-b"
                ],
                "nonce": "qdrant-sec-nonce-log-sentinel",
                "nonces": ["qdrant-sec-nonces-log-sentinel"],
                "signature": {
                    "sig": "qdrant-sec-signature-log-sentinel",
                    "public_key": "qdrant-sec-public-key-log-sentinel"
                },
                "signatures": ["qdrant-sec-signatures-log-sentinel"],
                "public_keys": ["qdrant-sec-public-keys-log-sentinel"],
                "crypto_context": "qdrant-sec-context-log-sentinel",
                "crypto_contexts": ["qdrant-sec-contexts-log-sentinel"],
                "context_digest": "qdrant-sec-context-digest-log-sentinel",
                "context_digests": ["qdrant-sec-context-digests-log-sentinel"],
                "encrypted_query": "qdrant-sec-encrypted-query-log-sentinel",
                "encrypted_queries": ["qdrant-sec-encrypted-queries-log-sentinel"],
                "wrapped_key_b64": "qdrant-sec-wrapped-key-log-sentinel",
                "wrapped_keys_b64": ["qdrant-sec-wrapped-keys-log-sentinel"],
                "value_b64": "qdrant-sec-inline-key-log-sentinel",
                "values_b64": ["qdrant-sec-inline-keys-log-sentinel"]
            }
        });

        redact_sensitive_log_fields(&mut value);
        let serialized = serde_json::to_string(&value).unwrap();

        for sentinel in [
            "qdrant-sec-ciphertext-log-sentinel",
            "qdrant-sec-ciphertexts-log-sentinel-a",
            "qdrant-sec-ciphertexts-log-sentinel-b",
            "qdrant-sec-nonce-log-sentinel",
            "qdrant-sec-nonces-log-sentinel",
            "qdrant-sec-signature-log-sentinel",
            "qdrant-sec-signatures-log-sentinel",
            "qdrant-sec-public-key-log-sentinel",
            "qdrant-sec-public-keys-log-sentinel",
            "qdrant-sec-context-log-sentinel",
            "qdrant-sec-contexts-log-sentinel",
            "qdrant-sec-context-digest-log-sentinel",
            "qdrant-sec-context-digests-log-sentinel",
            "qdrant-sec-encrypted-query-log-sentinel",
            "qdrant-sec-encrypted-queries-log-sentinel",
            "qdrant-sec-wrapped-key-log-sentinel",
            "qdrant-sec-wrapped-keys-log-sentinel",
            "qdrant-sec-inline-key-log-sentinel",
            "qdrant-sec-inline-keys-log-sentinel",
        ] {
            assert!(!serialized.contains(sentinel));
        }
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn log_value_redacts_generic_secret_fields_recursively() {
        let mut value = json!({
            "headers": {
                "authorization": "Bearer qdrant-sec-authorization-log-sentinel",
                "x-api-key": "qdrant-sec-x-api-key-log-sentinel",
                "cookie": "qdrant-sec-cookie-log-sentinel",
                "set-cookie": "qdrant-sec-set-cookie-log-sentinel",
                "Authorization": "Bearer qdrant-sec-title-authorization-log-sentinel",
                "X-API-Key": "qdrant-sec-title-api-key-log-sentinel",
                "Cookie": "qdrant-sec-title-cookie-log-sentinel",
                "Set-Cookie": "qdrant-sec-title-set-cookie-log-sentinel"
            },
            "snapshot": {
                "api_key": "qdrant-sec-api-key-log-sentinel",
                "token": "qdrant-sec-token-log-sentinel",
                "access_token": "qdrant-sec-access-token-log-sentinel",
                "refresh_token": "qdrant-sec-refresh-token-log-sentinel",
                "bearer_token": "qdrant-sec-bearer-token-log-sentinel",
                "id_token": "qdrant-sec-id-token-log-sentinel",
                "jwt": "qdrant-sec-jwt-log-sentinel",
                "session": "qdrant-sec-session-log-sentinel",
                "session_token": "qdrant-sec-session-token-log-sentinel",
                "vault_token": "qdrant-sec-vault-token-log-sentinel",
                "x-vault-token": "qdrant-sec-x-vault-token-log-sentinel",
                "client_secret": "qdrant-sec-client-secret-log-sentinel",
                "credential": "qdrant-sec-credential-log-sentinel",
                "credentials": "qdrant-sec-credentials-log-sentinel",
                "password": "qdrant-sec-password-log-sentinel"
            },
            "tls": {
                "private_key": "qdrant-sec-private-key-log-sentinel",
                "private_key_b64": "qdrant-sec-private-key-b64-log-sentinel"
            },
            "crypto": {
                "secret": "qdrant-sec-generic-secret-log-sentinel",
                "secret_b64": "qdrant-sec-generic-secret-b64-log-sentinel",
                "key_material": "qdrant-sec-key-material-log-sentinel",
                "key_material_b64": "qdrant-sec-key-material-b64-log-sentinel",
                "master_key": "qdrant-sec-master-key-log-sentinel",
                "master_key_b64": "qdrant-sec-master-key-b64-log-sentinel",
                "resource_key": "qdrant-sec-resource-key-log-sentinel",
                "resource_key_b64": "qdrant-sec-resource-key-b64-log-sentinel",
                "wrapping_key": "qdrant-sec-wrapping-key-log-sentinel",
                "wrapping_key_b64": "qdrant-sec-wrapping-key-b64-log-sentinel",
                "secret_key": "qdrant-sec-secret-key-log-sentinel",
                "secret_key_b64": "qdrant-sec-secret-key-b64-log-sentinel",
                "public_key_b64": "qdrant-sec-public-key-b64-log-sentinel",
                "signature_public_key_b64": "qdrant-sec-signature-public-key-log-sentinel"
            }
        });

        redact_sensitive_log_fields(&mut value);
        let serialized = serde_json::to_string(&value).unwrap();

        for sentinel in [
            "qdrant-sec-authorization-log-sentinel",
            "qdrant-sec-x-api-key-log-sentinel",
            "qdrant-sec-cookie-log-sentinel",
            "qdrant-sec-set-cookie-log-sentinel",
            "qdrant-sec-title-authorization-log-sentinel",
            "qdrant-sec-title-api-key-log-sentinel",
            "qdrant-sec-title-cookie-log-sentinel",
            "qdrant-sec-title-set-cookie-log-sentinel",
            "qdrant-sec-api-key-log-sentinel",
            "qdrant-sec-token-log-sentinel",
            "qdrant-sec-access-token-log-sentinel",
            "qdrant-sec-refresh-token-log-sentinel",
            "qdrant-sec-bearer-token-log-sentinel",
            "qdrant-sec-id-token-log-sentinel",
            "qdrant-sec-jwt-log-sentinel",
            "qdrant-sec-session-log-sentinel",
            "qdrant-sec-session-token-log-sentinel",
            "qdrant-sec-vault-token-log-sentinel",
            "qdrant-sec-x-vault-token-log-sentinel",
            "qdrant-sec-client-secret-log-sentinel",
            "qdrant-sec-credential-log-sentinel",
            "qdrant-sec-credentials-log-sentinel",
            "qdrant-sec-password-log-sentinel",
            "qdrant-sec-private-key-log-sentinel",
            "qdrant-sec-private-key-b64-log-sentinel",
            "qdrant-sec-generic-secret-log-sentinel",
            "qdrant-sec-generic-secret-b64-log-sentinel",
            "qdrant-sec-key-material-log-sentinel",
            "qdrant-sec-key-material-b64-log-sentinel",
            "qdrant-sec-master-key-log-sentinel",
            "qdrant-sec-master-key-b64-log-sentinel",
            "qdrant-sec-resource-key-log-sentinel",
            "qdrant-sec-resource-key-b64-log-sentinel",
            "qdrant-sec-wrapping-key-log-sentinel",
            "qdrant-sec-wrapping-key-b64-log-sentinel",
            "qdrant-sec-secret-key-log-sentinel",
            "qdrant-sec-secret-key-b64-log-sentinel",
            "qdrant-sec-public-key-b64-log-sentinel",
            "qdrant-sec-signature-public-key-log-sentinel",
        ] {
            assert!(!serialized.contains(sentinel));
        }
        assert!(serialized.contains("[redacted]"));
    }

    #[test]
    fn generic_secret_request_hash_uses_redacted_material() {
        let mut first = json!({
            "headers": {
                "authorization": "Bearer secret-a",
                "x-api-key": "api-secret-a",
                "Authorization": "Bearer title-secret-a",
                "X-API-Key": "title-api-secret-a",
                "cookie": "cookie-secret-a",
                "set-cookie": "set-cookie-secret-a",
                "Cookie": "title-cookie-secret-a",
                "Set-Cookie": "title-set-cookie-secret-a"
            },
            "oauth": {
                "access_token": "access-secret-a",
                "refresh_token": "refresh-secret-a",
                "id_token": "id-token-secret-a",
                "jwt": "jwt-secret-a",
                "client_secret": "client-secret-a"
            },
            "vault": {
                "x-vault-token": "vault-secret-a"
            },
            "session": {
                "session_token": "session-secret-a",
                "credentials": "credentials-secret-a"
            },
            "crypto": {
                "secret": "generic-secret-a",
                "secret_b64": "generic-secret-b64-a",
                "key_material": "material-secret-a",
                "key_material_b64": "material-secret-b64-a",
                "master_key": "master-secret-a",
                "master_key_b64": "master-secret-b64-a",
                "resource_key": "resource-secret-a",
                "resource_key_b64": "resource-secret-b64-a",
                "wrapping_key": "wrapping-secret-a",
                "wrapping_key_b64": "wrapping-secret-b64-a"
            }
        });
        let mut second = json!({
            "headers": {
                "authorization": "Bearer secret-b",
                "x-api-key": "api-secret-b",
                "Authorization": "Bearer title-secret-b",
                "X-API-Key": "title-api-secret-b",
                "cookie": "cookie-secret-b",
                "set-cookie": "set-cookie-secret-b",
                "Cookie": "title-cookie-secret-b",
                "Set-Cookie": "title-set-cookie-secret-b"
            },
            "oauth": {
                "access_token": "access-secret-b",
                "refresh_token": "refresh-secret-b",
                "id_token": "id-token-secret-b",
                "jwt": "jwt-secret-b",
                "client_secret": "client-secret-b"
            },
            "vault": {
                "x-vault-token": "vault-secret-b"
            },
            "session": {
                "session_token": "session-secret-b",
                "credentials": "credentials-secret-b"
            },
            "crypto": {
                "secret": "generic-secret-b",
                "secret_b64": "generic-secret-b64-b",
                "key_material": "material-secret-b",
                "key_material_b64": "material-secret-b64-b",
                "master_key": "master-secret-b",
                "master_key_b64": "master-secret-b64-b",
                "resource_key": "resource-secret-b",
                "resource_key_b64": "resource-secret-b64-b",
                "wrapping_key": "wrapping-secret-b",
                "wrapping_key_b64": "wrapping-secret-b64-b"
            }
        });

        redact_sensitive_log_fields(&mut first);
        redact_sensitive_log_fields(&mut second);

        assert_eq!(first, second);
        assert_eq!(
            redacted_request_hash("secret-bearing-request", &first),
            redacted_request_hash("secret-bearing-request", &second),
        );
    }
}
