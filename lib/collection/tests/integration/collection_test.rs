use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter};
use std::num::NonZeroU32;

use ahash::AHashSet;
use api::rest::SearchRequestInternal;
use collection::collection::distance_matrix::CollectionSearchMatrixRequest;
use collection::config::{
    CkksCollectionConfig, CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams,
    CryptoMigrationCheckpoint, CryptoMigrationCheckpointStatus, CryptoMigrationPlan,
    CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, WalConfig,
};
use collection::discovery::discover;
use collection::grouping::GroupBy;
use collection::grouping::group_by::{GroupRequest, SourceRequest};
use collection::operations::CollectionUpdateOperations;
use collection::operations::config_diff::CollectionParamsDiff;
use collection::operations::payload_ops::{DeletePayloadOp, PayloadOps, SetPayloadOp};
use collection::operations::point_ops::{
    BatchPersisted, BatchVectorStructPersisted, ConditionalInsertOperationInternal,
    PointInsertOperationsInternal, PointOperations, PointStructPersisted, PointSyncOperation,
    VectorStructPersisted, WriteOrdering,
};
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use collection::operations::types::{
    CollectionError, CollectionUpdateProvenance, CountRequestInternal, DiscoverRequestInternal,
    PointRequestInternal, RecommendExample, RecommendRequestInternal, ScrollRequestInternal,
    UpdateStatus,
};
use collection::operations::universal_query::collection_query::{
    CollectionPrefetch, CollectionQueryRequest, Query, VectorInputInternal, VectorQuery,
};
use collection::operations::universal_query::formula::{ExpressionInternal, FormulaInternal};
use collection::operations::universal_query::shard_query::{
    FusionInternal, SampleInternal, ScoringQuery, ShardQueryRequest,
};
use collection::operations::vector_ops::{
    PointVectorsPersisted, UpdateVectorsOp, VectorOperations,
};
use collection::operations::vector_params_builder::VectorParamsBuilder;
use collection::recommendations::recommend_by;
use collection::shards::replica_set::replica_set_state::{ReplicaSetState, ReplicaState};
use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::types::{DetailsLevel, TelemetryDetail};
use data_encoding::BASE64URL_NOPAD;
use fs_err::{self as fs, File};
use itertools::Itertools;
use qdrant_sec::{
    AeadCipher, CLIENT_ENCRYPTED_PAYLOAD_MARKER, CLIENT_PAYLOAD_ENVELOPE_BINDING,
    ClientPayloadSignatureVerification, ClientPayloadValidationContext,
    ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_PAYLOAD_MARKER, ENCRYPTED_VECTOR_SIDECAR_FIELD,
    PAYLOAD_TEXT_KEY_DOMAIN, PayloadEncryptionPolicy, PayloadTextEncryptor, SecretKey,
    ckks_vector_verified_sidecar_key, client_payload_signature_message,
    is_client_encrypted_payload_value, is_encrypted_payload_value,
    validate_client_payload_value_for_runtime,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use segment::data_types::facets::FacetParams;
use segment::data_types::order_by::{Direction, OrderBy, OrderByInterface};
use segment::data_types::vectors::{DEFAULT_VECTOR_NAME, VectorInternal, VectorStructInternal};
use segment::types::{
    Condition, Distance, ExtendedPointId, FieldCondition, Filter, HasIdCondition,
    HasVectorCondition, Payload, PayloadFieldSchema, PayloadSchemaType, PointIdType,
    WithPayloadInterface, WithVector,
};
use serde_json::Map;
use shard::files::PAYLOAD_INDEX_CONFIG_FILE;
use shard::payload_index_schema::PayloadIndexSchema;
use tempfile::Builder;

use crate::common::{
    N_SHARDS, TEST_OPTIMIZERS_CONFIG, encrypted_collection_fixture, load_local_collection,
    new_local_collection, simple_collection_fixture,
};

fn runtime_verified_client_envelopes_for_operation(
    operation: &CollectionUpdateOperations,
    collection_crypto_id: &str,
    public_key: &[u8],
) -> CollectionUpdateProvenance {
    let mut verified_envelope_keys = Vec::new();
    let mut collect_payload = |point_id: &PointIdType, payload: &Payload| {
        let Some(value) = payload
            .0
            .get("document")
            .and_then(|document| document.get("body"))
        else {
            return;
        };
        let key = validate_client_payload_value_for_runtime(
            value,
            ClientPayloadValidationContext {
                collection_id: collection_crypto_id,
                point_id: &point_id.to_string(),
                field_path: "document.body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                expected_rk_id: Some("tenant-a/client-rk-2026-04"),
                min_rk_epoch: Some(3),
                max_rk_epoch: Some(3),
                key_id_required: true,
                signature_required: true,
                signature_verification: Some(ClientPayloadSignatureVerification {
                    expected_key_id: "tenant-a/client-signing-v1",
                    public_key,
                }),
            },
        )
        .unwrap();
        verified_envelope_keys.push(key);
    };

    match operation {
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::PointsList(points),
        )) => {
            for point in points {
                if let Some(payload) = &point.payload {
                    collect_payload(&point.id, payload);
                }
            }
        }
        CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(operation)) => {
            for point in &operation.points {
                if let Some(payload) = &point.payload {
                    collect_payload(&point.id, payload);
                }
            }
        }
        _ => {}
    }

    CollectionUpdateProvenance::runtime_verified_client_envelopes(verified_envelope_keys)
}

fn sign_client_payload(payload: &mut Payload, key_pair: &Ed25519KeyPair) {
    let value = payload
        .0
        .get_mut("document")
        .and_then(|document| document.get_mut("body"))
        .expect("client payload fixture must contain document.body");
    let message = client_payload_signature_message(value, "document.body").unwrap();
    let signature = key_pair.sign(&message);
    value
        .as_object_mut()
        .unwrap()
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("signature")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "sig".to_string(),
            serde_json::Value::String(BASE64URL_NOPAD.encode(signature.as_ref())),
        );
}

fn payload_encryption_config() -> CollectionEncryptionConfig {
    CollectionEncryptionConfig {
        version: 1,
        key_id: Some("tenant-a:docs".to_string()),
        crypto_schema_version: 1,
        encryption_epoch: 0,
        migration_state: CryptoMigrationState::Active,
        rules: vec![EncryptionRuleRef {
            id: "document_body".to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec!["document.body".to_string()],
            },
            instance: "docs_payload_v1".to_string(),
            binding: Some("payload-field/v1".to_string()),
        }],
    }
}

fn client_payload_encryption_config() -> CollectionEncryptionConfig {
    CollectionEncryptionConfig {
        version: 1,
        key_id: Some("tenant-a/client-rk-2026-04".to_string()),
        crypto_schema_version: 1,
        encryption_epoch: 3,
        migration_state: CryptoMigrationState::Active,
        rules: vec![EncryptionRuleRef {
            id: "document_body_client".to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec!["document.body".to_string()],
            },
            instance: "docs_payload_client_v1".to_string(),
            binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
        }],
    }
}

fn vector_encryption_config() -> CollectionEncryptionConfig {
    CollectionEncryptionConfig {
        version: 1,
        key_id: Some("tenant-a:docs".to_string()),
        crypto_schema_version: 1,
        encryption_epoch: 0,
        migration_state: CryptoMigrationState::Active,
        rules: vec![EncryptionRuleRef {
            id: "default_vector".to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec![DEFAULT_VECTOR_NAME.to_string()],
            },
            instance: "docs_vector_v1".to_string(),
            binding: Some("vector-envelope/v1".to_string()),
        }],
    }
}

fn encrypted_payload_filter() -> Filter {
    Filter::new_must(Condition::Field(FieldCondition::new_match(
        "document.body".parse().unwrap(),
        serde_json::from_str(r#"{ "value": "secret body" }"#).unwrap(),
    )))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_updater() {
    test_collection_updater_with_shards(1).await;
    test_collection_updater_with_shards(N_SHARDS).await;
}

async fn test_collection_updater_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![1.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
            vec![1.0, 1.0, 1.0, 1.0],
            vec![1.0, 1.0, 0.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    let insert_result = collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter,
        )
        .await;

    match insert_result {
        Ok(res) => {
            assert_eq!(res.status, UpdateStatus::Completed)
        }
        Err(err) => panic!("operation failed: {err:?}"),
    }

    let search_request = SearchRequestInternal {
        vector: vec![1.0, 1.0, 1.0, 1.0].into(),
        with_payload: None,
        with_vector: None,
        filter: None,
        params: None,
        limit: 3,
        offset: None,
        score_threshold: None,
    };

    let hw_acc = HwMeasurementAcc::new();
    let search_res = collection
        .search(
            search_request.into(),
            None,
            &ShardSelectorInternal::All,
            None,
            hw_acc,
        )
        .await;

    match search_res {
        Ok(res) => {
            assert_eq!(res.len(), 3);
            assert_eq!(res[0].id, 2.into());
            assert!(res[0].payload.is_none());
        }
        Err(err) => panic!("search failed: {err:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_search_with_payload_and_vector() {
    test_collection_search_with_payload_and_vector_with_shards(1).await;
    test_collection_search_with_payload_and_vector_with_shards(N_SHARDS).await;
}

async fn test_collection_search_with_payload_and_vector_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0.into(), 1.into()],
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![1.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
        ]),
        payloads: serde_json::from_str(
            r#"[{ "k": { "type": "keyword", "value": "v1" } }, { "k": "v2" , "v": "v3"}]"#,
        )
        .unwrap(),
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    let insert_result = collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter,
        )
        .await;

    match insert_result {
        Ok(res) => {
            assert_eq!(res.status, UpdateStatus::Completed)
        }
        Err(err) => panic!("operation failed: {err:?}"),
    }

    let search_request = SearchRequestInternal {
        vector: vec![1.0, 0.0, 1.0, 1.0].into(),
        with_payload: Some(WithPayloadInterface::Bool(true)),
        with_vector: Some(true.into()),
        filter: None,
        params: None,
        limit: 3,
        offset: None,
        score_threshold: None,
    };

    let hw_acc = HwMeasurementAcc::new();
    let search_res = collection
        .search(
            search_request.into(),
            None,
            &ShardSelectorInternal::All,
            None,
            hw_acc,
        )
        .await;

    match search_res {
        Ok(res) => {
            assert_eq!(res.len(), 2);
            assert_eq!(res[0].id, 0.into());
            assert_eq!(res[0].payload.as_ref().unwrap().len(), 1);
            let vec = vec![1.0, 0.0, 1.0, 1.0];
            match &res[0].vector {
                Some(VectorStructInternal::Single(v)) => assert_eq!(v.clone(), vec),
                _ => panic!("vector is not returned"),
            }
        }
        Err(err) => panic!("search failed: {err:?}"),
    }

    let count_request = CountRequestInternal {
        filter: Some(Filter::new_must(Condition::Field(
            FieldCondition::new_match(
                "k".parse().unwrap(),
                serde_json::from_str(r#"{ "value": "v2" }"#).unwrap(),
            ),
        ))),
        exact: true,
    };

    let hw_acc = HwMeasurementAcc::new();
    let count_res = collection
        .count(
            count_request,
            None,
            &ShardSelectorInternal::All,
            None,
            hw_acc,
        )
        .await
        .unwrap();
    assert_eq!(count_res.count, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_loading() {
    test_collection_loading_with_shards(1).await;
    test_collection_loading_with_shards(N_SHARDS).await;
}

async fn test_collection_loading_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    {
        let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

        let batch = BatchPersisted {
            ids: vec![0, 1, 2, 3, 4]
                .into_iter()
                .map(|x| x.into())
                .collect_vec(),
            vectors: BatchVectorStructPersisted::Single(vec![
                vec![1.0, 0.0, 1.0, 1.0],
                vec![1.0, 0.0, 1.0, 0.0],
                vec![1.0, 1.0, 1.0, 1.0],
                vec![1.0, 1.0, 0.0, 1.0],
                vec![1.0, 0.0, 0.0, 0.0],
            ]),
            payloads: None,
        };

        let insert_points = CollectionUpdateOperations::PointOperation(
            PointOperations::UpsertPoints(PointInsertOperationsInternal::from(batch)),
        );

        let hw_counter = HwMeasurementAcc::new();
        collection
            .update_from_client_simple(
                insert_points,
                true,
                None,
                WriteOrdering::default(),
                hw_counter,
            )
            .await
            .unwrap();

        let payload: Payload = serde_json::from_str(r#"{"color":"red"}"#).unwrap();

        let assign_payload =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload,
                points: Some(vec![2.into(), 3.into()]),
                filter: None,
                key: None,
            }));

        let hw_counter = HwMeasurementAcc::new();
        collection
            .update_from_client_simple(
                assign_payload,
                true,
                None,
                WriteOrdering::default(),
                hw_counter,
            )
            .await
            .unwrap();

        collection.stop_gracefully().await;
    }

    let collection_path = collection_dir.path();
    let loaded_collection = load_local_collection(
        "test".to_string(),
        collection_path,
        &collection_path.join("snapshots"),
    )
    .await;
    let request = PointRequestInternal {
        ids: vec![1.into(), 2.into()],
        with_payload: Some(WithPayloadInterface::Bool(true)),
        with_vector: true.into(),
    };
    let retrieved = loaded_collection
        .retrieve(
            request,
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    assert_eq!(retrieved.len(), 2);

    for record in retrieved {
        if record.id == 2.into() {
            let non_empty_payload = record.payload.unwrap();

            assert_eq!(non_empty_payload.len(), 1)
        }
    }

    loaded_collection.stop_gracefully().await;
    println!("Function end");
}

#[test]
fn test_deserialization() {
    let batch = BatchPersisted {
        ids: vec![0.into(), 1.into()],
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![1.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));
    let json_str = serde_json::to_string_pretty(&insert_points).unwrap();

    let _read_obj: CollectionUpdateOperations = serde_json::from_str(&json_str).unwrap();

    let crob_bytes = rmp_serde::to_vec(&insert_points).unwrap();

    let _read_obj2: CollectionUpdateOperations = rmp_serde::from_slice(&crob_bytes).unwrap();
}

#[test]
fn test_deserialization2() {
    let points = vec![
        PointStructPersisted {
            id: 0.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 1.0, 1.0]),
            payload: None,
        },
        PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 1.0, 0.0]),
            payload: None,
        },
    ];

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(points),
    ));

    let json_str = serde_json::to_string_pretty(&insert_points).unwrap();

    let _read_obj: CollectionUpdateOperations = serde_json::from_str(&json_str).unwrap();

    let raw_bytes = rmp_serde::to_vec(&insert_points).unwrap();

    let _read_obj2: CollectionUpdateOperations = rmp_serde::from_slice(&raw_bytes).unwrap();
}

// Request to find points sent to all shards but they might not have a particular id, so they will return an error
#[tokio::test(flavor = "multi_thread")]
async fn test_recommendation_api() {
    test_recommendation_api_with_shards(1).await;
    test_recommendation_api_with_shards(N_SHARDS).await;
}

async fn test_recommendation_api_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4, 5, 6, 7, 8]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![0.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 0.0, 1.0],
            vec![0.0, 0.0, 0.0, 1.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_acc = HwMeasurementAcc::new();
    collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_acc.clone(),
        )
        .await
        .unwrap();
    let result = recommend_by(
        RecommendRequestInternal {
            positive: vec![0.into()],
            negative: vec![8.into()],
            limit: 5,
            ..Default::default()
        },
        &collection,
        |_name| async { unreachable!("Should not be called in this test") },
        None,
        ShardSelectorInternal::All,
        None,
        hw_acc,
    )
    .await
    .unwrap();
    assert!(!result.is_empty());
    let top1 = &result[0];

    assert!(top1.id == 5.into() || top1.id == 6.into());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_read_api() {
    test_read_api_with_shards(1).await;
    test_read_api_with_shards(N_SHARDS).await;
}

async fn test_read_api_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4, 5, 6, 7, 8]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![0.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 0.0, 1.0],
            vec![0.0, 0.0, 0.0, 1.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter,
        )
        .await
        .unwrap();

    let result = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(2),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.next_page_offset, Some(2.into()));
    assert_eq!(result.points.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ordered_read_api() {
    test_ordered_scroll_api_with_shards(1).await;
    test_ordered_scroll_api_with_shards(N_SHARDS).await;
}

async fn test_ordered_scroll_api_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    const PRICE_FLOAT_KEY: &str = "price_float";
    const PRICE_INT_KEY: &str = "price_int";
    const MULTI_VALUE_KEY: &str = "multi_value";

    let get_payload = |value: f64| -> Option<Payload> {
        let mut payload_map = Map::new();
        payload_map.insert(PRICE_FLOAT_KEY.to_string(), value.into());
        payload_map.insert(PRICE_INT_KEY.to_string(), (value as i64).into());
        payload_map.insert(
            MULTI_VALUE_KEY.to_string(),
            vec![value, value + 20.0].into(),
        );
        Some(Payload(payload_map))
    };

    let payloads: Vec<Option<Payload>> = vec![
        get_payload(11.0),
        get_payload(10.0),
        get_payload(9.0),
        get_payload(8.0),
        get_payload(7.0),
        get_payload(6.0),
        get_payload(5.0),
        get_payload(5.0),
        get_payload(5.0),
        get_payload(5.0),
        get_payload(4.0),
        get_payload(3.0),
        get_payload(2.0),
        get_payload(1.0),
    ];

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![0.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
            vec![0.0, 0.0, 0.0, 1.0],
            vec![0.0, 0.0, 0.0, 1.0],
            vec![0.0, 1.0, 1.0, 1.0],
            vec![0.0, 1.0, 1.0, 1.0],
            vec![0.0, 1.0, 1.0, 1.0],
            vec![0.0, 1.0, 1.0, 1.0],
            vec![1.0, 1.0, 1.0, 1.0],
        ]),
        payloads: Some(payloads),
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter.clone(),
        )
        .await
        .unwrap();

    collection
        .create_payload_index_with_wait(
            PRICE_FLOAT_KEY.parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Float),
            true,
            hw_counter.clone(),
        )
        .await
        .unwrap();

    collection
        .create_payload_index_with_wait(
            PRICE_INT_KEY.parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Integer),
            true,
            hw_counter.clone(),
        )
        .await
        .unwrap();

    collection
        .create_payload_index_with_wait(
            MULTI_VALUE_KEY.parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Float),
            true,
            hw_counter.clone(),
        )
        .await
        .unwrap();

    ///////// Test single-valued fields ///////////
    for key in [PRICE_FLOAT_KEY, PRICE_INT_KEY] {
        let result_asc = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(3),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: false.into(),
                    order_by: Some(OrderByInterface::Struct(OrderBy {
                        key: key.parse().unwrap(),
                        direction: Some(Direction::Asc),
                        start_from: None,
                    })),
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap();

        assert_eq!(result_asc.points.len(), 3);
        assert_eq!(result_asc.next_page_offset, None);
        assert!(result_asc.points.iter().tuple_windows().all(|(a, b)| {
            let a = a.payload.as_ref().unwrap();
            let b = b.payload.as_ref().unwrap();
            let a = a.0.get(key).unwrap().as_f64();
            let b = b.0.get(key).unwrap().as_f64();
            a <= b
        }));

        let result_desc = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(5),
                    filter: None,
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: false.into(),
                    order_by: Some(OrderByInterface::Struct(OrderBy {
                        key: key.parse().unwrap(),
                        direction: Some(Direction::Desc),
                        start_from: None,
                    })),
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap();

        assert_eq!(result_desc.points.len(), 5);
        assert_eq!(result_desc.next_page_offset, None);
        assert!(
            result_desc.points.iter().tuple_windows().all(|(a, b)| {
                let a = a.payload.as_ref().unwrap();
                let b = b.payload.as_ref().unwrap();
                let a = a.0.get(key).unwrap().as_f64();
                let b = b.0.get(key).unwrap().as_f64();
                a >= b
            }),
            "Expected descending order when using {key} key, got: {:#?}",
            result_desc.points
        );

        let asc_already_seen: AHashSet<_> = result_asc.points.iter().map(|x| x.id).collect();

        dbg!(&asc_already_seen);
        let asc_second_page = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(5),
                    filter: Some(Filter::new_must_not(Condition::HasId(
                        HasIdCondition::from(asc_already_seen),
                    ))),
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: false.into(),
                    order_by: Some(OrderByInterface::Struct(OrderBy {
                        key: key.parse().unwrap(),
                        direction: Some(Direction::Asc),
                        start_from: None,
                    })),
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap();

        let asc_second_page_points = asc_second_page
            .points
            .iter()
            .map(|x| x.id)
            .collect::<HashSet<_>>();
        let valid_asc_second_page_points = [10, 9, 8, 7, 6]
            .into_iter()
            .map(|x| x.into())
            .collect::<HashSet<ExtendedPointId>>();
        assert_eq!(asc_second_page.points.len(), 5);
        assert!(asc_second_page_points.is_subset(&valid_asc_second_page_points));

        let desc_already_seen: AHashSet<_> = result_desc.points.iter().map(|x| x.id).collect();

        dbg!(&desc_already_seen);

        let desc_second_page = collection
            .scroll_by(
                ScrollRequestInternal {
                    offset: None,
                    limit: Some(4),
                    filter: Some(Filter::new_must_not(Condition::HasId(
                        HasIdCondition::from(desc_already_seen),
                    ))),
                    with_payload: Some(WithPayloadInterface::Bool(true)),
                    with_vector: false.into(),
                    order_by: Some(OrderByInterface::Struct(OrderBy {
                        key: key.parse().unwrap(),
                        direction: Some(Direction::Desc),
                        start_from: None,
                    })),
                },
                None,
                &ShardSelectorInternal::All,
                None,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap();

        let desc_second_page_points = desc_second_page
            .points
            .iter()
            .map(|x| x.id)
            .collect::<HashSet<_>>();

        let valid_desc_second_page_points = [5, 6, 7, 8, 9]
            .into_iter()
            .map(|x| x.into())
            .collect::<HashSet<ExtendedPointId>>();

        assert_eq!(desc_second_page.points.len(), 4);
        assert!(
            desc_second_page_points.is_subset(&valid_desc_second_page_points),
            "expected: {valid_desc_second_page_points:?}, got: {desc_second_page_points:?}"
        );
    }

    ///////// Test multi-valued field ///////////
    let result_multi = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(100),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: Some(OrderByInterface::Key(MULTI_VALUE_KEY.parse().unwrap())),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    assert!(
        result_multi
            .points
            .iter()
            .fold(HashMap::<PointIdType, usize, _>::new(), |mut acc, point| {
                acc.entry(point.id)
                    .and_modify(|x| {
                        *x += 1;
                    })
                    .or_insert(1);
                acc
            })
            .values()
            .all(|&x| x == 2),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_payload_index() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    for indexed_field in ["document.body", "document", "document.body.keyword"] {
        let err = collection
            .create_payload_index_with_wait(
                indexed_field.parse().unwrap(),
                PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
                true,
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            CollectionError::BadInput { description }
                if description.contains("encrypted payload field")
                    && description.contains("document.body")
                    && description.contains("blind index")
        ));
    }

    collection
        .create_payload_index_with_wait(
            "document.summary".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
            true,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_recovered_payload_index_schema() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let snapshot_dir = collection_dir.path().join("snapshots");

    let mut payload_schema = PayloadIndexSchema::default();
    payload_schema.schema.insert(
        "document.body".parse().unwrap(),
        PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
    );
    fs::write(
        collection_dir.path().join(PAYLOAD_INDEX_CONFIG_FILE),
        serde_json::to_vec(&payload_schema).unwrap(),
    )
    .unwrap();

    let collection_config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorParamsBuilder::new(4, Distance::Dot).build().into(),
            shard_number: NonZeroU32::new(1).unwrap(),
            encryption: Some(payload_encryption_config()),
            ..CollectionParams::empty()
        },
        optimizer_config: TEST_OPTIMIZERS_CONFIG.clone(),
        wal_config: WalConfig {
            wal_capacity_mb: 1,
            wal_segments_ahead: 0,
            wal_retain_closed: 1,
        },
        hnsw_config: Default::default(),
        quantization_config: Default::default(),
        strict_mode_config: Default::default(),
        uuid: None,
        metadata: None,
    };

    let err = match new_local_collection(
        "test".to_string(),
        collection_dir.path(),
        &snapshot_dir,
        &collection_config,
    )
    .await
    {
        Ok(_) => panic!("expected encrypted payload index schema recovery to fail"),
        Err(err) => err,
    };

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("payload index schema")
                && description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_plan_updates_collection_config_through_admin_path() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let start_rotation = CryptoMigrationPlan {
        from: CryptoMigrationState::Active,
        to: CryptoMigrationState::Rotating,
        target_epoch: 1,
        active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
        retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
        dry_run: true,
        checkpoints: Vec::new(),
    };

    collection
        .apply_crypto_migration_plan(&start_rotation)
        .await
        .unwrap();
    let dry_run_config = collection.config_snapshot().await;
    let dry_run_encryption = dry_run_config.params.encryption.unwrap();
    assert_eq!(
        dry_run_encryption.migration_state,
        CryptoMigrationState::Active
    );
    assert_eq!(dry_run_encryption.encryption_epoch, 0);

    let mut start_rotation = start_rotation;
    start_rotation.dry_run = false;
    collection
        .apply_crypto_migration_plan(&start_rotation)
        .await
        .unwrap();
    let rotating_config = collection.config_snapshot().await;
    let rotating_encryption = rotating_config.params.encryption.unwrap();
    assert_eq!(
        rotating_encryption.migration_state,
        CryptoMigrationState::Rotating
    );
    assert_eq!(rotating_encryption.encryption_epoch, 1);

    let stale_start = CryptoMigrationPlan {
        from: CryptoMigrationState::Active,
        to: CryptoMigrationState::Rotating,
        target_epoch: 2,
        active_rk_id: Some("tenant-a/payload-rk-v3".to_string()),
        retired_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
        dry_run: false,
        checkpoints: Vec::new(),
    };
    let err = collection
        .apply_crypto_migration_plan(&stale_start)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("crypto_migration_current_state_mismatch")
    ));

    let complete_rotation = CryptoMigrationPlan {
        from: CryptoMigrationState::Rotating,
        to: CryptoMigrationState::Active,
        target_epoch: 1,
        active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
        retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
        dry_run: false,
        checkpoints: vec![CryptoMigrationCheckpoint {
            shard_id: 0,
            total_points: 1,
            processed_points: 1,
            rewritten_points: 1,
            status: CryptoMigrationCheckpointStatus::Verified,
        }],
    };
    collection
        .apply_crypto_migration_plan(&complete_rotation)
        .await
        .unwrap();
    let active_config = collection.config_snapshot().await;
    let active_encryption = active_config.params.encryption.unwrap();
    assert_eq!(
        active_encryption.migration_state,
        CryptoMigrationState::Active
    );
    assert_eq!(active_encryption.encryption_epoch, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn crypto_migration_completion_requires_all_collection_shards() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 2, payload_encryption_config()).await;

    collection
        .apply_crypto_migration_plan(&CryptoMigrationPlan {
            from: CryptoMigrationState::Active,
            to: CryptoMigrationState::Rotating,
            target_epoch: 1,
            active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
            retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
            dry_run: false,
            checkpoints: Vec::new(),
        })
        .await
        .unwrap();

    let incomplete_completion = CryptoMigrationPlan {
        from: CryptoMigrationState::Rotating,
        to: CryptoMigrationState::Active,
        target_epoch: 1,
        active_rk_id: Some("tenant-a/payload-rk-v2".to_string()),
        retired_rk_id: Some("tenant-a/payload-rk-v1".to_string()),
        dry_run: false,
        checkpoints: vec![CryptoMigrationCheckpoint {
            shard_id: 0,
            total_points: 1,
            processed_points: 1,
            rewritten_points: 1,
            status: CryptoMigrationCheckpointStatus::Verified,
        }],
    };
    let err = collection
        .apply_crypto_migration_plan(&incomplete_completion)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("must cover every collection shard")
    ));

    let mut complete = incomplete_completion;
    complete.checkpoints.push(CryptoMigrationCheckpoint {
        shard_id: 1,
        total_points: 1,
        processed_points: 1,
        rewritten_points: 1,
        status: CryptoMigrationCheckpointStatus::Verified,
    });
    collection
        .apply_crypto_migration_plan(&complete)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_filters() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: Some(encrypted_payload_filter()),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .count(
            CountRequestInternal {
                filter: Some(encrypted_payload_filter()),
                exact: true,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: None,
                filter: Some(encrypted_payload_filter()),
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .query(
            ShardQueryRequest {
                prefetches: vec![],
                query: Some(ScoringQuery::Sample(SampleInternal::Random)),
                filter: Some(encrypted_payload_filter()),
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
            },
            None,
            ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .facet(
            FacetParams {
                key: "document.title".parse().unwrap(),
                limit: 10,
                filter: Some(encrypted_payload_filter()),
                exact: true,
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted payload field")
                && description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_update_filters() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let operations = vec![
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPointsConditional(
            ConditionalInsertOperationInternal {
                points_op: PointInsertOperationsInternal::from(vec![PointStructPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                    payload: Some(serde_json::from_str(r#"{"tag":"updated"}"#).unwrap()),
                }]),
                condition: encrypted_payload_filter(),
                update_mode: None,
            },
        )),
        CollectionUpdateOperations::PointOperation(PointOperations::DeletePointsByFilter(
            encrypted_payload_filter(),
        )),
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: serde_json::from_str(r#"{"tag":"updated"}"#).unwrap(),
            points: None,
            filter: Some(encrypted_payload_filter()),
            key: None,
        })),
        CollectionUpdateOperations::PayloadOperation(PayloadOps::DeletePayload(DeletePayloadOp {
            keys: vec!["tag".parse().unwrap()],
            points: None,
            filter: Some(encrypted_payload_filter()),
        })),
        CollectionUpdateOperations::PayloadOperation(PayloadOps::ClearPayloadByFilter(
            encrypted_payload_filter(),
        )),
        CollectionUpdateOperations::VectorOperation(VectorOperations::UpdateVectors(
            UpdateVectorsOp {
                points: vec![PointVectorsPersisted {
                    id: 1.into(),
                    vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
                }],
                update_filter: Some(encrypted_payload_filter()),
            },
        )),
        CollectionUpdateOperations::VectorOperation(VectorOperations::DeleteVectorsByFilter(
            encrypted_payload_filter(),
            vec![DEFAULT_VECTOR_NAME.to_string()],
        )),
    ];

    for operation in operations {
        let err = collection
            .update_from_client_simple(
                operation,
                true,
                None,
                WriteOrdering::default(),
                HwMeasurementAcc::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CollectionError::BadInput { description }
                if description.contains("cannot filter on encrypted payload field")
                    && description.contains("document.body")
                    && description.contains("blind index")
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_order_by() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let encrypted_order_by = OrderBy {
        key: "document.body".parse().unwrap(),
        direction: Some(Direction::Asc),
        start_from: None,
    };
    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: Some(OrderByInterface::Struct(encrypted_order_by.clone())),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot order by encrypted payload field")
                && description.contains("document.body")
                && description.contains("blind index")
    ));

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::OrderBy(encrypted_order_by)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot order by encrypted payload field")
                && description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_formula() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let encrypted_formula = FormulaInternal {
        formula: ExpressionInternal::Variable("document.body".to_string()),
        defaults: HashMap::new(),
    };
    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Formula(encrypted_formula)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot use encrypted payload field")
                && description.contains("document.body")
                && description.contains("formula")
                && description.contains("blind index")
    ));

    let condition_formula = FormulaInternal {
        formula: ExpressionInternal::Condition(Box::new(
            encrypted_payload_filter().must.unwrap().pop().unwrap(),
        )),
        defaults: HashMap::new(),
    };
    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Formula(condition_formula)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot use formula condition")
                && description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_facet_key() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let err = collection
        .facet(
            FacetParams {
                key: "document.body".parse().unwrap(),
                limit: 10,
                filter: None,
                exact: true,
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot facet on encrypted payload field")
                && description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_group_by() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let group_request = GroupRequest {
        source: SourceRequest::Search(SearchRequestInternal {
            vector: vec![0.0, 0.0, 0.0, 0.0].into(),
            filter: None,
            params: None,
            limit: 1,
            offset: Some(0),
            with_payload: Some(WithPayloadInterface::Bool(false)),
            with_vector: Some(WithVector::Bool(false)),
            score_threshold: None,
        }),
        group_by: "document.body".parse().unwrap(),
        group_size: 1,
        limit: 1,
        with_lookup: None,
    };
    let err = GroupBy::new(
        group_request,
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot group by encrypted payload field")
                && description.contains("document.body")
                && description.contains("blind index")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_field_rejects_plaintext_payload_writes() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;

    let plaintext_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(
                    serde_json::from_str(r#"{"document":{"body":"secret body"}}"#).unwrap(),
                ),
            }]),
        ));
    let err = collection
        .update_from_client_simple(
            plaintext_upsert,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("plaintext payload")
                && description.contains("document.body")
    ));

    let keyed_plaintext_payload =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: serde_json::from_str(r#"{"body":"secret body"}"#).unwrap(),
            points: Some(vec![1.into()]),
            filter: None,
            key: Some("document".parse().unwrap()),
        }));
    let err = collection
        .update_from_client_simple(
            keyed_plaintext_payload,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("plaintext payload")
                && description.contains("document.body")
    ));

    let malformed_marker_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 3.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 0.0]),
                payload: Some(
                    serde_json::from_str(
                        r#"{"document":{"body":{"$qdrant_sec":{"kind":"payload_text"}}}}"#,
                    )
                    .unwrap(),
                ),
            }]),
        ));
    let err = collection
        .update_from_client_simple(
            malformed_marker_upsert,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("plaintext payload")
                && description.contains("document.body")
    ));

    let wrong_key_encryptor = PayloadTextEncryptor::new_with_derived_cipher_unchecked(
        "docs",
        AeadCipher::new_with_material_fingerprint(
            "tenant-a:other",
            SecretKey::from_bytes([7u8; 32]),
            "tenant-a/other@v1",
        )
        .unwrap(),
    )
    .unwrap();
    let mut wrong_key_payload: Payload =
        serde_json::from_str(r#"{"document":{"body":"wrong key marker"}}"#).unwrap();
    wrong_key_encryptor
        .encrypt_selected_fields(
            "4",
            &mut wrong_key_payload.0,
            &PayloadEncryptionPolicy::new(["document.body"]).unwrap(),
        )
        .unwrap();
    let wrong_key_marker_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 4.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 0.0, 1.0]),
                payload: Some(wrong_key_payload.clone()),
            }]),
        ));
    let err = collection
        .update_from_client_simple(
            wrong_key_marker_upsert,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted payload marker")
                && description.contains("document.body")
                && description.contains("requires runtime payload encryption")
    ));

    let wrong_key_marker_upsert_with_provenance =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 4.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 0.0, 1.0]),
                payload: Some(wrong_key_payload),
            }]),
        ));
    let err = collection
        .update_from_client(
            wrong_key_marker_upsert_with_provenance,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_payloads(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted payload marker")
                && description.contains("document.body")
                && description.contains("key id does not match")
    ));

    let valid_key_encryptor = PayloadTextEncryptor::new_with_derived_cipher_unchecked(
        "docs",
        AeadCipher::new_with_material_fingerprint(
            "tenant-a:docs",
            SecretKey::from_bytes([8u8; 32]),
            "tenant-a/docs@v1",
        )
        .unwrap(),
    )
    .unwrap();
    let mut malformed_header_payload: Payload =
        serde_json::from_str(r#"{"document":{"body":"bad nonce marker"}}"#).unwrap();
    valid_key_encryptor
        .encrypt_selected_fields(
            "5",
            &mut malformed_header_payload.0,
            &PayloadEncryptionPolicy::new(["document.body"]).unwrap(),
        )
        .unwrap();
    malformed_header_payload
        .0
        .get_mut("document")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("nonce".to_string(), serde_json::json!("AQID"));
    let malformed_header_marker_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 5.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 1.0, 0.0]),
                payload: Some(malformed_header_payload),
            }]),
        ));
    let err = collection
        .update_from_client(
            malformed_header_marker_upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_payloads(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted payload marker")
                && description.contains("document.body")
                && description.contains("nonce must decode to 96 bits")
    ));

    let plaintext_sync = CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(
        PointSyncOperation {
            from_id: None,
            to_id: None,
            points: vec![PointStructPersisted {
                id: 5.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 1.0]),
                payload: Some(
                    serde_json::from_str(r#"{"document":{"body":"sync plaintext"}}"#).unwrap(),
                ),
            }],
        },
    ));
    let err = collection
        .update_from_client_simple(
            plaintext_sync,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("plaintext payload")
                && description.contains("document.body")
    ));

    let public_payload = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 2.into(),
            vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
            payload: Some(serde_json::from_str(r#"{"document":{"summary":"public"}}"#).unwrap()),
        }]),
    ));

    collection
        .update_from_client_simple(
            public_payload,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn client_encrypted_payload_marker_must_match_collection_guard() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, client_payload_encryption_config())
            .await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();

    let client_payload_with_epoch = |collection_id: &str, point_id: &str, rk_id: &str, rk_epoch| {
        let mut payload = Payload(
            serde_json::json!({
                "document": {
                    "body": {
                        CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                            "version": 1,
                            "kind": "payload_text",
                            "algorithm": "AES-256-GCM",
                            "key_id": "tenant-a/client-rk-2026-04",
                            "rk_id": rk_id,
                            "rk_epoch": rk_epoch,
                            "kdf_domain": "qdrant-sec/client-payload-text/v1",
                            "aad": {
                                "collection_id": collection_id,
                                "point_id": point_id,
                                "field_path": "document.body",
                                "schema_version": 1
                            },
                            "nonce": "AAAAAAAAAAAAAAAA",
                            "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                            "signature": {
                                "alg": "ed25519",
                                "key_id": "tenant-a/client-signing-v1",
                                "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            }
                        }
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        sign_client_payload(&mut payload, &key_pair);
        payload
    };
    let client_payload = |collection_id: &str, point_id: &str, rk_id: &str| {
        client_payload_with_epoch(collection_id, point_id, rk_id, 3)
    };

    let unverified_sync_marker = CollectionUpdateOperations::PointOperation(
        PointOperations::SyncPoints(PointSyncOperation {
            from_id: None,
            to_id: None,
            points: vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }],
        }),
    );
    let err = collection
        .update_from_client_simple(
            unverified_sync_marker,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
    ));

    let empty_proof_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let empty_verified_provenance =
        CollectionUpdateProvenance::runtime_verified_client_envelopes(Vec::new());
    assert_eq!(
        empty_verified_provenance,
        CollectionUpdateProvenance::client_plaintext(),
    );
    let err = collection
        .update_from_client(
            empty_proof_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            empty_verified_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
    ));

    let point_specific_set_payload =
        client_payload(&collection_crypto_id, "1", "tenant-a/client-rk-2026-04");
    let point_specific_body = point_specific_set_payload
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .unwrap();
    let point_specific_verified_key = validate_client_payload_value_for_runtime(
        point_specific_body,
        ClientPayloadValidationContext {
            collection_id: &collection_crypto_id,
            point_id: "1",
            field_path: "document.body",
            expected_key_id: Some("tenant-a/client-rk-2026-04"),
            expected_rk_id: Some("tenant-a/client-rk-2026-04"),
            min_rk_epoch: Some(3),
            max_rk_epoch: Some(3),
            key_id_required: true,
            signature_required: true,
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a/client-signing-v1",
                public_key: &public_key,
            }),
        },
    )
    .unwrap();
    let pointless_set_marker =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: point_specific_set_payload,
            points: None,
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            pointless_set_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_verified_client_envelopes(vec![
                point_specific_verified_key,
            ]),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires point-specific runtime envelope verification")
    ));

    let mismatched_point_payload =
        client_payload(&collection_crypto_id, "1", "tenant-a/client-rk-2026-04");
    let mismatched_point_body = mismatched_point_payload
        .0
        .get("document")
        .and_then(|document| document.get("body"))
        .unwrap();
    let mismatched_point_verified_key = validate_client_payload_value_for_runtime(
        mismatched_point_body,
        ClientPayloadValidationContext {
            collection_id: &collection_crypto_id,
            point_id: "1",
            field_path: "document.body",
            expected_key_id: Some("tenant-a/client-rk-2026-04"),
            expected_rk_id: Some("tenant-a/client-rk-2026-04"),
            min_rk_epoch: Some(3),
            max_rk_epoch: Some(3),
            key_id_required: true,
            signature_required: true,
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a/client-signing-v1",
                public_key: &public_key,
            }),
        },
    )
    .unwrap();
    let mismatched_point_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 2.into(),
                vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
                payload: Some(mismatched_point_payload),
            }]),
        ));
    let err = collection
        .update_from_client(
            mismatched_point_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_verified_client_envelopes(vec![
                mismatched_point_verified_key,
            ]),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
    ));

    let mut wrong_collection_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let wrong_collection_provenance = runtime_verified_client_envelopes_for_operation(
        &wrong_collection_marker,
        &collection_crypto_id,
        &public_key,
    );
    if let CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::PointsList(points),
    )) = &mut wrong_collection_marker
    {
        points[0]
            .payload
            .as_mut()
            .unwrap()
            .0
            .get_mut("document")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("aad")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "collection_id".to_string(),
                serde_json::Value::String("wrong-collection".to_string()),
            );
    }
    let err = collection
        .update_from_client(
            wrong_collection_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_collection_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
    ));

    let mut wrong_rk_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let wrong_rk_provenance = runtime_verified_client_envelopes_for_operation(
        &wrong_rk_marker,
        &collection_crypto_id,
        &public_key,
    );
    if let CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::PointsList(points),
    )) = &mut wrong_rk_marker
    {
        points[0]
            .payload
            .as_mut()
            .unwrap()
            .0
            .get_mut("document")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "rk_id".to_string(),
                serde_json::Value::String("tenant-a/old-client-rk".to_string()),
            );
    }
    let err = collection
        .update_from_client(
            wrong_rk_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_rk_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
    ));

    let mut wrong_epoch_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload_with_epoch(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                    3,
                )),
            }]),
        ));
    let wrong_epoch_provenance = runtime_verified_client_envelopes_for_operation(
        &wrong_epoch_marker,
        &collection_crypto_id,
        &public_key,
    );
    if let CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::PointsList(points),
    )) = &mut wrong_epoch_marker
    {
        points[0]
            .payload
            .as_mut()
            .unwrap()
            .0
            .get_mut("document")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "rk_epoch".to_string(),
                serde_json::Value::Number(serde_json::Number::from(2)),
            );
    }
    let err = collection
        .update_from_client(
            wrong_epoch_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_epoch_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
    ));

    let mut unsigned_payload =
        client_payload(&collection_crypto_id, "1", "tenant-a/client-rk-2026-04");
    let unsigned_marker_for_provenance =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(unsigned_payload.clone()),
            }]),
        ));
    let unsigned_provenance = runtime_verified_client_envelopes_for_operation(
        &unsigned_marker_for_provenance,
        &collection_crypto_id,
        &public_key,
    );
    unsigned_payload
        .0
        .get_mut("document")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("signature");
    let unsigned_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(unsigned_payload),
            }]),
        ));
    let err = collection
        .update_from_client(
            unsigned_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            unsigned_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
    ));

    let mut signature_tamper_marker =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let signature_tamper_provenance = runtime_verified_client_envelopes_for_operation(
        &signature_tamper_marker,
        &collection_crypto_id,
        &public_key,
    );
    if let CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::PointsList(points),
    )) = &mut signature_tamper_marker
    {
        let signature_value = points[0]
            .payload
            .as_mut()
            .unwrap()
            .0
            .get_mut("document")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("body")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("signature")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("sig")
            .unwrap();
        let serde_json::Value::String(signature) = signature_value else {
            panic!("client signature fixture must contain string sig");
        };
        let replacement = if signature.starts_with('A') { "B" } else { "A" };
        signature.replace_range(0..1, replacement);
    }
    let err = collection
        .update_from_client(
            signature_tamper_marker,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            signature_tamper_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("requires runtime envelope verification")
    ));

    let replay_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![
            PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "1",
                    "tenant-a/client-rk-2026-04",
                )),
            },
            PointStructPersisted {
                id: 2.into(),
                vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "2",
                    "tenant-a/client-rk-2026-04",
                )),
            },
        ]),
    ));
    let err = collection
        .update_from_client(
            replay_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &replay_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("client encrypted payload marker")
                && description.contains("nonce was already used")
    ));

    let valid_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(client_payload(
                &collection_crypto_id,
                "1",
                "tenant-a/client-rk-2026-04",
            )),
        }]),
    ));
    collection
        .update_from_client(
            valid_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &valid_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap();

    let replay_after_valid =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 3.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 0.0]),
                payload: Some(client_payload(
                    &collection_crypto_id,
                    "3",
                    "tenant-a/client-rk-2026-04",
                )),
            }]),
        ));
    let err = collection
        .update_from_client(
            replay_after_valid.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &replay_after_valid,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("nonce was already used in this collection")
    ));

    let assert_raw_client_body = |payload: &Payload| {
        let body = payload
            .0
            .get("document")
            .and_then(|document| document.get("body"))
            .unwrap();
        assert!(is_client_encrypted_payload_value(body));
        assert!(!is_encrypted_payload_value(body));
    };

    let retrieved = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_raw_client_body(retrieved[0].payload.as_ref().unwrap());

    let scrolled = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(scrolled.points.len(), 1);
    assert_raw_client_body(scrolled.points[0].payload.as_ref().unwrap());

    let searched = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(searched.len(), 1);
    assert_raw_client_body(searched[0].payload.as_ref().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn client_encrypted_payload_nonce_replay_survives_collection_reload() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection_path = collection_dir.path().to_path_buf();
    let snapshot_path = collection_path.join("snapshots");
    let collection =
        encrypted_collection_fixture(&collection_path, 1, client_payload_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();

    let client_payload = |point_id: &str| {
        let mut payload = Payload(
            serde_json::json!({
                "document": {
                    "body": {
                        CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                            "version": 1,
                            "kind": "payload_text",
                            "algorithm": "AES-256-GCM",
                            "key_id": "tenant-a/client-rk-2026-04",
                            "rk_id": "tenant-a/client-rk-2026-04",
                            "rk_epoch": 3,
                            "kdf_domain": "qdrant-sec/client-payload-text/v1",
                            "aad": {
                                "collection_id": collection_crypto_id,
                                "point_id": point_id,
                                "field_path": "document.body",
                                "schema_version": 1
                            },
                            "nonce": "AAAAAAAAAAAAAAAA",
                            "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                            "signature": {
                                "alg": "ed25519",
                                "key_id": "tenant-a/client-signing-v1",
                                "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            }
                        }
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        sign_client_payload(&mut payload, &key_pair);
        payload
    };

    let valid_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(client_payload("1")),
        }]),
    ));
    collection
        .update_from_client(
            valid_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &valid_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap();

    collection.stop_gracefully().await;
    drop(collection);

    let collection =
        load_local_collection("test".to_string(), &collection_path, &snapshot_path).await;
    let replay_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 2.into(),
            vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
            payload: Some(client_payload("2")),
        }]),
    ));
    let err = collection
        .update_from_client(
            replay_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &replay_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("nonce was already used in this collection")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_encrypted_payload_nonce_replay_cache_backfills_from_stored_payloads() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection_path = collection_dir.path().to_path_buf();
    let snapshot_path = collection_path.join("snapshots");
    let collection =
        encrypted_collection_fixture(&collection_path, 1, client_payload_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();

    let client_payload = |point_id: &str| {
        let mut payload = Payload(
            serde_json::json!({
                "document": {
                    "body": {
                        CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                            "version": 1,
                            "kind": "payload_text",
                            "algorithm": "AES-256-GCM",
                            "key_id": "tenant-a/client-rk-2026-04",
                            "rk_id": "tenant-a/client-rk-2026-04",
                            "rk_epoch": 3,
                            "kdf_domain": "qdrant-sec/client-payload-text/v1",
                            "aad": {
                                "collection_id": collection_crypto_id,
                                "point_id": point_id,
                                "field_path": "document.body",
                                "schema_version": 1
                            },
                            "nonce": "AAAAAAAAAAAAAAAA",
                            "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
                            "signature": {
                                "alg": "ed25519",
                                "key_id": "tenant-a/client-signing-v1",
                                "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            }
                        }
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        sign_client_payload(&mut payload, &key_pair);
        payload
    };

    let valid_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 1.into(),
            vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
            payload: Some(client_payload("1")),
        }]),
    ));
    collection
        .update_from_client(
            valid_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &valid_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap();

    collection.stop_gracefully().await;
    drop(collection);
    fs::remove_file(collection_path.join("client_payload_nonce_replay.cache")).unwrap();

    let collection =
        load_local_collection("test".to_string(), &collection_path, &snapshot_path).await;
    let replay_marker = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(vec![PointStructPersisted {
            id: 2.into(),
            vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
            payload: Some(client_payload("2")),
        }]),
    ));
    let err = collection
        .update_from_client(
            replay_marker.clone(),
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            runtime_verified_client_envelopes_for_operation(
                &replay_marker,
                &collection_crypto_id,
                &public_key,
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("nonce was already used in this collection")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_payload_marker_upsert_does_not_leak_plaintext_to_collection_files() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection_path = collection_dir.path().to_path_buf();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, payload_encryption_config()).await;
    let sentinel = "qdrant-sec-plaintext-sentinel-9f74dcb5";
    let mut encrypted_payload = Payload(
        serde_json::json!({ "document": { "body": sentinel } })
            .as_object()
            .unwrap()
            .clone(),
    );
    let metadata_key = SecretKey::from_bytes([31u8; 32])
        .derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)
        .unwrap();
    let encryptor = PayloadTextEncryptor::new_with_derived_cipher_unchecked(
        "test",
        AeadCipher::new_with_material_fingerprint(
            "tenant-a:docs",
            metadata_key,
            "tenant-a/docs@v1",
        )
        .unwrap(),
    )
    .unwrap();
    let policy = PayloadEncryptionPolicy::new(vec!["document.body".to_string()]).unwrap();
    assert_eq!(
        encryptor
            .encrypt_selected_fields("1", &mut encrypted_payload.0, &policy)
            .unwrap(),
        1,
    );

    let encrypted_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![1.0, 0.0, 0.0, 0.0]),
                payload: Some(encrypted_payload),
            }]),
        ));
    collection
        .update_from_client(
            encrypted_upsert,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            CollectionUpdateProvenance::runtime_encrypted_payloads(),
        )
        .await
        .unwrap();

    let retrieved = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    let retrieved_payload = retrieved[0].payload.as_ref().unwrap();
    let assert_raw_encrypted_body = |payload: &Payload| {
        let body = payload
            .0
            .get("document")
            .and_then(|document| document.get("body"))
            .unwrap();
        assert!(is_encrypted_payload_value(body));
        assert_ne!(body, &serde_json::json!(sentinel));
    };
    assert_raw_encrypted_body(retrieved_payload);

    let scrolled = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(scrolled.points.len(), 1);
    assert_raw_encrypted_body(scrolled.points[0].payload.as_ref().unwrap());

    let searched = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: Some(WithPayloadInterface::Bool(true)),
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();
    assert_eq!(searched.len(), 1);
    assert_raw_encrypted_body(searched[0].payload.as_ref().unwrap());

    let telemetry = collection
        .get_telemetry_data(
            TelemetryDetail::new(DetailsLevel::Level4, true),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
    let telemetry_bytes = serde_json::to_vec(&telemetry).unwrap();
    assert!(
        !telemetry_bytes
            .windows(sentinel.as_bytes().len())
            .any(|window| window == sentinel.as_bytes()),
        "plaintext sentinel leaked into collection telemetry",
    );

    let snapshot_temp_dir = Builder::new().prefix("snapshot-temp").tempdir().unwrap();
    let snapshot = collection
        .create_snapshot(snapshot_temp_dir.path(), 0)
        .await
        .unwrap();
    let snapshot_path = collection_path.join("snapshots").join(&snapshot.name);
    assert!(snapshot_path.exists());

    collection.stop_gracefully().await;

    let sentinel = sentinel.as_bytes();
    let mut pending = vec![collection_path];
    while let Some(path) = pending.pop() {
        let metadata = fs::metadata(&path).unwrap();
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).unwrap() {
                pending.push(entry.unwrap().path());
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }

        let bytes = fs::read(&path).unwrap();
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel),
            "plaintext sentinel leaked into {}",
            path.display(),
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_rejects_plaintext_vector_writes() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection_path = collection_dir.path().to_path_buf();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;
    let vector_sentinel = [12345.125_f32, -23456.25, 34567.5, -45678.75];
    let vector_sentinel_f32_bytes: Vec<u8> = vector_sentinel
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    let vector_sentinel_f64_bytes: Vec<u8> = vector_sentinel
        .iter()
        .flat_map(|value| (*value as f64).to_le_bytes())
        .collect();

    let plaintext_upsert =
        CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::from(vec![PointStructPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vector_sentinel.to_vec()),
                payload: None,
            }]),
        ));
    let err = collection
        .update_from_client_simple(
            plaintext_upsert,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector")
                && description.contains("ciphertext storage/write path is not implemented")
    ));

    let plaintext_sync = CollectionUpdateOperations::PointOperation(PointOperations::SyncPoints(
        PointSyncOperation {
            from_id: None,
            to_id: None,
            points: vec![PointStructPersisted {
                id: 2.into(),
                vector: VectorStructPersisted::from(vec![0.0, 0.0, 1.0, 0.0]),
                payload: None,
            }],
        },
    ));
    let err = collection
        .update_from_client_simple(
            plaintext_sync,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector")
                && description.contains("ciphertext storage/write path is not implemented")
    ));

    let plaintext_vector_update = CollectionUpdateOperations::VectorOperation(
        VectorOperations::UpdateVectors(UpdateVectorsOp {
            points: vec![PointVectorsPersisted {
                id: 1.into(),
                vector: VectorStructPersisted::from(vec![0.0, 1.0, 0.0, 0.0]),
            }],
            update_filter: None,
        }),
    );
    let err = collection
        .update_from_client_simple(
            plaintext_vector_update,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector")
                && description.contains("ciphertext storage/write path is not implemented")
    ));

    let delete_vector =
        CollectionUpdateOperations::VectorOperation(VectorOperations::DeleteVectors(
            vec![1.into()].into(),
            vec![DEFAULT_VECTOR_NAME.to_string()],
        ));
    let err = collection
        .update_from_client_simple(
            delete_vector,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector")
                && description.contains("ciphertext storage/write path is not implemented")
    ));

    let delete_vector_by_filter =
        CollectionUpdateOperations::VectorOperation(VectorOperations::DeleteVectorsByFilter(
            Filter::default(),
            vec![DEFAULT_VECTOR_NAME.to_string()],
        ));
    let err = collection
        .update_from_client_simple(
            delete_vector_by_filter,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector")
                && description.contains("ciphertext storage/write path is not implemented")
    ));

    let has_encrypted_vector_filter = Filter::new_must(Condition::HasVector(
        HasVectorCondition::from(DEFAULT_VECTOR_NAME.to_string()),
    ));
    let delete_points_by_filter = CollectionUpdateOperations::PointOperation(
        PointOperations::DeletePointsByFilter(has_encrypted_vector_filter),
    );
    let err = collection
        .update_from_client_simple(
            delete_points_by_filter,
            true,
            None,
            WriteOrdering::default(),
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted vector")
                && description.contains("CKKS-native vector search is not implemented")
    ));

    collection.stop_gracefully().await;

    let mut pending = vec![collection_path];
    while let Some(path) = pending.pop() {
        let metadata = fs::metadata(&path).unwrap();
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).unwrap() {
                pending.push(entry.unwrap().path());
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }

        let bytes = fs::read(&path).unwrap();
        for pattern in [
            vector_sentinel_f32_bytes.as_slice(),
            vector_sentinel_f64_bytes.as_slice(),
        ] {
            assert!(
                !bytes.windows(pattern.len()).any(|window| window == pattern),
                "plaintext vector sentinel leaked into {}",
                path.display(),
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_sidecar_requires_matching_runtime_metadata() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;
    let collection_crypto_id = collection.config_snapshot().await.uuid.unwrap().to_string();

    let vector_sidecar = |vector_name: &str,
                          key_id: &str,
                          nonce: serde_json::Value,
                          ciphertext: serde_json::Value| {
        let mut sidecar = Map::new();
        sidecar.insert(
            vector_name.to_string(),
            serde_json::json!({
                ENCRYPTED_CKKS_VECTOR_MARKER: {
                    "version": 1,
                    "scheme": "openfhe-ckks",
                    "envelope": {
                        "version": 1,
                        "algorithm": "AES-256-GCM",
                        "key_id": key_id,
                        "material_fingerprint": "tenant-a/vector@v1",
                        "nonce": nonce,
                        "ciphertext": ciphertext,
                    },
                },
            }),
        );
        let mut payload = Map::new();
        payload.insert(
            ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
            serde_json::Value::Object(sidecar),
        );
        Payload(payload)
    };
    let valid_nonce = || serde_json::Value::String(BASE64URL_NOPAD.encode(&[1u8; 12]));
    let valid_ciphertext = || serde_json::Value::String(BASE64URL_NOPAD.encode(&[2u8; 16]));
    let vector_sidecar_provenance = |payload: &Payload, vector_name: &str| {
        let sidecar_value = payload
            .0
            .get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            .and_then(|sidecar| sidecar.as_object())
            .and_then(|sidecar| sidecar.get(vector_name))
            .unwrap();
        CollectionUpdateProvenance::runtime_encrypted_vectors(vec![
            ckks_vector_verified_sidecar_key(
                sidecar_value,
                &collection_crypto_id,
                "1",
                vector_name,
            )
            .unwrap(),
        ])
    };

    let wrong_key_payload = vector_sidecar(
        DEFAULT_VECTOR_NAME,
        "tenant-a:wrong",
        valid_nonce(),
        valid_ciphertext(),
    );
    let wrong_key_provenance = vector_sidecar_provenance(&wrong_key_payload, DEFAULT_VECTOR_NAME);
    let wrong_key_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: wrong_key_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            wrong_key_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_key_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("key id does not match")
    ));

    let unconfigured_payload =
        vector_sidecar("other", "tenant-a:docs", valid_nonce(), valid_ciphertext());
    let unconfigured_provenance = vector_sidecar_provenance(&unconfigured_payload, "other");
    let unconfigured_vector_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: unconfigured_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            unconfigured_vector_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            unconfigured_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry 'other'")
                && description.contains("not configured")
    ));

    let malformed_nonce_payload = vector_sidecar(
        DEFAULT_VECTOR_NAME,
        "tenant-a:docs",
        serde_json::Value::String("not-base64url".to_string()),
        valid_ciphertext(),
    );
    let malformed_nonce_provenance =
        vector_sidecar_provenance(&malformed_nonce_payload, DEFAULT_VECTOR_NAME);
    let malformed_nonce_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: malformed_nonce_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            malformed_nonce_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            malformed_nonce_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("nonce")
    ));

    let mut tampered_payload = vector_sidecar(
        DEFAULT_VECTOR_NAME,
        "tenant-a:docs",
        valid_nonce(),
        valid_ciphertext(),
    );
    let tampered_provenance = vector_sidecar_provenance(&tampered_payload, DEFAULT_VECTOR_NAME);
    let sidecar_entry = tampered_payload
        .0
        .get_mut(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        .and_then(|sidecar| sidecar.as_object_mut())
        .and_then(|sidecar| sidecar.get_mut(DEFAULT_VECTOR_NAME))
        .and_then(|entry| entry.as_object_mut())
        .and_then(|entry| entry.get_mut(ENCRYPTED_CKKS_VECTOR_MARKER))
        .and_then(|marker| marker.as_object_mut())
        .and_then(|marker| marker.get_mut("envelope"))
        .and_then(|envelope| envelope.as_object_mut())
        .unwrap();
    sidecar_entry.insert(
        "ciphertext".to_string(),
        serde_json::Value::String(BASE64URL_NOPAD.encode(&[3u8; 16])),
    );
    let tampered_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: tampered_payload,
            points: Some(vec![1.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            tampered_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            tampered_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("requires runtime vector encryption")
    ));

    let wrong_point_payload = vector_sidecar(
        DEFAULT_VECTOR_NAME,
        "tenant-a:docs",
        valid_nonce(),
        valid_ciphertext(),
    );
    let wrong_point_provenance =
        vector_sidecar_provenance(&wrong_point_payload, DEFAULT_VECTOR_NAME);
    let wrong_point_sidecar =
        CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
            payload: wrong_point_payload,
            points: Some(vec![2.into()]),
            filter: None,
            key: None,
        }));
    let err = collection
        .update_from_client(
            wrong_point_sidecar,
            true.into(),
            None,
            WriteOrdering::default(),
            None,
            HwMeasurementAcc::new(),
            wrong_point_provenance,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector sidecar entry")
                && description.contains("requires runtime vector encryption")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_rejects_plaintext_vector_reads() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;

    let err = collection
        .retrieve(
            PointRequestInternal {
                ids: vec![1.into()],
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: WithVector::Bool(true),
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot return encrypted vector")
                && description.contains("ciphertext read path is not implemented")
    ));

    let err = collection
        .scroll_by(
            ScrollRequestInternal {
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: WithVector::Selector(vec![DEFAULT_VECTOR_NAME.to_string()]),
                ..ScrollRequestInternal::default()
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot return encrypted vector")
                && description.contains("ciphertext read path is not implemented")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_vector_rejects_search_path() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection =
        encrypted_collection_fixture(collection_dir.path(), 1, vector_encryption_config()).await;

    let err = collection
        .search(
            SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                with_payload: None,
                with_vector: None,
                filter: None,
                params: None,
                limit: 1,
                offset: None,
                score_threshold: None,
            }
            .into(),
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot search encrypted vector")
                && description.contains("CKKS-native vector search is not implemented")
    ));

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![],
                    query: Some(Query::Vector(VectorQuery::Nearest(
                        VectorInputInternal::Vector(VectorInternal::from(vec![1.0, 0.0, 0.0, 0.0])),
                    ))),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot query encrypted vector")
                && description.contains("CKKS-native vector search is not implemented")
    ));

    let err = collection
        .query_batch(
            vec![(
                CollectionQueryRequest {
                    prefetch: vec![CollectionPrefetch {
                        prefetch: vec![CollectionPrefetch {
                            prefetch: vec![],
                            query: Some(Query::Vector(VectorQuery::Nearest(
                                VectorInputInternal::Vector(VectorInternal::from(vec![
                                    1.0, 0.0, 0.0, 0.0,
                                ])),
                            ))),
                            using: DEFAULT_VECTOR_NAME.to_string(),
                            filter: None,
                            score_threshold: None,
                            limit: 1,
                            params: None,
                            lookup_from: None,
                        }],
                        query: Some(Query::Sample(SampleInternal::Random)),
                        using: DEFAULT_VECTOR_NAME.to_string(),
                        filter: None,
                        score_threshold: None,
                        limit: 1,
                        params: None,
                        lookup_from: None,
                    }],
                    query: Some(Query::Fusion(FusionInternal::Dbsf)),
                    using: DEFAULT_VECTOR_NAME.to_string(),
                    filter: None,
                    score_threshold: None,
                    limit: 1,
                    offset: 0,
                    params: None,
                    with_vector: WithVector::Bool(false),
                    with_payload: WithPayloadInterface::Bool(false),
                    lookup_from: None,
                },
                ShardSelectorInternal::All,
            )],
            |_name| async { None },
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot query encrypted vector")
                && description.contains("CKKS-native vector search is not implemented")
    ));

    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Search(SearchRequestInternal {
                vector: vec![1.0, 0.0, 0.0, 0.0].into(),
                filter: None,
                params: None,
                limit: 1,
                offset: Some(0),
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: Some(WithVector::Bool(false)),
                score_threshold: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector")
                && description.contains("CKKS-native vector search is not implemented")
    ));

    let err = GroupBy::new(
        GroupRequest {
            source: SourceRequest::Query(CollectionQueryRequest {
                prefetch: vec![],
                query: Some(Query::Vector(VectorQuery::Nearest(
                    VectorInputInternal::Vector(VectorInternal::from(vec![1.0, 0.0, 0.0, 0.0])),
                ))),
                using: DEFAULT_VECTOR_NAME.to_string(),
                filter: None,
                score_threshold: None,
                limit: 1,
                offset: 0,
                params: None,
                with_vector: WithVector::Bool(false),
                with_payload: WithPayloadInterface::Bool(false),
                lookup_from: None,
            }),
            group_by: "group".parse().unwrap(),
            group_size: 1,
            limit: 1,
            with_lookup: None,
        },
        &collection,
        |_name| async { None },
        HwMeasurementAcc::new(),
    )
    .execute()
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("encrypted vector")
                && description.contains("CKKS-native vector search is not implemented")
    ));

    let err = recommend_by(
        RecommendRequestInternal {
            positive: vec![RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])],
            limit: 1,
            ..Default::default()
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot search encrypted vector")
                && description.contains("CKKS-native vector search is not implemented")
    ));

    let err = discover(
        DiscoverRequestInternal {
            target: Some(RecommendExample::Dense(vec![1.0, 0.0, 0.0, 0.0])),
            context: None,
            filter: None,
            params: None,
            limit: 1,
            offset: None,
            with_payload: None,
            with_vector: None,
            using: None,
            lookup_from: None,
        },
        &collection,
        |_name| async { None },
        None,
        ShardSelectorInternal::All,
        None,
        HwMeasurementAcc::new(),
    )
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot search encrypted vector")
                && description.contains("CKKS-native vector search is not implemented")
    ));

    let err = collection
        .search_points_matrix(
            CollectionSearchMatrixRequest {
                sample_size: 2,
                limit_per_sample: 1,
                filter: None,
                using: DEFAULT_VECTOR_NAME.to_string(),
            },
            ShardSelectorInternal::All,
            None,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("cannot filter on encrypted vector")
                && description.contains("CKKS-native vector search is not implemented")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn collection_params_diff_rejects_crypto_mutation() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();
    let collection = simple_collection_fixture(collection_dir.path(), 1).await;

    let err = collection
        .update_params_from_diff(CollectionParamsDiff {
            replication_factor: None,
            write_consistency_factor: None,
            read_fan_out_factor: None,
            read_fan_out_delay_ms: None,
            on_disk_payload: None,
            encryption: Some(payload_encryption_config()),
            ckks: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("crypto migration")
                && description.contains("params diff")
    ));

    let err = collection
        .update_params_from_diff(CollectionParamsDiff {
            replication_factor: None,
            write_consistency_factor: None,
            read_fan_out_factor: None,
            read_fan_out_delay_ms: None,
            on_disk_payload: None,
            encryption: None,
            ckks: Some(CkksCollectionConfig {
                enabled: true,
                key_id: Some("tenant-a:docs".to_string()),
                payload_text_fields: vec!["document.body".to_string()],
                vector_names: Vec::new(),
            }),
        })
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        CollectionError::BadInput { description }
            if description.contains("crypto migration")
                && description.contains("params diff")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_delete_points_by_filter() {
    test_collection_delete_points_by_filter_with_shards(1).await;
    test_collection_delete_points_by_filter_with_shards(N_SHARDS).await;
}

async fn test_collection_delete_points_by_filter_with_shards(shard_number: u32) {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    let collection = simple_collection_fixture(collection_dir.path(), shard_number).await;

    let batch = BatchPersisted {
        ids: vec![0, 1, 2, 3, 4]
            .into_iter()
            .map(|x| x.into())
            .collect_vec(),
        vectors: BatchVectorStructPersisted::Single(vec![
            vec![1.0, 0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
            vec![1.0, 1.0, 1.0, 1.0],
            vec![1.0, 1.0, 0.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
        ]),
        payloads: None,
    };

    let insert_points = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
        PointInsertOperationsInternal::from(batch),
    ));

    let hw_counter = HwMeasurementAcc::new();
    let insert_result = collection
        .update_from_client_simple(
            insert_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter.clone(),
        )
        .await;

    match insert_result {
        Ok(res) => {
            assert_eq!(res.status, UpdateStatus::Completed)
        }
        Err(err) => panic!("operation failed: {err:?}"),
    }

    // delete points with id (0, 3)
    let to_be_deleted: AHashSet<PointIdType> = vec![0.into(), 3.into()].into_iter().collect();
    let delete_filter =
        segment::types::Filter::new_must(Condition::HasId(HasIdCondition::from(to_be_deleted)));

    let delete_points = CollectionUpdateOperations::PointOperation(
        PointOperations::DeletePointsByFilter(delete_filter),
    );

    let delete_result = collection
        .update_from_client_simple(
            delete_points,
            true,
            None,
            WriteOrdering::default(),
            hw_counter,
        )
        .await;

    match delete_result {
        Ok(res) => {
            assert_eq!(res.status, UpdateStatus::Completed)
        }
        Err(err) => panic!("operation failed: {err:?}"),
    }

    let result = collection
        .scroll_by(
            ScrollRequestInternal {
                offset: None,
                limit: Some(10),
                filter: None,
                with_payload: Some(WithPayloadInterface::Bool(false)),
                with_vector: false.into(),
                order_by: None,
            },
            None,
            &ShardSelectorInternal::All,
            None,
            HwMeasurementAcc::new(),
        )
        .await
        .unwrap();

    // check if we only have 3 out of 5 points left and that the point id were really deleted
    assert_eq!(result.points.len(), 3);
    assert_eq!(result.points.first().unwrap().id, 1.into());
    assert_eq!(result.points.get(1).unwrap().id, 2.into());
    assert_eq!(result.points.get(2).unwrap().id, 4.into());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_collection_local_load_initializing_not_stuck() {
    let collection_dir = Builder::new().prefix("collection").tempdir().unwrap();

    // Create and unload collection
    simple_collection_fixture(collection_dir.path(), 1)
        .await
        .stop_gracefully()
        .await;

    // Modify replica state file on disk, set state to Initializing
    // This is to simulate a situation where a collection was not fully created, we cannot create
    // this situation through our collection interface
    {
        let replica_state_path = collection_dir.path().join("0/replica_state.json");
        let replica_state_file = BufReader::new(File::open(&replica_state_path).unwrap());
        let mut replica_set_state: ReplicaSetState =
            serde_json::from_reader(replica_state_file).unwrap();

        for peer_id in replica_set_state.peers().clone().into_keys() {
            replica_set_state.set_peer_state(peer_id, ReplicaState::Initializing);
        }

        let replica_state_file = BufWriter::new(File::create(&replica_state_path).unwrap());
        serde_json::to_writer(replica_state_file, &replica_set_state).unwrap();
    }

    // Reload collection
    let collection_path = collection_dir.path();
    let loaded_collection = load_local_collection(
        "test".to_string(),
        collection_path,
        &collection_path.join("snapshots"),
    )
    .await;

    // Local replica must be in Active state after loading (all replicas are local)
    let loaded_state = loaded_collection.state().await;
    for shard_info in loaded_state.shards.values() {
        for replica_state in shard_info.replicas.values() {
            assert_eq!(replica_state, &ReplicaState::Active);
        }
    }
}
