use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU32;
use std::sync::Arc;

use ahash::AHashMap;
use common::budget::ResourceBudget;
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams, PRIVATE_HNSW_ORAM_BINDING,
    PrivateHnswBucketAeadBaseContext, PrivateHnswClientKeys, PrivateHnswOramManifest,
    PrivateHnswOramSignature, PrivateHnswParams, ResultPrivacyMode, SecretKey,
    VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, seal_private_hnsw_oram_bucket,
};
use segment::types::Distance;
use sha2::{Digest, Sha256};
use shard::snapshots::snapshot_data::SnapshotData;
use tempfile::Builder;
use uuid::Uuid;

use crate::collection::{Collection, RequestShardTransfer};
use crate::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams, CryptoMigrationState,
    EncryptionRuleRef, EncryptionSelector, WalConfig,
};
use crate::operations::shared_storage_config::SharedStorageConfig;
use crate::operations::types::{NodeType, VectorsConfig};
use crate::operations::vector_params_builder::VectorParamsBuilder;
use crate::private_hnsw_oram_store::{
    PRIVATE_HNSW_ORAM_DIR, PrivateHnswOramEpochState, PrivateHnswOramStore,
};
use crate::private_result_oram_store::PRIVATE_RESULT_ORAM_DIR;
use crate::shards::channel_service::ChannelService;
use crate::shards::collection_shard_distribution::CollectionShardDistribution;
use crate::shards::replica_set::{AbortShardTransfer, ChangePeerFromState};
use crate::tests::fixtures::TEST_OPTIMIZERS_CONFIG;

pub fn dummy_on_replica_failure() -> ChangePeerFromState {
    Arc::new(move |_peer_id, _shard_id, _from_state| {})
}

pub fn dummy_request_shard_transfer() -> RequestShardTransfer {
    Arc::new(move |_transfer| {})
}

pub fn dummy_abort_shard_transfer() -> AbortShardTransfer {
    Arc::new(|_transfer, _reason| {})
}

fn init_logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

async fn _test_snapshot_collection(node_type: NodeType) {
    let wal_config = WalConfig {
        wal_capacity_mb: 1,
        wal_segments_ahead: 0,
        wal_retain_closed: 1,
    };

    let collection_params = CollectionParams {
        vectors: VectorsConfig::Single(VectorParamsBuilder::new(4, Distance::Dot).build()),
        shard_number: NonZeroU32::new(4).unwrap(),
        replication_factor: NonZeroU32::new(3).unwrap(),
        write_consistency_factor: NonZeroU32::new(2).unwrap(),
        ..CollectionParams::empty()
    };

    let config = CollectionConfigInternal {
        params: collection_params,
        optimizer_config: TEST_OPTIMIZERS_CONFIG.clone(),
        wal_config,
        hnsw_config: Default::default(),
        quantization_config: Default::default(),
        strict_mode_config: Default::default(),
        uuid: None,
        metadata: None,
    };

    let snapshots_path = Builder::new().prefix("test_snapshots").tempdir().unwrap();
    let collection_dir = Builder::new().prefix("test_collection").tempdir().unwrap();

    let collection_name = "test".to_string();
    let collection_name_rec = "test_rec".to_string();
    let mut shards = AHashMap::new();
    shards.insert(0, HashSet::from([1]));
    shards.insert(1, HashSet::from([1]));
    shards.insert(2, HashSet::from([10_000])); // remote shard
    shards.insert(3, HashSet::from([1, 20_000, 30_000]));

    let storage_config: SharedStorageConfig = SharedStorageConfig {
        node_type,
        ..Default::default()
    };

    let collection = Collection::new(
        collection_name,
        1,
        collection_dir.path(),
        snapshots_path.path(),
        &config,
        Arc::new(storage_config),
        CollectionShardDistribution { shards },
        None,
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();

    let private_hnsw_plaintext_sentinel = b"qdrant-sec-private-hnsw-plaintext-sentinel";
    let private_hnsw_bucket = collection_dir
        .path()
        .join(PRIVATE_HNSW_ORAM_DIR)
        .join("text")
        .join("buckets")
        .join("00000000.bucket");
    std::fs::create_dir_all(private_hnsw_bucket.parent().unwrap()).unwrap();
    let keys =
        PrivateHnswClientKeys::derive_from_resource_key(&SecretKey::from_bytes([91; 32])).unwrap();
    let bucket = seal_private_hnsw_oram_bucket(
        &keys,
        PrivateHnswBucketAeadBaseContext {
            collection_id: "test-private-hnsw-collection",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
        }
        .for_bucket(0, 42),
        private_hnsw_plaintext_sentinel,
    )
    .unwrap();
    let bucket_json = serde_json::to_vec(&bucket).unwrap();
    assert!(!contains_bytes(
        &bucket_json,
        private_hnsw_plaintext_sentinel
    ));
    std::fs::write(&private_hnsw_bucket, &bucket_json).unwrap();

    let snapshots_temp_dir = Builder::new().prefix("temp_dir").tempdir().unwrap();
    let snapshot_description = collection
        .create_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap();

    assert_eq!(snapshot_description.checksum.unwrap().len(), 64);
    let snapshot_path = snapshots_path.path().join(&snapshot_description.name);
    let snapshot_bytes = std::fs::read(&snapshot_path).unwrap();
    assert!(contains_bytes(
        &snapshot_bytes,
        PRIVATE_HNSW_ORAM_DIR.as_bytes()
    ));
    assert!(!contains_bytes(
        &snapshot_bytes,
        private_hnsw_plaintext_sentinel
    ));

    {
        let recover_dir = Builder::new()
            .prefix("test_collection_rec")
            .tempdir()
            .unwrap();
        let snapshot_data = SnapshotData::new_packed_persistent(snapshot_path.clone());

        // Do not recover in local mode if some shards are remote
        assert!(
            Collection::restore_snapshot(snapshot_data, recover_dir.path(), 0, false,).is_err(),
        );
    }

    let recover_dir = Builder::new()
        .prefix("test_collection_rec")
        .tempdir()
        .unwrap();
    let snapshot_data = SnapshotData::new_packed_persistent(snapshot_path);
    if let Err(err) = Collection::restore_snapshot(snapshot_data, recover_dir.path(), 0, true) {
        panic!("Failed to restore snapshot: {err}")
    }
    assert_eq!(
        std::fs::read(
            recover_dir
                .path()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join("text")
                .join("buckets")
                .join("00000000.bucket"),
        )
        .unwrap(),
        bucket_json,
    );

    let recovered_collection = Collection::load(
        collection_name_rec,
        1,
        recover_dir.path(),
        snapshots_path.path(),
        Default::default(),
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();

    {
        let shards_holder = &recovered_collection.shards_holder.read().await;

        let replica_ser_0 = shards_holder.get_shard(0).unwrap();
        assert!(replica_ser_0.is_local().await);
        let replica_ser_1 = shards_holder.get_shard(1).unwrap();
        assert!(replica_ser_1.is_local().await);
        let replica_ser_2 = shards_holder.get_shard(2).unwrap();
        assert!(!replica_ser_2.is_local().await);
        assert_eq!(replica_ser_2.peers().len(), 1);

        let replica_ser_3 = shards_holder.get_shard(3).unwrap();

        assert!(replica_ser_3.is_local().await);
        assert_eq!(replica_ser_3.peers().len(), 3); // 2 remotes + 1 local
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_private_result_oram_is_included_but_restore_fails_closed() {
    init_logger();

    let config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorsConfig::Single(VectorParamsBuilder::new(4, Distance::Dot).build()),
            shard_number: NonZeroU32::new(1).unwrap(),
            replication_factor: NonZeroU32::new(1).unwrap(),
            write_consistency_factor: NonZeroU32::new(1).unwrap(),
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

    let snapshots_path = Builder::new()
        .prefix("test_result_oram_snapshots")
        .tempdir()
        .unwrap();
    let collection_dir = Builder::new()
        .prefix("test_result_oram_collection")
        .tempdir()
        .unwrap();
    let mut shards = AHashMap::new();
    shards.insert(0, HashSet::from([1]));

    let collection = Collection::new(
        "test_result_oram".to_string(),
        1,
        collection_dir.path(),
        snapshots_path.path(),
        &config,
        Arc::new(SharedStorageConfig::default()),
        CollectionShardDistribution { shards },
        None,
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();

    let private_result_plaintext_sentinel = b"qdrant-sec-private-result-oram-plaintext-sentinel";
    let result_bucket_path = collection_dir
        .path()
        .join(PRIVATE_RESULT_ORAM_DIR)
        .join("buckets")
        .join("00000000.bucket");
    std::fs::create_dir_all(result_bucket_path.parent().unwrap()).unwrap();
    let ciphertext = BASE64URL_NOPAD.encode(b"encrypted result bucket 0");
    let ciphertext_sha256 =
        BASE64URL_NOPAD.encode(Sha256::digest(b"encrypted result bucket 0").as_ref());
    let bucket_json = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "bucket_id": 0,
        "index_epoch": 42,
        "ciphertext": ciphertext,
        "ciphertext_sha256": ciphertext_sha256,
        "bucket_commitment": BASE64URL_NOPAD.encode(&[7; 32]),
    }))
    .unwrap();
    assert!(!contains_bytes(
        &bucket_json,
        private_result_plaintext_sentinel
    ));
    std::fs::write(&result_bucket_path, &bucket_json).unwrap();

    let snapshots_temp_dir = Builder::new().prefix("temp_dir").tempdir().unwrap();
    let snapshot_description = collection
        .create_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap();
    let snapshot_path = snapshots_path.path().join(&snapshot_description.name);
    let snapshot_bytes = std::fs::read(&snapshot_path).unwrap();
    assert!(contains_bytes(
        &snapshot_bytes,
        PRIVATE_RESULT_ORAM_DIR.as_bytes()
    ));
    assert!(!contains_bytes(
        &snapshot_bytes,
        private_result_plaintext_sentinel
    ));

    let recover_dir = Builder::new()
        .prefix("test_result_oram_collection_rec")
        .tempdir()
        .unwrap();
    let snapshot_data = SnapshotData::new_packed_persistent(snapshot_path);
    let err = Collection::restore_snapshot(snapshot_data, recover_dir.path(), 0, true).unwrap_err();
    let err = err.to_string();
    assert!(err.contains("payload/private-result-oram@v1"));
    assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
    assert!(!err.contains(recover_dir.path().to_string_lossy().as_ref()));
    assert!(!err.contains(PRIVATE_RESULT_ORAM_DIR));
    assert!(!err.contains(&ciphertext));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_private_hnsw_missing_bucket_fails_before_archive() {
    init_logger();

    let collection_uuid = Uuid::from_u128(7);
    let collection_name = "test_private_hnsw_snapshot".to_string();
    let vector_name = "text".to_string();
    let key_id = "tenant-a/vector-private-rk".to_string();
    let signing_key_id = "tenant-a/private-hnsw-signing-v1".to_string();
    let leaf_commitments = vec![
        BASE64URL_NOPAD.encode(&[7; 32]),
        BASE64URL_NOPAD.encode(&[8; 32]),
        BASE64URL_NOPAD.encode(&[9; 32]),
    ];
    let root_hash = PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
    let config = CollectionConfigInternal {
        params: CollectionParams {
            vectors: VectorsConfig::Multi(BTreeMap::from([(
                vector_name.clone(),
                VectorParamsBuilder::new(2, Distance::Euclid).build(),
            )])),
            shard_number: NonZeroU32::new(1).unwrap(),
            replication_factor: NonZeroU32::new(1).unwrap(),
            write_consistency_factor: NonZeroU32::new(1).unwrap(),
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some(key_id.clone()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "text_private_hnsw".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec![vector_name.clone()],
                    },
                    instance: "docs_private_hnsw_v1".to_string(),
                    binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                }],
            }),
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
        uuid: Some(collection_uuid),
        metadata: None,
    };
    let snapshots_path = Builder::new()
        .prefix("test_private_hnsw_missing_bucket_snapshots")
        .tempdir()
        .unwrap();
    let collection_dir = Builder::new()
        .prefix("test_private_hnsw_missing_bucket_collection")
        .tempdir()
        .unwrap();
    let mut shards = AHashMap::new();
    shards.insert(0, HashSet::from([1]));
    let collection = Collection::new(
        collection_name,
        1,
        collection_dir.path(),
        snapshots_path.path(),
        &config,
        Arc::new(SharedStorageConfig::default()),
        CollectionShardDistribution { shards },
        None,
        ChannelService::default(),
        dummy_on_replica_failure(),
        dummy_request_shard_transfer(),
        dummy_abort_shard_transfer(),
        None,
        None,
        ResourceBudget::default(),
        None,
    )
    .await
    .unwrap();
    let store = PrivateHnswOramStore::new(collection_dir.path(), &vector_name).unwrap();
    let manifest = PrivateHnswOramManifest {
        version: 1,
        provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
        binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
        collection_id: collection_uuid.to_string(),
        vector_name: vector_name.clone(),
        key_id: key_id.clone(),
        rk_id: key_id,
        rk_epoch: 7,
        dim: 2,
        distance: DistanceKind::Euclid,
        hnsw: PrivateHnswParams {
            m: 2,
            ef_construction: 4,
            max_layers: 2,
            fixed_neighbor_slots: 4,
        },
        oram: OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 512,
            tree_height: 1,
            path_batch_size: 1,
        },
        fixed_budget: FixedBudgetParams {
            enabled: true,
            upper_layer_steps: 1,
            base_layer_steps: 1,
            paths_per_round: 1,
            fixed_result_k: 1,
        },
        index_epoch: 42,
        root_hash: root_hash.clone(),
        bucket_count: 3,
        logical_node_count: 1,
        dummy_node_count: 2,
        result_privacy: ResultPrivacyMode::IdsVisible,
        owner_signing_key_id: signing_key_id.clone(),
        created_at_unix: 1,
    };
    store
        .write_manifest(
            &manifest,
            &PrivateHnswOramSignature {
                alg: "ed25519".to_string(),
                key_id: signing_key_id,
                sig: BASE64URL_NOPAD.encode(&[7; 64]),
            },
        )
        .unwrap();
    store
        .write_initial_epoch(&PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash,
        })
        .unwrap();
    store
        .write_merkle_tree_from_commitments(42, manifest.root_hash.clone(), leaf_commitments)
        .unwrap();

    let snapshots_temp_dir = Builder::new().prefix("temp_dir").tempdir().unwrap();
    let err = collection
        .create_snapshot(snapshots_temp_dir.path(), 0)
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("private HNSW ORAM snapshot layout validation failed"));
    assert!(!err.contains(collection_dir.path().to_string_lossy().as_ref()));
    assert!(!err.contains(PRIVATE_HNSW_ORAM_DIR));
    assert!(!err.contains("00000000.bucket"));
    assert!(!err.contains(&manifest.root_hash));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_collection_normal() {
    init_logger();
    _test_snapshot_collection(NodeType::Normal).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_snapshot_collection_listener() {
    init_logger();
    _test_snapshot_collection(NodeType::Listener).await;
}
