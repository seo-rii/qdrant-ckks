use std::cell::RefCell;
use std::hint::black_box;
use std::sync::Arc;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use qdrant_sec::{
    DistanceKind, PrivateHnswBucketAeadBaseContext, PrivateHnswBuildPoint, PrivateHnswClientError,
    PrivateHnswClientKeys, PrivateHnswClientNodeCache, PrivateHnswNodeBlockPlaintext,
    PrivateHnswOramBucket, PrivateHnswOramClientConfig, PrivateHnswOramClientState,
    PrivateHnswOramPlaintextBucket, PrivateHnswSearchAccessMetrics, PrivateHnswSearchParams,
    SecretKey, build_private_hnsw_oram_plaintext_index_from_f32_points,
    build_private_hnsw_oram_plaintext_index_from_layered_f32_points,
    plan_private_hnsw_oram_directional_neighbor_filter,
    plan_private_hnsw_oram_graph_traversal_path_batch_with_stats,
    plan_private_hnsw_oram_neighbor_clustered_leaves, plan_private_hnsw_oram_speculative_prefetch,
    private_hnsw_oram_bucket_ids_for_leaf, private_hnsw_oram_leaf_count,
    sample_private_hnsw_oram_leaf, seal_private_hnsw_oram_plaintext_index,
    search_private_hnsw_oram_encrypted, search_private_hnsw_oram_plaintext,
    search_private_hnsw_oram_plaintext_with_cache,
};

const POINT_COUNT: usize = 64;
const DIM: usize = 32;
const NEIGHBORS: usize = 8;
const FIXED_STEPS: usize = 32;
const INDEX_EPOCH: u64 = 42;
const WRITEBACK_EPOCH: u64 = 43;

#[derive(Clone)]
struct PlaintextSearchFixture {
    config: PrivateHnswOramClientConfig,
    state: PrivateHnswOramClientState,
    buckets: Vec<PrivateHnswOramPlaintextBucket>,
    query: Vec<f32>,
    params: PrivateHnswSearchParams,
    cache: Option<PrivateHnswClientNodeCache>,
}

impl PlaintextSearchFixture {
    fn new() -> Self {
        let config = bench_config();
        let points = build_points();
        let leaves = build_leaves(config, points.len());
        let build = build_private_hnsw_oram_plaintext_index_from_f32_points(
            config,
            DistanceKind::Euclid,
            NEIGHBORS,
            &points,
            &leaves,
        )
        .unwrap();
        let query = deterministic_vector(7, DIM);
        let params = PrivateHnswSearchParams {
            entry_node_id: build.entry_node_id,
            k: 10,
            ef: 16,
            fixed_steps: FIXED_STEPS,
            distance: DistanceKind::Euclid,
            padding_node_id: Some(build.entry_node_id),
        };

        Self {
            config,
            state: build.state,
            buckets: build.buckets,
            query,
            params,
            cache: None,
        }
    }

    fn new_with_upper_layer_cache() -> Self {
        let config = bench_config();
        let points = build_points();
        let leaves = build_leaves(config, points.len());
        let levels = build_levels(points.len());
        let build = build_private_hnsw_oram_plaintext_index_from_layered_f32_points(
            config,
            DistanceKind::Euclid,
            NEIGHBORS,
            4,
            &points,
            &levels,
            &leaves,
        )
        .unwrap();
        let mut cache = PrivateHnswClientNodeCache::new();
        let cached_nodes = cache.extend_upper_layers_from_plaintext_build(&build, 1);
        assert!(cached_nodes > 0);
        let query = deterministic_vector(7, DIM);
        let params = PrivateHnswSearchParams {
            entry_node_id: build.entry_node_id,
            k: 10,
            ef: 16,
            fixed_steps: FIXED_STEPS,
            distance: DistanceKind::Euclid,
            padding_node_id: Some(build.entry_node_id),
        };

        Self {
            config,
            state: build.state,
            buckets: build.buckets,
            query,
            params,
            cache: Some(cache),
        }
    }

    fn search_metrics(&mut self) -> PrivateHnswSearchAccessMetrics {
        let config = self.config;
        let query = self.query.clone();
        let params = self.params;
        let cache = self.cache.clone();
        let store = RefCell::new(self.buckets.clone());
        let result = if let Some(cache) = cache.as_ref() {
            search_private_hnsw_oram_plaintext_with_cache(
                &mut self.state,
                config,
                &query,
                params,
                cache,
                |leaf| {
                    private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                        .into_iter()
                        .map(|bucket_id| {
                            store
                                .borrow()
                                .get(bucket_id as usize)
                                .cloned()
                                .ok_or(PrivateHnswClientError::PathBucketMismatch)
                        })
                        .collect()
                },
                |writeback_buckets| {
                    let mut store_mut = store.borrow_mut();
                    for bucket in writeback_buckets {
                        let slot = store_mut
                            .get_mut(bucket.bucket_id as usize)
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)?;
                        *slot = bucket.clone();
                    }
                    Ok(())
                },
                || sample_private_hnsw_oram_leaf(config.tree_height),
            )
        } else {
            search_private_hnsw_oram_plaintext(
                &mut self.state,
                config,
                &query,
                params,
                |leaf| {
                    private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                        .into_iter()
                        .map(|bucket_id| {
                            store
                                .borrow()
                                .get(bucket_id as usize)
                                .cloned()
                                .ok_or(PrivateHnswClientError::PathBucketMismatch)
                        })
                        .collect()
                },
                |writeback_buckets| {
                    let mut store_mut = store.borrow_mut();
                    for bucket in writeback_buckets {
                        let slot = store_mut
                            .get_mut(bucket.bucket_id as usize)
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)?;
                        *slot = bucket.clone();
                    }
                    Ok(())
                },
                || sample_private_hnsw_oram_leaf(config.tree_height),
            )
        }
        .unwrap();
        let metrics = result.access_metrics(&params);
        assert_eq!(metrics.path_accesses, FIXED_STEPS);
        assert!(metrics.exhausted_fixed_budget);
        metrics
    }
}

#[derive(Clone)]
struct EncryptedSearchFixture {
    keys: Arc<PrivateHnswClientKeys>,
    base_context: PrivateHnswBucketAeadBaseContext<'static>,
    config: PrivateHnswOramClientConfig,
    state: PrivateHnswOramClientState,
    buckets: Vec<PrivateHnswOramBucket>,
    query: Vec<f32>,
    params: PrivateHnswSearchParams,
}

impl EncryptedSearchFixture {
    fn new() -> Self {
        let config = bench_config();
        let points = build_points();
        let leaves = build_leaves(config, points.len());
        let build = build_private_hnsw_oram_plaintext_index_from_f32_points(
            config,
            DistanceKind::Euclid,
            NEIGHBORS,
            &points,
            &leaves,
        )
        .unwrap();
        let keys = Arc::new(client_keys());
        let base_context = bucket_base_context();
        let encrypted_build = seal_private_hnsw_oram_plaintext_index(
            &keys,
            base_context,
            INDEX_EPOCH,
            &build,
            config,
        )
        .unwrap();
        let query = deterministic_vector(7, DIM);
        let params = PrivateHnswSearchParams {
            entry_node_id: build.entry_node_id,
            k: 10,
            ef: 16,
            fixed_steps: FIXED_STEPS,
            distance: DistanceKind::Euclid,
            padding_node_id: Some(build.entry_node_id),
        };

        Self {
            keys,
            base_context,
            config,
            state: build.state,
            buckets: encrypted_build.buckets,
            query,
            params,
        }
    }

    fn search_metrics(&mut self) -> PrivateHnswSearchAccessMetrics {
        let config = self.config;
        let query = self.query.clone();
        let params = self.params;
        let store = RefCell::new(self.buckets.clone());
        let result = search_private_hnsw_oram_encrypted(
            &self.keys,
            self.base_context,
            WRITEBACK_EPOCH,
            &mut self.state,
            config,
            &query,
            params,
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(bucket_id as usize)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = store.borrow_mut();
                for bucket in writeback_buckets {
                    let slot = store_mut
                        .get_mut(bucket.bucket_id as usize)
                        .ok_or(PrivateHnswClientError::PathBucketMismatch)?;
                    *slot = bucket.clone();
                }
                Ok(())
            },
            || sample_private_hnsw_oram_leaf(config.tree_height),
        )
        .unwrap();
        let metrics = result.access_metrics(&params);
        assert_eq!(metrics.path_accesses, FIXED_STEPS);
        assert!(metrics.exhausted_fixed_budget);
        metrics
    }
}

struct PlanningFixture {
    config: PrivateHnswOramClientConfig,
    state: PrivateHnswOramClientState,
    candidate_node_ids: Vec<[u8; 32]>,
    padding_leaf: u64,
    blocks: Vec<PrivateHnswNodeBlockPlaintext>,
    entry_node_id: [u8; 32],
    query: Vec<f32>,
}

impl PlanningFixture {
    fn new() -> Self {
        let config = bench_config();
        let points = build_points();
        let leaves = build_leaves(config, points.len());
        let levels = build_levels(points.len());
        let build = build_private_hnsw_oram_plaintext_index_from_layered_f32_points(
            config,
            DistanceKind::Euclid,
            NEIGHBORS,
            4,
            &points,
            &levels,
            &leaves,
        )
        .unwrap();
        let candidate_node_ids = points
            .iter()
            .cycle()
            .skip(3)
            .take(24)
            .map(|point| point.node_id)
            .collect();
        let blocks = build
            .buckets
            .iter()
            .flat_map(|bucket| bucket.blocks.iter().flatten().cloned())
            .collect();

        Self {
            config,
            state: build.state,
            candidate_node_ids,
            padding_leaf: 0,
            blocks,
            entry_node_id: build.entry_node_id,
            query: deterministic_vector(7, DIM),
        }
    }
}

fn bench_config() -> PrivateHnswOramClientConfig {
    PrivateHnswOramClientConfig {
        tree_height: 8,
        bucket_size: 4,
        block_size_bytes: 4096,
        fixed_neighbor_slots: 16,
    }
}

fn client_keys() -> PrivateHnswClientKeys {
    let resource_key = SecretKey::from_bytes([9; 32]);
    PrivateHnswClientKeys::derive_from_resource_key_with_context(
        &resource_key,
        "bench-collection",
        "text",
        "bench/vector-rk",
        7,
    )
    .unwrap()
}

fn bucket_base_context() -> PrivateHnswBucketAeadBaseContext<'static> {
    PrivateHnswBucketAeadBaseContext {
        collection_id: "bench-collection",
        vector_name: "text",
        key_id: "bench/vector-rk",
        rk_id: "bench/vector-rk",
        rk_epoch: 7,
    }
}

fn build_points() -> Vec<PrivateHnswBuildPoint> {
    (0..POINT_COUNT)
        .map(|index| PrivateHnswBuildPoint {
            node_id: id_from_u64(index as u64 + 1),
            point_token: id_from_u64(index as u64 + 10_000),
            vector: deterministic_vector(index, DIM),
            payload_fetch_token: None,
        })
        .collect()
}

fn build_leaves(config: PrivateHnswOramClientConfig, point_count: usize) -> Vec<u64> {
    let leaf_count = private_hnsw_oram_leaf_count(config.tree_height).unwrap();
    (0..point_count)
        .map(|index| ((index as u64 * 37) + 11) % leaf_count)
        .collect()
}

fn build_levels(point_count: usize) -> Vec<u8> {
    (0..point_count)
        .map(|index| {
            if index % 32 == 0 {
                2
            } else if index % 8 == 0 {
                1
            } else {
                0
            }
        })
        .collect()
}

fn deterministic_vector(index: usize, dim: usize) -> Vec<f32> {
    (0..dim)
        .map(|axis| {
            let raw = ((index * 31) + (axis * 17) + 13) % 127;
            (raw as f32 / 127.0) + (index as f32 * 0.0001)
        })
        .collect()
}

fn id_from_u64(value: u64) -> [u8; 32] {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&value.to_be_bytes());
    id
}

fn private_hnsw_oram_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("private-hnsw-oram");
    group.sample_size(30);

    let config = bench_config();
    let points = build_points();
    let leaves = build_leaves(config, points.len());
    group.bench_function("build-plaintext-index-64x32", |b| {
        b.iter(|| {
            build_private_hnsw_oram_plaintext_index_from_f32_points(
                black_box(config),
                DistanceKind::Euclid,
                black_box(NEIGHBORS),
                black_box(points.as_slice()),
                black_box(leaves.as_slice()),
            )
            .unwrap()
        })
    });

    let fixture = PlaintextSearchFixture::new();
    group.bench_function("search-plaintext-fixed-budget-64x32", |b| {
        b.iter_batched(
            || fixture.clone(),
            |mut fixture| black_box(fixture.search_metrics()),
            BatchSize::SmallInput,
        )
    });

    let cached_fixture = PlaintextSearchFixture::new_with_upper_layer_cache();
    group.bench_function("search-plaintext-cache-fixed-budget-64x32", |b| {
        b.iter_batched(
            || cached_fixture.clone(),
            |mut fixture| black_box(fixture.search_metrics()),
            BatchSize::SmallInput,
        )
    });

    let encrypted_fixture = EncryptedSearchFixture::new();
    group.bench_function("search-encrypted-fixed-budget-64x32", |b| {
        b.iter_batched(
            || encrypted_fixture.clone(),
            |mut fixture| black_box(fixture.search_metrics()),
            BatchSize::SmallInput,
        )
    });

    let planning_fixture = PlanningFixture::new();
    group.bench_function("plan-speculative-prefetch-16-of-64", |b| {
        b.iter(|| {
            black_box(
                plan_private_hnsw_oram_speculative_prefetch(
                    black_box(&planning_fixture.state),
                    black_box(planning_fixture.config),
                    black_box(planning_fixture.candidate_node_ids.as_slice()),
                    black_box(16),
                    black_box(planning_fixture.padding_leaf),
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("plan-neighbor-clustered-leaves-64", |b| {
        b.iter(|| {
            black_box(
                plan_private_hnsw_oram_neighbor_clustered_leaves(
                    black_box(planning_fixture.config),
                    black_box(planning_fixture.blocks.as_slice()),
                    black_box(planning_fixture.entry_node_id),
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("plan-directional-neighbor-filter-64x32", |b| {
        let current_block = planning_fixture
            .blocks
            .iter()
            .find(|block| block.node_id == planning_fixture.entry_node_id)
            .unwrap();
        b.iter(|| {
            black_box(
                plan_private_hnsw_oram_directional_neighbor_filter(
                    black_box(current_block),
                    black_box(planning_fixture.blocks.as_slice()),
                    black_box(planning_fixture.query.as_slice()),
                    black_box(DistanceKind::Euclid),
                    black_box(NEIGHBORS),
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("plan-graph-traversal-path-batch-64x32", |b| {
        let current_block = planning_fixture
            .blocks
            .iter()
            .find(|block| block.node_id == planning_fixture.entry_node_id)
            .unwrap();
        b.iter(|| {
            black_box(
                plan_private_hnsw_oram_graph_traversal_path_batch_with_stats(
                    black_box(&planning_fixture.state),
                    black_box(planning_fixture.config),
                    black_box(current_block),
                    black_box(planning_fixture.blocks.as_slice()),
                    black_box(planning_fixture.query.as_slice()),
                    black_box(DistanceKind::Euclid),
                    black_box(NEIGHBORS),
                    black_box(planning_fixture.padding_leaf),
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = private_hnsw_oram_bench,
}

criterion_main!(benches);
