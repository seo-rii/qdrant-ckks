use std::cell::RefCell;
use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use qdrant_sec::{
    DistanceKind, PrivateHnswBuildPoint, PrivateHnswClientError, PrivateHnswOramClientConfig,
    PrivateHnswOramClientState, PrivateHnswOramPlaintextBucket, PrivateHnswSearchAccessMetrics,
    PrivateHnswSearchParams, build_private_hnsw_oram_plaintext_index_from_f32_points,
    private_hnsw_oram_bucket_ids_for_leaf, private_hnsw_oram_leaf_count,
    search_private_hnsw_oram_plaintext,
};

const POINT_COUNT: usize = 64;
const DIM: usize = 32;
const NEIGHBORS: usize = 8;
const FIXED_STEPS: usize = 32;

#[derive(Clone)]
struct PlaintextSearchFixture {
    config: PrivateHnswOramClientConfig,
    state: PrivateHnswOramClientState,
    buckets: Vec<PrivateHnswOramPlaintextBucket>,
    query: Vec<f32>,
    params: PrivateHnswSearchParams,
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
        }
    }

    fn search_metrics(&mut self) -> PrivateHnswSearchAccessMetrics {
        let store = RefCell::new(self.buckets.clone());
        let leaf_count = private_hnsw_oram_leaf_count(self.config.tree_height).unwrap();
        let mut next_leaf = 0;
        let result = search_private_hnsw_oram_plaintext(
            &mut self.state,
            self.config,
            &self.query,
            self.params,
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, self.config.tree_height)?
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
            || {
                let leaf = next_leaf;
                next_leaf = (next_leaf + 1) % leaf_count;
                Ok(leaf)
            },
        )
        .unwrap();
        let metrics = result.access_metrics(&self.params);
        assert_eq!(metrics.path_accesses, FIXED_STEPS);
        assert!(metrics.exhausted_fixed_budget);
        metrics
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

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = private_hnsw_oram_bench,
}

criterion_main!(benches);
