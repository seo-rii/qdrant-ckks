use std::cell::RefCell;
use std::collections::BTreeSet;

use proptest::prelude::*;
use qdrant_sec::{
    DistanceKind, PrivateHnswBucketAeadBaseContext, PrivateHnswBuildPoint, PrivateHnswClientError,
    PrivateHnswClientKeys, PrivateHnswOramBucket, PrivateHnswOramClientConfig,
    PrivateHnswOramClientState, PrivateHnswOramPlaintextBucket, PrivateHnswPlaintextIndexBuild,
    PrivateHnswSearchParams, PrivateHnswSearchResult, SecretKey,
    build_private_hnsw_oram_plaintext_index_from_f32_points, private_hnsw_oram_bucket_ids_for_leaf,
    private_hnsw_oram_leaf_count, seal_private_hnsw_oram_plaintext_index,
    search_private_hnsw_oram_encrypted, search_private_hnsw_oram_plaintext,
};

const K: usize = 10;
const NEIGHBORS: usize = 16;
const INDEX_EPOCH: u64 = 42;

#[derive(Clone, Copy)]
struct QualityCase {
    point_count: usize,
    dim: usize,
    query_count: usize,
    ef: usize,
    fixed_steps: usize,
    tree_height: u32,
}

#[derive(Debug)]
struct RecallStats {
    mean: f32,
    p10: f32,
    minimum: f32,
    top1: f32,
}

#[derive(Debug, PartialEq)]
struct SearchRun {
    results: Vec<PrivateHnswSearchResult>,
    final_state: PrivateHnswOramClientState,
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn unit_f32(&mut self) -> f32 {
        let mantissa = (self.next_u64() >> 40) as u32;
        mantissa as f32 / ((1u32 << 24) - 1) as f32
    }

    fn signed_f32(&mut self) -> f32 {
        self.unit_f32().mul_add(2.0, -1.0)
    }
}

#[test]
fn seeded_private_hnsw_oram_recall_meets_ci_floor() {
    let case = QualityCase {
        point_count: 512,
        dim: 32,
        query_count: 24,
        ef: 128,
        fixed_steps: 256,
        tree_height: 9,
    };
    let (points, queries) = seeded_points_and_queries(0x5eed_cafe, case);
    let config = quality_config(case);
    let build = build_index(config, &points);
    let actual = run_plaintext_searches(config, &build, &queries, case);
    let stats = recall_stats(&points, &queries, &actual.results, K);
    eprintln!("private HNSW ORAM CI recall: {stats:?}");

    assert!(
        stats.mean >= 0.97,
        "mean recall@{K} must be at least 0.97, got {stats:?}"
    );
    assert!(
        stats.minimum >= 0.80,
        "minimum recall@{K} must be at least 0.80, got {stats:?}"
    );
    assert!(
        stats.top1 >= 0.95,
        "top-1 recall must be at least 0.95, got {stats:?}"
    );
}

#[test]
fn seeded_private_hnsw_oram_recall_handles_non_anchor_queries() {
    let case = QualityCase {
        point_count: 512,
        dim: 32,
        query_count: 24,
        ef: 128,
        fixed_steps: 256,
        tree_height: 9,
    };
    let (points, _) = seeded_points_and_queries(0xdec0_de01, case);
    let mut rng = SplitMix64::new(0xdec0_de02);
    let queries = (0..case.query_count)
        .map(|query_index| {
            if query_index % 2 == 0 {
                return (0..case.dim).map(|_| rng.signed_f32()).collect();
            }
            let left = (query_index * 149 + 3) % points.len();
            let right = (query_index * 307 + 211) % points.len();
            points[left]
                .vector
                .iter()
                .zip(&points[right].vector)
                .map(|(left, right)| (left + right) * 0.5 + rng.signed_f32() * 0.02)
                .collect()
        })
        .collect::<Vec<_>>();
    let config = quality_config(case);
    let build = build_index(config, &points);
    let actual = run_plaintext_searches(config, &build, &queries, case);
    let stats = recall_stats(&points, &queries, &actual.results, K);
    eprintln!("private HNSW ORAM non-anchor recall: {stats:?}");

    assert!(
        stats.mean >= 0.95,
        "mean non-anchor recall@{K} must be at least 0.95, got {stats:?}"
    );
    assert!(
        stats.p10 >= 0.80,
        "p10 non-anchor recall@{K} must be at least 0.80, got {stats:?}"
    );
    assert!(
        stats.minimum >= 0.70,
        "minimum non-anchor recall@{K} must be at least 0.70, got {stats:?}"
    );
    assert!(
        stats.top1 >= 0.90,
        "non-anchor top-1 recall must be at least 0.90, got {stats:?}"
    );
}

#[test]
fn encrypted_private_hnsw_oram_matches_plaintext_search_results() {
    let case = QualityCase {
        point_count: 256,
        dim: 24,
        query_count: 8,
        ef: 96,
        fixed_steps: 160,
        tree_height: 8,
    };
    let (points, queries) = seeded_points_and_queries(0xc1a0_5eed, case);
    let config = quality_config(case);
    let build = build_index(config, &points);
    let plaintext = run_plaintext_searches(config, &build, &queries, case);
    let encrypted = run_encrypted_searches(config, &build, &queries, case);

    assert_eq!(encrypted, plaintext);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn generated_encrypted_search_matches_plaintext_and_budget_is_monotonic(
        seed in any::<u64>(),
        point_count in 16usize..49,
        dim in 4usize..13,
    ) {
        let base_case = QualityCase {
            point_count,
            dim,
            query_count: 1,
            ef: 16,
            fixed_steps: 64,
            tree_height: 6,
        };
        let (points, queries) = seeded_points_and_queries(seed, base_case);
        let config = quality_config(base_case);
        let build = build_index(config, &points);
        let plaintext = run_plaintext_searches(config, &build, &queries, base_case);
        let encrypted = run_encrypted_searches(config, &build, &queries, base_case);
        prop_assert_eq!(&encrypted, &plaintext);

        let short_case = QualityCase {
            fixed_steps: 32,
            ..base_case
        };
        let short = run_plaintext_searches(config, &build, &queries, short_case);
        let short_hits = &short.results[0].hits;
        let long_hits = &plaintext.results[0].hits;
        prop_assert_eq!(short_hits.len(), K);
        prop_assert_eq!(long_hits.len(), K);
        prop_assert!(long_hits[K - 1].distance <= short_hits[K - 1].distance);
        prop_assert!(long_hits[0].distance <= short_hits[0].distance);
    }
}

#[test]
#[ignore = "nightly quality gate: builds and searches a 2,048-point private graph"]
fn seeded_private_hnsw_oram_recall_meets_large_quality_floor() {
    let case = QualityCase {
        point_count: 2_048,
        dim: 32,
        query_count: 64,
        ef: 256,
        fixed_steps: 512,
        tree_height: 11,
    };
    let (points, queries) = seeded_points_and_queries(0x1a2b_3c4d_5e6f_7788, case);
    let config = quality_config(case);
    let build = build_index(config, &points);
    let actual = run_plaintext_searches(config, &build, &queries, case);
    let stats = recall_stats(&points, &queries, &actual.results, K);
    eprintln!("private HNSW ORAM large recall: {stats:?}");

    assert!(
        stats.mean >= 0.97,
        "mean recall@{K} must be at least 0.97, got {stats:?}"
    );
    assert!(
        stats.p10 >= 0.90,
        "p10 recall@{K} must be at least 0.90, got {stats:?}"
    );
    assert!(
        stats.minimum >= 0.70,
        "minimum recall@{K} must be at least 0.70, got {stats:?}"
    );
    assert!(
        stats.top1 >= 0.95,
        "top-1 recall must be at least 0.95, got {stats:?}"
    );
}

fn quality_config(case: QualityCase) -> PrivateHnswOramClientConfig {
    PrivateHnswOramClientConfig {
        tree_height: case.tree_height,
        bucket_size: 4,
        block_size_bytes: 2_048,
        fixed_neighbor_slots: NEIGHBORS,
    }
}

fn build_index(
    config: PrivateHnswOramClientConfig,
    points: &[PrivateHnswBuildPoint],
) -> PrivateHnswPlaintextIndexBuild {
    let leaf_count = private_hnsw_oram_leaf_count(config.tree_height).unwrap();
    assert!(points.len() as u64 <= leaf_count);
    let leaves = (0..points.len())
        .map(|index| ((index as u64 * 1_009) + 97) % leaf_count)
        .collect::<Vec<_>>();
    build_private_hnsw_oram_plaintext_index_from_f32_points(
        config,
        DistanceKind::Euclid,
        NEIGHBORS,
        points,
        &leaves,
    )
    .unwrap()
}

fn seeded_points_and_queries(
    seed: u64,
    case: QualityCase,
) -> (Vec<PrivateHnswBuildPoint>, Vec<Vec<f32>>) {
    let mut rng = SplitMix64::new(seed);
    let points = (0..case.point_count)
        .map(|index| PrivateHnswBuildPoint {
            node_id: id_from_u64(index as u64 + 1),
            point_token: id_from_u64(index as u64 + 1_000_001),
            vector: (0..case.dim).map(|_| rng.signed_f32()).collect(),
            payload_fetch_token: None,
        })
        .collect::<Vec<_>>();
    let queries = (0..case.query_count)
        .map(|query_index| {
            let anchor_index = (query_index * 1_009 + 17) % points.len();
            points[anchor_index]
                .vector
                .iter()
                .map(|coordinate| coordinate + rng.signed_f32() * 0.08)
                .collect()
        })
        .collect();
    (points, queries)
}

fn run_plaintext_searches(
    config: PrivateHnswOramClientConfig,
    build: &PrivateHnswPlaintextIndexBuild,
    queries: &[Vec<f32>],
    case: QualityCase,
) -> SearchRun {
    let mut state = build.state.clone();
    let store = RefCell::new(build.buckets.clone());
    let leaf_count = private_hnsw_oram_leaf_count(config.tree_height).unwrap();
    let mut next_leaf = 0u64;

    let results = queries
        .iter()
        .map(|query| {
            let params = search_params(build.entry_node_id, case);
            let result = search_private_hnsw_oram_plaintext(
                &mut state,
                config,
                query,
                params,
                |leaf| read_plaintext_path(&store, config, leaf),
                |writeback_buckets| write_plaintext_buckets(&store, writeback_buckets),
                || {
                    let leaf = next_leaf;
                    next_leaf = (next_leaf + 1) % leaf_count;
                    Ok(leaf)
                },
            )
            .unwrap();
            assert_eq!(result.completed_steps, case.fixed_steps);
            result
        })
        .collect();
    SearchRun {
        results,
        final_state: state,
    }
}

fn run_encrypted_searches(
    config: PrivateHnswOramClientConfig,
    build: &PrivateHnswPlaintextIndexBuild,
    queries: &[Vec<f32>],
    case: QualityCase,
) -> SearchRun {
    let keys = client_keys();
    let context = bucket_context();
    let encrypted =
        seal_private_hnsw_oram_plaintext_index(&keys, context, INDEX_EPOCH, build, config).unwrap();
    let mut state = build.state.clone();
    let store = RefCell::new(encrypted.buckets);
    let leaf_count = private_hnsw_oram_leaf_count(config.tree_height).unwrap();
    let mut next_leaf = 0u64;

    let results = queries
        .iter()
        .enumerate()
        .map(|(query_index, query)| {
            let params = search_params(build.entry_node_id, case);
            let result = search_private_hnsw_oram_encrypted(
                &keys,
                context,
                INDEX_EPOCH + query_index as u64 + 1,
                &mut state,
                config,
                query,
                params,
                |leaf| read_encrypted_path(&store, config, leaf),
                |writeback_buckets| write_encrypted_buckets(&store, writeback_buckets),
                || {
                    let leaf = next_leaf;
                    next_leaf = (next_leaf + 1) % leaf_count;
                    Ok(leaf)
                },
            )
            .unwrap();
            assert_eq!(result.completed_steps, case.fixed_steps);
            result
        })
        .collect();
    SearchRun {
        results,
        final_state: state,
    }
}

fn search_params(entry_node_id: [u8; 32], case: QualityCase) -> PrivateHnswSearchParams {
    PrivateHnswSearchParams {
        entry_node_id,
        k: K,
        ef: case.ef,
        fixed_steps: case.fixed_steps,
        distance: DistanceKind::Euclid,
        padding_node_id: Some(entry_node_id),
    }
}

fn read_plaintext_path(
    store: &RefCell<Vec<PrivateHnswOramPlaintextBucket>>,
    config: PrivateHnswOramClientConfig,
    leaf: u64,
) -> Result<Vec<PrivateHnswOramPlaintextBucket>, PrivateHnswClientError> {
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
}

fn write_plaintext_buckets(
    store: &RefCell<Vec<PrivateHnswOramPlaintextBucket>>,
    writeback_buckets: &[PrivateHnswOramPlaintextBucket],
) -> Result<(), PrivateHnswClientError> {
    let mut store = store.borrow_mut();
    for bucket in writeback_buckets {
        let slot = store
            .get_mut(bucket.bucket_id as usize)
            .ok_or(PrivateHnswClientError::PathBucketMismatch)?;
        *slot = bucket.clone();
    }
    Ok(())
}

fn read_encrypted_path(
    store: &RefCell<Vec<PrivateHnswOramBucket>>,
    config: PrivateHnswOramClientConfig,
    leaf: u64,
) -> Result<Vec<PrivateHnswOramBucket>, PrivateHnswClientError> {
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
}

fn write_encrypted_buckets(
    store: &RefCell<Vec<PrivateHnswOramBucket>>,
    writeback_buckets: &[PrivateHnswOramBucket],
) -> Result<(), PrivateHnswClientError> {
    let mut store = store.borrow_mut();
    for bucket in writeback_buckets {
        let slot = store
            .get_mut(bucket.bucket_id as usize)
            .ok_or(PrivateHnswClientError::PathBucketMismatch)?;
        *slot = bucket.clone();
    }
    Ok(())
}

fn recall_stats(
    points: &[PrivateHnswBuildPoint],
    queries: &[Vec<f32>],
    actual: &[PrivateHnswSearchResult],
    k: usize,
) -> RecallStats {
    let mut top1_matches = 0usize;
    let mut recalls = queries
        .iter()
        .zip(actual)
        .map(|(query, actual_result)| {
            assert_eq!(actual_result.hits.len(), k);
            let expected = exact_top_k(points, query, k);
            top1_matches += usize::from(actual_result.hits[0].node_id == expected[0]);
            let expected = expected.into_iter().collect::<BTreeSet<_>>();
            let actual = actual_result
                .hits
                .iter()
                .map(|hit| hit.node_id)
                .collect::<BTreeSet<_>>();
            expected.intersection(&actual).count() as f32 / k as f32
        })
        .collect::<Vec<_>>();
    recalls.sort_by(f32::total_cmp);
    let p10_index = (recalls.len() - 1) / 10;
    RecallStats {
        mean: recalls.iter().sum::<f32>() / recalls.len() as f32,
        p10: recalls[p10_index],
        minimum: recalls[0],
        top1: top1_matches as f32 / recalls.len() as f32,
    }
}

fn exact_top_k(points: &[PrivateHnswBuildPoint], query: &[f32], k: usize) -> Vec<[u8; 32]> {
    let mut distances = points
        .iter()
        .map(|point| {
            let distance = point
                .vector
                .iter()
                .zip(query)
                .map(|(left, right)| {
                    let delta = left - right;
                    delta * delta
                })
                .sum::<f32>();
            (distance, point.node_id)
        })
        .collect::<Vec<_>>();
    distances.sort_by(|left, right| {
        left.0
            .total_cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
    });
    distances
        .into_iter()
        .take(k)
        .map(|(_, node_id)| node_id)
        .collect()
}

fn client_keys() -> PrivateHnswClientKeys {
    let resource_key = SecretKey::from_bytes([0x5a; 32]);
    PrivateHnswClientKeys::derive_from_resource_key_with_context(
        &resource_key,
        "recall-test-collection",
        "text",
        "recall-test/vector-rk",
        7,
    )
    .unwrap()
}

fn bucket_context() -> PrivateHnswBucketAeadBaseContext<'static> {
    PrivateHnswBucketAeadBaseContext {
        collection_id: "recall-test-collection",
        vector_name: "text",
        key_id: "recall-test/vector-rk",
        rk_id: "recall-test/vector-rk",
        rk_epoch: 7,
    }
}

fn id_from_u64(value: u64) -> [u8; 32] {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&value.to_be_bytes());
    id
}
