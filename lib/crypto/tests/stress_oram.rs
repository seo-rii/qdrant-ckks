//! Deterministic load tests for the Path ORAM clients.
//!
//! Thousands of random accesses and evictions on a mid-sized tree must keep the client stash
//! small (the Path ORAM stash bound is what makes a fixed-shape access pattern possible) and must
//! never lose, duplicate or misplace a block. The pseudo-random sequence is seeded, so a failure
//! reproduces exactly.

use std::collections::{BTreeMap, BTreeSet};

use qdrant_sec::private_hnsw_client::*;
use qdrant_sec::private_result_oram::*;

const TREE_HEIGHT: u32 = 6;
const BUCKET_SIZE: usize = 4;
const BLOCK_COUNT: usize = 200;
const STEPS: usize = 4000;
/// Far above what Path ORAM with Z = 4 at 40% load needs; a stash that grows past this is an
/// eviction bug, not bad luck.
const STASH_LIMIT: usize = 32;

/// xorshift64*: deterministic, good enough to spread leaves and tokens.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

// ---------------------------------------------------------------------------------------------
// Result ORAM
// ---------------------------------------------------------------------------------------------

struct ResultServer {
    config: PrivateResultOramClientConfig,
    buckets: Vec<PrivateResultOramPlaintextBucket>,
}

impl ResultServer {
    fn new(config: PrivateResultOramClientConfig) -> Self {
        let bucket_count = private_result_oram_bucket_count(config.tree_height).unwrap();
        Self {
            config,
            buckets: (0..bucket_count)
                .map(|id| empty_private_result_oram_plaintext_bucket(id, config).unwrap())
                .collect(),
        }
    }

    fn path(&self, leaf: u64) -> Vec<PrivateResultOramPlaintextBucket> {
        private_result_oram_bucket_ids_for_leaf(leaf, self.config.tree_height)
            .unwrap()
            .into_iter()
            .map(|id| self.buckets[id as usize].clone())
            .collect()
    }

    fn write_back(&mut self, buckets: &[PrivateResultOramPlaintextBucket]) {
        for bucket in buckets {
            assert_eq!(bucket.blocks.len(), self.config.bucket_size);
            self.buckets[bucket.bucket_id as usize] = bucket.clone();
        }
    }

    fn stored(&self) -> BTreeMap<[u8; 32], (u64, PrivateResultOramPayloadBlockPlaintext)> {
        let mut stored = BTreeMap::new();
        for bucket in &self.buckets {
            for block in bucket.blocks.iter().flatten() {
                let previous =
                    stored.insert(block.payload_fetch_token, (bucket.bucket_id, block.clone()));
                assert!(previous.is_none(), "a block is stored in two buckets");
            }
        }
        stored
    }
}

fn result_block(index: usize) -> PrivateResultOramPayloadBlockPlaintext {
    PrivateResultOramPayloadBlockPlaintext {
        version: PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION,
        payload_fetch_token: [index as u8; 32],
        point_token: [(index as u8).wrapping_add(100); 32],
        payload: vec![index as u8; (index % 16) + 1],
        deleted: false,
        generation: index as u64,
    }
}

fn check_result_invariants(
    expected: &BTreeMap<[u8; 32], PrivateResultOramPayloadBlockPlaintext>,
    state: &PrivateResultOramClientState,
    server: &ResultServer,
) {
    let stored = server.stored();
    for (token, block) in expected {
        let leaf = state.position(token).expect("every block keeps a position");
        let path: BTreeSet<u64> = private_result_oram_bucket_ids_for_leaf(leaf, TREE_HEIGHT)
            .unwrap()
            .into_iter()
            .collect();
        match stored.get(token) {
            Some((bucket_id, stored_block)) => {
                assert!(
                    !state.stash_contains(token),
                    "block both stored and stashed"
                );
                assert!(
                    path.contains(bucket_id),
                    "stored block off its position path"
                );
                assert_eq!(stored_block, block);
            }
            None => assert!(state.stash_contains(token), "block lost"),
        }
    }
    assert_eq!(
        stored.len() + state.stash_len(),
        expected.len(),
        "foreign block"
    );
}

#[test]
fn result_path_oram_stash_stays_bounded_under_sustained_random_access() {
    let config = PrivateResultOramClientConfig {
        tree_height: TREE_HEIGHT,
        bucket_size: BUCKET_SIZE,
        block_size_bytes: 128,
    };
    let leaf_count = 1u64 << TREE_HEIGHT;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut server = ResultServer::new(config);
    let mut state = PrivateResultOramClientState::new();
    let mut expected = BTreeMap::new();

    for index in 0..BLOCK_COUNT {
        let block = result_block(index);
        let leaf = rng.next() % leaf_count;
        state
            .insert_new_stash_block(block.clone(), leaf, config)
            .unwrap();
        expected.insert(block.payload_fetch_token, block);
        let eviction =
            evict_private_result_oram_path(&mut state, config, leaf, &server.path(leaf)).unwrap();
        server.write_back(&eviction.writeback_buckets);
    }
    check_result_invariants(&expected, &state, &server);

    let mut max_stash = state.stash_len();
    for step in 0..STEPS {
        let draw = rng.next();
        if draw.is_multiple_of(5) {
            let leaf = (draw >> 8) % leaf_count;
            let eviction =
                evict_private_result_oram_path(&mut state, config, leaf, &server.path(leaf))
                    .unwrap();
            server.write_back(&eviction.writeback_buckets);
        } else {
            let token = [(draw % BLOCK_COUNT as u64) as u8; 32];
            let new_leaf = (draw >> 8) % leaf_count;
            let old_leaf = state.position(&token).unwrap();
            let access = access_private_result_oram_path(
                &mut state,
                config,
                token,
                &server.path(old_leaf),
                new_leaf,
            )
            .unwrap();
            assert_eq!(&access.block, &expected[&token]);
            assert_eq!(access.old_leaf, old_leaf);
            assert_eq!(access.new_leaf, new_leaf);
            assert_eq!(state.position(&token), Some(new_leaf));
            server.write_back(&access.writeback_buckets);
        }
        max_stash = max_stash.max(state.stash_len());
        assert!(
            state.stash_len() <= STASH_LIMIT,
            "stash reached {} at step {step}",
            state.stash_len()
        );
        if step % 250 == 0 {
            check_result_invariants(&expected, &state, &server);
        }
    }
    check_result_invariants(&expected, &state, &server);
    assert!(max_stash <= STASH_LIMIT, "max stash {max_stash}");
}

// ---------------------------------------------------------------------------------------------
// HNSW ORAM
// ---------------------------------------------------------------------------------------------

struct HnswServer {
    config: PrivateHnswOramClientConfig,
    buckets: Vec<PrivateHnswOramPlaintextBucket>,
}

impl HnswServer {
    fn new(config: PrivateHnswOramClientConfig) -> Self {
        let bucket_count = private_hnsw_oram_bucket_count(config.tree_height).unwrap();
        Self {
            config,
            buckets: (0..bucket_count)
                .map(|id| empty_private_hnsw_oram_plaintext_bucket(id, config).unwrap())
                .collect(),
        }
    }

    fn path(&self, leaf: u64) -> Vec<PrivateHnswOramPlaintextBucket> {
        private_hnsw_oram_bucket_ids_for_leaf(leaf, self.config.tree_height)
            .unwrap()
            .into_iter()
            .map(|id| self.buckets[id as usize].clone())
            .collect()
    }

    fn write_back(&mut self, buckets: &[PrivateHnswOramPlaintextBucket]) {
        for bucket in buckets {
            assert_eq!(bucket.blocks.len(), self.config.bucket_size);
            self.buckets[bucket.bucket_id as usize] = bucket.clone();
        }
    }

    fn stored(&self) -> BTreeMap<[u8; 32], (u64, PrivateHnswNodeBlockPlaintext)> {
        let mut stored = BTreeMap::new();
        for bucket in &self.buckets {
            for block in bucket.blocks.iter().flatten() {
                let previous = stored.insert(block.node_id, (bucket.bucket_id, block.clone()));
                assert!(previous.is_none(), "a block is stored in two buckets");
            }
        }
        stored
    }
}

fn hnsw_block(index: usize) -> PrivateHnswNodeBlockPlaintext {
    PrivateHnswNodeBlockPlaintext {
        version: 1,
        node_id: [index as u8; 32],
        point_token: [(index as u8).wrapping_add(100); 32],
        level_mask: 1,
        vector_encoding: PrivateHnswVectorEncoding::F32Le,
        vector: (index as f32).to_le_bytes().to_vec(),
        neighbors: vec![[(index as u8).wrapping_add(1); 32]],
        neighbor_levels: vec![0],
        deleted: false,
        generation: index as u64,
        payload_fetch_token: Some([(index as u8).wrapping_add(200); 32]),
    }
}

fn check_hnsw_invariants(
    expected: &BTreeMap<[u8; 32], PrivateHnswNodeBlockPlaintext>,
    state: &PrivateHnswOramClientState,
    server: &HnswServer,
) {
    let stored = server.stored();
    for (node_id, block) in expected {
        let leaf = state
            .position(node_id)
            .expect("every block keeps a position");
        let path: BTreeSet<u64> = private_hnsw_oram_bucket_ids_for_leaf(leaf, TREE_HEIGHT)
            .unwrap()
            .into_iter()
            .collect();
        match stored.get(node_id) {
            Some((bucket_id, stored_block)) => {
                assert!(
                    !state.stash_contains(node_id),
                    "block both stored and stashed"
                );
                assert!(
                    path.contains(bucket_id),
                    "stored block off its position path"
                );
                assert_eq!(stored_block, block);
            }
            None => assert!(state.stash_contains(node_id), "block lost"),
        }
    }
    assert_eq!(
        stored.len() + state.stash_len(),
        expected.len(),
        "foreign block"
    );
}

#[test]
fn hnsw_path_oram_stash_stays_bounded_under_sustained_random_access() {
    let config = PrivateHnswOramClientConfig {
        tree_height: TREE_HEIGHT,
        bucket_size: BUCKET_SIZE,
        block_size_bytes: 256,
        fixed_neighbor_slots: 1,
    };
    let leaf_count = 1u64 << TREE_HEIGHT;
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let mut server = HnswServer::new(config);
    let mut state = PrivateHnswOramClientState::new();
    let mut expected = BTreeMap::new();

    for index in 0..BLOCK_COUNT {
        let block = hnsw_block(index);
        let leaf = rng.next() % leaf_count;
        state
            .insert_new_stash_block(block.clone(), leaf, config)
            .unwrap();
        expected.insert(block.node_id, block);
        let eviction =
            evict_private_hnsw_oram_path(&mut state, config, leaf, &server.path(leaf)).unwrap();
        server.write_back(&eviction.writeback_buckets);
    }
    check_hnsw_invariants(&expected, &state, &server);

    let mut max_stash = state.stash_len();
    for step in 0..STEPS {
        let draw = rng.next();
        if draw.is_multiple_of(5) {
            let leaf = (draw >> 8) % leaf_count;
            let eviction =
                evict_private_hnsw_oram_path(&mut state, config, leaf, &server.path(leaf)).unwrap();
            server.write_back(&eviction.writeback_buckets);
        } else {
            let node_id = [(draw % BLOCK_COUNT as u64) as u8; 32];
            let new_leaf = (draw >> 8) % leaf_count;
            let old_leaf = state.position(&node_id).unwrap();
            let access = access_private_hnsw_oram_path(
                &mut state,
                config,
                node_id,
                &server.path(old_leaf),
                new_leaf,
            )
            .unwrap();
            assert_eq!(&access.block, &expected[&node_id]);
            assert_eq!(state.position(&node_id), Some(new_leaf));
            server.write_back(&access.writeback_buckets);
        }
        max_stash = max_stash.max(state.stash_len());
        assert!(
            state.stash_len() <= STASH_LIMIT,
            "stash reached {} at step {step}",
            state.stash_len()
        );
        if step % 250 == 0 {
            check_hnsw_invariants(&expected, &state, &server);
        }
    }
    check_hnsw_invariants(&expected, &state, &server);
    assert!(max_stash <= STASH_LIMIT, "max stash {max_stash}");
}
