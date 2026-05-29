use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::aead::{EncryptionError, SecretKey, validate_resource_key_id};
use crate::private_hnsw_oram::{
    DistanceKind, PrivateHnswOramBucket, PrivateHnswOramCommitBucketRef,
    PrivateHnswOramCommitSignatureInput, PrivateHnswOramManifest, PrivateHnswOramSignature,
    private_hnsw_oram_commit_signature_message, private_hnsw_oram_manifest_signature_message,
};

pub const PRIVATE_HNSW_NODE_AEAD_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-node-aead/v1";
pub const PRIVATE_HNSW_BUCKET_AEAD_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-bucket-aead/v1";
pub const PRIVATE_HNSW_POSITION_MAP_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-position-map/v1";
pub const PRIVATE_HNSW_PAYLOAD_TOKEN_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-payload-token/v1";
pub const PRIVATE_HNSW_BLIND_RESULT_DOMAIN: &[u8] = b"qdrant-sec/private-hnsw-blind-result/v1";

const NODE_BLOCK_MAGIC: &[u8; 4] = b"QPHO";
const NODE_BLOCK_VERSION: u16 = 1;
const BUCKET_PLAINTEXT_MAGIC: &[u8; 4] = b"QPHB";
const BUCKET_PLAINTEXT_VERSION: u16 = 1;
const BUCKET_AEAD_VERSION: u8 = 1;
const BUCKET_AEAD_NONCE_LEN: usize = 12;
const BUCKET_AEAD_TAG_LEN: usize = 16;
const PRIVATE_HNSW_BUCKET_AEAD_CONTEXT_DOMAIN: &str = "qdrant-sec/private-hnsw-oram-bucket-aead/v1";
const PRIVATE_HNSW_BUCKET_COMMITMENT_DOMAIN: &str =
    "qdrant-sec/private-hnsw-oram-bucket-commitment/v1";
pub const PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND: &str = "merkle_path_batch/v1";

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PrivateHnswClientError {
    #[error("private HNSW client encryption failed: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("private HNSW node block has invalid neighbor shape")]
    InvalidNeighborShape,
    #[error("private HNSW node block has {actual} neighbors but only {limit} slots")]
    TooManyNeighbors { actual: usize, limit: usize },
    #[error("private HNSW node block vector is too large")]
    VectorTooLarge,
    #[error("private HNSW node block fixed neighbor slot count is too large")]
    FixedNeighborSlotsTooLarge,
    #[error("private HNSW node block does not fit in configured block size")]
    EncodedBlockOversized,
    #[error("private HNSW node block encoding is malformed")]
    InvalidBlockEncoding,
    #[error("private HNSW node block uses unsupported version {0}")]
    UnsupportedBlockVersion(u16),
    #[error("private HNSW node block uses unsupported vector encoding {0}")]
    UnsupportedVectorEncoding(u8),
    #[error("private HNSW node block padding is invalid")]
    InvalidBlockPadding,
    #[error("private HNSW bucket context field {0} is invalid")]
    InvalidBucketContext(&'static str),
    #[error("private HNSW bucket ciphertext is not base64url")]
    InvalidBucketCiphertextEncoding,
    #[error("private HNSW bucket ciphertext hash is invalid")]
    InvalidBucketCiphertextHash,
    #[error("private HNSW bucket commitment is invalid")]
    InvalidBucketCommitment,
    #[error("private HNSW bucket metadata does not match the decrypt context")]
    BucketMetadataMismatch,
    #[error("private HNSW bucket uses unsupported ciphertext version {0}")]
    UnsupportedBucketCiphertextVersion(u8),
    #[error("private HNSW bucket ciphertext authentication failed")]
    BucketOpenFailed,
    #[error("private HNSW ORAM tree_height must be less than 63 for Path ORAM path decoding")]
    InvalidTreeHeight,
    #[error("private HNSW ORAM leaf label is outside ORAM tree range")]
    LeafOutOfRange,
    #[error("private HNSW ORAM leaf label is not base64url")]
    InvalidLeafLabelEncoding,
    #[error("private HNSW ORAM leaf label must encode an 8-byte u64")]
    InvalidLeafLabelLength,
    #[error("private HNSW ORAM bucket_count does not match tree_height")]
    BucketCountMismatch,
    #[error("private HNSW ORAM client config field {0} is invalid")]
    InvalidOramClientConfig(&'static str),
    #[error("private HNSW ORAM bucket plaintext is malformed")]
    InvalidBucketPlaintext,
    #[error("private HNSW ORAM bucket plaintext metadata does not match config")]
    BucketPlaintextMetadataMismatch,
    #[error("private HNSW ORAM bucket plaintext slot count does not match config")]
    BucketPlaintextSlotCountMismatch,
    #[error("private HNSW ORAM path buckets do not match the requested leaf path")]
    PathBucketMismatch,
    #[error("private HNSW ORAM client position map is missing a node")]
    MissingPosition,
    #[error("private HNSW ORAM path did not contain the requested node")]
    MissingBlock,
    #[error("private HNSW ORAM path contains duplicate node blocks")]
    DuplicateBlock,
    #[error("private HNSW ORAM build config field {0} is invalid")]
    InvalidBuildConfig(&'static str),
    #[error("private HNSW ORAM initial placement overflowed path for leaf {leaf}")]
    OramInitialPlacementOverflow { leaf: u64 },
    #[error("private HNSW search config field {0} is invalid")]
    InvalidSearchConfig(&'static str),
    #[error("private HNSW search currently requires f32_le node vectors")]
    UnsupportedSearchVectorEncoding,
    #[error("private HNSW search f32 vector bytes are malformed")]
    InvalidF32VectorLength,
    #[error("private HNSW search query and node vector dimensions differ")]
    VectorDimensionMismatch,
    #[error("private HNSW search distance is not finite")]
    NonFiniteDistance,
    #[error("private HNSW ORAM Merkle tree must contain at least one leaf")]
    EmptyMerkleTree,
    #[error("private HNSW ORAM Merkle root is invalid")]
    InvalidMerkleRoot,
    #[error("private HNSW ORAM Merkle root mismatch")]
    MerkleRootMismatch,
    #[error("private HNSW ORAM commit new_epoch must be greater than old_epoch")]
    InvalidCommitEpoch,
    #[error("private HNSW ORAM commit must update at least one bucket")]
    EmptyCommit,
    #[error(
        "private HNSW ORAM commit bucket {bucket_id} is out of range for {bucket_count} buckets"
    )]
    BucketOutOfRange { bucket_id: u64, bucket_count: u64 },
    #[error("private HNSW ORAM commit bucket {bucket_id} appears more than once")]
    DuplicateUpdatedBucket { bucket_id: u64 },
    #[error(
        "private HNSW ORAM commit bucket {bucket_id} has epoch {actual_epoch}, expected {expected_epoch}"
    )]
    StaleBucketEpoch {
        bucket_id: u64,
        expected_epoch: u64,
        actual_epoch: u64,
    },
    #[error("private HNSW ORAM bucket uses unsupported version {0}")]
    UnsupportedBucketVersion(u16),
    #[error("private HNSW ORAM commit signature context field {0} is invalid")]
    InvalidCommitSignatureContext(&'static str),
    #[error("private HNSW ORAM manifest signature context field {0} is invalid")]
    InvalidManifestSignatureContext(&'static str),
    #[error("private HNSW ORAM Merkle proof is malformed")]
    InvalidMerkleProof,
    #[error("private HNSW ORAM Merkle proof JSON is malformed")]
    InvalidMerkleProofJson,
    #[error("private HNSW ORAM Merkle proof does not match buckets/root")]
    MerkleProofMismatch,
}

pub struct PrivateHnswClientKeys {
    node_aead: SecretKey,
    bucket_aead: SecretKey,
    position_map: SecretKey,
    payload_token: SecretKey,
    blind_result: SecretKey,
}

impl PrivateHnswClientKeys {
    pub fn derive_from_resource_key(resource_key: &SecretKey) -> Result<Self, EncryptionError> {
        Ok(Self {
            node_aead: resource_key.derive_subkey(PRIVATE_HNSW_NODE_AEAD_DOMAIN)?,
            bucket_aead: resource_key.derive_subkey(PRIVATE_HNSW_BUCKET_AEAD_DOMAIN)?,
            position_map: resource_key.derive_subkey(PRIVATE_HNSW_POSITION_MAP_DOMAIN)?,
            payload_token: resource_key.derive_subkey(PRIVATE_HNSW_PAYLOAD_TOKEN_DOMAIN)?,
            blind_result: resource_key.derive_subkey(PRIVATE_HNSW_BLIND_RESULT_DOMAIN)?,
        })
    }

    pub fn node_aead_key(&self) -> &SecretKey {
        &self.node_aead
    }

    pub fn bucket_aead_key(&self) -> &SecretKey {
        &self.bucket_aead
    }

    pub fn position_map_key(&self) -> &SecretKey {
        &self.position_map
    }

    pub fn payload_token_key(&self) -> &SecretKey {
        &self.payload_token
    }

    pub fn blind_result_key(&self) -> &SecretKey {
        &self.blind_result
    }
}

impl Debug for PrivateHnswClientKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswClientKeys")
            .field("node_aead", &"[redacted; 32 bytes]")
            .field("bucket_aead", &"[redacted; 32 bytes]")
            .field("position_map", &"[redacted; 32 bytes]")
            .field("payload_token", &"[redacted; 32 bytes]")
            .field("blind_result", &"[redacted; 32 bytes]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateHnswVectorEncoding {
    F32Le,
    I8Quantized,
    PqCode,
    BinaryQuantized,
}

impl PrivateHnswVectorEncoding {
    fn tag(self) -> u8 {
        match self {
            Self::F32Le => 1,
            Self::I8Quantized => 2,
            Self::PqCode => 3,
            Self::BinaryQuantized => 4,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, PrivateHnswClientError> {
        match tag {
            1 => Ok(Self::F32Le),
            2 => Ok(Self::I8Quantized),
            3 => Ok(Self::PqCode),
            4 => Ok(Self::BinaryQuantized),
            _ => Err(PrivateHnswClientError::UnsupportedVectorEncoding(tag)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswNodeBlockPlaintext {
    pub version: u16,
    pub node_id: [u8; 32],
    pub point_token: [u8; 32],
    pub level_mask: u64,
    pub vector_encoding: PrivateHnswVectorEncoding,
    pub vector: Vec<u8>,
    pub neighbors: Vec<[u8; 32]>,
    pub neighbor_levels: Vec<u8>,
    pub deleted: bool,
    pub generation: u64,
    pub payload_fetch_token: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateHnswBucketAeadContext<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub bucket_id: u64,
    pub index_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateHnswBucketAeadBaseContext<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
}

impl<'a> PrivateHnswBucketAeadBaseContext<'a> {
    pub fn for_bucket(self, bucket_id: u64, index_epoch: u64) -> PrivateHnswBucketAeadContext<'a> {
        PrivateHnswBucketAeadContext {
            collection_id: self.collection_id,
            vector_name: self.vector_name,
            key_id: self.key_id,
            rk_id: self.rk_id,
            rk_epoch: self.rk_epoch,
            bucket_id,
            index_epoch,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateHnswOramClientConfig {
    pub tree_height: u32,
    pub bucket_size: usize,
    pub block_size_bytes: usize,
    pub fixed_neighbor_slots: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateHnswOramPlaintextBucket {
    pub bucket_id: u64,
    pub blocks: Vec<Option<PrivateHnswNodeBlockPlaintext>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramMerkleProof {
    pub kind: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub leaves: Vec<PrivateHnswOramMerkleProofLeaf>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramMerkleProofLeaf {
    pub bucket_id: u64,
    pub leaf_hash: String,
    pub siblings: Vec<PrivateHnswOramMerkleSibling>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramMerkleSibling {
    pub level: u32,
    pub position: PrivateHnswMerkleSiblingPosition,
    pub hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateHnswMerkleSiblingPosition {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateHnswEncryptedPathBatch {
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub proof_value: String,
    pub buckets: Vec<PrivateHnswOramBucket>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateHnswOramAccessResult {
    pub old_leaf: u64,
    pub new_leaf: u64,
    pub old_leaf_label: String,
    pub block: PrivateHnswNodeBlockPlaintext,
    pub writeback_buckets: Vec<PrivateHnswOramPlaintextBucket>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateHnswSearchParams {
    pub entry_node_id: [u8; 32],
    pub k: usize,
    pub ef: usize,
    pub fixed_steps: usize,
    pub distance: DistanceKind,
    pub padding_node_id: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PrivateHnswSearchHit {
    pub node_id: [u8; 32],
    pub point_token: [u8; 32],
    pub distance: f32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PrivateHnswSearchResult {
    pub hits: Vec<PrivateHnswSearchHit>,
    pub accessed_leaf_labels: Vec<String>,
    pub completed_steps: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateHnswPlaintextIndexBuild {
    pub entry_node_id: [u8; 32],
    pub state: PrivateHnswOramClientState,
    pub buckets: Vec<PrivateHnswOramPlaintextBucket>,
    pub logical_node_count: u64,
    pub dummy_node_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateHnswClientCommitBucketRef {
    pub bucket_id: u64,
    pub ciphertext_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateHnswClientCommitPlan {
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub leaf_commitments: Vec<String>,
    pub updated_buckets: Vec<PrivateHnswClientCommitBucketRef>,
}

impl PrivateHnswClientCommitPlan {
    pub fn signature_bucket_refs(&self) -> Vec<PrivateHnswOramCommitBucketRef<'_>> {
        self.updated_buckets
            .iter()
            .map(|bucket| PrivateHnswOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateHnswCommitSignatureContext<'a> {
    pub collection_id: &'a str,
    pub vector_name: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub signing_key_id: &'a str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivateHnswOramClientState {
    position_map: BTreeMap<[u8; 32], u64>,
    stash: BTreeMap<[u8; 32], PrivateHnswNodeBlockPlaintext>,
}

impl PrivateHnswOramClientState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_position_map(
        position_map: impl IntoIterator<Item = ([u8; 32], u64)>,
        tree_height: u32,
    ) -> Result<Self, PrivateHnswClientError> {
        let mut state = Self::new();
        for (node_id, leaf) in position_map {
            validate_private_hnsw_oram_leaf(leaf, tree_height)?;
            state.position_map.insert(node_id, leaf);
        }
        Ok(state)
    }

    pub fn insert_position(
        &mut self,
        node_id: [u8; 32],
        leaf: u64,
        tree_height: u32,
    ) -> Result<(), PrivateHnswClientError> {
        validate_private_hnsw_oram_leaf(leaf, tree_height)?;
        self.position_map.insert(node_id, leaf);
        Ok(())
    }

    pub fn position(&self, node_id: &[u8; 32]) -> Option<u64> {
        self.position_map.get(node_id).copied()
    }

    pub fn stash_len(&self) -> usize {
        self.stash.len()
    }

    pub fn stash_contains(&self, node_id: &[u8; 32]) -> bool {
        self.stash.contains_key(node_id)
    }
}

pub fn private_hnsw_oram_leaf_count(tree_height: u32) -> Result<u64, PrivateHnswClientError> {
    if tree_height >= 63 {
        return Err(PrivateHnswClientError::InvalidTreeHeight);
    }
    Ok(1u64 << tree_height)
}

pub fn private_hnsw_oram_bucket_count(tree_height: u32) -> Result<u64, PrivateHnswClientError> {
    private_hnsw_oram_leaf_count(tree_height)?
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .ok_or(PrivateHnswClientError::InvalidTreeHeight)
}

pub fn encode_private_hnsw_oram_leaf_label(
    leaf: u64,
    tree_height: u32,
) -> Result<String, PrivateHnswClientError> {
    validate_private_hnsw_oram_leaf(leaf, tree_height)?;
    Ok(BASE64URL_NOPAD.encode(&leaf.to_be_bytes()))
}

pub fn decode_private_hnsw_oram_leaf_label(
    label: &str,
    tree_height: u32,
) -> Result<u64, PrivateHnswClientError> {
    let bytes = BASE64URL_NOPAD
        .decode(label.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidLeafLabelEncoding)?;
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidLeafLabelLength)?;
    let leaf = u64::from_be_bytes(bytes);
    validate_private_hnsw_oram_leaf(leaf, tree_height)?;
    Ok(leaf)
}

pub fn private_hnsw_oram_bucket_ids_for_leaf(
    leaf: u64,
    tree_height: u32,
) -> Result<Vec<u64>, PrivateHnswClientError> {
    validate_private_hnsw_oram_leaf(leaf, tree_height)?;
    let mut bucket_ids = Vec::with_capacity(tree_height as usize + 1);
    for level in 0..=tree_height {
        let level_start = (1u64 << level) - 1;
        let prefix = if level == 0 {
            0
        } else {
            leaf >> (tree_height - level)
        };
        bucket_ids.push(level_start + prefix);
    }
    Ok(bucket_ids)
}

pub fn private_hnsw_oram_bucket_ids_for_leaf_labels<'a>(
    leaf_labels: impl IntoIterator<Item = &'a str>,
    tree_height: u32,
    bucket_count: u64,
) -> Result<Vec<u64>, PrivateHnswClientError> {
    if bucket_count != private_hnsw_oram_bucket_count(tree_height)? {
        return Err(PrivateHnswClientError::BucketCountMismatch);
    }
    let mut bucket_ids = BTreeSet::new();
    for label in leaf_labels {
        let leaf = decode_private_hnsw_oram_leaf_label(label, tree_height)?;
        bucket_ids.extend(private_hnsw_oram_bucket_ids_for_leaf(leaf, tree_height)?);
    }
    Ok(bucket_ids.into_iter().collect())
}

pub fn empty_private_hnsw_oram_plaintext_bucket(
    bucket_id: u64,
    config: PrivateHnswOramClientConfig,
) -> Result<PrivateHnswOramPlaintextBucket, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    Ok(PrivateHnswOramPlaintextBucket {
        bucket_id,
        blocks: vec![None; config.bucket_size],
    })
}

pub fn build_private_hnsw_oram_plaintext_index_from_blocks(
    config: PrivateHnswOramClientConfig,
    blocks: &[PrivateHnswNodeBlockPlaintext],
    leaves: &[u64],
) -> Result<PrivateHnswPlaintextIndexBuild, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    if blocks.is_empty() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("blocks"));
    }
    if blocks.len() != leaves.len() {
        return Err(PrivateHnswClientError::InvalidBuildConfig("leaves"));
    }

    let bucket_count = private_hnsw_oram_bucket_count(config.tree_height)?;
    let bucket_count_usize: usize = bucket_count
        .try_into()
        .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
    let mut buckets = Vec::with_capacity(bucket_count_usize);
    for bucket_id in 0..bucket_count {
        buckets.push(empty_private_hnsw_oram_plaintext_bucket(bucket_id, config)?);
    }

    let mut state = PrivateHnswOramClientState::new();
    let mut seen_nodes = BTreeSet::new();
    for (block, leaf) in blocks.iter().zip(leaves) {
        if !seen_nodes.insert(block.node_id) {
            return Err(PrivateHnswClientError::DuplicateBlock);
        }
        validate_private_hnsw_oram_leaf(*leaf, config.tree_height)?;
        encode_private_hnsw_node_block(
            block,
            config.block_size_bytes,
            config.fixed_neighbor_slots,
        )?;
        state.insert_position(block.node_id, *leaf, config.tree_height)?;

        let mut placed = false;
        for bucket_id in private_hnsw_oram_bucket_ids_for_leaf(*leaf, config.tree_height)?
            .into_iter()
            .rev()
        {
            let bucket = buckets.get_mut(bucket_id as usize).ok_or(
                PrivateHnswClientError::BucketOutOfRange {
                    bucket_id,
                    bucket_count,
                },
            )?;
            if let Some(slot) = bucket.blocks.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(block.clone());
                placed = true;
                break;
            }
        }
        if !placed {
            return Err(PrivateHnswClientError::OramInitialPlacementOverflow { leaf: *leaf });
        }
    }

    let logical_node_count: u64 = blocks
        .len()
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBuildConfig("blocks"))?;
    let capacity = bucket_count
        .checked_mul(config.bucket_size as u64)
        .ok_or(PrivateHnswClientError::BucketCountMismatch)?;
    let dummy_node_count = capacity
        .checked_sub(logical_node_count)
        .ok_or(PrivateHnswClientError::BucketCountMismatch)?;

    Ok(PrivateHnswPlaintextIndexBuild {
        entry_node_id: blocks[0].node_id,
        state,
        buckets,
        logical_node_count,
        dummy_node_count,
    })
}

pub fn encode_private_hnsw_oram_bucket_plaintext(
    bucket: &PrivateHnswOramPlaintextBucket,
    config: PrivateHnswOramClientConfig,
) -> Result<Vec<u8>, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    if bucket.blocks.len() != config.bucket_size {
        return Err(PrivateHnswClientError::BucketPlaintextSlotCountMismatch);
    }
    let bucket_size_u32: u32 = config
        .bucket_size
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidOramClientConfig("bucket_size"))?;
    let block_size_u32: u32 = config
        .block_size_bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidOramClientConfig("block_size_bytes"))?;

    let mut encoded = Vec::with_capacity(
        BUCKET_PLAINTEXT_MAGIC.len()
            + 2
            + 4
            + 4
            + config.bucket_size * (1 + config.block_size_bytes),
    );
    encoded.extend_from_slice(BUCKET_PLAINTEXT_MAGIC);
    push_u16(&mut encoded, BUCKET_PLAINTEXT_VERSION);
    push_u32(&mut encoded, bucket_size_u32);
    push_u32(&mut encoded, block_size_u32);

    for slot in &bucket.blocks {
        match slot {
            Some(block) => {
                encoded.push(1);
                encoded.extend_from_slice(&encode_private_hnsw_node_block(
                    block,
                    config.block_size_bytes,
                    config.fixed_neighbor_slots,
                )?);
            }
            None => {
                encoded.push(0);
                encoded.resize(encoded.len() + config.block_size_bytes, 0);
            }
        }
    }
    Ok(encoded)
}

pub fn decode_private_hnsw_oram_bucket_plaintext(
    bucket_id: u64,
    encoded: &[u8],
    config: PrivateHnswOramClientConfig,
) -> Result<PrivateHnswOramPlaintextBucket, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    let expected_len = BUCKET_PLAINTEXT_MAGIC
        .len()
        .checked_add(2)
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(4))
        .and_then(|len| {
            config
                .bucket_size
                .checked_mul(1 + config.block_size_bytes)
                .and_then(|slots_len| len.checked_add(slots_len))
        })
        .ok_or(PrivateHnswClientError::InvalidOramClientConfig(
            "bucket_size",
        ))?;
    if encoded.len() != expected_len {
        return Err(PrivateHnswClientError::InvalidBucketPlaintext);
    }

    let mut cursor = 0;
    let magic = read_exact(encoded, &mut cursor, BUCKET_PLAINTEXT_MAGIC.len())?;
    if magic != BUCKET_PLAINTEXT_MAGIC {
        return Err(PrivateHnswClientError::InvalidBucketPlaintext);
    }
    let version = read_u16(encoded, &mut cursor)?;
    if version != BUCKET_PLAINTEXT_VERSION {
        return Err(PrivateHnswClientError::InvalidBucketPlaintext);
    }
    let encoded_bucket_size = read_u32(encoded, &mut cursor)? as usize;
    let encoded_block_size = read_u32(encoded, &mut cursor)? as usize;
    if encoded_bucket_size != config.bucket_size || encoded_block_size != config.block_size_bytes {
        return Err(PrivateHnswClientError::BucketPlaintextMetadataMismatch);
    }

    let mut blocks = Vec::with_capacity(config.bucket_size);
    for _ in 0..config.bucket_size {
        let occupied = read_u8(encoded, &mut cursor)?;
        let block_bytes = read_exact(encoded, &mut cursor, config.block_size_bytes)?;
        match occupied {
            0 => {
                if block_bytes.iter().any(|byte| *byte != 0) {
                    return Err(PrivateHnswClientError::InvalidBucketPlaintext);
                }
                blocks.push(None);
            }
            1 => blocks.push(Some(decode_private_hnsw_node_block(block_bytes)?)),
            _ => return Err(PrivateHnswClientError::InvalidBucketPlaintext),
        }
    }

    Ok(PrivateHnswOramPlaintextBucket { bucket_id, blocks })
}

pub fn open_private_hnsw_oram_plaintext_bucket(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    bucket: &PrivateHnswOramBucket,
    config: PrivateHnswOramClientConfig,
) -> Result<PrivateHnswOramPlaintextBucket, PrivateHnswClientError> {
    let plaintext = open_private_hnsw_oram_bucket(
        keys,
        base_context.for_bucket(bucket.bucket_id, bucket.index_epoch),
        bucket,
    )?;
    decode_private_hnsw_oram_bucket_plaintext(bucket.bucket_id, &plaintext, config)
}

pub fn open_private_hnsw_oram_verified_path_batch(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    config: PrivateHnswOramClientConfig,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    proof_value: &str,
    buckets: &[PrivateHnswOramBucket],
) -> Result<Vec<PrivateHnswOramPlaintextBucket>, PrivateHnswClientError> {
    verify_private_hnsw_oram_merkle_proof_json(
        proof_value,
        expected_epoch,
        expected_root_hash,
        expected_bucket_count,
        buckets,
    )?;
    buckets
        .iter()
        .map(|bucket| open_private_hnsw_oram_plaintext_bucket(keys, base_context, bucket, config))
        .collect()
}

pub fn seal_private_hnsw_oram_plaintext_bucket(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    index_epoch: u64,
    bucket: &PrivateHnswOramPlaintextBucket,
    config: PrivateHnswOramClientConfig,
) -> Result<PrivateHnswOramBucket, PrivateHnswClientError> {
    let plaintext = encode_private_hnsw_oram_bucket_plaintext(bucket, config)?;
    seal_private_hnsw_oram_bucket(
        keys,
        base_context.for_bucket(bucket.bucket_id, index_epoch),
        &plaintext,
    )
}

pub fn access_private_hnsw_oram_path(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    target_node_id: [u8; 32],
    path_buckets: &[PrivateHnswOramPlaintextBucket],
    remap_leaf: u64,
) -> Result<PrivateHnswOramAccessResult, PrivateHnswClientError> {
    validate_oram_client_config(config)?;
    let old_leaf = state
        .position(&target_node_id)
        .ok_or(PrivateHnswClientError::MissingPosition)?;
    validate_private_hnsw_oram_leaf(remap_leaf, config.tree_height)?;
    let expected_bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(old_leaf, config.tree_height)?;
    if path_buckets.len() != expected_bucket_ids.len()
        || path_buckets
            .iter()
            .zip(&expected_bucket_ids)
            .any(|(bucket, expected_id)| bucket.bucket_id != *expected_id)
    {
        return Err(PrivateHnswClientError::PathBucketMismatch);
    }

    for bucket in path_buckets {
        if bucket.blocks.len() != config.bucket_size {
            return Err(PrivateHnswClientError::BucketPlaintextSlotCountMismatch);
        }
        for block in bucket.blocks.iter().flatten() {
            if state.stash.contains_key(&block.node_id) {
                return Err(PrivateHnswClientError::DuplicateBlock);
            }
            state.stash.insert(block.node_id, block.clone());
        }
    }

    let block = state
        .stash
        .get(&target_node_id)
        .cloned()
        .ok_or(PrivateHnswClientError::MissingBlock)?;
    state.position_map.insert(target_node_id, remap_leaf);

    let mut writeback_by_bucket = BTreeMap::new();
    for bucket_id in expected_bucket_ids.iter().rev() {
        let mut blocks = Vec::with_capacity(config.bucket_size);
        while blocks.len() < config.bucket_size {
            let candidate_node_id = state.stash.keys().copied().find(|node_id| {
                let Some(leaf) = state.position_map.get(node_id) else {
                    return false;
                };
                private_hnsw_oram_bucket_ids_for_leaf(*leaf, config.tree_height)
                    .map(|path| path.contains(bucket_id))
                    .unwrap_or(false)
            });
            let Some(candidate_node_id) = candidate_node_id else {
                break;
            };
            let block = state
                .stash
                .remove(&candidate_node_id)
                .ok_or(PrivateHnswClientError::MissingBlock)?;
            blocks.push(Some(block));
        }
        blocks.resize(config.bucket_size, None);
        writeback_by_bucket.insert(
            *bucket_id,
            PrivateHnswOramPlaintextBucket {
                bucket_id: *bucket_id,
                blocks,
            },
        );
    }

    let writeback_buckets = expected_bucket_ids
        .iter()
        .map(|bucket_id| {
            writeback_by_bucket
                .remove(bucket_id)
                .ok_or(PrivateHnswClientError::PathBucketMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PrivateHnswOramAccessResult {
        old_leaf,
        new_leaf: remap_leaf,
        old_leaf_label: encode_private_hnsw_oram_leaf_label(old_leaf, config.tree_height)?,
        block,
        writeback_buckets,
    })
}

pub fn search_private_hnsw_oram_plaintext<ReadPath, WriteBack, NextLeaf>(
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    mut next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<Vec<PrivateHnswOramPlaintextBucket>, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramPlaintextBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    validate_oram_client_config(config)?;
    validate_search_params(query, params)?;

    let mut pending = vec![params.entry_node_id];
    let mut queued = BTreeSet::from([params.entry_node_id]);
    let mut visited = BTreeSet::new();
    let mut hits = Vec::new();
    let mut accessed_leaf_labels = Vec::new();

    'search: for _ in 0..params.fixed_steps {
        let (node_id, padding_access) = loop {
            if hits.len() < params.ef {
                if !pending.is_empty() {
                    let candidate_node_id = pending.remove(0);
                    queued.remove(&candidate_node_id);
                    if visited.insert(candidate_node_id) {
                        break (candidate_node_id, false);
                    }
                    continue;
                }
            }

            let Some(padding_node_id) = params.padding_node_id else {
                break 'search;
            };
            break (padding_node_id, true);
        };

        let old_leaf = state
            .position(&node_id)
            .ok_or(PrivateHnswClientError::MissingPosition)?;
        let path_buckets = read_path(old_leaf)?;
        let access = access_private_hnsw_oram_path(
            state,
            config,
            node_id,
            &path_buckets,
            next_remap_leaf()?,
        )?;
        writeback(&access.writeback_buckets)?;
        accessed_leaf_labels.push(access.old_leaf_label);

        if padding_access || access.block.deleted {
            continue;
        }

        let vector = decode_f32_le_vector(&access.block)?;
        let distance = private_hnsw_distance(query, &vector, params.distance)?;
        hits.push(PrivateHnswSearchHit {
            node_id: access.block.node_id,
            point_token: access.block.point_token,
            distance,
        });
        sort_hits(&mut hits);
        hits.truncate(params.ef);

        for neighbor_id in &access.block.neighbors {
            if !visited.contains(neighbor_id) && queued.insert(*neighbor_id) {
                if state.position(neighbor_id).is_some() {
                    pending.push(*neighbor_id);
                }
            }
        }
    }

    sort_hits(&mut hits);
    hits.truncate(params.k);
    let completed_steps = accessed_leaf_labels.len();

    Ok(PrivateHnswSearchResult {
        hits,
        accessed_leaf_labels,
        completed_steps,
    })
}

pub fn search_private_hnsw_oram_encrypted<ReadPath, WriteBack, NextLeaf>(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    writeback_epoch: u64,
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<Vec<PrivateHnswOramBucket>, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    search_private_hnsw_oram_plaintext(
        state,
        config,
        query,
        params,
        |leaf| {
            read_path(leaf)?
                .into_iter()
                .map(|bucket| {
                    open_private_hnsw_oram_plaintext_bucket(keys, base_context, &bucket, config)
                })
                .collect()
        },
        |writeback_buckets| {
            let encrypted_buckets = writeback_buckets
                .iter()
                .map(|bucket| {
                    seal_private_hnsw_oram_plaintext_bucket(
                        keys,
                        base_context,
                        writeback_epoch,
                        bucket,
                        config,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            writeback(&encrypted_buckets)
        },
        next_remap_leaf,
    )
}

pub fn search_private_hnsw_oram_encrypted_verified<ReadPath, WriteBack, NextLeaf>(
    keys: &PrivateHnswClientKeys,
    base_context: PrivateHnswBucketAeadBaseContext<'_>,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    writeback_epoch: u64,
    state: &mut PrivateHnswOramClientState,
    config: PrivateHnswOramClientConfig,
    query: &[f32],
    params: PrivateHnswSearchParams,
    mut read_path: ReadPath,
    mut writeback: WriteBack,
    next_remap_leaf: NextLeaf,
) -> Result<PrivateHnswSearchResult, PrivateHnswClientError>
where
    ReadPath: FnMut(u64) -> Result<PrivateHnswEncryptedPathBatch, PrivateHnswClientError>,
    WriteBack: FnMut(&[PrivateHnswOramBucket]) -> Result<(), PrivateHnswClientError>,
    NextLeaf: FnMut() -> Result<u64, PrivateHnswClientError>,
{
    search_private_hnsw_oram_plaintext(
        state,
        config,
        query,
        params,
        |leaf| {
            let batch = read_path(leaf)?;
            if batch.index_epoch != expected_epoch
                || batch.root_hash != expected_root_hash
                || batch.bucket_count != expected_bucket_count
            {
                return Err(PrivateHnswClientError::MerkleProofMismatch);
            }
            open_private_hnsw_oram_verified_path_batch(
                keys,
                base_context,
                config,
                expected_epoch,
                expected_root_hash,
                expected_bucket_count,
                &batch.proof_value,
                &batch.buckets,
            )
        },
        |writeback_buckets| {
            let encrypted_buckets = writeback_buckets
                .iter()
                .map(|bucket| {
                    seal_private_hnsw_oram_plaintext_bucket(
                        keys,
                        base_context,
                        writeback_epoch,
                        bucket,
                        config,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            writeback(&encrypted_buckets)
        },
        next_remap_leaf,
    )
}

pub fn private_hnsw_oram_merkle_root_for_commitments(
    commitments: &[String],
) -> Result<String, PrivateHnswClientError> {
    let levels = private_hnsw_oram_merkle_levels(commitments)?;
    let root = levels
        .last()
        .and_then(|level| level.first())
        .ok_or(PrivateHnswClientError::EmptyMerkleTree)?;
    Ok(BASE64URL_NOPAD.encode(root))
}

pub fn verify_private_hnsw_oram_merkle_proof_json(
    proof_value: &str,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    buckets: &[PrivateHnswOramBucket],
) -> Result<(), PrivateHnswClientError> {
    let proof: PrivateHnswOramMerkleProof = serde_json::from_str(proof_value)
        .map_err(|_| PrivateHnswClientError::InvalidMerkleProofJson)?;
    verify_private_hnsw_oram_merkle_proof(
        &proof,
        expected_epoch,
        expected_root_hash,
        expected_bucket_count,
        buckets,
    )
}

pub fn verify_private_hnsw_oram_merkle_proof(
    proof: &PrivateHnswOramMerkleProof,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    buckets: &[PrivateHnswOramBucket],
) -> Result<(), PrivateHnswClientError> {
    if expected_bucket_count == 0
        || proof.kind != PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND
        || proof.index_epoch != expected_epoch
        || proof.bucket_count != expected_bucket_count
        || proof.leaves.len() != buckets.len()
    {
        return Err(PrivateHnswClientError::InvalidMerkleProof);
    }

    let expected_root = decode_merkle_root(expected_root_hash)?;
    let proof_root = decode_merkle_root(&proof.root_hash)?;
    if proof_root != expected_root {
        return Err(PrivateHnswClientError::MerkleProofMismatch);
    }

    let mut buckets_by_id = BTreeMap::new();
    for bucket in buckets {
        if bucket.version != 1
            || bucket.index_epoch != expected_epoch
            || bucket.bucket_id >= expected_bucket_count
        {
            return Err(PrivateHnswClientError::InvalidMerkleProof);
        }
        decode_bucket_commitment(&bucket.bucket_commitment)?;
        if buckets_by_id.insert(bucket.bucket_id, bucket).is_some() {
            return Err(PrivateHnswClientError::InvalidMerkleProof);
        }
    }

    let mut seen_leaves = BTreeSet::new();
    for leaf in &proof.leaves {
        if leaf.bucket_id >= expected_bucket_count || !seen_leaves.insert(leaf.bucket_id) {
            return Err(PrivateHnswClientError::InvalidMerkleProof);
        }
        let Some(bucket) = buckets_by_id.get(&leaf.bucket_id) else {
            return Err(PrivateHnswClientError::MerkleProofMismatch);
        };
        if bucket.bucket_commitment != leaf.leaf_hash {
            return Err(PrivateHnswClientError::MerkleProofMismatch);
        }

        let mut node_hash = decode_merkle_proof_hash(&leaf.leaf_hash)?;
        let mut index = leaf.bucket_id;
        for (expected_level, sibling) in leaf.siblings.iter().enumerate() {
            if sibling.level != expected_level as u32 {
                return Err(PrivateHnswClientError::InvalidMerkleProof);
            }
            let sibling_hash = decode_merkle_proof_hash(&sibling.hash)?;
            let expected_position = if index % 2 == 0 {
                PrivateHnswMerkleSiblingPosition::Right
            } else {
                PrivateHnswMerkleSiblingPosition::Left
            };
            if sibling.position != expected_position {
                return Err(PrivateHnswClientError::InvalidMerkleProof);
            }
            node_hash = match sibling.position {
                PrivateHnswMerkleSiblingPosition::Left => {
                    private_hnsw_oram_merkle_parent_hash(&sibling_hash, &node_hash)
                }
                PrivateHnswMerkleSiblingPosition::Right => {
                    private_hnsw_oram_merkle_parent_hash(&node_hash, &sibling_hash)
                }
            };
            index /= 2;
        }
        if node_hash != expected_root {
            return Err(PrivateHnswClientError::MerkleProofMismatch);
        }
    }

    Ok(())
}

pub fn plan_private_hnsw_oram_commit(
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateHnswOramBucket],
) -> Result<PrivateHnswClientCommitPlan, PrivateHnswClientError> {
    if new_epoch <= old_epoch {
        return Err(PrivateHnswClientError::InvalidCommitEpoch);
    }
    if updated_buckets.is_empty() {
        return Err(PrivateHnswClientError::EmptyCommit);
    }
    decode_merkle_root(old_root_hash)?;
    let computed_old_root =
        private_hnsw_oram_merkle_root_for_commitments(current_leaf_commitments)?;
    if computed_old_root != old_root_hash {
        return Err(PrivateHnswClientError::MerkleRootMismatch);
    }

    let bucket_count = u64::try_from(current_leaf_commitments.len())
        .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
    let mut next_leaf_commitments = current_leaf_commitments.to_vec();
    let mut seen_bucket_ids = BTreeSet::new();
    let mut commit_bucket_refs = Vec::with_capacity(updated_buckets.len());

    for bucket in updated_buckets {
        if bucket.version != 1 {
            return Err(PrivateHnswClientError::UnsupportedBucketVersion(
                bucket.version,
            ));
        }
        if bucket.index_epoch != new_epoch {
            return Err(PrivateHnswClientError::StaleBucketEpoch {
                bucket_id: bucket.bucket_id,
                expected_epoch: new_epoch,
                actual_epoch: bucket.index_epoch,
            });
        }
        if bucket.bucket_id >= bucket_count {
            return Err(PrivateHnswClientError::BucketOutOfRange {
                bucket_id: bucket.bucket_id,
                bucket_count,
            });
        }
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateHnswClientError::DuplicateUpdatedBucket {
                bucket_id: bucket.bucket_id,
            });
        }
        decode_bucket_ciphertext_hash(&bucket.ciphertext_sha256)?;
        decode_bucket_commitment(&bucket.bucket_commitment)?;

        let bucket_index = usize::try_from(bucket.bucket_id)
            .map_err(|_| PrivateHnswClientError::BucketCountMismatch)?;
        next_leaf_commitments[bucket_index] = bucket.bucket_commitment.clone();
        commit_bucket_refs.push(PrivateHnswClientCommitBucketRef {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        });
    }

    let new_root_hash = private_hnsw_oram_merkle_root_for_commitments(&next_leaf_commitments)?;
    Ok(PrivateHnswClientCommitPlan {
        old_epoch,
        new_epoch,
        old_root_hash: old_root_hash.to_string(),
        new_root_hash,
        leaf_commitments: next_leaf_commitments,
        updated_buckets: commit_bucket_refs,
    })
}

pub fn sign_private_hnsw_oram_commit(
    key_pair: &Ed25519KeyPair,
    context: PrivateHnswCommitSignatureContext<'_>,
    plan: &PrivateHnswClientCommitPlan,
) -> Result<PrivateHnswOramSignature, PrivateHnswClientError> {
    validate_commit_signature_context(context)?;
    let bucket_refs = plan.signature_bucket_refs();
    let input = PrivateHnswOramCommitSignatureInput {
        collection_id: context.collection_id,
        vector_name: context.vector_name,
        key_id: context.key_id,
        rk_id: context.rk_id,
        rk_epoch: context.rk_epoch,
        old_epoch: plan.old_epoch,
        new_epoch: plan.new_epoch,
        old_root_hash: &plan.old_root_hash,
        new_root_hash: &plan.new_root_hash,
        updated_buckets: &bucket_refs,
        signature_alg: "ed25519",
        signature_key_id: context.signing_key_id,
    };
    let message = private_hnsw_oram_commit_signature_message(input);
    let signature = key_pair.sign(&message);
    Ok(PrivateHnswOramSignature {
        alg: "ed25519".to_string(),
        key_id: context.signing_key_id.to_string(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn sign_private_hnsw_oram_manifest(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateHnswOramManifest,
) -> Result<PrivateHnswOramSignature, PrivateHnswClientError> {
    validate_resource_key_id(&manifest.owner_signing_key_id).map_err(|_| {
        PrivateHnswClientError::InvalidManifestSignatureContext("owner_signing_key_id")
    })?;
    let message = private_hnsw_oram_manifest_signature_message(manifest);
    let signature = key_pair.sign(&message);
    Ok(PrivateHnswOramSignature {
        alg: "ed25519".to_string(),
        key_id: manifest.owner_signing_key_id.clone(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn encode_private_hnsw_node_block(
    block: &PrivateHnswNodeBlockPlaintext,
    block_size_bytes: usize,
    fixed_neighbor_slots: usize,
) -> Result<Vec<u8>, PrivateHnswClientError> {
    if block.neighbors.len() != block.neighbor_levels.len() {
        return Err(PrivateHnswClientError::InvalidNeighborShape);
    }
    if block.neighbors.len() > fixed_neighbor_slots {
        return Err(PrivateHnswClientError::TooManyNeighbors {
            actual: block.neighbors.len(),
            limit: fixed_neighbor_slots,
        });
    }
    let vector_len: u32 = block
        .vector
        .len()
        .try_into()
        .map_err(|_| PrivateHnswClientError::VectorTooLarge)?;
    let fixed_neighbor_slots_u32: u32 = fixed_neighbor_slots
        .try_into()
        .map_err(|_| PrivateHnswClientError::FixedNeighborSlotsTooLarge)?;

    let mut encoded = Vec::new();
    encoded.extend_from_slice(NODE_BLOCK_MAGIC);
    push_u16(&mut encoded, NODE_BLOCK_VERSION);
    encoded.extend_from_slice(&block.node_id);
    encoded.extend_from_slice(&block.point_token);
    push_u64(&mut encoded, block.level_mask);
    encoded.push(block.vector_encoding.tag());
    encoded.push(u8::from(block.deleted));
    push_u64(&mut encoded, block.generation);
    match block.payload_fetch_token {
        Some(token) => {
            encoded.push(1);
            encoded.extend_from_slice(&token);
        }
        None => {
            encoded.push(0);
            encoded.extend_from_slice(&[0; 32]);
        }
    }
    push_u32(&mut encoded, block.neighbors.len() as u32);
    push_u32(&mut encoded, fixed_neighbor_slots_u32);
    push_u32(&mut encoded, vector_len);
    encoded.extend_from_slice(&block.vector);

    for (neighbor, level) in block.neighbors.iter().zip(&block.neighbor_levels) {
        encoded.extend_from_slice(neighbor);
        encoded.push(*level);
    }
    for _ in block.neighbors.len()..fixed_neighbor_slots {
        encoded.extend_from_slice(&[0; 32]);
        encoded.push(0);
    }

    if encoded.len() > block_size_bytes {
        return Err(PrivateHnswClientError::EncodedBlockOversized);
    }
    encoded.resize(block_size_bytes, 0);
    Ok(encoded)
}

pub fn decode_private_hnsw_node_block(
    encoded: &[u8],
) -> Result<PrivateHnswNodeBlockPlaintext, PrivateHnswClientError> {
    let mut cursor = 0;
    let magic = read_exact(encoded, &mut cursor, NODE_BLOCK_MAGIC.len())?;
    if magic != NODE_BLOCK_MAGIC {
        return Err(PrivateHnswClientError::InvalidBlockEncoding);
    }
    let version = read_u16(encoded, &mut cursor)?;
    if version != NODE_BLOCK_VERSION {
        return Err(PrivateHnswClientError::UnsupportedBlockVersion(version));
    }
    let node_id = read_array_32(encoded, &mut cursor)?;
    let point_token = read_array_32(encoded, &mut cursor)?;
    let level_mask = read_u64(encoded, &mut cursor)?;
    let vector_encoding = PrivateHnswVectorEncoding::from_tag(read_u8(encoded, &mut cursor)?)?;
    let deleted = match read_u8(encoded, &mut cursor)? {
        0 => false,
        1 => true,
        _ => return Err(PrivateHnswClientError::InvalidBlockEncoding),
    };
    let generation = read_u64(encoded, &mut cursor)?;
    let payload_present = read_u8(encoded, &mut cursor)?;
    let payload_token = read_array_32(encoded, &mut cursor)?;
    let payload_fetch_token = match payload_present {
        0 => {
            if payload_token != [0; 32] {
                return Err(PrivateHnswClientError::InvalidBlockPadding);
            }
            None
        }
        1 => Some(payload_token),
        _ => return Err(PrivateHnswClientError::InvalidBlockEncoding),
    };

    let neighbor_count = read_u32(encoded, &mut cursor)? as usize;
    let fixed_neighbor_slots = read_u32(encoded, &mut cursor)? as usize;
    if neighbor_count > fixed_neighbor_slots {
        return Err(PrivateHnswClientError::TooManyNeighbors {
            actual: neighbor_count,
            limit: fixed_neighbor_slots,
        });
    }
    let vector_len = read_u32(encoded, &mut cursor)? as usize;
    let vector = read_exact(encoded, &mut cursor, vector_len)?.to_vec();

    let mut neighbors = Vec::with_capacity(neighbor_count);
    let mut neighbor_levels = Vec::with_capacity(neighbor_count);
    for slot in 0..fixed_neighbor_slots {
        let neighbor = read_array_32(encoded, &mut cursor)?;
        let level = read_u8(encoded, &mut cursor)?;
        if slot < neighbor_count {
            neighbors.push(neighbor);
            neighbor_levels.push(level);
        } else if neighbor != [0; 32] || level != 0 {
            return Err(PrivateHnswClientError::InvalidBlockPadding);
        }
    }

    if encoded[cursor..].iter().any(|byte| *byte != 0) {
        return Err(PrivateHnswClientError::InvalidBlockPadding);
    }

    Ok(PrivateHnswNodeBlockPlaintext {
        version,
        node_id,
        point_token,
        level_mask,
        vector_encoding,
        vector,
        neighbors,
        neighbor_levels,
        deleted,
        generation,
        payload_fetch_token,
    })
}

pub fn seal_private_hnsw_oram_bucket(
    keys: &PrivateHnswClientKeys,
    context: PrivateHnswBucketAeadContext<'_>,
    plaintext: &[u8],
) -> Result<PrivateHnswOramBucket, PrivateHnswClientError> {
    validate_bucket_context(context)?;

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; BUCKET_AEAD_NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| EncryptionError::RandomFailure)?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.bucket_aead_key().as_bytes())
        .map_err(|_| EncryptionError::SealFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = private_hnsw_bucket_aead(context)?;
    let mut in_out = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad.as_slice()), &mut in_out)
        .map_err(|_| EncryptionError::SealFailed)?;
    in_out.extend_from_slice(tag.as_ref());

    let mut raw_ciphertext = Vec::with_capacity(1 + BUCKET_AEAD_NONCE_LEN + in_out.len());
    raw_ciphertext.push(BUCKET_AEAD_VERSION);
    raw_ciphertext.extend_from_slice(&nonce_bytes);
    raw_ciphertext.extend_from_slice(&in_out);

    let ciphertext_sha256 = base64url_sha256(&raw_ciphertext);
    let bucket_commitment = private_hnsw_bucket_commitment(context, &ciphertext_sha256)?;

    Ok(PrivateHnswOramBucket {
        version: 1,
        bucket_id: context.bucket_id,
        index_epoch: context.index_epoch,
        ciphertext: BASE64URL_NOPAD.encode(&raw_ciphertext),
        ciphertext_sha256,
        bucket_commitment,
    })
}

pub fn open_private_hnsw_oram_bucket(
    keys: &PrivateHnswClientKeys,
    context: PrivateHnswBucketAeadContext<'_>,
    bucket: &PrivateHnswOramBucket,
) -> Result<Vec<u8>, PrivateHnswClientError> {
    validate_bucket_context(context)?;
    if bucket.version != 1
        || bucket.bucket_id != context.bucket_id
        || bucket.index_epoch != context.index_epoch
    {
        return Err(PrivateHnswClientError::BucketMetadataMismatch);
    }

    let raw_ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextEncoding)?;
    if raw_ciphertext.len() < 1 + BUCKET_AEAD_NONCE_LEN + BUCKET_AEAD_TAG_LEN {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextEncoding);
    }
    let ciphertext_sha256 = base64url_sha256(&raw_ciphertext);
    if ciphertext_sha256 != bucket.ciphertext_sha256 {
        return Err(PrivateHnswClientError::InvalidBucketCiphertextHash);
    }
    let expected_commitment = private_hnsw_bucket_commitment(context, &bucket.ciphertext_sha256)?;
    if expected_commitment != bucket.bucket_commitment {
        return Err(PrivateHnswClientError::InvalidBucketCommitment);
    }
    if raw_ciphertext[0] != BUCKET_AEAD_VERSION {
        return Err(PrivateHnswClientError::UnsupportedBucketCiphertextVersion(
            raw_ciphertext[0],
        ));
    }

    let nonce_bytes: [u8; BUCKET_AEAD_NONCE_LEN] = raw_ciphertext[1..1 + BUCKET_AEAD_NONCE_LEN]
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextEncoding)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext = raw_ciphertext[1 + BUCKET_AEAD_NONCE_LEN..].to_vec();

    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.bucket_aead_key().as_bytes())
        .map_err(|_| EncryptionError::OpenFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let aad = private_hnsw_bucket_aead(context)?;
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext)
        .map_err(|_| PrivateHnswClientError::BucketOpenFailed)?;
    Ok(plaintext.to_vec())
}

pub fn private_hnsw_bucket_commitment(
    context: PrivateHnswBucketAeadContext<'_>,
    ciphertext_sha256: &str,
) -> Result<String, PrivateHnswClientError> {
    validate_bucket_context(context)?;
    let ciphertext_sha256_bytes = decode_bucket_ciphertext_hash(ciphertext_sha256)?;

    let mut message = Vec::new();
    append_len_prefixed(
        &mut message,
        PRIVATE_HNSW_BUCKET_COMMITMENT_DOMAIN.as_bytes(),
    );
    append_len_prefixed(&mut message, context.collection_id.as_bytes());
    append_len_prefixed(&mut message, context.vector_name.as_bytes());
    append_len_prefixed(&mut message, context.key_id.as_bytes());
    append_len_prefixed(&mut message, context.rk_id.as_bytes());
    message.extend_from_slice(&context.rk_epoch.to_be_bytes());
    message.extend_from_slice(&context.bucket_id.to_be_bytes());
    message.extend_from_slice(&context.index_epoch.to_be_bytes());
    message.extend_from_slice(&ciphertext_sha256_bytes);

    Ok(base64url_sha256(&message))
}

fn private_hnsw_bucket_aead(
    context: PrivateHnswBucketAeadContext<'_>,
) -> Result<Vec<u8>, PrivateHnswClientError> {
    validate_bucket_context(context)?;
    let mut aad = Vec::new();
    append_len_prefixed(&mut aad, PRIVATE_HNSW_BUCKET_AEAD_CONTEXT_DOMAIN.as_bytes());
    append_len_prefixed(&mut aad, context.collection_id.as_bytes());
    append_len_prefixed(&mut aad, context.vector_name.as_bytes());
    append_len_prefixed(&mut aad, context.key_id.as_bytes());
    append_len_prefixed(&mut aad, context.rk_id.as_bytes());
    aad.extend_from_slice(&context.rk_epoch.to_be_bytes());
    aad.extend_from_slice(&context.bucket_id.to_be_bytes());
    aad.extend_from_slice(&context.index_epoch.to_be_bytes());
    Ok(aad)
}

fn validate_bucket_context(
    context: PrivateHnswBucketAeadContext<'_>,
) -> Result<(), PrivateHnswClientError> {
    if context.collection_id.is_empty() {
        return Err(PrivateHnswClientError::InvalidBucketContext(
            "collection_id",
        ));
    }
    if context.vector_name.is_empty() {
        return Err(PrivateHnswClientError::InvalidBucketContext("vector_name"));
    }
    validate_resource_key_id(context.key_id)
        .map_err(|_| PrivateHnswClientError::InvalidBucketContext("key_id"))?;
    validate_resource_key_id(context.rk_id)
        .map_err(|_| PrivateHnswClientError::InvalidBucketContext("rk_id"))?;
    Ok(())
}

fn validate_commit_signature_context(
    context: PrivateHnswCommitSignatureContext<'_>,
) -> Result<(), PrivateHnswClientError> {
    if context.collection_id.is_empty() {
        return Err(PrivateHnswClientError::InvalidCommitSignatureContext(
            "collection_id",
        ));
    }
    if context.vector_name.is_empty() {
        return Err(PrivateHnswClientError::InvalidCommitSignatureContext(
            "vector_name",
        ));
    }
    validate_resource_key_id(context.key_id)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("key_id"))?;
    validate_resource_key_id(context.rk_id)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("rk_id"))?;
    validate_resource_key_id(context.signing_key_id)
        .map_err(|_| PrivateHnswClientError::InvalidCommitSignatureContext("signing_key_id"))?;
    Ok(())
}

fn validate_oram_client_config(
    config: PrivateHnswOramClientConfig,
) -> Result<(), PrivateHnswClientError> {
    private_hnsw_oram_bucket_count(config.tree_height)?;
    if config.bucket_size == 0 {
        return Err(PrivateHnswClientError::InvalidOramClientConfig(
            "bucket_size",
        ));
    }
    if config.block_size_bytes == 0 {
        return Err(PrivateHnswClientError::InvalidOramClientConfig(
            "block_size_bytes",
        ));
    }
    config
        .bucket_size
        .checked_mul(1 + config.block_size_bytes)
        .ok_or(PrivateHnswClientError::InvalidOramClientConfig(
            "bucket_size",
        ))?;
    Ok(())
}

fn validate_search_params(
    query: &[f32],
    params: PrivateHnswSearchParams,
) -> Result<(), PrivateHnswClientError> {
    if query.is_empty() {
        return Err(PrivateHnswClientError::InvalidSearchConfig("query"));
    }
    if query.iter().any(|value| !value.is_finite()) {
        return Err(PrivateHnswClientError::NonFiniteDistance);
    }
    if params.k == 0 {
        return Err(PrivateHnswClientError::InvalidSearchConfig("k"));
    }
    if params.ef < params.k {
        return Err(PrivateHnswClientError::InvalidSearchConfig("ef"));
    }
    if params.fixed_steps == 0 {
        return Err(PrivateHnswClientError::InvalidSearchConfig("fixed_steps"));
    }
    Ok(())
}

fn validate_private_hnsw_oram_leaf(
    leaf: u64,
    tree_height: u32,
) -> Result<(), PrivateHnswClientError> {
    if leaf >= private_hnsw_oram_leaf_count(tree_height)? {
        return Err(PrivateHnswClientError::LeafOutOfRange);
    }
    Ok(())
}

fn decode_f32_le_vector(
    block: &PrivateHnswNodeBlockPlaintext,
) -> Result<Vec<f32>, PrivateHnswClientError> {
    if block.vector_encoding != PrivateHnswVectorEncoding::F32Le {
        return Err(PrivateHnswClientError::UnsupportedSearchVectorEncoding);
    }
    let chunks = block.vector.chunks_exact(4);
    if !chunks.remainder().is_empty() {
        return Err(PrivateHnswClientError::InvalidF32VectorLength);
    }
    chunks
        .map(|chunk| {
            let bytes: [u8; 4] = chunk
                .try_into()
                .map_err(|_| PrivateHnswClientError::InvalidF32VectorLength)?;
            Ok(f32::from_le_bytes(bytes))
        })
        .collect()
}

fn private_hnsw_distance(
    query: &[f32],
    vector: &[f32],
    distance: DistanceKind,
) -> Result<f32, PrivateHnswClientError> {
    if query.len() != vector.len() {
        return Err(PrivateHnswClientError::VectorDimensionMismatch);
    }
    let value = match distance {
        DistanceKind::Euclid => query
            .iter()
            .zip(vector)
            .map(|(lhs, rhs)| {
                let delta = lhs - rhs;
                delta * delta
            })
            .sum(),
        DistanceKind::Manhattan => query
            .iter()
            .zip(vector)
            .map(|(lhs, rhs)| (lhs - rhs).abs())
            .sum(),
        DistanceKind::Dot => -query
            .iter()
            .zip(vector)
            .map(|(lhs, rhs)| lhs * rhs)
            .sum::<f32>(),
        DistanceKind::Cosine => {
            let dot = query
                .iter()
                .zip(vector)
                .map(|(lhs, rhs)| lhs * rhs)
                .sum::<f32>();
            let query_norm = query.iter().map(|value| value * value).sum::<f32>().sqrt();
            let vector_norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
            if query_norm == 0.0 || vector_norm == 0.0 {
                return Err(PrivateHnswClientError::NonFiniteDistance);
            }
            1.0 - dot / (query_norm * vector_norm)
        }
    };
    if value.is_finite() {
        Ok(value)
    } else {
        Err(PrivateHnswClientError::NonFiniteDistance)
    }
}

fn sort_hits(hits: &mut [PrivateHnswSearchHit]) {
    hits.sort_by(|lhs, rhs| {
        lhs.distance
            .total_cmp(&rhs.distance)
            .then_with(|| lhs.node_id.cmp(&rhs.node_id))
    });
}

fn decode_bucket_ciphertext_hash(value: &str) -> Result<[u8; 32], PrivateHnswClientError> {
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextHash)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBucketCiphertextHash)
}

fn decode_bucket_commitment(value: &str) -> Result<[u8; 32], PrivateHnswClientError> {
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidBucketCommitment)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBucketCommitment)
}

fn decode_merkle_root(value: &str) -> Result<[u8; 32], PrivateHnswClientError> {
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidMerkleRoot)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidMerkleRoot)
}

fn decode_merkle_proof_hash(value: &str) -> Result<[u8; 32], PrivateHnswClientError> {
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateHnswClientError::InvalidMerkleProof)?;
    bytes
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidMerkleProof)
}

fn private_hnsw_oram_merkle_levels(
    commitments: &[String],
) -> Result<Vec<Vec<[u8; 32]>>, PrivateHnswClientError> {
    if commitments.is_empty() {
        return Err(PrivateHnswClientError::EmptyMerkleTree);
    }
    let mut leaves = commitments
        .iter()
        .map(|commitment| decode_bucket_commitment(commitment))
        .collect::<Result<Vec<_>, _>>()?;
    let padded_len = leaves
        .len()
        .checked_next_power_of_two()
        .ok_or(PrivateHnswClientError::BucketCountMismatch)?;
    leaves.resize(padded_len, [0; 32]);

    let mut levels = vec![leaves];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let previous = levels.last().expect("checked above");
        let mut next = Vec::with_capacity(previous.len() / 2);
        for pair in previous.chunks_exact(2) {
            next.push(private_hnsw_oram_merkle_parent_hash(&pair[0], &pair[1]));
        }
        levels.push(next);
    }
    Ok(levels)
}

fn private_hnsw_oram_merkle_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn base64url_sha256(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(Sha256::digest(bytes).as_ref())
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_exact<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], PrivateHnswClientError> {
    let end = cursor
        .checked_add(len)
        .ok_or(PrivateHnswClientError::InvalidBlockEncoding)?;
    if end > bytes.len() {
        return Err(PrivateHnswClientError::InvalidBlockEncoding);
    }
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, PrivateHnswClientError> {
    Ok(read_exact(bytes, cursor, 1)?[0])
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, PrivateHnswClientError> {
    let value: [u8; 2] = read_exact(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBlockEncoding)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, PrivateHnswClientError> {
    let value: [u8; 4] = read_exact(bytes, cursor, 4)?
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBlockEncoding)?;
    Ok(u32::from_be_bytes(value))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, PrivateHnswClientError> {
    let value: [u8; 8] = read_exact(bytes, cursor, 8)?
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBlockEncoding)?;
    Ok(u64::from_be_bytes(value))
}

fn read_array_32(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 32], PrivateHnswClientError> {
    read_exact(bytes, cursor, 32)?
        .try_into()
        .map_err(|_| PrivateHnswClientError::InvalidBlockEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> PrivateHnswClientKeys {
        let resource_key = SecretKey::from_bytes([7; 32]);
        PrivateHnswClientKeys::derive_from_resource_key(&resource_key).unwrap()
    }

    fn bucket_context(bucket_id: u64) -> PrivateHnswBucketAeadContext<'static> {
        bucket_base_context().for_bucket(bucket_id, 42)
    }

    fn bucket_base_context() -> PrivateHnswBucketAeadBaseContext<'static> {
        PrivateHnswBucketAeadBaseContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
        }
    }

    fn commitment(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn fixture_commit_bucket(
        bucket_id: u64,
        index_epoch: u64,
        commitment_byte: u8,
        hash_byte: u8,
    ) -> PrivateHnswOramBucket {
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch,
            ciphertext: BASE64URL_NOPAD.encode(&[hash_byte; 48]),
            ciphertext_sha256: BASE64URL_NOPAD.encode(&[hash_byte; 32]),
            bucket_commitment: commitment(commitment_byte),
        }
    }

    fn proof_sibling(
        level: u32,
        position: PrivateHnswMerkleSiblingPosition,
        hash: String,
    ) -> PrivateHnswOramMerkleSibling {
        PrivateHnswOramMerkleSibling {
            level,
            position,
            hash,
        }
    }

    fn proof_for_bucket_ids(
        bucket_ids: &[u64],
        index_epoch: u64,
        root_hash: String,
        commitments: &[String],
    ) -> PrivateHnswOramMerkleProof {
        let levels = private_hnsw_oram_merkle_levels(commitments).unwrap();
        let leaves = bucket_ids
            .iter()
            .map(|bucket_id| {
                let mut index = *bucket_id as usize;
                let siblings = levels
                    .iter()
                    .enumerate()
                    .take(levels.len().saturating_sub(1))
                    .map(|(level, level_hashes)| {
                        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
                        let position = if index % 2 == 0 {
                            PrivateHnswMerkleSiblingPosition::Right
                        } else {
                            PrivateHnswMerkleSiblingPosition::Left
                        };
                        index /= 2;
                        proof_sibling(
                            level as u32,
                            position,
                            BASE64URL_NOPAD.encode(&level_hashes[sibling_index]),
                        )
                    })
                    .collect();
                PrivateHnswOramMerkleProofLeaf {
                    bucket_id: *bucket_id,
                    leaf_hash: commitments[*bucket_id as usize].clone(),
                    siblings,
                }
            })
            .collect();

        PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch,
            root_hash,
            bucket_count: commitments.len() as u64,
            leaves,
        }
    }

    fn fixture_manifest() -> crate::private_hnsw_oram::PrivateHnswOramManifest {
        use crate::control_plane::{PRIVATE_HNSW_ORAM_BINDING, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER};
        use crate::private_hnsw_oram::{
            FixedBudgetParams, OramKind, OramParams, PrivateHnswOramManifest, PrivateHnswParams,
            ResultPrivacyMode,
        };

        PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            vector_name: "text".to_string(),
            key_id: "tenant-a/vector-private-rk".to_string(),
            rk_id: "tenant-a/vector-private-rk".to_string(),
            rk_epoch: 7,
            dim: 1536,
            distance: DistanceKind::Cosine,
            hnsw: PrivateHnswParams {
                m: 32,
                ef_construction: 128,
                max_layers: 16,
                fixed_neighbor_slots: 64,
            },
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 8192,
                tree_height: 24,
                path_batch_size: 8,
            },
            fixed_budget: FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 32,
                base_layer_steps: 256,
                paths_per_round: 8,
                fixed_result_k: 10,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: 1 << 20,
            logical_node_count: 500_000,
            dummy_node_count: 24_288,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn node_block() -> PrivateHnswNodeBlockPlaintext {
        PrivateHnswNodeBlockPlaintext {
            version: NODE_BLOCK_VERSION,
            node_id: [1; 32],
            point_token: [2; 32],
            level_mask: 0b101,
            vector_encoding: PrivateHnswVectorEncoding::F32Le,
            vector: vec![0, 0, 128, 63, 0, 0, 0, 64],
            neighbors: vec![[3; 32], [4; 32]],
            neighbor_levels: vec![1, 0],
            deleted: false,
            generation: 9,
            payload_fetch_token: Some([5; 32]),
        }
    }

    fn node_block_with_id(id: u8) -> PrivateHnswNodeBlockPlaintext {
        let mut block = node_block();
        block.node_id = [id; 32];
        block.point_token = [id.wrapping_add(20); 32];
        block.payload_fetch_token = None;
        block
    }

    fn node_block_with_vector(
        id: u8,
        vector: &[f32],
        neighbors: Vec<[u8; 32]>,
    ) -> PrivateHnswNodeBlockPlaintext {
        PrivateHnswNodeBlockPlaintext {
            version: NODE_BLOCK_VERSION,
            node_id: [id; 32],
            point_token: [id.wrapping_add(20); 32],
            level_mask: 1,
            vector_encoding: PrivateHnswVectorEncoding::F32Le,
            vector: vector
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect(),
            neighbor_levels: vec![0; neighbors.len()],
            neighbors,
            deleted: false,
            generation: 1,
            payload_fetch_token: None,
        }
    }

    fn oram_config() -> PrivateHnswOramClientConfig {
        PrivateHnswOramClientConfig {
            tree_height: 2,
            bucket_size: 1,
            block_size_bytes: 512,
            fixed_neighbor_slots: 4,
        }
    }

    #[test]
    fn path_oram_leaf_labels_and_bucket_paths_are_canonical() {
        assert_eq!(private_hnsw_oram_leaf_count(3).unwrap(), 8);
        assert_eq!(private_hnsw_oram_bucket_count(3).unwrap(), 15);
        assert_eq!(
            private_hnsw_oram_bucket_ids_for_leaf(5, 3).unwrap(),
            vec![0, 2, 5, 12]
        );

        let left = encode_private_hnsw_oram_leaf_label(4, 3).unwrap();
        let right = encode_private_hnsw_oram_leaf_label(5, 3).unwrap();
        assert_eq!(decode_private_hnsw_oram_leaf_label(&right, 3).unwrap(), 5);
        assert_eq!(
            private_hnsw_oram_bucket_ids_for_leaf_labels([left.as_str(), right.as_str()], 3, 15)
                .unwrap(),
            vec![0, 2, 5, 11, 12]
        );
    }

    #[test]
    fn path_oram_helpers_reject_invalid_tree_and_leaf_labels() {
        assert_eq!(
            private_hnsw_oram_leaf_count(63),
            Err(PrivateHnswClientError::InvalidTreeHeight)
        );
        assert_eq!(
            encode_private_hnsw_oram_leaf_label(8, 3),
            Err(PrivateHnswClientError::LeafOutOfRange)
        );
        assert_eq!(
            decode_private_hnsw_oram_leaf_label("not-base64", 3),
            Err(PrivateHnswClientError::InvalidLeafLabelEncoding)
        );
        let label = BASE64URL_NOPAD.encode(&7u64.to_be_bytes());
        assert_eq!(
            private_hnsw_oram_bucket_ids_for_leaf_labels([label.as_str()], 3, 14),
            Err(PrivateHnswClientError::BucketCountMismatch)
        );
    }

    #[test]
    fn client_key_derivation_is_domain_separated_and_deterministic() {
        let resource_key = SecretKey::from_bytes([7; 32]);
        let first = PrivateHnswClientKeys::derive_from_resource_key(&resource_key).unwrap();
        let second = PrivateHnswClientKeys::derive_from_resource_key(&resource_key).unwrap();

        assert_eq!(
            first.bucket_aead_key().as_bytes(),
            second.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.node_aead_key().as_bytes(),
            first.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.position_map_key().as_bytes(),
            first.payload_token_key().as_bytes()
        );
        assert_ne!(
            first.payload_token_key().as_bytes(),
            first.blind_result_key().as_bytes()
        );
    }

    #[test]
    fn node_block_codec_pads_to_fixed_size_and_roundtrips() {
        let block = node_block();
        let encoded = encode_private_hnsw_node_block(&block, 512, 4).unwrap();
        assert_eq!(encoded.len(), 512);

        let decoded = decode_private_hnsw_node_block(&encoded).unwrap();
        assert_eq!(decoded, block);
    }

    #[test]
    fn node_block_codec_rejects_shape_and_padding_tamper() {
        let mut block = node_block();
        block.neighbor_levels.pop();
        assert_eq!(
            encode_private_hnsw_node_block(&block, 512, 4),
            Err(PrivateHnswClientError::InvalidNeighborShape)
        );

        let block = node_block();
        assert_eq!(
            encode_private_hnsw_node_block(&block, 512, 1),
            Err(PrivateHnswClientError::TooManyNeighbors {
                actual: 2,
                limit: 1
            })
        );

        let mut encoded = encode_private_hnsw_node_block(&block, 512, 4).unwrap();
        let last = encoded.len() - 1;
        encoded[last] = 1;
        assert_eq!(
            decode_private_hnsw_node_block(&encoded),
            Err(PrivateHnswClientError::InvalidBlockPadding)
        );
    }

    #[test]
    fn bucket_plaintext_codec_roundtrips_fixed_slots_and_rejects_tamper() {
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let bucket = PrivateHnswOramPlaintextBucket {
            bucket_id: 3,
            blocks: vec![Some(node_block_with_id(8)), None],
        };
        let encoded = encode_private_hnsw_oram_bucket_plaintext(&bucket, config).unwrap();
        assert_eq!(
            encoded.len(),
            4 + 2 + 4 + 4 + config.bucket_size * (1 + config.block_size_bytes)
        );
        assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(3, &encoded, config).unwrap(),
            bucket
        );

        let mut tampered = encoded;
        let last = tampered.len() - 1;
        tampered[last] = 1;
        assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(3, &tampered, config),
            Err(PrivateHnswClientError::InvalidBucketPlaintext)
        );
    }

    #[test]
    fn path_oram_access_absorbs_path_remaps_and_writes_back() {
        let config = oram_config();
        let node_a = node_block_with_id(10);
        let node_b = node_block_with_id(11);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(node_a.node_id, 2), (node_b.node_id, 3)],
            config.tree_height,
        )
        .unwrap();
        let path = vec![
            PrivateHnswOramPlaintextBucket {
                bucket_id: 0,
                blocks: vec![None],
            },
            PrivateHnswOramPlaintextBucket {
                bucket_id: 2,
                blocks: vec![Some(node_b.clone())],
            },
            PrivateHnswOramPlaintextBucket {
                bucket_id: 5,
                blocks: vec![Some(node_a.clone())],
            },
        ];

        let access =
            access_private_hnsw_oram_path(&mut state, config, node_a.node_id, &path, 0).unwrap();

        assert_eq!(access.old_leaf, 2);
        assert_eq!(access.new_leaf, 0);
        assert_eq!(
            access.old_leaf_label,
            encode_private_hnsw_oram_leaf_label(2, config.tree_height).unwrap()
        );
        assert_eq!(access.block, node_a);
        assert_eq!(state.position(&[10; 32]), Some(0));
        assert_eq!(state.position(&[11; 32]), Some(3));
        assert_eq!(state.stash_len(), 0);
        assert_eq!(
            access
                .writeback_buckets
                .iter()
                .map(|bucket| bucket.bucket_id)
                .collect::<Vec<_>>(),
            vec![0, 2, 5]
        );
        assert_eq!(
            access.writeback_buckets[0].blocks[0]
                .as_ref()
                .map(|block| block.node_id),
            Some([10; 32])
        );
        assert_eq!(
            access.writeback_buckets[1].blocks[0]
                .as_ref()
                .map(|block| block.node_id),
            Some([11; 32])
        );
        assert!(access.writeback_buckets[2].blocks[0].is_none());
    }

    #[test]
    fn path_oram_access_rejects_wrong_path_and_missing_target() {
        let config = oram_config();
        let node_a = node_block_with_id(10);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(node_a.node_id, 2)],
            config.tree_height,
        )
        .unwrap();
        let wrong_path = vec![
            empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(1, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(3, config).unwrap(),
        ];
        assert_eq!(
            access_private_hnsw_oram_path(&mut state, config, node_a.node_id, &wrong_path, 0),
            Err(PrivateHnswClientError::PathBucketMismatch)
        );

        let path = vec![
            empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(2, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(5, config).unwrap(),
        ];
        assert_eq!(
            access_private_hnsw_oram_path(&mut state, config, node_a.node_id, &path, 0),
            Err(PrivateHnswClientError::MissingBlock)
        );
    }

    #[test]
    fn path_oram_writeback_buckets_can_be_encoded_sealed_and_reopened() {
        let config = oram_config();
        let keys = test_keys();
        let node_a = node_block_with_id(10);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(node_a.node_id, 2)],
            config.tree_height,
        )
        .unwrap();
        let path = vec![
            empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(2, config).unwrap(),
            PrivateHnswOramPlaintextBucket {
                bucket_id: 5,
                blocks: vec![Some(node_a.clone())],
            },
        ];

        let access =
            access_private_hnsw_oram_path(&mut state, config, node_a.node_id, &path, 0).unwrap();
        let root_writeback = &access.writeback_buckets[0];
        let plaintext = encode_private_hnsw_oram_bucket_plaintext(root_writeback, config).unwrap();
        let sealed = seal_private_hnsw_oram_bucket(
            &keys,
            bucket_context(root_writeback.bucket_id),
            &plaintext,
        )
        .unwrap();
        let reopened =
            open_private_hnsw_oram_bucket(&keys, bucket_context(root_writeback.bucket_id), &sealed)
                .unwrap();
        assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(root_writeback.bucket_id, &reopened, config)
                .unwrap(),
            *root_writeback
        );
    }

    #[test]
    fn verified_path_batch_opens_buckets_only_after_merkle_proof_check() {
        let config = oram_config();
        let keys = test_keys();
        let plaintext_bucket = PrivateHnswOramPlaintextBucket {
            bucket_id: 0,
            blocks: vec![Some(node_block_with_id(8))],
        };
        let bucket = seal_private_hnsw_oram_plaintext_bucket(
            &keys,
            bucket_base_context(),
            42,
            &plaintext_bucket,
            config,
        )
        .unwrap();
        let root_hash = bucket.bucket_commitment.clone();
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root_hash.clone(),
            bucket_count: 1,
            leaves: vec![PrivateHnswOramMerkleProofLeaf {
                bucket_id: 0,
                leaf_hash: bucket.bucket_commitment.clone(),
                siblings: vec![],
            }],
        };
        let proof_json = serde_json::to_string(&proof).unwrap();

        let opened = open_private_hnsw_oram_verified_path_batch(
            &keys,
            bucket_base_context(),
            config,
            42,
            &root_hash,
            1,
            &proof_json,
            std::slice::from_ref(&bucket),
        )
        .unwrap();
        assert_eq!(opened, vec![plaintext_bucket]);

        let mut tampered = proof;
        tampered.root_hash = commitment(9);
        let tampered_json = serde_json::to_string(&tampered).unwrap();
        assert_eq!(
            open_private_hnsw_oram_verified_path_batch(
                &keys,
                bucket_base_context(),
                config,
                42,
                &root_hash,
                1,
                &tampered_json,
                &[bucket],
            ),
            Err(PrivateHnswClientError::MerkleProofMismatch)
        );
    }

    #[test]
    fn commit_plan_updates_merkle_root_and_signature_refs() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9, 10);

        let plan = plan_private_hnsw_oram_commit(
            42,
            43,
            &old_root,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        assert_eq!(plan.old_epoch, 42);
        assert_eq!(plan.new_epoch, 43);
        assert_eq!(plan.old_root_hash, old_root);
        assert_ne!(plan.new_root_hash, plan.old_root_hash);
        assert_eq!(plan.leaf_commitments[2], updated_bucket.bucket_commitment);
        assert_eq!(
            plan.updated_buckets,
            vec![PrivateHnswClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }]
        );
        assert_eq!(
            plan.signature_bucket_refs(),
            vec![PrivateHnswOramCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.as_str(),
            }]
        );
    }

    #[test]
    fn commit_plan_can_be_signed_and_verified_by_server_validator() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        use crate::private_hnsw_oram::{
            PrivateHnswOramCommitSignatureInput, PrivateHnswSignatureVerification,
            validate_private_hnsw_oram_commit_signature,
        };

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9, 10);
        let plan = plan_private_hnsw_oram_commit(
            42,
            43,
            &old_root,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        let signature = sign_private_hnsw_oram_commit(
            &key_pair,
            PrivateHnswCommitSignatureContext {
                collection_id: "collection-uuid-1",
                vector_name: "text",
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                signing_key_id: "tenant-a/private-hnsw-signing-v1",
            },
            &plan,
        )
        .unwrap();

        let bucket_refs = plan.signature_bucket_refs();
        validate_private_hnsw_oram_commit_signature(
            PrivateHnswOramCommitSignatureInput {
                collection_id: "collection-uuid-1",
                vector_name: "text",
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                old_epoch: plan.old_epoch,
                new_epoch: plan.new_epoch,
                old_root_hash: &plan.old_root_hash,
                new_root_hash: &plan.new_root_hash,
                updated_buckets: &bucket_refs,
                signature_alg: &signature.alg,
                signature_key_id: &signature.key_id,
            },
            &signature.sig,
            PrivateHnswSignatureVerification {
                expected_key_id: "tenant-a/private-hnsw-signing-v1",
                public_key: key_pair.public_key().as_ref(),
            },
        )
        .unwrap();
    }

    #[test]
    fn manifest_can_be_signed_and_verified_by_server_validator() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        use crate::private_hnsw_oram::{
            PrivateHnswManifestValidationContext, PrivateHnswSignatureVerification,
            validate_private_hnsw_oram_manifest,
        };

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let manifest = fixture_manifest();
        let signature = sign_private_hnsw_oram_manifest(&key_pair, &manifest).unwrap();

        let epoch = validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            PrivateHnswManifestValidationContext {
                expected_collection_id: "collection-uuid-1",
                expected_vector_name: "text",
                expected_key_id: "tenant-a/vector-private-rk",
                expected_rk_id: "tenant-a/vector-private-rk",
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 1536,
                expected_distance: DistanceKind::Cosine,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            },
        )
        .unwrap();

        assert_eq!(signature.alg, "ed25519");
        assert_eq!(signature.key_id, manifest.owner_signing_key_id);
        assert_eq!(epoch.epoch, manifest.index_epoch);
        assert_eq!(epoch.root_hash, [42; 32]);
    }

    #[test]
    fn commit_plan_rejects_stale_duplicate_out_of_range_and_root_mismatch() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9, 10);

        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &commitment(99),
                &leaf_commitments,
                std::slice::from_ref(&updated_bucket),
            ),
            Err(PrivateHnswClientError::MerkleRootMismatch)
        );

        let stale_bucket = fixture_commit_bucket(2, 42, 9, 10);
        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&stale_bucket),
            ),
            Err(PrivateHnswClientError::StaleBucketEpoch {
                bucket_id: 2,
                expected_epoch: 43,
                actual_epoch: 42,
            })
        );

        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                &[updated_bucket.clone(), updated_bucket.clone()],
            ),
            Err(PrivateHnswClientError::DuplicateUpdatedBucket { bucket_id: 2 })
        );

        let out_of_range = fixture_commit_bucket(4, 43, 9, 10);
        assert_eq!(
            plan_private_hnsw_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&out_of_range),
            ),
            Err(PrivateHnswClientError::BucketOutOfRange {
                bucket_id: 4,
                bucket_count: 4,
            })
        );
    }

    #[test]
    fn merkle_proof_verifier_accepts_server_path_batch_proof_json() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let parent_01 = private_hnsw_oram_merkle_parent_hash(
            &decode_bucket_commitment(&leaf_commitments[0]).unwrap(),
            &decode_bucket_commitment(&leaf_commitments[1]).unwrap(),
        );
        let bucket = fixture_commit_bucket(2, 42, 3, 10);
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root.clone(),
            bucket_count: 4,
            leaves: vec![PrivateHnswOramMerkleProofLeaf {
                bucket_id: 2,
                leaf_hash: leaf_commitments[2].clone(),
                siblings: vec![
                    proof_sibling(0, PrivateHnswMerkleSiblingPosition::Right, commitment(4)),
                    proof_sibling(
                        1,
                        PrivateHnswMerkleSiblingPosition::Left,
                        BASE64URL_NOPAD.encode(&parent_01),
                    ),
                ],
            }],
        };
        let proof_json = serde_json::to_string(&proof).unwrap();

        verify_private_hnsw_oram_merkle_proof_json(
            &proof_json,
            42,
            &root,
            4,
            std::slice::from_ref(&bucket),
        )
        .unwrap();
        verify_private_hnsw_oram_merkle_proof(&proof, 42, &root, 4, &[bucket]).unwrap();
    }

    #[test]
    fn merkle_proof_verifier_rejects_tampered_leaf_and_sibling() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let root = private_hnsw_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let parent_01 = private_hnsw_oram_merkle_parent_hash(
            &decode_bucket_commitment(&leaf_commitments[0]).unwrap(),
            &decode_bucket_commitment(&leaf_commitments[1]).unwrap(),
        );
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root.clone(),
            bucket_count: 4,
            leaves: vec![PrivateHnswOramMerkleProofLeaf {
                bucket_id: 2,
                leaf_hash: leaf_commitments[2].clone(),
                siblings: vec![
                    proof_sibling(0, PrivateHnswMerkleSiblingPosition::Right, commitment(4)),
                    proof_sibling(
                        1,
                        PrivateHnswMerkleSiblingPosition::Left,
                        BASE64URL_NOPAD.encode(&parent_01),
                    ),
                ],
            }],
        };

        let wrong_bucket = fixture_commit_bucket(2, 42, 9, 10);
        assert_eq!(
            verify_private_hnsw_oram_merkle_proof(
                &proof,
                42,
                &root,
                4,
                std::slice::from_ref(&wrong_bucket),
            ),
            Err(PrivateHnswClientError::MerkleProofMismatch)
        );

        let mut tampered = proof;
        tampered.leaves[0].siblings[0].hash = commitment(9);
        let bucket = fixture_commit_bucket(2, 42, 3, 10);
        assert_eq!(
            verify_private_hnsw_oram_merkle_proof(&tampered, 42, &root, 4, &[bucket]),
            Err(PrivateHnswClientError::MerkleProofMismatch)
        );
    }

    #[test]
    fn plaintext_oram_bulk_build_places_blocks_on_paths_and_searches() {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32], [3; 32]]);
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let far = node_block_with_vector(3, &[0.0, 1.0], vec![]);
        let build = build_private_hnsw_oram_plaintext_index_from_blocks(
            config,
            &[entry.clone(), near.clone(), far.clone()],
            &[0, 1, 2],
        )
        .unwrap();

        assert_eq!(build.entry_node_id, entry.node_id);
        assert_eq!(build.logical_node_count, 3);
        assert_eq!(
            build.dummy_node_count,
            private_hnsw_oram_bucket_count(config.tree_height).unwrap() * config.bucket_size as u64
                - 3
        );
        assert_eq!(build.state.position(&near.node_id), Some(1));

        let store = RefCell::new(
            build
                .buckets
                .into_iter()
                .map(|bucket| (bucket.bucket_id, bucket))
                .collect::<BTreeMap<_, _>>(),
        );
        let mut state = build.state;
        let mut remaps = [3, 3, 3].into_iter();
        let result = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 3,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = store.borrow_mut();
                for bucket in writeback_buckets {
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
    }

    #[test]
    fn plaintext_oram_hnsw_search_walks_graph_and_ranks_top_k() {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32], [3; 32]]);
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let far = node_block_with_vector(3, &[0.0, 1.0], vec![]);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (near.node_id, 1), (far.node_id, 2)],
            config.tree_height,
        )
        .unwrap();

        let store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..private_hnsw_oram_bucket_count(config.tree_height).unwrap() {
            store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(0, entry.clone()), (1, near.clone()), (2, far.clone())] {
            let leaf_bucket_id = *private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let mut store_mut = store.borrow_mut();
            let bucket = store_mut.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block);
        }

        let mut remaps = [3, 3, 3].into_iter();
        let result = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 3,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = store.borrow_mut();
                for bucket in writeback_buckets {
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.completed_steps, 3);
        assert_eq!(
            result.accessed_leaf_labels,
            vec![
                encode_private_hnsw_oram_leaf_label(0, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(1, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(2, config.tree_height).unwrap(),
            ]
        );
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
        assert_eq!(result.hits[0].distance, 0.0);
        assert_eq!(state.position(&entry.node_id), Some(3));
        assert_eq!(state.position(&near.node_id), Some(3));
        assert_eq!(state.position(&far.node_id), Some(3));
    }

    #[test]
    fn plaintext_oram_hnsw_search_pads_to_fixed_steps_with_dummy_node() {
        use std::cell::RefCell;

        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[1.0, 0.0], vec![]);
        let mut dummy = node_block_with_vector(99, &[0.0, 0.0], vec![]);
        dummy.deleted = true;
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (dummy.node_id, 1)],
            config.tree_height,
        )
        .unwrap();

        let store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..private_hnsw_oram_bucket_count(config.tree_height).unwrap() {
            store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(0, entry.clone()), (1, dummy.clone())] {
            let leaf_bucket_id = *private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let mut store_mut = store.borrow_mut();
            let bucket = store_mut.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block);
        }

        let mut remaps = [2, 3, 0].into_iter();
        let result = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 1,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: Some(dummy.node_id),
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = store.borrow_mut();
                for bucket in writeback_buckets {
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.completed_steps, 3);
        assert_eq!(
            result.accessed_leaf_labels,
            vec![
                encode_private_hnsw_oram_leaf_label(0, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(1, config.tree_height).unwrap(),
                encode_private_hnsw_oram_leaf_label(3, config.tree_height).unwrap(),
            ]
        );
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, entry.node_id);
        assert_eq!(state.position(&entry.node_id), Some(2));
        assert_eq!(state.position(&dummy.node_id), Some(0));
    }

    #[test]
    fn encrypted_oram_hnsw_search_opens_and_reseals_writeback_buckets() {
        use std::cell::RefCell;

        let keys = test_keys();
        let base_context = bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32], [3; 32]]);
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let far = node_block_with_vector(3, &[0.0, 1.0], vec![]);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (near.node_id, 1), (far.node_id, 2)],
            config.tree_height,
        )
        .unwrap();

        let plaintext_store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..private_hnsw_oram_bucket_count(config.tree_height).unwrap() {
            plaintext_store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(0, entry.clone()), (1, near.clone()), (2, far.clone())] {
            let leaf_bucket_id = *private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let mut store_mut = plaintext_store.borrow_mut();
            let bucket = store_mut.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block);
        }

        let encrypted_store = RefCell::new(BTreeMap::new());
        for bucket in plaintext_store.borrow().values() {
            let encrypted =
                seal_private_hnsw_oram_plaintext_bucket(&keys, base_context, 42, bucket, config)
                    .unwrap();
            encrypted_store
                .borrow_mut()
                .insert(bucket.bucket_id, encrypted);
        }

        let mut remaps = [3, 3, 3].into_iter();
        let result = search_private_hnsw_oram_encrypted(
            &keys,
            base_context,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 3,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?
                    .into_iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(&bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect()
            },
            |writeback_buckets| {
                let mut store_mut = encrypted_store.borrow_mut();
                for bucket in writeback_buckets {
                    assert_eq!(bucket.index_epoch, 43);
                    store_mut.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
        assert_eq!(result.hits[0].distance, 0.0);
        assert_eq!(result.completed_steps, 3);
        assert!(
            encrypted_store
                .borrow()
                .values()
                .any(|bucket| bucket.index_epoch == 43)
        );

        let root = encrypted_store.borrow().get(&0).cloned().unwrap();
        let root_plaintext =
            open_private_hnsw_oram_plaintext_bucket(&keys, base_context, &root, config).unwrap();
        assert_eq!(root_plaintext.bucket_id, 0);
        assert!(root_plaintext.blocks.iter().any(|slot| slot.is_some()));
    }

    #[test]
    fn verified_encrypted_oram_hnsw_search_checks_merkle_proofs_before_opening() {
        use std::cell::RefCell;

        let keys = test_keys();
        let base_context = bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            bucket_size: 2,
            ..oram_config()
        };
        let bucket_count = private_hnsw_oram_bucket_count(config.tree_height).unwrap();
        let entry = node_block_with_vector(1, &[10.0, 0.0], vec![[2; 32], [3; 32]]);
        let near = node_block_with_vector(2, &[1.0, 0.0], vec![]);
        let far = node_block_with_vector(3, &[0.0, 1.0], vec![]);
        let mut state = PrivateHnswOramClientState::with_position_map(
            [(entry.node_id, 0), (near.node_id, 1), (far.node_id, 2)],
            config.tree_height,
        )
        .unwrap();

        let plaintext_store = RefCell::new(BTreeMap::new());
        for bucket_id in 0..bucket_count {
            plaintext_store.borrow_mut().insert(
                bucket_id,
                empty_private_hnsw_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(0, entry.clone()), (1, near.clone()), (2, far.clone())] {
            let leaf_bucket_id = *private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let mut store_mut = plaintext_store.borrow_mut();
            let bucket = store_mut.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block);
        }

        let encrypted_store = RefCell::new(BTreeMap::new());
        for bucket in plaintext_store.borrow().values() {
            let encrypted =
                seal_private_hnsw_oram_plaintext_bucket(&keys, base_context, 42, bucket, config)
                    .unwrap();
            encrypted_store
                .borrow_mut()
                .insert(bucket.bucket_id, encrypted);
        }
        let commitments = (0..bucket_count)
            .map(|bucket_id| {
                encrypted_store
                    .borrow()
                    .get(&bucket_id)
                    .map(|bucket| bucket.bucket_commitment.clone())
                    .ok_or(PrivateHnswClientError::PathBucketMismatch)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let root_hash = private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap();
        let writebacks = RefCell::new(Vec::new());

        let mut bad_state = state.clone();
        let bad_writeback_called = RefCell::new(false);
        let err = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut bad_state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let buckets = bucket_ids
                    .iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut proof =
                    proof_for_bucket_ids(&bucket_ids, 42, root_hash.clone(), &commitments);
                proof.leaves[0].leaf_hash = commitment(99);
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 42,
                    root_hash: root_hash.clone(),
                    bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                assert!(!writeback_buckets.is_empty());
                *bad_writeback_called.borrow_mut() = true;
                Ok(())
            },
            || Ok(3),
        )
        .unwrap_err();

        assert_eq!(err, PrivateHnswClientError::MerkleProofMismatch);
        assert!(!*bad_writeback_called.borrow());
        assert_eq!(bad_state.position(&entry.node_id), Some(0));

        let mut remaps = [3, 3, 3].into_iter();
        let result = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: entry.node_id,
                k: 1,
                ef: 3,
                fixed_steps: 3,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let buckets = bucket_ids
                    .iter()
                    .map(|bucket_id| {
                        encrypted_store
                            .borrow()
                            .get(bucket_id)
                            .cloned()
                            .ok_or(PrivateHnswClientError::PathBucketMismatch)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let proof = proof_for_bucket_ids(&bucket_ids, 42, root_hash.clone(), &commitments);
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 42,
                    root_hash: root_hash.clone(),
                    bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                writebacks.borrow_mut().extend_from_slice(writeback_buckets);
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].node_id, near.node_id);
        assert_eq!(result.completed_steps, 3);
        assert!(
            writebacks
                .borrow()
                .iter()
                .all(|bucket| bucket.index_epoch == 43)
        );
    }

    #[test]
    fn plaintext_oram_hnsw_search_rejects_bad_vector_shapes() {
        let config = oram_config();
        let mut state =
            PrivateHnswOramClientState::with_position_map([([1; 32], 0)], config.tree_height)
                .unwrap();
        let bad_vector = PrivateHnswNodeBlockPlaintext {
            version: NODE_BLOCK_VERSION,
            node_id: [1; 32],
            point_token: [2; 32],
            level_mask: 1,
            vector_encoding: PrivateHnswVectorEncoding::F32Le,
            vector: vec![1, 2, 3],
            neighbors: vec![],
            neighbor_levels: vec![],
            deleted: false,
            generation: 1,
            payload_fetch_token: None,
        };
        let path = [
            empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_hnsw_oram_plaintext_bucket(1, config).unwrap(),
            PrivateHnswOramPlaintextBucket {
                bucket_id: 3,
                blocks: vec![Some(bad_vector)],
            },
        ];

        let err = search_private_hnsw_oram_plaintext(
            &mut state,
            config,
            &[1.0],
            PrivateHnswSearchParams {
                entry_node_id: [1; 32],
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |_| Ok(path.to_vec()),
            |_| Ok(()),
            || Ok(0),
        )
        .unwrap_err();
        assert_eq!(err, PrivateHnswClientError::InvalidF32VectorLength);
    }

    #[test]
    fn bucket_seal_open_roundtrips_and_populates_integrity_fields() {
        let keys = test_keys();
        let context = bucket_context(3);
        let plaintext = vec![11; 256];
        let bucket = seal_private_hnsw_oram_bucket(&keys, context, &plaintext).unwrap();

        assert_eq!(bucket.version, 1);
        assert_eq!(bucket.bucket_id, 3);
        assert_eq!(bucket.index_epoch, 42);
        decode_bucket_ciphertext_hash(&bucket.ciphertext_sha256).unwrap();
        decode_bucket_commitment(&bucket.bucket_commitment).unwrap();
        assert_eq!(
            private_hnsw_bucket_commitment(context, &bucket.ciphertext_sha256).unwrap(),
            bucket.bucket_commitment
        );
        assert_eq!(
            open_private_hnsw_oram_bucket(&keys, context, &bucket).unwrap(),
            plaintext
        );
    }

    #[test]
    fn bucket_open_rejects_wrong_context_hash_and_ciphertext_tamper() {
        let keys = test_keys();
        let context = bucket_context(3);
        let bucket = seal_private_hnsw_oram_bucket(&keys, context, &[9; 64]).unwrap();

        let mut wrong_context = context;
        wrong_context.bucket_id = 4;
        assert_eq!(
            open_private_hnsw_oram_bucket(&keys, wrong_context, &bucket),
            Err(PrivateHnswClientError::BucketMetadataMismatch)
        );

        let mut wrong_hash = bucket.clone();
        wrong_hash.ciphertext_sha256 = BASE64URL_NOPAD.encode(&[8; 32]);
        assert_eq!(
            open_private_hnsw_oram_bucket(&keys, context, &wrong_hash),
            Err(PrivateHnswClientError::InvalidBucketCiphertextHash)
        );

        let mut wrong_ciphertext = bucket;
        let mut raw = BASE64URL_NOPAD
            .decode(wrong_ciphertext.ciphertext.as_bytes())
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        wrong_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&raw);
        wrong_ciphertext.ciphertext_sha256 = base64url_sha256(&raw);
        wrong_ciphertext.bucket_commitment =
            private_hnsw_bucket_commitment(context, &wrong_ciphertext.ciphertext_sha256).unwrap();
        assert_eq!(
            open_private_hnsw_oram_bucket(&keys, context, &wrong_ciphertext),
            Err(PrivateHnswClientError::BucketOpenFailed)
        );
    }
}
