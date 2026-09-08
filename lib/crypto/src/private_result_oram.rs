use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::aead::{AeadInvocationBudget, EncryptionError, SecretKey, validate_resource_key_id};
use crate::control_plane::{PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING};
use crate::private_hnsw_oram::OramParams;

pub const PRIVATE_RESULT_ORAM_MANIFEST_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-result-oram-manifest-signature/v1";
pub const PRIVATE_RESULT_ORAM_COMMIT_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-result-oram-commit-signature/v1";
pub const PRIVATE_RESULT_ORAM_READ_BUCKETS_SIGNATURE_DOMAIN: &str =
    "qdrant-sec/private-result-oram-read-buckets-signature/v1";
pub const PRIVATE_RESULT_ORAM_BUCKET_COMMITMENT_DOMAIN: &str =
    "qdrant-sec/private-result-oram-bucket-commitment/v1";
pub const PRIVATE_RESULT_ORAM_BUCKET_AEAD_DOMAIN: &[u8] =
    b"qdrant-sec/private-result-oram-bucket-aead/v1";
pub const PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_DOMAIN: &[u8] =
    b"qdrant-sec/private-result-oram-client-state-aead/v1";
const PRIVATE_RESULT_ORAM_CLIENT_KDF_CONTEXT_DOMAIN: &[u8] =
    b"qdrant-sec/private-result-oram-client-kdf-context/v1";

const PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM: &str = "ed25519";
const PRIVATE_RESULT_ORAM_BUCKET_AEAD_CONTEXT_DOMAIN: &str =
    "qdrant-sec/private-result-oram-bucket-aead-context/v1";
const PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_CONTEXT_DOMAIN: &str =
    "qdrant-sec/private-result-oram-client-state-aead-context/v1";
const PRIVATE_RESULT_ORAM_BUCKET_AEAD_VERSION: u8 = 1;
const PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_VERSION: u16 = 1;
const PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN: usize = 12;
const PRIVATE_RESULT_ORAM_BUCKET_AEAD_TAG_LEN: usize = 16;
const PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_HEADER_BYTES: usize = 4 + 2 + 8 + 4 + 4;
const PRIVATE_RESULT_ORAM_BUCKET_AEAD_OVERHEAD_BYTES: usize =
    1 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN + PRIVATE_RESULT_ORAM_BUCKET_AEAD_TAG_LEN;
const PRIVATE_RESULT_ORAM_BUCKET_CIPHERTEXT_OPEN_MAX_BYTES: usize = 64 * 1024 * 1024;
const PRIVATE_RESULT_ORAM_CLIENT_STATE_CIPHERTEXT_MAX_BYTES: usize = 256 * 1024 * 1024;
const PRIVATE_RESULT_ORAM_CLIENT_STATE_SNAPSHOT_VERSION: u16 = 1;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const BASE64URL_NOPAD_8_BYTE_LEN: usize = 11;
const BASE64URL_NOPAD_64_BYTE_LEN: usize = 86;
const PRIVATE_RESULT_ORAM_MERKLE_PROOF_JSON_MAX_BYTES: usize = 4 * 1024 * 1024;
const PRIVATE_RESULT_ORAM_MANIFEST_VERSION: u16 = 1;
const PRIVATE_RESULT_ORAM_BUCKET_VERSION: u16 = 1;
const PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_MAGIC: &[u8; 4] = b"QRPO";
pub const PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION: u16 = 1;
const PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_MAGIC: &[u8; 4] = b"QRPB";
const PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_VERSION: u16 = 1;

#[derive(Error, PartialEq, Eq)]
pub enum PrivateResultOramError {
    #[error("private result ORAM client encryption failed")]
    Encryption(EncryptionError),
    #[error("private result ORAM manifest uses unsupported version")]
    UnsupportedManifestVersion(u16),
    #[error("private result ORAM manifest provider is invalid")]
    InvalidProvider,
    #[error("private result ORAM manifest binding is invalid")]
    InvalidBinding,
    #[error("private result ORAM manifest field is invalid")]
    InvalidManifestField(&'static str),
    #[error("private result ORAM manifest field does not match runtime context")]
    ManifestContextMismatch(&'static str),
    #[error("private result ORAM manifest signature is missing")]
    MissingManifestSignature,
    #[error("private result ORAM signature uses unsupported algorithm")]
    UnsupportedSignatureAlgorithm(String),
    #[error("private result ORAM signature key id does not match runtime context")]
    SignatureKeyIdMismatch,
    #[error("private result ORAM signature is malformed")]
    MalformedSignature,
    #[error("private result ORAM manifest signature verification failed")]
    InvalidManifestSignature,
    #[error("private result ORAM commit signature verification failed")]
    InvalidCommitSignature,
    #[error("private result ORAM read_buckets signature verification failed")]
    InvalidReadBucketsSignature,
    #[error("private result ORAM resource key id is invalid")]
    InvalidResourceKeyId,
    #[error("private result ORAM bucket uses unsupported version")]
    UnsupportedBucketVersion(u16),
    #[error("private result ORAM bucket is out of range")]
    BucketOutOfRange { bucket_id: u64, bucket_count: u64 },
    #[error("private result ORAM bucket field is invalid")]
    InvalidBucketField(&'static str),
    #[error("private result ORAM bucket ciphertext exceeds maximum size")]
    BucketOversized,
    #[error("private result ORAM bucket ciphertext_sha256 mismatch")]
    InvalidBucketHash,
    #[error("private result ORAM bucket ciphertext is malformed")]
    InvalidBucketCiphertextEncoding,
    #[error("private result ORAM bucket ciphertext hash mismatch")]
    InvalidBucketCiphertextHash,
    #[error("private result ORAM bucket ciphertext uses unsupported version")]
    UnsupportedBucketCiphertextVersion(u8),
    #[error("private result ORAM bucket decryption authentication failed")]
    BucketOpenFailed,
    #[error("private result ORAM bucket metadata does not match context")]
    BucketMetadataMismatch,
    #[error("private result ORAM bucket context is invalid")]
    InvalidBucketContext(&'static str),
    #[error("private result ORAM bucket commitment context mismatch")]
    InvalidBucketCommitment,
    #[error("private result ORAM Merkle tree is empty")]
    EmptyMerkleTree,
    #[error("private result ORAM Merkle root does not match current commitments")]
    MerkleRootMismatch,
    #[error("private result ORAM manifest epoch/root does not match commit old epoch/root")]
    ManifestCommitMismatch,
    #[error("private result ORAM bucket has stale epoch")]
    StaleBucketEpoch {
        bucket_id: u64,
        expected_epoch: u64,
        actual_epoch: u64,
    },
    #[error("private result ORAM commit repeats bucket")]
    DuplicateUpdatedBucket { bucket_id: u64 },
    #[error("private result ORAM commit must update at least one bucket")]
    EmptyCommit,
    #[error("private result ORAM Merkle proof is malformed")]
    InvalidMerkleProof,
    #[error("private result ORAM Merkle proof JSON is malformed")]
    InvalidMerkleProofJson,
    #[error("private result ORAM Merkle proof does not match bucket commitments")]
    MerkleProofMismatch,
    #[error("private result ORAM fetch plan field is invalid")]
    InvalidFetchPlanField(&'static str),
    #[error("private result ORAM fetch token position is missing")]
    MissingPayloadFetchTokenPosition,
    #[error("private result ORAM fetch token appears more than once")]
    DuplicatePayloadFetchToken,
    #[error("private result ORAM point token appears more than once")]
    DuplicatePointToken,
    #[error("private result ORAM fetch token position appears more than once")]
    DuplicatePayloadFetchTokenPosition,
    #[error("private result ORAM client config is invalid")]
    InvalidClientConfig(&'static str),
    #[error("private result ORAM payload block uses unsupported version")]
    UnsupportedPayloadBlockVersion(u16),
    #[error("private result ORAM payload block is malformed")]
    InvalidPayloadBlock,
    #[error("private result ORAM payload block padding is invalid")]
    InvalidPayloadBlockPadding,
    #[error("private result ORAM payload block exceeds configured size")]
    PayloadBlockOversized,
    #[error("private result ORAM bucket plaintext is malformed")]
    InvalidBucketPlaintext,
    #[error("private result ORAM bucket plaintext slot count does not match config")]
    BucketPlaintextSlotCountMismatch,
    #[error("private result ORAM client position map is missing a token")]
    MissingPosition,
    #[error("private result ORAM path did not contain the requested block")]
    MissingBlock,
    #[error("private result ORAM path buckets do not match the requested leaf path")]
    PathBucketMismatch,
    #[error("private result ORAM client state snapshot uses unsupported version")]
    UnsupportedClientStateSnapshotVersion(u16),
    #[error("private result ORAM client state snapshot is malformed")]
    InvalidClientStateSnapshot,
    #[error("private result ORAM client state context is invalid")]
    InvalidClientStateContext(&'static str),
    #[error("private result ORAM client state ciphertext is not base64url")]
    InvalidClientStateCiphertextEncoding,
    #[error("private result ORAM client state ciphertext hash is invalid")]
    InvalidClientStateCiphertextHash,
    #[error("private result ORAM client state uses unsupported ciphertext version")]
    UnsupportedClientStateCiphertextVersion(u16),
    #[error("private result ORAM client state decryption authentication failed")]
    ClientStateOpenFailed,
}

impl Debug for PrivateResultOramError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateResultOramError")
            .field(&self.to_string())
            .finish()
    }
}

impl From<EncryptionError> for PrivateResultOramError {
    fn from(error: EncryptionError) -> Self {
        Self::Encryption(error)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramManifest {
    pub version: u16,
    pub provider: String,
    pub binding: String,
    pub collection_id: String,
    pub key_id: String,
    pub rk_id: String,
    pub rk_epoch: u64,
    pub oram: OramParams,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub logical_result_count: u64,
    pub dummy_result_count: u64,
    pub owner_signing_key_id: String,
    pub created_at_unix: u64,
}

impl Debug for PrivateResultOramManifest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramManifest")
            .field("version", &self.version)
            .field("provider", &self.provider)
            .field("binding", &self.binding)
            .field("collection_id", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("oram", &self.oram)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &self.bucket_count)
            .field("logical_result_count", &self.logical_result_count)
            .field("dummy_result_count", &self.dummy_result_count)
            .field("owner_signing_key_id", &"[redacted]")
            .field("created_at_unix", &self.created_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramBucket {
    pub version: u16,
    pub bucket_id: u64,
    pub index_epoch: u64,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
    pub bucket_commitment: String,
}

impl Debug for PrivateResultOramBucket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramBucket")
            .field("version", &self.version)
            .field("bucket_id", &"[redacted]")
            .field("index_epoch", &"[redacted]")
            .field("ciphertext_len", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .field("bucket_commitment", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateResultOramSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramSignature")
            .field("alg", &self.alg)
            .field("key_id", &"[redacted]")
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramPayloadBlockPlaintext {
    pub version: u16,
    pub payload_fetch_token: [u8; 32],
    pub point_token: [u8; 32],
    pub payload: Vec<u8>,
    pub deleted: bool,
    pub generation: u64,
}

impl Debug for PrivateResultOramPayloadBlockPlaintext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramPayloadBlockPlaintext")
            .field("version", &self.version)
            .field("payload_fetch_token", &"[redacted; 32 bytes]")
            .field("point_token", &"[redacted; 32 bytes]")
            .field("payload_len", &"[redacted]")
            .field("deleted", &"[redacted]")
            .field("generation", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramClientConfig {
    pub tree_height: u32,
    pub bucket_size: usize,
    pub block_size_bytes: usize,
}

impl Debug for PrivateResultOramClientConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramClientConfig")
            .field("tree_height", &"[redacted]")
            .field("bucket_size", &"[redacted]")
            .field("block_size_bytes", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramPlaintextBucket {
    pub bucket_id: u64,
    pub blocks: Vec<Option<PrivateResultOramPayloadBlockPlaintext>>,
}

impl Debug for PrivateResultOramPlaintextBucket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramPlaintextBucket")
            .field("bucket_id", &"[redacted]")
            .field("blocks_len", &"[redacted]")
            .field("occupied_blocks", &"[redacted]")
            .finish()
    }
}

pub fn private_result_oram_bucket_ciphertext_bytes(
    oram: &OramParams,
) -> Result<usize, PrivateResultOramError> {
    let bucket_size = usize::try_from(oram.bucket_size)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("oram.bucket_size"))?;
    let block_size_bytes = usize::try_from(oram.block_size_bytes)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("oram.block_size_bytes"))?;
    private_result_oram_bucket_ciphertext_bytes_for_geometry(bucket_size, block_size_bytes)
}

fn private_result_oram_bucket_ciphertext_bytes_for_geometry(
    bucket_size: usize,
    block_size_bytes: usize,
) -> Result<usize, PrivateResultOramError> {
    let slot_bytes = 1usize.checked_add(block_size_bytes).ok_or(
        PrivateResultOramError::InvalidManifestField("oram.block_size_bytes"),
    )?;
    let bucket_payload_bytes =
        bucket_size
            .checked_mul(slot_bytes)
            .ok_or(PrivateResultOramError::InvalidManifestField(
                "oram.bucket_size",
            ))?;
    let plaintext_bytes = PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_HEADER_BYTES
        .checked_add(bucket_payload_bytes)
        .ok_or(PrivateResultOramError::InvalidManifestField("oram"))?;
    PRIVATE_RESULT_ORAM_BUCKET_AEAD_OVERHEAD_BYTES
        .checked_add(plaintext_bytes)
        .ok_or(PrivateResultOramError::InvalidManifestField("oram"))
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramAccessResult {
    pub old_leaf: u64,
    pub new_leaf: u64,
    pub block: PrivateResultOramPayloadBlockPlaintext,
    pub writeback_buckets: Vec<PrivateResultOramPlaintextBucket>,
}

impl Debug for PrivateResultOramAccessResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramAccessResult")
            .field("old_leaf", &"[redacted]")
            .field("new_leaf", &"[redacted]")
            .field("block", &"[redacted]")
            .field("writeback_bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramEvictionResult {
    pub leaf: u64,
    pub writeback_buckets: Vec<PrivateResultOramPlaintextBucket>,
}

impl Debug for PrivateResultOramEvictionResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramEvictionResult")
            .field("leaf", &"[redacted]")
            .field("writeback_bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramClientStateSnapshot {
    pub version: u16,
    pub tree_height: u32,
    pub positions: Vec<PrivateResultOramPositionMapSnapshotEntry>,
    pub stash: Vec<PrivateResultOramPayloadBlockPlaintext>,
}

impl Debug for PrivateResultOramClientStateSnapshot {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramClientStateSnapshot")
            .field("version", &self.version)
            .field("tree_height", &"[redacted]")
            .field("position_count", &"[redacted]")
            .field("stash_len", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramPositionMapSnapshotEntry {
    pub payload_fetch_token: String,
    pub leaf_label: String,
}

impl Debug for PrivateResultOramPositionMapSnapshotEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramPositionMapSnapshotEntry")
            .field("payload_fetch_token", &"[redacted]")
            .field("leaf_label", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramEncryptedClientStateSnapshot {
    pub version: u16,
    pub index_epoch: u64,
    pub root_hash: String,
    pub ciphertext: String,
    pub ciphertext_sha256: String,
}

impl Debug for PrivateResultOramEncryptedClientStateSnapshot {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramEncryptedClientStateSnapshot")
            .field("version", &self.version)
            .field("index_epoch", &"[redacted]")
            .field("root_hash", &"[redacted]")
            .field("ciphertext_len", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct PrivateResultOramClientState {
    position_map: BTreeMap<[u8; 32], u64>,
    stash: BTreeMap<[u8; 32], PrivateResultOramPayloadBlockPlaintext>,
}

impl Debug for PrivateResultOramClientState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramClientState")
            .field("position_map_len", &"[redacted]")
            .field("stash_len", &"[redacted]")
            .finish()
    }
}

impl PrivateResultOramClientState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_position_map(
        position_map: impl IntoIterator<Item = ([u8; 32], u64)>,
        tree_height: u32,
    ) -> Result<Self, PrivateResultOramError> {
        let mut state = Self::new();
        for (payload_fetch_token, leaf) in position_map {
            validate_private_result_oram_leaf(leaf, tree_height)?;
            if state
                .position_map
                .insert(payload_fetch_token, leaf)
                .is_some()
            {
                return Err(PrivateResultOramError::InvalidClientStateSnapshot);
            }
        }
        Ok(state)
    }

    pub fn insert_position(
        &mut self,
        payload_fetch_token: [u8; 32],
        leaf: u64,
        tree_height: u32,
    ) -> Result<(), PrivateResultOramError> {
        validate_private_result_oram_leaf(leaf, tree_height)?;
        self.position_map.insert(payload_fetch_token, leaf);
        Ok(())
    }

    pub fn insert_position_if_absent(
        &mut self,
        payload_fetch_token: [u8; 32],
        leaf: u64,
        tree_height: u32,
    ) -> Result<(), PrivateResultOramError> {
        validate_private_result_oram_leaf(leaf, tree_height)?;
        if self.position_map.contains_key(&payload_fetch_token) {
            return Err(PrivateResultOramError::DuplicatePayloadFetchToken);
        }
        self.position_map.insert(payload_fetch_token, leaf);
        Ok(())
    }

    pub fn insert_new_stash_block(
        &mut self,
        block: PrivateResultOramPayloadBlockPlaintext,
        leaf: u64,
        config: PrivateResultOramClientConfig,
    ) -> Result<(), PrivateResultOramError> {
        validate_private_result_oram_client_config(config)?;
        validate_private_result_oram_leaf(leaf, config.tree_height)?;
        encode_private_result_oram_payload_block(&block, config.block_size_bytes)?;
        if self.position_map.contains_key(&block.payload_fetch_token)
            || self.stash.contains_key(&block.payload_fetch_token)
        {
            return Err(PrivateResultOramError::DuplicatePayloadFetchToken);
        }
        if self
            .stash
            .values()
            .any(|existing| existing.point_token == block.point_token)
        {
            return Err(PrivateResultOramError::DuplicatePointToken);
        }

        self.position_map.insert(block.payload_fetch_token, leaf);
        self.stash.insert(block.payload_fetch_token, block);
        Ok(())
    }

    pub fn position(&self, payload_fetch_token: &[u8; 32]) -> Option<u64> {
        self.position_map.get(payload_fetch_token).copied()
    }

    pub fn to_snapshot(
        &self,
        tree_height: u32,
    ) -> Result<PrivateResultOramClientStateSnapshot, PrivateResultOramError> {
        private_result_oram_leaf_count(tree_height)?;
        let positions = self
            .position_map
            .iter()
            .map(|(payload_fetch_token, leaf)| {
                Ok(PrivateResultOramPositionMapSnapshotEntry {
                    payload_fetch_token: BASE64URL_NOPAD.encode(payload_fetch_token),
                    leaf_label: encode_private_result_oram_leaf_label(*leaf, tree_height)?,
                })
            })
            .collect::<Result<Vec<_>, PrivateResultOramError>>()?;
        let mut stash_point_tokens = BTreeSet::new();
        for (payload_fetch_token, block) in &self.stash {
            if block.payload_fetch_token != *payload_fetch_token {
                return Err(PrivateResultOramError::InvalidClientStateSnapshot);
            }
            if !self.position_map.contains_key(payload_fetch_token) {
                return Err(PrivateResultOramError::InvalidClientStateSnapshot);
            }
            validate_private_result_oram_client_state_stash_block(block)?;
            if !stash_point_tokens.insert(block.point_token) {
                return Err(PrivateResultOramError::InvalidClientStateSnapshot);
            }
        }

        Ok(PrivateResultOramClientStateSnapshot {
            version: PRIVATE_RESULT_ORAM_CLIENT_STATE_SNAPSHOT_VERSION,
            tree_height,
            positions,
            stash: self.stash.values().cloned().collect(),
        })
    }

    pub fn from_snapshot(
        snapshot: &PrivateResultOramClientStateSnapshot,
    ) -> Result<Self, PrivateResultOramError> {
        if snapshot.version != PRIVATE_RESULT_ORAM_CLIENT_STATE_SNAPSHOT_VERSION {
            return Err(
                PrivateResultOramError::UnsupportedClientStateSnapshotVersion(snapshot.version),
            );
        }
        private_result_oram_leaf_count(snapshot.tree_height)?;

        let mut position_map = BTreeMap::new();
        for entry in &snapshot.positions {
            let payload_fetch_token =
                decode_client_state_snapshot_payload_fetch_token(&entry.payload_fetch_token)?;
            let leaf =
                decode_private_result_oram_leaf_label(&entry.leaf_label, snapshot.tree_height)?;
            if position_map.insert(payload_fetch_token, leaf).is_some() {
                return Err(PrivateResultOramError::InvalidClientStateSnapshot);
            }
        }

        let mut stash = BTreeMap::new();
        let mut stash_point_tokens = BTreeSet::new();
        for block in &snapshot.stash {
            validate_private_result_oram_client_state_stash_block(block)?;
            if !position_map.contains_key(&block.payload_fetch_token) {
                return Err(PrivateResultOramError::InvalidClientStateSnapshot);
            }
            if !stash_point_tokens.insert(block.point_token) {
                return Err(PrivateResultOramError::InvalidClientStateSnapshot);
            }
            if stash
                .insert(block.payload_fetch_token, block.clone())
                .is_some()
            {
                return Err(PrivateResultOramError::InvalidClientStateSnapshot);
            }
        }

        Ok(Self {
            position_map,
            stash,
        })
    }

    pub fn stash_len(&self) -> usize {
        self.stash.len()
    }

    pub fn stash_contains(&self, payload_fetch_token: &[u8; 32]) -> bool {
        self.stash.contains_key(payload_fetch_token)
    }
}

pub struct PrivateResultOramClientKeys {
    bucket_aead: SecretKey,
    client_state: SecretKey,
    /// AES-GCM invocations spent on `bucket_aead` by this instance.
    bucket_seals: AeadInvocationBudget,
    /// AES-GCM invocations spent on `client_state` by this instance.
    client_state_seals: AeadInvocationBudget,
}

impl PrivateResultOramClientKeys {
    /// Legacy domain-only derivation kept for existing fixtures and clients.
    ///
    /// New private result ORAM indexes should derive from the manifest so the
    /// client keys are bound to collection/resource-key epoch context.
    #[deprecated(
        note = "use derive_from_resource_key_for_manifest or derive_from_resource_key_with_context"
    )]
    pub fn derive_from_resource_key(resource_key: &SecretKey) -> Result<Self, EncryptionError> {
        Ok(Self {
            bucket_aead: resource_key.derive_subkey(PRIVATE_RESULT_ORAM_BUCKET_AEAD_DOMAIN)?,
            client_state: resource_key
                .derive_subkey(PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_DOMAIN)?,
            bucket_seals: AeadInvocationBudget::new(),
            client_state_seals: AeadInvocationBudget::new(),
        })
    }

    pub fn derive_from_resource_key_for_manifest(
        resource_key: &SecretKey,
        manifest: &PrivateResultOramManifest,
    ) -> Result<Self, EncryptionError> {
        Self::derive_from_resource_key_with_context(
            resource_key,
            &manifest.collection_id,
            &manifest.rk_id,
            manifest.rk_epoch,
        )
    }

    pub fn derive_from_resource_key_with_context(
        resource_key: &SecretKey,
        collection_id: &str,
        rk_id: &str,
        rk_epoch: u64,
    ) -> Result<Self, EncryptionError> {
        let bucket_aead = derive_private_result_oram_context_subkey(
            resource_key,
            PRIVATE_RESULT_ORAM_BUCKET_AEAD_DOMAIN,
            collection_id,
            rk_id,
            rk_epoch,
        )?;
        let client_state = derive_private_result_oram_context_subkey(
            resource_key,
            PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_DOMAIN,
            collection_id,
            rk_id,
            rk_epoch,
        )?;

        Ok(Self {
            bucket_aead,
            client_state,
            bucket_seals: AeadInvocationBudget::new(),
            client_state_seals: AeadInvocationBudget::new(),
        })
    }

    pub fn bucket_aead_key(&self) -> &SecretKey {
        &self.bucket_aead
    }

    pub fn client_state_key(&self) -> &SecretKey {
        &self.client_state
    }

    /// AES-GCM seals performed with the bucket key by this instance.
    pub fn bucket_seal_invocations(&self) -> u64 {
        self.bucket_seals.invocations()
    }

    /// AES-GCM seals performed with the client-state key by this instance.
    pub fn client_state_seal_invocations(&self) -> u64 {
        self.client_state_seals.invocations()
    }
}

fn derive_private_result_oram_context_subkey(
    resource_key: &SecretKey,
    domain: &[u8],
    collection_id: &str,
    rk_id: &str,
    rk_epoch: u64,
) -> Result<SecretKey, EncryptionError> {
    let rk_epoch = rk_epoch.to_be_bytes();
    resource_key.derive_subkey_with_context(
        domain,
        PRIVATE_RESULT_ORAM_CLIENT_KDF_CONTEXT_DOMAIN,
        &[collection_id.as_bytes(), rk_id.as_bytes(), &rk_epoch],
    )
}

impl Debug for PrivateResultOramClientKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramClientKeys")
            .field("bucket_aead", &"[redacted; 32 bytes]")
            .field("client_state", &"[redacted; 32 bytes]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramBucketAeadContext<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub bucket_id: u64,
    pub index_epoch: u64,
}

impl Debug for PrivateResultOramBucketAeadContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramBucketAeadContext")
            .field("collection_id", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("bucket_id", &"[redacted]")
            .field("index_epoch", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramBucketAeadBaseContext<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
}

impl Debug for PrivateResultOramBucketAeadBaseContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramBucketAeadBaseContext")
            .field("collection_id", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramClientStateAeadContext<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub index_epoch: u64,
    pub root_hash: &'a str,
}

impl Debug for PrivateResultOramClientStateAeadContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramClientStateAeadContext")
            .field("collection_id", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("index_epoch", &"[redacted]")
            .field("root_hash", &"[redacted]")
            .finish()
    }
}

impl<'a> PrivateResultOramBucketAeadBaseContext<'a> {
    pub fn for_bucket(
        self,
        bucket_id: u64,
        index_epoch: u64,
    ) -> PrivateResultOramBucketAeadContext<'a> {
        PrivateResultOramBucketAeadContext {
            collection_id: self.collection_id,
            key_id: self.key_id,
            rk_id: self.rk_id,
            rk_epoch: self.rk_epoch,
            bucket_id,
            index_epoch,
        }
    }
}

/// The fixed shape a sealed client-state snapshot is padded to. `block_size_bytes` bounds every
/// stash block's payload and `stash_capacity` bounds the stash block count, so the ciphertext
/// length is a function of the position-map size alone (the signed state already publishes that
/// as its logical count) and never of which blocks the stash holds or how large they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateResultOramClientStateSnapshotPadding {
    pub block_size_bytes: usize,
    pub stash_capacity: usize,
}

fn pad_private_result_oram_client_state_snapshot(
    snapshot: &PrivateResultOramClientStateSnapshot,
    padding: PrivateResultOramClientStateSnapshotPadding,
) -> Result<Vec<u8>, PrivateResultOramError> {
    if snapshot.stash.len() > padding.stash_capacity
        || snapshot
            .stash
            .iter()
            .any(|block| block.payload.len() > padding.block_size_bytes)
    {
        return Err(PrivateResultOramError::InvalidClientStateSnapshot);
    }
    // The widest JSON one stash block can serialize to: every number at its maximum digit count,
    // `false` rather than `true`, and a payload of `block_size_bytes` three-digit bytes.
    let widest_block = PrivateResultOramPayloadBlockPlaintext {
        version: u16::MAX,
        payload_fetch_token: [u8::MAX; 32],
        point_token: [u8::MAX; 32],
        payload: vec![u8::MAX; padding.block_size_bytes],
        deleted: false,
        generation: u64::MAX,
    };
    let widest_block_len = serde_json::to_vec(&widest_block)
        .map_err(|_| PrivateResultOramError::InvalidClientStateSnapshot)?
        .len();
    // Position entries are fixed-width base64 labels (`from_snapshot` has validated them), so
    // the stash-less length depends on the position count only.
    let stashless_len = serde_json::to_vec(&PrivateResultOramClientStateSnapshot {
        version: snapshot.version,
        tree_height: snapshot.tree_height,
        positions: snapshot.positions.clone(),
        stash: Vec::new(),
    })
    .map_err(|_| PrivateResultOramError::InvalidClientStateSnapshot)?
    .len();
    let max_plaintext_len = PRIVATE_RESULT_ORAM_CLIENT_STATE_CIPHERTEXT_MAX_BYTES
        - 2
        - PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN
        - PRIVATE_RESULT_ORAM_BUCKET_AEAD_TAG_LEN;
    // `stash_capacity` blocks plus one separator each always fit, whatever the stash holds.
    let padded_len = widest_block_len
        .checked_add(1)
        .and_then(|block_len| block_len.checked_mul(padding.stash_capacity))
        .and_then(|stash_len| stash_len.checked_add(stashless_len))
        .filter(|padded_len| *padded_len <= max_plaintext_len)
        .ok_or(PrivateResultOramError::InvalidClientStateSnapshot)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(snapshot)
            .map_err(|_| PrivateResultOramError::InvalidClientStateSnapshot)?,
    );
    // JSON never carries a raw NUL (serde_json escapes control characters), so zero padding is
    // unambiguous to strip on open.
    if plaintext.len() > padded_len || plaintext.contains(&0) {
        return Err(PrivateResultOramError::InvalidClientStateSnapshot);
    }
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(&plaintext[..]);
    padded.resize(padded_len, 0);
    Ok(padded)
}

pub fn seal_private_result_oram_client_state_snapshot(
    keys: &PrivateResultOramClientKeys,
    context: PrivateResultOramClientStateAeadContext<'_>,
    snapshot: &PrivateResultOramClientStateSnapshot,
    padding: PrivateResultOramClientStateSnapshotPadding,
) -> Result<PrivateResultOramEncryptedClientStateSnapshot, PrivateResultOramError> {
    validate_private_result_client_state_context(context)?;
    PrivateResultOramClientState::from_snapshot(snapshot)?;
    let plaintext = Zeroizing::new(pad_private_result_oram_client_state_snapshot(
        snapshot, padding,
    )?);
    keys.client_state_seals
        .reserve("private result ORAM client state key")?;

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| EncryptionError::RandomFailure)?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.client_state_key().as_bytes())
        .map_err(|_| EncryptionError::SealFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = private_result_oram_client_state_aead(context)?;
    let mut in_out = plaintext;
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad.as_slice()), &mut in_out[..])
        .map_err(|_| EncryptionError::SealFailed)?;

    let mut raw_ciphertext = Vec::with_capacity(
        2 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN + in_out.len() + tag.as_ref().len(),
    );
    raw_ciphertext.extend_from_slice(&PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_VERSION.to_be_bytes());
    raw_ciphertext.extend_from_slice(&nonce_bytes);
    raw_ciphertext.extend_from_slice(&in_out[..]);
    raw_ciphertext.extend_from_slice(tag.as_ref());

    Ok(PrivateResultOramEncryptedClientStateSnapshot {
        version: PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_VERSION,
        index_epoch: context.index_epoch,
        root_hash: context.root_hash.to_string(),
        ciphertext: BASE64URL_NOPAD.encode(&raw_ciphertext),
        ciphertext_sha256: base64url_sha256(&raw_ciphertext),
    })
}

pub fn open_private_result_oram_client_state_snapshot(
    keys: &PrivateResultOramClientKeys,
    context: PrivateResultOramClientStateAeadContext<'_>,
    encrypted: &PrivateResultOramEncryptedClientStateSnapshot,
) -> Result<PrivateResultOramClientStateSnapshot, PrivateResultOramError> {
    validate_private_result_client_state_context(context)?;
    if encrypted.version != PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_VERSION {
        return Err(
            PrivateResultOramError::UnsupportedClientStateCiphertextVersion(encrypted.version),
        );
    }
    if encrypted.index_epoch != context.index_epoch || encrypted.root_hash != context.root_hash {
        return Err(PrivateResultOramError::ClientStateOpenFailed);
    }
    if encrypted.ciphertext_sha256.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateResultOramError::InvalidClientStateCiphertextHash);
    }
    validate_private_result_oram_client_state_ciphertext_encoded_len(encrypted.ciphertext.len())?;

    let raw_ciphertext = BASE64URL_NOPAD
        .decode(encrypted.ciphertext.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidClientStateCiphertextEncoding)?;
    if raw_ciphertext.len()
        < 2 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN + PRIVATE_RESULT_ORAM_BUCKET_AEAD_TAG_LEN
    {
        return Err(PrivateResultOramError::InvalidClientStateCiphertextEncoding);
    }
    if base64url_sha256(&raw_ciphertext) != encrypted.ciphertext_sha256 {
        return Err(PrivateResultOramError::InvalidClientStateCiphertextHash);
    }
    let encoded_version = u16::from_be_bytes(
        raw_ciphertext[0..2]
            .try_into()
            .map_err(|_| PrivateResultOramError::InvalidClientStateCiphertextEncoding)?,
    );
    if encoded_version != PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_VERSION {
        return Err(
            PrivateResultOramError::UnsupportedClientStateCiphertextVersion(encoded_version),
        );
    }

    let nonce_bytes: [u8; PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN] = raw_ciphertext
        [2..2 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN]
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidClientStateCiphertextEncoding)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext =
        Zeroizing::new(raw_ciphertext[2 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN..].to_vec());
    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.client_state_key().as_bytes())
        .map_err(|_| EncryptionError::OpenFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let aad = private_result_oram_client_state_aead(context)?;
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext[..])
        .map_err(|_| PrivateResultOramError::ClientStateOpenFailed)?;
    // The plaintext is zero-padded to a shape-only length; JSON never contains a raw NUL.
    let json_len = plaintext
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    let snapshot =
        serde_json::from_slice::<PrivateResultOramClientStateSnapshot>(&plaintext[..json_len])
            .map_err(|_| PrivateResultOramError::InvalidClientStateSnapshot)?;
    PrivateResultOramClientState::from_snapshot(&snapshot)?;
    Ok(snapshot)
}

pub const PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND: &str = "merkle_path_batch/v1";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramMerkleProof {
    pub kind: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub leaves: Vec<PrivateResultOramMerkleProofLeaf>,
}

impl Debug for PrivateResultOramMerkleProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramMerkleProof")
            .field("kind", &self.kind)
            .field("index_epoch", &"[redacted]")
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("leaf_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramMerkleProofLeaf {
    pub bucket_id: u64,
    pub leaf_hash: String,
    pub siblings: Vec<PrivateResultOramMerkleSibling>,
}

impl Debug for PrivateResultOramMerkleProofLeaf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramMerkleProofLeaf")
            .field("bucket_id", &"[redacted]")
            .field("leaf_hash", &"[redacted]")
            .field("sibling_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramMerkleSibling {
    pub level: u32,
    pub position: PrivateResultOramMerkleSiblingPosition,
    pub hash: String,
}

impl Debug for PrivateResultOramMerkleSibling {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramMerkleSibling")
            .field("level", &self.level)
            .field("position", &self.position)
            .field("hash", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateResultOramMerkleSiblingPosition {
    Left,
    Right,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramUploadBundle {
    pub manifest: PrivateResultOramManifest,
    pub manifest_signature: PrivateResultOramSignature,
    pub buckets: Vec<PrivateResultOramBucket>,
}

impl Debug for PrivateResultOramUploadBundle {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramUploadBundle")
            .field("manifest", &self.manifest)
            .field("manifest_signature", &self.manifest_signature)
            .field("bucket_count", &"[redacted]")
            .finish()
    }
}

impl PrivateResultOramUploadBundle {
    pub fn index_epoch(&self) -> u64 {
        self.manifest.index_epoch
    }

    pub fn root_hash(&self) -> &str {
        &self.manifest.root_hash
    }

    pub fn bucket_count(&self) -> u64 {
        self.manifest.bucket_count
    }

    pub fn bucket_commitments(&self) -> Vec<String> {
        self.buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect()
    }

    pub fn validate_initial_upload_contract(&self) -> Result<Vec<String>, PrivateResultOramError> {
        validate_private_result_oram_upload_bundle(self)
    }

    pub fn validate_initial_upload_contract_with_signature(
        &self,
        validation_context: PrivateResultOramManifestValidationContext<'_>,
    ) -> Result<Vec<String>, PrivateResultOramError> {
        validate_private_result_oram_upload_bundle_with_signature(self, validation_context)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramEpoch {
    pub epoch: u64,
    pub root_hash: [u8; 32],
}

impl Debug for PrivateResultOramEpoch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramEpoch")
            .field("epoch", &self.epoch)
            .field("root_hash", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramSignatureVerification<'a> {
    pub expected_key_id: &'a str,
    pub public_key: &'a [u8],
}

impl Debug for PrivateResultOramSignatureVerification<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramSignatureVerification")
            .field("expected_key_id", &"[redacted]")
            .field("public_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramManifestValidationContext<'a> {
    pub expected_collection_id: &'a str,
    pub expected_key_id: &'a str,
    pub expected_rk_id: &'a str,
    pub min_rk_epoch: u64,
    pub max_rk_epoch: u64,
    pub signature_verification: PrivateResultOramSignatureVerification<'a>,
}

impl Debug for PrivateResultOramManifestValidationContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramManifestValidationContext")
            .field("expected_collection_id", &"[redacted]")
            .field("expected_key_id", &"[redacted]")
            .field("expected_rk_id", &"[redacted]")
            .field("min_rk_epoch", &self.min_rk_epoch)
            .field("max_rk_epoch", &self.max_rk_epoch)
            .field("signature_verification", &self.signature_verification)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramCommitSignatureContext<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub signing_key_id: &'a str,
}

impl Debug for PrivateResultOramCommitSignatureContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramCommitSignatureContext")
            .field("collection_id", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("signing_key_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramReadBucketsSignatureContext<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub signing_key_id: &'a str,
}

impl Debug for PrivateResultOramReadBucketsSignatureContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadBucketsSignatureContext")
            .field("collection_id", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("signing_key_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramBucketValidationContext {
    pub expected_index_epoch: u64,
    pub bucket_count: u64,
    pub max_ciphertext_bytes: usize,
}

impl Debug for PrivateResultOramBucketValidationContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramBucketValidationContext")
            .field("expected_index_epoch", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("max_ciphertext_bytes", &"[redacted]")
            .finish()
    }
}

impl PrivateResultOramBucketValidationContext {
    pub fn from_manifest(
        manifest: &PrivateResultOramManifest,
        max_ciphertext_bytes: usize,
    ) -> Self {
        Self {
            expected_index_epoch: manifest.index_epoch,
            bucket_count: manifest.bucket_count,
            max_ciphertext_bytes,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramBucketCommitmentContext<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub bucket_id: u64,
    pub index_epoch: u64,
}

impl Debug for PrivateResultOramBucketCommitmentContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramBucketCommitmentContext")
            .field("collection_id", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("bucket_id", &"[redacted]")
            .field("index_epoch", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramClientCommitBucketRef {
    pub bucket_id: u64,
    pub ciphertext_sha256: String,
}

impl Debug for PrivateResultOramClientCommitBucketRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramClientCommitBucketRef")
            .field("bucket_id", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramFetchTokenPosition {
    pub payload_fetch_token: [u8; 32],
    pub leaf: u64,
}

impl Debug for PrivateResultOramFetchTokenPosition {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramFetchTokenPosition")
            .field("payload_fetch_token", &"[redacted; 32 bytes]")
            .field("leaf", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramReadBucketBatchPlan {
    pub bucket_ids: Vec<u64>,
    pub token_count: usize,
    /// Dummy paths appended when several tokens of the batch share a leaf, so every batch still
    /// reads exactly `token_count` distinct paths and a collision stays invisible to the server.
    pub padding_leaves: Vec<u64>,
}

impl Debug for PrivateResultOramReadBucketBatchPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadBucketBatchPlan")
            .field("bucket_id_count", &"[redacted]")
            .field("token_count", &"[redacted]")
            .field("padding_leaf_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramReadBucketPlan {
    pub batches: Vec<PrivateResultOramReadBucketBatchPlan>,
    pub token_count: usize,
    pub path_batch_size: usize,
}

impl Debug for PrivateResultOramReadBucketPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadBucketPlan")
            .field("batch_count", &"[redacted]")
            .field("token_count", &"[redacted]")
            .field("path_batch_size", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramOrderedReadBucketPlan {
    pub payload_fetch_tokens: Vec<[u8; 32]>,
    pub read_plan: PrivateResultOramReadBucketPlan,
}

impl Debug for PrivateResultOramOrderedReadBucketPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramOrderedReadBucketPlan")
            .field("payload_fetch_token_count", &"[redacted]")
            .field("read_plan", &self.read_plan)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramEncryptedBucketBatch {
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub proof_value: String,
    pub buckets: Vec<PrivateResultOramBucket>,
}

impl Debug for PrivateResultOramEncryptedBucketBatch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramEncryptedBucketBatch")
            .field("index_epoch", &"[redacted]")
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("proof_value", &"[redacted]")
            .field("returned_bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramTokenFetchAccess {
    pub payload_fetch_token: [u8; 32],
    pub old_leaf: u64,
    pub new_leaf: u64,
    pub block: PrivateResultOramPayloadBlockPlaintext,
}

impl Debug for PrivateResultOramTokenFetchAccess {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramTokenFetchAccess")
            .field("payload_fetch_token", &"[redacted; 32 bytes]")
            .field("old_leaf", &"[redacted]")
            .field("new_leaf", &"[redacted]")
            .field("block", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramTokenFetchResult {
    pub accesses: Vec<PrivateResultOramTokenFetchAccess>,
    pub updated_buckets: Vec<PrivateResultOramBucket>,
}

impl Debug for PrivateResultOramTokenFetchResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramTokenFetchResult")
            .field("access_count", &"[redacted]")
            .field("updated_bucket_count", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrivateResultOramCommitPlan {
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: String,
    pub new_root_hash: String,
    pub leaf_commitments: Vec<String>,
    pub updated_buckets: Vec<PrivateResultOramClientCommitBucketRef>,
}

impl Debug for PrivateResultOramCommitPlan {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramCommitPlan")
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("leaf_commitment_count", &"[redacted]")
            .field("updated_bucket_count", &"[redacted]")
            .finish()
    }
}

impl PrivateResultOramCommitPlan {
    pub fn signature_bucket_refs(&self) -> Vec<PrivateResultOramCommitBucketRef<'_>> {
        self.updated_buckets
            .iter()
            .map(|bucket| PrivateResultOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramCommitBucketRef<'a> {
    pub bucket_id: u64,
    pub ciphertext_sha256: &'a str,
}

impl Debug for PrivateResultOramCommitBucketRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramCommitBucketRef")
            .field("bucket_id", &"[redacted]")
            .field("ciphertext_sha256", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramCommitSignatureInput<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_root_hash: &'a str,
    pub new_root_hash: &'a str,
    pub updated_buckets: &'a [PrivateResultOramCommitBucketRef<'a>],
    pub signature_alg: &'a str,
    pub signature_key_id: &'a str,
}

impl Debug for PrivateResultOramCommitSignatureInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramCommitSignatureInput")
            .field("collection_id", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("old_epoch", &self.old_epoch)
            .field("new_epoch", &self.new_epoch)
            .field("old_root_hash", &"[redacted]")
            .field("new_root_hash", &"[redacted]")
            .field("updated_bucket_count", &"[redacted]")
            .field("signature_alg", &self.signature_alg)
            .field("signature_key_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PrivateResultOramReadBucketsSignatureInput<'a> {
    pub collection_id: &'a str,
    pub key_id: &'a str,
    pub rk_id: &'a str,
    pub rk_epoch: u64,
    pub index_epoch: u64,
    pub root_hash: &'a str,
    pub bucket_count: u64,
    pub bucket_ids: &'a [u64],
    pub signature_alg: &'a str,
    pub signature_key_id: &'a str,
}

impl Debug for PrivateResultOramReadBucketsSignatureInput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadBucketsSignatureInput")
            .field("collection_id", &"[redacted]")
            .field("key_id", &"[redacted]")
            .field("rk_id", &"[redacted]")
            .field("rk_epoch", &self.rk_epoch)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("requested_bucket_count", &"[redacted]")
            .field("signature_alg", &self.signature_alg)
            .field("signature_key_id", &"[redacted]")
            .finish()
    }
}

pub fn validate_private_result_oram_manifest(
    manifest: &PrivateResultOramManifest,
    signature: Option<&PrivateResultOramSignature>,
    context: PrivateResultOramManifestValidationContext<'_>,
) -> Result<PrivateResultOramEpoch, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    validate_manifest_context(manifest, context)?;
    validate_private_result_oram_manifest_signature(
        manifest,
        signature,
        context.signature_verification,
    )?;

    let root_hash = decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(PrivateResultOramEpoch {
        epoch: manifest.index_epoch,
        root_hash,
    })
}

pub fn validate_private_result_oram_manifest_shape(
    manifest: &PrivateResultOramManifest,
) -> Result<(), PrivateResultOramError> {
    if manifest.version != PRIVATE_RESULT_ORAM_MANIFEST_VERSION {
        return Err(PrivateResultOramError::UnsupportedManifestVersion(
            manifest.version,
        ));
    }
    if manifest.provider != PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER {
        return Err(PrivateResultOramError::InvalidProvider);
    }
    if manifest.binding != PRIVATE_RESULT_ORAM_BINDING {
        return Err(PrivateResultOramError::InvalidBinding);
    }
    validate_id(&manifest.collection_id, "collection_id")?;
    validate_resource_id(&manifest.key_id)?;
    validate_resource_id(&manifest.rk_id)?;
    validate_resource_id(&manifest.owner_signing_key_id)?;
    if manifest.oram.bucket_size == 0
        || manifest.oram.block_size_bytes == 0
        || manifest.oram.tree_height == 0
        || manifest.oram.path_batch_size == 0
    {
        return Err(PrivateResultOramError::InvalidManifestField("oram"));
    }
    if manifest.bucket_count == 0 {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }
    let leaf_count = private_result_oram_leaf_count(manifest.oram.tree_height)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("oram"))?;
    if u64::from(manifest.oram.path_batch_size) > leaf_count {
        return Err(PrivateResultOramError::InvalidManifestField(
            "oram.path_batch_size",
        ));
    }
    let expected_bucket_count = path_oram_bucket_count(manifest.oram.tree_height)
        .ok_or(PrivateResultOramError::InvalidManifestField("oram"))?;
    if manifest.bucket_count != expected_bucket_count {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }
    let capacity = manifest
        .bucket_count
        .checked_mul(u64::from(manifest.oram.bucket_size))
        .ok_or(PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    let result_count = manifest
        .logical_result_count
        .checked_add(manifest.dummy_result_count)
        .ok_or(PrivateResultOramError::InvalidManifestField("result_count"))?;
    if result_count > capacity {
        return Err(PrivateResultOramError::InvalidManifestField("result_count"));
    }
    decode_base64url_32(&manifest.root_hash, "root_hash")?;
    Ok(())
}

fn path_oram_bucket_count(tree_height: u32) -> Option<u64> {
    if tree_height >= 63 {
        return None;
    }
    (1u64 << tree_height)
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
}

fn path_oram_tree_height_from_bucket_count(bucket_count: u64) -> Option<u32> {
    for tree_height in 1..63 {
        let expected_bucket_count = path_oram_bucket_count(tree_height)?;
        if expected_bucket_count == bucket_count {
            return Some(tree_height);
        }
        if expected_bucket_count > bucket_count {
            return None;
        }
    }
    None
}

pub fn private_result_oram_leaf_count(tree_height: u32) -> Result<u64, PrivateResultOramError> {
    if tree_height == 0 || tree_height >= 63 {
        return Err(PrivateResultOramError::InvalidFetchPlanField("tree_height"));
    }
    Ok(1u64 << tree_height)
}

pub fn private_result_oram_bucket_count(tree_height: u32) -> Result<u64, PrivateResultOramError> {
    private_result_oram_leaf_count(tree_height)?
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .ok_or(PrivateResultOramError::InvalidFetchPlanField("tree_height"))
}

fn private_result_oram_path_len(tree_height: u32) -> Result<usize, PrivateResultOramError> {
    private_result_oram_leaf_count(tree_height)?;
    usize::try_from(tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or(PrivateResultOramError::InvalidFetchPlanField("tree_height"))
}

/// Writeback budget for a session that has read `read_path_count` result ORAM paths: one path
/// worth of buckets per read path, never below one fixed read batch, capped by the tree.
pub fn private_result_oram_session_writeback_bucket_budget(
    oram: &OramParams,
    read_path_count: usize,
) -> Result<usize, PrivateResultOramError> {
    let path_len = private_result_oram_path_len(oram.tree_height)?;
    let round_budget = private_result_oram_fixed_writeback_bucket_budget(oram)?;
    let bucket_count = usize::try_from(private_result_oram_bucket_count(oram.tree_height)?)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("oram"))?;
    Ok(round_budget
        .max(path_len.saturating_mul(read_path_count))
        .min(bucket_count))
}

/// Samples a uniformly random result ORAM leaf for a remap or padding access.
///
/// Every remap leaf passed to the result ORAM access/fetch helpers MUST be an independent uniform
/// sample; a predictable schedule lets the server link consecutive payload fetches.
pub fn sample_private_result_oram_leaf(tree_height: u32) -> Result<u64, PrivateResultOramError> {
    let leaf_count = private_result_oram_leaf_count(tree_height)?;
    crate::private_hnsw_client::sample_uniform_leaf(&ring::rand::SystemRandom::new(), leaf_count)
        .ok_or_else(|| EncryptionError::RandomFailure.into())
}

pub fn private_result_oram_fixed_writeback_bucket_budget(
    oram: &OramParams,
) -> Result<usize, PrivateResultOramError> {
    let path_len = private_result_oram_path_len(oram.tree_height)?;
    let path_batch_size = usize::try_from(oram.path_batch_size)
        .map_err(|_| PrivateResultOramError::InvalidFetchPlanField("path_batch_size"))?;
    if path_batch_size == 0 {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "path_batch_size",
        ));
    }
    path_len
        .checked_mul(path_batch_size)
        .ok_or(PrivateResultOramError::InvalidFetchPlanField(
            "updated_buckets",
        ))
}

pub fn private_result_oram_bucket_ids_for_leaf(
    leaf: u64,
    tree_height: u32,
) -> Result<Vec<u64>, PrivateResultOramError> {
    validate_private_result_oram_leaf(leaf, tree_height)?;
    let mut bucket_ids = Vec::with_capacity(private_result_oram_path_len(tree_height)?);
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

pub fn encode_private_result_oram_leaf_label(
    leaf: u64,
    tree_height: u32,
) -> Result<String, PrivateResultOramError> {
    validate_private_result_oram_leaf(leaf, tree_height)?;
    Ok(BASE64URL_NOPAD.encode(&leaf.to_be_bytes()))
}

pub fn decode_private_result_oram_leaf_label(
    label: &str,
    tree_height: u32,
) -> Result<u64, PrivateResultOramError> {
    let bytes = decode_private_result_oram_leaf_label_shape(label)?;
    let leaf = u64::from_be_bytes(bytes);
    validate_private_result_oram_leaf(leaf, tree_height)?;
    Ok(leaf)
}

fn validate_private_result_oram_leaf(
    leaf: u64,
    tree_height: u32,
) -> Result<(), PrivateResultOramError> {
    if leaf >= private_result_oram_leaf_count(tree_height)? {
        return Err(PrivateResultOramError::InvalidFetchPlanField("leaf"));
    }
    Ok(())
}

fn validate_private_result_oram_client_state_stash_block(
    block: &PrivateResultOramPayloadBlockPlaintext,
) -> Result<(), PrivateResultOramError> {
    if block.version != PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION {
        return Err(PrivateResultOramError::InvalidClientStateSnapshot);
    }
    let _: u32 = block
        .payload
        .len()
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidClientStateSnapshot)?;
    Ok(())
}

fn decode_private_result_oram_leaf_label_shape(
    label: &str,
) -> Result<[u8; 8], PrivateResultOramError> {
    if label.len() != BASE64URL_NOPAD_8_BYTE_LEN {
        return Err(PrivateResultOramError::InvalidClientStateSnapshot);
    }
    let bytes = BASE64URL_NOPAD
        .decode(label.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidClientStateSnapshot)?;
    bytes
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidClientStateSnapshot)
}

fn decode_client_state_snapshot_payload_fetch_token(
    value: &str,
) -> Result<[u8; 32], PrivateResultOramError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateResultOramError::InvalidClientStateSnapshot);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidClientStateSnapshot)?;
    bytes
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidClientStateSnapshot)
}

/// Plans the fixed-size read batches for `payload_fetch_tokens`.
///
/// Tokens of one batch that share a Path ORAM leaf are read once and the batch is topped up with
/// dummy paths from `next_padding_leaf` (which MUST return independent uniform samples, see
/// [`sample_private_result_oram_leaf`]), so a leaf collision never changes the shape of the
/// request the server observes.
pub fn plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
    manifest: &PrivateResultOramManifest,
    payload_fetch_tokens: &[[u8; 32]],
    token_positions: &[PrivateResultOramFetchTokenPosition],
    mut next_padding_leaf: impl FnMut() -> Result<u64, PrivateResultOramError>,
) -> Result<PrivateResultOramReadBucketPlan, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    if manifest.bucket_count != private_result_oram_bucket_count(manifest.oram.tree_height)? {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }
    if payload_fetch_tokens.is_empty() {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "payload_fetch_tokens",
        ));
    }
    let path_batch_size = usize::try_from(manifest.oram.path_batch_size)
        .map_err(|_| PrivateResultOramError::InvalidFetchPlanField("path_batch_size"))?;
    if path_batch_size == 0 {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "path_batch_size",
        ));
    }
    if payload_fetch_tokens.len() % path_batch_size != 0 {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "payload_fetch_tokens",
        ));
    }

    let mut positions = BTreeMap::new();
    for position in token_positions {
        validate_private_result_oram_leaf(position.leaf, manifest.oram.tree_height)?;
        if positions
            .insert(position.payload_fetch_token, position.leaf)
            .is_some()
        {
            return Err(PrivateResultOramError::DuplicatePayloadFetchTokenPosition);
        }
    }

    let leaf_count = private_result_oram_leaf_count(manifest.oram.tree_height)?;
    let max_padding_attempts = leaf_count.saturating_mul(8).saturating_add(64);
    let mut seen_tokens = BTreeSet::new();
    let mut batches = Vec::new();
    for token_batch in payload_fetch_tokens.chunks(path_batch_size) {
        let mut batch_leaves = Vec::with_capacity(token_batch.len());
        let mut seen_batch_leaves = BTreeSet::new();
        for token in token_batch {
            if !seen_tokens.insert(*token) {
                return Err(PrivateResultOramError::DuplicatePayloadFetchToken);
            }
            let leaf = positions
                .get(token)
                .copied()
                .ok_or(PrivateResultOramError::MissingPayloadFetchTokenPosition)?;
            if seen_batch_leaves.insert(leaf) {
                batch_leaves.push(leaf);
            }
        }
        let mut padding_leaves = Vec::new();
        let mut padding_attempts = 0u64;
        while batch_leaves.len() + padding_leaves.len() < token_batch.len() {
            let leaf = next_padding_leaf()?;
            validate_private_result_oram_leaf(leaf, manifest.oram.tree_height)?;
            padding_attempts += 1;
            if seen_batch_leaves.insert(leaf) {
                padding_leaves.push(leaf);
            } else if padding_attempts > max_padding_attempts {
                return Err(PrivateResultOramError::InvalidFetchPlanField(
                    "padding_leaves",
                ));
            }
        }
        // Canonical leaf order: listing the real paths first and the padding paths last would
        // tell the server which paths pad a leaf collision, and therefore that two of the
        // fetched payloads share a path.
        let mut ordered_leaves: Vec<u64> = batch_leaves
            .iter()
            .chain(&padding_leaves)
            .copied()
            .collect();
        ordered_leaves.sort_unstable();
        let mut bucket_ids = Vec::new();
        for leaf in &ordered_leaves {
            bucket_ids.extend(private_result_oram_bucket_ids_for_leaf(
                *leaf,
                manifest.oram.tree_height,
            )?);
        }
        batches.push(PrivateResultOramReadBucketBatchPlan {
            bucket_ids,
            token_count: token_batch.len(),
            padding_leaves,
        });
    }

    Ok(PrivateResultOramReadBucketPlan {
        batches,
        token_count: payload_fetch_tokens.len(),
        path_batch_size,
    })
}

/// Reorders `payload_fetch_tokens` so that leaf collisions are spread across batches where
/// possible; collisions that cannot be spread are padded by the batch planner instead of failing.
pub fn plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens(
    manifest: &PrivateResultOramManifest,
    payload_fetch_tokens: &[[u8; 32]],
    token_positions: &[PrivateResultOramFetchTokenPosition],
    next_padding_leaf: impl FnMut() -> Result<u64, PrivateResultOramError>,
) -> Result<PrivateResultOramOrderedReadBucketPlan, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    if manifest.bucket_count != private_result_oram_bucket_count(manifest.oram.tree_height)? {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }
    if payload_fetch_tokens.is_empty() {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "payload_fetch_tokens",
        ));
    }
    let path_batch_size = usize::try_from(manifest.oram.path_batch_size)
        .map_err(|_| PrivateResultOramError::InvalidFetchPlanField("path_batch_size"))?;
    if path_batch_size == 0 {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "path_batch_size",
        ));
    }
    if payload_fetch_tokens.len() % path_batch_size != 0 {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "payload_fetch_tokens",
        ));
    }
    let batch_count = payload_fetch_tokens.len() / path_batch_size;

    let mut positions = BTreeMap::new();
    for position in token_positions {
        validate_private_result_oram_leaf(position.leaf, manifest.oram.tree_height)?;
        if positions
            .insert(position.payload_fetch_token, position.leaf)
            .is_some()
        {
            return Err(PrivateResultOramError::DuplicatePayloadFetchTokenPosition);
        }
    }

    let mut seen_tokens = BTreeSet::new();
    let mut tokens_by_leaf = BTreeMap::<u64, VecDeque<[u8; 32]>>::new();
    for token in payload_fetch_tokens {
        if !seen_tokens.insert(*token) {
            return Err(PrivateResultOramError::DuplicatePayloadFetchToken);
        }
        let leaf = positions
            .get(token)
            .copied()
            .ok_or(PrivateResultOramError::MissingPayloadFetchTokenPosition)?;
        tokens_by_leaf.entry(leaf).or_default().push_back(*token);
    }

    let mut ordered_payload_fetch_tokens = Vec::with_capacity(payload_fetch_tokens.len());
    for _batch_index in 0..batch_count {
        let mut batch_leaves = BTreeSet::new();
        for _slot in 0..path_batch_size {
            let mut selected_leaf = None;
            let mut selected_len = 0;
            for (leaf, tokens) in &tokens_by_leaf {
                if batch_leaves.contains(leaf) || tokens.is_empty() {
                    continue;
                }
                if selected_leaf.is_none() || tokens.len() > selected_len {
                    selected_leaf = Some(*leaf);
                    selected_len = tokens.len();
                }
            }
            // Every remaining token collides with a leaf already in this batch: place one
            // anyway (the batch planner pads the duplicate path with a dummy leaf), taking it
            // from the leaf with the most tokens left so that collisions do not pile up in the
            // last batches.
            let leaf = match selected_leaf {
                Some(leaf) => leaf,
                None => tokens_by_leaf
                    .iter()
                    .filter(|(_, tokens)| !tokens.is_empty())
                    .max_by_key(|(_, tokens)| tokens.len())
                    .map(|(leaf, _)| *leaf)
                    .ok_or(PrivateResultOramError::InvalidFetchPlanField("bucket_ids"))?,
            };
            let token = tokens_by_leaf
                .get_mut(&leaf)
                .and_then(VecDeque::pop_front)
                .ok_or(PrivateResultOramError::InvalidFetchPlanField("bucket_ids"))?;
            batch_leaves.insert(leaf);
            ordered_payload_fetch_tokens.push(token);
        }
    }

    let read_plan = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
        manifest,
        &ordered_payload_fetch_tokens,
        token_positions,
        next_padding_leaf,
    )?;
    Ok(PrivateResultOramOrderedReadBucketPlan {
        payload_fetch_tokens: ordered_payload_fetch_tokens,
        read_plan,
    })
}

pub fn private_result_oram_client_config_from_manifest(
    manifest: &PrivateResultOramManifest,
) -> Result<PrivateResultOramClientConfig, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    let config = PrivateResultOramClientConfig {
        tree_height: manifest.oram.tree_height,
        bucket_size: usize::try_from(manifest.oram.bucket_size)
            .map_err(|_| PrivateResultOramError::InvalidClientConfig("bucket_size"))?,
        block_size_bytes: usize::try_from(manifest.oram.block_size_bytes)
            .map_err(|_| PrivateResultOramError::InvalidClientConfig("block_size_bytes"))?,
    };
    validate_private_result_oram_client_config(config)?;
    Ok(config)
}

pub fn validate_private_result_oram_client_config(
    config: PrivateResultOramClientConfig,
) -> Result<(), PrivateResultOramError> {
    private_result_oram_leaf_count(config.tree_height)?;
    if config.bucket_size == 0 {
        return Err(PrivateResultOramError::InvalidClientConfig("bucket_size"));
    }
    if config.block_size_bytes == 0 {
        return Err(PrivateResultOramError::InvalidClientConfig(
            "block_size_bytes",
        ));
    }
    private_result_oram_bucket_plaintext_slots_len(config)?;
    Ok(())
}

fn private_result_oram_bucket_plaintext_slots_len(
    config: PrivateResultOramClientConfig,
) -> Result<usize, PrivateResultOramError> {
    let slot_len = config.block_size_bytes.checked_add(1).ok_or(
        PrivateResultOramError::InvalidClientConfig("block_size_bytes"),
    )?;
    config
        .bucket_size
        .checked_mul(slot_len)
        .ok_or(PrivateResultOramError::InvalidClientConfig("bucket_size"))
}

pub fn empty_private_result_oram_plaintext_bucket(
    bucket_id: u64,
    config: PrivateResultOramClientConfig,
) -> Result<PrivateResultOramPlaintextBucket, PrivateResultOramError> {
    validate_private_result_oram_client_config(config)?;
    Ok(PrivateResultOramPlaintextBucket {
        bucket_id,
        blocks: vec![None; config.bucket_size],
    })
}

pub fn access_private_result_oram_path(
    state: &mut PrivateResultOramClientState,
    config: PrivateResultOramClientConfig,
    target_payload_fetch_token: [u8; 32],
    path_buckets: &[PrivateResultOramPlaintextBucket],
    remap_leaf: u64,
) -> Result<PrivateResultOramAccessResult, PrivateResultOramError> {
    validate_private_result_oram_client_config(config)?;
    let old_leaf = state
        .position(&target_payload_fetch_token)
        .ok_or(PrivateResultOramError::MissingPosition)?;
    validate_private_result_oram_leaf(remap_leaf, config.tree_height)?;
    let expected_bucket_ids =
        private_result_oram_bucket_ids_for_leaf(old_leaf, config.tree_height)?;
    load_private_result_oram_path_into_stash(
        state,
        config,
        &expected_bucket_ids,
        path_buckets,
        Some(&target_payload_fetch_token),
    )?;

    let block = state
        .stash
        .get(&target_payload_fetch_token)
        .cloned()
        .ok_or(PrivateResultOramError::MissingBlock)?;
    state
        .position_map
        .insert(target_payload_fetch_token, remap_leaf);
    let writeback_buckets = evict_private_result_loaded_path(state, config, &expected_bucket_ids)?;

    Ok(PrivateResultOramAccessResult {
        old_leaf,
        new_leaf: remap_leaf,
        block,
        writeback_buckets,
    })
}

pub fn evict_private_result_oram_path(
    state: &mut PrivateResultOramClientState,
    config: PrivateResultOramClientConfig,
    leaf: u64,
    path_buckets: &[PrivateResultOramPlaintextBucket],
) -> Result<PrivateResultOramEvictionResult, PrivateResultOramError> {
    validate_private_result_oram_client_config(config)?;
    validate_private_result_oram_leaf(leaf, config.tree_height)?;
    let mut working_state = state.clone();
    let expected_bucket_ids = private_result_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
    load_private_result_oram_path_into_stash(
        &mut working_state,
        config,
        &expected_bucket_ids,
        path_buckets,
        None,
    )?;
    let writeback_buckets =
        evict_private_result_loaded_path(&mut working_state, config, &expected_bucket_ids)?;
    *state = working_state;
    Ok(PrivateResultOramEvictionResult {
        leaf,
        writeback_buckets,
    })
}

/// Validates a served path and moves its blocks into the stash.
///
/// Every check runs before the first block is stashed: a path rejected here leaves the client
/// state untouched. `required_payload_fetch_token` is the block an access needs; failing on it
/// after the load would strand the other path blocks in the stash while the server still
/// stores them, and the next read of an overlapping path would then be rejected as a duplicate.
fn load_private_result_oram_path_into_stash(
    state: &mut PrivateResultOramClientState,
    config: PrivateResultOramClientConfig,
    expected_bucket_ids: &[u64],
    path_buckets: &[PrivateResultOramPlaintextBucket],
    required_payload_fetch_token: Option<&[u8; 32]>,
) -> Result<(), PrivateResultOramError> {
    if path_buckets.len() != expected_bucket_ids.len()
        || path_buckets
            .iter()
            .zip(expected_bucket_ids)
            .any(|(bucket, expected_id)| bucket.bucket_id != *expected_id)
    {
        return Err(PrivateResultOramError::PathBucketMismatch);
    }

    let mut path_payload_fetch_tokens = BTreeSet::new();
    let mut path_point_tokens = state
        .stash
        .values()
        .map(|block| block.point_token)
        .collect::<BTreeSet<_>>();
    for bucket in path_buckets {
        if bucket.blocks.len() != config.bucket_size {
            return Err(PrivateResultOramError::BucketPlaintextSlotCountMismatch);
        }
        for block in bucket.blocks.iter().flatten() {
            if state.stash.contains_key(&block.payload_fetch_token)
                || !path_payload_fetch_tokens.insert(block.payload_fetch_token)
            {
                return Err(PrivateResultOramError::DuplicatePayloadFetchToken);
            }
            if !path_point_tokens.insert(block.point_token) {
                return Err(PrivateResultOramError::DuplicatePointToken);
            }
        }
    }
    if let Some(required) = required_payload_fetch_token
        && !state.stash.contains_key(required)
        && !path_payload_fetch_tokens.contains(required)
    {
        return Err(PrivateResultOramError::MissingBlock);
    }
    for block in path_buckets
        .iter()
        .flat_map(|bucket| bucket.blocks.iter().flatten())
    {
        state.stash.insert(block.payload_fetch_token, block.clone());
    }
    Ok(())
}

fn evict_private_result_loaded_path(
    state: &mut PrivateResultOramClientState,
    config: PrivateResultOramClientConfig,
    expected_bucket_ids: &[u64],
) -> Result<Vec<PrivateResultOramPlaintextBucket>, PrivateResultOramError> {
    let mut writeback_by_bucket: BTreeMap<u64, PrivateResultOramPlaintextBucket> = BTreeMap::new();
    for bucket_id in expected_bucket_ids.iter().rev() {
        let mut blocks = Vec::with_capacity(config.bucket_size);
        while blocks.len() < config.bucket_size {
            let candidate_token = state.stash.keys().copied().find(|payload_fetch_token| {
                let Some(leaf) = state.position_map.get(payload_fetch_token) else {
                    return false;
                };
                private_result_oram_bucket_ids_for_leaf(*leaf, config.tree_height)
                    .map(|path| path.contains(bucket_id))
                    .unwrap_or(false)
            });
            let Some(candidate_token) = candidate_token else {
                break;
            };
            let block = state
                .stash
                .remove(&candidate_token)
                .ok_or(PrivateResultOramError::MissingBlock)?;
            blocks.push(Some(block));
        }
        blocks.resize(config.bucket_size, None);
        writeback_by_bucket.insert(
            *bucket_id,
            PrivateResultOramPlaintextBucket {
                bucket_id: *bucket_id,
                blocks,
            },
        );
    }

    expected_bucket_ids
        .iter()
        .map(|bucket_id| {
            writeback_by_bucket
                .remove(bucket_id)
                .ok_or(PrivateResultOramError::PathBucketMismatch)
        })
        .collect()
}

pub fn encode_private_result_oram_payload_block(
    block: &PrivateResultOramPayloadBlockPlaintext,
    block_size_bytes: usize,
) -> Result<Vec<u8>, PrivateResultOramError> {
    if block.version != PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION {
        return Err(PrivateResultOramError::UnsupportedPayloadBlockVersion(
            block.version,
        ));
    }
    if block_size_bytes == 0 {
        return Err(PrivateResultOramError::InvalidClientConfig(
            "block_size_bytes",
        ));
    }
    let payload_len: u32 = block
        .payload
        .len()
        .try_into()
        .map_err(|_| PrivateResultOramError::PayloadBlockOversized)?;

    let mut encoded = Vec::new();
    encoded.extend_from_slice(PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_MAGIC);
    push_u16(&mut encoded, PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION);
    encoded.extend_from_slice(&block.payload_fetch_token);
    encoded.extend_from_slice(&block.point_token);
    encoded.push(u8::from(block.deleted));
    push_u64(&mut encoded, block.generation);
    push_u32(&mut encoded, payload_len);
    encoded.extend_from_slice(&block.payload);

    if encoded.len() > block_size_bytes {
        return Err(PrivateResultOramError::PayloadBlockOversized);
    }
    encoded.resize(block_size_bytes, 0);
    Ok(encoded)
}

pub fn decode_private_result_oram_payload_block(
    encoded: &[u8],
) -> Result<PrivateResultOramPayloadBlockPlaintext, PrivateResultOramError> {
    let mut cursor = 0;
    let magic = read_payload_exact(
        encoded,
        &mut cursor,
        PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_MAGIC.len(),
    )?;
    if magic != PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_MAGIC {
        return Err(PrivateResultOramError::InvalidPayloadBlock);
    }
    let version = read_payload_u16(encoded, &mut cursor)?;
    if version != PRIVATE_RESULT_ORAM_PAYLOAD_BLOCK_VERSION {
        return Err(PrivateResultOramError::UnsupportedPayloadBlockVersion(
            version,
        ));
    }
    let payload_fetch_token = read_payload_array_32(encoded, &mut cursor)?;
    let point_token = read_payload_array_32(encoded, &mut cursor)?;
    let deleted = match read_payload_u8(encoded, &mut cursor)? {
        0 => false,
        1 => true,
        _ => return Err(PrivateResultOramError::InvalidPayloadBlock),
    };
    let generation = read_payload_u64(encoded, &mut cursor)?;
    let payload_len = read_payload_u32_usize(encoded, &mut cursor)?;
    let payload = read_payload_exact(encoded, &mut cursor, payload_len)?.to_vec();
    if encoded[cursor..].iter().any(|byte| *byte != 0) {
        return Err(PrivateResultOramError::InvalidPayloadBlockPadding);
    }
    Ok(PrivateResultOramPayloadBlockPlaintext {
        version,
        payload_fetch_token,
        point_token,
        payload,
        deleted,
        generation,
    })
}

pub fn encode_private_result_oram_bucket_plaintext(
    bucket: &PrivateResultOramPlaintextBucket,
    config: PrivateResultOramClientConfig,
) -> Result<Vec<u8>, PrivateResultOramError> {
    validate_private_result_oram_client_config(config)?;
    if bucket.blocks.len() != config.bucket_size {
        return Err(PrivateResultOramError::BucketPlaintextSlotCountMismatch);
    }
    validate_private_result_plaintext_bucket_tokens(&bucket.blocks)?;
    let bucket_size_u32: u32 = config
        .bucket_size
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidClientConfig("bucket_size"))?;
    let block_size_u32: u32 = config
        .block_size_bytes
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidClientConfig("block_size_bytes"))?;

    let mut encoded = Vec::new();
    encoded.extend_from_slice(PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_MAGIC);
    push_u16(&mut encoded, PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_VERSION);
    push_u64(&mut encoded, bucket.bucket_id);
    push_u32(&mut encoded, bucket_size_u32);
    push_u32(&mut encoded, block_size_u32);

    for slot in &bucket.blocks {
        match slot {
            Some(block) => {
                encoded.push(1);
                encoded.extend_from_slice(&encode_private_result_oram_payload_block(
                    block,
                    config.block_size_bytes,
                )?);
            }
            None => {
                encoded.push(0);
                let next_len = encoded.len().checked_add(config.block_size_bytes).ok_or(
                    PrivateResultOramError::InvalidClientConfig("block_size_bytes"),
                )?;
                encoded.resize(next_len, 0);
            }
        }
    }

    Ok(encoded)
}

pub fn decode_private_result_oram_bucket_plaintext(
    bucket_id: u64,
    encoded: &[u8],
    config: PrivateResultOramClientConfig,
) -> Result<PrivateResultOramPlaintextBucket, PrivateResultOramError> {
    validate_private_result_oram_client_config(config)?;
    let mut cursor = 0;
    let magic = read_bucket_exact(
        encoded,
        &mut cursor,
        PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_MAGIC.len(),
    )?;
    if magic != PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_MAGIC {
        return Err(PrivateResultOramError::InvalidBucketPlaintext);
    }
    let version = read_bucket_u16(encoded, &mut cursor)?;
    if version != PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_VERSION {
        return Err(PrivateResultOramError::InvalidBucketPlaintext);
    }
    let encoded_bucket_id = read_bucket_u64(encoded, &mut cursor)?;
    if encoded_bucket_id != bucket_id {
        return Err(PrivateResultOramError::InvalidBucketPlaintext);
    }
    let encoded_bucket_size = read_bucket_u32_usize(encoded, &mut cursor)?;
    let encoded_block_size = read_bucket_u32_usize(encoded, &mut cursor)?;
    if encoded_bucket_size != config.bucket_size || encoded_block_size != config.block_size_bytes {
        return Err(PrivateResultOramError::BucketPlaintextSlotCountMismatch);
    }

    let mut blocks = Vec::with_capacity(config.bucket_size);
    for _ in 0..config.bucket_size {
        let present = read_bucket_u8(encoded, &mut cursor)?;
        let block_bytes = read_bucket_exact(encoded, &mut cursor, config.block_size_bytes)?;
        match present {
            0 => {
                if block_bytes.iter().any(|byte| *byte != 0) {
                    return Err(PrivateResultOramError::InvalidBucketPlaintext);
                }
                blocks.push(None);
            }
            1 => blocks.push(Some(decode_private_result_oram_payload_block(block_bytes)?)),
            _ => return Err(PrivateResultOramError::InvalidBucketPlaintext),
        }
    }
    if cursor != encoded.len() {
        return Err(PrivateResultOramError::InvalidBucketPlaintext);
    }

    validate_private_result_plaintext_bucket_tokens(&blocks)?;
    Ok(PrivateResultOramPlaintextBucket { bucket_id, blocks })
}

fn validate_private_result_plaintext_bucket_tokens(
    blocks: &[Option<PrivateResultOramPayloadBlockPlaintext>],
) -> Result<(), PrivateResultOramError> {
    let mut payload_fetch_tokens = BTreeSet::new();
    let mut point_tokens = BTreeSet::new();
    for block in blocks.iter().flatten() {
        if !payload_fetch_tokens.insert(block.payload_fetch_token) {
            return Err(PrivateResultOramError::DuplicatePayloadFetchToken);
        }
        if !point_tokens.insert(block.point_token) {
            return Err(PrivateResultOramError::DuplicatePointToken);
        }
    }
    Ok(())
}

pub fn seal_private_result_oram_bucket(
    keys: &PrivateResultOramClientKeys,
    context: PrivateResultOramBucketAeadContext<'_>,
    plaintext: &[u8],
) -> Result<PrivateResultOramBucket, PrivateResultOramError> {
    validate_private_result_bucket_context(context)?;
    keys.bucket_seals
        .reserve("private result ORAM bucket key")?;

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| EncryptionError::RandomFailure)?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.bucket_aead_key().as_bytes())
        .map_err(|_| EncryptionError::SealFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = private_result_oram_bucket_aead(context)?;
    let mut in_out = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad.as_slice()), &mut in_out)
        .map_err(|_| EncryptionError::SealFailed)?;
    in_out.extend_from_slice(tag.as_ref());

    let mut raw_ciphertext =
        Vec::with_capacity(1 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN + in_out.len());
    raw_ciphertext.push(PRIVATE_RESULT_ORAM_BUCKET_AEAD_VERSION);
    raw_ciphertext.extend_from_slice(&nonce_bytes);
    raw_ciphertext.extend_from_slice(&in_out);

    let ciphertext_sha256 = base64url_sha256(&raw_ciphertext);
    let bucket_commitment = private_result_oram_bucket_commitment(
        PrivateResultOramBucketCommitmentContext {
            collection_id: context.collection_id,
            key_id: context.key_id,
            rk_id: context.rk_id,
            rk_epoch: context.rk_epoch,
            bucket_id: context.bucket_id,
            index_epoch: context.index_epoch,
        },
        &ciphertext_sha256,
    )?;

    Ok(PrivateResultOramBucket {
        version: PRIVATE_RESULT_ORAM_BUCKET_VERSION,
        bucket_id: context.bucket_id,
        index_epoch: context.index_epoch,
        ciphertext: BASE64URL_NOPAD.encode(&raw_ciphertext),
        ciphertext_sha256,
        bucket_commitment,
    })
}

pub fn open_private_result_oram_bucket(
    keys: &PrivateResultOramClientKeys,
    context: PrivateResultOramBucketAeadContext<'_>,
    bucket: &PrivateResultOramBucket,
) -> Result<Vec<u8>, PrivateResultOramError> {
    validate_private_result_bucket_context(context)?;
    if bucket.version != PRIVATE_RESULT_ORAM_BUCKET_VERSION
        || bucket.bucket_id != context.bucket_id
        || bucket.index_epoch != context.index_epoch
    {
        return Err(PrivateResultOramError::BucketMetadataMismatch);
    }

    let Some(decoded_len) = base64url_nopad_decoded_len(bucket.ciphertext.len()) else {
        return Err(PrivateResultOramError::InvalidBucketCiphertextEncoding);
    };
    if decoded_len > PRIVATE_RESULT_ORAM_BUCKET_CIPHERTEXT_OPEN_MAX_BYTES {
        return Err(PrivateResultOramError::InvalidBucketCiphertextEncoding);
    }
    let raw_ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidBucketCiphertextEncoding)?;
    if raw_ciphertext.len()
        < 1 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN + PRIVATE_RESULT_ORAM_BUCKET_AEAD_TAG_LEN
    {
        return Err(PrivateResultOramError::InvalidBucketCiphertextEncoding);
    }
    let ciphertext_sha256 = base64url_sha256(&raw_ciphertext);
    if ciphertext_sha256 != bucket.ciphertext_sha256 {
        return Err(PrivateResultOramError::InvalidBucketCiphertextHash);
    }
    let expected_commitment = private_result_oram_bucket_commitment(
        PrivateResultOramBucketCommitmentContext {
            collection_id: context.collection_id,
            key_id: context.key_id,
            rk_id: context.rk_id,
            rk_epoch: context.rk_epoch,
            bucket_id: context.bucket_id,
            index_epoch: context.index_epoch,
        },
        &bucket.ciphertext_sha256,
    )?;
    if expected_commitment != bucket.bucket_commitment {
        return Err(PrivateResultOramError::InvalidBucketCommitment);
    }
    if raw_ciphertext[0] != PRIVATE_RESULT_ORAM_BUCKET_AEAD_VERSION {
        return Err(PrivateResultOramError::UnsupportedBucketCiphertextVersion(
            raw_ciphertext[0],
        ));
    }

    let nonce_bytes: [u8; PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN] = raw_ciphertext
        [1..1 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN]
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidBucketCiphertextEncoding)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext =
        Zeroizing::new(raw_ciphertext[1 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN..].to_vec());

    let unbound_key = UnboundKey::new(&AES_256_GCM, keys.bucket_aead_key().as_bytes())
        .map_err(|_| EncryptionError::OpenFailed)?;
    let key = LessSafeKey::new(unbound_key);
    let aad = private_result_oram_bucket_aead(context)?;
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext[..])
        .map_err(|_| PrivateResultOramError::BucketOpenFailed)?;
    Ok(plaintext.to_vec())
}

pub fn seal_private_result_oram_plaintext_bucket(
    keys: &PrivateResultOramClientKeys,
    base_context: PrivateResultOramBucketAeadBaseContext<'_>,
    index_epoch: u64,
    bucket: &PrivateResultOramPlaintextBucket,
    config: PrivateResultOramClientConfig,
) -> Result<PrivateResultOramBucket, PrivateResultOramError> {
    let plaintext = encode_private_result_oram_bucket_plaintext(bucket, config)?;
    seal_private_result_oram_bucket(
        keys,
        base_context.for_bucket(bucket.bucket_id, index_epoch),
        &plaintext,
    )
}

pub fn open_private_result_oram_plaintext_bucket(
    keys: &PrivateResultOramClientKeys,
    base_context: PrivateResultOramBucketAeadBaseContext<'_>,
    bucket: &PrivateResultOramBucket,
    config: PrivateResultOramClientConfig,
) -> Result<PrivateResultOramPlaintextBucket, PrivateResultOramError> {
    let plaintext = open_private_result_oram_bucket(
        keys,
        base_context.for_bucket(bucket.bucket_id, bucket.index_epoch),
        bucket,
    )?;
    decode_private_result_oram_bucket_plaintext(bucket.bucket_id, &plaintext, config)
}

pub fn open_private_result_oram_verified_bucket_batch(
    keys: &PrivateResultOramClientKeys,
    base_context: PrivateResultOramBucketAeadBaseContext<'_>,
    config: PrivateResultOramClientConfig,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    proof_value: &str,
    buckets: &[PrivateResultOramBucket],
) -> Result<Vec<PrivateResultOramPlaintextBucket>, PrivateResultOramError> {
    verify_private_result_oram_merkle_proof_json(
        proof_value,
        expected_epoch,
        expected_root_hash,
        expected_bucket_count,
        buckets,
    )?;
    buckets
        .iter()
        .map(|bucket| open_private_result_oram_plaintext_bucket(keys, base_context, bucket, config))
        .collect()
}

pub fn fetch_private_result_oram_tokens_encrypted_verified<NextLeaf>(
    keys: &PrivateResultOramClientKeys,
    base_context: PrivateResultOramBucketAeadBaseContext<'_>,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    writeback_epoch: u64,
    state: &mut PrivateResultOramClientState,
    config: PrivateResultOramClientConfig,
    payload_fetch_tokens: &[[u8; 32]],
    read_plan: &PrivateResultOramReadBucketPlan,
    encrypted_batches: &[PrivateResultOramEncryptedBucketBatch],
    mut next_remap_leaf: NextLeaf,
) -> Result<PrivateResultOramTokenFetchResult, PrivateResultOramError>
where
    NextLeaf: FnMut() -> Result<u64, PrivateResultOramError>,
{
    validate_private_result_oram_client_config(config)?;
    if Some(writeback_epoch) != expected_epoch.checked_add(1) {
        return Err(PrivateResultOramError::InvalidManifestField("new_epoch"));
    }
    if payload_fetch_tokens.is_empty() {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "payload_fetch_tokens",
        ));
    }
    if read_plan.token_count != payload_fetch_tokens.len() {
        return Err(PrivateResultOramError::InvalidFetchPlanField("read_plan"));
    }
    if read_plan.path_batch_size == 0 {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "path_batch_size",
        ));
    }
    let leaf_count = private_result_oram_leaf_count(config.tree_height)?;
    let path_batch_size = u64::try_from(read_plan.path_batch_size)
        .map_err(|_| PrivateResultOramError::InvalidFetchPlanField("path_batch_size"))?;
    if path_batch_size > leaf_count {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "path_batch_size",
        ));
    }
    if payload_fetch_tokens.len() % read_plan.path_batch_size != 0 {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "payload_fetch_tokens",
        ));
    }
    if expected_bucket_count != private_result_oram_bucket_count(config.tree_height)? {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "bucket_count",
        ));
    }

    let expected_batch_count = payload_fetch_tokens
        .chunks(read_plan.path_batch_size)
        .count();
    if read_plan.batches.len() != expected_batch_count {
        return Err(PrivateResultOramError::InvalidFetchPlanField("batches"));
    }
    if encrypted_batches.len() != expected_batch_count {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "encrypted_batches",
        ));
    }

    let mut seen_tokens = BTreeSet::new();
    for token in payload_fetch_tokens {
        if !seen_tokens.insert(*token) {
            return Err(PrivateResultOramError::DuplicatePayloadFetchToken);
        }
    }

    // Every bucket a verified fetch opens has the fixed ciphertext size the geometry implies.
    // Checking the encoded length before the Merkle proof decodes the ciphertexts keeps a hostile
    // server from making the client allocate an arbitrarily large buffer per bucket.
    let expected_ciphertext_encoded_len =
        max_base64url_nopad_encoded_len(private_result_oram_bucket_ciphertext_bytes_for_geometry(
            config.bucket_size,
            config.block_size_bytes,
        )?)
        .ok_or(PrivateResultOramError::InvalidBucketField("ciphertext"))?;

    let mut working_state = state.clone();
    let mut accesses = Vec::with_capacity(payload_fetch_tokens.len());
    let mut fetched_point_tokens = BTreeSet::new();
    let mut writeback_by_bucket: BTreeMap<u64, PrivateResultOramPlaintextBucket> = BTreeMap::new();
    for (batch_index, token_chunk) in payload_fetch_tokens
        .chunks(read_plan.path_batch_size)
        .enumerate()
    {
        let batch_plan = read_plan
            .batches
            .get(batch_index)
            .ok_or(PrivateResultOramError::InvalidFetchPlanField("batches"))?;
        if batch_plan.token_count != token_chunk.len() {
            return Err(PrivateResultOramError::InvalidFetchPlanField("token_count"));
        }
        let path_len = usize::try_from(config.tree_height)
            .ok()
            .and_then(|height| height.checked_add(1))
            .ok_or(PrivateResultOramError::InvalidFetchPlanField("bucket_ids"))?;
        let mut expected_bucket_ids = Vec::with_capacity(
            batch_plan
                .token_count
                .checked_mul(path_len)
                .ok_or(PrivateResultOramError::InvalidFetchPlanField("bucket_ids"))?,
        );
        let mut seen_batch_leaves = BTreeSet::new();
        let mut batch_leaves = Vec::with_capacity(token_chunk.len());
        for payload_fetch_token in token_chunk {
            let old_leaf = working_state
                .position(payload_fetch_token)
                .ok_or(PrivateResultOramError::MissingPosition)?;
            if seen_batch_leaves.insert(old_leaf) {
                batch_leaves.push(old_leaf);
            }
        }
        for padding_leaf in &batch_plan.padding_leaves {
            validate_private_result_oram_leaf(*padding_leaf, config.tree_height)?;
            if !seen_batch_leaves.insert(*padding_leaf) {
                return Err(PrivateResultOramError::InvalidFetchPlanField(
                    "padding_leaves",
                ));
            }
            batch_leaves.push(*padding_leaf);
        }
        if batch_leaves.len() != token_chunk.len() {
            return Err(PrivateResultOramError::InvalidFetchPlanField("bucket_ids"));
        }
        // The plan lists the batch in canonical leaf order (see the planner).
        let mut ordered_leaves = batch_leaves.clone();
        ordered_leaves.sort_unstable();
        for leaf in &ordered_leaves {
            expected_bucket_ids.extend(private_result_oram_bucket_ids_for_leaf(
                *leaf,
                config.tree_height,
            )?);
        }
        if batch_plan.bucket_ids.is_empty()
            || batch_plan.bucket_ids != expected_bucket_ids
            || batch_plan
                .bucket_ids
                .iter()
                .any(|bucket_id| *bucket_id >= expected_bucket_count)
        {
            return Err(PrivateResultOramError::InvalidFetchPlanField("bucket_ids"));
        }
        let encrypted_batch = encrypted_batches.get(batch_index).ok_or(
            PrivateResultOramError::InvalidFetchPlanField("encrypted_batches"),
        )?;
        if encrypted_batch.index_epoch != expected_epoch
            || encrypted_batch.root_hash != expected_root_hash
            || encrypted_batch.bucket_count != expected_bucket_count
        {
            return Err(PrivateResultOramError::MerkleProofMismatch);
        }
        let actual_bucket_ids = encrypted_batch
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_id)
            .collect::<Vec<_>>();
        if actual_bucket_ids != batch_plan.bucket_ids {
            return Err(PrivateResultOramError::InvalidFetchPlanField("bucket_ids"));
        }

        if encrypted_batch
            .buckets
            .iter()
            .any(|bucket| bucket.ciphertext.len() != expected_ciphertext_encoded_len)
        {
            return Err(PrivateResultOramError::InvalidBucketField("ciphertext"));
        }

        let mut plaintext_by_bucket = open_private_result_oram_verified_bucket_batch(
            keys,
            base_context,
            config,
            expected_epoch,
            expected_root_hash,
            expected_bucket_count,
            &encrypted_batch.proof_value,
            &encrypted_batch.buckets,
        )?
        .into_iter()
        .map(|bucket| (bucket.bucket_id, bucket))
        .collect::<BTreeMap<_, _>>();

        for (bucket_id, bucket) in &writeback_by_bucket {
            if plaintext_by_bucket.contains_key(bucket_id) {
                plaintext_by_bucket.insert(*bucket_id, bucket.clone());
            }
        }

        for payload_fetch_token in token_chunk {
            let old_leaf = working_state
                .position(payload_fetch_token)
                .ok_or(PrivateResultOramError::MissingPosition)?;
            let path_bucket_ids =
                private_result_oram_bucket_ids_for_leaf(old_leaf, config.tree_height)?;
            let path_buckets = path_bucket_ids
                .iter()
                .map(|bucket_id| {
                    plaintext_by_bucket
                        .get(bucket_id)
                        .cloned()
                        .ok_or(PrivateResultOramError::PathBucketMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let access = access_private_result_oram_path(
                &mut working_state,
                config,
                *payload_fetch_token,
                &path_buckets,
                next_remap_leaf()?,
            )?;
            if !fetched_point_tokens.insert(access.block.point_token) {
                return Err(PrivateResultOramError::InvalidFetchPlanField("point_token"));
            }
            for bucket in &access.writeback_buckets {
                plaintext_by_bucket.insert(bucket.bucket_id, bucket.clone());
                writeback_by_bucket.insert(bucket.bucket_id, bucket.clone());
            }
            accesses.push(PrivateResultOramTokenFetchAccess {
                payload_fetch_token: *payload_fetch_token,
                old_leaf: access.old_leaf,
                new_leaf: access.new_leaf,
                block: access.block,
            });
        }

        // Every read path is written back, the dummy paths that pad a leaf collision included:
        // a write-back that covered only the real paths would tell the server which of the
        // read paths were padding, and therefore that two fetched payloads shared a leaf.
        // Evicting along a dummy path is an ordinary Path ORAM eviction and only moves stash
        // blocks whose own position lies on that path.
        for padding_leaf in &batch_plan.padding_leaves {
            let path_bucket_ids =
                private_result_oram_bucket_ids_for_leaf(*padding_leaf, config.tree_height)?;
            let path_buckets = path_bucket_ids
                .iter()
                .map(|bucket_id| {
                    plaintext_by_bucket
                        .get(bucket_id)
                        .cloned()
                        .ok_or(PrivateResultOramError::PathBucketMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let eviction = evict_private_result_oram_path(
                &mut working_state,
                config,
                *padding_leaf,
                &path_buckets,
            )?;
            for bucket in &eviction.writeback_buckets {
                plaintext_by_bucket.insert(bucket.bucket_id, bucket.clone());
                writeback_by_bucket.insert(bucket.bucket_id, bucket.clone());
            }
        }
    }

    let updated_buckets = writeback_by_bucket
        .into_values()
        .map(|bucket| {
            seal_private_result_oram_plaintext_bucket(
                keys,
                base_context,
                writeback_epoch,
                &bucket,
                config,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    *state = working_state;

    Ok(PrivateResultOramTokenFetchResult {
        accesses,
        updated_buckets,
    })
}

pub(crate) fn validate_private_result_upload_bucket(
    base_context: PrivateResultOramBucketAeadBaseContext<'_>,
    bucket: &PrivateResultOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    expected_ciphertext_bytes: usize,
) -> Result<(), PrivateResultOramError> {
    validate_private_result_oram_bucket_shape(
        bucket,
        PrivateResultOramBucketValidationContext {
            expected_index_epoch: expected_epoch,
            bucket_count,
            max_ciphertext_bytes: expected_ciphertext_bytes,
        },
    )?;
    let raw_ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidBucketCiphertextEncoding)?;
    if raw_ciphertext.len() != expected_ciphertext_bytes
        || raw_ciphertext.len()
            < 1 + PRIVATE_RESULT_ORAM_BUCKET_AEAD_NONCE_LEN
                + PRIVATE_RESULT_ORAM_BUCKET_AEAD_TAG_LEN
    {
        return Err(PrivateResultOramError::InvalidBucketCiphertextEncoding);
    }
    if raw_ciphertext[0] != PRIVATE_RESULT_ORAM_BUCKET_AEAD_VERSION {
        return Err(PrivateResultOramError::UnsupportedBucketCiphertextVersion(
            raw_ciphertext[0],
        ));
    }
    let expected_commitment = private_result_oram_bucket_commitment(
        PrivateResultOramBucketCommitmentContext {
            collection_id: base_context.collection_id,
            key_id: base_context.key_id,
            rk_id: base_context.rk_id,
            rk_epoch: base_context.rk_epoch,
            bucket_id: bucket.bucket_id,
            index_epoch: bucket.index_epoch,
        },
        &bucket.ciphertext_sha256,
    )?;
    if bucket.bucket_commitment != expected_commitment {
        return Err(PrivateResultOramError::InvalidBucketCommitment);
    }
    Ok(())
}

pub fn validate_private_result_oram_bucket_shape(
    bucket: &PrivateResultOramBucket,
    context: PrivateResultOramBucketValidationContext,
) -> Result<(), PrivateResultOramError> {
    if bucket.version != PRIVATE_RESULT_ORAM_BUCKET_VERSION {
        return Err(PrivateResultOramError::UnsupportedBucketVersion(
            bucket.version,
        ));
    }
    if bucket.bucket_id >= context.bucket_count {
        return Err(PrivateResultOramError::BucketOutOfRange {
            bucket_id: bucket.bucket_id,
            bucket_count: context.bucket_count,
        });
    }
    if bucket.index_epoch != context.expected_index_epoch {
        return Err(PrivateResultOramError::InvalidBucketField("index_epoch"));
    }
    let max_ciphertext_b64_len = max_base64url_nopad_encoded_len(context.max_ciphertext_bytes)
        .ok_or(PrivateResultOramError::InvalidBucketField(
            "max_ciphertext_bytes",
        ))?;
    if bucket.ciphertext.len() > max_ciphertext_b64_len {
        return Err(PrivateResultOramError::BucketOversized);
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext"))?;
    if ciphertext.len() > context.max_ciphertext_bytes {
        return Err(PrivateResultOramError::BucketOversized);
    }
    let ciphertext_hash = decode_base64url_32(&bucket.ciphertext_sha256, "ciphertext_sha256")
        .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext_sha256"))?;
    let computed_hash: [u8; 32] = Sha256::digest(&ciphertext).into();
    if computed_hash != ciphertext_hash {
        return Err(PrivateResultOramError::InvalidBucketHash);
    }
    decode_base64url_32(&bucket.bucket_commitment, "bucket_commitment")
        .map_err(|_| PrivateResultOramError::InvalidBucketField("bucket_commitment"))?;
    Ok(())
}

fn max_base64url_nopad_encoded_len(byte_len: usize) -> Option<usize> {
    let full_chunks = byte_len / 3;
    let tail_len = match byte_len % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => return None,
    };
    full_chunks
        .checked_mul(4)
        .and_then(|len| len.checked_add(tail_len))
}

pub fn validate_private_result_oram_manifest_signature_shape(
    signature: &PrivateResultOramSignature,
) -> Result<(), PrivateResultOramError> {
    if signature.alg != PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM {
        return Err(PrivateResultOramError::UnsupportedSignatureAlgorithm(
            signature.alg.clone(),
        ));
    }
    validate_resource_id(&signature.key_id)?;
    decode_base64url_64(&signature.sig)?;
    Ok(())
}

pub fn validate_private_result_oram_manifest_signature(
    manifest: &PrivateResultOramManifest,
    signature: Option<&PrivateResultOramSignature>,
    verification: PrivateResultOramSignatureVerification<'_>,
) -> Result<(), PrivateResultOramError> {
    let signature = signature.ok_or(PrivateResultOramError::MissingManifestSignature)?;
    validate_private_result_oram_manifest_shape(manifest)?;
    validate_signature_header(
        signature,
        manifest.owner_signing_key_id.as_str(),
        verification,
    )?;
    let signature_bytes = decode_base64url_64(&signature.sig)?;
    let message = try_private_result_oram_manifest_signature_message(manifest)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateResultOramError::InvalidManifestSignature)
}

pub fn validate_private_result_oram_commit_signature(
    input: PrivateResultOramCommitSignatureInput<'_>,
    signature: &str,
    verification: PrivateResultOramSignatureVerification<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_signature_fields(input.signature_alg, input.signature_key_id, verification)?;
    validate_signature_input_context(input.collection_id, input.key_id, input.rk_id)?;
    validate_private_result_oram_commit_signature_shape(input)?;
    let signature_bytes = decode_base64url_64(signature)?;
    let message = try_private_result_oram_commit_signature_message(input)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateResultOramError::InvalidCommitSignature)
}

pub fn validate_private_result_oram_read_buckets_signature(
    input: PrivateResultOramReadBucketsSignatureInput<'_>,
    signature: &str,
    verification: PrivateResultOramSignatureVerification<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_signature_fields(input.signature_alg, input.signature_key_id, verification)?;
    validate_signature_input_context(input.collection_id, input.key_id, input.rk_id)?;
    decode_base64url_32(input.root_hash, "root_hash")?;
    validate_private_result_oram_read_bucket_sequence_shape(input.bucket_count, input.bucket_ids)?;
    let signature_bytes = decode_base64url_64(signature)?;
    let message = try_private_result_oram_read_buckets_signature_message(input)?;
    UnparsedPublicKey::new(&ED25519, verification.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PrivateResultOramError::InvalidReadBucketsSignature)
}

pub fn sign_private_result_oram_manifest(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateResultOramManifest,
) -> Result<PrivateResultOramSignature, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    validate_resource_id(&manifest.owner_signing_key_id)?;
    let message = try_private_result_oram_manifest_signature_message(manifest)?;
    let signature = key_pair.sign(&message);
    Ok(PrivateResultOramSignature {
        alg: PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM.to_string(),
        key_id: manifest.owner_signing_key_id.clone(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn sign_private_result_oram_commit(
    key_pair: &Ed25519KeyPair,
    context: PrivateResultOramCommitSignatureContext<'_>,
    plan: &PrivateResultOramCommitPlan,
) -> Result<PrivateResultOramSignature, PrivateResultOramError> {
    validate_commit_signature_context(context)?;
    if plan.updated_buckets.is_empty() {
        return Err(PrivateResultOramError::EmptyCommit);
    }
    if u32::try_from(plan.updated_buckets.len()).is_err() {
        return Err(PrivateResultOramError::InvalidCommitSignature);
    }
    if Some(plan.new_epoch) != plan.old_epoch.checked_add(1) {
        return Err(PrivateResultOramError::InvalidManifestField("new_epoch"));
    }
    decode_base64url_32(&plan.old_root_hash, "old_root_hash")?;
    decode_base64url_32(&plan.new_root_hash, "new_root_hash")?;
    let mut seen_bucket_ids = BTreeSet::new();
    for bucket in &plan.updated_buckets {
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateResultOramError::DuplicateUpdatedBucket {
                bucket_id: bucket.bucket_id,
            });
        }
        decode_base64url_32(&bucket.ciphertext_sha256, "ciphertext_sha256")
            .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext_sha256"))?;
    }
    let bucket_refs = plan.signature_bucket_refs();
    let input = PrivateResultOramCommitSignatureInput {
        collection_id: context.collection_id,
        key_id: context.key_id,
        rk_id: context.rk_id,
        rk_epoch: context.rk_epoch,
        old_epoch: plan.old_epoch,
        new_epoch: plan.new_epoch,
        old_root_hash: &plan.old_root_hash,
        new_root_hash: &plan.new_root_hash,
        updated_buckets: &bucket_refs,
        signature_alg: PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM,
        signature_key_id: context.signing_key_id,
    };
    let message = try_private_result_oram_commit_signature_message(input)?;
    let signature = key_pair.sign(&message);
    Ok(PrivateResultOramSignature {
        alg: PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM.to_string(),
        key_id: context.signing_key_id.to_string(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn sign_private_result_oram_read_buckets(
    key_pair: &Ed25519KeyPair,
    context: PrivateResultOramReadBucketsSignatureContext<'_>,
    index_epoch: u64,
    root_hash: &str,
    bucket_count: u64,
    bucket_ids: &[u64],
) -> Result<PrivateResultOramSignature, PrivateResultOramError> {
    validate_read_buckets_signature_context(context)?;
    decode_base64url_32(root_hash, "root_hash")?;
    validate_private_result_oram_read_bucket_sequence_shape(bucket_count, bucket_ids)?;
    let input = PrivateResultOramReadBucketsSignatureInput {
        collection_id: context.collection_id,
        key_id: context.key_id,
        rk_id: context.rk_id,
        rk_epoch: context.rk_epoch,
        index_epoch,
        root_hash,
        bucket_count,
        bucket_ids,
        signature_alg: PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM,
        signature_key_id: context.signing_key_id,
    };
    let message = try_private_result_oram_read_buckets_signature_message(input)?;
    let signature = key_pair.sign(&message);
    Ok(PrivateResultOramSignature {
        alg: PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM.to_string(),
        key_id: context.signing_key_id.to_string(),
        sig: BASE64URL_NOPAD.encode(signature.as_ref()),
    })
}

pub fn sign_private_result_oram_read_buckets_for_manifest(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateResultOramManifest,
    bucket_ids: &[u64],
) -> Result<PrivateResultOramSignature, PrivateResultOramError> {
    sign_private_result_oram_read_buckets_for_manifest_context(
        key_pair,
        manifest,
        manifest.index_epoch,
        &manifest.root_hash,
        bucket_ids,
    )
}

pub fn sign_private_result_oram_read_buckets_for_manifest_context(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateResultOramManifest,
    index_epoch: u64,
    root_hash: &str,
    bucket_ids: &[u64],
) -> Result<PrivateResultOramSignature, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    let path_len = usize::try_from(manifest.oram.tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or(PrivateResultOramError::InvalidReadBucketsSignature)?;
    let expected_bucket_ids = u64::from(manifest.oram.tree_height)
        .checked_add(1)
        .and_then(|path_len| path_len.checked_mul(u64::from(manifest.oram.path_batch_size)))
        .ok_or(PrivateResultOramError::InvalidReadBucketsSignature)?;
    let actual_bucket_ids = u64::try_from(bucket_ids.len())
        .map_err(|_| PrivateResultOramError::InvalidReadBucketsSignature)?;
    if actual_bucket_ids != expected_bucket_ids {
        return Err(PrivateResultOramError::InvalidReadBucketsSignature);
    }
    for path in bucket_ids.chunks(path_len) {
        validate_private_result_oram_read_bucket_path_shape(path)?;
    }
    sign_private_result_oram_read_buckets(
        key_pair,
        PrivateResultOramReadBucketsSignatureContext {
            collection_id: &manifest.collection_id,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            signing_key_id: &manifest.owner_signing_key_id,
        },
        index_epoch,
        root_hash,
        manifest.bucket_count,
        bucket_ids,
    )
}

fn validate_private_result_oram_read_bucket_sequence_shape(
    bucket_count: u64,
    bucket_ids: &[u64],
) -> Result<(), PrivateResultOramError> {
    let tree_height = path_oram_tree_height_from_bucket_count(bucket_count)
        .ok_or(PrivateResultOramError::InvalidReadBucketsSignature)?;
    let path_len = usize::try_from(tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or(PrivateResultOramError::InvalidReadBucketsSignature)?;
    if bucket_ids.is_empty()
        || u32::try_from(bucket_ids.len()).is_err()
        || bucket_ids.len() % path_len != 0
        || bucket_ids
            .iter()
            .any(|bucket_id| *bucket_id >= bucket_count)
    {
        return Err(PrivateResultOramError::InvalidReadBucketsSignature);
    }
    let mut seen_paths = BTreeSet::new();
    for path in bucket_ids.chunks(path_len) {
        validate_private_result_oram_read_bucket_path_shape(path)?;
        if !seen_paths.insert(path) {
            return Err(PrivateResultOramError::InvalidReadBucketsSignature);
        }
    }
    Ok(())
}

fn validate_private_result_oram_read_bucket_path_shape(
    path: &[u64],
) -> Result<(), PrivateResultOramError> {
    if path.first().copied() != Some(0) {
        return Err(PrivateResultOramError::InvalidReadBucketsSignature);
    }
    for window in path.windows(2) {
        let parent = window[0];
        let child = window[1];
        let Some(left_child) = parent.checked_mul(2).and_then(|value| value.checked_add(1)) else {
            return Err(PrivateResultOramError::InvalidReadBucketsSignature);
        };
        let Some(right_child) = parent.checked_mul(2).and_then(|value| value.checked_add(2)) else {
            return Err(PrivateResultOramError::InvalidReadBucketsSignature);
        };
        if child != left_child && child != right_child {
            return Err(PrivateResultOramError::InvalidReadBucketsSignature);
        }
    }
    Ok(())
}

pub fn package_private_result_oram_upload_bundle(
    key_pair: &Ed25519KeyPair,
    manifest: PrivateResultOramManifest,
    buckets: Vec<PrivateResultOramBucket>,
) -> Result<PrivateResultOramUploadBundle, PrivateResultOramError> {
    let manifest_signature = sign_private_result_oram_manifest(key_pair, &manifest)?;
    let bundle = PrivateResultOramUploadBundle {
        manifest,
        manifest_signature,
        buckets,
    };
    validate_private_result_oram_upload_bundle(&bundle)?;
    Ok(bundle)
}

pub fn validate_private_result_oram_upload_bundle(
    bundle: &PrivateResultOramUploadBundle,
) -> Result<Vec<String>, PrivateResultOramError> {
    let manifest = &bundle.manifest;
    validate_private_result_oram_manifest_shape(manifest)?;
    validate_private_result_oram_manifest_signature_shape(&bundle.manifest_signature)?;
    if bundle.manifest_signature.key_id != manifest.owner_signing_key_id {
        return Err(PrivateResultOramError::SignatureKeyIdMismatch);
    }
    let bucket_count = usize::try_from(manifest.bucket_count)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    if bundle.buckets.len() != bucket_count {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }

    let max_ciphertext_bytes = private_result_oram_upload_max_ciphertext_bytes(manifest)?;
    let expected_ciphertext_bytes = private_result_oram_bucket_ciphertext_bytes(&manifest.oram)?;
    let validation_context =
        PrivateResultOramBucketValidationContext::from_manifest(manifest, max_ciphertext_bytes);
    let mut commitments = Vec::with_capacity(bundle.buckets.len());
    for (expected_bucket_id, bucket) in bundle.buckets.iter().enumerate() {
        let expected_bucket_id = u64::try_from(expected_bucket_id)
            .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_count"))?;
        if bucket.bucket_id != expected_bucket_id {
            return Err(PrivateResultOramError::InvalidBucketField("bucket_id"));
        }
        validate_private_result_oram_bucket_shape(bucket, validation_context)?;
        validate_private_result_oram_bucket_ciphertext_fixed_size(
            bucket,
            expected_ciphertext_bytes,
        )?;
        let expected_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch: manifest.index_epoch,
            },
            &bucket.ciphertext_sha256,
        )?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(PrivateResultOramError::InvalidBucketCommitment);
        }
        commitments.push(bucket.bucket_commitment.clone());
    }
    if private_result_oram_merkle_root_for_commitments(&commitments)? != manifest.root_hash {
        return Err(PrivateResultOramError::MerkleRootMismatch);
    }
    Ok(commitments)
}

fn validate_private_result_oram_bucket_ciphertext_fixed_size(
    bucket: &PrivateResultOramBucket,
    expected_ciphertext_bytes: usize,
) -> Result<(), PrivateResultOramError> {
    let Some(expected_encoded_len) = max_base64url_nopad_encoded_len(expected_ciphertext_bytes)
    else {
        return Err(PrivateResultOramError::InvalidBucketField("ciphertext"));
    };
    if bucket.ciphertext.len() != expected_encoded_len {
        return Err(PrivateResultOramError::InvalidBucketField("ciphertext"));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext"))?;
    if ciphertext.len() != expected_ciphertext_bytes {
        return Err(PrivateResultOramError::InvalidBucketField("ciphertext"));
    }
    Ok(())
}

pub fn validate_private_result_oram_upload_bundle_with_signature(
    bundle: &PrivateResultOramUploadBundle,
    validation_context: PrivateResultOramManifestValidationContext<'_>,
) -> Result<Vec<String>, PrivateResultOramError> {
    let commitments = validate_private_result_oram_upload_bundle(bundle)?;
    validate_private_result_oram_manifest(
        &bundle.manifest,
        Some(&bundle.manifest_signature),
        validation_context,
    )?;
    Ok(commitments)
}

fn private_result_oram_upload_max_ciphertext_bytes(
    manifest: &PrivateResultOramManifest,
) -> Result<usize, PrivateResultOramError> {
    let block_size = usize::try_from(manifest.oram.block_size_bytes)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("block_size_bytes"))?;
    let bucket_size = usize::try_from(manifest.oram.bucket_size)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_size"))?;
    block_size
        .checked_mul(bucket_size)
        .and_then(|size| size.checked_add(4096))
        .ok_or(PrivateResultOramError::InvalidManifestField("oram"))
}

pub fn refresh_private_result_oram_manifest_for_commit(
    manifest: &PrivateResultOramManifest,
    plan: &PrivateResultOramCommitPlan,
) -> Result<PrivateResultOramManifest, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    if manifest.index_epoch != plan.old_epoch || manifest.root_hash != plan.old_root_hash {
        return Err(PrivateResultOramError::ManifestCommitMismatch);
    }
    if Some(plan.new_epoch) != plan.old_epoch.checked_add(1) {
        return Err(PrivateResultOramError::InvalidManifestField("new_epoch"));
    }
    decode_base64url_32(&plan.new_root_hash, "root_hash")?;

    let mut refreshed = manifest.clone();
    refreshed.index_epoch = plan.new_epoch;
    refreshed.root_hash = plan.new_root_hash.clone();
    Ok(refreshed)
}

pub fn sign_private_result_oram_manifest_refresh(
    key_pair: &Ed25519KeyPair,
    manifest: &PrivateResultOramManifest,
    plan: &PrivateResultOramCommitPlan,
) -> Result<(PrivateResultOramManifest, PrivateResultOramSignature), PrivateResultOramError> {
    let refreshed = refresh_private_result_oram_manifest_for_commit(manifest, plan)?;
    let signature = sign_private_result_oram_manifest(key_pair, &refreshed)?;
    Ok((refreshed, signature))
}

pub fn try_private_result_oram_manifest_signature_message(
    manifest: &PrivateResultOramManifest,
) -> Result<Vec<u8>, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_RESULT_ORAM_MANIFEST_SIGNATURE_DOMAIN.as_bytes(),
        || PrivateResultOramError::InvalidManifestField("signature_message"),
    )?;
    push_u16(&mut message, manifest.version);
    try_push_str(&mut message, &manifest.provider, || {
        PrivateResultOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.binding, || {
        PrivateResultOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.collection_id, || {
        PrivateResultOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.key_id, || {
        PrivateResultOramError::InvalidManifestField("signature_message")
    })?;
    try_push_str(&mut message, &manifest.rk_id, || {
        PrivateResultOramError::InvalidManifestField("signature_message")
    })?;
    push_u64(&mut message, manifest.rk_epoch);
    try_push_str(&mut message, manifest.oram.kind.as_str(), || {
        PrivateResultOramError::InvalidManifestField("signature_message")
    })?;
    push_u32(&mut message, manifest.oram.bucket_size);
    push_u32(&mut message, manifest.oram.block_size_bytes);
    push_u32(&mut message, manifest.oram.tree_height);
    push_u32(&mut message, manifest.oram.path_batch_size);
    push_u64(&mut message, manifest.index_epoch);
    try_push_str(&mut message, &manifest.root_hash, || {
        PrivateResultOramError::InvalidManifestField("signature_message")
    })?;
    push_u64(&mut message, manifest.bucket_count);
    push_u64(&mut message, manifest.logical_result_count);
    push_u64(&mut message, manifest.dummy_result_count);
    try_push_str(&mut message, &manifest.owner_signing_key_id, || {
        PrivateResultOramError::InvalidManifestField("signature_message")
    })?;
    Ok(message)
}

pub fn try_private_result_oram_commit_signature_message(
    input: PrivateResultOramCommitSignatureInput<'_>,
) -> Result<Vec<u8>, PrivateResultOramError> {
    validate_signature_input_context(input.collection_id, input.key_id, input.rk_id)?;
    validate_private_result_oram_commit_signature_shape(input)?;
    validate_signature_message_header_shape(input.signature_alg, input.signature_key_id)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_RESULT_ORAM_COMMIT_SIGNATURE_DOMAIN.as_bytes(),
        || PrivateResultOramError::InvalidCommitSignature,
    )?;
    try_push_str(&mut message, input.collection_id, || {
        PrivateResultOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.key_id, || {
        PrivateResultOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.rk_id, || {
        PrivateResultOramError::InvalidCommitSignature
    })?;
    push_u64(&mut message, input.rk_epoch);
    push_u64(&mut message, input.old_epoch);
    push_u64(&mut message, input.new_epoch);
    try_push_str(&mut message, input.old_root_hash, || {
        PrivateResultOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.new_root_hash, || {
        PrivateResultOramError::InvalidCommitSignature
    })?;
    let updated_bucket_count = u32::try_from(input.updated_buckets.len())
        .map_err(|_| PrivateResultOramError::InvalidCommitSignature)?;
    push_u32(&mut message, updated_bucket_count);
    for bucket in input.updated_buckets {
        push_u64(&mut message, bucket.bucket_id);
        try_push_str(&mut message, bucket.ciphertext_sha256, || {
            PrivateResultOramError::InvalidCommitSignature
        })?;
    }
    try_push_str(&mut message, input.signature_alg, || {
        PrivateResultOramError::InvalidCommitSignature
    })?;
    try_push_str(&mut message, input.signature_key_id, || {
        PrivateResultOramError::InvalidCommitSignature
    })?;
    Ok(message)
}

pub fn private_result_oram_writeback_digest(
    input: PrivateResultOramCommitSignatureInput<'_>,
) -> Result<String, PrivateResultOramError> {
    let message = try_private_result_oram_commit_signature_message(input)?;
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(message)))
}

fn validate_private_result_oram_commit_signature_shape(
    input: PrivateResultOramCommitSignatureInput<'_>,
) -> Result<(), PrivateResultOramError> {
    if input.updated_buckets.is_empty() {
        return Err(PrivateResultOramError::EmptyCommit);
    }
    if u32::try_from(input.updated_buckets.len()).is_err() {
        return Err(PrivateResultOramError::InvalidCommitSignature);
    }
    if Some(input.new_epoch) != input.old_epoch.checked_add(1) {
        return Err(PrivateResultOramError::InvalidManifestField("new_epoch"));
    }
    decode_base64url_32(input.old_root_hash, "old_root_hash")?;
    decode_base64url_32(input.new_root_hash, "new_root_hash")?;
    let mut seen_bucket_ids = BTreeSet::new();
    for bucket in input.updated_buckets {
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateResultOramError::InvalidCommitSignature);
        }
        decode_base64url_32(bucket.ciphertext_sha256, "ciphertext_sha256")
            .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext_sha256"))?;
    }
    Ok(())
}

pub fn try_private_result_oram_read_buckets_signature_message(
    input: PrivateResultOramReadBucketsSignatureInput<'_>,
) -> Result<Vec<u8>, PrivateResultOramError> {
    validate_signature_input_context(input.collection_id, input.key_id, input.rk_id)?;
    decode_base64url_32(input.root_hash, "root_hash")?;
    validate_private_result_oram_read_bucket_sequence_shape(input.bucket_count, input.bucket_ids)?;
    validate_signature_message_header_shape(input.signature_alg, input.signature_key_id)?;
    let mut message = Vec::new();
    try_push_domain(
        &mut message,
        PRIVATE_RESULT_ORAM_READ_BUCKETS_SIGNATURE_DOMAIN.as_bytes(),
        || PrivateResultOramError::InvalidReadBucketsSignature,
    )?;
    try_push_str(&mut message, input.collection_id, || {
        PrivateResultOramError::InvalidReadBucketsSignature
    })?;
    try_push_str(&mut message, input.key_id, || {
        PrivateResultOramError::InvalidReadBucketsSignature
    })?;
    try_push_str(&mut message, input.rk_id, || {
        PrivateResultOramError::InvalidReadBucketsSignature
    })?;
    push_u64(&mut message, input.rk_epoch);
    push_u64(&mut message, input.index_epoch);
    try_push_str(&mut message, input.root_hash, || {
        PrivateResultOramError::InvalidReadBucketsSignature
    })?;
    push_u64(&mut message, input.bucket_count);
    let bucket_id_count = u32::try_from(input.bucket_ids.len())
        .map_err(|_| PrivateResultOramError::InvalidReadBucketsSignature)?;
    push_u32(&mut message, bucket_id_count);
    for bucket_id in input.bucket_ids {
        push_u64(&mut message, *bucket_id);
    }
    try_push_str(&mut message, input.signature_alg, || {
        PrivateResultOramError::InvalidReadBucketsSignature
    })?;
    try_push_str(&mut message, input.signature_key_id, || {
        PrivateResultOramError::InvalidReadBucketsSignature
    })?;
    Ok(message)
}

pub fn private_result_oram_bucket_commitment(
    context: PrivateResultOramBucketCommitmentContext<'_>,
    ciphertext_sha256: &str,
) -> Result<String, PrivateResultOramError> {
    validate_id(context.collection_id, "collection_id")?;
    validate_resource_id(context.key_id)?;
    validate_resource_id(context.rk_id)?;
    let ciphertext_sha256 = decode_base64url_32(ciphertext_sha256, "ciphertext_sha256")
        .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext_sha256"))?;

    let mut message = Vec::new();
    push_bucket_context_domain(
        &mut message,
        PRIVATE_RESULT_ORAM_BUCKET_COMMITMENT_DOMAIN.as_bytes(),
    )?;
    push_bucket_context_str(&mut message, context.collection_id)?;
    push_bucket_context_str(&mut message, context.key_id)?;
    push_bucket_context_str(&mut message, context.rk_id)?;
    push_u64(&mut message, context.rk_epoch);
    push_u64(&mut message, context.bucket_id);
    push_u64(&mut message, context.index_epoch);
    message.extend_from_slice(&ciphertext_sha256);
    Ok(BASE64URL_NOPAD.encode(Sha256::digest(&message).as_ref()))
}

fn private_result_oram_bucket_aead(
    context: PrivateResultOramBucketAeadContext<'_>,
) -> Result<Vec<u8>, PrivateResultOramError> {
    validate_private_result_bucket_context(context)?;
    let mut aad = Vec::new();
    push_bucket_context_domain(
        &mut aad,
        PRIVATE_RESULT_ORAM_BUCKET_AEAD_CONTEXT_DOMAIN.as_bytes(),
    )?;
    push_bucket_context_str(&mut aad, context.collection_id)?;
    push_bucket_context_str(&mut aad, context.key_id)?;
    push_bucket_context_str(&mut aad, context.rk_id)?;
    push_u64(&mut aad, context.rk_epoch);
    push_u64(&mut aad, context.bucket_id);
    push_u64(&mut aad, context.index_epoch);
    Ok(aad)
}

fn private_result_oram_client_state_aead(
    context: PrivateResultOramClientStateAeadContext<'_>,
) -> Result<Vec<u8>, PrivateResultOramError> {
    validate_private_result_client_state_context(context)?;
    let root_hash = decode_base64url_32(context.root_hash, "root_hash")?;
    let mut aad = Vec::new();
    push_client_state_context_domain(
        &mut aad,
        PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_CONTEXT_DOMAIN.as_bytes(),
    )?;
    push_client_state_context_str(&mut aad, context.collection_id)?;
    push_client_state_context_str(&mut aad, context.key_id)?;
    push_client_state_context_str(&mut aad, context.rk_id)?;
    push_u64(&mut aad, context.rk_epoch);
    push_u64(&mut aad, context.index_epoch);
    aad.extend_from_slice(&root_hash);
    Ok(aad)
}

fn validate_private_result_bucket_context(
    context: PrivateResultOramBucketAeadContext<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_id(context.collection_id, "collection_id")
        .map_err(|_| PrivateResultOramError::InvalidBucketContext("collection_id"))?;
    validate_resource_key_id(context.key_id)
        .map_err(|_| PrivateResultOramError::InvalidBucketContext("key_id"))?;
    validate_resource_key_id(context.rk_id)
        .map_err(|_| PrivateResultOramError::InvalidBucketContext("rk_id"))?;
    Ok(())
}

fn validate_private_result_client_state_context(
    context: PrivateResultOramClientStateAeadContext<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_id(context.collection_id, "collection_id")
        .map_err(|_| PrivateResultOramError::InvalidClientStateContext("collection_id"))?;
    validate_resource_key_id(context.key_id)
        .map_err(|_| PrivateResultOramError::InvalidClientStateContext("key_id"))?;
    validate_resource_key_id(context.rk_id)
        .map_err(|_| PrivateResultOramError::InvalidClientStateContext("rk_id"))?;
    decode_base64url_32(context.root_hash, "root_hash")
        .map_err(|_| PrivateResultOramError::InvalidClientStateContext("root_hash"))?;
    Ok(())
}

pub fn private_result_oram_merkle_root_for_commitments(
    commitments: &[String],
) -> Result<String, PrivateResultOramError> {
    let levels = private_result_oram_merkle_levels(commitments)?;
    let root = levels
        .last()
        .and_then(|level| level.first())
        .ok_or(PrivateResultOramError::EmptyMerkleTree)?;
    Ok(BASE64URL_NOPAD.encode(root))
}

pub fn verify_private_result_oram_merkle_proof_json(
    proof_value: &str,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    buckets: &[PrivateResultOramBucket],
) -> Result<(), PrivateResultOramError> {
    if proof_value.len() > PRIVATE_RESULT_ORAM_MERKLE_PROOF_JSON_MAX_BYTES {
        return Err(PrivateResultOramError::InvalidMerkleProofJson);
    }
    let proof: PrivateResultOramMerkleProof = serde_json::from_str(proof_value)
        .map_err(|_| PrivateResultOramError::InvalidMerkleProofJson)?;
    verify_private_result_oram_merkle_proof(
        &proof,
        expected_epoch,
        expected_root_hash,
        expected_bucket_count,
        buckets,
    )
}

pub fn verify_private_result_oram_merkle_proof(
    proof: &PrivateResultOramMerkleProof,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
    buckets: &[PrivateResultOramBucket],
) -> Result<(), PrivateResultOramError> {
    if expected_bucket_count == 0
        || proof.kind != PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND
        || proof.index_epoch != expected_epoch
        || proof.bucket_count != expected_bucket_count
        || buckets.is_empty()
        || proof.leaves.len() != buckets.len()
    {
        return Err(PrivateResultOramError::InvalidMerkleProof);
    }

    let expected_root = decode_merkle_proof_hash(expected_root_hash)?;
    let proof_root = decode_merkle_proof_hash(&proof.root_hash)?;
    if proof_root != expected_root {
        return Err(PrivateResultOramError::MerkleProofMismatch);
    }

    let mut buckets_by_id = std::collections::BTreeMap::new();
    for bucket in buckets {
        if bucket.version != PRIVATE_RESULT_ORAM_BUCKET_VERSION
            || bucket.index_epoch > expected_epoch
            || bucket.bucket_id >= expected_bucket_count
        {
            return Err(PrivateResultOramError::InvalidMerkleProof);
        }
        let raw_ciphertext = BASE64URL_NOPAD
            .decode(bucket.ciphertext.as_bytes())
            .map_err(|_| PrivateResultOramError::InvalidBucketCiphertextEncoding)?;
        if base64url_sha256(&raw_ciphertext) != bucket.ciphertext_sha256 {
            return Err(PrivateResultOramError::InvalidBucketCiphertextHash);
        }
        decode_bucket_commitment(&bucket.bucket_commitment)?;
        if let Some(existing) = buckets_by_id.insert(bucket.bucket_id, bucket) {
            if existing != bucket {
                return Err(PrivateResultOramError::InvalidMerkleProof);
            }
        }
    }

    let mut leaves_by_id = std::collections::BTreeMap::new();
    for leaf in &proof.leaves {
        if leaf.bucket_id >= expected_bucket_count {
            return Err(PrivateResultOramError::InvalidMerkleProof);
        }
        if let Some(existing) = leaves_by_id.insert(leaf.bucket_id, leaf) {
            if existing != leaf {
                return Err(PrivateResultOramError::InvalidMerkleProof);
            }
            continue;
        }
        let Some(bucket) = buckets_by_id.get(&leaf.bucket_id) else {
            return Err(PrivateResultOramError::MerkleProofMismatch);
        };
        if bucket.bucket_commitment != leaf.leaf_hash {
            return Err(PrivateResultOramError::MerkleProofMismatch);
        }

        let mut node_hash = decode_merkle_proof_hash(&leaf.leaf_hash)?;
        let mut index = leaf.bucket_id;
        for (expected_level, sibling) in leaf.siblings.iter().enumerate() {
            let expected_level = u32::try_from(expected_level)
                .map_err(|_| PrivateResultOramError::InvalidMerkleProof)?;
            if sibling.level != expected_level {
                return Err(PrivateResultOramError::InvalidMerkleProof);
            }
            let sibling_hash = decode_merkle_proof_hash(&sibling.hash)?;
            let expected_position = if index % 2 == 0 {
                PrivateResultOramMerkleSiblingPosition::Right
            } else {
                PrivateResultOramMerkleSiblingPosition::Left
            };
            if sibling.position != expected_position {
                return Err(PrivateResultOramError::InvalidMerkleProof);
            }
            node_hash = match sibling.position {
                PrivateResultOramMerkleSiblingPosition::Left => {
                    private_result_oram_merkle_parent_hash(&sibling_hash, &node_hash)
                }
                PrivateResultOramMerkleSiblingPosition::Right => {
                    private_result_oram_merkle_parent_hash(&node_hash, &sibling_hash)
                }
            };
            index /= 2;
        }
        if node_hash != expected_root {
            return Err(PrivateResultOramError::MerkleProofMismatch);
        }
    }
    for bucket_id in buckets_by_id.keys() {
        if !leaves_by_id.contains_key(bucket_id) {
            return Err(PrivateResultOramError::MerkleProofMismatch);
        }
    }

    Ok(())
}

pub fn plan_private_result_oram_commit(
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateResultOramBucket],
) -> Result<PrivateResultOramCommitPlan, PrivateResultOramError> {
    if Some(new_epoch) != old_epoch.checked_add(1) {
        return Err(PrivateResultOramError::InvalidManifestField("new_epoch"));
    }
    if updated_buckets.is_empty() {
        return Err(PrivateResultOramError::EmptyCommit);
    }
    let computed_old_root =
        private_result_oram_merkle_root_for_commitments(current_leaf_commitments)?;
    if computed_old_root != old_root_hash {
        return Err(PrivateResultOramError::MerkleRootMismatch);
    }

    let bucket_count = u64::try_from(current_leaf_commitments.len())
        .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    let mut next_leaf_commitments = current_leaf_commitments.to_vec();
    let mut seen_bucket_ids = std::collections::BTreeSet::new();
    let mut commit_bucket_refs = Vec::with_capacity(updated_buckets.len());

    for bucket in updated_buckets {
        if bucket.version != PRIVATE_RESULT_ORAM_BUCKET_VERSION {
            return Err(PrivateResultOramError::UnsupportedBucketVersion(
                bucket.version,
            ));
        }
        if bucket.index_epoch != new_epoch {
            return Err(PrivateResultOramError::StaleBucketEpoch {
                bucket_id: bucket.bucket_id,
                expected_epoch: new_epoch,
                actual_epoch: bucket.index_epoch,
            });
        }
        if bucket.bucket_id >= bucket_count {
            return Err(PrivateResultOramError::BucketOutOfRange {
                bucket_id: bucket.bucket_id,
                bucket_count,
            });
        }
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(PrivateResultOramError::DuplicateUpdatedBucket {
                bucket_id: bucket.bucket_id,
            });
        }
        decode_base64url_32(&bucket.ciphertext_sha256, "ciphertext_sha256")
            .map_err(|_| PrivateResultOramError::InvalidBucketField("ciphertext_sha256"))?;
        let raw_ciphertext = BASE64URL_NOPAD
            .decode(bucket.ciphertext.as_bytes())
            .map_err(|_| PrivateResultOramError::InvalidBucketCiphertextEncoding)?;
        if base64url_sha256(&raw_ciphertext) != bucket.ciphertext_sha256 {
            return Err(PrivateResultOramError::InvalidBucketCiphertextHash);
        }
        decode_bucket_commitment(&bucket.bucket_commitment)?;

        let bucket_index = usize::try_from(bucket.bucket_id)
            .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_count"))?;
        next_leaf_commitments[bucket_index] = bucket.bucket_commitment.clone();
        commit_bucket_refs.push(PrivateResultOramClientCommitBucketRef {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
        });
    }

    let new_root_hash = private_result_oram_merkle_root_for_commitments(&next_leaf_commitments)?;
    Ok(PrivateResultOramCommitPlan {
        old_epoch,
        new_epoch,
        old_root_hash: old_root_hash.to_string(),
        new_root_hash,
        leaf_commitments: next_leaf_commitments,
        updated_buckets: commit_bucket_refs,
    })
}

pub fn plan_private_result_oram_commit_for_manifest(
    manifest: &PrivateResultOramManifest,
    new_epoch: u64,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateResultOramBucket],
) -> Result<PrivateResultOramCommitPlan, PrivateResultOramError> {
    plan_private_result_oram_commit_for_manifest_context(
        manifest,
        manifest.index_epoch,
        new_epoch,
        &manifest.root_hash,
        current_leaf_commitments,
        updated_buckets,
    )
}

/// Plans a commit for a session that read a single fixed batch (`path_batch_size` paths). A
/// token fetch that spanned several read batches must use
/// [`plan_private_result_oram_commit_for_manifest_context_with_read_paths`] with the number of
/// paths it read (`batches * path_batch_size`).
pub fn plan_private_result_oram_commit_for_manifest_context(
    manifest: &PrivateResultOramManifest,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateResultOramBucket],
) -> Result<PrivateResultOramCommitPlan, PrivateResultOramError> {
    let read_path_count = usize::try_from(manifest.oram.path_batch_size)
        .map_err(|_| PrivateResultOramError::InvalidFetchPlanField("path_batch_size"))?;
    plan_private_result_oram_commit_for_manifest_context_with_read_paths(
        manifest,
        old_epoch,
        new_epoch,
        old_root_hash,
        current_leaf_commitments,
        updated_buckets,
        read_path_count,
    )
}

/// Plans a commit for a session that read `read_path_count` paths; the writeback must fit
/// [`private_result_oram_session_writeback_bucket_budget`], which is what the server enforces.
pub fn plan_private_result_oram_commit_for_manifest_context_with_read_paths(
    manifest: &PrivateResultOramManifest,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: &str,
    current_leaf_commitments: &[String],
    updated_buckets: &[PrivateResultOramBucket],
    read_path_count: usize,
) -> Result<PrivateResultOramCommitPlan, PrivateResultOramError> {
    validate_private_result_oram_manifest_shape(manifest)?;
    let manifest_bucket_count = usize::try_from(manifest.bucket_count)
        .map_err(|_| PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    if current_leaf_commitments.len() != manifest_bucket_count {
        return Err(PrivateResultOramError::InvalidManifestField("bucket_count"));
    }
    if Some(new_epoch) != old_epoch.checked_add(1) {
        return Err(PrivateResultOramError::InvalidManifestField("new_epoch"));
    }
    if updated_buckets.is_empty() {
        return Err(PrivateResultOramError::EmptyCommit);
    }
    let max_updated_buckets =
        private_result_oram_session_writeback_bucket_budget(&manifest.oram, read_path_count)?;
    if updated_buckets.len() > max_updated_buckets {
        return Err(PrivateResultOramError::InvalidFetchPlanField(
            "updated_buckets",
        ));
    }
    if private_result_oram_merkle_root_for_commitments(current_leaf_commitments)? != old_root_hash {
        return Err(PrivateResultOramError::MerkleRootMismatch);
    }
    let max_ciphertext_bytes = private_result_oram_upload_max_ciphertext_bytes(manifest)?;
    let expected_ciphertext_bytes = private_result_oram_bucket_ciphertext_bytes(&manifest.oram)?;
    for bucket in updated_buckets {
        validate_private_result_oram_bucket_ciphertext_fixed_size(
            bucket,
            expected_ciphertext_bytes,
        )?;
        validate_private_result_oram_bucket_shape(
            bucket,
            PrivateResultOramBucketValidationContext {
                expected_index_epoch: new_epoch,
                bucket_count: manifest.bucket_count,
                max_ciphertext_bytes,
            },
        )?;
        let expected_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch: new_epoch,
            },
            &bucket.ciphertext_sha256,
        )?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(PrivateResultOramError::InvalidBucketCommitment);
        }
    }
    let plan = plan_private_result_oram_commit(
        old_epoch,
        new_epoch,
        old_root_hash,
        current_leaf_commitments,
        updated_buckets,
    )?;
    Ok(plan)
}

fn validate_id(value: &str, field: &'static str) -> Result<(), PrivateResultOramError> {
    if value.is_empty()
        || value.len() > 255
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(PrivateResultOramError::InvalidManifestField(field));
    }
    Ok(())
}

fn validate_resource_id(value: &str) -> Result<(), PrivateResultOramError> {
    validate_resource_key_id(value).map_err(|_| PrivateResultOramError::InvalidResourceKeyId)
}

fn validate_manifest_context(
    manifest: &PrivateResultOramManifest,
    context: PrivateResultOramManifestValidationContext<'_>,
) -> Result<(), PrivateResultOramError> {
    if manifest.collection_id != context.expected_collection_id {
        return Err(PrivateResultOramError::ManifestContextMismatch(
            "collection_id",
        ));
    }
    if manifest.key_id != context.expected_key_id {
        return Err(PrivateResultOramError::ManifestContextMismatch("key_id"));
    }
    if manifest.rk_id != context.expected_rk_id {
        return Err(PrivateResultOramError::ManifestContextMismatch("rk_id"));
    }
    if manifest.rk_epoch < context.min_rk_epoch || manifest.rk_epoch > context.max_rk_epoch {
        return Err(PrivateResultOramError::ManifestContextMismatch("rk_epoch"));
    }
    Ok(())
}

fn validate_commit_signature_context(
    context: PrivateResultOramCommitSignatureContext<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_id(context.collection_id, "collection_id")?;
    validate_resource_id(context.key_id)?;
    validate_resource_id(context.rk_id)?;
    validate_resource_id(context.signing_key_id)?;
    Ok(())
}

fn validate_read_buckets_signature_context(
    context: PrivateResultOramReadBucketsSignatureContext<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_id(context.collection_id, "collection_id")?;
    validate_resource_id(context.key_id)?;
    validate_resource_id(context.rk_id)?;
    validate_resource_id(context.signing_key_id)?;
    Ok(())
}

fn validate_signature_header(
    signature: &PrivateResultOramSignature,
    expected_owner_key_id: &str,
    verification: PrivateResultOramSignatureVerification<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_signature_fields(&signature.alg, &signature.key_id, verification)?;
    decode_base64url_64(&signature.sig)?;
    if signature.key_id != expected_owner_key_id {
        return Err(PrivateResultOramError::SignatureKeyIdMismatch);
    }
    Ok(())
}

fn validate_signature_fields(
    alg: &str,
    key_id: &str,
    verification: PrivateResultOramSignatureVerification<'_>,
) -> Result<(), PrivateResultOramError> {
    validate_signature_message_header_shape(alg, key_id)?;
    if key_id != verification.expected_key_id {
        return Err(PrivateResultOramError::SignatureKeyIdMismatch);
    }
    Ok(())
}

fn validate_signature_message_header_shape(
    alg: &str,
    key_id: &str,
) -> Result<(), PrivateResultOramError> {
    if alg != PRIVATE_RESULT_ORAM_SIGNATURE_ALGORITHM {
        return Err(PrivateResultOramError::UnsupportedSignatureAlgorithm(
            alg.to_string(),
        ));
    }
    validate_resource_id(key_id)
}

fn validate_signature_input_context(
    collection_id: &str,
    key_id: &str,
    rk_id: &str,
) -> Result<(), PrivateResultOramError> {
    validate_id(collection_id, "collection_id")?;
    validate_resource_id(key_id)?;
    validate_resource_id(rk_id)?;
    Ok(())
}

fn decode_base64url_32(
    value: &str,
    field: &'static str,
) -> Result<[u8; 32], PrivateResultOramError> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(PrivateResultOramError::InvalidManifestField(field));
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateResultOramError::InvalidManifestField(field))?;
    bytes
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidManifestField(field))
}

fn decode_base64url_64(value: &str) -> Result<[u8; 64], PrivateResultOramError> {
    if value.len() != BASE64URL_NOPAD_64_BYTE_LEN {
        return Err(PrivateResultOramError::MalformedSignature);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PrivateResultOramError::MalformedSignature)?;
    bytes
        .try_into()
        .map_err(|_| PrivateResultOramError::MalformedSignature)
}

fn decode_bucket_commitment(value: &str) -> Result<[u8; 32], PrivateResultOramError> {
    decode_base64url_32(value, "bucket_commitment")
        .map_err(|_| PrivateResultOramError::InvalidBucketField("bucket_commitment"))
}

fn decode_merkle_proof_hash(value: &str) -> Result<[u8; 32], PrivateResultOramError> {
    decode_base64url_32(value, "merkle_proof_hash")
        .map_err(|_| PrivateResultOramError::InvalidMerkleProof)
}

fn private_result_oram_merkle_levels(
    commitments: &[String],
) -> Result<Vec<Vec<[u8; 32]>>, PrivateResultOramError> {
    if commitments.is_empty() {
        return Err(PrivateResultOramError::EmptyMerkleTree);
    }
    let mut leaves = commitments
        .iter()
        .map(|commitment| decode_bucket_commitment(commitment))
        .collect::<Result<Vec<_>, _>>()?;
    let padded_len = leaves
        .len()
        .checked_next_power_of_two()
        .ok_or(PrivateResultOramError::InvalidManifestField("bucket_count"))?;
    leaves.resize(padded_len, [0; 32]);

    let mut levels = vec![leaves];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let Some(previous) = levels.last() else {
            return Err(PrivateResultOramError::InvalidMerkleProof);
        };
        let mut next = Vec::with_capacity(previous.len() / 2);
        for pair in previous.chunks_exact(2) {
            next.push(private_result_oram_merkle_parent_hash(&pair[0], &pair[1]));
        }
        levels.push(next);
    }
    Ok(levels)
}

fn private_result_oram_merkle_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn base64url_sha256(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(Sha256::digest(bytes).as_ref())
}

fn base64url_nopad_decoded_len(encoded_len: usize) -> Option<usize> {
    let full_quads = encoded_len / 4;
    let base_len = full_quads.checked_mul(3)?;
    match encoded_len % 4 {
        0 => Some(base_len),
        2 => base_len.checked_add(1),
        3 => base_len.checked_add(2),
        _ => None,
    }
}

fn validate_private_result_oram_client_state_ciphertext_encoded_len(
    encoded_len: usize,
) -> Result<usize, PrivateResultOramError> {
    let Some(decoded_len) = base64url_nopad_decoded_len(encoded_len) else {
        return Err(PrivateResultOramError::InvalidClientStateCiphertextEncoding);
    };
    if decoded_len > PRIVATE_RESULT_ORAM_CLIENT_STATE_CIPHERTEXT_MAX_BYTES {
        return Err(PrivateResultOramError::InvalidClientStateCiphertextEncoding);
    }
    Ok(decoded_len)
}

fn push_bucket_context_domain(
    message: &mut Vec<u8>,
    domain: &[u8],
) -> Result<(), PrivateResultOramError> {
    let len: u32 = domain
        .len()
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidBucketContext("context_length"))?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(domain);
    Ok(())
}

fn push_bucket_context_str(
    message: &mut Vec<u8>,
    value: &str,
) -> Result<(), PrivateResultOramError> {
    let len: u64 = value
        .len()
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidBucketContext("context_length"))?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_client_state_context_domain(
    message: &mut Vec<u8>,
    domain: &[u8],
) -> Result<(), PrivateResultOramError> {
    let len: u32 = domain
        .len()
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidClientStateContext("context_length"))?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(domain);
    Ok(())
}

fn push_client_state_context_str(
    message: &mut Vec<u8>,
    value: &str,
) -> Result<(), PrivateResultOramError> {
    let len: u64 = value
        .len()
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidClientStateContext("context_length"))?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value.as_bytes());
    Ok(())
}

fn try_push_domain(
    message: &mut Vec<u8>,
    value: &[u8],
    error: impl FnOnce() -> PrivateResultOramError,
) -> Result<(), PrivateResultOramError> {
    let len: u32 = value.len().try_into().map_err(|_| error())?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value);
    Ok(())
}

fn try_push_str(
    message: &mut Vec<u8>,
    value: &str,
    error: impl FnOnce() -> PrivateResultOramError,
) -> Result<(), PrivateResultOramError> {
    let len: u64 = value.len().try_into().map_err(|_| error())?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u16(message: &mut Vec<u8>, value: u16) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(message: &mut Vec<u8>, value: u32) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(message: &mut Vec<u8>, value: u64) {
    message.extend_from_slice(&value.to_be_bytes());
}

fn read_payload_exact<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], PrivateResultOramError> {
    let end = cursor
        .checked_add(len)
        .ok_or(PrivateResultOramError::InvalidPayloadBlock)?;
    if end > bytes.len() {
        return Err(PrivateResultOramError::InvalidPayloadBlock);
    }
    let out = &bytes[*cursor..end];
    *cursor = end;
    Ok(out)
}

fn read_payload_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, PrivateResultOramError> {
    read_payload_exact(bytes, cursor, 1).map(|bytes| bytes[0])
}

fn read_payload_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, PrivateResultOramError> {
    let bytes = read_payload_exact(bytes, cursor, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_payload_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, PrivateResultOramError> {
    let bytes = read_payload_exact(bytes, cursor, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_payload_u32_usize(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<usize, PrivateResultOramError> {
    usize::try_from(read_payload_u32(bytes, cursor)?)
        .map_err(|_| PrivateResultOramError::InvalidPayloadBlock)
}

fn read_payload_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, PrivateResultOramError> {
    let bytes = read_payload_exact(bytes, cursor, 8)?;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_payload_array_32(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; 32], PrivateResultOramError> {
    read_payload_exact(bytes, cursor, 32)?
        .try_into()
        .map_err(|_| PrivateResultOramError::InvalidPayloadBlock)
}

fn read_bucket_exact<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], PrivateResultOramError> {
    let end = cursor
        .checked_add(len)
        .ok_or(PrivateResultOramError::InvalidBucketPlaintext)?;
    if end > bytes.len() {
        return Err(PrivateResultOramError::InvalidBucketPlaintext);
    }
    let out = &bytes[*cursor..end];
    *cursor = end;
    Ok(out)
}

fn read_bucket_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, PrivateResultOramError> {
    read_bucket_exact(bytes, cursor, 1).map(|bytes| bytes[0])
}

fn read_bucket_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, PrivateResultOramError> {
    let bytes = read_bucket_exact(bytes, cursor, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_bucket_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, PrivateResultOramError> {
    let bytes = read_bucket_exact(bytes, cursor, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_bucket_u32_usize(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<usize, PrivateResultOramError> {
    usize::try_from(read_bucket_u32(bytes, cursor)?)
        .map_err(|_| PrivateResultOramError::InvalidBucketPlaintext)
}

fn read_bucket_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, PrivateResultOramError> {
    let bytes = read_bucket_exact(bytes, cursor, 8)?;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;
    use crate::private_hnsw_oram::OramKind;

    /// Deterministic padding source for plan tests: consecutive leaves from `start`.
    fn padding_from(
        start: u64,
        tree_height: u32,
    ) -> impl FnMut() -> Result<u64, PrivateResultOramError> {
        let leaf_count = private_result_oram_leaf_count(tree_height).unwrap();
        let mut next = start;
        move || {
            let leaf = next;
            next = (next + 1) % leaf_count;
            Ok(leaf)
        }
    }

    #[test]
    fn private_result_oram_error_display_does_not_reflect_structured_values() {
        let cases = [
            PrivateResultOramError::Encryption(EncryptionError::UnsupportedAlgorithm(
                "aead-alg-sentinel".to_string(),
            ))
            .to_string(),
            PrivateResultOramError::UnsupportedManifestVersion(99).to_string(),
            PrivateResultOramError::InvalidProvider.to_string(),
            PrivateResultOramError::InvalidBinding.to_string(),
            PrivateResultOramError::InvalidManifestField("manifest-field-sentinel").to_string(),
            PrivateResultOramError::ManifestContextMismatch("manifest-context-sentinel")
                .to_string(),
            PrivateResultOramError::MissingManifestSignature.to_string(),
            PrivateResultOramError::UnsupportedSignatureAlgorithm("rsa-pss-sentinel".to_string())
                .to_string(),
            PrivateResultOramError::SignatureKeyIdMismatch.to_string(),
            PrivateResultOramError::MalformedSignature.to_string(),
            PrivateResultOramError::InvalidManifestSignature.to_string(),
            PrivateResultOramError::InvalidCommitSignature.to_string(),
            PrivateResultOramError::InvalidReadBucketsSignature.to_string(),
            PrivateResultOramError::InvalidResourceKeyId.to_string(),
            PrivateResultOramError::UnsupportedBucketVersion(88).to_string(),
            PrivateResultOramError::InvalidBucketField("bucket-field-sentinel").to_string(),
            PrivateResultOramError::BucketOversized.to_string(),
            PrivateResultOramError::InvalidBucketHash.to_string(),
            PrivateResultOramError::InvalidBucketCiphertextEncoding.to_string(),
            PrivateResultOramError::InvalidBucketCiphertextHash.to_string(),
            PrivateResultOramError::InvalidBucketContext("bucket-context-sentinel").to_string(),
            PrivateResultOramError::UnsupportedBucketCiphertextVersion(77).to_string(),
            PrivateResultOramError::BucketOpenFailed.to_string(),
            PrivateResultOramError::BucketMetadataMismatch.to_string(),
            PrivateResultOramError::InvalidBucketCommitment.to_string(),
            PrivateResultOramError::EmptyMerkleTree.to_string(),
            PrivateResultOramError::MerkleRootMismatch.to_string(),
            PrivateResultOramError::ManifestCommitMismatch.to_string(),
            PrivateResultOramError::InvalidFetchPlanField("fetch-plan-field-sentinel").to_string(),
            PrivateResultOramError::InvalidFetchPlanField("payload_fetch_tokens").to_string(),
            PrivateResultOramError::InvalidFetchPlanField("payloadFetchTokens").to_string(),
            PrivateResultOramError::InvalidFetchPlanField("payload.fetch.token").to_string(),
            PrivateResultOramError::EmptyCommit.to_string(),
            PrivateResultOramError::InvalidMerkleProof.to_string(),
            PrivateResultOramError::InvalidMerkleProofJson.to_string(),
            PrivateResultOramError::MerkleProofMismatch.to_string(),
            PrivateResultOramError::MissingPayloadFetchTokenPosition.to_string(),
            PrivateResultOramError::InvalidClientConfig("client-config-sentinel").to_string(),
            PrivateResultOramError::InvalidClientConfig("payload_fetch_token").to_string(),
            PrivateResultOramError::InvalidClientConfig("payloadFetchToken").to_string(),
            PrivateResultOramError::InvalidClientConfig("payload.fetch.token").to_string(),
            PrivateResultOramError::UnsupportedPayloadBlockVersion(99).to_string(),
            PrivateResultOramError::InvalidPayloadBlock.to_string(),
            PrivateResultOramError::InvalidPayloadBlockPadding.to_string(),
            PrivateResultOramError::PayloadBlockOversized.to_string(),
            PrivateResultOramError::InvalidBucketPlaintext.to_string(),
            PrivateResultOramError::BucketPlaintextSlotCountMismatch.to_string(),
            PrivateResultOramError::MissingPosition.to_string(),
            PrivateResultOramError::MissingBlock.to_string(),
            PrivateResultOramError::PathBucketMismatch.to_string(),
            PrivateResultOramError::UnsupportedClientStateSnapshotVersion(55).to_string(),
            PrivateResultOramError::InvalidClientStateSnapshot.to_string(),
            PrivateResultOramError::InvalidClientStateContext("client-state-context-sentinel")
                .to_string(),
            PrivateResultOramError::InvalidClientStateContext("payload_fetch_tokens").to_string(),
            PrivateResultOramError::InvalidClientStateContext("payloadFetchTokens").to_string(),
            PrivateResultOramError::InvalidClientStateContext("payload.fetch.token").to_string(),
            PrivateResultOramError::InvalidClientStateCiphertextEncoding.to_string(),
            PrivateResultOramError::InvalidClientStateCiphertextHash.to_string(),
            PrivateResultOramError::UnsupportedClientStateCiphertextVersion(66).to_string(),
            PrivateResultOramError::ClientStateOpenFailed.to_string(),
            PrivateResultOramError::BucketOutOfRange {
                bucket_id: 123,
                bucket_count: 456,
            }
            .to_string(),
            PrivateResultOramError::StaleBucketEpoch {
                bucket_id: 123,
                expected_epoch: 42,
                actual_epoch: 43,
            }
            .to_string(),
            PrivateResultOramError::DuplicateUpdatedBucket { bucket_id: 123 }.to_string(),
            PrivateResultOramError::DuplicatePayloadFetchToken.to_string(),
            PrivateResultOramError::DuplicatePointToken.to_string(),
            PrivateResultOramError::DuplicatePayloadFetchTokenPosition.to_string(),
        ];

        for rendered in cases {
            assert!(!rendered.contains("aead-alg-sentinel"), "{rendered}");
            assert!(!rendered.contains("rsa-pss-sentinel"), "{rendered}");
            for leaked in [
                "manifest-field-sentinel",
                "manifest-context-sentinel",
                "bucket-field-sentinel",
                "bucket-context-sentinel",
                "fetch-plan-field-sentinel",
                "client-config-sentinel",
                "client-state-context-sentinel",
                "payload_fetch_token",
                "payload_fetch_tokens",
                "payloadFetchToken",
                "payloadFetchTokens",
                "payload.fetch.token",
            ] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
            for leaked in ["99", "88", "77", "66", "55", "123", "456", "42", "43"] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
        }
    }

    #[test]
    fn private_result_oram_error_debug_does_not_reflect_structured_values() {
        let cases = [
            format!(
                "{:?}",
                PrivateResultOramError::Encryption(EncryptionError::UnsupportedAlgorithm(
                    "aead-alg-sentinel".to_string(),
                ))
            ),
            format!(
                "{:?}",
                PrivateResultOramError::UnsupportedManifestVersion(99)
            ),
            format!("{:?}", PrivateResultOramError::InvalidProvider),
            format!("{:?}", PrivateResultOramError::InvalidBinding),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidManifestField("manifest-field-sentinel")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::ManifestContextMismatch("manifest-context-sentinel")
            ),
            format!("{:?}", PrivateResultOramError::MissingManifestSignature),
            format!(
                "{:?}",
                PrivateResultOramError::UnsupportedSignatureAlgorithm(
                    "rsa-pss-sentinel".to_string()
                )
            ),
            format!("{:?}", PrivateResultOramError::SignatureKeyIdMismatch),
            format!("{:?}", PrivateResultOramError::MalformedSignature),
            format!("{:?}", PrivateResultOramError::InvalidManifestSignature),
            format!("{:?}", PrivateResultOramError::InvalidCommitSignature),
            format!("{:?}", PrivateResultOramError::InvalidReadBucketsSignature),
            format!("{:?}", PrivateResultOramError::InvalidResourceKeyId),
            format!("{:?}", PrivateResultOramError::UnsupportedBucketVersion(88)),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidBucketField("bucket-field-sentinel")
            ),
            format!("{:?}", PrivateResultOramError::BucketOversized),
            format!("{:?}", PrivateResultOramError::InvalidBucketHash),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidBucketCiphertextEncoding
            ),
            format!("{:?}", PrivateResultOramError::InvalidBucketCiphertextHash),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidBucketContext("bucket-context-sentinel")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::UnsupportedBucketCiphertextVersion(77)
            ),
            format!("{:?}", PrivateResultOramError::BucketOpenFailed),
            format!("{:?}", PrivateResultOramError::BucketMetadataMismatch),
            format!("{:?}", PrivateResultOramError::InvalidBucketCommitment),
            format!("{:?}", PrivateResultOramError::EmptyMerkleTree),
            format!("{:?}", PrivateResultOramError::MerkleRootMismatch),
            format!("{:?}", PrivateResultOramError::ManifestCommitMismatch),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidFetchPlanField("fetch-plan-field-sentinel")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidFetchPlanField("payload_fetch_tokens")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidFetchPlanField("payloadFetchTokens")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidFetchPlanField("payload.fetch.token")
            ),
            format!("{:?}", PrivateResultOramError::EmptyCommit),
            format!("{:?}", PrivateResultOramError::InvalidMerkleProof),
            format!("{:?}", PrivateResultOramError::InvalidMerkleProofJson),
            format!("{:?}", PrivateResultOramError::MerkleProofMismatch),
            format!(
                "{:?}",
                PrivateResultOramError::MissingPayloadFetchTokenPosition
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientConfig("client-config-sentinel")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientConfig("payload_fetch_token")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientConfig("payloadFetchToken")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientConfig("payload.fetch.token")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::UnsupportedPayloadBlockVersion(99)
            ),
            format!("{:?}", PrivateResultOramError::InvalidPayloadBlock),
            format!("{:?}", PrivateResultOramError::InvalidPayloadBlockPadding),
            format!("{:?}", PrivateResultOramError::PayloadBlockOversized),
            format!("{:?}", PrivateResultOramError::InvalidBucketPlaintext),
            format!(
                "{:?}",
                PrivateResultOramError::BucketPlaintextSlotCountMismatch
            ),
            format!("{:?}", PrivateResultOramError::MissingPosition),
            format!("{:?}", PrivateResultOramError::MissingBlock),
            format!("{:?}", PrivateResultOramError::PathBucketMismatch),
            format!(
                "{:?}",
                PrivateResultOramError::UnsupportedClientStateSnapshotVersion(55)
            ),
            format!("{:?}", PrivateResultOramError::InvalidClientStateSnapshot),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientStateContext("client-state-context-sentinel")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientStateContext("payload_fetch_tokens")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientStateContext("payloadFetchTokens")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientStateContext("payload.fetch.token")
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientStateCiphertextEncoding
            ),
            format!(
                "{:?}",
                PrivateResultOramError::InvalidClientStateCiphertextHash
            ),
            format!(
                "{:?}",
                PrivateResultOramError::UnsupportedClientStateCiphertextVersion(66)
            ),
            format!("{:?}", PrivateResultOramError::ClientStateOpenFailed),
            format!(
                "{:?}",
                PrivateResultOramError::BucketOutOfRange {
                    bucket_id: 123,
                    bucket_count: 456,
                }
            ),
            format!(
                "{:?}",
                PrivateResultOramError::StaleBucketEpoch {
                    bucket_id: 123,
                    expected_epoch: 42,
                    actual_epoch: 43,
                }
            ),
            format!(
                "{:?}",
                PrivateResultOramError::DuplicateUpdatedBucket { bucket_id: 123 }
            ),
            format!("{:?}", PrivateResultOramError::DuplicatePayloadFetchToken),
            format!("{:?}", PrivateResultOramError::DuplicatePointToken),
            format!(
                "{:?}",
                PrivateResultOramError::DuplicatePayloadFetchTokenPosition
            ),
        ];

        for rendered in cases {
            assert!(!rendered.contains("aead-alg-sentinel"), "{rendered}");
            assert!(!rendered.contains("rsa-pss-sentinel"), "{rendered}");
            for leaked in [
                "manifest-field-sentinel",
                "manifest-context-sentinel",
                "bucket-field-sentinel",
                "bucket-context-sentinel",
                "fetch-plan-field-sentinel",
                "client-config-sentinel",
                "client-state-context-sentinel",
                "payload_fetch_token",
                "payload_fetch_tokens",
                "payloadFetchToken",
                "payloadFetchTokens",
                "payload.fetch.token",
            ] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
            for leaked in ["99", "88", "77", "66", "55", "123", "456", "42", "43"] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
        }
    }

    #[test]
    fn private_result_oram_encryption_wrapper_does_not_expose_source_error() {
        let err = PrivateResultOramError::Encryption(EncryptionError::UnsupportedAlgorithm(
            "aead-source-sentinel".to_string(),
        ));

        assert!(std::error::Error::source(&err).is_none());
        assert!(!err.to_string().contains("aead-source-sentinel"));
        assert!(!format!("{err:?}").contains("aead-source-sentinel"));
    }

    fn fixture_manifest() -> PrivateResultOramManifest {
        PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            key_id: "tenant-a/payload-private-rk".to_string(),
            rk_id: "tenant-a/payload-private-rk".to_string(),
            rk_epoch: 7,
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 8192,
                tree_height: 24,
                path_batch_size: 8,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: (1 << 25) - 1,
            logical_result_count: 700,
            dummy_result_count: 324,
            owner_signing_key_id: "tenant-a/private-result-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn deterministic_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap()
    }

    fn fixture_context<'a>(
        public_key: &'a [u8],
        key_id: &'a str,
    ) -> PrivateResultOramManifestValidationContext<'a> {
        PrivateResultOramManifestValidationContext {
            expected_collection_id: "collection-uuid-1",
            expected_key_id: "tenant-a/payload-private-rk",
            expected_rk_id: "tenant-a/payload-private-rk",
            min_rk_epoch: 7,
            max_rk_epoch: 7,
            signature_verification: PrivateResultOramSignatureVerification {
                expected_key_id: key_id,
                public_key,
            },
        }
    }

    fn sign_b64(key_pair: &Ed25519KeyPair, message: &[u8]) -> String {
        BASE64URL_NOPAD.encode(key_pair.sign(message).as_ref())
    }

    fn checked_manifest_signature_message(manifest: &PrivateResultOramManifest) -> Vec<u8> {
        try_private_result_oram_manifest_signature_message(manifest).unwrap()
    }

    fn checked_commit_signature_message(
        input: PrivateResultOramCommitSignatureInput<'_>,
    ) -> Vec<u8> {
        try_private_result_oram_commit_signature_message(input).unwrap()
    }

    fn unchecked_commit_signature_message(
        input: PrivateResultOramCommitSignatureInput<'_>,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        try_push_domain(
            &mut message,
            PRIVATE_RESULT_ORAM_COMMIT_SIGNATURE_DOMAIN.as_bytes(),
            || PrivateResultOramError::InvalidCommitSignature,
        )
        .unwrap();
        try_push_str(&mut message, input.collection_id, || {
            PrivateResultOramError::InvalidCommitSignature
        })
        .unwrap();
        try_push_str(&mut message, input.key_id, || {
            PrivateResultOramError::InvalidCommitSignature
        })
        .unwrap();
        try_push_str(&mut message, input.rk_id, || {
            PrivateResultOramError::InvalidCommitSignature
        })
        .unwrap();
        push_u64(&mut message, input.rk_epoch);
        push_u64(&mut message, input.old_epoch);
        push_u64(&mut message, input.new_epoch);
        try_push_str(&mut message, input.old_root_hash, || {
            PrivateResultOramError::InvalidCommitSignature
        })
        .unwrap();
        try_push_str(&mut message, input.new_root_hash, || {
            PrivateResultOramError::InvalidCommitSignature
        })
        .unwrap();
        push_u32(
            &mut message,
            u32::try_from(input.updated_buckets.len()).unwrap(),
        );
        for bucket in input.updated_buckets {
            push_u64(&mut message, bucket.bucket_id);
            try_push_str(&mut message, bucket.ciphertext_sha256, || {
                PrivateResultOramError::InvalidCommitSignature
            })
            .unwrap();
        }
        try_push_str(&mut message, input.signature_alg, || {
            PrivateResultOramError::InvalidCommitSignature
        })
        .unwrap();
        try_push_str(&mut message, input.signature_key_id, || {
            PrivateResultOramError::InvalidCommitSignature
        })
        .unwrap();
        message
    }

    fn checked_read_buckets_signature_message(
        input: PrivateResultOramReadBucketsSignatureInput<'_>,
    ) -> Vec<u8> {
        try_private_result_oram_read_buckets_signature_message(input).unwrap()
    }

    fn unchecked_read_buckets_signature_message(
        input: PrivateResultOramReadBucketsSignatureInput<'_>,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        try_push_domain(
            &mut message,
            PRIVATE_RESULT_ORAM_READ_BUCKETS_SIGNATURE_DOMAIN.as_bytes(),
            || PrivateResultOramError::InvalidReadBucketsSignature,
        )
        .unwrap();
        try_push_str(&mut message, input.collection_id, || {
            PrivateResultOramError::InvalidReadBucketsSignature
        })
        .unwrap();
        try_push_str(&mut message, input.key_id, || {
            PrivateResultOramError::InvalidReadBucketsSignature
        })
        .unwrap();
        try_push_str(&mut message, input.rk_id, || {
            PrivateResultOramError::InvalidReadBucketsSignature
        })
        .unwrap();
        push_u64(&mut message, input.rk_epoch);
        push_u64(&mut message, input.index_epoch);
        try_push_str(&mut message, input.root_hash, || {
            PrivateResultOramError::InvalidReadBucketsSignature
        })
        .unwrap();
        push_u64(&mut message, input.bucket_count);
        push_u32(&mut message, u32::try_from(input.bucket_ids.len()).unwrap());
        for bucket_id in input.bucket_ids {
            push_u64(&mut message, *bucket_id);
        }
        try_push_str(&mut message, input.signature_alg, || {
            PrivateResultOramError::InvalidReadBucketsSignature
        })
        .unwrap();
        try_push_str(&mut message, input.signature_key_id, || {
            PrivateResultOramError::InvalidReadBucketsSignature
        })
        .unwrap();
        message
    }

    fn bucket_validation_context() -> PrivateResultOramBucketValidationContext {
        let manifest = PrivateResultOramManifest {
            bucket_count: 16,
            ..fixture_manifest()
        };
        PrivateResultOramBucketValidationContext::from_manifest(&manifest, 128)
    }

    fn fixture_bucket() -> PrivateResultOramBucket {
        let ciphertext = [3; 32];
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(ciphertext).as_ref());
        PrivateResultOramBucket {
            version: 1,
            bucket_id: 9,
            index_epoch: 42,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256: ciphertext_sha256.clone(),
            bucket_commitment: fixture_bucket_commitment(9, 42, &ciphertext_sha256),
        }
    }

    fn fixture_commit_bucket(
        bucket_id: u64,
        epoch: u64,
        commitment_byte: u8,
    ) -> PrivateResultOramBucket {
        let ciphertext = [commitment_byte; 32];
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(ciphertext).as_ref());
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256: ciphertext_sha256.clone(),
            bucket_commitment: fixture_bucket_commitment(bucket_id, epoch, &ciphertext_sha256),
        }
    }

    fn commitment(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn fixture_bucket_commitment(bucket_id: u64, epoch: u64, ciphertext_sha256: &str) -> String {
        private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/payload-private-rk",
                rk_id: "tenant-a/payload-private-rk",
                rk_epoch: 7,
                bucket_id,
                index_epoch: epoch,
            },
            ciphertext_sha256,
        )
        .unwrap()
    }

    fn fixture_upload_bucket_set(
        manifest: &PrivateResultOramManifest,
    ) -> Vec<PrivateResultOramBucket> {
        (0..3)
            .map(|bucket_id| {
                fixture_upload_bucket(
                    bucket_id,
                    manifest.index_epoch,
                    bucket_id as u8 + 1,
                    manifest,
                )
            })
            .collect()
    }

    fn fixture_upload_bucket(
        bucket_id: u64,
        epoch: u64,
        byte: u8,
        manifest: &PrivateResultOramManifest,
    ) -> PrivateResultOramBucket {
        let ciphertext =
            vec![byte; private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap()];
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref());
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256: ciphertext_sha256.clone(),
            bucket_commitment: fixture_bucket_commitment(bucket_id, epoch, &ciphertext_sha256),
        }
    }

    fn small_fetch_manifest() -> PrivateResultOramManifest {
        PrivateResultOramManifest {
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 256,
                tree_height: 3,
                path_batch_size: 2,
            },
            bucket_count: 15,
            logical_result_count: 3,
            dummy_result_count: 5,
            ..fixture_manifest()
        }
    }

    fn result_client_config() -> PrivateResultOramClientConfig {
        PrivateResultOramClientConfig {
            tree_height: 3,
            bucket_size: 2,
            block_size_bytes: 128,
        }
    }

    fn payload_block(id: u8) -> PrivateResultOramPayloadBlockPlaintext {
        PrivateResultOramPayloadBlockPlaintext {
            version: 1,
            payload_fetch_token: [id; 32],
            point_token: [id.wrapping_add(20); 32],
            payload: vec![id, id.wrapping_add(1), id.wrapping_add(2)],
            deleted: false,
            generation: u64::from(id),
        }
    }

    fn result_test_keys() -> PrivateResultOramClientKeys {
        PrivateResultOramClientKeys::derive_from_resource_key_with_context(
            &SecretKey::from_bytes([7; 32]),
            "collection-uuid-1",
            "tenant-a/payload-private-rk",
            7,
        )
        .unwrap()
    }

    fn result_bucket_context(bucket_id: u64) -> PrivateResultOramBucketAeadContext<'static> {
        PrivateResultOramBucketAeadContext {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            bucket_id,
            index_epoch: 42,
        }
    }

    fn result_bucket_base_context() -> PrivateResultOramBucketAeadBaseContext<'static> {
        PrivateResultOramBucketAeadBaseContext {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
        }
    }

    fn result_client_state_context(root_hash: &str) -> PrivateResultOramClientStateAeadContext<'_> {
        PrivateResultOramClientStateAeadContext {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash,
        }
    }

    fn result_snapshot_padding() -> PrivateResultOramClientStateSnapshotPadding {
        PrivateResultOramClientStateSnapshotPadding {
            block_size_bytes: 128,
            stash_capacity: 4,
        }
    }

    fn result_proof_sibling(
        level: u32,
        position: PrivateResultOramMerkleSiblingPosition,
        hash: String,
    ) -> PrivateResultOramMerkleSibling {
        PrivateResultOramMerkleSibling {
            level,
            position,
            hash,
        }
    }

    fn result_proof_for_bucket_ids(
        bucket_ids: &[u64],
        index_epoch: u64,
        root_hash: String,
        commitments: &[String],
    ) -> PrivateResultOramMerkleProof {
        let levels = private_result_oram_merkle_levels(commitments).unwrap();
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
                            PrivateResultOramMerkleSiblingPosition::Right
                        } else {
                            PrivateResultOramMerkleSiblingPosition::Left
                        };
                        index /= 2;
                        result_proof_sibling(
                            level as u32,
                            position,
                            BASE64URL_NOPAD.encode(&level_hashes[sibling_index]),
                        )
                    })
                    .collect();
                PrivateResultOramMerkleProofLeaf {
                    bucket_id: *bucket_id,
                    leaf_hash: commitments[*bucket_id as usize].clone(),
                    siblings,
                }
            })
            .collect();

        PrivateResultOramMerkleProof {
            kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch,
            root_hash,
            bucket_count: commitments.len() as u64,
            leaves,
        }
    }

    #[test]
    #[allow(deprecated)]
    fn result_oram_client_key_derivation_is_domain_separated() {
        let resource_key = SecretKey::from_bytes([7; 32]);
        let keys = PrivateResultOramClientKeys::derive_from_resource_key(&resource_key).unwrap();
        assert_ne!(keys.bucket_aead_key().as_bytes(), resource_key.as_bytes());
        assert_eq!(
            keys.bucket_aead_key().as_bytes(),
            resource_key
                .derive_subkey(PRIVATE_RESULT_ORAM_BUCKET_AEAD_DOMAIN)
                .unwrap()
                .as_bytes()
        );
        assert_ne!(
            keys.bucket_aead_key().as_bytes(),
            keys.client_state_key().as_bytes()
        );
        assert_eq!(
            keys.client_state_key().as_bytes(),
            resource_key
                .derive_subkey(PRIVATE_RESULT_ORAM_CLIENT_STATE_AEAD_DOMAIN)
                .unwrap()
                .as_bytes()
        );
        let debug = format!("{keys:?}");
        assert!(debug.contains("[redacted; 32 bytes]"));
        for secret in [keys.bucket_aead_key(), keys.client_state_key()] {
            assert!(!debug.contains(&BASE64URL_NOPAD.encode(secret.as_bytes())));
        }
    }

    #[test]
    #[allow(deprecated)]
    fn result_oram_client_key_derivation_binds_manifest_context() {
        let resource_key = SecretKey::from_bytes([7; 32]);
        let manifest = fixture_manifest();
        let first = PrivateResultOramClientKeys::derive_from_resource_key_for_manifest(
            &resource_key,
            &manifest,
        )
        .unwrap();
        let second = PrivateResultOramClientKeys::derive_from_resource_key_for_manifest(
            &resource_key,
            &manifest,
        )
        .unwrap();
        let legacy = PrivateResultOramClientKeys::derive_from_resource_key(&resource_key).unwrap();
        let mut other_collection = manifest.clone();
        other_collection.collection_id = "collection-uuid-2".to_string();
        let other_collection_keys =
            PrivateResultOramClientKeys::derive_from_resource_key_for_manifest(
                &resource_key,
                &other_collection,
            )
            .unwrap();
        let mut other_epoch = manifest;
        other_epoch.rk_epoch += 1;
        let other_epoch_keys = PrivateResultOramClientKeys::derive_from_resource_key_for_manifest(
            &resource_key,
            &other_epoch,
        )
        .unwrap();

        assert_eq!(
            first.bucket_aead_key().as_bytes(),
            second.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.bucket_aead_key().as_bytes(),
            legacy.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.bucket_aead_key().as_bytes(),
            other_collection_keys.bucket_aead_key().as_bytes()
        );
        assert_ne!(
            first.bucket_aead_key().as_bytes(),
            other_epoch_keys.bucket_aead_key().as_bytes()
        );
    }

    #[test]
    fn result_oram_debug_redacts_plaintext_and_access_pattern_values() {
        let block = payload_block(44);
        let bucket = PrivateResultOramPlaintextBucket {
            bucket_id: 123_456,
            blocks: vec![Some(block.clone()), None],
        };
        let access = PrivateResultOramAccessResult {
            old_leaf: 654_321,
            new_leaf: 654_322,
            block: block.clone(),
            writeback_buckets: vec![bucket.clone()],
        };
        let client_config = PrivateResultOramClientConfig {
            tree_height: 3,
            bucket_size: 2,
            block_size_bytes: 128,
        };
        let token_position = PrivateResultOramFetchTokenPosition {
            payload_fetch_token: block.payload_fetch_token,
            leaf: 777_888,
        };
        let read_bucket_id = 123_456;
        let next_read_bucket_id = 123_457;
        let read_batch = PrivateResultOramReadBucketBatchPlan {
            bucket_ids: vec![read_bucket_id, next_read_bucket_id],
            token_count: 1,
            padding_leaves: Vec::new(),
        };
        let read_plan = PrivateResultOramReadBucketPlan {
            batches: vec![read_batch.clone()],
            token_count: 77,
            path_batch_size: 88,
        };
        let ordered_read_plan = PrivateResultOramOrderedReadBucketPlan {
            payload_fetch_tokens: vec![block.payload_fetch_token, [64; 32]],
            read_plan: read_plan.clone(),
        };
        let token_access = PrivateResultOramTokenFetchAccess {
            payload_fetch_token: block.payload_fetch_token,
            old_leaf: 654_321,
            new_leaf: 654_322,
            block: block.clone(),
        };
        let fetch_result = PrivateResultOramTokenFetchResult {
            accesses: vec![token_access],
            updated_buckets: Vec::new(),
        };
        let encrypted_bucket = PrivateResultOramBucket {
            version: 1,
            bucket_id: 123_456,
            index_epoch: 42,
            ciphertext: "RESULT-CIPHERTEXT-SENTINEL".to_string(),
            ciphertext_sha256: "RESULT-SHA-SENTINEL".to_string(),
            bucket_commitment: "RESULT-COMMITMENT-SENTINEL".to_string(),
        };
        let leaf_commitment = encrypted_bucket.bucket_commitment.clone();
        let signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: "RESULT-SIGNATURE-KEY-SENTINEL".to_string(),
            sig: "RESULT-SIGNATURE-SENTINEL".to_string(),
        };
        let state_snapshot = PrivateResultOramClientStateSnapshot {
            version: 1,
            tree_height: 3,
            positions: vec![PrivateResultOramPositionMapSnapshotEntry {
                payload_fetch_token: BASE64URL_NOPAD.encode(&[44; 32]),
                leaf_label: "leaf-label-sentinel".to_string(),
            }],
            stash: vec![block.clone()],
        };
        let encrypted_state_snapshot = PrivateResultOramEncryptedClientStateSnapshot {
            version: 1,
            index_epoch: 42,
            root_hash: "RESULT-ROOT-SENTINEL".to_string(),
            ciphertext: "RESULT-STATE-CIPHERTEXT-SENTINEL".to_string(),
            ciphertext_sha256: "RESULT-STATE-SHA-SENTINEL".to_string(),
        };
        let proof = PrivateResultOramMerkleProof {
            kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: "RESULT-ROOT-SENTINEL".to_string(),
            bucket_count: 8,
            leaves: vec![PrivateResultOramMerkleProofLeaf {
                bucket_id: 123_456,
                leaf_hash: "RESULT-LEAF-HASH-SENTINEL".to_string(),
                siblings: vec![PrivateResultOramMerkleSibling {
                    level: 0,
                    position: PrivateResultOramMerkleSiblingPosition::Left,
                    hash: "RESULT-SIBLING-HASH-SENTINEL".to_string(),
                }],
            }],
        };
        let mut manifest = fixture_manifest();
        manifest.collection_id = "RESULT-MANIFEST-COLLECTION-ID-SENTINEL".to_string();
        manifest.key_id = "RESULT-MANIFEST-KEY-SENTINEL".to_string();
        manifest.rk_id = "RESULT-MANIFEST-RK-SENTINEL".to_string();
        manifest.owner_signing_key_id = "RESULT-MANIFEST-OWNER-SIGNING-KEY-SENTINEL".to_string();
        manifest.root_hash = "RESULT-MANIFEST-ROOT-SENTINEL".to_string();
        let upload_bundle = PrivateResultOramUploadBundle {
            manifest: manifest.clone(),
            manifest_signature: signature.clone(),
            buckets: vec![encrypted_bucket.clone()],
        };
        let encrypted_batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: 42,
            root_hash: "RESULT-ROOT-SENTINEL".to_string(),
            bucket_count: 8,
            proof_value: "RESULT-PROOF-VALUE-SENTINEL".to_string(),
            buckets: vec![encrypted_bucket.clone()],
        };
        let commit_plan = PrivateResultOramCommitPlan {
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: "RESULT-OLD-ROOT-SENTINEL".to_string(),
            new_root_hash: "RESULT-NEW-ROOT-SENTINEL".to_string(),
            leaf_commitments: vec![leaf_commitment],
            updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: 123_456,
                ciphertext_sha256: "RESULT-SHA-SENTINEL".to_string(),
            }],
        };
        let commit_refs = commit_plan.signature_bucket_refs();
        let commit_ref = PrivateResultOramCommitBucketRef {
            bucket_id: 123_456,
            ciphertext_sha256: "RESULT-COMMIT-REF-SHA-SENTINEL",
        };
        let commit_signature_input = PrivateResultOramCommitSignatureInput {
            collection_id: "RESULT-COMMIT-COLLECTION-ID-SENTINEL",
            key_id: "RESULT-COMMIT-KEY-SENTINEL",
            rk_id: "RESULT-COMMIT-RK-SENTINEL",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: "RESULT-OLD-ROOT-SENTINEL",
            new_root_hash: "RESULT-NEW-ROOT-SENTINEL",
            updated_buckets: &commit_refs,
            signature_alg: "ed25519",
            signature_key_id: "RESULT-COMMIT-SIGNATURE-KEY-SENTINEL",
        };
        let read_bucket_ids = [read_bucket_id, next_read_bucket_id];
        let read_signature_input = PrivateResultOramReadBucketsSignatureInput {
            collection_id: "RESULT-READ-COLLECTION-ID-SENTINEL",
            key_id: "RESULT-READ-KEY-SENTINEL",
            rk_id: "RESULT-READ-RK-SENTINEL",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: "RESULT-ROOT-SENTINEL",
            bucket_count: 8,
            bucket_ids: &read_bucket_ids,
            signature_alg: "ed25519",
            signature_key_id: "RESULT-READ-SIGNATURE-KEY-SENTINEL",
        };
        let validation_context = PrivateResultOramManifestValidationContext {
            expected_collection_id: "RESULT-CONTEXT-COLLECTION-ID-SENTINEL",
            expected_key_id: "RESULT-CONTEXT-KEY-SENTINEL",
            expected_rk_id: "RESULT-CONTEXT-RK-SENTINEL",
            min_rk_epoch: 7,
            max_rk_epoch: 7,
            signature_verification: PrivateResultOramSignatureVerification {
                expected_key_id: "RESULT-CONTEXT-SIGNATURE-KEY-SENTINEL",
                public_key: &[88; 32],
            },
        };
        let commit_signature_context = PrivateResultOramCommitSignatureContext {
            collection_id: "RESULT-SIGN-CONTEXT-COLLECTION-ID-SENTINEL",
            key_id: "RESULT-SIGN-CONTEXT-KEY-SENTINEL",
            rk_id: "RESULT-SIGN-CONTEXT-RK-SENTINEL",
            rk_epoch: 7,
            signing_key_id: "RESULT-SIGN-CONTEXT-SIGNING-KEY-SENTINEL",
        };
        let read_signature_context = PrivateResultOramReadBucketsSignatureContext {
            collection_id: "RESULT-READ-CONTEXT-COLLECTION-ID-SENTINEL",
            key_id: "RESULT-READ-CONTEXT-KEY-SENTINEL",
            rk_id: "RESULT-READ-CONTEXT-RK-SENTINEL",
            rk_epoch: 7,
            signing_key_id: "RESULT-READ-CONTEXT-SIGNING-KEY-SENTINEL",
        };
        let bucket_validation_context = PrivateResultOramBucketValidationContext {
            expected_index_epoch: 991_001,
            bucket_count: 991_002,
            max_ciphertext_bytes: 991_003,
        };
        let bucket_aead_context = PrivateResultOramBucketAeadContext {
            collection_id: "RESULT-AEAD-BUCKET-COLLECTION-ID-SENTINEL",
            key_id: "RESULT-AEAD-BUCKET-KEY-SENTINEL",
            rk_id: "RESULT-AEAD-BUCKET-RK-SENTINEL",
            rk_epoch: 7,
            bucket_id: 888_223,
            index_epoch: 777_223,
        };
        let bucket_aead_base_context = PrivateResultOramBucketAeadBaseContext {
            collection_id: "RESULT-AEAD-BASE-COLLECTION-ID-SENTINEL",
            key_id: "RESULT-AEAD-BASE-KEY-SENTINEL",
            rk_id: "RESULT-AEAD-BASE-RK-SENTINEL",
            rk_epoch: 7,
        };
        let client_state_aead_context = PrivateResultOramClientStateAeadContext {
            collection_id: "RESULT-AEAD-STATE-COLLECTION-ID-SENTINEL",
            key_id: "RESULT-AEAD-STATE-KEY-SENTINEL",
            rk_id: "RESULT-AEAD-STATE-RK-SENTINEL",
            rk_epoch: 7,
            index_epoch: 777_224,
            root_hash: "RESULT-AEAD-STATE-ROOT-SENTINEL",
        };
        let bucket_commitment_context = PrivateResultOramBucketCommitmentContext {
            collection_id: "RESULT-COMMITMENT-CONTEXT-COLLECTION-ID-SENTINEL",
            key_id: "RESULT-COMMITMENT-CONTEXT-KEY-SENTINEL",
            rk_id: "RESULT-COMMITMENT-CONTEXT-RK-SENTINEL",
            rk_epoch: 7,
            bucket_id: 888_224,
            index_epoch: 777_225,
        };
        let epoch = PrivateResultOramEpoch {
            epoch: 42,
            root_hash: [66; 32],
        };

        let rendered = [
            format!("{block:?}"),
            format!("{bucket:?}"),
            format!("{access:?}"),
            format!("{client_config:?}"),
            format!("{token_position:?}"),
            format!("{read_batch:?}"),
            format!("{read_plan:?}"),
            format!("{ordered_read_plan:?}"),
            format!("{fetch_result:?}"),
            format!("{encrypted_bucket:?}"),
            format!("{signature:?}"),
            format!("{state_snapshot:?}"),
            format!("{encrypted_state_snapshot:?}"),
            format!("{proof:?}"),
            format!("{:?}", proof.leaves[0]),
            format!("{:?}", proof.leaves[0].siblings[0]),
            format!("{manifest:?}"),
            format!("{upload_bundle:?}"),
            format!("{encrypted_batch:?}"),
            format!("{commit_plan:?}"),
            format!("{commit_ref:?}"),
            format!("{commit_signature_input:?}"),
            format!("{read_signature_input:?}"),
            format!("{validation_context:?}"),
            format!("{commit_signature_context:?}"),
            format!("{read_signature_context:?}"),
            format!("{bucket_validation_context:?}"),
            format!("{bucket_aead_context:?}"),
            format!("{bucket_aead_base_context:?}"),
            format!("{client_state_aead_context:?}"),
            format!("{bucket_commitment_context:?}"),
            format!("{epoch:?}"),
        ]
        .join("\n");
        for epoch_redacted in [
            format!("{encrypted_state_snapshot:?}"),
            format!("{proof:?}"),
            format!("{encrypted_batch:?}"),
        ] {
            assert!(!epoch_redacted.contains("42"), "{epoch_redacted}");
        }
        let encrypted_state_snapshot_rendered = format!("{encrypted_state_snapshot:?}");
        assert!(
            !encrypted_state_snapshot_rendered
                .contains(&encrypted_state_snapshot.ciphertext.len().to_string()),
            "{encrypted_state_snapshot_rendered}"
        );
        let encrypted_bucket_rendered = format!("{encrypted_bucket:?}");
        assert!(!encrypted_bucket_rendered.contains("123456"));
        assert!(!encrypted_bucket_rendered.contains("42"));
        assert!(
            !encrypted_bucket_rendered.contains(&encrypted_bucket.ciphertext.len().to_string()),
            "{encrypted_bucket_rendered}"
        );
        for leaked in [
            BASE64URL_NOPAD.encode(&[44; 32]),
            BASE64URL_NOPAD.encode(&[64; 32]),
            format!("{:?}", [44u8; 32]),
            format!("{:?}", [64u8; 32]),
            serde_json::to_string(&vec![44_u8, 45, 46]).unwrap(),
            "123456".to_string(),
            "123457".to_string(),
            "654321".to_string(),
            "777888".to_string(),
            "leaf-label-sentinel".to_string(),
            "RESULT-CIPHERTEXT-SENTINEL".to_string(),
            "RESULT-SHA-SENTINEL".to_string(),
            "RESULT-COMMIT-REF-SHA-SENTINEL".to_string(),
            "RESULT-COMMITMENT-SENTINEL".to_string(),
            "RESULT-SIGNATURE-KEY-SENTINEL".to_string(),
            "RESULT-SIGNATURE-SENTINEL".to_string(),
            "RESULT-COMMIT-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-COMMIT-KEY-SENTINEL".to_string(),
            "RESULT-COMMIT-RK-SENTINEL".to_string(),
            "RESULT-COMMIT-SIGNATURE-KEY-SENTINEL".to_string(),
            "RESULT-READ-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-READ-KEY-SENTINEL".to_string(),
            "RESULT-READ-RK-SENTINEL".to_string(),
            "RESULT-READ-SIGNATURE-KEY-SENTINEL".to_string(),
            "RESULT-CONTEXT-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-CONTEXT-KEY-SENTINEL".to_string(),
            "RESULT-CONTEXT-RK-SENTINEL".to_string(),
            "RESULT-CONTEXT-SIGNATURE-KEY-SENTINEL".to_string(),
            "[88, 88, 88".to_string(),
            "RESULT-SIGN-CONTEXT-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-SIGN-CONTEXT-KEY-SENTINEL".to_string(),
            "RESULT-SIGN-CONTEXT-RK-SENTINEL".to_string(),
            "RESULT-SIGN-CONTEXT-SIGNING-KEY-SENTINEL".to_string(),
            "RESULT-READ-CONTEXT-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-READ-CONTEXT-KEY-SENTINEL".to_string(),
            "RESULT-READ-CONTEXT-RK-SENTINEL".to_string(),
            "RESULT-READ-CONTEXT-SIGNING-KEY-SENTINEL".to_string(),
            "991001".to_string(),
            "991002".to_string(),
            "991003".to_string(),
            "RESULT-AEAD-BUCKET-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-AEAD-BUCKET-KEY-SENTINEL".to_string(),
            "RESULT-AEAD-BUCKET-RK-SENTINEL".to_string(),
            "888223".to_string(),
            "777223".to_string(),
            "RESULT-AEAD-BASE-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-AEAD-BASE-KEY-SENTINEL".to_string(),
            "RESULT-AEAD-BASE-RK-SENTINEL".to_string(),
            "RESULT-AEAD-STATE-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-AEAD-STATE-KEY-SENTINEL".to_string(),
            "RESULT-AEAD-STATE-RK-SENTINEL".to_string(),
            "777224".to_string(),
            "RESULT-AEAD-STATE-ROOT-SENTINEL".to_string(),
            "RESULT-COMMITMENT-CONTEXT-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-COMMITMENT-CONTEXT-KEY-SENTINEL".to_string(),
            "RESULT-COMMITMENT-CONTEXT-RK-SENTINEL".to_string(),
            "888224".to_string(),
            "777225".to_string(),
            "[66, 66, 66".to_string(),
            "RESULT-ROOT-SENTINEL".to_string(),
            "RESULT-STATE-CIPHERTEXT-SENTINEL".to_string(),
            "RESULT-STATE-SHA-SENTINEL".to_string(),
            "RESULT-LEAF-HASH-SENTINEL".to_string(),
            "RESULT-SIBLING-HASH-SENTINEL".to_string(),
            "RESULT-PROOF-VALUE-SENTINEL".to_string(),
            "RESULT-OLD-ROOT-SENTINEL".to_string(),
            "RESULT-NEW-ROOT-SENTINEL".to_string(),
            "RESULT-MANIFEST-COLLECTION-ID-SENTINEL".to_string(),
            "RESULT-MANIFEST-KEY-SENTINEL".to_string(),
            "RESULT-MANIFEST-RK-SENTINEL".to_string(),
            "RESULT-MANIFEST-OWNER-SIGNING-KEY-SENTINEL".to_string(),
            "RESULT-MANIFEST-ROOT-SENTINEL".to_string(),
        ] {
            assert!(!rendered.contains(&leaked), "{rendered}");
        }
        for (debug_rendered, redacted_count) in [
            (format!("{block:?}"), "payload_len: 3"),
            (format!("{block:?}"), "deleted: false"),
            (format!("{block:?}"), "generation: 44"),
            (format!("{bucket:?}"), "blocks_len: 2"),
            (format!("{bucket:?}"), "occupied_blocks: 1"),
            (format!("{access:?}"), "writeback_bucket_count: 1"),
            (format!("{client_config:?}"), "tree_height: 3"),
            (format!("{client_config:?}"), "bucket_size: 2"),
            (format!("{client_config:?}"), "block_size_bytes: 128"),
            (format!("{state_snapshot:?}"), "tree_height: 3"),
            (format!("{state_snapshot:?}"), "position_count: 1"),
            (format!("{state_snapshot:?}"), "stash_len: 1"),
            (format!("{proof:?}"), "bucket_count: 8"),
            (format!("{proof:?}"), "leaf_count: 1"),
            (format!("{:?}", proof.leaves[0]), "sibling_count: 1"),
            (format!("{read_batch:?}"), "bucket_id_count: 2"),
            (format!("{read_batch:?}"), "token_count: 1"),
            (format!("{read_plan:?}"), "batch_count: 1"),
            (format!("{read_plan:?}"), "token_count: 77"),
            (format!("{read_plan:?}"), "path_batch_size: 88"),
            (
                format!("{ordered_read_plan:?}"),
                "payload_fetch_token_count: 2",
            ),
            (format!("{fetch_result:?}"), "access_count: 1"),
            (format!("{fetch_result:?}"), "updated_bucket_count: 0"),
            (format!("{upload_bundle:?}"), "bucket_count: 1"),
            (format!("{encrypted_batch:?}"), "bucket_count: 8"),
            (format!("{encrypted_batch:?}"), "returned_bucket_count: 1"),
            (format!("{commit_plan:?}"), "leaf_commitment_count: 1"),
            (format!("{commit_plan:?}"), "updated_bucket_count: 1"),
            (
                format!("{commit_signature_input:?}"),
                "updated_bucket_count: 1",
            ),
            (format!("{read_signature_input:?}"), "bucket_count: 8"),
            (
                format!("{read_signature_input:?}"),
                "requested_bucket_count: 2",
            ),
            (
                format!("{bucket_validation_context:?}"),
                "expected_index_epoch: 991001",
            ),
            (
                format!("{bucket_validation_context:?}"),
                "bucket_count: 991002",
            ),
            (
                format!("{bucket_validation_context:?}"),
                "max_ciphertext_bytes: 991003",
            ),
        ] {
            assert!(
                !debug_rendered.contains(redacted_count),
                "leaked {redacted_count} in {debug_rendered}"
            );
        }
    }

    #[test]
    fn payload_block_codec_pads_to_fixed_size_and_roundtrips() {
        let block = payload_block(7);
        let encoded = encode_private_result_oram_payload_block(&block, 128).unwrap();
        assert_eq!(encoded.len(), 128);
        assert_eq!(
            decode_private_result_oram_payload_block(&encoded).unwrap(),
            block
        );

        let mut tampered = encoded;
        let last = tampered.len() - 1;
        tampered[last] = 1;
        assert_eq!(
            decode_private_result_oram_payload_block(&tampered),
            Err(PrivateResultOramError::InvalidPayloadBlockPadding)
        );
    }

    #[test]
    fn payload_block_codec_rejects_oversized_payload() {
        let mut block = payload_block(7);
        block.payload = vec![1; 256];
        assert_eq!(
            encode_private_result_oram_payload_block(&block, 128),
            Err(PrivateResultOramError::PayloadBlockOversized)
        );

        block.version = 99;
        assert_eq!(
            encode_private_result_oram_payload_block(&block, 512),
            Err(PrivateResultOramError::UnsupportedPayloadBlockVersion(99))
        );
    }

    #[test]
    fn bucket_plaintext_codec_roundtrips_fixed_slots_and_rejects_tamper() {
        let config = result_client_config();
        let bucket = PrivateResultOramPlaintextBucket {
            bucket_id: 3,
            blocks: vec![Some(payload_block(8)), None],
        };
        let encoded = encode_private_result_oram_bucket_plaintext(&bucket, config).unwrap();
        assert_eq!(
            encoded.len(),
            PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_MAGIC.len()
                + 2
                + 8
                + 4
                + 4
                + private_result_oram_bucket_plaintext_slots_len(config).unwrap()
        );
        assert_eq!(
            decode_private_result_oram_bucket_plaintext(3, &encoded, config).unwrap(),
            bucket
        );

        let mut tampered = encoded;
        let last = tampered.len() - 1;
        tampered[last] = 1;
        assert_eq!(
            decode_private_result_oram_bucket_plaintext(3, &tampered, config),
            Err(PrivateResultOramError::InvalidBucketPlaintext)
        );

        let duplicate_point_a = payload_block(9);
        let mut duplicate_point_b = payload_block(10);
        duplicate_point_b.point_token = duplicate_point_a.point_token;
        let duplicate_point_bucket = PrivateResultOramPlaintextBucket {
            bucket_id: 3,
            blocks: vec![
                Some(duplicate_point_a.clone()),
                Some(duplicate_point_b.clone()),
            ],
        };
        assert_eq!(
            encode_private_result_oram_bucket_plaintext(&duplicate_point_bucket, config),
            Err(PrivateResultOramError::DuplicatePointToken)
        );

        let mut duplicate_point_encoded = Vec::new();
        duplicate_point_encoded.extend_from_slice(PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_MAGIC);
        push_u16(
            &mut duplicate_point_encoded,
            PRIVATE_RESULT_ORAM_BUCKET_PLAINTEXT_VERSION,
        );
        push_u64(&mut duplicate_point_encoded, 3);
        push_u32(&mut duplicate_point_encoded, config.bucket_size as u32);
        push_u32(&mut duplicate_point_encoded, config.block_size_bytes as u32);
        for block in [duplicate_point_a, duplicate_point_b] {
            duplicate_point_encoded.push(1);
            duplicate_point_encoded.extend_from_slice(
                &encode_private_result_oram_payload_block(&block, config.block_size_bytes).unwrap(),
            );
        }
        assert_eq!(
            decode_private_result_oram_bucket_plaintext(3, &duplicate_point_encoded, config),
            Err(PrivateResultOramError::DuplicatePointToken)
        );

        let duplicate_payload_a = payload_block(11);
        let mut duplicate_payload_b = payload_block(12);
        duplicate_payload_b.payload_fetch_token = duplicate_payload_a.payload_fetch_token;
        let duplicate_payload_bucket = PrivateResultOramPlaintextBucket {
            bucket_id: 3,
            blocks: vec![Some(duplicate_payload_a), Some(duplicate_payload_b)],
        };
        assert_eq!(
            encode_private_result_oram_bucket_plaintext(&duplicate_payload_bucket, config),
            Err(PrivateResultOramError::DuplicatePayloadFetchToken)
        );
    }

    #[test]
    fn bucket_plaintext_codec_rejects_overflowing_shape_config() {
        let block_size_overflow = PrivateResultOramClientConfig {
            block_size_bytes: usize::MAX,
            ..result_client_config()
        };
        let bucket = PrivateResultOramPlaintextBucket {
            bucket_id: 3,
            blocks: Vec::new(),
        };
        assert_eq!(
            encode_private_result_oram_bucket_plaintext(&bucket, block_size_overflow),
            Err(PrivateResultOramError::InvalidClientConfig(
                "block_size_bytes"
            ))
        );

        let bucket_size_overflow = PrivateResultOramClientConfig {
            bucket_size: usize::MAX,
            block_size_bytes: 2,
            ..result_client_config()
        };
        assert_eq!(
            empty_private_result_oram_plaintext_bucket(3, bucket_size_overflow),
            Err(PrivateResultOramError::InvalidClientConfig("bucket_size"))
        );
    }

    #[test]
    fn plaintext_readers_reject_cursor_overflow() {
        let mut payload_cursor = usize::MAX;
        assert!(matches!(
            read_payload_exact(&[], &mut payload_cursor, 1),
            Err(PrivateResultOramError::InvalidPayloadBlock)
        ));

        let mut bucket_cursor = usize::MAX;
        assert!(matches!(
            read_bucket_exact(&[], &mut bucket_cursor, 1),
            Err(PrivateResultOramError::InvalidBucketPlaintext)
        ));
    }

    #[test]
    fn bucket_ciphertext_size_matches_path_oram_encoding_contract() {
        let manifest = fixture_manifest();
        let config = private_result_oram_client_config_from_manifest(&manifest).unwrap();
        let plaintext_bucket = empty_private_result_oram_plaintext_bucket(0, config).unwrap();
        let plaintext =
            encode_private_result_oram_bucket_plaintext(&plaintext_bucket, config).unwrap();

        assert_eq!(
            private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
            PRIVATE_RESULT_ORAM_BUCKET_AEAD_OVERHEAD_BYTES + plaintext.len()
        );
    }

    #[test]
    fn bucket_seal_open_roundtrips_and_populates_integrity_fields() {
        let keys = result_test_keys();
        let context = result_bucket_context(3);
        let plaintext = vec![11; 256];
        let bucket = seal_private_result_oram_bucket(&keys, context, &plaintext).unwrap();

        assert_eq!(bucket.version, 1);
        assert_eq!(bucket.bucket_id, 3);
        assert_eq!(bucket.index_epoch, 42);
        decode_base64url_32(&bucket.ciphertext_sha256, "ciphertext_sha256").unwrap();
        decode_bucket_commitment(&bucket.bucket_commitment).unwrap();
        assert_eq!(
            private_result_oram_bucket_commitment(
                PrivateResultOramBucketCommitmentContext {
                    collection_id: context.collection_id,
                    key_id: context.key_id,
                    rk_id: context.rk_id,
                    rk_epoch: context.rk_epoch,
                    bucket_id: context.bucket_id,
                    index_epoch: context.index_epoch,
                },
                &bucket.ciphertext_sha256,
            )
            .unwrap(),
            bucket.bucket_commitment
        );
        assert_eq!(
            open_private_result_oram_bucket(&keys, context, &bucket).unwrap(),
            plaintext
        );
    }

    #[test]
    fn upload_bucket_validation_rejects_rehashed_unknown_aead_version() {
        let keys = result_test_keys();
        let context = result_bucket_context(3);
        let mut bucket = seal_private_result_oram_bucket(&keys, context, &[9; 64]).unwrap();
        let mut raw_ciphertext = BASE64URL_NOPAD
            .decode(bucket.ciphertext.as_bytes())
            .unwrap();
        raw_ciphertext[0] = 77;
        bucket.ciphertext = BASE64URL_NOPAD.encode(&raw_ciphertext);
        bucket.ciphertext_sha256 = base64url_sha256(&raw_ciphertext);
        bucket.bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: context.collection_id,
                key_id: context.key_id,
                rk_id: context.rk_id,
                rk_epoch: context.rk_epoch,
                bucket_id: context.bucket_id,
                index_epoch: context.index_epoch,
            },
            &bucket.ciphertext_sha256,
        )
        .unwrap();

        assert_eq!(
            validate_private_result_upload_bucket(
                PrivateResultOramBucketAeadBaseContext {
                    collection_id: context.collection_id,
                    key_id: context.key_id,
                    rk_id: context.rk_id,
                    rk_epoch: context.rk_epoch,
                },
                &bucket,
                context.index_epoch,
                8,
                raw_ciphertext.len(),
            ),
            Err(PrivateResultOramError::UnsupportedBucketCiphertextVersion(
                77
            ))
        );
    }

    #[test]
    fn bucket_open_rejects_wrong_context_hash_and_ciphertext_tamper() {
        let keys = result_test_keys();
        let context = result_bucket_context(3);
        let bucket = seal_private_result_oram_bucket(&keys, context, &[9; 64]).unwrap();

        let mut wrong_context = context;
        wrong_context.bucket_id = 4;
        assert_eq!(
            open_private_result_oram_bucket(&keys, wrong_context, &bucket),
            Err(PrivateResultOramError::BucketMetadataMismatch)
        );

        for wrong_context in [
            PrivateResultOramBucketAeadContext {
                collection_id: "collection-uuid-2",
                ..context
            },
            PrivateResultOramBucketAeadContext {
                key_id: "tenant-a/payload-private-rk-v2",
                ..context
            },
            PrivateResultOramBucketAeadContext {
                rk_id: "tenant-a/payload-private-rk-v2",
                ..context
            },
            PrivateResultOramBucketAeadContext {
                rk_epoch: 8,
                ..context
            },
        ] {
            let mut wrong_context_bucket = bucket.clone();
            wrong_context_bucket.bucket_commitment = private_result_oram_bucket_commitment(
                PrivateResultOramBucketCommitmentContext {
                    collection_id: wrong_context.collection_id,
                    key_id: wrong_context.key_id,
                    rk_id: wrong_context.rk_id,
                    rk_epoch: wrong_context.rk_epoch,
                    bucket_id: wrong_context.bucket_id,
                    index_epoch: wrong_context.index_epoch,
                },
                &wrong_context_bucket.ciphertext_sha256,
            )
            .unwrap();
            assert_eq!(
                open_private_result_oram_bucket(&keys, wrong_context, &wrong_context_bucket),
                Err(PrivateResultOramError::BucketOpenFailed)
            );
        }

        let mut wrong_hash = bucket.clone();
        wrong_hash.ciphertext_sha256 = BASE64URL_NOPAD.encode(&[8; 32]);
        assert_eq!(
            open_private_result_oram_bucket(&keys, context, &wrong_hash),
            Err(PrivateResultOramError::InvalidBucketCiphertextHash)
        );

        let mut malformed_ciphertext = bucket.clone();
        malformed_ciphertext.ciphertext = "A".to_string();
        assert_eq!(
            open_private_result_oram_bucket(&keys, context, &malformed_ciphertext),
            Err(PrivateResultOramError::InvalidBucketCiphertextEncoding)
        );

        let mut wrong_ciphertext = bucket;
        let mut raw = BASE64URL_NOPAD
            .decode(wrong_ciphertext.ciphertext.as_bytes())
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        wrong_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&raw);
        wrong_ciphertext.ciphertext_sha256 = base64url_sha256(&raw);
        wrong_ciphertext.bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: context.collection_id,
                key_id: context.key_id,
                rk_id: context.rk_id,
                rk_epoch: context.rk_epoch,
                bucket_id: context.bucket_id,
                index_epoch: context.index_epoch,
            },
            &wrong_ciphertext.ciphertext_sha256,
        )
        .unwrap();
        assert_eq!(
            open_private_result_oram_bucket(&keys, context, &wrong_ciphertext),
            Err(PrivateResultOramError::BucketOpenFailed)
        );
    }

    #[test]
    fn plaintext_bucket_seal_open_roundtrips() {
        let keys = result_test_keys();
        let config = result_client_config();
        let plaintext_bucket = PrivateResultOramPlaintextBucket {
            bucket_id: 0,
            blocks: vec![Some(payload_block(8)), None],
        };
        let sealed = seal_private_result_oram_plaintext_bucket(
            &keys,
            result_bucket_base_context(),
            42,
            &plaintext_bucket,
            config,
        )
        .unwrap();

        assert_eq!(
            open_private_result_oram_plaintext_bucket(
                &keys,
                result_bucket_base_context(),
                &sealed,
                config,
            )
            .unwrap(),
            plaintext_bucket
        );
    }

    #[test]
    fn verified_bucket_batch_opens_only_after_merkle_proof_check() {
        let keys = result_test_keys();
        let config = result_client_config();
        let bucket0 = seal_private_result_oram_plaintext_bucket(
            &keys,
            result_bucket_base_context(),
            42,
            &PrivateResultOramPlaintextBucket {
                bucket_id: 0,
                blocks: vec![Some(payload_block(8)), None],
            },
            config,
        )
        .unwrap();
        let bucket1 = seal_private_result_oram_plaintext_bucket(
            &keys,
            result_bucket_base_context(),
            42,
            &PrivateResultOramPlaintextBucket {
                bucket_id: 1,
                blocks: vec![Some(payload_block(9)), None],
            },
            config,
        )
        .unwrap();
        let root = private_result_oram_merkle_root_for_commitments(&[
            bucket0.bucket_commitment.clone(),
            bucket1.bucket_commitment.clone(),
        ])
        .unwrap();
        let proof = PrivateResultOramMerkleProof {
            kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root.clone(),
            bucket_count: 2,
            leaves: vec![PrivateResultOramMerkleProofLeaf {
                bucket_id: 0,
                leaf_hash: bucket0.bucket_commitment.clone(),
                siblings: vec![PrivateResultOramMerkleSibling {
                    level: 0,
                    position: PrivateResultOramMerkleSiblingPosition::Right,
                    hash: bucket1.bucket_commitment.clone(),
                }],
            }],
        };
        let proof_value = serde_json::to_string(&proof).unwrap();

        let opened = open_private_result_oram_verified_bucket_batch(
            &keys,
            result_bucket_base_context(),
            config,
            42,
            &root,
            2,
            &proof_value,
            std::slice::from_ref(&bucket0),
        )
        .unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].blocks[0], Some(payload_block(8)));

        let mut unopened_tampered_bucket = bucket0.clone();
        let mut raw_ciphertext = BASE64URL_NOPAD
            .decode(unopened_tampered_bucket.ciphertext.as_bytes())
            .unwrap();
        *raw_ciphertext.last_mut().unwrap() ^= 0x01;
        unopened_tampered_bucket.ciphertext = BASE64URL_NOPAD.encode(&raw_ciphertext);
        unopened_tampered_bucket.ciphertext_sha256 = base64url_sha256(&raw_ciphertext);
        // Keep the old commitment so opening this bucket would fail if proof checks moved later.

        let tampered_proof = PrivateResultOramMerkleProof {
            root_hash: BASE64URL_NOPAD.encode(&[99; 32]),
            ..proof
        };
        assert_eq!(
            open_private_result_oram_verified_bucket_batch(
                &keys,
                result_bucket_base_context(),
                config,
                42,
                &root,
                2,
                &serde_json::to_string(&tampered_proof).unwrap(),
                std::slice::from_ref(&unopened_tampered_bucket),
            ),
            Err(PrivateResultOramError::MerkleProofMismatch)
        );
    }

    #[test]
    fn path_oram_access_absorbs_path_remaps_and_writes_back() {
        let config = result_client_config();
        let block_a = payload_block(10);
        let block_b = payload_block(11);
        let mut state = PrivateResultOramClientState::with_position_map(
            [
                (block_a.payload_fetch_token, 2),
                (block_b.payload_fetch_token, 3),
            ],
            config.tree_height,
        )
        .unwrap();
        let path = vec![
            empty_private_result_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(1, config).unwrap(),
            PrivateResultOramPlaintextBucket {
                bucket_id: 4,
                blocks: vec![Some(block_b.clone()), None],
            },
            PrivateResultOramPlaintextBucket {
                bucket_id: 9,
                blocks: vec![Some(block_a.clone()), None],
            },
        ];

        let access = access_private_result_oram_path(
            &mut state,
            config,
            block_a.payload_fetch_token,
            &path,
            0,
        )
        .unwrap();

        assert_eq!(access.old_leaf, 2);
        assert_eq!(access.new_leaf, 0);
        assert_eq!(access.block, block_a);
        assert_eq!(state.position(&block_a.payload_fetch_token), Some(0));
        assert_eq!(state.position(&block_b.payload_fetch_token), Some(3));
        assert_eq!(state.stash_len(), 0);
        assert_eq!(
            access
                .writeback_buckets
                .iter()
                .map(|bucket| bucket.bucket_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 4, 9]
        );
        assert!(access.writeback_buckets[0].blocks[0].is_none());
        assert_eq!(
            access.writeback_buckets[1].blocks[0]
                .as_ref()
                .map(|block| block.payload_fetch_token),
            Some([10; 32])
        );
        assert_eq!(
            access.writeback_buckets[2].blocks[0]
                .as_ref()
                .map(|block| block.payload_fetch_token),
            Some([11; 32])
        );
        assert!(access.writeback_buckets[3].blocks[0].is_none());
    }

    #[test]
    fn path_oram_access_rejects_wrong_path_and_missing_target() {
        let config = result_client_config();
        let block_a = payload_block(10);
        let mut state = PrivateResultOramClientState::with_position_map(
            [(block_a.payload_fetch_token, 2)],
            config.tree_height,
        )
        .unwrap();
        let wrong_path = vec![
            empty_private_result_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(1, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(4, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(10, config).unwrap(),
        ];
        assert_eq!(
            access_private_result_oram_path(
                &mut state,
                config,
                block_a.payload_fetch_token,
                &wrong_path,
                0,
            ),
            Err(PrivateResultOramError::PathBucketMismatch)
        );

        let path = vec![
            empty_private_result_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(1, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(4, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(9, config).unwrap(),
        ];
        assert_eq!(
            access_private_result_oram_path(
                &mut state,
                config,
                block_a.payload_fetch_token,
                &path,
                0,
            ),
            Err(PrivateResultOramError::MissingBlock)
        );
    }

    #[test]
    fn path_oram_access_rejects_duplicate_point_tokens() {
        let config = result_client_config();
        let block_a = payload_block(10);
        let mut duplicate_point_block = payload_block(11);
        duplicate_point_block.point_token = block_a.point_token;
        let mut state = PrivateResultOramClientState::with_position_map(
            [
                (block_a.payload_fetch_token, 2),
                (duplicate_point_block.payload_fetch_token, 3),
            ],
            config.tree_height,
        )
        .unwrap();
        let path = vec![
            empty_private_result_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(1, config).unwrap(),
            PrivateResultOramPlaintextBucket {
                bucket_id: 4,
                blocks: vec![Some(duplicate_point_block), None],
            },
            PrivateResultOramPlaintextBucket {
                bucket_id: 9,
                blocks: vec![Some(block_a.clone()), None],
            },
        ];

        assert_eq!(
            access_private_result_oram_path(
                &mut state,
                config,
                block_a.payload_fetch_token,
                &path,
                0,
            ),
            Err(PrivateResultOramError::DuplicatePointToken)
        );
        assert_eq!(state.stash_len(), 0);
        assert_eq!(state.position(&block_a.payload_fetch_token), Some(2));
    }

    #[test]
    fn path_oram_writeback_buckets_can_be_encoded_sealed_and_reopened() {
        let config = result_client_config();
        let keys = result_test_keys();
        let block = payload_block(10);
        let mut state = PrivateResultOramClientState::with_position_map(
            [(block.payload_fetch_token, 2)],
            config.tree_height,
        )
        .unwrap();
        let path = vec![
            empty_private_result_oram_plaintext_bucket(0, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(1, config).unwrap(),
            empty_private_result_oram_plaintext_bucket(4, config).unwrap(),
            PrivateResultOramPlaintextBucket {
                bucket_id: 9,
                blocks: vec![Some(block), None],
            },
        ];

        let access =
            access_private_result_oram_path(&mut state, config, [10; 32], &path, 0).unwrap();
        let root_writeback = &access.writeback_buckets[0];
        let sealed = seal_private_result_oram_plaintext_bucket(
            &keys,
            result_bucket_base_context(),
            42,
            root_writeback,
            config,
        )
        .unwrap();
        assert_eq!(
            open_private_result_oram_plaintext_bucket(
                &keys,
                result_bucket_base_context(),
                &sealed,
                config,
            )
            .unwrap(),
            *root_writeback
        );
    }

    #[test]
    fn encrypted_verified_token_fetch_opens_remaps_and_reseals_unique_writebacks() {
        let keys = result_test_keys();
        let base_context = result_bucket_base_context();
        let config = result_client_config();
        let bucket_count = private_result_oram_bucket_count(config.tree_height).unwrap();
        let bucket_count_usize = usize::try_from(bucket_count).unwrap();
        let block_a = payload_block(10);
        let block_b = payload_block(11);

        let mut plaintext_store = BTreeMap::new();
        for bucket_id in 0..bucket_count {
            plaintext_store.insert(
                bucket_id,
                empty_private_result_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(2, block_a.clone()), (3, block_b.clone())] {
            let leaf_bucket_id = *private_result_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let bucket = plaintext_store.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block);
        }

        let encrypted_store = plaintext_store
            .values()
            .map(|bucket| {
                let encrypted = seal_private_result_oram_plaintext_bucket(
                    &keys,
                    base_context,
                    42,
                    bucket,
                    config,
                )
                .unwrap();
                (bucket.bucket_id, encrypted)
            })
            .collect::<BTreeMap<_, _>>();
        let commitments = (0..bucket_count)
            .map(|bucket_id| {
                encrypted_store
                    .get(&bucket_id)
                    .unwrap()
                    .bucket_commitment
                    .clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(commitments.len(), bucket_count_usize);
        let root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let manifest = PrivateResultOramManifest {
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: config.bucket_size as u32,
                block_size_bytes: config.block_size_bytes as u32,
                tree_height: config.tree_height,
                path_batch_size: 2,
            },
            bucket_count,
            root_hash: root_hash.clone(),
            logical_result_count: 2,
            dummy_result_count: 0,
            ..fixture_manifest()
        };

        let payload_fetch_tokens = [block_a.payload_fetch_token, block_b.payload_fetch_token];
        let token_positions = [
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: block_a.payload_fetch_token,
                leaf: 2,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: block_b.payload_fetch_token,
                leaf: 3,
            },
        ];
        let read_plan = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
            &manifest,
            &payload_fetch_tokens,
            &token_positions,
            padding_from(0, 3),
        )
        .unwrap();
        assert_eq!(read_plan.batches.len(), 1);
        assert_eq!(
            read_plan.batches[0].bucket_ids,
            vec![0, 1, 4, 9, 0, 1, 4, 10]
        );

        let bucket_ids = &read_plan.batches[0].bucket_ids;
        let proof = result_proof_for_bucket_ids(bucket_ids, 42, root_hash.clone(), &commitments);
        let encrypted_batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: 42,
            root_hash: root_hash.clone(),
            bucket_count,
            proof_value: serde_json::to_string(&proof).unwrap(),
            buckets: bucket_ids
                .iter()
                .map(|bucket_id| encrypted_store.get(bucket_id).unwrap().clone())
                .collect(),
        };
        let mut state = PrivateResultOramClientState::with_position_map(
            [
                (block_a.payload_fetch_token, 2),
                (block_b.payload_fetch_token, 3),
            ],
            config.tree_height,
        )
        .unwrap();
        let mut remaps = [0, 1].into_iter();

        let result = fetch_private_result_oram_tokens_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut state,
            config,
            &payload_fetch_tokens,
            &read_plan,
            &[encrypted_batch],
            || {
                remaps
                    .next()
                    .ok_or(PrivateResultOramError::InvalidFetchPlanField("leaf"))
            },
        )
        .unwrap();

        assert_eq!(result.accesses.len(), 2);
        assert_eq!(result.accesses[0].block, block_a);
        assert_eq!(result.accesses[1].block, block_b);
        assert_eq!(result.accesses[0].old_leaf, 2);
        assert_eq!(result.accesses[0].new_leaf, 0);
        assert_eq!(result.accesses[1].old_leaf, 3);
        assert_eq!(result.accesses[1].new_leaf, 1);
        assert_eq!(state.position(&block_a.payload_fetch_token), Some(0));
        assert_eq!(state.position(&block_b.payload_fetch_token), Some(1));
        assert!(
            result
                .updated_buckets
                .iter()
                .all(|bucket| bucket.index_epoch == 43)
        );
        assert_eq!(
            result
                .updated_buckets
                .iter()
                .map(|bucket| bucket.bucket_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 4, 9, 10]
        );

        let updated_bucket_one = result
            .updated_buckets
            .iter()
            .find(|bucket| bucket.bucket_id == 1)
            .unwrap();
        let opened_bucket_one = open_private_result_oram_plaintext_bucket(
            &keys,
            base_context,
            updated_bucket_one,
            config,
        )
        .unwrap();
        let mut bucket_one_tokens = opened_bucket_one
            .blocks
            .iter()
            .flatten()
            .map(|block| block.payload_fetch_token)
            .collect::<Vec<_>>();
        bucket_one_tokens.sort_unstable();
        assert_eq!(
            bucket_one_tokens,
            vec![block_a.payload_fetch_token, block_b.payload_fetch_token]
        );

        let commit_plan = plan_private_result_oram_commit_for_manifest(
            &manifest,
            43,
            &commitments,
            &result.updated_buckets,
        )
        .unwrap();
        assert_eq!(commit_plan.updated_buckets.len(), 5);
        assert_ne!(commit_plan.new_root_hash, root_hash);
    }

    #[test]
    fn encrypted_verified_token_fetch_rejects_duplicate_payload_point_tokens() {
        let keys = result_test_keys();
        let base_context = result_bucket_base_context();
        let config = result_client_config();
        let bucket_count = private_result_oram_bucket_count(config.tree_height).unwrap();
        let block_a = payload_block(10);
        let mut block_b = payload_block(11);
        block_b.point_token = block_a.point_token;

        let mut plaintext_store = BTreeMap::new();
        for bucket_id in 0..bucket_count {
            plaintext_store.insert(
                bucket_id,
                empty_private_result_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in [(2, block_a.clone()), (3, block_b.clone())] {
            let leaf_bucket_id = *private_result_oram_bucket_ids_for_leaf(leaf, config.tree_height)
                .unwrap()
                .last()
                .unwrap();
            let bucket = plaintext_store.get_mut(&leaf_bucket_id).unwrap();
            *bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap() = Some(block);
        }

        let encrypted_store = plaintext_store
            .values()
            .map(|bucket| {
                let encrypted = seal_private_result_oram_plaintext_bucket(
                    &keys,
                    base_context,
                    42,
                    bucket,
                    config,
                )
                .unwrap();
                (bucket.bucket_id, encrypted)
            })
            .collect::<BTreeMap<_, _>>();
        let commitments = (0..bucket_count)
            .map(|bucket_id| {
                encrypted_store
                    .get(&bucket_id)
                    .unwrap()
                    .bucket_commitment
                    .clone()
            })
            .collect::<Vec<_>>();
        let root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let manifest = PrivateResultOramManifest {
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: config.bucket_size as u32,
                block_size_bytes: config.block_size_bytes as u32,
                tree_height: config.tree_height,
                path_batch_size: 2,
            },
            bucket_count,
            root_hash: root_hash.clone(),
            logical_result_count: 2,
            dummy_result_count: 0,
            ..fixture_manifest()
        };
        let payload_fetch_tokens = [block_a.payload_fetch_token, block_b.payload_fetch_token];
        let token_positions = [
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: block_a.payload_fetch_token,
                leaf: 2,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: block_b.payload_fetch_token,
                leaf: 3,
            },
        ];
        let read_plan = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
            &manifest,
            &payload_fetch_tokens,
            &token_positions,
            padding_from(0, 3),
        )
        .unwrap();
        let bucket_ids = &read_plan.batches[0].bucket_ids;
        let proof = result_proof_for_bucket_ids(bucket_ids, 42, root_hash.clone(), &commitments);
        let encrypted_batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: 42,
            root_hash: root_hash.clone(),
            bucket_count,
            proof_value: serde_json::to_string(&proof).unwrap(),
            buckets: bucket_ids
                .iter()
                .map(|bucket_id| encrypted_store.get(bucket_id).unwrap().clone())
                .collect(),
        };
        let mut state = PrivateResultOramClientState::with_position_map(
            [
                (block_a.payload_fetch_token, 2),
                (block_b.payload_fetch_token, 3),
            ],
            config.tree_height,
        )
        .unwrap();
        let mut remaps = [0, 1].into_iter();

        assert_eq!(
            fetch_private_result_oram_tokens_encrypted_verified(
                &keys,
                base_context,
                42,
                &root_hash,
                bucket_count,
                43,
                &mut state,
                config,
                &payload_fetch_tokens,
                &read_plan,
                &[encrypted_batch],
                || {
                    remaps
                        .next()
                        .ok_or(PrivateResultOramError::InvalidFetchPlanField("leaf"))
                },
            ),
            Err(PrivateResultOramError::DuplicatePointToken)
        );
        assert_eq!(state.position(&block_a.payload_fetch_token), Some(2));
        assert_eq!(state.position(&block_b.payload_fetch_token), Some(3));
    }

    #[test]
    fn encrypted_verified_token_fetch_keeps_state_when_final_reseal_fails() {
        let keys = result_test_keys();
        let base_context = result_bucket_base_context();
        let config = result_client_config();
        let bucket_count = private_result_oram_bucket_count(config.tree_height).unwrap();
        let block = payload_block(10);

        let mut plaintext_store = BTreeMap::new();
        for bucket_id in 0..bucket_count {
            plaintext_store.insert(
                bucket_id,
                empty_private_result_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        let leaf_bucket_id = *private_result_oram_bucket_ids_for_leaf(2, config.tree_height)
            .unwrap()
            .last()
            .unwrap();
        plaintext_store.get_mut(&leaf_bucket_id).unwrap().blocks[0] = Some(block.clone());

        let encrypted_store = plaintext_store
            .values()
            .map(|bucket| {
                let encrypted = seal_private_result_oram_plaintext_bucket(
                    &keys,
                    base_context,
                    42,
                    bucket,
                    config,
                )
                .unwrap();
                (bucket.bucket_id, encrypted)
            })
            .collect::<BTreeMap<_, _>>();
        let commitments = (0..bucket_count)
            .map(|bucket_id| {
                encrypted_store
                    .get(&bucket_id)
                    .unwrap()
                    .bucket_commitment
                    .clone()
            })
            .collect::<Vec<_>>();
        let root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let manifest = PrivateResultOramManifest {
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: config.bucket_size as u32,
                block_size_bytes: config.block_size_bytes as u32,
                tree_height: config.tree_height,
                path_batch_size: 1,
            },
            bucket_count,
            root_hash: root_hash.clone(),
            logical_result_count: 1,
            dummy_result_count: 0,
            ..fixture_manifest()
        };

        let payload_fetch_tokens = [block.payload_fetch_token];
        let token_positions = [PrivateResultOramFetchTokenPosition {
            payload_fetch_token: block.payload_fetch_token,
            leaf: 2,
        }];
        let read_plan = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
            &manifest,
            &payload_fetch_tokens,
            &token_positions,
            padding_from(0, 3),
        )
        .unwrap();
        let bucket_ids = &read_plan.batches[0].bucket_ids;
        let proof = result_proof_for_bucket_ids(bucket_ids, 42, root_hash.clone(), &commitments);
        let encrypted_batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: 42,
            root_hash: root_hash.clone(),
            bucket_count,
            proof_value: serde_json::to_string(&proof).unwrap(),
            buckets: bucket_ids
                .iter()
                .map(|bucket_id| encrypted_store.get(bucket_id).unwrap().clone())
                .collect(),
        };
        let mut oversized_stash_block = payload_block(99);
        oversized_stash_block.payload = vec![99; config.block_size_bytes];
        let mut state = PrivateResultOramClientState::with_position_map(
            [
                (block.payload_fetch_token, 2),
                (oversized_stash_block.payload_fetch_token, 0),
            ],
            config.tree_height,
        )
        .unwrap();
        state.stash.insert(
            oversized_stash_block.payload_fetch_token,
            oversized_stash_block,
        );
        let original_state = state.clone();
        let mut remaps = [0].into_iter();

        let err = fetch_private_result_oram_tokens_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut state,
            config,
            &payload_fetch_tokens,
            &read_plan,
            &[encrypted_batch],
            || {
                remaps
                    .next()
                    .ok_or(PrivateResultOramError::InvalidFetchPlanField("leaf"))
            },
        )
        .unwrap_err();

        assert_eq!(err, PrivateResultOramError::PayloadBlockOversized);
        assert_eq!(state, original_state);
    }

    #[test]
    fn encrypted_verified_token_fetch_rejects_multi_batch_single_commit_writeback() {
        let keys = result_test_keys();
        let base_context = result_bucket_base_context();
        let config = result_client_config();
        let bucket_count = private_result_oram_bucket_count(config.tree_height).unwrap();
        let blocks = [
            (2, payload_block(10)),
            (3, payload_block(11)),
            (4, payload_block(12)),
            (5, payload_block(13)),
        ];

        let mut plaintext_store = BTreeMap::new();
        for bucket_id in 0..bucket_count {
            plaintext_store.insert(
                bucket_id,
                empty_private_result_oram_plaintext_bucket(bucket_id, config).unwrap(),
            );
        }
        for (leaf, block) in &blocks {
            let leaf_bucket_id =
                *private_result_oram_bucket_ids_for_leaf(*leaf, config.tree_height)
                    .unwrap()
                    .last()
                    .unwrap();
            let bucket = plaintext_store.get_mut(&leaf_bucket_id).unwrap();
            let slot = bucket
                .blocks
                .iter_mut()
                .find(|slot| slot.is_none())
                .unwrap();
            *slot = Some(block.clone());
        }

        let encrypted_store = plaintext_store
            .values()
            .map(|bucket| {
                let encrypted = seal_private_result_oram_plaintext_bucket(
                    &keys,
                    base_context,
                    42,
                    bucket,
                    config,
                )
                .unwrap();
                (bucket.bucket_id, encrypted)
            })
            .collect::<BTreeMap<_, _>>();
        let commitments = (0..bucket_count)
            .map(|bucket_id| {
                encrypted_store
                    .get(&bucket_id)
                    .unwrap()
                    .bucket_commitment
                    .clone()
            })
            .collect::<Vec<_>>();
        let root_hash = private_result_oram_merkle_root_for_commitments(&commitments).unwrap();
        let manifest = PrivateResultOramManifest {
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: config.bucket_size as u32,
                block_size_bytes: config.block_size_bytes as u32,
                tree_height: config.tree_height,
                path_batch_size: 2,
            },
            bucket_count,
            root_hash: root_hash.clone(),
            logical_result_count: 4,
            dummy_result_count: 0,
            ..fixture_manifest()
        };

        let payload_fetch_tokens = blocks
            .iter()
            .map(|(_, block)| block.payload_fetch_token)
            .collect::<Vec<_>>();
        let token_positions = blocks
            .iter()
            .map(|(leaf, block)| PrivateResultOramFetchTokenPosition {
                payload_fetch_token: block.payload_fetch_token,
                leaf: *leaf,
            })
            .collect::<Vec<_>>();
        let read_plan = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
            &manifest,
            &payload_fetch_tokens,
            &token_positions,
            padding_from(0, 3),
        )
        .unwrap();
        assert_eq!(read_plan.batches.len(), 2);

        let encrypted_batches = read_plan
            .batches
            .iter()
            .map(|batch| {
                let proof = result_proof_for_bucket_ids(
                    &batch.bucket_ids,
                    42,
                    root_hash.clone(),
                    &commitments,
                );
                PrivateResultOramEncryptedBucketBatch {
                    index_epoch: 42,
                    root_hash: root_hash.clone(),
                    bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets: batch
                        .bucket_ids
                        .iter()
                        .map(|bucket_id| encrypted_store.get(bucket_id).unwrap().clone())
                        .collect(),
                }
            })
            .collect::<Vec<_>>();

        let mut failing_batches = encrypted_batches.clone();
        failing_batches[1].root_hash = BASE64URL_NOPAD.encode(&[99; 32]);
        let mut failing_state = PrivateResultOramClientState::with_position_map(
            token_positions
                .iter()
                .map(|position| (position.payload_fetch_token, position.leaf)),
            config.tree_height,
        )
        .unwrap();
        let original_failing_state = failing_state.clone();
        let mut failing_remaps = [0, 1, 6, 7].into_iter();
        assert_eq!(
            fetch_private_result_oram_tokens_encrypted_verified(
                &keys,
                base_context,
                42,
                &root_hash,
                bucket_count,
                43,
                &mut failing_state,
                config,
                &payload_fetch_tokens,
                &read_plan,
                &failing_batches,
                || {
                    failing_remaps
                        .next()
                        .ok_or(PrivateResultOramError::InvalidFetchPlanField("leaf"))
                },
            ),
            Err(PrivateResultOramError::MerkleProofMismatch)
        );
        assert_eq!(failing_state, original_failing_state);

        let mut state = PrivateResultOramClientState::with_position_map(
            token_positions
                .iter()
                .map(|position| (position.payload_fetch_token, position.leaf)),
            config.tree_height,
        )
        .unwrap();
        let mut remaps = [0, 1, 6, 7].into_iter();

        let result = fetch_private_result_oram_tokens_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            43,
            &mut state,
            config,
            &payload_fetch_tokens,
            &read_plan,
            &encrypted_batches,
            || {
                remaps
                    .next()
                    .ok_or(PrivateResultOramError::InvalidFetchPlanField("leaf"))
            },
        )
        .unwrap();

        assert_eq!(result.accesses.len(), 4);
        let single_batch_writeback_budget =
            private_result_oram_fixed_writeback_bucket_budget(&manifest.oram).unwrap();
        assert!(result.updated_buckets.len() > single_batch_writeback_budget);
        assert!(result.updated_buckets.len() <= usize::try_from(bucket_count).unwrap());

        let err = plan_private_result_oram_commit_for_manifest(
            &manifest,
            43,
            &commitments,
            &result.updated_buckets,
        )
        .unwrap_err();
        assert_eq!(
            err,
            PrivateResultOramError::InvalidFetchPlanField("updated_buckets")
        );

        let fixed_window_commit_plan = plan_private_result_oram_commit_for_manifest(
            &manifest,
            43,
            &commitments,
            &result.updated_buckets[..single_batch_writeback_budget],
        )
        .unwrap();
        assert_eq!(
            fixed_window_commit_plan.updated_buckets.len(),
            single_batch_writeback_budget,
        );
    }

    #[test]
    fn encrypted_verified_token_fetch_rejects_non_advancing_writeback_epoch_before_access() {
        use std::cell::Cell;

        let keys = result_test_keys();
        let base_context = result_bucket_base_context();
        let config = result_client_config();
        let payload_fetch_token = [11; 32];
        let root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let bucket_count = private_result_oram_bucket_count(config.tree_height).unwrap();
        let mut state = PrivateResultOramClientState::with_position_map(
            [(payload_fetch_token, 2)],
            config.tree_height,
        )
        .unwrap();
        let read_plan = PrivateResultOramReadBucketPlan {
            batches: vec![PrivateResultOramReadBucketBatchPlan {
                bucket_ids: vec![0, 1, 4, 9],
                token_count: 1,
                padding_leaves: Vec::new(),
            }],
            token_count: 1,
            path_batch_size: 1,
        };
        let next_leaf_called = Cell::new(false);

        let err = fetch_private_result_oram_tokens_encrypted_verified(
            &keys,
            base_context,
            42,
            &root_hash,
            bucket_count,
            42,
            &mut state,
            config,
            &[payload_fetch_token],
            &read_plan,
            &[],
            || {
                next_leaf_called.set(true);
                Ok(0)
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            PrivateResultOramError::InvalidManifestField("new_epoch")
        );
        assert!(!next_leaf_called.get());
        assert_eq!(state.position(&payload_fetch_token), Some(2));
    }

    #[test]
    fn encrypted_verified_token_fetch_rejects_malformed_read_plan_before_access() {
        use std::cell::Cell;

        let keys = result_test_keys();
        let base_context = result_bucket_base_context();
        let config = result_client_config();
        let payload_fetch_token = [11; 32];
        let root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let bucket_count = private_result_oram_bucket_count(config.tree_height).unwrap();
        let mut state = PrivateResultOramClientState::with_position_map(
            [(payload_fetch_token, 2)],
            config.tree_height,
        )
        .unwrap();
        let valid_plan = PrivateResultOramReadBucketPlan {
            batches: vec![PrivateResultOramReadBucketBatchPlan {
                bucket_ids: vec![0, 1, 4, 9],
                token_count: 1,
                padding_leaves: Vec::new(),
            }],
            token_count: 1,
            path_batch_size: 1,
        };
        let valid_batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: 42,
            root_hash: root_hash.clone(),
            bucket_count,
            proof_value: "{}".to_string(),
            buckets: Vec::new(),
        };
        let next_leaf_called = Cell::new(false);

        macro_rules! assert_rejects_before_access {
            ($tokens:expr, $plan:expr, $expected_bucket_count:expr, $batches:expr, $expected:expr) => {{
                next_leaf_called.set(false);
                let err = fetch_private_result_oram_tokens_encrypted_verified(
                    &keys,
                    base_context,
                    42,
                    &root_hash,
                    $expected_bucket_count,
                    43,
                    &mut state,
                    config,
                    $tokens,
                    $plan,
                    $batches,
                    || {
                        next_leaf_called.set(true);
                        Ok(0)
                    },
                )
                .unwrap_err();
                assert_eq!(err, $expected);
                assert!(!next_leaf_called.get());
                assert_eq!(state.position(&payload_fetch_token), Some(2));
            }};
        }

        let empty_tokens: &[[u8; 32]] = &[];
        assert_rejects_before_access!(
            empty_tokens,
            &PrivateResultOramReadBucketPlan {
                token_count: 0,
                ..valid_plan.clone()
            },
            bucket_count,
            &[],
            PrivateResultOramError::InvalidFetchPlanField("payload_fetch_tokens")
        );

        assert_rejects_before_access!(
            &[payload_fetch_token],
            &PrivateResultOramReadBucketPlan {
                token_count: 2,
                ..valid_plan.clone()
            },
            bucket_count,
            &[],
            PrivateResultOramError::InvalidFetchPlanField("read_plan")
        );

        assert_rejects_before_access!(
            &[payload_fetch_token],
            &PrivateResultOramReadBucketPlan {
                path_batch_size: 0,
                ..valid_plan.clone()
            },
            bucket_count,
            &[],
            PrivateResultOramError::InvalidFetchPlanField("path_batch_size")
        );

        assert_rejects_before_access!(
            &[payload_fetch_token],
            &valid_plan,
            bucket_count - 1,
            &[],
            PrivateResultOramError::InvalidFetchPlanField("bucket_count")
        );

        assert_rejects_before_access!(
            &[payload_fetch_token],
            &PrivateResultOramReadBucketPlan {
                batches: Vec::new(),
                ..valid_plan.clone()
            },
            bucket_count,
            &[],
            PrivateResultOramError::InvalidFetchPlanField("batches")
        );

        assert_rejects_before_access!(
            &[payload_fetch_token],
            &valid_plan,
            bucket_count,
            &[],
            PrivateResultOramError::InvalidFetchPlanField("encrypted_batches")
        );

        assert_rejects_before_access!(
            &[payload_fetch_token],
            &PrivateResultOramReadBucketPlan {
                batches: vec![PrivateResultOramReadBucketBatchPlan {
                    bucket_ids: vec![0, 1, 4, 9],
                    token_count: 2,
                    padding_leaves: Vec::new(),
                }],
                ..valid_plan
            },
            bucket_count,
            std::slice::from_ref(&valid_batch),
            PrivateResultOramError::InvalidFetchPlanField("token_count")
        );
    }

    #[test]
    fn encrypted_verified_token_fetch_rejects_bad_metadata_and_duplicate_tokens() {
        let keys = result_test_keys();
        let base_context = result_bucket_base_context();
        let config = result_client_config();
        let bucket_count = private_result_oram_bucket_count(config.tree_height).unwrap();
        let block = payload_block(10);
        let root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let mut state = PrivateResultOramClientState::with_position_map(
            [(block.payload_fetch_token, 2)],
            config.tree_height,
        )
        .unwrap();
        let read_plan = PrivateResultOramReadBucketPlan {
            batches: vec![PrivateResultOramReadBucketBatchPlan {
                bucket_ids: vec![0, 1, 4, 9],
                token_count: 1,
                padding_leaves: Vec::new(),
            }],
            token_count: 1,
            path_batch_size: 1,
        };
        let oversized_path_batch_plan = PrivateResultOramReadBucketPlan {
            batches: vec![PrivateResultOramReadBucketBatchPlan {
                bucket_ids: Vec::new(),
                token_count: 9,
                padding_leaves: Vec::new(),
            }],
            token_count: 9,
            path_batch_size: 9,
        };
        let oversized_path_batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: 42,
            root_hash: root_hash.clone(),
            bucket_count,
            proof_value: "{}".to_string(),
            buckets: Vec::new(),
        };
        let oversized_path_tokens = vec![[7u8; 32]; 9];
        assert_eq!(
            fetch_private_result_oram_tokens_encrypted_verified(
                &keys,
                base_context,
                42,
                &root_hash,
                bucket_count,
                43,
                &mut state,
                config,
                &oversized_path_tokens,
                &oversized_path_batch_plan,
                &[oversized_path_batch],
                || Ok(0),
            ),
            Err(PrivateResultOramError::InvalidFetchPlanField(
                "path_batch_size"
            ))
        );

        let bad_metadata_batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[99; 32]),
            bucket_count,
            proof_value: "{}".to_string(),
            buckets: Vec::new(),
        };
        assert_eq!(
            fetch_private_result_oram_tokens_encrypted_verified(
                &keys,
                base_context,
                42,
                &root_hash,
                bucket_count,
                43,
                &mut state,
                config,
                &[block.payload_fetch_token],
                &read_plan,
                &[bad_metadata_batch],
                || Ok(0),
            ),
            Err(PrivateResultOramError::MerkleProofMismatch)
        );

        let duplicate_plan = PrivateResultOramReadBucketPlan {
            batches: vec![PrivateResultOramReadBucketBatchPlan {
                bucket_ids: vec![0, 1, 4, 9],
                token_count: 2,
                padding_leaves: Vec::new(),
            }],
            token_count: 2,
            path_batch_size: 2,
        };
        let duplicate_batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: 42,
            root_hash: root_hash.clone(),
            bucket_count,
            proof_value: "{}".to_string(),
            buckets: Vec::new(),
        };
        assert_eq!(
            fetch_private_result_oram_tokens_encrypted_verified(
                &keys,
                base_context,
                42,
                &root_hash,
                bucket_count,
                43,
                &mut state,
                config,
                &[block.payload_fetch_token, block.payload_fetch_token],
                &duplicate_plan,
                std::slice::from_ref(&duplicate_batch),
                || Ok(0),
            ),
            Err(PrivateResultOramError::DuplicatePayloadFetchToken)
        );

        let mut duplicate_leaf_state = PrivateResultOramClientState::with_position_map(
            [(block.payload_fetch_token, 2), ([2; 32], 2)],
            config.tree_height,
        )
        .unwrap();
        let duplicate_path_plan = PrivateResultOramReadBucketPlan {
            batches: vec![PrivateResultOramReadBucketBatchPlan {
                bucket_ids: vec![0, 1, 4, 9, 0, 1, 4, 9],
                token_count: 2,
                padding_leaves: Vec::new(),
            }],
            token_count: 2,
            path_batch_size: 2,
        };
        assert_eq!(
            fetch_private_result_oram_tokens_encrypted_verified(
                &keys,
                base_context,
                42,
                &root_hash,
                bucket_count,
                43,
                &mut duplicate_leaf_state,
                config,
                &[block.payload_fetch_token, [2; 32]],
                &duplicate_path_plan,
                std::slice::from_ref(&duplicate_batch),
                || Ok(0),
            ),
            Err(PrivateResultOramError::InvalidFetchPlanField("bucket_ids"))
        );
        assert_eq!(
            duplicate_leaf_state.position(&block.payload_fetch_token),
            Some(2)
        );
        assert_eq!(duplicate_leaf_state.position(&[2; 32]), Some(2));

        let partial_batch_plan = PrivateResultOramReadBucketPlan {
            batches: vec![
                PrivateResultOramReadBucketBatchPlan {
                    bucket_ids: vec![0, 1, 4, 9, 0, 1, 4, 10],
                    token_count: 2,
                    padding_leaves: Vec::new(),
                },
                PrivateResultOramReadBucketBatchPlan {
                    bucket_ids: vec![0, 1, 3, 8],
                    token_count: 1,
                    padding_leaves: Vec::new(),
                },
            ],
            token_count: 3,
            path_batch_size: 2,
        };
        assert_eq!(
            fetch_private_result_oram_tokens_encrypted_verified(
                &keys,
                base_context,
                42,
                &root_hash,
                bucket_count,
                43,
                &mut state,
                config,
                &[block.payload_fetch_token, [2; 32], [3; 32]],
                &partial_batch_plan,
                &[],
                || Ok(0),
            ),
            Err(PrivateResultOramError::InvalidFetchPlanField(
                "payload_fetch_tokens"
            ))
        );

        let wrong_path_plan = PrivateResultOramReadBucketPlan {
            batches: vec![PrivateResultOramReadBucketBatchPlan {
                bucket_ids: vec![0, 1, 4, 10],
                token_count: 1,
                padding_leaves: Vec::new(),
            }],
            token_count: 1,
            path_batch_size: 1,
        };
        let wrong_path_batch = PrivateResultOramEncryptedBucketBatch {
            index_epoch: 42,
            root_hash,
            bucket_count,
            proof_value: "{}".to_string(),
            buckets: Vec::new(),
        };
        assert_eq!(
            fetch_private_result_oram_tokens_encrypted_verified(
                &keys,
                base_context,
                42,
                &BASE64URL_NOPAD.encode(&[42; 32]),
                bucket_count,
                43,
                &mut state,
                config,
                &[block.payload_fetch_token],
                &wrong_path_plan,
                &[wrong_path_batch],
                || Ok(0),
            ),
            Err(PrivateResultOramError::InvalidFetchPlanField("bucket_ids"))
        );
    }

    #[test]
    fn client_state_snapshot_roundtrips_position_map_and_stash() {
        let config = result_client_config();
        let entry = payload_block(10);
        let stash = payload_block(11);
        let mut state = PrivateResultOramClientState::with_position_map(
            [
                (entry.payload_fetch_token, 0),
                (stash.payload_fetch_token, 1),
            ],
            config.tree_height,
        )
        .unwrap();
        state.stash.insert(stash.payload_fetch_token, stash.clone());
        let debug = format!("{state:?}");
        assert!(!debug.contains("position_map_len: 2"), "{debug}");
        assert!(!debug.contains("stash_len: 1"), "{debug}");
        assert!(!debug.contains(&BASE64URL_NOPAD.encode(&entry.payload_fetch_token)));
        assert!(!debug.contains(&BASE64URL_NOPAD.encode(&stash.payload_fetch_token)));
        assert!(!debug.contains(&serde_json::to_string(&stash.payload).unwrap()));

        let snapshot = state.to_snapshot(config.tree_height).unwrap();
        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.tree_height, config.tree_height);
        assert_eq!(snapshot.positions.len(), 2);
        assert_eq!(snapshot.stash, vec![stash.clone()]);
        let mut malformed_state = state.clone();
        malformed_state
            .stash
            .get_mut(&stash.payload_fetch_token)
            .unwrap()
            .version = 2;
        assert_eq!(
            malformed_state.to_snapshot(config.tree_height),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
        let mut mismatched_stash_key_state = state.clone();
        mismatched_stash_key_state
            .stash
            .get_mut(&stash.payload_fetch_token)
            .unwrap()
            .payload_fetch_token = [99; 32];
        assert_eq!(
            mismatched_stash_key_state.to_snapshot(config.tree_height),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
        let mut duplicate_stash_point_state = state.clone();
        let mut duplicate_stash_point = payload_block(12);
        duplicate_stash_point.point_token = stash.point_token;
        duplicate_stash_point_state
            .position_map
            .insert(duplicate_stash_point.payload_fetch_token, 2);
        duplicate_stash_point_state.stash.insert(
            duplicate_stash_point.payload_fetch_token,
            duplicate_stash_point,
        );
        assert_eq!(
            duplicate_stash_point_state.to_snapshot(config.tree_height),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
        let leaf_label = encode_private_result_oram_leaf_label(1, config.tree_height).unwrap();
        assert_eq!(
            decode_private_result_oram_leaf_label(&leaf_label, config.tree_height).unwrap(),
            1
        );

        let encoded = serde_json::to_string(&snapshot).unwrap();
        let decoded: PrivateResultOramClientStateSnapshot = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            PrivateResultOramClientState::from_snapshot(&decoded).unwrap(),
            state
        );

        let mut bad_version = decoded.clone();
        bad_version.version = 2;
        assert_eq!(
            PrivateResultOramClientState::from_snapshot(&bad_version),
            Err(PrivateResultOramError::UnsupportedClientStateSnapshotVersion(2))
        );

        let mut bad_token = decoded.clone();
        bad_token.positions[0].payload_fetch_token = "not-base64".to_string();
        assert_eq!(
            PrivateResultOramClientState::from_snapshot(&bad_token),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );

        let mut bad_leaf_label = decoded.clone();
        bad_leaf_label.positions[0].leaf_label = "AAAA".to_string();
        assert_eq!(
            PrivateResultOramClientState::from_snapshot(&bad_leaf_label),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );

        let mut duplicate_position = decoded.clone();
        duplicate_position
            .positions
            .push(duplicate_position.positions[0].clone());
        assert_eq!(
            PrivateResultOramClientState::from_snapshot(&duplicate_position),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );

        let mut bad_stash = decoded.clone();
        bad_stash.stash[0].payload_fetch_token = [99; 32];
        assert_eq!(
            PrivateResultOramClientState::from_snapshot(&bad_stash),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
        let mut bad_stash_version = decoded.clone();
        bad_stash_version.stash[0].version = 2;
        assert_eq!(
            PrivateResultOramClientState::from_snapshot(&bad_stash_version),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
        let mut duplicate_point_stash = decoded.clone();
        let mut duplicate_point_block = payload_block(12);
        duplicate_point_block.point_token = duplicate_point_stash.stash[0].point_token;
        duplicate_point_stash
            .positions
            .push(PrivateResultOramPositionMapSnapshotEntry {
                payload_fetch_token: BASE64URL_NOPAD
                    .encode(&duplicate_point_block.payload_fetch_token),
                leaf_label: encode_private_result_oram_leaf_label(2, config.tree_height).unwrap(),
            });
        duplicate_point_stash.stash.push(duplicate_point_block);
        assert_eq!(
            PrivateResultOramClientState::from_snapshot(&duplicate_point_stash),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );

        let mut duplicate_stash = decoded;
        duplicate_stash.stash.push(stash);
        assert_eq!(
            PrivateResultOramClientState::from_snapshot(&duplicate_stash),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
        assert_eq!(
            PrivateResultOramClientState::with_position_map(
                [
                    (entry.payload_fetch_token, 0),
                    (entry.payload_fetch_token, 1),
                ],
                config.tree_height,
            ),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
    }

    #[test]
    fn client_state_snapshot_ciphertext_length_hides_stash_occupancy_and_block_sizes() {
        let keys = result_test_keys();
        let config = result_client_config();
        let root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let context = result_client_state_context(&root_hash);
        let blocks = [payload_block(10), payload_block(11), payload_block(12)];
        let sealed = |stash_count: usize,
                      payload_len: usize,
                      padding: PrivateResultOramClientStateSnapshotPadding| {
            let mut state = PrivateResultOramClientState::with_position_map(
                blocks
                    .iter()
                    .enumerate()
                    .map(|(leaf, block)| (block.payload_fetch_token, leaf as u64))
                    .collect::<Vec<_>>(),
                config.tree_height,
            )
            .unwrap();
            for block in blocks.iter().take(stash_count) {
                let mut block = block.clone();
                block.payload = vec![7; payload_len];
                state.stash.insert(block.payload_fetch_token, block);
            }
            let snapshot = state.to_snapshot(config.tree_height).unwrap();
            let encrypted =
                seal_private_result_oram_client_state_snapshot(&keys, context, &snapshot, padding)?;
            assert_eq!(
                open_private_result_oram_client_state_snapshot(&keys, context, &encrypted).unwrap(),
                snapshot
            );
            Ok::<usize, PrivateResultOramError>(encrypted.ciphertext.len())
        };
        let padding = result_snapshot_padding();

        let empty_stash_len = sealed(0, 0, padding).unwrap();
        assert_eq!(sealed(1, 3, padding).unwrap(), empty_stash_len);
        assert_eq!(sealed(3, 128, padding).unwrap(), empty_stash_len);

        assert_eq!(
            sealed(1, 129, padding),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
        let two_blocks = PrivateResultOramClientStateSnapshotPadding {
            stash_capacity: 2,
            ..padding
        };
        assert_eq!(
            sealed(3, 3, two_blocks),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
        assert_ne!(sealed(2, 3, two_blocks).unwrap(), empty_stash_len);
    }

    #[test]
    fn client_state_snapshot_seal_open_binds_epoch_and_root_context() {
        let keys = result_test_keys();
        let config = result_client_config();
        let entry = payload_block(10);
        let stash = payload_block(11);
        let mut state = PrivateResultOramClientState::with_position_map(
            [
                (entry.payload_fetch_token, 0),
                (stash.payload_fetch_token, 1),
            ],
            config.tree_height,
        )
        .unwrap();
        state.stash.insert(stash.payload_fetch_token, stash);
        let snapshot = state.to_snapshot(config.tree_height).unwrap();
        let root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let context = result_client_state_context(&root_hash);

        let encrypted = seal_private_result_oram_client_state_snapshot(
            &keys,
            context,
            &snapshot,
            result_snapshot_padding(),
        )
        .unwrap();
        assert_eq!(encrypted.version, 1);
        assert_eq!(encrypted.index_epoch, 42);
        assert_eq!(encrypted.root_hash, root_hash);
        assert_eq!(
            open_private_result_oram_client_state_snapshot(&keys, context, &encrypted).unwrap(),
            snapshot
        );

        let mut wrong_epoch = encrypted.clone();
        wrong_epoch.index_epoch = 43;
        assert_eq!(
            open_private_result_oram_client_state_snapshot(&keys, context, &wrong_epoch),
            Err(PrivateResultOramError::ClientStateOpenFailed)
        );

        let wrong_root = BASE64URL_NOPAD.encode(&[43; 32]);
        assert_eq!(
            open_private_result_oram_client_state_snapshot(
                &keys,
                result_client_state_context(&wrong_root),
                &encrypted,
            ),
            Err(PrivateResultOramError::ClientStateOpenFailed)
        );

        for wrong_context in [
            PrivateResultOramClientStateAeadContext {
                collection_id: "collection-uuid-2",
                ..context
            },
            PrivateResultOramClientStateAeadContext {
                key_id: "tenant-a/payload-private-rk-v2",
                ..context
            },
            PrivateResultOramClientStateAeadContext {
                rk_id: "tenant-a/payload-private-rk-v2",
                ..context
            },
            PrivateResultOramClientStateAeadContext {
                rk_epoch: 8,
                ..context
            },
        ] {
            assert_eq!(
                open_private_result_oram_client_state_snapshot(&keys, wrong_context, &encrypted),
                Err(PrivateResultOramError::ClientStateOpenFailed)
            );
        }
        let malformed_context = PrivateResultOramClientStateAeadContext {
            collection_id: "collection\nuuid",
            ..context
        };
        assert_eq!(
            seal_private_result_oram_client_state_snapshot(
                &keys,
                malformed_context,
                &snapshot,
                result_snapshot_padding(),
            ),
            Err(PrivateResultOramError::InvalidClientStateContext(
                "collection_id"
            ))
        );

        let mut tampered_hash = encrypted.clone();
        tampered_hash.ciphertext_sha256 = BASE64URL_NOPAD.encode(&[9; 32]);
        assert_eq!(
            open_private_result_oram_client_state_snapshot(&keys, context, &tampered_hash),
            Err(PrivateResultOramError::InvalidClientStateCiphertextHash)
        );

        let mut malformed_ciphertext = encrypted.clone();
        malformed_ciphertext.ciphertext = "client-state-ciphertext!sentinel".to_string();
        assert_eq!(
            open_private_result_oram_client_state_snapshot(&keys, context, &malformed_ciphertext),
            Err(PrivateResultOramError::InvalidClientStateCiphertextEncoding)
        );

        let mut short_ciphertext = encrypted.clone();
        short_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&[0, 1, 2, 3]);
        short_ciphertext.ciphertext_sha256 = base64url_sha256(&[0, 1, 2, 3]);
        assert_eq!(
            open_private_result_oram_client_state_snapshot(&keys, context, &short_ciphertext),
            Err(PrivateResultOramError::InvalidClientStateCiphertextEncoding)
        );

        let mut malformed_hash = encrypted.clone();
        malformed_hash.ciphertext_sha256 = "AAAA".to_string();
        assert_eq!(
            open_private_result_oram_client_state_snapshot(&keys, context, &malformed_hash),
            Err(PrivateResultOramError::InvalidClientStateCiphertextHash)
        );

        let mut wrong_encoded_version = encrypted.clone();
        let mut raw = BASE64URL_NOPAD
            .decode(wrong_encoded_version.ciphertext.as_bytes())
            .unwrap();
        raw[0..2].copy_from_slice(&2u16.to_be_bytes());
        wrong_encoded_version.ciphertext = BASE64URL_NOPAD.encode(&raw);
        wrong_encoded_version.ciphertext_sha256 = base64url_sha256(&raw);
        assert_eq!(
            open_private_result_oram_client_state_snapshot(&keys, context, &wrong_encoded_version),
            Err(PrivateResultOramError::UnsupportedClientStateCiphertextVersion(2))
        );

        let mut tampered_ciphertext = encrypted.clone();
        let mut raw = BASE64URL_NOPAD
            .decode(tampered_ciphertext.ciphertext.as_bytes())
            .unwrap();
        let last = raw.last_mut().unwrap();
        *last ^= 0x80;
        tampered_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&raw);
        tampered_ciphertext.ciphertext_sha256 = base64url_sha256(&raw);
        assert_eq!(
            open_private_result_oram_client_state_snapshot(&keys, context, &tampered_ciphertext),
            Err(PrivateResultOramError::ClientStateOpenFailed)
        );

        let mut malformed_snapshot = snapshot;
        malformed_snapshot.stash.push(payload_block(99));
        assert_eq!(
            seal_private_result_oram_client_state_snapshot(
                &keys,
                context,
                &malformed_snapshot,
                result_snapshot_padding(),
            ),
            Err(PrivateResultOramError::InvalidClientStateSnapshot)
        );
    }

    #[test]
    fn client_state_snapshot_ciphertext_does_not_expose_position_map_or_stash() {
        fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
            !needle.is_empty()
                && haystack
                    .windows(needle.len())
                    .any(|window| window == needle)
        }

        let keys = result_test_keys();
        let config = result_client_config();
        let mut stash = payload_block(11);
        stash.payload_fetch_token = [44; 32];
        stash.point_token = [55; 32];
        stash.payload = b"RESULT-ORAM-STASH-PAYLOAD-RAW-V1!".to_vec();
        let mut state = PrivateResultOramClientState::with_position_map(
            [(stash.payload_fetch_token, 1)],
            config.tree_height,
        )
        .unwrap();
        state.stash.insert(stash.payload_fetch_token, stash.clone());
        let snapshot = state.to_snapshot(config.tree_height).unwrap();
        let plaintext_json = serde_json::to_string(&snapshot).unwrap();
        let root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let context = result_client_state_context(&root_hash);

        assert!(plaintext_json.contains("positions"));
        assert!(plaintext_json.contains("stash"));
        assert!(plaintext_json.contains("payload_fetch_token"));
        let sensitive_stash_values = [
            serde_json::to_string(&stash.payload_fetch_token).unwrap(),
            serde_json::to_string(&stash.point_token).unwrap(),
            serde_json::to_string(&stash.payload).unwrap(),
        ];
        for sensitive_value in &sensitive_stash_values {
            assert!(plaintext_json.contains(sensitive_value));
        }
        for position in &snapshot.positions {
            assert!(plaintext_json.contains(&position.payload_fetch_token));
            assert!(plaintext_json.contains(&position.leaf_label));
        }

        let encrypted = seal_private_result_oram_client_state_snapshot(
            &keys,
            context,
            &snapshot,
            result_snapshot_padding(),
        )
        .unwrap();
        let encrypted_json = serde_json::to_string(&encrypted).unwrap();
        let raw_ciphertext = BASE64URL_NOPAD
            .decode(encrypted.ciphertext.as_bytes())
            .unwrap();

        for plaintext_marker in [
            "positions",
            "stash",
            "payload_fetch_token",
            "leaf_label",
            "point_token",
            "payload",
        ] {
            assert!(!encrypted_json.contains(plaintext_marker));
            assert!(!contains_bytes(
                &raw_ciphertext,
                plaintext_marker.as_bytes()
            ));
        }
        for position in &snapshot.positions {
            assert!(!encrypted_json.contains(&position.payload_fetch_token));
            assert!(!encrypted_json.contains(&position.leaf_label));
            assert!(!contains_bytes(
                &raw_ciphertext,
                position.payload_fetch_token.as_bytes()
            ));
            assert!(!contains_bytes(
                &raw_ciphertext,
                position.leaf_label.as_bytes()
            ));
        }
        for sensitive_value in &sensitive_stash_values {
            assert!(!encrypted_json.contains(sensitive_value));
            assert!(!contains_bytes(&raw_ciphertext, sensitive_value.as_bytes()));
        }
        assert!(!contains_bytes(&raw_ciphertext, &stash.payload_fetch_token));
        assert!(!contains_bytes(&raw_ciphertext, &stash.point_token));
        assert!(!contains_bytes(&raw_ciphertext, &stash.payload));
    }

    #[test]
    fn bucket_plaintext_codec_rejects_slot_count_and_context_mismatch() {
        let config = result_client_config();
        let bucket = PrivateResultOramPlaintextBucket {
            bucket_id: 3,
            blocks: vec![Some(payload_block(8))],
        };
        assert_eq!(
            encode_private_result_oram_bucket_plaintext(&bucket, config),
            Err(PrivateResultOramError::BucketPlaintextSlotCountMismatch)
        );

        let bucket = PrivateResultOramPlaintextBucket {
            bucket_id: 3,
            blocks: vec![Some(payload_block(8)), None],
        };
        let encoded = encode_private_result_oram_bucket_plaintext(&bucket, config).unwrap();
        assert_eq!(
            decode_private_result_oram_bucket_plaintext(4, &encoded, config),
            Err(PrivateResultOramError::InvalidBucketPlaintext)
        );
    }

    #[test]
    fn fetch_token_read_plan_batches_oram_bucket_ids() {
        let manifest = small_fetch_manifest();
        assert_eq!(private_result_oram_leaf_count(3).unwrap(), 8);
        assert_eq!(private_result_oram_bucket_count(3).unwrap(), 15);
        assert_eq!(
            private_result_oram_leaf_count(0),
            Err(PrivateResultOramError::InvalidFetchPlanField("tree_height"))
        );
        assert_eq!(
            private_result_oram_bucket_count(0),
            Err(PrivateResultOramError::InvalidFetchPlanField("tree_height"))
        );
        assert_eq!(
            private_result_oram_bucket_ids_for_leaf(5, 3).unwrap(),
            vec![0, 2, 5, 12]
        );

        let positions = vec![
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [1; 32],
                leaf: 5,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [2; 32],
                leaf: 6,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [3; 32],
                leaf: 1,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [4; 32],
                leaf: 0,
            },
        ];
        let plan = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
            &manifest,
            &[[1; 32], [2; 32], [3; 32], [4; 32]],
            &positions,
            padding_from(0, 3),
        )
        .unwrap();

        assert_eq!(plan.token_count, 4);
        assert_eq!(plan.path_batch_size, 2);
        assert_eq!(plan.batches.len(), 2);
        assert_eq!(plan.batches[0].token_count, 2);
        assert_eq!(plan.batches[0].bucket_ids, vec![0, 2, 5, 12, 0, 2, 6, 13]);
        assert_eq!(plan.batches[1].token_count, 2);
        assert_eq!(plan.batches[1].bucket_ids, vec![0, 1, 3, 7, 0, 1, 3, 8]);
    }

    #[test]
    fn ordered_fetch_token_read_plan_distributes_leaf_collisions() {
        let manifest = small_fetch_manifest();
        let positions = vec![
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [1; 32],
                leaf: 5,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [2; 32],
                leaf: 5,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [3; 32],
                leaf: 6,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [4; 32],
                leaf: 7,
            },
        ];

        let padded = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
            &manifest,
            &[[1; 32], [2; 32], [3; 32], [4; 32]],
            &positions,
            padding_from(0, 3),
        )
        .unwrap();
        assert_eq!(padded.batches[0].padding_leaves, vec![0]);
        assert!(padded.batches[1].padding_leaves.is_empty());

        let ordered = plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens(
            &manifest,
            &[[1; 32], [2; 32], [3; 32], [4; 32]],
            &positions,
            padding_from(0, 3),
        )
        .unwrap();

        assert_eq!(
            ordered.payload_fetch_tokens,
            vec![[1; 32], [3; 32], [2; 32], [4; 32]]
        );
        assert_eq!(ordered.read_plan.token_count, 4);
        assert_eq!(ordered.read_plan.path_batch_size, 2);
        assert_eq!(ordered.read_plan.batches.len(), 2);
        assert_eq!(
            ordered.read_plan.batches[0].bucket_ids,
            vec![0, 2, 5, 12, 0, 2, 6, 13]
        );
        assert_eq!(
            ordered.read_plan.batches[1].bucket_ids,
            vec![0, 2, 5, 12, 0, 2, 6, 14]
        );

        let impossible_positions = vec![
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [1; 32],
                leaf: 5,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [2; 32],
                leaf: 5,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [3; 32],
                leaf: 5,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [4; 32],
                leaf: 6,
            },
        ];
        // Three tokens on one leaf cannot be spread over two batches; the leftover collision is
        // padded instead of failing the fetch (which would itself be query-dependent).
        let padded = plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens(
            &manifest,
            &[[1; 32], [2; 32], [3; 32], [4; 32]],
            &impossible_positions,
            padding_from(0, 3),
        )
        .unwrap();
        assert_eq!(padded.read_plan.batches.len(), 2);
        assert_eq!(
            padded
                .read_plan
                .batches
                .iter()
                .map(|batch| batch.padding_leaves.len())
                .sum::<usize>(),
            1
        );
        for batch in &padded.read_plan.batches {
            assert_eq!(batch.bucket_ids.len(), 8);
        }
    }

    #[test]
    fn ordered_fetch_token_read_plan_schedules_all_small_feasible_leaf_distributions() {
        fn enumerate_counts(
            leaf_index: usize,
            leaf_count: usize,
            remaining: usize,
            max_per_leaf: usize,
            counts: &mut Vec<usize>,
            cases: &mut Vec<Vec<usize>>,
        ) {
            if leaf_index == leaf_count {
                if remaining == 0 {
                    cases.push(counts.clone());
                }
                return;
            }

            for count in 0..=remaining.min(max_per_leaf) {
                counts.push(count);
                enumerate_counts(
                    leaf_index + 1,
                    leaf_count,
                    remaining - count,
                    max_per_leaf,
                    counts,
                    cases,
                );
                counts.pop();
            }
        }

        let mut manifest = small_fetch_manifest();
        manifest.oram.path_batch_size = 3;
        let path_batch_size = usize::try_from(manifest.oram.path_batch_size).unwrap();
        let batch_count = 3;
        let token_count = path_batch_size * batch_count;
        let leaf_count =
            usize::try_from(private_result_oram_leaf_count(manifest.oram.tree_height).unwrap())
                .unwrap();
        let mut cases = Vec::new();
        enumerate_counts(
            0,
            leaf_count,
            token_count,
            batch_count,
            &mut Vec::new(),
            &mut cases,
        );
        assert_eq!(cases.len(), 5328);

        for counts in cases {
            let mut payload_fetch_tokens = Vec::with_capacity(token_count);
            let mut token_positions = Vec::with_capacity(token_count);
            let mut token_to_leaf = BTreeMap::new();
            let mut token_byte = 1u8;
            for (leaf, count) in counts.iter().copied().enumerate() {
                for _ in 0..count {
                    let token = [token_byte; 32];
                    token_byte = token_byte
                        .checked_add(1)
                        .expect("test fixture should use fewer than 255 tokens");
                    payload_fetch_tokens.push(token);
                    token_positions.push(PrivateResultOramFetchTokenPosition {
                        payload_fetch_token: token,
                        leaf: u64::try_from(leaf).unwrap(),
                    });
                    token_to_leaf.insert(token, leaf);
                }
            }

            let ordered = plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens(
                &manifest,
                &payload_fetch_tokens,
                &token_positions,
                padding_from(0, 3),
            )
            .unwrap_or_else(|err| panic!("failed to schedule counts {counts:?}: {err:?}"));
            assert_eq!(ordered.payload_fetch_tokens.len(), token_count);
            assert_eq!(ordered.read_plan.batches.len(), batch_count);
            assert_eq!(ordered.read_plan.path_batch_size, path_batch_size);

            for (token_batch, read_batch) in ordered
                .payload_fetch_tokens
                .chunks(path_batch_size)
                .zip(&ordered.read_plan.batches)
            {
                let mut batch_leaves = BTreeSet::new();
                for token in token_batch {
                    let leaf = token_to_leaf
                        .get(token)
                        .copied()
                        .expect("ordered token must come from input plan");
                    assert!(
                        batch_leaves.insert(leaf),
                        "batch repeated leaf {leaf} for counts {counts:?}"
                    );
                }
                assert_eq!(batch_leaves.len(), path_batch_size);
                assert_eq!(read_batch.token_count, path_batch_size);
                assert_eq!(
                    read_batch.bucket_ids.len(),
                    path_batch_size * (usize::try_from(manifest.oram.tree_height).unwrap() + 1)
                );
            }
        }
    }

    #[test]
    fn fetch_token_read_plan_rejects_missing_duplicate_and_bad_leaf() {
        let manifest = small_fetch_manifest();
        let position = PrivateResultOramFetchTokenPosition {
            payload_fetch_token: [1; 32],
            leaf: 5,
        };
        assert_eq!(
            plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
                &manifest,
                &[],
                std::slice::from_ref(&position),
                padding_from(0, 3),
            ),
            Err(PrivateResultOramError::InvalidFetchPlanField(
                "payload_fetch_tokens"
            ))
        );
        assert_eq!(
            plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
                &manifest,
                &[[9; 32], [1; 32]],
                std::slice::from_ref(&position),
                padding_from(0, 3),
            ),
            Err(PrivateResultOramError::MissingPayloadFetchTokenPosition)
        );
        assert_eq!(
            plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
                &manifest,
                &[[1; 32], [1; 32]],
                std::slice::from_ref(&position),
                padding_from(0, 3),
            ),
            Err(PrivateResultOramError::DuplicatePayloadFetchToken)
        );

        let duplicate_positions = vec![
            position.clone(),
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [1; 32],
                leaf: 6,
            },
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [2; 32],
                leaf: 6,
            },
        ];
        assert_eq!(
            plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
                &manifest,
                &[[1; 32], [2; 32]],
                &duplicate_positions,
                padding_from(0, 3),
            ),
            Err(PrivateResultOramError::DuplicatePayloadFetchTokenPosition)
        );

        let duplicate_leaf_positions = vec![
            position.clone(),
            PrivateResultOramFetchTokenPosition {
                payload_fetch_token: [2; 32],
                leaf: 5,
            },
        ];
        // Two tokens on one leaf read that path once and pad the batch with a dummy path, so
        // the server still sees exactly `path_batch_size` distinct paths.
        let padded = plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
            &manifest,
            &[[1; 32], [2; 32]],
            &duplicate_leaf_positions,
            padding_from(0, 3),
        )
        .unwrap();
        assert_eq!(padded.batches.len(), 1);
        assert_eq!(padded.batches[0].token_count, 2);
        assert_eq!(padded.batches[0].padding_leaves, vec![0]);
        assert_eq!(padded.batches[0].bucket_ids, vec![0, 1, 3, 7, 0, 2, 5, 12]);
        // A padding source that only ever returns colliding leaves is rejected.
        assert_eq!(
            plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
                &manifest,
                &[[1; 32], [2; 32]],
                &duplicate_leaf_positions,
                || Ok(5),
            ),
            Err(PrivateResultOramError::InvalidFetchPlanField(
                "padding_leaves"
            ))
        );

        let bad_leaf = PrivateResultOramFetchTokenPosition {
            payload_fetch_token: [1; 32],
            leaf: 8,
        };
        assert_eq!(
            plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
                &manifest,
                &[[1; 32], [2; 32]],
                &[bad_leaf],
                padding_from(0, 3),
            ),
            Err(PrivateResultOramError::InvalidFetchPlanField("leaf"))
        );
        assert_eq!(
            plan_private_result_oram_read_bucket_batches_for_fetch_tokens(
                &manifest,
                &[[1; 32], [2; 32], [3; 32]],
                &[
                    position.clone(),
                    PrivateResultOramFetchTokenPosition {
                        payload_fetch_token: [2; 32],
                        leaf: 6,
                    },
                    PrivateResultOramFetchTokenPosition {
                        payload_fetch_token: [3; 32],
                        leaf: 1,
                    },
                ],
                padding_from(0, 3),
            ),
            Err(PrivateResultOramError::InvalidFetchPlanField(
                "payload_fetch_tokens"
            ))
        );
    }

    #[test]
    fn manifest_signature_message_is_stable() {
        let digest = Sha256::digest(checked_manifest_signature_message(&fixture_manifest()));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "mOy8vej616osyutILgm6MwoTDwZhq7tau_9wyHgaYGA"
        );
    }

    #[test]
    fn commit_signature_message_is_stable() {
        let buckets = [
            PrivateResultOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateResultOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let input = PrivateResultOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };

        let digest = Sha256::digest(checked_commit_signature_message(input));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "Dsso6H8kYZbPZHYG49vdmgVaLa02M2fP47VCQH4wPtM"
        );
        assert_eq!(
            private_result_oram_writeback_digest(input).unwrap(),
            "Dsso6H8kYZbPZHYG49vdmgVaLa02M2fP47VCQH4wPtM"
        );
    }

    #[test]
    fn read_buckets_signature_message_is_stable() {
        let bucket_ids = [0, 1, 3, 0, 1, 4];
        let input = PrivateResultOramReadBucketsSignatureInput {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: 7,
            bucket_ids: &bucket_ids,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };

        let digest = Sha256::digest(checked_read_buckets_signature_message(input));
        assert_eq!(
            BASE64URL_NOPAD.encode(digest.as_ref()),
            "lgqPWza4bMJhkNB3N3ceznqz8moFXvgbm-Ov3i6TkYQ"
        );
    }

    #[test]
    fn signature_known_answer_vectors_are_stable() {
        let key_pair = deterministic_key_pair();
        assert_eq!(
            sign_b64(
                &key_pair,
                &checked_manifest_signature_message(&fixture_manifest())
            ),
            "GKetv5HZkKN_7nAWL13DeBewxPe58jh9FOqAU0zawMUpY2QtJQ7HEVdBAm93jK3VzacU1EHFJ2msAzZMlBaDDQ"
        );

        let buckets = [
            PrivateResultOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateResultOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let commit_input = PrivateResultOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };
        assert_eq!(
            sign_b64(&key_pair, &checked_commit_signature_message(commit_input)),
            "6obLb5HsEc1T-PpKlm3_yQJATe-dKP7I-wQ0UcaVBTuJz_IPbWyy6VoLeZ87pbZRUonloDrDsIByfFj8YD7fBQ"
        );

        let bucket_ids = [0, 1, 3, 0, 1, 4];
        let read_input = PrivateResultOramReadBucketsSignatureInput {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: 7,
            bucket_ids: &bucket_ids,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };
        assert_eq!(
            sign_b64(
                &key_pair,
                &checked_read_buckets_signature_message(read_input)
            ),
            "ddffysc8cqOCF7Lp2gVTLIBrVPlEy9xBK1vCOby4mUNoONW5Roa7fgJ_rm8es8XvAYRP224MCZLvWBZlkNQXAA"
        );
    }

    fn assert_signature_fixture(
        fixture: &serde_json::Value,
        case_name: &str,
        expected_domain: &str,
        message: &[u8],
        signature: &str,
    ) {
        let case = fixture["cases"]
            .as_array()
            .and_then(|cases| {
                cases
                    .iter()
                    .find(|case| case["name"].as_str() == Some(case_name))
            })
            .unwrap_or_else(|| panic!("test vector case {case_name} must exist"));
        let get = |key: &str| {
            case[key]
                .as_str()
                .unwrap_or_else(|| panic!("test vector case {case_name} must define {key}"))
        };

        assert_eq!(get("domain"), expected_domain);
        assert_eq!(get("signature_alg"), "ed25519");
        assert_eq!(
            message.len() as u64,
            case["signature_message_len"]
                .as_u64()
                .unwrap_or_else(|| panic!("test vector case {case_name} must define message len"))
        );
        assert_eq!(
            BASE64URL_NOPAD.encode(message),
            get("signature_message_b64")
        );
        assert_eq!(
            BASE64URL_NOPAD.encode(Sha256::digest(message).as_ref()),
            get("signature_message_sha256_b64")
        );
        assert_eq!(signature, get("signature_b64"));
    }

    #[test]
    fn signature_messages_match_sdk_test_vector() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/qdrant-sec-private-result-oram-signature-test-vector.json"
        ))
        .expect("private result ORAM signature test vector must be valid JSON");
        assert_eq!(
            fixture["provider"].as_str(),
            Some(PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER)
        );
        assert_eq!(
            fixture["binding"].as_str(),
            Some(PRIVATE_RESULT_ORAM_BINDING)
        );
        assert_eq!(
            fixture["deterministic_seed_hex"].as_str(),
            Some("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        );

        let key_pair = deterministic_key_pair();
        let manifest_message = checked_manifest_signature_message(&fixture_manifest());
        let manifest_signature = sign_b64(&key_pair, &manifest_message);
        assert_signature_fixture(
            &fixture,
            "manifest",
            PRIVATE_RESULT_ORAM_MANIFEST_SIGNATURE_DOMAIN,
            &manifest_message,
            &manifest_signature,
        );

        let buckets = [
            PrivateResultOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateResultOramCommitBucketRef {
                bucket_id: 27,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[27; 32]),
            },
        ];
        let commit_input = PrivateResultOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };
        let commit_message = checked_commit_signature_message(commit_input);
        let commit_signature = sign_b64(&key_pair, &commit_message);
        assert_signature_fixture(
            &fixture,
            "commit",
            PRIVATE_RESULT_ORAM_COMMIT_SIGNATURE_DOMAIN,
            &commit_message,
            &commit_signature,
        );

        let bucket_ids = [0, 1, 3, 0, 1, 4];
        let read_input = PrivateResultOramReadBucketsSignatureInput {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: 7,
            bucket_ids: &bucket_ids,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };
        let read_message = checked_read_buckets_signature_message(read_input);
        let read_signature = sign_b64(&key_pair, &read_message);
        assert_signature_fixture(
            &fixture,
            "read_buckets",
            PRIVATE_RESULT_ORAM_READ_BUCKETS_SIGNATURE_DOMAIN,
            &read_message,
            &read_signature,
        );
    }

    #[test]
    fn signature_message_builders_reject_invalid_context() {
        let mut manifest = fixture_manifest();
        manifest.collection_id = "collection id sentinel".to_string();
        assert_eq!(
            try_private_result_oram_manifest_signature_message(&manifest),
            Err(PrivateResultOramError::InvalidManifestField(
                "collection_id"
            ))
        );

        let buckets = [PrivateResultOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
        }];
        let commit_input = PrivateResultOramCommitSignatureInput {
            collection_id: "collection id sentinel",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };
        assert_eq!(
            try_private_result_oram_commit_signature_message(commit_input),
            Err(PrivateResultOramError::InvalidManifestField(
                "collection_id"
            ))
        );

        let bucket_ids = [0];
        let read_input = PrivateResultOramReadBucketsSignatureInput {
            collection_id: "collection id sentinel",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            index_epoch: 42,
            root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: 7,
            bucket_ids: &bucket_ids,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };
        assert_eq!(
            try_private_result_oram_read_buckets_signature_message(read_input),
            Err(PrivateResultOramError::InvalidManifestField(
                "collection_id"
            ))
        );

        let valid_commit_input = PrivateResultOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            ..commit_input
        };
        let unsupported_commit_alg = PrivateResultOramCommitSignatureInput {
            signature_alg: "rsa-pss-sentinel",
            ..valid_commit_input
        };
        assert_eq!(
            try_private_result_oram_commit_signature_message(unsupported_commit_alg),
            Err(PrivateResultOramError::UnsupportedSignatureAlgorithm(
                "rsa-pss-sentinel".to_string()
            ))
        );
        let malformed_commit_key = PrivateResultOramCommitSignatureInput {
            signature_key_id: "bad key id",
            ..valid_commit_input
        };
        assert_eq!(
            try_private_result_oram_commit_signature_message(malformed_commit_key),
            Err(PrivateResultOramError::InvalidResourceKeyId)
        );
        for malformed_commit_context in [
            PrivateResultOramCommitSignatureInput {
                key_id: "tenant-a/payload private-rk",
                ..valid_commit_input
            },
            PrivateResultOramCommitSignatureInput {
                rk_id: "tenant-a/payload private-rk",
                ..valid_commit_input
            },
        ] {
            assert_eq!(
                try_private_result_oram_commit_signature_message(malformed_commit_context),
                Err(PrivateResultOramError::InvalidResourceKeyId)
            );
        }

        let valid_read_bucket_ids = [0, 1, 3];
        let valid_read_input = PrivateResultOramReadBucketsSignatureInput {
            collection_id: "collection-uuid-1",
            bucket_ids: &valid_read_bucket_ids,
            ..read_input
        };
        let unsupported_read_alg = PrivateResultOramReadBucketsSignatureInput {
            signature_alg: "rsa-pss-sentinel",
            ..valid_read_input
        };
        assert_eq!(
            try_private_result_oram_read_buckets_signature_message(unsupported_read_alg),
            Err(PrivateResultOramError::UnsupportedSignatureAlgorithm(
                "rsa-pss-sentinel".to_string()
            ))
        );
        let malformed_read_key = PrivateResultOramReadBucketsSignatureInput {
            signature_key_id: "bad key id",
            ..valid_read_input
        };
        assert_eq!(
            try_private_result_oram_read_buckets_signature_message(malformed_read_key),
            Err(PrivateResultOramError::InvalidResourceKeyId)
        );
        for malformed_read_context in [
            PrivateResultOramReadBucketsSignatureInput {
                key_id: "tenant-a/payload private-rk",
                ..valid_read_input
            },
            PrivateResultOramReadBucketsSignatureInput {
                rk_id: "tenant-a/payload private-rk",
                ..valid_read_input
            },
        ] {
            assert_eq!(
                try_private_result_oram_read_buckets_signature_message(malformed_read_context),
                Err(PrivateResultOramError::InvalidResourceKeyId)
            );
        }
    }

    #[test]
    fn manifest_shape_rejects_wrong_provider_and_root() {
        let mut manifest = fixture_manifest();
        validate_private_result_oram_manifest_shape(&manifest).unwrap();

        manifest.provider = "payload/client-aead@v1".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_shape(&manifest),
            Err(PrivateResultOramError::InvalidProvider)
        );

        for malformed_manifest in [
            PrivateResultOramManifest {
                collection_id: "collection\nuuid".to_string(),
                ..fixture_manifest()
            },
            PrivateResultOramManifest {
                key_id: "tenant-a/payload\nprivate-rk".to_string(),
                ..fixture_manifest()
            },
            PrivateResultOramManifest {
                rk_id: "tenant-a/payload\nprivate-rk".to_string(),
                ..fixture_manifest()
            },
            PrivateResultOramManifest {
                owner_signing_key_id: "tenant-a/private\nresult-signing-v1".to_string(),
                ..fixture_manifest()
            },
        ] {
            let expected = if malformed_manifest.collection_id.contains('\n') {
                PrivateResultOramError::InvalidManifestField("collection_id")
            } else {
                PrivateResultOramError::InvalidResourceKeyId
            };
            assert_eq!(
                validate_private_result_oram_manifest_shape(&malformed_manifest),
                Err(expected)
            );
        }

        manifest = fixture_manifest();
        manifest.root_hash = "not-base64url".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_shape(&manifest),
            Err(PrivateResultOramError::InvalidManifestField("root_hash"))
        );

        manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.bucket_count = 3;
        manifest.oram.bucket_size = 1;
        manifest.oram.path_batch_size = 2;
        manifest.logical_result_count = 4;
        manifest.dummy_result_count = 0;
        assert_eq!(
            validate_private_result_oram_manifest_shape(&manifest),
            Err(PrivateResultOramError::InvalidManifestField("result_count"))
        );

        manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.bucket_count = 3;
        manifest.oram.path_batch_size = 3;
        manifest.logical_result_count = 1;
        manifest.dummy_result_count = 0;
        assert_eq!(
            validate_private_result_oram_manifest_shape(&manifest),
            Err(PrivateResultOramError::InvalidManifestField(
                "oram.path_batch_size"
            ))
        );

        manifest = fixture_manifest();
        manifest.bucket_count -= 1;
        assert_eq!(
            validate_private_result_oram_manifest_shape(&manifest),
            Err(PrivateResultOramError::InvalidManifestField("bucket_count"))
        );
    }

    #[test]
    fn signature_shape_rejects_wrong_alg_and_malformed_signature() {
        let mut signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-result-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[9; 64]),
        };
        validate_private_result_oram_manifest_signature_shape(&signature).unwrap();

        signature.alg = "rsa-pss".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_signature_shape(&signature),
            Err(PrivateResultOramError::UnsupportedSignatureAlgorithm(
                "rsa-pss".to_string()
            ))
        );

        signature.alg = "ed25519".to_string();
        signature.sig = "short".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_signature_shape(&signature),
            Err(PrivateResultOramError::MalformedSignature)
        );

        signature.sig = BASE64URL_NOPAD.encode(&[9; 64]);
        signature.key_id = "tenant-a/private\nresult-signing-v1".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_signature_shape(&signature),
            Err(PrivateResultOramError::InvalidResourceKeyId)
        );
    }

    #[test]
    fn bucket_shape_validates_hash_range_and_size() {
        let bucket = fixture_bucket();
        validate_private_result_oram_bucket_shape(&bucket, bucket_validation_context()).unwrap();

        let mut out_of_range = bucket.clone();
        out_of_range.bucket_id = 16;
        assert_eq!(
            validate_private_result_oram_bucket_shape(&out_of_range, bucket_validation_context()),
            Err(PrivateResultOramError::BucketOutOfRange {
                bucket_id: 16,
                bucket_count: 16,
            })
        );

        let mut hash_mismatch = bucket.clone();
        hash_mismatch.ciphertext_sha256 = BASE64URL_NOPAD.encode(&[5; 32]);
        assert_eq!(
            validate_private_result_oram_bucket_shape(&hash_mismatch, bucket_validation_context()),
            Err(PrivateResultOramError::InvalidBucketHash)
        );

        let mut oversized = bucket;
        oversized.ciphertext = BASE64URL_NOPAD.encode(&[7; 129]);
        oversized.ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest([7; 129]).as_ref());
        assert_eq!(
            validate_private_result_oram_bucket_shape(&oversized, bucket_validation_context()),
            Err(PrivateResultOramError::BucketOversized)
        );

        let mut encoded_oversized = fixture_bucket();
        encoded_oversized.ciphertext =
            "A".repeat(max_base64url_nopad_encoded_len(128).unwrap() + 1);
        encoded_oversized.ciphertext_sha256 = BASE64URL_NOPAD.encode(&[9; 32]);
        assert_eq!(
            validate_private_result_oram_bucket_shape(
                &encoded_oversized,
                bucket_validation_context()
            ),
            Err(PrivateResultOramError::BucketOversized)
        );
    }

    #[test]
    fn max_base64url_nopad_encoded_len_handles_tail_lengths_and_overflow() {
        assert_eq!(max_base64url_nopad_encoded_len(0), Some(0));
        assert_eq!(max_base64url_nopad_encoded_len(1), Some(2));
        assert_eq!(max_base64url_nopad_encoded_len(2), Some(3));
        assert_eq!(max_base64url_nopad_encoded_len(3), Some(4));
        assert_eq!(max_base64url_nopad_encoded_len(4), Some(6));
        assert_eq!(max_base64url_nopad_encoded_len(usize::MAX), None);
    }

    #[test]
    fn merkle_root_for_commitments_is_stable_and_rejects_bad_leaves() {
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&[
                commitment(1),
                commitment(2),
                commitment(3),
            ])
            .unwrap(),
            "WaBpZZL4P-1d3PL6tJFGletAnWPATB_KlpiiL9p5U5E"
        );
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&[]),
            Err(PrivateResultOramError::EmptyMerkleTree)
        );
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&["bad".to_string()]),
            Err(PrivateResultOramError::InvalidBucketField(
                "bucket_commitment"
            ))
        );
    }

    #[test]
    fn merkle_proof_verifies_bucket_commitments_and_json() {
        let bucket0 = fixture_commit_bucket(0, 42, 1);
        let bucket1 = fixture_commit_bucket(1, 42, 2);
        let root = private_result_oram_merkle_root_for_commitments(&[
            bucket0.bucket_commitment.clone(),
            bucket1.bucket_commitment.clone(),
        ])
        .unwrap();
        let proof = PrivateResultOramMerkleProof {
            kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: root.clone(),
            bucket_count: 2,
            leaves: vec![
                PrivateResultOramMerkleProofLeaf {
                    bucket_id: 0,
                    leaf_hash: bucket0.bucket_commitment.clone(),
                    siblings: vec![PrivateResultOramMerkleSibling {
                        level: 0,
                        position: PrivateResultOramMerkleSiblingPosition::Right,
                        hash: bucket1.bucket_commitment.clone(),
                    }],
                },
                PrivateResultOramMerkleProofLeaf {
                    bucket_id: 1,
                    leaf_hash: bucket1.bucket_commitment.clone(),
                    siblings: vec![PrivateResultOramMerkleSibling {
                        level: 0,
                        position: PrivateResultOramMerkleSiblingPosition::Left,
                        hash: bucket0.bucket_commitment.clone(),
                    }],
                },
            ],
        };

        let empty_proof = PrivateResultOramMerkleProof {
            leaves: Vec::new(),
            ..proof.clone()
        };
        assert_eq!(
            verify_private_result_oram_merkle_proof(&empty_proof, 42, &root, 2, &[]),
            Err(PrivateResultOramError::InvalidMerkleProof)
        );

        verify_private_result_oram_merkle_proof(
            &proof,
            42,
            &root,
            2,
            &[bucket0.clone(), bucket1.clone()],
        )
        .unwrap();
        verify_private_result_oram_merkle_proof_json(
            &serde_json::to_string(&proof).unwrap(),
            42,
            &root,
            2,
            &[bucket0.clone(), bucket1.clone()],
        )
        .unwrap();

        let mut hash_mismatch_bucket = bucket0.clone();
        hash_mismatch_bucket.ciphertext_sha256 = commitment(8);
        assert_eq!(
            verify_private_result_oram_merkle_proof(
                &proof,
                42,
                &root,
                2,
                &[hash_mismatch_bucket, bucket1.clone()],
            ),
            Err(PrivateResultOramError::InvalidBucketCiphertextHash)
        );

        let mut future_epoch_bucket = bucket0.clone();
        future_epoch_bucket.index_epoch = 43;
        assert_eq!(
            verify_private_result_oram_merkle_proof(
                &proof,
                42,
                &root,
                2,
                &[future_epoch_bucket, bucket1.clone()],
            ),
            Err(PrivateResultOramError::InvalidMerkleProof)
        );

        let duplicate_proof = PrivateResultOramMerkleProof {
            leaves: vec![proof.leaves[0].clone(), proof.leaves[0].clone()],
            ..proof.clone()
        };
        verify_private_result_oram_merkle_proof(
            &duplicate_proof,
            42,
            &root,
            2,
            &[bucket0.clone(), bucket0.clone()],
        )
        .unwrap();
        verify_private_result_oram_merkle_proof_json(
            &serde_json::to_string(&duplicate_proof).unwrap(),
            42,
            &root,
            2,
            &[bucket0.clone(), bucket0.clone()],
        )
        .unwrap();

        let mut conflicting_duplicate_bucket = bucket0.clone();
        let conflicting_raw = b"conflicting duplicate bucket";
        conflicting_duplicate_bucket.ciphertext = BASE64URL_NOPAD.encode(conflicting_raw);
        conflicting_duplicate_bucket.ciphertext_sha256 = base64url_sha256(conflicting_raw);
        assert_eq!(
            verify_private_result_oram_merkle_proof(
                &duplicate_proof,
                42,
                &root,
                2,
                &[bucket0.clone(), conflicting_duplicate_bucket],
            ),
            Err(PrivateResultOramError::InvalidMerkleProof)
        );

        let mut conflicting_duplicate_proof = duplicate_proof.clone();
        conflicting_duplicate_proof.leaves[1].leaf_hash = bucket1.bucket_commitment.clone();
        assert_eq!(
            verify_private_result_oram_merkle_proof(
                &conflicting_duplicate_proof,
                42,
                &root,
                2,
                &[bucket0.clone(), bucket0.clone()],
            ),
            Err(PrivateResultOramError::InvalidMerkleProof)
        );

        let mut tampered = proof.clone();
        tampered.leaves[0].leaf_hash = bucket1.bucket_commitment.clone();
        assert_eq!(
            verify_private_result_oram_merkle_proof(&tampered, 42, &root, 2, &[bucket0, bucket1]),
            Err(PrivateResultOramError::MerkleProofMismatch)
        );
        assert_eq!(
            verify_private_result_oram_merkle_proof_json("not-json", 42, &root, 2, &[]),
            Err(PrivateResultOramError::InvalidMerkleProofJson)
        );
        let oversized_proof_json = " ".repeat(PRIVATE_RESULT_ORAM_MERKLE_PROOF_JSON_MAX_BYTES + 1);
        assert_eq!(
            verify_private_result_oram_merkle_proof_json(&oversized_proof_json, 42, &root, 2, &[]),
            Err(PrivateResultOramError::InvalidMerkleProofJson)
        );
    }

    #[test]
    fn commit_plan_updates_merkle_root_and_signature_refs() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9);

        let plan = plan_private_result_oram_commit(
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
            vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }]
        );
        assert_eq!(
            plan.signature_bucket_refs(),
            vec![PrivateResultOramCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.as_str(),
            }]
        );
    }

    #[test]
    fn commit_plan_for_manifest_rejects_bucket_commitment_context_mismatch() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3)];
        let old_root = private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.oram.path_batch_size = 2;
        manifest.bucket_count = leaf_commitments.len() as u64;
        manifest.logical_result_count = 2;
        manifest.dummy_result_count = 0;
        manifest.root_hash = old_root.clone();
        let updated_bucket = fixture_upload_bucket(2, 43, 9, &manifest);

        let plan = plan_private_result_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();
        assert_eq!(plan.old_epoch, manifest.index_epoch);
        assert_eq!(plan.old_root_hash, old_root);
        assert_eq!(plan.leaf_commitments[2], updated_bucket.bucket_commitment);

        let mut wrong_commitment = updated_bucket.clone();
        wrong_commitment.bucket_commitment = commitment(99);
        assert_eq!(
            plan_private_result_oram_commit_for_manifest(
                &manifest,
                43,
                &leaf_commitments,
                std::slice::from_ref(&wrong_commitment),
            ),
            Err(PrivateResultOramError::InvalidBucketCommitment)
        );

        let mut wrong_provider = manifest.clone();
        wrong_provider.provider = "payload/wrong-result-oram@v1".to_string();
        assert_eq!(
            plan_private_result_oram_commit_for_manifest(
                &wrong_provider,
                43,
                &leaf_commitments,
                std::slice::from_ref(&updated_bucket),
            ),
            Err(PrivateResultOramError::InvalidProvider)
        );

        let mut short_ciphertext = updated_bucket.clone();
        let short_raw = b"short-result-commit-bucket";
        let short_hash = BASE64URL_NOPAD.encode(Sha256::digest(short_raw).as_ref());
        short_ciphertext.ciphertext = BASE64URL_NOPAD.encode(short_raw);
        short_ciphertext.ciphertext_sha256 = short_hash.clone();
        short_ciphertext.bucket_commitment =
            fixture_bucket_commitment(2, short_ciphertext.index_epoch, &short_hash);
        assert_eq!(
            plan_private_result_oram_commit_for_manifest(
                &manifest,
                43,
                &leaf_commitments,
                std::slice::from_ref(&short_ciphertext),
            ),
            Err(PrivateResultOramError::InvalidBucketField("ciphertext"))
        );

        let mut long_ciphertext = updated_bucket.clone();
        let expected_bytes = private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
        let long_raw = vec![7; expected_bytes + 1];
        let long_hash = BASE64URL_NOPAD.encode(Sha256::digest(&long_raw).as_ref());
        long_ciphertext.ciphertext = BASE64URL_NOPAD.encode(&long_raw);
        long_ciphertext.ciphertext_sha256 = long_hash.clone();
        long_ciphertext.bucket_commitment =
            fixture_bucket_commitment(2, long_ciphertext.index_epoch, &long_hash);
        assert_eq!(
            plan_private_result_oram_commit_for_manifest(
                &manifest,
                43,
                &leaf_commitments,
                std::slice::from_ref(&long_ciphertext),
            ),
            Err(PrivateResultOramError::InvalidBucketField("ciphertext"))
        );

        let wrong_bucket_count = PrivateResultOramManifest {
            bucket_count: 2,
            ..manifest
        };
        assert_eq!(
            plan_private_result_oram_commit_for_manifest(
                &wrong_bucket_count,
                43,
                &leaf_commitments,
                std::slice::from_ref(&wrong_commitment),
            ),
            Err(PrivateResultOramError::InvalidManifestField("bucket_count",))
        );
    }

    #[test]
    fn commit_plan_for_manifest_context_allows_live_epoch_after_commit() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3)];
        let old_root = private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 1;
        manifest.oram.path_batch_size = 2;
        manifest.bucket_count = leaf_commitments.len() as u64;
        manifest.logical_result_count = 2;
        manifest.dummy_result_count = 0;
        manifest.root_hash = old_root;

        let first_bucket = fixture_upload_bucket(2, 43, 9, &manifest);
        let first_plan = plan_private_result_oram_commit_for_manifest(
            &manifest,
            43,
            &leaf_commitments,
            std::slice::from_ref(&first_bucket),
        )
        .unwrap();

        let second_bucket = fixture_upload_bucket(1, 44, 10, &manifest);
        assert_eq!(
            plan_private_result_oram_commit_for_manifest(
                &manifest,
                43,
                &first_plan.leaf_commitments,
                std::slice::from_ref(&second_bucket),
            ),
            Err(PrivateResultOramError::MerkleRootMismatch)
        );

        let second_plan = plan_private_result_oram_commit_for_manifest_context(
            &manifest,
            first_plan.new_epoch,
            44,
            &first_plan.new_root_hash,
            &first_plan.leaf_commitments,
            std::slice::from_ref(&second_bucket),
        )
        .unwrap();
        assert_eq!(second_plan.old_epoch, first_plan.new_epoch);
        assert_eq!(second_plan.old_root_hash, first_plan.new_root_hash);
        assert_eq!(
            second_plan.leaf_commitments[1],
            second_bucket.bucket_commitment
        );

        let mut wrong_commitment = second_bucket;
        wrong_commitment.bucket_commitment = commitment(99);
        assert_eq!(
            plan_private_result_oram_commit_for_manifest_context(
                &manifest,
                first_plan.new_epoch,
                44,
                &first_plan.new_root_hash,
                &first_plan.leaf_commitments,
                std::slice::from_ref(&wrong_commitment),
            ),
            Err(PrivateResultOramError::InvalidBucketCommitment)
        );
    }

    #[test]
    fn commit_plan_rejects_stale_duplicate_out_of_range_and_root_mismatch() {
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9);

        assert_eq!(
            plan_private_result_oram_commit(42, 43, &old_root, &leaf_commitments, &[]),
            Err(PrivateResultOramError::EmptyCommit)
        );

        assert_eq!(
            plan_private_result_oram_commit(
                42,
                43,
                &commitment(99),
                &leaf_commitments,
                std::slice::from_ref(&updated_bucket),
            ),
            Err(PrivateResultOramError::MerkleRootMismatch)
        );

        let stale_bucket = fixture_commit_bucket(2, 42, 9);
        assert_eq!(
            plan_private_result_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&stale_bucket),
            ),
            Err(PrivateResultOramError::StaleBucketEpoch {
                bucket_id: 2,
                expected_epoch: 43,
                actual_epoch: 42,
            })
        );

        assert_eq!(
            plan_private_result_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                &[updated_bucket.clone(), updated_bucket.clone()],
            ),
            Err(PrivateResultOramError::DuplicateUpdatedBucket { bucket_id: 2 })
        );

        let out_of_range = fixture_commit_bucket(4, 43, 9);
        assert_eq!(
            plan_private_result_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&out_of_range),
            ),
            Err(PrivateResultOramError::BucketOutOfRange {
                bucket_id: 4,
                bucket_count: 4,
            })
        );

        let mut hash_mismatch = updated_bucket.clone();
        hash_mismatch.ciphertext_sha256 = commitment(8);
        assert_eq!(
            plan_private_result_oram_commit(
                42,
                43,
                &old_root,
                &leaf_commitments,
                std::slice::from_ref(&hash_mismatch),
            ),
            Err(PrivateResultOramError::InvalidBucketCiphertextHash)
        );
    }

    #[test]
    fn commit_plan_can_be_signed_and_verified_by_server_validator() {
        let key_pair = deterministic_key_pair();
        let leaf_commitments = vec![commitment(1), commitment(2), commitment(3), commitment(4)];
        let old_root = private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap();
        let updated_bucket = fixture_commit_bucket(2, 43, 9);
        let plan = plan_private_result_oram_commit(
            42,
            43,
            &old_root,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        let context = PrivateResultOramCommitSignatureContext {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            signing_key_id: "tenant-a/private-result-signing-v1",
        };
        let signature = sign_private_result_oram_commit(&key_pair, context, &plan).unwrap();
        let malformed_context = PrivateResultOramCommitSignatureContext {
            collection_id: "collection\nuuid",
            ..context
        };
        assert_eq!(
            sign_private_result_oram_commit(&key_pair, malformed_context, &plan),
            Err(PrivateResultOramError::InvalidManifestField(
                "collection_id"
            ))
        );
        for malformed_context in [
            PrivateResultOramCommitSignatureContext {
                key_id: "tenant-a/payload\nprivate-rk",
                ..context
            },
            PrivateResultOramCommitSignatureContext {
                rk_id: "tenant-a/payload\nprivate-rk",
                ..context
            },
            PrivateResultOramCommitSignatureContext {
                signing_key_id: "tenant-a/private\nresult-signing-v1",
                ..context
            },
        ] {
            assert_eq!(
                sign_private_result_oram_commit(&key_pair, malformed_context, &plan),
                Err(PrivateResultOramError::InvalidResourceKeyId)
            );
        }

        let bucket_refs = plan.signature_bucket_refs();
        validate_private_result_oram_commit_signature(
            PrivateResultOramCommitSignatureInput {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/payload-private-rk",
                rk_id: "tenant-a/payload-private-rk",
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
            PrivateResultOramSignatureVerification {
                expected_key_id: "tenant-a/private-result-signing-v1",
                public_key: key_pair.public_key().as_ref(),
            },
        )
        .unwrap();

        let empty_plan = PrivateResultOramCommitPlan {
            old_epoch: plan.old_epoch,
            new_epoch: plan.new_epoch,
            old_root_hash: plan.old_root_hash.clone(),
            new_root_hash: plan.old_root_hash.clone(),
            leaf_commitments: plan.leaf_commitments.clone(),
            updated_buckets: Vec::new(),
        };
        assert_eq!(
            sign_private_result_oram_commit(&key_pair, context, &empty_plan),
            Err(PrivateResultOramError::EmptyCommit)
        );

        let mut stale_epoch_plan = plan.clone();
        stale_epoch_plan.new_epoch = stale_epoch_plan.old_epoch;
        assert_eq!(
            sign_private_result_oram_commit(&key_pair, context, &stale_epoch_plan),
            Err(PrivateResultOramError::InvalidManifestField("new_epoch"))
        );

        let mut malformed_root_plan = plan.clone();
        malformed_root_plan.old_root_hash = "AAAA".to_string();
        assert_eq!(
            sign_private_result_oram_commit(&key_pair, context, &malformed_root_plan),
            Err(PrivateResultOramError::InvalidManifestField(
                "old_root_hash"
            ))
        );

        let mut malformed_hash_plan = plan.clone();
        malformed_hash_plan.updated_buckets[0].ciphertext_sha256 = "AAAA".to_string();
        assert_eq!(
            sign_private_result_oram_commit(&key_pair, context, &malformed_hash_plan),
            Err(PrivateResultOramError::InvalidBucketField(
                "ciphertext_sha256"
            ))
        );

        let mut duplicate_bucket_plan = plan.clone();
        duplicate_bucket_plan
            .updated_buckets
            .push(duplicate_bucket_plan.updated_buckets[0].clone());
        assert_eq!(
            sign_private_result_oram_commit(&key_pair, context, &duplicate_bucket_plan),
            Err(PrivateResultOramError::DuplicateUpdatedBucket { bucket_id: 2 })
        );
    }

    #[test]
    fn manifest_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let mut manifest = fixture_manifest();
        let signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };
        let verification = PrivateResultOramSignatureVerification {
            expected_key_id: signature.key_id.as_str(),
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_result_oram_manifest_signature(&manifest, Some(&signature), verification)
            .unwrap();

        manifest.index_epoch += 1;
        assert_eq!(
            validate_private_result_oram_manifest_signature(
                &manifest,
                Some(&signature),
                verification,
            ),
            Err(PrivateResultOramError::InvalidManifestSignature)
        );
        assert_eq!(
            validate_private_result_oram_manifest_signature(&manifest, None, verification),
            Err(PrivateResultOramError::MissingManifestSignature)
        );

        let mut malformed = fixture_manifest();
        malformed.root_hash = "AAAA".to_string();
        assert_eq!(
            validate_private_result_oram_manifest_signature(
                &malformed,
                Some(&signature),
                verification,
            ),
            Err(PrivateResultOramError::InvalidManifestField("root_hash"))
        );
    }

    #[test]
    fn manifest_signature_requires_owner_and_runtime_key_id_match() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };

        let mut wrong_owner_signature = signature.clone();
        wrong_owner_signature.key_id = "tenant-a/private-result-signing-v2".to_string();
        assert_eq!(
            validate_private_result_oram_manifest(
                &manifest,
                Some(&wrong_owner_signature),
                fixture_context(
                    key_pair.public_key().as_ref(),
                    &wrong_owner_signature.key_id
                ),
            ),
            Err(PrivateResultOramError::SignatureKeyIdMismatch)
        );

        assert_eq!(
            validate_private_result_oram_manifest(
                &manifest,
                Some(&signature),
                fixture_context(
                    key_pair.public_key().as_ref(),
                    "tenant-a/private-result-wrong"
                ),
            ),
            Err(PrivateResultOramError::SignatureKeyIdMismatch)
        );
    }

    #[test]
    fn manifest_can_be_signed_and_verified_by_server_validator() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = sign_private_result_oram_manifest(&key_pair, &manifest).unwrap();

        let epoch = validate_private_result_oram_manifest(
            &manifest,
            Some(&signature),
            fixture_context(key_pair.public_key().as_ref(), &signature.key_id),
        )
        .unwrap();

        assert_eq!(epoch.epoch, 42);
        assert_eq!(epoch.root_hash, [42; 32]);

        let mut malformed = manifest;
        malformed.root_hash = "AAAA".to_string();
        assert_eq!(
            sign_private_result_oram_manifest(&key_pair, &malformed),
            Err(PrivateResultOramError::InvalidManifestField("root_hash"))
        );
    }

    #[test]
    fn manifest_refresh_for_commit_advances_epoch_root_and_resigns() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let plan = PrivateResultOramCommitPlan {
            old_epoch: manifest.index_epoch,
            new_epoch: manifest.index_epoch + 1,
            old_root_hash: manifest.root_hash.clone(),
            new_root_hash: commitment(43),
            leaf_commitments: vec![commitment(1), commitment(2)],
            updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: 1,
                ciphertext_sha256: commitment(9),
            }],
        };

        let refreshed = refresh_private_result_oram_manifest_for_commit(&manifest, &plan).unwrap();
        assert_eq!(refreshed.index_epoch, plan.new_epoch);
        assert_eq!(refreshed.root_hash, plan.new_root_hash);
        assert_eq!(refreshed.collection_id, manifest.collection_id);
        assert_eq!(refreshed.bucket_count, manifest.bucket_count);
        assert_eq!(
            refreshed.logical_result_count,
            manifest.logical_result_count
        );
        assert_eq!(refreshed.dummy_result_count, manifest.dummy_result_count);

        let (signed_manifest, signature) =
            sign_private_result_oram_manifest_refresh(&key_pair, &manifest, &plan).unwrap();
        assert_eq!(signed_manifest, refreshed);
        assert_eq!(signature.key_id, signed_manifest.owner_signing_key_id);
        let epoch = validate_private_result_oram_manifest(
            &signed_manifest,
            Some(&signature),
            fixture_context(key_pair.public_key().as_ref(), &signature.key_id),
        )
        .unwrap();
        assert_eq!(epoch.epoch, 43);
        assert_eq!(epoch.root_hash, [43; 32]);

        let mut wrong_provider = manifest.clone();
        wrong_provider.provider = "payload/wrong-result-oram@v1".to_string();
        assert_eq!(
            refresh_private_result_oram_manifest_for_commit(&wrong_provider, &plan),
            Err(PrivateResultOramError::InvalidProvider)
        );

        let mut stale_plan = plan.clone();
        stale_plan.old_root_hash = commitment(99);
        assert_eq!(
            refresh_private_result_oram_manifest_for_commit(&manifest, &stale_plan),
            Err(PrivateResultOramError::ManifestCommitMismatch)
        );
    }

    #[test]
    fn upload_bundle_packages_signed_manifest_and_buckets() {
        let key_pair = deterministic_key_pair();
        let manifest_without_root = PrivateResultOramManifest {
            bucket_count: 3,
            logical_result_count: 3,
            dummy_result_count: 0,
            oram: OramParams {
                tree_height: 1,
                path_batch_size: 2,
                ..fixture_manifest().oram
            },
            ..fixture_manifest()
        };
        let buckets = fixture_upload_bucket_set(&manifest_without_root);
        let root_hash = private_result_oram_merkle_root_for_commitments(
            &buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let manifest = PrivateResultOramManifest {
            root_hash: root_hash.clone(),
            ..manifest_without_root
        };

        let bundle =
            package_private_result_oram_upload_bundle(&key_pair, manifest.clone(), buckets.clone())
                .unwrap();

        assert_eq!(bundle.index_epoch(), 42);
        assert_eq!(bundle.root_hash(), root_hash);
        assert_eq!(bundle.bucket_count(), 3);
        assert_eq!(bundle.buckets, buckets);
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&bundle.bucket_commitments()).unwrap(),
            root_hash
        );
        let ordered_commitments = bundle.validate_initial_upload_contract().unwrap();
        assert_eq!(ordered_commitments, bundle.bucket_commitments());

        let encoded = serde_json::to_string(&bundle).unwrap();
        let decoded: PrivateResultOramUploadBundle = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, bundle);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&decoded).unwrap(),
            ordered_commitments
        );
        for malformed_manifest in [
            PrivateResultOramManifest {
                collection_id: "collection\nuuid".to_string(),
                ..manifest.clone()
            },
            PrivateResultOramManifest {
                key_id: "tenant-a/payload\nprivate-rk".to_string(),
                ..manifest.clone()
            },
            PrivateResultOramManifest {
                rk_id: "tenant-a/payload\nprivate-rk".to_string(),
                ..manifest.clone()
            },
            PrivateResultOramManifest {
                owner_signing_key_id: "tenant-a/private\nresult-signing-v1".to_string(),
                ..manifest.clone()
            },
        ] {
            let expected = if malformed_manifest.collection_id.contains('\n') {
                PrivateResultOramError::InvalidManifestField("collection_id")
            } else {
                PrivateResultOramError::InvalidResourceKeyId
            };
            assert_eq!(
                package_private_result_oram_upload_bundle(
                    &key_pair,
                    malformed_manifest,
                    buckets.clone()
                ),
                Err(expected)
            );
        }

        let mut malformed_signature = decoded.clone();
        malformed_signature.manifest_signature.alg = "ed25519-sentinel".to_string();
        assert_eq!(
            validate_private_result_oram_upload_bundle(&malformed_signature),
            Err(PrivateResultOramError::UnsupportedSignatureAlgorithm(
                "ed25519-sentinel".to_string()
            ))
        );

        let mut wrong_signature_key = decoded.clone();
        wrong_signature_key.manifest_signature.key_id =
            "tenant-a/private-result-signing-v2".to_string();
        assert_eq!(
            validate_private_result_oram_upload_bundle(&wrong_signature_key),
            Err(PrivateResultOramError::SignatureKeyIdMismatch)
        );

        validate_private_result_oram_manifest(
            &decoded.manifest,
            Some(&decoded.manifest_signature),
            fixture_context(
                key_pair.public_key().as_ref(),
                &decoded.manifest_signature.key_id,
            ),
        )
        .unwrap();

        assert_eq!(
            validate_private_result_oram_upload_bundle_with_signature(
                &decoded,
                fixture_context(
                    key_pair.public_key().as_ref(),
                    &decoded.manifest_signature.key_id,
                ),
            )
            .unwrap(),
            ordered_commitments
        );
        assert_eq!(
            decoded
                .validate_initial_upload_contract_with_signature(fixture_context(
                    key_pair.public_key().as_ref(),
                    &decoded.manifest_signature.key_id,
                ))
                .unwrap(),
            ordered_commitments
        );

        let mut tampered_signature = decoded.clone();
        tampered_signature.manifest_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        assert_eq!(
            validate_private_result_oram_upload_bundle_with_signature(
                &tampered_signature,
                fixture_context(
                    key_pair.public_key().as_ref(),
                    &tampered_signature.manifest_signature.key_id,
                ),
            ),
            Err(PrivateResultOramError::InvalidManifestSignature)
        );

        assert_eq!(
            validate_private_result_oram_upload_bundle_with_signature(
                &decoded,
                fixture_context(
                    key_pair.public_key().as_ref(),
                    "tenant-a/private-result-wrong"
                ),
            ),
            Err(PrivateResultOramError::SignatureKeyIdMismatch)
        );

        let mut incomplete = decoded.clone();
        incomplete.buckets.pop();
        assert_eq!(
            validate_private_result_oram_upload_bundle(&incomplete),
            Err(PrivateResultOramError::InvalidManifestField("bucket_count"))
        );

        let mut unordered = decoded.clone();
        unordered.buckets.swap(0, 1);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&unordered),
            Err(PrivateResultOramError::InvalidBucketField("bucket_id"))
        );

        let mut duplicate = decoded.clone();
        duplicate.buckets[1] = duplicate.buckets[0].clone();
        assert_eq!(
            validate_private_result_oram_upload_bundle(&duplicate),
            Err(PrivateResultOramError::InvalidBucketField("bucket_id"))
        );

        let mut wrong_hash = decoded.clone();
        wrong_hash.buckets[0].ciphertext_sha256 = commitment(99);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&wrong_hash),
            Err(PrivateResultOramError::InvalidBucketHash)
        );

        let mut malformed_hash = decoded.clone();
        malformed_hash.buckets[0].ciphertext_sha256 = "AAAA".to_string();
        assert_eq!(
            validate_private_result_oram_upload_bundle(&malformed_hash),
            Err(PrivateResultOramError::InvalidBucketField(
                "ciphertext_sha256"
            ))
        );

        let mut wrong_commitment = decoded.clone();
        wrong_commitment.buckets[0].bucket_commitment = commitment(99);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&wrong_commitment),
            Err(PrivateResultOramError::InvalidBucketCommitment)
        );

        let mut malformed_commitment = decoded.clone();
        malformed_commitment.buckets[0].bucket_commitment = "AAAA".to_string();
        assert_eq!(
            validate_private_result_oram_upload_bundle(&malformed_commitment),
            Err(PrivateResultOramError::InvalidBucketField(
                "bucket_commitment"
            ))
        );

        let mut malformed_ciphertext = decoded.clone();
        malformed_ciphertext.buckets[0].ciphertext = "A".to_string();
        assert_eq!(
            validate_private_result_oram_upload_bundle(&malformed_ciphertext),
            Err(PrivateResultOramError::InvalidBucketField("ciphertext"))
        );

        let mut short_ciphertext = decoded.clone();
        let short_raw = b"short-private-result-bucket";
        let short_hash = BASE64URL_NOPAD.encode(Sha256::digest(short_raw).as_ref());
        short_ciphertext.buckets[0].ciphertext = BASE64URL_NOPAD.encode(short_raw);
        short_ciphertext.buckets[0].ciphertext_sha256 = short_hash.clone();
        short_ciphertext.buckets[0].bucket_commitment =
            fixture_bucket_commitment(0, short_ciphertext.manifest.index_epoch, &short_hash);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&short_ciphertext),
            Err(PrivateResultOramError::InvalidBucketField("ciphertext"))
        );

        let mut long_ciphertext = decoded.clone();
        let expected_ciphertext_bytes =
            private_result_oram_bucket_ciphertext_bytes(&long_ciphertext.manifest.oram).unwrap();
        let long_raw = vec![7; expected_ciphertext_bytes + 1];
        let long_hash = BASE64URL_NOPAD.encode(Sha256::digest(&long_raw).as_ref());
        long_ciphertext.buckets[0].ciphertext = BASE64URL_NOPAD.encode(&long_raw);
        long_ciphertext.buckets[0].ciphertext_sha256 = long_hash.clone();
        long_ciphertext.buckets[0].bucket_commitment =
            fixture_bucket_commitment(0, long_ciphertext.manifest.index_epoch, &long_hash);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&long_ciphertext),
            Err(PrivateResultOramError::InvalidBucketField("ciphertext"))
        );

        let mut oversized_ciphertext = decoded.clone();
        let oversized_raw =
            vec![
                0;
                private_result_oram_upload_max_ciphertext_bytes(&decoded.manifest).unwrap() + 1
            ];
        oversized_ciphertext.buckets[0].ciphertext = BASE64URL_NOPAD.encode(&oversized_raw);
        assert_eq!(
            validate_private_result_oram_upload_bundle(&oversized_ciphertext),
            Err(PrivateResultOramError::BucketOversized)
        );

        let mut malformed_root = decoded.clone();
        malformed_root.manifest.root_hash = "AAAA".to_string();
        assert_eq!(
            validate_private_result_oram_upload_bundle(&malformed_root),
            Err(PrivateResultOramError::InvalidManifestField("root_hash"))
        );

        let mut wrong_root = manifest;
        wrong_root.root_hash = commitment(99);
        assert_eq!(
            package_private_result_oram_upload_bundle(&key_pair, wrong_root, buckets),
            Err(PrivateResultOramError::MerkleRootMismatch)
        );
    }

    #[test]
    fn commit_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let buckets = [PrivateResultOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
        }];
        let input = PrivateResultOramCommitSignatureInput {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            old_epoch: 42,
            new_epoch: 43,
            old_root_hash: &BASE64URL_NOPAD.encode(&[42; 32]),
            new_root_hash: &BASE64URL_NOPAD.encode(&[43; 32]),
            updated_buckets: &buckets,
            signature_alg: "ed25519",
            signature_key_id: "tenant-a/private-result-signing-v1",
        };
        let signature = sign_b64(&key_pair, &checked_commit_signature_message(input));
        let verification = PrivateResultOramSignatureVerification {
            expected_key_id: "tenant-a/private-result-signing-v1",
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_result_oram_commit_signature(input, &signature, verification).unwrap();

        let stale_epoch_input = PrivateResultOramCommitSignatureInput {
            new_epoch: input.old_epoch,
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                stale_epoch_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidManifestField("new_epoch"))
        );

        let invalid_context = PrivateResultOramCommitSignatureInput {
            collection_id: "",
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                invalid_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidManifestField(
                "collection_id"
            ))
        );

        let invalid_key_context = PrivateResultOramCommitSignatureInput {
            key_id: "bad key id",
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                invalid_key_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidResourceKeyId)
        );
        let invalid_rk_context = PrivateResultOramCommitSignatureInput {
            rk_id: "bad rk id",
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                invalid_rk_context,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidResourceKeyId)
        );

        let empty_input = PrivateResultOramCommitSignatureInput {
            updated_buckets: &[],
            ..input
        };
        assert_eq!(
            try_private_result_oram_commit_signature_message(empty_input),
            Err(PrivateResultOramError::EmptyCommit)
        );
        assert_eq!(
            validate_private_result_oram_commit_signature(
                empty_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::EmptyCommit)
        );

        let malformed_root_input = PrivateResultOramCommitSignatureInput {
            old_root_hash: "AAAA",
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                malformed_root_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidManifestField(
                "old_root_hash"
            ))
        );

        let malformed_hash_buckets = [PrivateResultOramCommitBucketRef {
            bucket_id: 9,
            ciphertext_sha256: "AAAA",
        }];
        let malformed_hash_input = PrivateResultOramCommitSignatureInput {
            updated_buckets: &malformed_hash_buckets,
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                malformed_hash_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidBucketField(
                "ciphertext_sha256"
            ))
        );

        let duplicate_buckets = [
            PrivateResultOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[9; 32]),
            },
            PrivateResultOramCommitBucketRef {
                bucket_id: 9,
                ciphertext_sha256: &BASE64URL_NOPAD.encode(&[10; 32]),
            },
        ];
        let duplicate_input = PrivateResultOramCommitSignatureInput {
            updated_buckets: &duplicate_buckets,
            ..input
        };
        assert_eq!(
            try_private_result_oram_commit_signature_message(duplicate_input),
            Err(PrivateResultOramError::InvalidCommitSignature)
        );
        let duplicate_signature = sign_b64(
            &key_pair,
            &unchecked_commit_signature_message(duplicate_input),
        );
        assert_eq!(
            validate_private_result_oram_commit_signature(
                duplicate_input,
                &duplicate_signature,
                verification,
            ),
            Err(PrivateResultOramError::InvalidCommitSignature)
        );

        let wrong_signature_key_input = PrivateResultOramCommitSignatureInput {
            signature_key_id: "tenant-a/private-result-signing-v2",
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                wrong_signature_key_input,
                &signature,
                verification,
            ),
            Err(PrivateResultOramError::SignatureKeyIdMismatch)
        );
        let malformed_signature_key_input = PrivateResultOramCommitSignatureInput {
            signature_key_id: "tenant-a/private\nresult-signing-v1",
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(
                malformed_signature_key_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidResourceKeyId)
        );

        let tampered = PrivateResultOramCommitSignatureInput {
            old_epoch: 43,
            new_epoch: 44,
            ..input
        };
        assert_eq!(
            validate_private_result_oram_commit_signature(tampered, &signature, verification),
            Err(PrivateResultOramError::InvalidCommitSignature)
        );
    }

    #[test]
    fn read_buckets_signature_verifies_and_tamper_fails() {
        let key_pair = deterministic_key_pair();
        let bucket_ids = [0, 1, 3, 0, 1, 4];
        let context = PrivateResultOramReadBucketsSignatureContext {
            collection_id: "collection-uuid-1",
            key_id: "tenant-a/payload-private-rk",
            rk_id: "tenant-a/payload-private-rk",
            rk_epoch: 7,
            signing_key_id: "tenant-a/private-result-signing-v1",
        };
        let root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let signature = sign_private_result_oram_read_buckets(
            &key_pair,
            context,
            42,
            &root_hash,
            7,
            &bucket_ids,
        )
        .unwrap();
        let input = PrivateResultOramReadBucketsSignatureInput {
            collection_id: context.collection_id,
            key_id: context.key_id,
            rk_id: context.rk_id,
            rk_epoch: context.rk_epoch,
            index_epoch: 42,
            root_hash: &root_hash,
            bucket_count: 7,
            bucket_ids: &bucket_ids,
            signature_alg: signature.alg.as_str(),
            signature_key_id: signature.key_id.as_str(),
        };
        let verification = PrivateResultOramSignatureVerification {
            expected_key_id: "tenant-a/private-result-signing-v1",
            public_key: key_pair.public_key().as_ref(),
        };
        validate_private_result_oram_read_buckets_signature(input, &signature.sig, verification)
            .unwrap();
        for invalid_context in [
            PrivateResultOramReadBucketsSignatureInput {
                collection_id: "",
                ..input
            },
            PrivateResultOramReadBucketsSignatureInput {
                key_id: "bad key id",
                ..input
            },
            PrivateResultOramReadBucketsSignatureInput {
                rk_id: "bad rk id",
                ..input
            },
        ] {
            let expected = if invalid_context.collection_id.is_empty() {
                PrivateResultOramError::InvalidManifestField("collection_id")
            } else {
                PrivateResultOramError::InvalidResourceKeyId
            };
            assert_eq!(
                validate_private_result_oram_read_buckets_signature(
                    invalid_context,
                    "malformed-signature",
                    verification,
                ),
                Err(expected)
            );
        }
        let malformed_signature_key_input = PrivateResultOramReadBucketsSignatureInput {
            signature_key_id: "tenant-a/private\nresult-signing-v1",
            ..input
        };
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                malformed_signature_key_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidResourceKeyId)
        );
        let malformed_context = PrivateResultOramReadBucketsSignatureContext {
            collection_id: "collection\nuuid",
            ..context
        };
        assert_eq!(
            sign_private_result_oram_read_buckets(
                &key_pair,
                malformed_context,
                42,
                &root_hash,
                7,
                &bucket_ids,
            ),
            Err(PrivateResultOramError::InvalidManifestField(
                "collection_id"
            ))
        );
        for malformed_context in [
            PrivateResultOramReadBucketsSignatureContext {
                key_id: "tenant-a/payload\nprivate-rk",
                ..context
            },
            PrivateResultOramReadBucketsSignatureContext {
                rk_id: "tenant-a/payload\nprivate-rk",
                ..context
            },
            PrivateResultOramReadBucketsSignatureContext {
                signing_key_id: "tenant-a/private\nresult-signing-v1",
                ..context
            },
        ] {
            assert_eq!(
                sign_private_result_oram_read_buckets(
                    &key_pair,
                    malformed_context,
                    42,
                    &root_hash,
                    7,
                    &bucket_ids,
                ),
                Err(PrivateResultOramError::InvalidResourceKeyId)
            );
        }

        assert_eq!(
            sign_private_result_oram_read_buckets(
                &key_pair,
                context,
                42,
                &root_hash,
                8,
                &bucket_ids,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let partial_path_bucket_ids = [0, 1];
        assert_eq!(
            sign_private_result_oram_read_buckets(
                &key_pair,
                context,
                42,
                &root_hash,
                7,
                &partial_path_bucket_ids,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let empty_input = PrivateResultOramReadBucketsSignatureInput {
            bucket_ids: &[],
            ..input
        };
        assert_eq!(
            try_private_result_oram_read_buckets_signature_message(empty_input),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                empty_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let out_of_range_bucket_ids = [0, 1, 7];
        let out_of_range_input = PrivateResultOramReadBucketsSignatureInput {
            bucket_ids: &out_of_range_bucket_ids,
            ..input
        };
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                out_of_range_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let non_canonical_bucket_count_input = PrivateResultOramReadBucketsSignatureInput {
            bucket_count: 8,
            ..input
        };
        assert_eq!(
            try_private_result_oram_read_buckets_signature_message(
                non_canonical_bucket_count_input
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );
        let non_canonical_bucket_count_signature = sign_b64(
            &key_pair,
            &unchecked_read_buckets_signature_message(non_canonical_bucket_count_input),
        );
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                non_canonical_bucket_count_input,
                &non_canonical_bucket_count_signature,
                verification,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let partial_path_input = PrivateResultOramReadBucketsSignatureInput {
            bucket_ids: &partial_path_bucket_ids,
            ..input
        };
        assert_eq!(
            try_private_result_oram_read_buckets_signature_message(partial_path_input),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );
        let partial_path_signature = sign_b64(
            &key_pair,
            &unchecked_read_buckets_signature_message(partial_path_input),
        );
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                partial_path_input,
                &partial_path_signature,
                verification,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let duplicate_path_bucket_ids = [0, 1, 3, 0, 1, 3];
        let duplicate_path_input = PrivateResultOramReadBucketsSignatureInput {
            bucket_ids: &duplicate_path_bucket_ids,
            ..input
        };
        assert_eq!(
            try_private_result_oram_read_buckets_signature_message(duplicate_path_input),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );
        let duplicate_path_signature = sign_b64(
            &key_pair,
            &unchecked_read_buckets_signature_message(duplicate_path_input),
        );
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                duplicate_path_input,
                &duplicate_path_signature,
                verification,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let malformed_path_bucket_ids = [0, 2, 3];
        let malformed_path_input = PrivateResultOramReadBucketsSignatureInput {
            bucket_ids: &malformed_path_bucket_ids,
            ..input
        };
        assert_eq!(
            try_private_result_oram_read_buckets_signature_message(malformed_path_input),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );
        let malformed_path_signature = sign_b64(
            &key_pair,
            &unchecked_read_buckets_signature_message(malformed_path_input),
        );
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                malformed_path_input,
                &malformed_path_signature,
                verification,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let malformed_root_input = PrivateResultOramReadBucketsSignatureInput {
            root_hash: "AAAA",
            ..input
        };
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                malformed_root_input,
                "malformed-signature",
                verification,
            ),
            Err(PrivateResultOramError::InvalidManifestField("root_hash"))
        );

        let tampered = PrivateResultOramReadBucketsSignatureInput {
            index_epoch: 43,
            ..input
        };
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                tampered,
                &signature.sig,
                verification,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let tampered_bucket_count = PrivateResultOramReadBucketsSignatureInput {
            bucket_count: 8,
            ..input
        };
        assert_eq!(
            validate_private_result_oram_read_buckets_signature(
                tampered_bucket_count,
                &signature.sig,
                verification,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );
    }

    #[test]
    fn read_buckets_manifest_signer_enforces_fixed_batch_context() {
        let key_pair = deterministic_key_pair();
        let mut manifest = fixture_manifest();
        manifest.oram.tree_height = 2;
        manifest.oram.path_batch_size = 2;
        manifest.bucket_count = 7;
        manifest.logical_result_count = 8;
        manifest.dummy_result_count = 4;
        let bucket_ids = [0, 1, 3, 0, 2, 5];

        let signature =
            sign_private_result_oram_read_buckets_for_manifest(&key_pair, &manifest, &bucket_ids)
                .unwrap();
        let input = PrivateResultOramReadBucketsSignatureInput {
            collection_id: &manifest.collection_id,
            key_id: &manifest.key_id,
            rk_id: &manifest.rk_id,
            rk_epoch: manifest.rk_epoch,
            index_epoch: manifest.index_epoch,
            root_hash: &manifest.root_hash,
            bucket_count: manifest.bucket_count,
            bucket_ids: &bucket_ids,
            signature_alg: &signature.alg,
            signature_key_id: &signature.key_id,
        };
        validate_private_result_oram_read_buckets_signature(
            input,
            &signature.sig,
            PrivateResultOramSignatureVerification {
                expected_key_id: &manifest.owner_signing_key_id,
                public_key: key_pair.public_key().as_ref(),
            },
        )
        .unwrap();

        assert_eq!(signature.key_id, manifest.owner_signing_key_id);
        let live_root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let live_signature = sign_private_result_oram_read_buckets_for_manifest_context(
            &key_pair,
            &manifest,
            manifest.index_epoch + 1,
            &live_root_hash,
            &bucket_ids,
        )
        .unwrap();
        validate_private_result_oram_read_buckets_signature(
            PrivateResultOramReadBucketsSignatureInput {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                index_epoch: manifest.index_epoch + 1,
                root_hash: &live_root_hash,
                bucket_count: manifest.bucket_count,
                bucket_ids: &bucket_ids,
                signature_alg: &live_signature.alg,
                signature_key_id: &live_signature.key_id,
            },
            &live_signature.sig,
            PrivateResultOramSignatureVerification {
                expected_key_id: &manifest.owner_signing_key_id,
                public_key: key_pair.public_key().as_ref(),
            },
        )
        .unwrap();
        assert_eq!(
            sign_private_result_oram_read_buckets_for_manifest(
                &key_pair,
                &manifest,
                &bucket_ids[..3],
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let duplicate_path_bucket_ids = [0, 1, 3, 0, 1, 3];
        assert_eq!(
            sign_private_result_oram_read_buckets_for_manifest(
                &key_pair,
                &manifest,
                &duplicate_path_bucket_ids,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );

        let malformed_path_bucket_ids = [0, 1, 3, 0, 6, 5];
        assert_eq!(
            sign_private_result_oram_read_buckets_for_manifest(
                &key_pair,
                &manifest,
                &malformed_path_bucket_ids,
            ),
            Err(PrivateResultOramError::InvalidReadBucketsSignature)
        );
    }

    #[test]
    fn client_state_ciphertext_length_guard_rejects_impossible_and_oversized_shapes() {
        fn base64url_nopad_encoded_len(decoded_len: usize) -> usize {
            let full_triples = decoded_len / 3;
            let base_len = full_triples * 4;
            match decoded_len % 3 {
                0 => base_len,
                1 => base_len + 2,
                2 => base_len + 3,
                _ => unreachable!(),
            }
        }

        assert_eq!(base64url_nopad_decoded_len(0), Some(0));
        assert_eq!(base64url_nopad_decoded_len(2), Some(1));
        assert_eq!(base64url_nopad_decoded_len(3), Some(2));
        assert_eq!(base64url_nopad_decoded_len(4), Some(3));
        assert_eq!(base64url_nopad_decoded_len(1), None);
        assert_eq!(base64url_nopad_decoded_len(5), None);

        let max_encoded =
            base64url_nopad_encoded_len(PRIVATE_RESULT_ORAM_CLIENT_STATE_CIPHERTEXT_MAX_BYTES);
        assert_eq!(
            validate_private_result_oram_client_state_ciphertext_encoded_len(max_encoded).unwrap(),
            PRIVATE_RESULT_ORAM_CLIENT_STATE_CIPHERTEXT_MAX_BYTES
        );
        let oversized_encoded =
            base64url_nopad_encoded_len(PRIVATE_RESULT_ORAM_CLIENT_STATE_CIPHERTEXT_MAX_BYTES + 1);
        assert_eq!(
            validate_private_result_oram_client_state_ciphertext_encoded_len(oversized_encoded),
            Err(PrivateResultOramError::InvalidClientStateCiphertextEncoding)
        );
        assert_eq!(
            validate_private_result_oram_client_state_ciphertext_encoded_len(5),
            Err(PrivateResultOramError::InvalidClientStateCiphertextEncoding)
        );
    }

    #[test]
    fn manifest_validation_binds_context_and_returns_epoch() {
        let key_pair = deterministic_key_pair();
        let manifest = fixture_manifest();
        let signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: manifest.owner_signing_key_id.clone(),
            sig: sign_b64(&key_pair, &checked_manifest_signature_message(&manifest)),
        };
        let context = fixture_context(key_pair.public_key().as_ref(), &signature.key_id);

        assert_eq!(
            validate_private_result_oram_manifest(&manifest, Some(&signature), context),
            Ok(PrivateResultOramEpoch {
                epoch: 42,
                root_hash: [42; 32],
            })
        );

        let bad_context = PrivateResultOramManifestValidationContext {
            expected_collection_id: "other-collection",
            ..context
        };
        assert_eq!(
            validate_private_result_oram_manifest(&manifest, Some(&signature), bad_context),
            Err(PrivateResultOramError::ManifestContextMismatch(
                "collection_id"
            ))
        );

        let bad_signature_context = PrivateResultOramManifestValidationContext {
            signature_verification: PrivateResultOramSignatureVerification {
                expected_key_id: "tenant-a/other-signing-v1",
                public_key: key_pair.public_key().as_ref(),
            },
            ..context
        };
        assert_eq!(
            validate_private_result_oram_manifest(
                &manifest,
                Some(&signature),
                bad_signature_context,
            ),
            Err(PrivateResultOramError::SignatureKeyIdMismatch)
        );
    }
}

#[cfg(test)]
#[path = "private_result_oram_budget_tests.rs"]
mod budget_tests;
