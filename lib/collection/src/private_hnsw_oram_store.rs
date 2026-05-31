use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{PrivateHnswOramBucket, PrivateHnswOramManifest, PrivateHnswOramSignature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::operations::types::{CollectionError, CollectionResult};

pub const PRIVATE_HNSW_ORAM_DIR: &str = "private_hnsw_oram";
const MANIFEST_FILE: &str = "manifest.json";
const MANIFEST_SIGNATURE_FILE: &str = "manifest.sig";
const BUCKETS_DIR: &str = "buckets";
const EPOCHS_DIR: &str = "epochs";
const MERKLE_DIR: &str = "merkle";
const TEMP_DIR: &str = "temp";
const CURRENT_EPOCH_FILE: &str = "current.json";
const MERKLE_NODES_FILE: &str = "nodes.dat";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;
const MAX_EPOCH_BYTES: u64 = 16 * 1024;
const MAX_MERKLE_BYTES: u64 = 256 * 1024 * 1024;
pub const PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND: &str = "merkle_path_batch/v1";

#[derive(Clone, Debug)]
pub struct PrivateHnswOramStore {
    root: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramEpochState {
    pub index_epoch: u64,
    pub root_hash: String,
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
    pub position: MerkleSiblingPosition,
    pub hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MerkleSiblingPosition {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateHnswOramMerkleTree {
    version: u16,
    index_epoch: u64,
    root_hash: String,
    bucket_count: u64,
    leaf_hashes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PrivateHnswPreparedMerkleCommit {
    store: PrivateHnswOramStore,
    tree: PrivateHnswOramMerkleTree,
}

impl PrivateHnswOramStore {
    pub fn new(collection_path: impl AsRef<Path>, vector_name: &str) -> CollectionResult<Self> {
        validate_path_component(vector_name, "vector name")?;
        Ok(Self {
            root: collection_path
                .as_ref()
                .join(PRIVATE_HNSW_ORAM_DIR)
                .join(vector_name),
        })
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    pub fn ensure_layout(&self) -> CollectionResult<()> {
        create_private_dir(&self.root)?;
        create_private_dir(&self.buckets_dir())?;
        create_private_dir(&self.epochs_dir())?;
        create_private_dir(&self.merkle_dir())?;
        create_private_dir(&self.temp_dir())?;
        Ok(())
    }

    pub fn write_manifest(
        &self,
        manifest: &PrivateHnswOramManifest,
        signature: &PrivateHnswOramSignature,
    ) -> CollectionResult<()> {
        self.ensure_layout()?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.manifest_path(),
            manifest,
        )?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.manifest_signature_path(),
            signature,
        )?;
        Ok(())
    }

    pub fn read_manifest(
        &self,
    ) -> CollectionResult<(PrivateHnswOramManifest, PrivateHnswOramSignature)> {
        validate_private_dir(&self.root)?;
        let manifest = read_json_private_file(&self.manifest_path(), MAX_MANIFEST_BYTES)?;
        let signature =
            read_json_private_file(&self.manifest_signature_path(), MAX_SIGNATURE_BYTES)?;
        Ok((manifest, signature))
    }

    pub fn write_bucket(
        &self,
        bucket: &PrivateHnswOramBucket,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        self.ensure_layout()?;
        validate_bucket(bucket, expected_epoch, bucket_count, max_ciphertext_bytes)?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.bucket_path(bucket.bucket_id),
            bucket,
        )
    }

    pub fn read_bucket(
        &self,
        bucket_id: u64,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramBucket> {
        validate_private_dir(&self.buckets_dir())?;
        let max_bucket_file_bytes = max_ciphertext_bytes as u64 + 32 * 1024;
        let bucket: PrivateHnswOramBucket =
            read_json_private_file(&self.bucket_path(bucket_id), max_bucket_file_bytes)?;
        if bucket.bucket_id != bucket_id {
            return Err(CollectionError::service_error(format!(
                "private HNSW ORAM bucket file id mismatch: requested {bucket_id}, found {}",
                bucket.bucket_id,
            )));
        }
        validate_bucket_for_read(&bucket, expected_epoch, bucket_count, max_ciphertext_bytes)?;
        Ok(bucket)
    }

    pub fn write_initial_epoch(&self, epoch: &PrivateHnswOramEpochState) -> CollectionResult<()> {
        self.ensure_layout()?;
        validate_epoch_state(epoch)?;
        let current_path = self.current_epoch_path();
        if current_path.exists() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM current epoch already exists",
            ));
        }
        write_json_atomic(&self.root, &self.temp_dir(), &current_path, epoch)
    }

    pub fn write_initial_epoch_if_absent_or_matching(
        &self,
        epoch: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        self.ensure_layout()?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => Ok(()),
            Ok(current) => Err(CollectionError::bad_request(format!(
                "private HNSW ORAM current epoch/root does not match uploaded manifest epoch {}",
                current.index_epoch,
            ))),
            Err(CollectionError::NotFound { .. }) => self.write_initial_epoch(epoch),
            Err(err) => Err(err),
        }
    }

    pub fn read_current_epoch(&self) -> CollectionResult<PrivateHnswOramEpochState> {
        validate_private_dir(&self.epochs_dir())?;
        let epoch = read_json_private_file(&self.current_epoch_path(), MAX_EPOCH_BYTES)?;
        validate_epoch_state(&epoch)?;
        Ok(epoch)
    }

    pub fn compare_and_swap_epoch(
        &self,
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        self.ensure_layout()?;
        validate_epoch_state(old)?;
        validate_epoch_state(new)?;
        if new.index_epoch <= old.index_epoch {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM new epoch must be greater than old epoch",
            ));
        }

        let current = self.read_current_epoch()?;
        if &current != old {
            return Err(CollectionError::bad_request(format!(
                "private HNSW ORAM RootHashMismatch: current epoch/root does not match old epoch {}",
                old.index_epoch,
            )));
        }

        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.commit_epoch_path(new.index_epoch),
            new,
        )?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.current_epoch_path(),
            new,
        )?;
        Ok(())
    }

    pub fn merkle_root_for_commitments(commitments: &[String]) -> CollectionResult<String> {
        let levels = merkle_levels(commitments)?;
        let root = levels
            .last()
            .and_then(|level| level.first())
            .ok_or_else(|| {
                CollectionError::bad_request("private HNSW ORAM Merkle tree is empty")
            })?;
        Ok(BASE64URL_NOPAD.encode(root))
    }

    pub fn write_merkle_tree_from_commitments(
        &self,
        index_epoch: u64,
        root_hash: String,
        leaf_hashes: Vec<String>,
    ) -> CollectionResult<()> {
        self.ensure_layout()?;
        let tree = PrivateHnswOramMerkleTree {
            version: 1,
            index_epoch,
            root_hash,
            bucket_count: leaf_hashes.len() as u64,
            leaf_hashes,
        };
        validate_merkle_tree(&tree)?;
        self.write_merkle_tree(&tree)
    }

    pub fn read_merkle_path_batch(
        &self,
        bucket_ids: &[u64],
        expected_epoch: u64,
        expected_root_hash: &str,
        expected_bucket_count: u64,
    ) -> CollectionResult<PrivateHnswOramMerkleProof> {
        let tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(
            &tree,
            expected_epoch,
            expected_root_hash,
            expected_bucket_count,
        )?;
        let levels = merkle_levels(&tree.leaf_hashes)?;
        let mut leaves = Vec::with_capacity(bucket_ids.len());
        for &bucket_id in bucket_ids {
            if bucket_id >= tree.bucket_count {
                return Err(CollectionError::bad_request(format!(
                    "private HNSW ORAM Merkle proof bucket {bucket_id} is out of range",
                )));
            }
            let bucket_index = usize::try_from(bucket_id).map_err(|_| {
                CollectionError::bad_request(
                    "private HNSW ORAM Merkle proof bucket id exceeds usize",
                )
            })?;
            leaves.push(PrivateHnswOramMerkleProofLeaf {
                bucket_id,
                leaf_hash: tree.leaf_hashes[bucket_index].clone(),
                siblings: merkle_siblings_for_bucket(&levels, bucket_index)?,
            });
        }

        Ok(PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: tree.index_epoch,
            root_hash: tree.root_hash,
            bucket_count: tree.bucket_count,
            leaves,
        })
    }

    pub fn prepare_merkle_commit(
        &self,
        old_epoch: u64,
        old_root_hash: &str,
        new_epoch: u64,
        new_root_hash: &str,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
    ) -> CollectionResult<PrivateHnswPreparedMerkleCommit> {
        if new_epoch <= old_epoch {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle commit new epoch must be greater than old epoch",
            ));
        }
        let mut tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(&tree, old_epoch, old_root_hash, bucket_count)?;
        for bucket in updated_buckets {
            if bucket.index_epoch != new_epoch {
                return Err(CollectionError::bad_request(format!(
                    "private HNSW ORAM Merkle commit bucket {} has stale epoch {}",
                    bucket.bucket_id, bucket.index_epoch,
                )));
            }
            if bucket.bucket_id >= bucket_count {
                return Err(CollectionError::bad_request(format!(
                    "private HNSW ORAM Merkle commit bucket {} is out of range",
                    bucket.bucket_id,
                )));
            }
            decode_base64url_32(&bucket.bucket_commitment, "bucket_commitment")?;
            let bucket_index = usize::try_from(bucket.bucket_id).map_err(|_| {
                CollectionError::bad_request(
                    "private HNSW ORAM Merkle commit bucket id exceeds usize",
                )
            })?;
            tree.leaf_hashes[bucket_index] = bucket.bucket_commitment.clone();
        }
        let computed_root = Self::merkle_root_for_commitments(&tree.leaf_hashes)?;
        if computed_root != new_root_hash {
            return Err(CollectionError::bad_request(format!(
                "private HNSW ORAM Merkle commit new_root_hash mismatch: computed {computed_root}",
            )));
        }
        tree.index_epoch = new_epoch;
        tree.root_hash = new_root_hash.to_string();
        validate_merkle_tree(&tree)?;
        Ok(PrivateHnswPreparedMerkleCommit {
            store: self.clone(),
            tree,
        })
    }

    fn read_merkle_tree(&self) -> CollectionResult<PrivateHnswOramMerkleTree> {
        validate_private_dir(&self.merkle_dir())?;
        let tree = read_json_private_file(&self.merkle_nodes_path(), MAX_MERKLE_BYTES)?;
        validate_merkle_tree(&tree)?;
        Ok(tree)
    }

    fn write_merkle_tree(&self, tree: &PrivateHnswOramMerkleTree) -> CollectionResult<()> {
        self.ensure_layout()?;
        validate_merkle_tree(tree)?;
        write_json_atomic(
            &self.root,
            &self.temp_dir(),
            &self.merkle_nodes_path(),
            tree,
        )
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join(MANIFEST_FILE)
    }

    fn manifest_signature_path(&self) -> PathBuf {
        self.root.join(MANIFEST_SIGNATURE_FILE)
    }

    fn buckets_dir(&self) -> PathBuf {
        self.root.join(BUCKETS_DIR)
    }

    fn epochs_dir(&self) -> PathBuf {
        self.root.join(EPOCHS_DIR)
    }

    fn merkle_dir(&self) -> PathBuf {
        self.root.join(MERKLE_DIR)
    }

    fn temp_dir(&self) -> PathBuf {
        self.root.join(TEMP_DIR)
    }

    fn current_epoch_path(&self) -> PathBuf {
        self.epochs_dir().join(CURRENT_EPOCH_FILE)
    }

    fn merkle_nodes_path(&self) -> PathBuf {
        self.merkle_dir().join(MERKLE_NODES_FILE)
    }

    fn commit_epoch_path(&self, epoch: u64) -> PathBuf {
        self.epochs_dir().join(format!("{epoch:08}.commit"))
    }

    fn bucket_path(&self, bucket_id: u64) -> PathBuf {
        self.buckets_dir().join(format!("{bucket_id:08}.bucket"))
    }
}

impl PrivateHnswPreparedMerkleCommit {
    pub fn write(self) -> CollectionResult<()> {
        self.store.write_merkle_tree(&self.tree)
    }
}

fn validate_merkle_tree(tree: &PrivateHnswOramMerkleTree) -> CollectionResult<()> {
    if tree.version != 1 {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM Merkle tree has unsupported version {}",
            tree.version,
        )));
    }
    if tree.bucket_count == 0 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree bucket_count must be non-zero",
        ));
    }
    if tree.leaf_hashes.len() as u64 != tree.bucket_count {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree leaf count does not match bucket_count",
        ));
    }
    let computed_root = PrivateHnswOramStore::merkle_root_for_commitments(&tree.leaf_hashes)?;
    if computed_root != tree.root_hash {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM Merkle tree root_hash mismatch: computed {computed_root}",
        )));
    }
    Ok(())
}

fn validate_merkle_tree_context(
    tree: &PrivateHnswOramMerkleTree,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
) -> CollectionResult<()> {
    validate_merkle_tree(tree)?;
    if tree.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM Merkle tree epoch mismatch: expected {expected_epoch}, found {}",
            tree.index_epoch,
        )));
    }
    if tree.root_hash != expected_root_hash {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree root_hash mismatch",
        ));
    }
    if tree.bucket_count != expected_bucket_count {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM Merkle tree bucket_count mismatch: expected {expected_bucket_count}, found {}",
            tree.bucket_count,
        )));
    }
    Ok(())
}

fn merkle_levels(commitments: &[String]) -> CollectionResult<Vec<Vec<[u8; 32]>>> {
    if commitments.is_empty() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree must contain at least one leaf",
        ));
    }
    let mut leaves = commitments
        .iter()
        .map(|commitment| decode_base64url_32(commitment, "bucket_commitment"))
        .collect::<CollectionResult<Vec<_>>>()?;
    let padded_len = leaves.len().checked_next_power_of_two().ok_or_else(|| {
        CollectionError::bad_request("private HNSW ORAM Merkle tree is too large")
    })?;
    leaves.resize(padded_len, [0; 32]);

    let mut levels = vec![leaves];
    while levels.last().is_some_and(|level| level.len() > 1) {
        let previous = levels.last().expect("checked above");
        let mut next = Vec::with_capacity(previous.len() / 2);
        for pair in previous.chunks_exact(2) {
            next.push(merkle_parent_hash(&pair[0], &pair[1]));
        }
        levels.push(next);
    }
    Ok(levels)
}

fn merkle_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn merkle_siblings_for_bucket(
    levels: &[Vec<[u8; 32]>],
    mut index: usize,
) -> CollectionResult<Vec<PrivateHnswOramMerkleSibling>> {
    if levels.is_empty() || index >= levels[0].len() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle proof bucket index is out of range",
        ));
    }
    let mut siblings = Vec::with_capacity(levels.len().saturating_sub(1));
    for (level_index, level) in levels
        .iter()
        .enumerate()
        .take(levels.len().saturating_sub(1))
    {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        let position = if index % 2 == 0 {
            MerkleSiblingPosition::Right
        } else {
            MerkleSiblingPosition::Left
        };
        let sibling = level.get(sibling_index).ok_or_else(|| {
            CollectionError::bad_request("private HNSW ORAM Merkle proof sibling is missing")
        })?;
        siblings.push(PrivateHnswOramMerkleSibling {
            level: u32::try_from(level_index).map_err(|_| {
                CollectionError::bad_request("private HNSW ORAM Merkle proof level exceeds u32")
            })?,
            position,
            hash: BASE64URL_NOPAD.encode(sibling),
        });
        index /= 2;
    }
    Ok(siblings)
}

fn validate_bucket(
    bucket: &PrivateHnswOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_bucket_shape(bucket, bucket_count, max_ciphertext_bytes)?;
    if bucket.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM bucket {} has stale epoch {}",
            bucket.bucket_id, bucket.index_epoch,
        )));
    }
    Ok(())
}

fn validate_bucket_for_read(
    bucket: &PrivateHnswOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_bucket_shape(bucket, bucket_count, max_ciphertext_bytes)?;
    if bucket.index_epoch > expected_epoch {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM bucket {} is newer than requested epoch {}",
            bucket.bucket_id, expected_epoch,
        )));
    }
    Ok(())
}

fn validate_bucket_shape(
    bucket: &PrivateHnswOramBucket,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    if bucket.version != 1 {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM bucket {} has unsupported version {}",
            bucket.bucket_id, bucket.version,
        )));
    }
    if bucket.bucket_id >= bucket_count {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM bucket {} is out of range",
            bucket.bucket_id,
        )));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            CollectionError::bad_request(format!(
                "private HNSW ORAM bucket {} ciphertext is not base64url",
                bucket.bucket_id,
            ))
        })?;
    if ciphertext.len() > max_ciphertext_bytes {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM bucket {} ciphertext exceeds maximum size",
            bucket.bucket_id,
        )));
    }
    let sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref());
    if sha256 != bucket.ciphertext_sha256 {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM bucket {} ciphertext_sha256 mismatch",
            bucket.bucket_id,
        )));
    }
    decode_base64url_32(&bucket.bucket_commitment, "bucket_commitment")?;
    Ok(())
}

fn validate_epoch_state(epoch: &PrivateHnswOramEpochState) -> CollectionResult<()> {
    decode_base64url_32(&epoch.root_hash, "root_hash")?;
    Ok(())
}

fn decode_base64url_32(value: &str, field: &str) -> CollectionResult<[u8; 32]> {
    if value.len() != 43 {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM {field} must encode 32 bytes",
        )));
    }
    let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        CollectionError::bad_request(format!("private HNSW ORAM {field} is not base64url"))
    })?;
    bytes.try_into().map_err(|_| {
        CollectionError::bad_request(format!("private HNSW ORAM {field} must encode 32 bytes"))
    })
}

fn validate_path_component(value: &str, label: &str) -> CollectionResult<()> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM {label} is not a safe path component",
        )));
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> CollectionResult<()> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|err| {
            CollectionError::service_error(format!(
                "failed to create private HNSW ORAM directory {path:?}: {err}",
            ))
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
            CollectionError::service_error(format!(
                "failed to harden private HNSW ORAM directory {path:?}: {err}",
            ))
        })?;
    }
    validate_private_dir(path)
}

fn validate_private_dir(path: &Path) -> CollectionResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to inspect private HNSW ORAM directory {path:?}: {err}",
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CollectionError::service_error(format!(
            "private HNSW ORAM path {path:?} must be a non-symlink directory",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if metadata.uid() != effective_uid {
            return Err(CollectionError::service_error(format!(
                "private HNSW ORAM directory {path:?} must be owned by the current user",
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(format!(
                "private HNSW ORAM directory {path:?} must not be group/world accessible",
            )));
        }
    }
    Ok(())
}

fn read_json_private_file<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: u64,
) -> CollectionResult<T> {
    let mut file = open_private_file_for_read(path, max_bytes)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to read private HNSW ORAM file {path:?}: {err}",
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        CollectionError::bad_request(format!(
            "private HNSW ORAM file {path:?} contains invalid JSON: {err}",
        ))
    })
}

fn write_json_atomic<T: Serialize>(
    root: &Path,
    temp_dir: &Path,
    target: &Path,
    value: &T,
) -> CollectionResult<()> {
    validate_target_under_root(root, target)?;
    validate_private_dir(temp_dir)?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to serialize private HNSW ORAM file {target:?}: {err}",
        ))
    })?;
    let temp_path = unique_temp_path(temp_dir);
    let mut file = open_private_file_for_write(&temp_path)?;
    file.write_all(&bytes).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to write private HNSW ORAM temp file {temp_path:?}: {err}",
        ))
    })?;
    file.flush().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to flush private HNSW ORAM temp file {temp_path:?}: {err}",
        ))
    })?;
    file.sync_all().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to sync private HNSW ORAM temp file {temp_path:?}: {err}",
        ))
    })?;
    drop(file);

    fs::rename(&temp_path, target).map_err(|err| {
        let _ = fs::remove_file(&temp_path);
        CollectionError::service_error(format!(
            "failed to replace private HNSW ORAM file {target:?}: {err}",
        ))
    })?;
    if let Some(parent) = target.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn validate_target_under_root(root: &Path, target: &Path) -> CollectionResult<()> {
    if !target.starts_with(root) {
        return Err(CollectionError::service_error(format!(
            "private HNSW ORAM target {target:?} escapes root {root:?}",
        )));
    }
    if let Some(parent) = target.parent() {
        validate_private_dir(parent)?;
    }
    Ok(())
}

fn open_private_file_for_read(path: &Path, max_bytes: u64) -> CollectionResult<File> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            return CollectionError::not_found(format!("private HNSW ORAM file {path:?}"));
        }
        CollectionError::service_error(format!(
            "failed to inspect private HNSW ORAM file {path:?}: {err}",
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CollectionError::service_error(format!(
            "private HNSW ORAM file {path:?} must be a non-symlink regular file",
        )));
    }
    if metadata.len() > max_bytes {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM file {path:?} exceeds maximum size",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(format!(
                "private HNSW ORAM file {path:?} must not be group/world accessible",
            )));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to open private HNSW ORAM file {path:?}: {err}",
                ))
            })?;
        return Ok(file);
    }
    #[cfg(not(unix))]
    {
        File::open(path).map_err(|err| {
            CollectionError::service_error(format!(
                "failed to open private HNSW ORAM file {path:?}: {err}",
            ))
        })
    }
}

fn open_private_file_for_write(path: &Path) -> CollectionResult<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to create private HNSW ORAM temp file {path:?}: {err}",
        ))
    })
}

fn unique_temp_path(temp_dir: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    temp_dir.join(format!(
        "private-hnsw-oram-{}-{timestamp}.tmp",
        std::process::id(),
    ))
}

fn sync_dir(path: &Path) -> CollectionResult<()> {
    let file = File::open(path).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to open private HNSW ORAM directory {path:?} for sync: {err}",
        ))
    })?;
    file.sync_all().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to sync private HNSW ORAM directory {path:?}: {err}",
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use qdrant_sec::{
        DistanceKind, FixedBudgetParams, OramKind, OramParams, PRIVATE_HNSW_ORAM_BINDING,
        PrivateHnswBucketAeadBaseContext, PrivateHnswBucketAeadContext, PrivateHnswBuildPoint,
        PrivateHnswClientError, PrivateHnswClientKeys, PrivateHnswEncryptedPathBatch,
        PrivateHnswManifestBuildContext, PrivateHnswNodeBlockPlaintext,
        PrivateHnswOramClientConfig, PrivateHnswOramPlaintextBucket, PrivateHnswParams,
        PrivateHnswSearchParams, PrivateHnswVectorEncoding, ResultPrivacyMode, SecretKey,
        VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, build_private_hnsw_oram_manifest_from_encrypted_index,
        build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points,
        decode_private_hnsw_oram_bucket_plaintext, empty_private_hnsw_oram_plaintext_bucket,
        encode_private_hnsw_oram_bucket_plaintext, open_private_hnsw_oram_bucket,
        plan_private_hnsw_oram_commit, private_hnsw_oram_bucket_ids_for_leaf,
        private_hnsw_oram_merkle_root_for_commitments, seal_private_hnsw_oram_bucket,
        seal_private_hnsw_oram_plaintext_index, search_private_hnsw_oram_encrypted_verified,
    };
    use tempfile::TempDir;

    use super::*;

    fn root_hash(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn bucket_ciphertext(bytes: &[u8]) -> (String, String) {
        (
            BASE64URL_NOPAD.encode(bytes),
            BASE64URL_NOPAD.encode(Sha256::digest(bytes).as_ref()),
        )
    }

    fn fixture_store(temp: &TempDir) -> PrivateHnswOramStore {
        PrivateHnswOramStore::new(temp.path(), "text").unwrap()
    }

    fn fixture_manifest() -> PrivateHnswOramManifest {
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
            root_hash: root_hash(42),
            bucket_count: 16,
            logical_node_count: 10,
            dummy_node_count: 6,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn fixture_signature() -> PrivateHnswOramSignature {
        PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        }
    }

    fn fixture_bucket(bucket_id: u64, epoch: u64, plaintext: &[u8]) -> PrivateHnswOramBucket {
        let (ciphertext, ciphertext_sha256) = bucket_ciphertext(plaintext);
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment: root_hash(99),
        }
    }

    fn client_bucket_context(bucket_id: u64) -> PrivateHnswBucketAeadContext<'static> {
        client_bucket_base_context().for_bucket(bucket_id, 42)
    }

    fn client_bucket_base_context() -> PrivateHnswBucketAeadBaseContext<'static> {
        PrivateHnswBucketAeadBaseContext {
            collection_id: "collection-uuid-1",
            vector_name: "text",
            key_id: "tenant-a/vector-private-rk",
            rk_id: "tenant-a/vector-private-rk",
            rk_epoch: 7,
        }
    }

    fn client_oram_config() -> PrivateHnswOramClientConfig {
        PrivateHnswOramClientConfig {
            tree_height: 1,
            bucket_size: 2,
            block_size_bytes: 512,
            fixed_neighbor_slots: 4,
        }
    }

    fn client_node_block() -> PrivateHnswNodeBlockPlaintext {
        PrivateHnswNodeBlockPlaintext {
            version: 1,
            node_id: [21; 32],
            point_token: [22; 32],
            level_mask: 1,
            vector_encoding: PrivateHnswVectorEncoding::F32Le,
            vector: vec![0, 0, 128, 63],
            neighbors: vec![[23; 32]],
            neighbor_levels: vec![0],
            deleted: false,
            generation: 1,
            payload_fetch_token: None,
        }
    }

    #[test]
    fn manifest_roundtrip_writes_private_files() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let manifest = fixture_manifest();
        let signature = fixture_signature();

        store.write_manifest(&manifest, &signature).unwrap();
        let (stored_manifest, stored_signature) = store.read_manifest().unwrap();
        assert_eq!(stored_manifest, manifest);
        assert_eq!(stored_signature, signature);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let manifest_mode = fs::metadata(store.root_path().join(MANIFEST_FILE))
                .unwrap()
                .permissions()
                .mode();
            let root_mode = fs::metadata(store.root_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(manifest_mode & 0o077, 0);
            assert_eq!(root_mode & 0o077, 0);
        }
    }

    #[test]
    fn initial_epoch_if_absent_creates_private_layout() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };

        store
            .write_initial_epoch_if_absent_or_matching(&epoch)
            .unwrap();

        assert_eq!(store.read_current_epoch().unwrap(), epoch);
    }

    #[test]
    fn bucket_write_rejects_hash_mismatch_and_oversize() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(3, 42, b"encrypted bucket");

        store.write_bucket(&bucket, 42, 16, 64).unwrap();
        assert_eq!(store.read_bucket(3, 42, 16, 64).unwrap(), bucket);

        let mut bad_hash = bucket.clone();
        bad_hash.ciphertext_sha256 = root_hash(1);
        let err = store.write_bucket(&bad_hash, 42, 16, 64).unwrap_err();
        assert!(err.to_string().contains("ciphertext_sha256 mismatch"));

        let oversized = fixture_bucket(4, 42, &[8; 65]);
        let err = store.write_bucket(&oversized, 42, 16, 64).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum size"));
    }

    #[test]
    fn store_accepts_client_sealed_buckets_and_merkle_root_roundtrips() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let keys =
            PrivateHnswClientKeys::derive_from_resource_key(&SecretKey::from_bytes([13; 32]))
                .unwrap();

        let config = client_oram_config();
        let plaintext_bucket0 = PrivateHnswOramPlaintextBucket {
            bucket_id: 0,
            blocks: vec![Some(client_node_block()), None],
        };
        let plaintext_bucket1 = empty_private_hnsw_oram_plaintext_bucket(1, config).unwrap();
        let bucket0_plaintext =
            encode_private_hnsw_oram_bucket_plaintext(&plaintext_bucket0, config).unwrap();
        let bucket1_plaintext =
            encode_private_hnsw_oram_bucket_plaintext(&plaintext_bucket1, config).unwrap();
        let bucket0 =
            seal_private_hnsw_oram_bucket(&keys, client_bucket_context(0), &bucket0_plaintext)
                .unwrap();
        let bucket1 =
            seal_private_hnsw_oram_bucket(&keys, client_bucket_context(1), &bucket1_plaintext)
                .unwrap();
        let commitments = vec![
            bucket0.bucket_commitment.clone(),
            bucket1.bucket_commitment.clone(),
        ];
        let root = PrivateHnswOramStore::merkle_root_for_commitments(&commitments).unwrap();
        assert_eq!(
            private_hnsw_oram_merkle_root_for_commitments(&commitments).unwrap(),
            root
        );

        store
            .write_merkle_tree_from_commitments(42, root.clone(), commitments.clone())
            .unwrap();
        store.write_bucket(&bucket0, 42, 2, 2048).unwrap();
        store.write_bucket(&bucket1, 42, 2, 2048).unwrap();

        let stored_bucket0 = store.read_bucket(0, 42, 2, 2048).unwrap();
        let reopened_bucket0 =
            open_private_hnsw_oram_bucket(&keys, client_bucket_context(0), &stored_bucket0)
                .unwrap();
        assert_eq!(
            decode_private_hnsw_oram_bucket_plaintext(0, &reopened_bucket0, config).unwrap(),
            plaintext_bucket0
        );

        let proof = store.read_merkle_path_batch(&[0, 1], 42, &root, 2).unwrap();
        assert_eq!(proof.root_hash, root);
        assert_eq!(proof.leaves[0].leaf_hash, commitments[0]);
        assert_eq!(proof.leaves[1].leaf_hash, commitments[1]);
    }

    #[test]
    fn client_commit_plan_matches_store_merkle_commit_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3), root_hash(4)];
        let old_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(2, 43, b"updated bucket");
        let plan = plan_private_hnsw_oram_commit(
            42,
            43,
            &old_root,
            &leaf_commitments,
            std::slice::from_ref(&updated_bucket),
        )
        .unwrap();

        store
            .prepare_merkle_commit(
                42,
                &old_root,
                43,
                &plan.new_root_hash,
                4,
                std::slice::from_ref(&updated_bucket),
            )
            .unwrap()
            .write()
            .unwrap();
        assert_eq!(
            store
                .read_merkle_path_batch(&[2], 43, &plan.new_root_hash, 4)
                .unwrap()
                .leaves[0]
                .leaf_hash,
            updated_bucket.bucket_commitment
        );
    }

    #[test]
    fn bucket_read_accepts_unchanged_bucket_from_prior_committed_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let unchanged_bucket = fixture_bucket(0, 42, b"unchanged bucket");
        let replaced_bucket = fixture_bucket(1, 42, b"old bucket");
        let leaf_commitments = vec![
            unchanged_bucket.bucket_commitment.clone(),
            replaced_bucket.bucket_commitment.clone(),
        ];
        let old_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();

        store.write_bucket(&unchanged_bucket, 42, 2, 64).unwrap();
        store.write_bucket(&replaced_bucket, 42, 2, 64).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(1, 43, b"new bucket");
        let mut updated_commitments = leaf_commitments;
        updated_commitments[1] = updated_bucket.bucket_commitment.clone();
        let new_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&updated_commitments).unwrap();
        store
            .prepare_merkle_commit(
                42,
                &old_root,
                43,
                &new_root,
                2,
                std::slice::from_ref(&updated_bucket),
            )
            .unwrap()
            .write()
            .unwrap();
        store.write_bucket(&updated_bucket, 43, 2, 64).unwrap();

        assert_eq!(store.read_bucket(0, 43, 2, 64).unwrap(), unchanged_bucket);
        assert_eq!(store.read_bucket(1, 43, 2, 64).unwrap(), updated_bucket);
        let err = store.read_bucket(1, 42, 2, 64).unwrap_err();
        assert!(err.to_string().contains("newer than requested epoch"));
    }

    #[test]
    fn sdk_upload_search_fixture_roundtrips_store_read_paths_and_commit() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let keys =
            PrivateHnswClientKeys::derive_from_resource_key(&SecretKey::from_bytes([13; 32]))
                .unwrap();
        let base_context = client_bucket_base_context();
        let config = PrivateHnswOramClientConfig {
            tree_height: 2,
            bucket_size: 2,
            block_size_bytes: 512,
            fixed_neighbor_slots: 4,
        };
        let entry_id = [1; 32];
        let neighbor_id = [2; 32];
        let far_id = [3; 32];
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: entry_id,
                point_token: [11; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: neighbor_id,
                point_token: [22; 32],
                vector: vec![2.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: far_id,
                point_token: [33; 32],
                vector: vec![0.0, 1.0],
                payload_fetch_token: None,
            },
        ];
        let plaintext_build = build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
            config,
            DistanceKind::Euclid,
            2,
            1,
            2,
            &points,
            &[0, 1, 2],
        )
        .unwrap();
        let encrypted_build = seal_private_hnsw_oram_plaintext_index(
            &keys,
            base_context,
            42,
            &plaintext_build,
            config,
        )
        .unwrap();
        let manifest = build_private_hnsw_oram_manifest_from_encrypted_index(
            PrivateHnswManifestBuildContext {
                collection_id: "collection-uuid-1",
                vector_name: "text",
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                dim: 2,
                distance: DistanceKind::Euclid,
                hnsw: PrivateHnswParams {
                    m: 2,
                    ef_construction: 4,
                    max_layers: 3,
                    fixed_neighbor_slots: config.fixed_neighbor_slots as u32,
                },
                oram: OramParams {
                    kind: OramKind::PathOram,
                    bucket_size: config.bucket_size as u32,
                    block_size_bytes: config.block_size_bytes as u32,
                    tree_height: config.tree_height,
                    path_batch_size: 1,
                },
                fixed_budget: FixedBudgetParams {
                    enabled: true,
                    upper_layer_steps: 1,
                    base_layer_steps: 3,
                    paths_per_round: 1,
                    fixed_result_k: 1,
                },
                result_privacy: ResultPrivacyMode::IdsVisible,
                owner_signing_key_id: "tenant-a/private-hnsw-signing-v1",
                created_at_unix: 1_770_000_000,
            },
            &encrypted_build,
        )
        .unwrap();
        assert_eq!(manifest.root_hash, encrypted_build.root_hash);

        let old_epoch = PrivateHnswOramEpochState {
            index_epoch: encrypted_build.index_epoch,
            root_hash: encrypted_build.root_hash.clone(),
        };
        let leaf_commitments = encrypted_build
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        store
            .write_manifest(&manifest, &fixture_signature())
            .unwrap();
        store.write_initial_epoch(&old_epoch).unwrap();
        store
            .write_merkle_tree_from_commitments(
                encrypted_build.index_epoch,
                encrypted_build.root_hash.clone(),
                leaf_commitments.clone(),
            )
            .unwrap();
        for bucket in &encrypted_build.buckets {
            store
                .write_bucket(
                    bucket,
                    encrypted_build.index_epoch,
                    encrypted_build.bucket_count,
                    4096,
                )
                .unwrap();
        }

        let updated_by_bucket = std::cell::RefCell::new(BTreeMap::new());
        let mut state = plaintext_build.state.clone();
        let mut remaps = [3].into_iter();
        let result = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            encrypted_build.index_epoch,
            &encrypted_build.root_hash,
            encrypted_build.bucket_count,
            43,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: encrypted_build.entry_node_id,
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let mut buckets = Vec::with_capacity(bucket_ids.len());
                for bucket_id in &bucket_ids {
                    let overlay_bucket = updated_by_bucket.borrow().get(bucket_id).cloned();
                    let bucket = match overlay_bucket {
                        Some(bucket) => bucket,
                        None => store
                            .read_bucket(
                                *bucket_id,
                                encrypted_build.index_epoch,
                                encrypted_build.bucket_count,
                                4096,
                            )
                            .map_err(|_| PrivateHnswClientError::PathBucketMismatch)?,
                    };
                    buckets.push(bucket);
                }
                let proof = store
                    .read_merkle_path_batch(
                        &bucket_ids,
                        encrypted_build.index_epoch,
                        &encrypted_build.root_hash,
                        encrypted_build.bucket_count,
                    )
                    .map_err(|_| PrivateHnswClientError::MerkleProofMismatch)?;
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: encrypted_build.index_epoch,
                    root_hash: encrypted_build.root_hash.clone(),
                    bucket_count: encrypted_build.bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                let mut updated = updated_by_bucket.borrow_mut();
                for bucket in writeback_buckets {
                    updated.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || remaps.next().ok_or(PrivateHnswClientError::LeafOutOfRange),
        )
        .unwrap();
        assert_eq!(result.hits[0].node_id, entry_id);

        let updated_buckets = updated_by_bucket
            .into_inner()
            .into_values()
            .collect::<Vec<_>>();
        let commit_plan = plan_private_hnsw_oram_commit(
            42,
            43,
            &encrypted_build.root_hash,
            &leaf_commitments,
            &updated_buckets,
        )
        .unwrap();
        let prepared = store
            .prepare_merkle_commit(
                42,
                &encrypted_build.root_hash,
                43,
                &commit_plan.new_root_hash,
                encrypted_build.bucket_count,
                &updated_buckets,
            )
            .unwrap();
        for bucket in &updated_buckets {
            store
                .write_bucket(bucket, 43, encrypted_build.bucket_count, 4096)
                .unwrap();
        }
        prepared.write().unwrap();
        let new_epoch = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: commit_plan.new_root_hash.clone(),
        };
        store
            .compare_and_swap_epoch(&old_epoch, &new_epoch)
            .unwrap();

        let mut post_commit_remaps = [3].into_iter();
        let post_commit_updates = std::cell::RefCell::new(BTreeMap::new());
        let post_commit_result = search_private_hnsw_oram_encrypted_verified(
            &keys,
            base_context,
            43,
            &commit_plan.new_root_hash,
            encrypted_build.bucket_count,
            44,
            &mut state,
            config,
            &[1.0, 0.0],
            PrivateHnswSearchParams {
                entry_node_id: encrypted_build.entry_node_id,
                k: 1,
                ef: 1,
                fixed_steps: 1,
                distance: DistanceKind::Euclid,
                padding_node_id: None,
            },
            |leaf| {
                let bucket_ids = private_hnsw_oram_bucket_ids_for_leaf(leaf, config.tree_height)?;
                let mut buckets = Vec::with_capacity(bucket_ids.len());
                for bucket_id in &bucket_ids {
                    let overlay_bucket = post_commit_updates.borrow().get(bucket_id).cloned();
                    let bucket = match overlay_bucket {
                        Some(bucket) => bucket,
                        None => store
                            .read_bucket(*bucket_id, 43, encrypted_build.bucket_count, 4096)
                            .map_err(|_| PrivateHnswClientError::PathBucketMismatch)?,
                    };
                    buckets.push(bucket);
                }
                let proof = store
                    .read_merkle_path_batch(
                        &bucket_ids,
                        43,
                        &commit_plan.new_root_hash,
                        encrypted_build.bucket_count,
                    )
                    .map_err(|_| PrivateHnswClientError::MerkleProofMismatch)?;
                Ok(PrivateHnswEncryptedPathBatch {
                    index_epoch: 43,
                    root_hash: commit_plan.new_root_hash.clone(),
                    bucket_count: encrypted_build.bucket_count,
                    proof_value: serde_json::to_string(&proof).unwrap(),
                    buckets,
                })
            },
            |writeback_buckets| {
                let mut updated = post_commit_updates.borrow_mut();
                for bucket in writeback_buckets {
                    updated.insert(bucket.bucket_id, bucket.clone());
                }
                Ok(())
            },
            || {
                post_commit_remaps
                    .next()
                    .ok_or(PrivateHnswClientError::LeafOutOfRange)
            },
        )
        .unwrap();
        assert_eq!(post_commit_result.hits[0].node_id, entry_id);
        assert!(
            post_commit_updates
                .borrow()
                .values()
                .all(|bucket| bucket.index_epoch == 44)
        );
    }

    #[test]
    fn epoch_compare_and_swap_rejects_stale_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let new = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };
        store.write_initial_epoch(&old).unwrap();
        store
            .write_initial_epoch_if_absent_or_matching(&old)
            .unwrap();
        store.compare_and_swap_epoch(&old, &new).unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), new);

        let newer = PrivateHnswOramEpochState {
            index_epoch: 44,
            root_hash: root_hash(44),
        };
        let err = store.compare_and_swap_epoch(&old, &newer).unwrap_err();
        assert!(err.to_string().contains("RootHashMismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn bucket_symlink_rejects() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside = temp.path().join("outside.bucket");
        fs::write(&outside, b"{}").unwrap();
        symlink(
            outside,
            store.root_path().join(BUCKETS_DIR).join("00000003.bucket"),
        )
        .unwrap();

        let err = store.read_bucket(3, 42, 16, 64).unwrap_err();
        assert!(err.to_string().contains("non-symlink regular file"));
    }

    #[test]
    fn merkle_tree_roundtrip_returns_batch_proof_for_requested_buckets() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3), root_hash(4)];
        let root = PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();

        store
            .write_merkle_tree_from_commitments(42, root.clone(), leaf_commitments.clone())
            .unwrap();
        let proof = store.read_merkle_path_batch(&[1, 3], 42, &root, 4).unwrap();

        assert_eq!(proof.kind, "merkle_path_batch/v1");
        assert_eq!(proof.index_epoch, 42);
        assert_eq!(proof.root_hash, root);
        assert_eq!(proof.bucket_count, 4);
        assert_eq!(proof.leaves.len(), 2);
        assert_eq!(proof.leaves[0].bucket_id, 1);
        assert_eq!(proof.leaves[0].leaf_hash, leaf_commitments[1]);
        assert_eq!(proof.leaves[1].bucket_id, 3);
        assert_eq!(proof.leaves[1].leaf_hash, leaf_commitments[3]);
        assert_eq!(proof.leaves[0].siblings.len(), 2);
    }

    #[test]
    fn merkle_commit_updates_root_and_rejects_wrong_new_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3), root_hash(4)];
        let old_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(2, 43, b"updated bucket");
        let mut updated_commitments = leaf_commitments;
        updated_commitments[2] = updated_bucket.bucket_commitment.clone();
        let new_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&updated_commitments).unwrap();

        let err = store
            .prepare_merkle_commit(
                42,
                &old_root,
                43,
                &root_hash(99),
                4,
                std::slice::from_ref(&updated_bucket),
            )
            .unwrap_err();
        assert!(err.to_string().contains("new_root_hash mismatch"));

        store
            .prepare_merkle_commit(42, &old_root, 43, &new_root, 4, &[updated_bucket])
            .unwrap()
            .write()
            .unwrap();
        let proof = store
            .read_merkle_path_batch(&[2], 43, &new_root, 4)
            .unwrap();
        assert_eq!(proof.root_hash, new_root);
        assert_eq!(proof.leaves[0].leaf_hash, updated_commitments[2]);
    }
}
