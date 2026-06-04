use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PrivateResultOramBucket,
    PrivateResultOramBucketCommitmentContext, PrivateResultOramBucketValidationContext,
    PrivateResultOramManifest, PrivateResultOramMerkleProof, PrivateResultOramMerkleProofLeaf,
    PrivateResultOramMerkleSibling, PrivateResultOramMerkleSiblingPosition,
    PrivateResultOramSignature, PrivateResultOramUploadBundle,
    private_result_oram_bucket_commitment, validate_private_result_oram_bucket_shape,
    validate_private_result_oram_upload_bundle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::operations::types::{CollectionError, CollectionResult};

pub const PRIVATE_RESULT_ORAM_DIR: &str = "private_result_oram";
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

#[derive(Clone, Debug)]
pub struct PrivateResultOramStore {
    root: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateResultOramEpochState {
    pub index_epoch: u64,
    pub root_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateResultOramMerkleTree {
    version: u16,
    index_epoch: u64,
    root_hash: String,
    bucket_count: u64,
    leaf_hashes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PrivateResultPreparedMerkleCommit {
    store: PrivateResultOramStore,
    tree: PrivateResultOramMerkleTree,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitialEpochStatus {
    Absent,
    Matching,
}

impl PrivateResultOramStore {
    pub fn new(collection_path: impl AsRef<Path>) -> Self {
        Self {
            root: collection_path.as_ref().join(PRIVATE_RESULT_ORAM_DIR),
        }
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
        manifest: &PrivateResultOramManifest,
        signature: &PrivateResultOramSignature,
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
        )
    }

    pub fn read_manifest(
        &self,
    ) -> CollectionResult<(PrivateResultOramManifest, PrivateResultOramSignature)> {
        validate_private_dir(&self.root)?;
        let manifest = read_json_private_file(&self.manifest_path(), MAX_MANIFEST_BYTES)?;
        let signature =
            read_json_private_file(&self.manifest_signature_path(), MAX_SIGNATURE_BYTES)?;
        Ok((manifest, signature))
    }

    pub fn write_initial_upload_bundle(
        &self,
        bundle: &PrivateResultOramUploadBundle,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        let leaf_commitments = validate_upload_bundle(bundle, max_ciphertext_bytes)?;
        let epoch = PrivateResultOramEpochState {
            index_epoch: bundle.manifest.index_epoch,
            root_hash: bundle.manifest.root_hash.clone(),
        };

        match self.initial_epoch_status(&epoch, "upload bundle")? {
            InitialEpochStatus::Absent => {}
            InitialEpochStatus::Matching => {
                self.validate_existing_initial_upload_bundle(
                    bundle,
                    &leaf_commitments,
                    max_ciphertext_bytes,
                )?;
                return Ok(epoch);
            }
        }
        self.write_manifest(&bundle.manifest, &bundle.manifest_signature)?;
        self.write_merkle_tree_from_commitments(
            bundle.manifest.index_epoch,
            bundle.manifest.root_hash.clone(),
            leaf_commitments,
        )?;
        for bucket in &bundle.buckets {
            self.write_bucket(
                bucket,
                bundle.manifest.index_epoch,
                bundle.manifest.bucket_count,
                max_ciphertext_bytes,
            )?;
        }
        self.write_initial_epoch_if_absent_or_matching(&epoch)?;
        Ok(epoch)
    }

    fn initial_epoch_status(
        &self,
        epoch: &PrivateResultOramEpochState,
        operation: &str,
    ) -> CollectionResult<InitialEpochStatus> {
        self.ensure_layout()?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => Ok(InitialEpochStatus::Matching),
            Ok(current) => Err(CollectionError::bad_request(format!(
                "private result ORAM current epoch/root does not match {operation} epoch {}",
                current.index_epoch,
            ))),
            Err(CollectionError::NotFound { .. }) => Ok(InitialEpochStatus::Absent),
            Err(err) => Err(err),
        }
    }

    fn validate_existing_initial_upload_bundle(
        &self,
        bundle: &PrivateResultOramUploadBundle,
        leaf_commitments: &[String],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        let (stored_manifest, stored_signature) = self.read_manifest()?;
        if stored_manifest != bundle.manifest || stored_signature != bundle.manifest_signature {
            return Err(CollectionError::bad_request(
                "private result ORAM initial upload bundle does not match existing manifest",
            ));
        }

        let stored_tree = self.read_merkle_tree()?;
        if stored_tree.index_epoch != bundle.manifest.index_epoch
            || stored_tree.root_hash != bundle.manifest.root_hash
            || stored_tree.bucket_count != bundle.manifest.bucket_count
            || stored_tree.leaf_hashes.as_slice() != leaf_commitments
        {
            return Err(CollectionError::bad_request(
                "private result ORAM initial upload bundle does not match existing Merkle tree",
            ));
        }

        for bucket in &bundle.buckets {
            let stored_bucket = self.read_bucket(
                bucket.bucket_id,
                bundle.manifest.index_epoch,
                bundle.manifest.bucket_count,
                max_ciphertext_bytes,
            )?;
            if stored_bucket != *bucket {
                return Err(CollectionError::bad_request(
                    "private result ORAM initial upload bundle does not match existing bucket set",
                ));
            }
        }
        Ok(())
    }

    pub fn write_bucket(
        &self,
        bucket: &PrivateResultOramBucket,
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
    ) -> CollectionResult<PrivateResultOramBucket> {
        validate_private_dir(&self.buckets_dir())?;
        let max_bucket_file_bytes = max_ciphertext_bytes as u64 + 32 * 1024;
        let bucket: PrivateResultOramBucket =
            read_json_private_file(&self.bucket_path(bucket_id), max_bucket_file_bytes)?;
        if bucket.bucket_id != bucket_id {
            return Err(CollectionError::service_error(format!(
                "private result ORAM bucket file id mismatch: requested {bucket_id}, found {}",
                bucket.bucket_id,
            )));
        }
        validate_bucket_for_read(&bucket, expected_epoch, bucket_count, max_ciphertext_bytes)?;
        Ok(bucket)
    }

    pub fn write_initial_epoch(&self, epoch: &PrivateResultOramEpochState) -> CollectionResult<()> {
        self.ensure_layout()?;
        validate_epoch_state(epoch)?;
        let current_path = self.current_epoch_path();
        if current_path.exists() {
            return Err(CollectionError::bad_request(
                "private result ORAM current epoch already exists",
            ));
        }
        write_json_atomic(&self.root, &self.temp_dir(), &current_path, epoch)
    }

    pub fn write_initial_epoch_if_absent_or_matching(
        &self,
        epoch: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        self.ensure_layout()?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => Ok(()),
            Ok(current) => Err(CollectionError::bad_request(format!(
                "private result ORAM current epoch/root does not match uploaded manifest epoch {}",
                current.index_epoch,
            ))),
            Err(CollectionError::NotFound { .. }) => self.write_initial_epoch(epoch),
            Err(err) => Err(err),
        }
    }

    pub fn read_current_epoch(&self) -> CollectionResult<PrivateResultOramEpochState> {
        validate_private_dir(&self.epochs_dir())?;
        let epoch = read_json_private_file(&self.current_epoch_path(), MAX_EPOCH_BYTES)?;
        validate_epoch_state(&epoch)?;
        Ok(epoch)
    }

    pub fn compare_and_swap_epoch(
        &self,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        self.ensure_layout()?;
        validate_epoch_state(old)?;
        validate_epoch_state(new)?;
        if new.index_epoch <= old.index_epoch {
            return Err(CollectionError::bad_request(
                "private result ORAM new epoch must be greater than old epoch",
            ));
        }

        let current = self.read_current_epoch()?;
        if &current != old {
            return Err(CollectionError::bad_request(format!(
                "private result ORAM RootHashMismatch: current epoch/root does not match old epoch {}",
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
        )
    }

    pub fn commit_writeback(
        &self,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateResultOramBucket],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        self.ensure_current_epoch_matches(old)?;
        let (manifest, _) = self.read_manifest()?;
        validate_commit_manifest_context(&manifest, old, bucket_count)?;
        for bucket in updated_buckets {
            validate_bucket(bucket, new.index_epoch, bucket_count, max_ciphertext_bytes)?;
        }
        validate_bucket_commitment_context(&manifest, new.index_epoch, updated_buckets)?;
        let prepared_merkle_commit = self.prepare_merkle_commit(
            old.index_epoch,
            &old.root_hash,
            new.index_epoch,
            &new.root_hash,
            bucket_count,
            updated_buckets,
        )?;
        for bucket in updated_buckets {
            self.write_bucket(bucket, new.index_epoch, bucket_count, max_ciphertext_bytes)?;
        }
        prepared_merkle_commit.write()?;
        self.compare_and_swap_epoch(old, new)?;
        Ok(new.clone())
    }

    pub fn merkle_root_for_commitments(commitments: &[String]) -> CollectionResult<String> {
        let levels = merkle_levels(commitments)?;
        let root = levels
            .last()
            .and_then(|level| level.first())
            .ok_or_else(|| {
                CollectionError::bad_request("private result ORAM Merkle tree is empty")
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
        let tree = PrivateResultOramMerkleTree {
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
    ) -> CollectionResult<PrivateResultOramMerkleProof> {
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
                    "private result ORAM Merkle proof bucket {bucket_id} is out of range",
                )));
            }
            let bucket_index = usize::try_from(bucket_id).map_err(|_| {
                CollectionError::bad_request(
                    "private result ORAM Merkle proof bucket id exceeds usize",
                )
            })?;
            leaves.push(PrivateResultOramMerkleProofLeaf {
                bucket_id,
                leaf_hash: tree.leaf_hashes[bucket_index].clone(),
                siblings: merkle_siblings_for_bucket(&levels, bucket_index)?,
            });
        }

        Ok(PrivateResultOramMerkleProof {
            kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
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
        updated_buckets: &[PrivateResultOramBucket],
    ) -> CollectionResult<PrivateResultPreparedMerkleCommit> {
        if new_epoch <= old_epoch {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle commit new epoch must be greater than old epoch",
            ));
        }
        let mut tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(&tree, old_epoch, old_root_hash, bucket_count)?;
        let mut seen_bucket_ids = std::collections::BTreeSet::new();
        for bucket in updated_buckets {
            if !seen_bucket_ids.insert(bucket.bucket_id) {
                return Err(CollectionError::bad_request(format!(
                    "private result ORAM Merkle commit repeats bucket {}",
                    bucket.bucket_id,
                )));
            }
            if bucket.index_epoch != new_epoch {
                return Err(CollectionError::bad_request(format!(
                    "private result ORAM Merkle commit bucket {} has stale epoch {}",
                    bucket.bucket_id, bucket.index_epoch,
                )));
            }
            if bucket.bucket_id >= bucket_count {
                return Err(CollectionError::bad_request(format!(
                    "private result ORAM Merkle commit bucket {} is out of range",
                    bucket.bucket_id,
                )));
            }
            decode_base64url_32(&bucket.bucket_commitment, "bucket_commitment")?;
            let bucket_index = usize::try_from(bucket.bucket_id).map_err(|_| {
                CollectionError::bad_request(
                    "private result ORAM Merkle commit bucket id exceeds usize",
                )
            })?;
            tree.leaf_hashes[bucket_index] = bucket.bucket_commitment.clone();
        }
        let computed_root = Self::merkle_root_for_commitments(&tree.leaf_hashes)?;
        if computed_root != new_root_hash {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle commit new_root_hash mismatch",
            ));
        }
        tree.index_epoch = new_epoch;
        tree.root_hash = new_root_hash.to_string();
        validate_merkle_tree(&tree)?;
        Ok(PrivateResultPreparedMerkleCommit {
            store: self.clone(),
            tree,
        })
    }

    fn read_merkle_tree(&self) -> CollectionResult<PrivateResultOramMerkleTree> {
        validate_private_dir(&self.merkle_dir())?;
        let tree = read_json_private_file(&self.merkle_nodes_path(), MAX_MERKLE_BYTES)?;
        validate_merkle_tree(&tree)?;
        Ok(tree)
    }

    fn write_merkle_tree(&self, tree: &PrivateResultOramMerkleTree) -> CollectionResult<()> {
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

    fn ensure_current_epoch_matches(
        &self,
        expected: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        let current = self.read_current_epoch()?;
        if &current != expected {
            return Err(CollectionError::bad_request(format!(
                "private result ORAM RootHashMismatch: current epoch/root does not match old epoch {}",
                expected.index_epoch,
            )));
        }
        Ok(())
    }
}

impl PrivateResultPreparedMerkleCommit {
    pub fn write(self) -> CollectionResult<()> {
        self.store.write_merkle_tree(&self.tree)
    }
}

fn validate_merkle_tree(tree: &PrivateResultOramMerkleTree) -> CollectionResult<()> {
    if tree.version != 1 {
        return Err(CollectionError::bad_request(format!(
            "private result ORAM Merkle tree has unsupported version {}",
            tree.version,
        )));
    }
    if tree.bucket_count == 0 {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree bucket_count must be non-zero",
        ));
    }
    if tree.leaf_hashes.len() as u64 != tree.bucket_count {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree leaf count does not match bucket_count",
        ));
    }
    let computed_root = PrivateResultOramStore::merkle_root_for_commitments(&tree.leaf_hashes)?;
    if computed_root != tree.root_hash {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree root_hash mismatch",
        ));
    }
    Ok(())
}

fn validate_merkle_tree_context(
    tree: &PrivateResultOramMerkleTree,
    expected_epoch: u64,
    expected_root_hash: &str,
    expected_bucket_count: u64,
) -> CollectionResult<()> {
    validate_merkle_tree(tree)?;
    if tree.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(format!(
            "private result ORAM Merkle tree epoch mismatch: expected {expected_epoch}, found {}",
            tree.index_epoch,
        )));
    }
    if tree.root_hash != expected_root_hash {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree root_hash mismatch",
        ));
    }
    if tree.bucket_count != expected_bucket_count {
        return Err(CollectionError::bad_request(format!(
            "private result ORAM Merkle tree bucket_count mismatch: expected {expected_bucket_count}, found {}",
            tree.bucket_count,
        )));
    }
    Ok(())
}

fn merkle_levels(commitments: &[String]) -> CollectionResult<Vec<Vec<[u8; 32]>>> {
    if commitments.is_empty() {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree must contain at least one leaf",
        ));
    }
    let mut leaves = commitments
        .iter()
        .map(|commitment| decode_base64url_32(commitment, "bucket_commitment"))
        .collect::<CollectionResult<Vec<_>>>()?;
    let padded_len = leaves.len().checked_next_power_of_two().ok_or_else(|| {
        CollectionError::bad_request("private result ORAM Merkle tree is too large")
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
) -> CollectionResult<Vec<PrivateResultOramMerkleSibling>> {
    if levels.is_empty() || index >= levels[0].len() {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle proof bucket index is out of range",
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
            PrivateResultOramMerkleSiblingPosition::Right
        } else {
            PrivateResultOramMerkleSiblingPosition::Left
        };
        let sibling = level.get(sibling_index).ok_or_else(|| {
            CollectionError::bad_request("private result ORAM Merkle proof sibling is missing")
        })?;
        siblings.push(PrivateResultOramMerkleSibling {
            level: u32::try_from(level_index).map_err(|_| {
                CollectionError::bad_request("private result ORAM Merkle proof level exceeds u32")
            })?,
            position,
            hash: BASE64URL_NOPAD.encode(sibling),
        });
        index /= 2;
    }
    Ok(siblings)
}

fn validate_bucket(
    bucket: &PrivateResultOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_bucket_shape(bucket, bucket_count, max_ciphertext_bytes)?;
    if bucket.index_epoch != expected_epoch {
        return Err(CollectionError::bad_request(format!(
            "private result ORAM bucket {} has stale epoch {}",
            bucket.bucket_id, bucket.index_epoch,
        )));
    }
    Ok(())
}

fn validate_commit_manifest_context(
    manifest: &PrivateResultOramManifest,
    old: &PrivateResultOramEpochState,
    bucket_count: u64,
) -> CollectionResult<()> {
    if manifest.index_epoch != old.index_epoch || manifest.root_hash != old.root_hash {
        return Err(CollectionError::bad_request(
            "private result ORAM manifest epoch/root does not match commit old epoch/root",
        ));
    }
    if manifest.bucket_count != bucket_count {
        return Err(CollectionError::bad_request(
            "private result ORAM manifest bucket_count does not match commit bucket_count",
        ));
    }
    Ok(())
}

fn validate_bucket_commitment_context(
    manifest: &PrivateResultOramManifest,
    index_epoch: u64,
    buckets: &[PrivateResultOramBucket],
) -> CollectionResult<()> {
    for bucket in buckets {
        let expected_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id: bucket.bucket_id,
                index_epoch,
            },
            &bucket.ciphertext_sha256,
        )
        .map_err(|_| {
            CollectionError::bad_request(
                "private result ORAM commit bucket commitment context mismatch",
            )
        })?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(CollectionError::bad_request(
                "private result ORAM commit bucket commitment context mismatch",
            ));
        }
    }
    Ok(())
}

fn validate_bucket_for_read(
    bucket: &PrivateResultOramBucket,
    expected_epoch: u64,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_bucket_shape(bucket, bucket_count, max_ciphertext_bytes)?;
    if bucket.index_epoch > expected_epoch {
        return Err(CollectionError::bad_request(format!(
            "private result ORAM bucket {} is newer than requested epoch {}",
            bucket.bucket_id, expected_epoch,
        )));
    }
    Ok(())
}

fn validate_bucket_shape(
    bucket: &PrivateResultOramBucket,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    validate_private_result_oram_bucket_shape(
        bucket,
        PrivateResultOramBucketValidationContext {
            expected_index_epoch: bucket.index_epoch,
            bucket_count,
            max_ciphertext_bytes,
        },
    )
    .map_err(private_result_oram_error)
}

fn validate_upload_bundle(
    bundle: &PrivateResultOramUploadBundle,
    max_ciphertext_bytes: usize,
) -> CollectionResult<Vec<String>> {
    let leaf_commitments =
        validate_private_result_oram_upload_bundle(bundle).map_err(private_result_oram_error)?;
    for bucket in &bundle.buckets {
        validate_bucket(
            bucket,
            bundle.manifest.index_epoch,
            bundle.manifest.bucket_count,
            max_ciphertext_bytes,
        )?;
    }
    Ok(leaf_commitments)
}

fn validate_epoch_state(epoch: &PrivateResultOramEpochState) -> CollectionResult<()> {
    decode_base64url_32(&epoch.root_hash, "root_hash")?;
    Ok(())
}

fn private_result_oram_error(err: qdrant_sec::PrivateResultOramError) -> CollectionError {
    CollectionError::bad_request(err.to_string())
}

fn decode_base64url_32(value: &str, field: &str) -> CollectionResult<[u8; 32]> {
    if value.len() != 43 {
        return Err(CollectionError::bad_request(format!(
            "private result ORAM {field} must encode 32 bytes",
        )));
    }
    let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        CollectionError::bad_request(format!("private result ORAM {field} is not base64url"))
    })?;
    bytes.try_into().map_err(|_| {
        CollectionError::bad_request(format!("private result ORAM {field} must encode 32 bytes"))
    })
}

fn create_private_dir(path: &Path) -> CollectionResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            return Err(CollectionError::service_error(format!(
                "private result ORAM path {path:?} must be a non-symlink directory",
            )));
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to create private result ORAM directory {path:?}: {err}",
                ))
            })?;
            let metadata = fs::symlink_metadata(path).map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to inspect private result ORAM directory {path:?}: {err}",
                ))
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(CollectionError::service_error(format!(
                    "private result ORAM path {path:?} must be a non-symlink directory",
                )));
            }
        }
        Err(err) => {
            return Err(CollectionError::service_error(format!(
                "failed to inspect private result ORAM directory {path:?}: {err}",
            )));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
            CollectionError::service_error(format!(
                "failed to harden private result ORAM directory {path:?}: {err}",
            ))
        })?;
    }
    validate_private_dir(path)
}

fn validate_private_dir(path: &Path) -> CollectionResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            return CollectionError::not_found(format!("private result ORAM directory {path:?}"));
        }
        CollectionError::service_error(format!(
            "failed to inspect private result ORAM directory {path:?}: {err}",
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CollectionError::service_error(format!(
            "private result ORAM path {path:?} must be a non-symlink directory",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if metadata.uid() != effective_uid {
            return Err(CollectionError::service_error(format!(
                "private result ORAM directory {path:?} must be owned by the current user",
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(format!(
                "private result ORAM directory {path:?} must not be group/world accessible",
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
            "failed to read private result ORAM file {path:?}: {err}",
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        CollectionError::bad_request(format!(
            "private result ORAM file {path:?} contains invalid JSON: {err}",
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
            "failed to serialize private result ORAM file {target:?}: {err}",
        ))
    })?;
    let temp_path = unique_temp_path(temp_dir);
    let mut file = open_private_file_for_write(&temp_path)?;
    file.write_all(&bytes).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to write private result ORAM temp file {temp_path:?}: {err}",
        ))
    })?;
    file.flush().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to flush private result ORAM temp file {temp_path:?}: {err}",
        ))
    })?;
    file.sync_all().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to sync private result ORAM temp file {temp_path:?}: {err}",
        ))
    })?;
    drop(file);

    fs::rename(&temp_path, target).map_err(|err| {
        let _ = fs::remove_file(&temp_path);
        CollectionError::service_error(format!(
            "failed to replace private result ORAM file {target:?}: {err}",
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
            "private result ORAM target {target:?} escapes root {root:?}",
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
            return CollectionError::not_found(format!("private result ORAM file {path:?}"));
        }
        CollectionError::service_error(format!(
            "failed to inspect private result ORAM file {path:?}: {err}",
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CollectionError::service_error(format!(
            "private result ORAM file {path:?} must be a non-symlink regular file",
        )));
    }
    if metadata.len() > max_bytes {
        return Err(CollectionError::bad_request(format!(
            "private result ORAM file {path:?} exceeds maximum size",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(format!(
                "private result ORAM file {path:?} must not be group/world accessible",
            )));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|err| {
                CollectionError::service_error(format!(
                    "failed to open private result ORAM file {path:?}: {err}",
                ))
            })?;
        return Ok(file);
    }
    #[cfg(not(unix))]
    {
        File::open(path).map_err(|err| {
            CollectionError::service_error(format!(
                "failed to open private result ORAM file {path:?}: {err}",
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
            "failed to create private result ORAM temp file {path:?}: {err}",
        ))
    })
}

fn unique_temp_path(temp_dir: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    temp_dir.join(format!(
        "private-result-oram-{}-{timestamp}.tmp",
        std::process::id(),
    ))
}

fn sync_dir(path: &Path) -> CollectionResult<()> {
    let file = File::open(path).map_err(|err| {
        CollectionError::service_error(format!(
            "failed to open private result ORAM directory {path:?} for sync: {err}",
        ))
    })?;
    file.sync_all().map_err(|err| {
        CollectionError::service_error(format!(
            "failed to sync private result ORAM directory {path:?}: {err}",
        ))
    })
}

#[cfg(test)]
mod tests {
    use qdrant_sec::{
        OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING,
        PrivateResultOramBucketCommitmentContext, private_result_oram_bucket_commitment,
        private_result_oram_merkle_root_for_commitments, verify_private_result_oram_merkle_proof,
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

    fn fixture_store(temp: &TempDir) -> PrivateResultOramStore {
        PrivateResultOramStore::new(temp.path())
    }

    fn fixture_manifest() -> PrivateResultOramManifest {
        PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            key_id: "tenant-a/result-private-rk".to_string(),
            rk_id: "tenant-a/result-private-rk".to_string(),
            rk_epoch: 7,
            oram: OramParams {
                kind: OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 8192,
                tree_height: 1,
                path_batch_size: 8,
            },
            index_epoch: 42,
            root_hash: root_hash(42),
            bucket_count: 3,
            logical_result_count: 2,
            dummy_result_count: 1,
            owner_signing_key_id: "tenant-a/private-result-signing-v1".to_string(),
            created_at_unix: 1_770_000_000,
        }
    }

    fn fixture_signature() -> PrivateResultOramSignature {
        PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-result-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        }
    }

    fn fixture_bucket(bucket_id: u64, epoch: u64, plaintext: &[u8]) -> PrivateResultOramBucket {
        let (ciphertext, ciphertext_sha256) = bucket_ciphertext(plaintext);
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext,
            ciphertext_sha256: ciphertext_sha256.clone(),
            bucket_commitment: fixture_bucket_commitment(bucket_id, epoch, &ciphertext_sha256),
        }
    }

    fn fixture_bucket_commitment(bucket_id: u64, epoch: u64, ciphertext_sha256: &str) -> String {
        private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/result-private-rk",
                rk_id: "tenant-a/result-private-rk",
                rk_epoch: 7,
                bucket_id,
                index_epoch: epoch,
            },
            ciphertext_sha256,
        )
        .unwrap()
    }

    fn fixture_upload_bundle() -> PrivateResultOramUploadBundle {
        let buckets = vec![
            fixture_bucket(0, 42, b"encrypted result bucket 0"),
            fixture_bucket(1, 42, b"encrypted result bucket 1"),
            fixture_bucket(2, 42, b"encrypted result bucket 2"),
        ];
        let commitments = buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        let mut manifest = fixture_manifest();
        manifest.bucket_count = buckets.len() as u64;
        manifest.logical_result_count = 2;
        manifest.dummy_result_count = 1;
        manifest.root_hash =
            PrivateResultOramStore::merkle_root_for_commitments(&commitments).unwrap();
        PrivateResultOramUploadBundle {
            manifest,
            manifest_signature: fixture_signature(),
            buckets,
        }
    }

    #[test]
    fn missing_layout_reads_fail_as_not_found() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);

        let err = store.read_manifest().unwrap_err();
        assert!(matches!(err, CollectionError::NotFound { .. }));

        let err = store.read_current_epoch().unwrap_err();
        assert!(matches!(err, CollectionError::NotFound { .. }));
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
        let epoch = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };

        store
            .write_initial_epoch_if_absent_or_matching(&epoch)
            .unwrap();

        assert_eq!(store.read_current_epoch().unwrap(), epoch);
    }

    #[test]
    fn initial_epoch_reupload_is_idempotent_and_conflict_preserves_current() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let conflicting_epoch = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(43),
        };

        store
            .write_initial_epoch_if_absent_or_matching(&epoch)
            .unwrap();
        store
            .write_initial_epoch_if_absent_or_matching(&epoch)
            .unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), epoch);

        let err = store
            .write_initial_epoch_if_absent_or_matching(&conflicting_epoch)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("current epoch/root does not match uploaded manifest")
        );
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
    }

    #[test]
    fn bucket_write_rejects_hash_mismatch_and_oversize() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(3, 42, b"encrypted result bucket");

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

    #[cfg(unix)]
    #[test]
    fn bucket_read_rejects_symlink_file() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside_bucket = temp.path().join("outside.bucket");
        std::fs::write(&outside_bucket, b"{}").unwrap();
        std::os::unix::fs::symlink(
            &outside_bucket,
            store.root_path().join(BUCKETS_DIR).join("00000000.bucket"),
        )
        .unwrap();

        let err = store.read_bucket(0, 42, 1, 128).unwrap_err();

        assert!(err.to_string().contains("non-symlink regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_layout_rejects_root_symlink_without_chmod_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().unwrap();
        let outside_dir = temp.path().join("outside-private-result");
        fs::create_dir(&outside_dir).unwrap();
        fs::set_permissions(&outside_dir, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&outside_dir, temp.path().join(PRIVATE_RESULT_ORAM_DIR)).unwrap();
        let store = fixture_store(&temp);

        let err = store.ensure_layout().unwrap_err();

        assert!(err.to_string().contains("non-symlink directory"));
        let outside_mode = fs::metadata(&outside_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(outside_mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn bucket_directory_group_world_accessible_rejects() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        fs::set_permissions(
            store.root_path().join(BUCKETS_DIR),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let err = store.read_bucket(0, 42, 1, 128).unwrap_err();

        assert!(err.to_string().contains("group/world accessible"));
    }

    #[cfg(unix)]
    #[test]
    fn bucket_file_group_world_accessible_rejects() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(0, 42, b"encrypted result bucket");
        store.write_bucket(&bucket, 42, 1, 128).unwrap();
        fs::set_permissions(
            store.root_path().join(BUCKETS_DIR).join("00000000.bucket"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let err = store.read_bucket(0, 42, 1, 128).unwrap_err();

        assert!(err.to_string().contains("group/world accessible"));
    }

    #[test]
    fn initial_upload_bundle_writes_manifest_buckets_merkle_and_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();

        let epoch = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        assert_eq!(
            epoch,
            PrivateResultOramEpochState {
                index_epoch: bundle.manifest.index_epoch,
                root_hash: bundle.manifest.root_hash.clone(),
            }
        );
        assert_eq!(
            store.read_manifest().unwrap(),
            (bundle.manifest.clone(), bundle.manifest_signature.clone()),
        );
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
        assert_eq!(
            store
                .read_bucket(1, bundle.manifest.index_epoch, 3, 128)
                .unwrap(),
            bundle.buckets[1],
        );
        let proof = store
            .read_merkle_path_batch(
                &[1],
                bundle.manifest.index_epoch,
                &bundle.manifest.root_hash,
                3,
            )
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );
        verify_private_result_oram_merkle_proof(
            &proof,
            bundle.manifest.index_epoch,
            &bundle.manifest.root_hash,
            bundle.manifest.bucket_count,
            &[bundle.buckets[1].clone()],
        )
        .unwrap();
    }

    #[test]
    fn initial_upload_bundle_rejects_root_mismatch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let mut bundle = fixture_upload_bundle();
        let computed_root = PrivateResultOramStore::merkle_root_for_commitments(
            &bundle
                .buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        bundle.manifest.root_hash = root_hash(99);
        assert_ne!(computed_root, bundle.manifest.root_hash);

        let err = store.write_initial_upload_bundle(&bundle, 128).unwrap_err();

        assert!(err.to_string().contains("Merkle root does not match"));
        assert!(!err.to_string().contains(&computed_root));
    }

    #[test]
    fn initial_upload_bundle_preflights_existing_epoch_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle();
        store.write_initial_upload_bundle(&original, 128).unwrap();

        let mut replacement = fixture_upload_bundle();
        replacement.buckets[0] = fixture_bucket(0, 42, b"replacement encrypted result bucket");
        let replacement_commitments = replacement
            .buckets
            .iter()
            .map(|bucket| bucket.bucket_commitment.clone())
            .collect::<Vec<_>>();
        replacement.manifest.root_hash =
            PrivateResultOramStore::merkle_root_for_commitments(&replacement_commitments).unwrap();

        let err = store
            .write_initial_upload_bundle(&replacement, 128)
            .unwrap_err();

        assert!(err.to_string().contains("current epoch/root"));
        assert_eq!(store.read_manifest().unwrap().0, original.manifest);
        assert_eq!(
            store
                .read_bucket(0, original.manifest.index_epoch, 3, 128)
                .unwrap(),
            original.buckets[0],
        );
        let proof = store
            .read_merkle_path_batch(
                &[0],
                original.manifest.index_epoch,
                &original.manifest.root_hash,
                3,
            )
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            original.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_files_to_match() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle();
        store.write_initial_upload_bundle(&original, 128).unwrap();
        store.write_initial_upload_bundle(&original, 128).unwrap();

        let replacement = fixture_bucket(
            0,
            original.manifest.index_epoch,
            b"same root different encrypted result bucket",
        );
        assert_ne!(replacement, original.buckets[0]);
        store
            .write_bucket(&replacement, original.manifest.index_epoch, 3, 128)
            .unwrap();

        let err = store
            .write_initial_upload_bundle(&original, 128)
            .unwrap_err();

        assert!(err.to_string().contains("existing bucket set"));
        assert_eq!(
            store
                .read_bucket(0, original.manifest.index_epoch, 3, 128)
                .unwrap(),
            replacement,
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_manifest_to_match() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle();
        store.write_initial_upload_bundle(&original, 128).unwrap();

        let mut tampered_signature = original.manifest_signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        store
            .write_manifest(&original.manifest, &tampered_signature)
            .unwrap();

        let err = store
            .write_initial_upload_bundle(&original, 128)
            .unwrap_err();

        assert!(err.to_string().contains("existing manifest"));
        assert_eq!(store.read_manifest().unwrap().1, tampered_signature);
        assert_eq!(
            store.read_current_epoch().unwrap().root_hash,
            original.manifest.root_hash
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_merkle_tree_to_match() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle();
        store.write_initial_upload_bundle(&original, 128).unwrap();

        let tampered_bucket = fixture_bucket(
            1,
            original.manifest.index_epoch,
            b"tampered result bucket for merkle tree",
        );
        let mut tampered_commitments = original.bucket_commitments();
        tampered_commitments[1] = tampered_bucket.bucket_commitment.clone();
        let tampered_root =
            PrivateResultOramStore::merkle_root_for_commitments(&tampered_commitments).unwrap();
        assert_ne!(tampered_root, original.manifest.root_hash);
        store
            .write_merkle_tree_from_commitments(
                original.manifest.index_epoch,
                tampered_root.clone(),
                tampered_commitments,
            )
            .unwrap();

        let err = store
            .write_initial_upload_bundle(&original, 128)
            .unwrap_err();

        assert!(err.to_string().contains("existing Merkle tree"));
        assert_eq!(
            store.read_current_epoch().unwrap().root_hash,
            original.manifest.root_hash
        );
        assert_eq!(store.read_merkle_tree().unwrap().root_hash, tampered_root);
    }

    #[test]
    fn writeback_commit_updates_bucket_merkle_and_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let updated_bucket = fixture_bucket(1, 43, b"updated result bucket 1");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[1] = updated_bucket.bucket_commitment.clone();
        let new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let committed = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                &[updated_bucket.clone()],
                128,
            )
            .unwrap();

        assert_eq!(committed, new);
        assert_eq!(store.read_current_epoch().unwrap(), new);
        assert_eq!(
            store
                .read_bucket(1, new.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            updated_bucket,
        );
        assert_eq!(
            store
                .read_bucket(0, new.index_epoch, bundle.bucket_count(), 128)
                .unwrap()
                .index_epoch,
            old.index_epoch,
        );
        let err = store
            .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
            .unwrap_err();
        assert!(err.to_string().contains("newer than requested epoch"));
        let proof = store
            .read_merkle_path_batch(&[1], new.index_epoch, &new.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(proof.leaves[0].leaf_hash, updated_bucket.bucket_commitment);

        let err = store
            .commit_writeback(&old, &new, bundle.bucket_count(), &[], 128)
            .unwrap_err();
        assert!(err.to_string().contains("RootHashMismatch"));
    }

    #[test]
    fn writeback_commit_preflights_stale_current_epoch_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let stale_current = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let updated_bucket = fixture_bucket(0, 43, b"stale writeback bucket");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[0] = updated_bucket.bucket_commitment.clone();
        let attempted_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &attempted_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
            )
            .unwrap_err();

        assert!(err.to_string().contains("RootHashMismatch"));
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[0],
        );
        let proof = store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn writeback_commit_rejects_bucket_commitment_context_mismatch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let valid_bucket = fixture_bucket(1, 43, b"updated result bucket 1");
        let mut invalid_bucket = valid_bucket.clone();
        invalid_bucket.bucket_commitment = root_hash(88);
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[1] = invalid_bucket.bucket_commitment.clone();
        let new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&invalid_bucket),
                128,
            )
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("commit bucket commitment context mismatch")
        );
        assert_eq!(
            store
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1]
        );
        let proof = store
            .read_merkle_path_batch(&[1], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );
    }

    #[test]
    fn writeback_commit_preflights_manifest_epoch_root_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let mut tampered_manifest = bundle.manifest.clone();
        tampered_manifest.root_hash = root_hash(99);
        assert_ne!(tampered_manifest.root_hash, old.root_hash);
        store
            .write_manifest(&tampered_manifest, &bundle.manifest_signature)
            .unwrap();

        let updated_bucket = fixture_bucket(1, 43, b"manifest drift result bucket");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[1] = updated_bucket.bucket_commitment.clone();
        let attempted_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &attempted_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
            )
            .unwrap_err();

        assert!(err.to_string().contains("manifest epoch/root"));
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1]
        );
        let proof = store
            .read_merkle_path_batch(&[1], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );
    }

    #[test]
    fn writeback_commit_preflights_manifest_bucket_count_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let mut tampered_manifest = bundle.manifest.clone();
        tampered_manifest.bucket_count += 1;
        store
            .write_manifest(&tampered_manifest, &bundle.manifest_signature)
            .unwrap();

        let updated_bucket = fixture_bucket(2, 43, b"manifest bucket count drift");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[2] = updated_bucket.bucket_commitment.clone();
        let attempted_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &attempted_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
            )
            .unwrap_err();

        assert!(err.to_string().contains("manifest bucket_count"));
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(2, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[2]
        );
        let proof = store
            .read_merkle_path_batch(&[2], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[2].bucket_commitment
        );
    }

    #[test]
    fn merkle_commit_updates_root_consistently() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3), root_hash(4)];
        let old_root =
            PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        assert_eq!(
            private_result_oram_merkle_root_for_commitments(&leaf_commitments).unwrap(),
            old_root,
        );
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(2, 43, b"updated result bucket");
        let mut next_commitments = leaf_commitments;
        next_commitments[2] = updated_bucket.bucket_commitment.clone();
        let new_root =
            PrivateResultOramStore::merkle_root_for_commitments(&next_commitments).unwrap();

        let wrong_new_root = root_hash(99);
        assert_ne!(wrong_new_root, new_root);
        let err = store
            .prepare_merkle_commit(
                42,
                &old_root,
                43,
                &wrong_new_root,
                4,
                &[updated_bucket.clone()],
            )
            .unwrap_err();
        assert!(err.to_string().contains("new_root_hash mismatch"));
        assert!(!err.to_string().contains(&new_root));

        store
            .prepare_merkle_commit(42, &old_root, 43, &new_root, 4, &[updated_bucket])
            .unwrap()
            .write()
            .unwrap();

        let err = store
            .prepare_merkle_commit(42, &old_root, 43, &new_root, 4, &[])
            .unwrap_err();
        assert!(err.to_string().contains("epoch mismatch"));
    }

    #[test]
    fn merkle_commit_rejects_duplicate_bucket_updates() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2)];
        let old_root =
            PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), leaf_commitments)
            .unwrap();

        let first = fixture_bucket(1, 43, b"first update");
        let second = fixture_bucket(1, 43, b"second update");

        let err = store
            .prepare_merkle_commit(42, &old_root, 43, &root_hash(43), 2, &[first, second])
            .unwrap_err();

        assert!(err.to_string().contains("repeats bucket 1"));
    }

    #[test]
    fn merkle_path_batch_returns_leaf_hashes_and_siblings() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let leaf_commitments = vec![root_hash(1), root_hash(2), root_hash(3)];
        let root = PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        store
            .write_merkle_tree_from_commitments(42, root.clone(), leaf_commitments.clone())
            .unwrap();

        let proof = store.read_merkle_path_batch(&[0, 2], 42, &root, 3).unwrap();
        assert_eq!(proof.kind, PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND);
        assert_eq!(proof.index_epoch, 42);
        assert_eq!(proof.root_hash, root);
        assert_eq!(proof.bucket_count, 3);
        assert_eq!(proof.leaves[0].bucket_id, 0);
        assert_eq!(proof.leaves[0].leaf_hash, leaf_commitments[0]);
        assert_eq!(proof.leaves[1].bucket_id, 2);
        assert_eq!(proof.leaves[1].leaf_hash, leaf_commitments[2]);
        assert_eq!(
            proof.leaves[0].siblings[0].position,
            PrivateResultOramMerkleSiblingPosition::Right
        );
        assert_eq!(
            proof.leaves[1].siblings[0].position,
            PrivateResultOramMerkleSiblingPosition::Right
        );

        let duplicate_proof = store
            .read_merkle_path_batch(&[0, 2, 0], 42, &root, 3)
            .unwrap();
        assert_eq!(duplicate_proof.leaves.len(), 3);
        assert_eq!(duplicate_proof.leaves[0], duplicate_proof.leaves[2]);

        let err = store
            .read_merkle_path_batch(&[3], 42, &root, 3)
            .unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn merkle_tree_validation_rejects_root_mismatch_without_computed_root() {
        let tree = PrivateResultOramMerkleTree {
            version: 1,
            index_epoch: 42,
            root_hash: root_hash(99),
            bucket_count: 2,
            leaf_hashes: vec![root_hash(1), root_hash(2)],
        };
        let computed_root =
            PrivateResultOramStore::merkle_root_for_commitments(&tree.leaf_hashes).unwrap();
        assert_ne!(computed_root, tree.root_hash);

        let err = validate_merkle_tree(&tree).unwrap_err();

        assert!(err.to_string().contains("root_hash mismatch"));
        assert!(!err.to_string().contains(&computed_root));
    }

    #[test]
    fn epoch_cas_rejects_stale_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let stale = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(41),
        };
        let new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };

        store.write_initial_epoch(&old).unwrap();
        let err = store.compare_and_swap_epoch(&stale, &new).unwrap_err();
        assert!(err.to_string().contains("RootHashMismatch"));

        store.compare_and_swap_epoch(&old, &new).unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), new);
    }
}
