use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PrivateResultOramBucket,
    PrivateResultOramBucketCommitmentContext, PrivateResultOramBucketValidationContext,
    PrivateResultOramCommitBucketRef, PrivateResultOramCommitSignatureInput,
    PrivateResultOramManifest, PrivateResultOramManifestValidationContext,
    PrivateResultOramMerkleProof, PrivateResultOramMerkleProofLeaf, PrivateResultOramMerkleSibling,
    PrivateResultOramMerkleSiblingPosition, PrivateResultOramSignature,
    PrivateResultOramSignatureVerification, PrivateResultOramUploadBundle,
    private_result_oram_bucket_ciphertext_bytes, private_result_oram_bucket_commitment,
    validate_private_result_oram_bucket_shape, validate_private_result_oram_commit_signature,
    validate_private_result_oram_upload_bundle,
    validate_private_result_oram_upload_bundle_with_signature,
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

    pub fn write_initial_upload_bundle_with_signature(
        &self,
        bundle: &PrivateResultOramUploadBundle,
        max_ciphertext_bytes: usize,
        validation_context: PrivateResultOramManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        validate_upload_bundle_with_signature(bundle, max_ciphertext_bytes, validation_context)?;
        self.write_initial_upload_bundle(bundle, max_ciphertext_bytes)
    }

    fn initial_epoch_status(
        &self,
        epoch: &PrivateResultOramEpochState,
        operation: &str,
    ) -> CollectionResult<InitialEpochStatus> {
        self.ensure_layout()?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => Ok(InitialEpochStatus::Matching),
            Ok(_) => Err(CollectionError::bad_request(format!(
                "private result ORAM current epoch/root does not match {operation} epoch",
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

    pub fn validate_bucket_for_write(
        &self,
        bucket: &PrivateResultOramBucket,
        expected_epoch: u64,
        bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        validate_bucket(bucket, expected_epoch, bucket_count, max_ciphertext_bytes)
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
            return Err(CollectionError::service_error(
                "private result ORAM bucket file id mismatch",
            ));
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
            Ok(_) => Err(CollectionError::bad_request(
                "private result ORAM current epoch/root does not match uploaded manifest epoch",
            )),
            Err(CollectionError::NotFound { .. }) => self.write_initial_epoch(epoch),
            Err(err) => Err(err),
        }
    }

    pub fn write_manifest_with_initial_epoch_if_absent_or_matching(
        &self,
        manifest: &PrivateResultOramManifest,
        signature: &PrivateResultOramSignature,
        epoch: &PrivateResultOramEpochState,
    ) -> CollectionResult<()> {
        self.ensure_layout()?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => match self.read_manifest() {
                Ok((stored_manifest, stored_signature))
                    if stored_manifest.index_epoch == current.index_epoch
                        && stored_manifest.root_hash == current.root_hash =>
                {
                    if stored_manifest != *manifest || stored_signature != *signature {
                        return Err(CollectionError::bad_request(
                            "private result ORAM manifest upload does not match existing current manifest",
                        ));
                    }
                    Ok(())
                }
                Ok(_) | Err(CollectionError::NotFound { .. }) => {
                    self.write_manifest(manifest, signature)
                }
                Err(err) => Err(err),
            },
            Ok(_) => Err(CollectionError::bad_request(
                "private result ORAM current epoch/root does not match uploaded manifest epoch",
            )),
            Err(CollectionError::NotFound { .. }) => {
                self.write_manifest(manifest, signature)?;
                self.write_initial_epoch(epoch)
            }
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
            return Err(CollectionError::bad_request(
                "private result ORAM RootHashMismatch: current epoch/root does not match old epoch",
            ));
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
        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM commit must update at least one bucket",
            ));
        }
        if new.index_epoch <= old.index_epoch {
            return Err(CollectionError::bad_request(
                "private result ORAM commit new epoch must be greater than old epoch",
            ));
        }
        self.ensure_current_epoch_matches(old)?;
        let (manifest, _) = self.read_manifest()?;
        validate_commit_manifest_context(&manifest, old, bucket_count)?;
        for bucket in updated_buckets {
            validate_bucket(bucket, new.index_epoch, bucket_count, max_ciphertext_bytes)?;
            validate_bucket_ciphertext_fixed_size(bucket, &manifest)?;
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

    pub fn commit_writeback_with_signature(
        &self,
        old: &PrivateResultOramEpochState,
        new: &PrivateResultOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateResultOramBucket],
        max_ciphertext_bytes: usize,
        commit_signature: &PrivateResultOramSignature,
        signature_verification: PrivateResultOramSignatureVerification<'_>,
    ) -> CollectionResult<PrivateResultOramEpochState> {
        let (manifest, _) = self.read_manifest()?;
        let updated_bucket_refs = updated_buckets
            .iter()
            .map(|bucket| PrivateResultOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect::<Vec<_>>();
        validate_private_result_oram_commit_signature(
            PrivateResultOramCommitSignatureInput {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                old_epoch: old.index_epoch,
                new_epoch: new.index_epoch,
                old_root_hash: &old.root_hash,
                new_root_hash: &new.root_hash,
                updated_buckets: &updated_bucket_refs,
                signature_alg: &commit_signature.alg,
                signature_key_id: &commit_signature.key_id,
            },
            &commit_signature.sig,
            signature_verification,
        )
        .map_err(private_result_oram_error)?;
        self.commit_writeback(
            old,
            new,
            bucket_count,
            updated_buckets,
            max_ciphertext_bytes,
        )
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
        if bucket_ids.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle proof bucket batch is empty",
            ));
        }
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
                return Err(CollectionError::bad_request(
                    "private result ORAM Merkle proof bucket is out of range",
                ));
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

    pub fn read_bucket_batch_with_proof(
        &self,
        bucket_ids: &[u64],
        expected_epoch: u64,
        expected_root_hash: &str,
        expected_bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<(Vec<PrivateResultOramBucket>, PrivateResultOramMerkleProof)> {
        if bucket_ids.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM bucket batch is empty",
            ));
        }
        let expected = PrivateResultOramEpochState {
            index_epoch: expected_epoch,
            root_hash: expected_root_hash.to_string(),
        };
        self.ensure_current_epoch_matches(&expected)?;
        let proof = self.read_merkle_path_batch(
            bucket_ids,
            expected_epoch,
            expected_root_hash,
            expected_bucket_count,
        )?;
        let mut buckets = Vec::with_capacity(bucket_ids.len());
        for &bucket_id in bucket_ids {
            buckets.push(self.read_bucket(
                bucket_id,
                expected_epoch,
                expected_bucket_count,
                max_ciphertext_bytes,
            )?);
        }
        ensure_read_proof_matches_buckets(&proof, &buckets)?;
        Ok((buckets, proof))
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
        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle commit must update at least one bucket",
            ));
        }
        let mut tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(&tree, old_epoch, old_root_hash, bucket_count)?;
        let mut seen_bucket_ids = std::collections::BTreeSet::new();
        for bucket in updated_buckets {
            if !seen_bucket_ids.insert(bucket.bucket_id) {
                return Err(CollectionError::bad_request(
                    "private result ORAM Merkle commit repeats a bucket",
                ));
            }
            if bucket.index_epoch != new_epoch {
                return Err(CollectionError::bad_request(
                    "private result ORAM Merkle commit bucket has stale epoch",
                ));
            }
            if bucket.bucket_id >= bucket_count {
                return Err(CollectionError::bad_request(
                    "private result ORAM Merkle commit bucket is out of range",
                ));
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
            return Err(CollectionError::bad_request(
                "private result ORAM RootHashMismatch: current epoch/root does not match old epoch",
            ));
        }
        Ok(())
    }
}

impl PrivateResultPreparedMerkleCommit {
    pub fn write(self) -> CollectionResult<()> {
        self.store.write_merkle_tree(&self.tree)
    }
}

fn ensure_read_proof_matches_buckets(
    proof: &PrivateResultOramMerkleProof,
    buckets: &[PrivateResultOramBucket],
) -> CollectionResult<()> {
    if proof.leaves.len() != buckets.len() {
        return Err(CollectionError::bad_request(
            "private result ORAM encrypted bucket/proof consistency validation failed",
        ));
    }
    for (leaf, bucket) in proof.leaves.iter().zip(buckets) {
        if leaf.bucket_id != bucket.bucket_id || leaf.leaf_hash != bucket.bucket_commitment {
            return Err(CollectionError::bad_request(
                "private result ORAM encrypted bucket/proof consistency validation failed",
            ));
        }
    }
    Ok(())
}

fn validate_merkle_tree(tree: &PrivateResultOramMerkleTree) -> CollectionResult<()> {
    if tree.version != 1 {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree has unsupported version",
        ));
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
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree epoch mismatch",
        ));
    }
    if tree.root_hash != expected_root_hash {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree root_hash mismatch",
        ));
    }
    if tree.bucket_count != expected_bucket_count {
        return Err(CollectionError::bad_request(
            "private result ORAM Merkle tree bucket_count mismatch",
        ));
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
        let Some(previous) = levels.last() else {
            return Err(CollectionError::bad_request(
                "private result ORAM Merkle tree is invalid",
            ));
        };
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
        return Err(CollectionError::bad_request(
            "private result ORAM bucket has stale epoch",
        ));
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

fn validate_bucket_ciphertext_fixed_size(
    bucket: &PrivateResultOramBucket,
    manifest: &PrivateResultOramManifest,
) -> CollectionResult<()> {
    let expected = private_result_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(private_result_oram_error)?;
    let expected_b64_len = base64url_nopad_encoded_len(expected)?;
    if bucket.ciphertext.len() != expected_b64_len {
        return Err(CollectionError::bad_request(
            "private result ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            CollectionError::bad_request("private result ORAM bucket ciphertext is not base64url")
        })?;
    if ciphertext.len() != expected {
        return Err(CollectionError::bad_request(
            "private result ORAM bucket ciphertext must match fixed ciphertext size",
        ));
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
        return Err(CollectionError::bad_request(
            "private result ORAM bucket is newer than requested epoch",
        ));
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

fn validate_upload_bundle_with_signature(
    bundle: &PrivateResultOramUploadBundle,
    max_ciphertext_bytes: usize,
    validation_context: PrivateResultOramManifestValidationContext<'_>,
) -> CollectionResult<Vec<String>> {
    let leaf_commitments =
        validate_private_result_oram_upload_bundle_with_signature(bundle, validation_context)
            .map_err(private_result_oram_error)?;
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

fn base64url_nopad_encoded_len(byte_len: usize) -> CollectionResult<usize> {
    let full_chunks = byte_len / 3;
    let tail_len = match byte_len % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => {
            return Err(CollectionError::bad_request(
                "private result ORAM bucket ciphertext size overflows",
            ));
        }
    };
    full_chunks
        .checked_mul(4)
        .and_then(|len| len.checked_add(tail_len))
        .ok_or_else(|| {
            CollectionError::bad_request("private result ORAM bucket ciphertext size overflows")
        })
}

fn private_result_oram_error(err: qdrant_sec::PrivateResultOramError) -> CollectionError {
    use qdrant_sec::PrivateResultOramError;

    let message = match err {
        PrivateResultOramError::Encryption(_) => "private result ORAM client encryption failed",
        PrivateResultOramError::UnsupportedManifestVersion(_) => {
            "private result ORAM manifest version is unsupported"
        }
        PrivateResultOramError::InvalidProvider => {
            "private result ORAM manifest provider is invalid"
        }
        PrivateResultOramError::InvalidBinding => "private result ORAM manifest binding is invalid",
        PrivateResultOramError::InvalidManifestField(_) => {
            "private result ORAM manifest field is invalid"
        }
        PrivateResultOramError::ManifestContextMismatch(_) => {
            "private result ORAM manifest field does not match runtime context"
        }
        PrivateResultOramError::MissingManifestSignature => {
            "private result ORAM manifest signature is missing"
        }
        PrivateResultOramError::UnsupportedSignatureAlgorithm(_) => {
            "private result ORAM signature algorithm must be ed25519"
        }
        PrivateResultOramError::SignatureKeyIdMismatch => {
            "private result ORAM signature key id does not match runtime context"
        }
        PrivateResultOramError::MalformedSignature => "private result ORAM signature is malformed",
        PrivateResultOramError::InvalidManifestSignature => {
            "private result ORAM manifest signature verification failed"
        }
        PrivateResultOramError::InvalidCommitSignature => {
            "private result ORAM commit signature verification failed"
        }
        PrivateResultOramError::InvalidReadBucketsSignature => {
            "private result ORAM read_buckets signature verification failed"
        }
        PrivateResultOramError::InvalidResourceKeyId => {
            "private result ORAM resource key id is invalid"
        }
        PrivateResultOramError::UnsupportedBucketVersion(_) => {
            "private result ORAM bucket version is unsupported"
        }
        PrivateResultOramError::UnsupportedBucketCiphertextVersion(_) => {
            "private result ORAM bucket ciphertext uses unsupported version"
        }
        PrivateResultOramError::UnsupportedPayloadBlockVersion(_) => {
            "private result ORAM payload block uses unsupported version"
        }
        PrivateResultOramError::UnsupportedClientStateSnapshotVersion(_) => {
            "private result ORAM client state snapshot uses unsupported version"
        }
        PrivateResultOramError::UnsupportedClientStateCiphertextVersion(_) => {
            "private result ORAM client state uses unsupported ciphertext version"
        }
        PrivateResultOramError::BucketOutOfRange { .. } => {
            "private result ORAM bucket is out of range"
        }
        PrivateResultOramError::InvalidBucketField(_) => {
            "private result ORAM bucket field is invalid"
        }
        PrivateResultOramError::BucketOversized => {
            "private result ORAM bucket ciphertext exceeds maximum size"
        }
        PrivateResultOramError::InvalidBucketHash => {
            "private result ORAM bucket ciphertext_sha256 mismatch"
        }
        PrivateResultOramError::InvalidBucketCiphertextEncoding => {
            "private result ORAM bucket ciphertext is malformed"
        }
        PrivateResultOramError::InvalidBucketCiphertextHash => {
            "private result ORAM bucket ciphertext hash mismatch"
        }
        PrivateResultOramError::BucketOpenFailed => {
            "private result ORAM bucket decryption authentication failed"
        }
        PrivateResultOramError::BucketMetadataMismatch => {
            "private result ORAM bucket metadata does not match context"
        }
        PrivateResultOramError::InvalidBucketContext(_) => {
            "private result ORAM bucket context is invalid"
        }
        PrivateResultOramError::InvalidBucketCommitment => {
            "private result ORAM bucket commitment context mismatch"
        }
        PrivateResultOramError::EmptyMerkleTree => "private result ORAM Merkle tree is empty",
        PrivateResultOramError::MerkleRootMismatch => {
            "private result ORAM Merkle root does not match current commitments"
        }
        PrivateResultOramError::ManifestCommitMismatch => {
            "private result ORAM manifest epoch/root does not match commit old epoch/root"
        }
        PrivateResultOramError::StaleBucketEpoch { .. } => {
            "private result ORAM bucket epoch does not match expected epoch"
        }
        PrivateResultOramError::DuplicateUpdatedBucket { .. } => {
            "private result ORAM commit repeats a bucket"
        }
        PrivateResultOramError::EmptyCommit => {
            "private result ORAM commit must update at least one bucket"
        }
        PrivateResultOramError::InvalidMerkleProof => {
            "private result ORAM Merkle proof is malformed"
        }
        PrivateResultOramError::InvalidMerkleProofJson => {
            "private result ORAM Merkle proof JSON is malformed"
        }
        PrivateResultOramError::MerkleProofMismatch => {
            "private result ORAM Merkle proof does not match bucket commitments"
        }
        PrivateResultOramError::InvalidFetchPlanField(_) => {
            "private result ORAM fetch plan field is invalid"
        }
        PrivateResultOramError::MissingPayloadFetchTokenPosition => {
            "private result ORAM fetch token position is missing"
        }
        PrivateResultOramError::DuplicatePayloadFetchToken => {
            "private result ORAM fetch token appears more than once"
        }
        PrivateResultOramError::DuplicatePayloadFetchTokenPosition => {
            "private result ORAM fetch token position appears more than once"
        }
        PrivateResultOramError::InvalidClientConfig(_) => {
            "private result ORAM client config is invalid"
        }
        PrivateResultOramError::InvalidPayloadBlock => {
            "private result ORAM payload block is malformed"
        }
        PrivateResultOramError::InvalidPayloadBlockPadding => {
            "private result ORAM payload block padding is invalid"
        }
        PrivateResultOramError::PayloadBlockOversized => {
            "private result ORAM payload block exceeds configured size"
        }
        PrivateResultOramError::InvalidBucketPlaintext => {
            "private result ORAM bucket plaintext is malformed"
        }
        PrivateResultOramError::BucketPlaintextSlotCountMismatch => {
            "private result ORAM bucket plaintext slot count does not match config"
        }
        PrivateResultOramError::MissingPosition => {
            "private result ORAM client position map is missing a token"
        }
        PrivateResultOramError::MissingBlock => {
            "private result ORAM path did not contain requested block"
        }
        PrivateResultOramError::PathBucketMismatch => {
            "private result ORAM path buckets do not match requested leaf"
        }
        PrivateResultOramError::InvalidClientStateSnapshot => {
            "private result ORAM client state snapshot is malformed"
        }
        PrivateResultOramError::InvalidClientStateContext(_) => {
            "private result ORAM client state context is invalid"
        }
        PrivateResultOramError::InvalidClientStateCiphertextEncoding => {
            "private result ORAM client state ciphertext is not base64url"
        }
        PrivateResultOramError::InvalidClientStateCiphertextHash => {
            "private result ORAM client state ciphertext hash is invalid"
        }
        PrivateResultOramError::ClientStateOpenFailed => {
            "private result ORAM client state decryption authentication failed"
        }
    };
    CollectionError::bad_request(message)
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
    let created = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            return Err(CollectionError::service_error(
                "private result ORAM path must be a non-symlink directory",
            ));
        }
        Ok(_) => false,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| {
                CollectionError::service_error("failed to create private result ORAM directory")
            })?;
            let metadata = fs::symlink_metadata(path).map_err(|_| {
                CollectionError::service_error("failed to inspect private result ORAM directory")
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(CollectionError::service_error(
                    "private result ORAM path must be a non-symlink directory",
                ));
            }
            true
        }
        Err(_) => {
            return Err(CollectionError::service_error(
                "failed to inspect private result ORAM directory",
            ));
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if created {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                CollectionError::service_error("failed to harden private result ORAM directory")
            })?;
        }
    }
    validate_private_dir(path)
}

fn validate_private_dir(path: &Path) -> CollectionResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            return CollectionError::not_found("private result ORAM directory");
        }
        CollectionError::service_error("failed to inspect private result ORAM directory")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CollectionError::service_error(
            "private result ORAM path must be a non-symlink directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if metadata.uid() != effective_uid {
            return Err(CollectionError::service_error(
                "private result ORAM directory must be owned by the current user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "private result ORAM directory must not be group/world accessible",
            ));
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
    file.read_to_end(&mut bytes)
        .map_err(|_| CollectionError::service_error("failed to read private result ORAM file"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| CollectionError::bad_request("private result ORAM file contains invalid JSON"))
}

fn write_json_atomic<T: Serialize>(
    root: &Path,
    temp_dir: &Path,
    target: &Path,
    value: &T,
) -> CollectionResult<()> {
    validate_target_under_root(root, target)?;
    validate_private_dir(temp_dir)?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| {
        CollectionError::service_error("failed to serialize private result ORAM file")
    })?;
    let temp_path = unique_temp_path(temp_dir);
    let mut file = open_private_file_for_write(&temp_path)?;
    file.write_all(&bytes).map_err(|_| {
        CollectionError::service_error("failed to write private result ORAM temp file")
    })?;
    file.flush().map_err(|_| {
        CollectionError::service_error("failed to flush private result ORAM temp file")
    })?;
    file.sync_all().map_err(|_| {
        CollectionError::service_error("failed to sync private result ORAM temp file")
    })?;
    drop(file);

    fs::rename(&temp_path, target).map_err(|_| {
        let _ = fs::remove_file(&temp_path);
        CollectionError::service_error("failed to replace private result ORAM file")
    })?;
    if let Some(parent) = target.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn validate_target_under_root(root: &Path, target: &Path) -> CollectionResult<()> {
    if !target.starts_with(root) {
        return Err(CollectionError::service_error(
            "private result ORAM target escapes root",
        ));
    }
    if let Some(parent) = target.parent() {
        validate_private_dir(parent)?;
    }
    Ok(())
}

fn open_private_file_for_read(path: &Path, max_bytes: u64) -> CollectionResult<File> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            return CollectionError::not_found("private result ORAM file");
        }
        CollectionError::service_error("failed to inspect private result ORAM file")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CollectionError::service_error(
            "private result ORAM file must be a non-symlink regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CollectionError::bad_request(
            "private result ORAM file exceeds maximum size",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "private result ORAM file must not be group/world accessible",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| {
                CollectionError::service_error("failed to open private result ORAM file")
            })?;
        return Ok(file);
    }
    #[cfg(not(unix))]
    {
        File::open(path)
            .map_err(|_| CollectionError::service_error("failed to open private result ORAM file"))
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
    options.open(path).map_err(|_| {
        CollectionError::service_error("failed to create private result ORAM temp file")
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
    let file = File::open(path).map_err(|_| {
        CollectionError::service_error("failed to open private result ORAM directory for sync")
    })?;
    file.sync_all()
        .map_err(|_| CollectionError::service_error("failed to sync private result ORAM directory"))
}

#[cfg(test)]
mod tests {
    use qdrant_sec::{
        OramKind, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING,
        PrivateResultOramBucketCommitmentContext, PrivateResultOramClientCommitBucketRef,
        PrivateResultOramCommitPlan, PrivateResultOramCommitSignatureContext,
        PrivateResultOramError, PrivateResultOramSignatureVerification,
        private_result_oram_bucket_commitment, private_result_oram_merkle_root_for_commitments,
        sign_private_result_oram_commit, sign_private_result_oram_manifest,
        verify_private_result_oram_merkle_proof,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::TempDir;

    use super::*;

    fn root_hash(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    fn bucket_ciphertext(bytes: &[u8]) -> (String, String) {
        let expected =
            qdrant_sec::private_result_oram_bucket_ciphertext_bytes(&fixture_manifest().oram)
                .unwrap();
        assert!(bytes.len() <= expected);
        let mut ciphertext = vec![0; expected];
        ciphertext[..bytes.len()].copy_from_slice(bytes);
        (
            BASE64URL_NOPAD.encode(&ciphertext),
            BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref()),
        )
    }

    fn max_base64url_nopad_encoded_len_for_test(byte_len: usize) -> usize {
        let full_chunks = byte_len / 3;
        let remainder = byte_len % 3;
        full_chunks * 4
            + match remainder {
                0 => 0,
                1 => 2,
                2 => 3,
                _ => unreachable!("remainder modulo 3"),
            }
    }

    #[test]
    fn private_result_oram_error_mapping_redacts_structured_values() {
        let cases = [
            (
                private_result_oram_error(PrivateResultOramError::UnsupportedManifestVersion(
                    65_000,
                )),
                vec!["65000"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::UnsupportedSignatureAlgorithm(
                    "rsa-pss-777777".to_string(),
                )),
                vec!["rsa-pss-777777", "777777"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::UnsupportedBucketVersion(65_000)),
                vec!["65000"],
            ),
            (
                private_result_oram_error(
                    PrivateResultOramError::UnsupportedBucketCiphertextVersion(77),
                ),
                vec!["77"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::UnsupportedPayloadBlockVersion(
                    65_000,
                )),
                vec!["65000"],
            ),
            (
                private_result_oram_error(
                    PrivateResultOramError::UnsupportedClientStateSnapshotVersion(65_000),
                ),
                vec!["65000"],
            ),
            (
                private_result_oram_error(
                    PrivateResultOramError::UnsupportedClientStateCiphertextVersion(65_000),
                ),
                vec!["65000"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::BucketOutOfRange {
                    bucket_id: 777_777,
                    bucket_count: 888_888,
                }),
                vec!["777777", "888888"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::StaleBucketEpoch {
                    bucket_id: 777_777,
                    expected_epoch: 888_888,
                    actual_epoch: 999_999,
                }),
                vec!["777777", "888888", "999999"],
            ),
            (
                private_result_oram_error(PrivateResultOramError::DuplicateUpdatedBucket {
                    bucket_id: 777_777,
                }),
                vec!["777777"],
            ),
        ];

        for (err, needles) in cases {
            let rendered = err.to_string();
            for needle in needles {
                assert!(!rendered.contains(needle), "{rendered}");
            }
        }
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
                block_size_bytes: 8,
                tree_height: 1,
                path_batch_size: 2,
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

    fn signed_fixture_upload_bundle(key_pair: &Ed25519KeyPair) -> PrivateResultOramUploadBundle {
        let mut bundle = fixture_upload_bundle();
        bundle.manifest_signature =
            sign_private_result_oram_manifest(key_pair, &bundle.manifest).unwrap();
        bundle
    }

    fn fixture_validation_context<'a>(
        public_key: &'a [u8],
    ) -> PrivateResultOramManifestValidationContext<'a> {
        PrivateResultOramManifestValidationContext {
            expected_collection_id: "collection-uuid-1",
            expected_key_id: "tenant-a/result-private-rk",
            expected_rk_id: "tenant-a/result-private-rk",
            min_rk_epoch: 7,
            max_rk_epoch: 7,
            signature_verification: PrivateResultOramSignatureVerification {
                expected_key_id: "tenant-a/private-result-signing-v1",
                public_key,
            },
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
        let rendered = err.to_string();
        assert!(rendered.contains("current epoch/root does not match uploaded manifest"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains(&epoch.root_hash), "{rendered}");
        assert!(
            !rendered.contains(&conflicting_epoch.root_hash),
            "{rendered}"
        );
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
    }

    #[test]
    fn current_manifest_reupload_requires_existing_manifest_to_match() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let manifest = fixture_manifest();
        let signature = fixture_signature();
        let epoch = PrivateResultOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        };

        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(&manifest, &signature, &epoch)
            .unwrap();
        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(&manifest, &signature, &epoch)
            .unwrap();

        let mut replacement = manifest.clone();
        replacement.logical_result_count += 1;
        replacement.dummy_result_count -= 1;
        let replacement_signature = PrivateResultOramSignature {
            sig: BASE64URL_NOPAD.encode(&[8; 64]),
            ..signature.clone()
        };
        let rendered = store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &replacement,
                &replacement_signature,
                &epoch,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("manifest upload does not match existing current manifest"));
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
        assert_eq!(store.read_manifest().unwrap(), (manifest, signature));
    }

    #[test]
    fn post_commit_manifest_refresh_allows_current_epoch_ahead_of_stored_manifest() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_manifest = fixture_manifest();
        let old_signature = fixture_signature();
        let old_epoch = PrivateResultOramEpochState {
            index_epoch: old_manifest.index_epoch,
            root_hash: old_manifest.root_hash.clone(),
        };
        let mut new_manifest = old_manifest.clone();
        new_manifest.index_epoch = old_manifest.index_epoch + 1;
        new_manifest.root_hash = root_hash(43);
        let new_signature = PrivateResultOramSignature {
            sig: BASE64URL_NOPAD.encode(&[8; 64]),
            ..old_signature.clone()
        };
        let new_epoch = PrivateResultOramEpochState {
            index_epoch: new_manifest.index_epoch,
            root_hash: new_manifest.root_hash.clone(),
        };

        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &old_manifest,
                &old_signature,
                &old_epoch,
            )
            .unwrap();
        store
            .compare_and_swap_epoch(&old_epoch, &new_epoch)
            .unwrap();
        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &new_manifest,
                &new_signature,
                &new_epoch,
            )
            .unwrap();

        assert_eq!(store.read_current_epoch().unwrap(), new_epoch);
        assert_eq!(
            store.read_manifest().unwrap(),
            (new_manifest, new_signature)
        );
    }

    #[test]
    fn manifest_initial_epoch_publish_requires_manifest_write_success() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let manifest = fixture_manifest();
        let signature = fixture_signature();
        let epoch = PrivateResultOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        };
        store.ensure_layout().unwrap();
        fs::create_dir(store.root_path().join(MANIFEST_SIGNATURE_FILE)).unwrap();

        store
            .write_manifest_with_initial_epoch_if_absent_or_matching(&manifest, &signature, &epoch)
            .unwrap_err();

        assert!(
            matches!(
                store.read_current_epoch().unwrap_err(),
                CollectionError::NotFound { .. }
            ),
            "failed initial manifest upload must not publish current epoch",
        );
    }

    #[test]
    fn bucket_write_rejects_hash_mismatch_and_oversize() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(3, 42, b"encrypted result bucket");

        store
            .validate_bucket_for_write(&bucket, 42, 16, 128)
            .unwrap();
        store.write_bucket(&bucket, 42, 16, 128).unwrap();
        assert_eq!(store.read_bucket(3, 42, 16, 128).unwrap(), bucket);

        let mut bad_hash = bucket.clone();
        bad_hash.ciphertext_sha256 = root_hash(1);
        let err = store
            .validate_bucket_for_write(&bad_hash, 42, 16, 128)
            .unwrap_err();
        assert!(err.to_string().contains("ciphertext_sha256 mismatch"));
        let err = store.write_bucket(&bad_hash, 42, 16, 128).unwrap_err();
        assert!(err.to_string().contains("ciphertext_sha256 mismatch"));

        let oversized = fixture_bucket(4, 42, &[8; 65]);
        let err = store
            .validate_bucket_for_write(&oversized, 42, 16, 64)
            .unwrap_err();
        assert!(err.to_string().contains("exceeds maximum size"));
        let err = store.write_bucket(&oversized, 42, 16, 64).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum size"));

        let mut encoded_oversized = bucket.clone();
        encoded_oversized.bucket_id = 5;
        encoded_oversized.ciphertext = "A".repeat(max_base64url_nopad_encoded_len_for_test(64) + 1);
        encoded_oversized.ciphertext_sha256 = root_hash(2);
        let err = store
            .validate_bucket_for_write(&encoded_oversized, 42, 16, 64)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("exceeds maximum size"));
        assert!(!rendered.contains("ciphertext_sha256 mismatch"));
        assert!(!rendered.contains(&encoded_oversized.ciphertext));

        let out_of_range = fixture_bucket(99, 42, b"out of range result bucket");
        let err = store
            .validate_bucket_for_write(&out_of_range, 42, 16, 64)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("99"), "{rendered}");
        assert!(!rendered.contains("16"), "{rendered}");
        let err = store.write_bucket(&out_of_range, 42, 16, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("99"), "{rendered}");
        assert!(!rendered.contains("16"), "{rendered}");
    }

    #[test]
    fn bucket_read_rejects_file_id_mismatch_without_ciphertext_leak() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let mut mismatched_bucket = fixture_bucket(1, 42, b"encrypted result bucket mismatch");
        mismatched_bucket.ciphertext =
            BASE64URL_NOPAD.encode(b"private-result-bucket-ciphertext-sentinel");
        write_json_atomic(
            store.root_path(),
            &store.temp_dir(),
            &store.root_path().join(BUCKETS_DIR).join("00000000.bucket"),
            &mismatched_bucket,
        )
        .unwrap();

        let err = store.read_bucket(0, 42, 2, 128).unwrap_err();
        let err = err.to_string();

        assert!(err.contains("bucket file id mismatch"));
        assert!(!err.contains("requested"));
        assert!(!err.contains("found"));
        assert!(!err.contains("private-result-bucket-ciphertext-sentinel"));
        assert!(!err.contains(&mismatched_bucket.ciphertext));
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

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink regular file"));
        assert!(!rendered.contains("outside.bucket"), "{rendered}");
        assert!(!rendered.contains("00000000.bucket"), "{rendered}");
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

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink directory"));
        assert!(!rendered.contains("outside-private-result"), "{rendered}");
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        let outside_mode = fs::metadata(&outside_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(outside_mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn temp_directory_symlink_rejects_without_path_or_temp_name_leak() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside_temp = temp.path().join("outside-private-result-temp");
        fs::create_dir(&outside_temp).unwrap();
        fs::set_permissions(&outside_temp, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir(store.root_path().join(TEMP_DIR)).unwrap();
        symlink(&outside_temp, store.root_path().join(TEMP_DIR)).unwrap();

        let err = store
            .write_initial_epoch(&PrivateResultOramEpochState {
                index_epoch: 42,
                root_hash: root_hash(42),
            })
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink directory"));
        assert!(
            !rendered.contains("outside-private-result-temp"),
            "{rendered}"
        );
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        assert!(!rendered.contains("private-result-oram-"), "{rendered}");
        let outside_mode = fs::metadata(&outside_temp).unwrap().permissions().mode() & 0o777;
        assert_eq!(outside_mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn temp_directory_group_world_accessible_rejects_without_path_leak() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        fs::set_permissions(
            store.root_path().join(TEMP_DIR),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let err = store
            .write_initial_epoch(&PrivateResultOramEpochState {
                index_epoch: 42,
                root_hash: root_hash(42),
            })
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        assert!(!rendered.contains("private-result-oram-"), "{rendered}");
        assert!(matches!(
            store.read_current_epoch(),
            Err(CollectionError::NotFound { .. })
        ));
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

        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
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

        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("00000000.bucket"), "{rendered}");
    }

    #[test]
    fn initial_upload_bundle_writes_manifest_buckets_merkle_and_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();

        let mut bad_alg_bundle = bundle.clone();
        let signature_alg_sentinel = "private-result-signature-alg-sentinel";
        bad_alg_bundle.manifest_signature.alg = signature_alg_sentinel.to_string();
        let err = store
            .write_initial_upload_bundle(&bad_alg_bundle, 128)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature algorithm must be ed25519"));
        assert!(!rendered.contains(signature_alg_sentinel), "{rendered}");

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
    fn initial_upload_bundle_with_signature_verifies_manifest_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
        let bundle = signed_fixture_upload_bundle(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                128,
                fixture_validation_context(key_pair.public_key().as_ref()),
            )
            .unwrap();
        assert_eq!(epoch.index_epoch, bundle.manifest.index_epoch);
        assert_eq!(
            store.read_manifest().unwrap(),
            (bundle.manifest.clone(), bundle.manifest_signature.clone()),
        );

        let mut tampered = bundle.clone();
        tampered.manifest_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let rendered = store
            .write_initial_upload_bundle_with_signature(
                &tampered,
                128,
                fixture_validation_context(key_pair.public_key().as_ref()),
            )
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest signature verification failed"));
        assert!(!rendered.contains(&tampered.manifest_signature.sig));
        assert!(
            !store.root_path().exists(),
            "invalid signed upload must not create private result ORAM layout"
        );
        assert!(matches!(
            store.read_current_epoch(),
            Err(CollectionError::NotFound { .. })
        ));
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

        let empty_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: old.root_hash.clone(),
        };
        let err = store
            .commit_writeback(&old, &empty_new, bundle.bucket_count(), &[], 128)
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));

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
                .unwrap(),
            bundle.buckets[0],
        );
        let err = store
            .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains("1"), "{rendered}");
        let proof = store
            .read_merkle_path_batch(&[1], new.index_epoch, &new.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(proof.leaves[0].leaf_hash, updated_bucket.bucket_commitment);

        let err = store
            .commit_writeback(&old, &new, bundle.bucket_count(), &[], 128)
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));
    }

    #[test]
    fn writeback_commit_with_signature_verifies_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let bundle = fixture_upload_bundle();
        let updated_bucket = fixture_bucket(1, 43, b"updated signed result bucket 1");
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[1] = updated_bucket.bucket_commitment.clone();
        let new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };
        let plan = PrivateResultOramCommitPlan {
            old_epoch: bundle.manifest.index_epoch,
            new_epoch: new.index_epoch,
            old_root_hash: bundle.manifest.root_hash.clone(),
            new_root_hash: new.root_hash.clone(),
            leaf_commitments: next_commitments,
            updated_buckets: vec![PrivateResultOramClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }],
        };
        let signature = sign_private_result_oram_commit(
            &key_pair,
            PrivateResultOramCommitSignatureContext {
                collection_id: "collection-uuid-1",
                key_id: "tenant-a/result-private-rk",
                rk_id: "tenant-a/result-private-rk",
                rk_epoch: 7,
                signing_key_id: "tenant-a/private-result-signing-v1",
            },
            &plan,
        )
        .unwrap();

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let committed = store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id: "tenant-a/private-result-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
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

        let temp = TempDir::new().unwrap();
        let tampered_store = fixture_store(&temp);
        let old = tampered_store
            .write_initial_upload_bundle(&bundle, 128)
            .unwrap();
        let mut tampered_signature = signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        let rendered = tampered_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &tampered_signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id: "tenant-a/private-result-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("commit signature verification failed"));
        assert!(!rendered.contains(&tampered_signature.sig), "{rendered}");
        assert_eq!(tampered_store.read_current_epoch().unwrap(), old);
        assert_eq!(
            tampered_store
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1],
        );
        let proof = tampered_store
            .read_merkle_path_batch(&[1], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );

        let temp = TempDir::new().unwrap();
        let unsupported_alg_store = fixture_store(&temp);
        let old = unsupported_alg_store
            .write_initial_upload_bundle(&bundle, 128)
            .unwrap();
        let mut unsupported_alg_signature = signature.clone();
        unsupported_alg_signature.alg = "rsa-pss-result-sentinel".to_string();
        let rendered = unsupported_alg_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &unsupported_alg_signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id: "tenant-a/private-result-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("signature algorithm must be ed25519"));
        assert!(
            !rendered.contains(&unsupported_alg_signature.alg),
            "{rendered}"
        );
        assert_eq!(unsupported_alg_store.read_current_epoch().unwrap(), old);
        assert_eq!(
            unsupported_alg_store
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1],
        );
        let proof = unsupported_alg_store
            .read_merkle_path_batch(&[1], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );

        let temp = TempDir::new().unwrap();
        let wrong_key_store = fixture_store(&temp);
        let old = wrong_key_store
            .write_initial_upload_bundle(&bundle, 128)
            .unwrap();
        let mut wrong_key_signature = signature.clone();
        wrong_key_signature.key_id = "tenant-a/private-result-signing-v2".to_string();
        let rendered = wrong_key_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
                &wrong_key_signature,
                PrivateResultOramSignatureVerification {
                    expected_key_id: "tenant-a/private-result-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("signature key id does not match runtime context"));
        assert!(
            !rendered.contains(&wrong_key_signature.key_id),
            "{rendered}"
        );
        assert_eq!(wrong_key_store.read_current_epoch().unwrap(), old);
        assert_eq!(
            wrong_key_store
                .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1],
        );
        let proof = wrong_key_store
            .read_merkle_path_batch(&[1], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[1].bucket_commitment
        );
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

        let rendered = err.to_string();
        assert!(rendered.contains("RootHashMismatch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&stale_current.root_hash), "{rendered}");
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
    fn writeback_commit_rejects_non_advancing_epoch_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let original_bucket = bundle.buckets[0].clone();
        let updated_bucket =
            fixture_bucket(0, old.index_epoch, b"private-result-non-advancing-sentinel");
        let non_advancing_new = PrivateResultOramEpochState {
            index_epoch: old.index_epoch,
            root_hash: root_hash(99),
        };

        let err = store
            .commit_writeback(
                &old,
                &non_advancing_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                128,
            )
            .unwrap_err();
        let err = err.to_string();

        assert!(err.contains("new epoch must be greater than old epoch"));
        assert!(!err.contains("private-result-non-advancing-sentinel"));
        assert!(!err.contains(&updated_bucket.ciphertext));
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            original_bucket
        );
        let proof = store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(proof.leaves[0].leaf_hash, original_bucket.bucket_commitment);
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
    fn writeback_commit_rejects_invalid_bucket_and_root_mismatch_before_writes() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let original_bucket = bundle.buckets[1].clone();
        let assert_writeback_target_unchanged = || {
            assert_eq!(store.read_current_epoch().unwrap(), old);
            assert_eq!(
                store
                    .read_bucket(1, old.index_epoch, bundle.bucket_count(), 128)
                    .unwrap(),
                original_bucket
            );
            let proof = store
                .read_merkle_path_batch(
                    &[1],
                    old.index_epoch,
                    &old.root_hash,
                    bundle.bucket_count(),
                )
                .unwrap();
            assert_eq!(proof.leaves[0].leaf_hash, original_bucket.bucket_commitment);
        };

        let mut hash_mismatch_bucket = fixture_bucket(1, 43, b"hash mismatch result bucket");
        hash_mismatch_bucket.ciphertext =
            BASE64URL_NOPAD.encode(b"private-result-writeback-ciphertext-sentinel");
        let mut hash_mismatch_commitments = bundle.bucket_commitments();
        hash_mismatch_commitments[1] = hash_mismatch_bucket.bucket_commitment.clone();
        let hash_mismatch_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(
                &hash_mismatch_commitments,
            )
            .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &hash_mismatch_new,
                bundle.bucket_count(),
                std::slice::from_ref(&hash_mismatch_bucket),
                128,
            )
            .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("ciphertext_sha256 mismatch"));
        assert!(!err.contains("private-result-writeback-ciphertext-sentinel"));
        assert!(!err.contains(&hash_mismatch_bucket.ciphertext));
        assert_writeback_target_unchanged();

        let mut short_ciphertext_bucket =
            fixture_bucket(1, 43, b"valid hash with short result bucket");
        let short_raw = b"short-result-commit";
        let short_hash = BASE64URL_NOPAD.encode(Sha256::digest(short_raw).as_ref());
        short_ciphertext_bucket.ciphertext = BASE64URL_NOPAD.encode(short_raw);
        short_ciphertext_bucket.ciphertext_sha256 = short_hash.clone();
        short_ciphertext_bucket.bucket_commitment = fixture_bucket_commitment(1, 43, &short_hash);
        let mut short_ciphertext_commitments = bundle.bucket_commitments();
        short_ciphertext_commitments[1] = short_ciphertext_bucket.bucket_commitment.clone();
        let short_ciphertext_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(
                &short_ciphertext_commitments,
            )
            .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &short_ciphertext_new,
                bundle.bucket_count(),
                std::slice::from_ref(&short_ciphertext_bucket),
                128,
            )
            .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("fixed ciphertext size"));
        assert!(!err.contains("short-result-commit"));
        assert!(!err.contains(&short_ciphertext_bucket.ciphertext));
        assert_writeback_target_unchanged();

        let expected_bytes =
            private_result_oram_bucket_ciphertext_bytes(&bundle.manifest.oram).unwrap();
        let mut long_ciphertext_bucket =
            fixture_bucket(1, 43, b"valid hash with long result bucket");
        let long_raw = vec![7; expected_bytes + 1];
        let long_hash = BASE64URL_NOPAD.encode(Sha256::digest(&long_raw).as_ref());
        long_ciphertext_bucket.ciphertext = BASE64URL_NOPAD.encode(&long_raw);
        long_ciphertext_bucket.ciphertext_sha256 = long_hash.clone();
        long_ciphertext_bucket.bucket_commitment = fixture_bucket_commitment(1, 43, &long_hash);
        let mut long_ciphertext_commitments = bundle.bucket_commitments();
        long_ciphertext_commitments[1] = long_ciphertext_bucket.bucket_commitment.clone();
        let long_ciphertext_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: PrivateResultOramStore::merkle_root_for_commitments(
                &long_ciphertext_commitments,
            )
            .unwrap(),
        };

        let err = store
            .commit_writeback(
                &old,
                &long_ciphertext_new,
                bundle.bucket_count(),
                std::slice::from_ref(&long_ciphertext_bucket),
                128,
            )
            .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("fixed ciphertext size"));
        assert!(!err.contains(&long_ciphertext_bucket.ciphertext));
        assert_writeback_target_unchanged();

        let valid_bucket = fixture_bucket(1, 43, b"valid result bucket with wrong root");
        let wrong_root_new = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(99),
        };

        let err = store
            .commit_writeback(
                &old,
                &wrong_root_new,
                bundle.bucket_count(),
                std::slice::from_ref(&valid_bucket),
                128,
            )
            .unwrap_err();
        assert!(err.to_string().contains("new_root_hash mismatch"));
        assert_writeback_target_unchanged();
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
            .prepare_merkle_commit(42, &old_root, 43, &old_root, 4, &[])
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));

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
        assert!(err.to_string().contains("must update at least one bucket"));
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

        let rendered = err.to_string();
        assert!(rendered.contains("repeats a bucket"));
        assert!(!rendered.contains("1"), "{rendered}");
    }

    #[test]
    fn merkle_path_batch_returns_leaf_hashes_and_siblings() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket0 = fixture_bucket(0, 42, b"encrypted result bucket 0");
        let bucket1 = fixture_bucket(1, 42, b"encrypted result bucket 1");
        let bucket2 = fixture_bucket(2, 42, b"encrypted result bucket 2");
        let leaf_commitments = vec![
            bucket0.bucket_commitment.clone(),
            bucket1.bucket_commitment.clone(),
            bucket2.bucket_commitment.clone(),
        ];
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
        verify_private_result_oram_merkle_proof(
            &duplicate_proof,
            42,
            &root,
            3,
            &[bucket0.clone(), bucket2, bucket0],
        )
        .unwrap();

        let err = store.read_merkle_path_batch(&[], 42, &root, 3).unwrap_err();
        assert!(err.to_string().contains("bucket batch is empty"));

        let err = store
            .read_merkle_path_batch(&[3], 42, &root, 3)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("3"), "{rendered}");
    }

    #[test]
    fn read_bucket_batch_with_proof_checks_current_epoch_and_commitments() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let current = store.write_initial_upload_bundle(&bundle, 128).unwrap();

        let (buckets, proof) = store
            .read_bucket_batch_with_proof(
                &[0, 2, 0],
                current.index_epoch,
                &current.root_hash,
                bundle.bucket_count(),
                128,
            )
            .unwrap();

        assert_eq!(
            buckets,
            vec![
                bundle.buckets[0].clone(),
                bundle.buckets[2].clone(),
                bundle.buckets[0].clone(),
            ]
        );
        assert_eq!(proof.leaves.len(), buckets.len());
        assert_eq!(proof.leaves[0], proof.leaves[2]);
        verify_private_result_oram_merkle_proof(
            &proof,
            current.index_epoch,
            &current.root_hash,
            bundle.bucket_count(),
            &buckets,
        )
        .unwrap();

        let replacement = fixture_bucket(
            2,
            current.index_epoch,
            b"private-result-read-bucket-mismatch-sentinel",
        );
        assert_ne!(
            replacement.bucket_commitment,
            bundle.buckets[2].bucket_commitment
        );
        store
            .write_bucket(
                &replacement,
                current.index_epoch,
                bundle.bucket_count(),
                128,
            )
            .unwrap();
        let rendered = store
            .read_bucket_batch_with_proof(
                &[2],
                current.index_epoch,
                &current.root_hash,
                bundle.bucket_count(),
                128,
            )
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("encrypted bucket/proof consistency validation failed"));
        assert!(!rendered.contains("private-result-read-bucket-mismatch-sentinel"));
        assert!(!rendered.contains(&replacement.ciphertext));
        assert!(!rendered.contains(&replacement.bucket_commitment));

        let rendered = store
            .read_bucket_batch_with_proof(
                &[],
                current.index_epoch,
                &current.root_hash,
                bundle.bucket_count(),
                128,
            )
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("bucket batch is empty"));
    }

    #[test]
    fn read_bucket_batch_with_proof_preflights_stale_current_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bundle = fixture_upload_bundle();
        let old = store.write_initial_upload_bundle(&bundle, 128).unwrap();
        let stale_current = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let rendered = store
            .read_bucket_batch_with_proof(
                &[1],
                old.index_epoch,
                &old.root_hash,
                bundle.bucket_count(),
                128,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("RootHashMismatch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&stale_current.root_hash), "{rendered}");
        assert_eq!(
            store
                .read_bucket(1, stale_current.index_epoch, bundle.bucket_count(), 128)
                .unwrap(),
            bundle.buckets[1],
        );
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
        let rendered = err.to_string();
        assert!(rendered.contains("RootHashMismatch"));
        assert!(!rendered.contains("41"), "{rendered}");
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&stale.root_hash), "{rendered}");
        assert!(!rendered.contains(&new.root_hash), "{rendered}");

        store.compare_and_swap_epoch(&old, &new).unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), new);
    }
}
