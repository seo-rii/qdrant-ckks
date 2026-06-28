use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    PrivateHnswBucketAeadContext, PrivateHnswManifestValidationContext, PrivateHnswOramBucket,
    PrivateHnswOramCommitBucketRef, PrivateHnswOramCommitSignatureInput, PrivateHnswOramManifest,
    PrivateHnswOramSignature, PrivateHnswOramUploadBundle, PrivateHnswSignatureVerification,
    private_hnsw_bucket_commitment, private_hnsw_oram_bucket_ciphertext_bytes,
    validate_private_hnsw_oram_commit_signature, validate_private_hnsw_oram_upload_bundle,
    validate_private_hnsw_oram_upload_bundle_with_signature,
};
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
const BUCKET_JSON_OVERHEAD_BYTES: usize = 32 * 1024;
pub const PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND: &str = "merkle_path_batch/v1";

#[derive(Clone)]
pub struct PrivateHnswOramStore {
    root: PathBuf,
}

impl Debug for PrivateHnswOramStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramStore")
            .field("root", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramEpochState {
    pub index_epoch: u64,
    pub root_hash: String,
}

impl Debug for PrivateHnswOramEpochState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramEpochState")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramMerkleProof {
    pub kind: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub bucket_count: u64,
    pub leaves: Vec<PrivateHnswOramMerkleProofLeaf>,
}

impl Debug for PrivateHnswOramMerkleProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramMerkleProof")
            .field("kind", &self.kind)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &self.bucket_count)
            .field("leaf_count", &self.leaves.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramMerkleProofLeaf {
    pub bucket_id: u64,
    pub leaf_hash: String,
    pub siblings: Vec<PrivateHnswOramMerkleSibling>,
}

impl Debug for PrivateHnswOramMerkleProofLeaf {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramMerkleProofLeaf")
            .field("bucket_id", &"[redacted]")
            .field("leaf_hash", &"[redacted]")
            .field("sibling_count", &self.siblings.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHnswOramMerkleSibling {
    pub level: u32,
    pub position: MerkleSiblingPosition,
    pub hash: String,
}

impl Debug for PrivateHnswOramMerkleSibling {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramMerkleSibling")
            .field("level", &self.level)
            .field("position", &self.position)
            .field("hash", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MerkleSiblingPosition {
    Left,
    Right,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateHnswOramMerkleTree {
    version: u16,
    index_epoch: u64,
    root_hash: String,
    bucket_count: u64,
    leaf_hashes: Vec<String>,
}

impl Debug for PrivateHnswOramMerkleTree {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswOramMerkleTree")
            .field("version", &self.version)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &self.bucket_count)
            .field("leaf_hash_count", &self.leaf_hashes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitialEpochStatus {
    Absent,
    Matching,
}

#[derive(Clone)]
pub struct PrivateHnswPreparedMerkleCommit {
    store: PrivateHnswOramStore,
    tree: PrivateHnswOramMerkleTree,
}

impl Debug for PrivateHnswPreparedMerkleCommit {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswPreparedMerkleCommit")
            .field("store", &self.store)
            .field("tree", &self.tree)
            .finish()
    }
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
        let private_hnsw_dir = self.root.parent().ok_or_else(|| {
            CollectionError::service_error("private HNSW ORAM store path is invalid")
        })?;
        create_private_dir(private_hnsw_dir)?;
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

    pub fn write_initial_upload_bundle(
        &self,
        bundle: &PrivateHnswOramUploadBundle,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        let leaf_commitments = validate_upload_bundle(bundle, max_ciphertext_bytes)?;
        let epoch = PrivateHnswOramEpochState {
            index_epoch: bundle.manifest.index_epoch,
            root_hash: bundle.manifest.root_hash.clone(),
        };

        match self.initial_epoch_status(&epoch)? {
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
        bundle: &PrivateHnswOramUploadBundle,
        max_ciphertext_bytes: usize,
        validation_context: PrivateHnswManifestValidationContext<'_>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        validate_upload_bundle_with_signature(bundle, max_ciphertext_bytes, validation_context)?;
        self.write_initial_upload_bundle(bundle, max_ciphertext_bytes)
    }

    fn initial_epoch_status(
        &self,
        epoch: &PrivateHnswOramEpochState,
    ) -> CollectionResult<InitialEpochStatus> {
        self.ensure_layout()?;
        match self.read_current_epoch() {
            Ok(current) if current == *epoch => Ok(InitialEpochStatus::Matching),
            Ok(_) => Err(CollectionError::bad_request(
                "private HNSW ORAM current epoch/root does not match initial epoch",
            )),
            Err(CollectionError::NotFound { .. }) => Ok(InitialEpochStatus::Absent),
            Err(err) => Err(err),
        }
    }

    fn validate_existing_initial_upload_bundle(
        &self,
        bundle: &PrivateHnswOramUploadBundle,
        leaf_commitments: &[String],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<()> {
        let (stored_manifest, stored_signature) = self.read_manifest()?;
        if stored_manifest != bundle.manifest || stored_signature != bundle.manifest_signature {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM initial upload bundle does not match existing manifest",
            ));
        }

        let stored_tree = self.read_merkle_tree()?;
        if stored_tree.index_epoch != bundle.manifest.index_epoch
            || stored_tree.root_hash != bundle.manifest.root_hash
            || stored_tree.bucket_count != bundle.manifest.bucket_count
            || stored_tree.leaf_hashes.as_slice() != leaf_commitments
        {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM initial upload bundle does not match existing Merkle tree",
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
                    "private HNSW ORAM initial upload bundle does not match existing bucket set",
                ));
            }
        }
        Ok(())
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

    pub fn validate_bucket_for_write(
        &self,
        bucket: &PrivateHnswOramBucket,
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
    ) -> CollectionResult<PrivateHnswOramBucket> {
        validate_private_dir(&self.buckets_dir())?;
        let max_bucket_file_bytes = max_bucket_file_bytes(max_ciphertext_bytes)?;
        let bucket: PrivateHnswOramBucket =
            read_json_private_file(&self.bucket_path(bucket_id), max_bucket_file_bytes)?;
        if bucket.bucket_id != bucket_id {
            return Err(CollectionError::service_error(
                "private HNSW ORAM bucket file id mismatch",
            ));
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
            Ok(_) => Err(CollectionError::bad_request(
                "private HNSW ORAM current epoch/root does not match uploaded manifest epoch",
            )),
            Err(CollectionError::NotFound { .. }) => self.write_initial_epoch(epoch),
            Err(err) => Err(err),
        }
    }

    pub fn write_manifest_with_initial_epoch_if_absent_or_matching(
        &self,
        manifest: &PrivateHnswOramManifest,
        signature: &PrivateHnswOramSignature,
        epoch: &PrivateHnswOramEpochState,
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
                            "private HNSW ORAM manifest upload does not match existing current manifest",
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
                "private HNSW ORAM current epoch/root does not match uploaded manifest epoch",
            )),
            Err(CollectionError::NotFound { .. }) => {
                self.write_manifest(manifest, signature)?;
                self.write_initial_epoch(epoch)
            }
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
            return Err(CollectionError::bad_request(
                "private HNSW ORAM RootHashMismatch: current epoch/root does not match old epoch",
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
        )?;
        Ok(())
    }

    pub fn commit_writeback(
        &self,
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM commit must update at least one bucket",
            ));
        }
        if new.index_epoch <= old.index_epoch {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM commit new epoch must be greater than old epoch",
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
        old: &PrivateHnswOramEpochState,
        new: &PrivateHnswOramEpochState,
        bucket_count: u64,
        updated_buckets: &[PrivateHnswOramBucket],
        max_ciphertext_bytes: usize,
        commit_signature: &PrivateHnswOramSignature,
        signature_verification: PrivateHnswSignatureVerification<'_>,
    ) -> CollectionResult<PrivateHnswOramEpochState> {
        let (manifest, _) = self.read_manifest()?;
        let updated_bucket_refs = updated_buckets
            .iter()
            .map(|bucket| PrivateHnswOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect::<Vec<_>>();
        validate_private_hnsw_oram_commit_signature(
            PrivateHnswOramCommitSignatureInput {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
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
        .map_err(private_hnsw_oram_error)?;
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
        let bucket_count = u64::try_from(leaf_hashes.len()).map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM Merkle tree bucket_count exceeds u64")
        })?;
        let tree = PrivateHnswOramMerkleTree {
            version: 1,
            index_epoch,
            root_hash,
            bucket_count,
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
        if bucket_ids.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle proof bucket batch is empty",
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
                    "private HNSW ORAM Merkle proof bucket is out of range",
                ));
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

    pub fn read_bucket_batch_with_proof(
        &self,
        bucket_ids: &[u64],
        expected_epoch: u64,
        expected_root_hash: &str,
        expected_bucket_count: u64,
        max_ciphertext_bytes: usize,
    ) -> CollectionResult<(Vec<PrivateHnswOramBucket>, PrivateHnswOramMerkleProof)> {
        if bucket_ids.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM bucket batch is empty",
            ));
        }
        let expected = PrivateHnswOramEpochState {
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
        updated_buckets: &[PrivateHnswOramBucket],
    ) -> CollectionResult<PrivateHnswPreparedMerkleCommit> {
        if new_epoch <= old_epoch {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle commit new epoch must be greater than old epoch",
            ));
        }
        if updated_buckets.is_empty() {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle commit must update at least one bucket",
            ));
        }
        let mut tree = self.read_merkle_tree()?;
        validate_merkle_tree_context(&tree, old_epoch, old_root_hash, bucket_count)?;
        let mut seen_bucket_ids = BTreeSet::new();
        for bucket in updated_buckets {
            if !seen_bucket_ids.insert(bucket.bucket_id) {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM Merkle commit repeats a bucket",
                ));
            }
            if bucket.index_epoch != new_epoch {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM Merkle commit bucket has stale epoch",
                ));
            }
            if bucket.bucket_id >= bucket_count {
                return Err(CollectionError::bad_request(
                    "private HNSW ORAM Merkle commit bucket is out of range",
                ));
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
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle commit new_root_hash mismatch",
            ));
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

    fn ensure_current_epoch_matches(
        &self,
        expected: &PrivateHnswOramEpochState,
    ) -> CollectionResult<()> {
        let current = self.read_current_epoch()?;
        if &current != expected {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM RootHashMismatch: current epoch/root does not match old epoch",
            ));
        }
        Ok(())
    }
}

impl PrivateHnswPreparedMerkleCommit {
    pub fn write(self) -> CollectionResult<()> {
        self.store.write_merkle_tree(&self.tree)
    }
}

fn ensure_read_proof_matches_buckets(
    proof: &PrivateHnswOramMerkleProof,
    buckets: &[PrivateHnswOramBucket],
) -> CollectionResult<()> {
    if proof.leaves.len() != buckets.len() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM encrypted bucket/proof consistency validation failed",
        ));
    }
    for (leaf, bucket) in proof.leaves.iter().zip(buckets) {
        if leaf.bucket_id != bucket.bucket_id || leaf.leaf_hash != bucket.bucket_commitment {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM encrypted bucket/proof consistency validation failed",
            ));
        }
    }
    Ok(())
}

fn validate_merkle_tree(tree: &PrivateHnswOramMerkleTree) -> CollectionResult<()> {
    if tree.version != 1 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree has unsupported version",
        ));
    }
    if tree.bucket_count == 0 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree bucket_count must be non-zero",
        ));
    }
    let leaf_hash_count = u64::try_from(tree.leaf_hashes.len()).map_err(|_| {
        CollectionError::bad_request("private HNSW ORAM Merkle tree leaf count exceeds u64")
    })?;
    if leaf_hash_count != tree.bucket_count {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree leaf count does not match bucket_count",
        ));
    }
    let computed_root = PrivateHnswOramStore::merkle_root_for_commitments(&tree.leaf_hashes)?;
    if computed_root != tree.root_hash {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree root_hash mismatch",
        ));
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
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree epoch mismatch",
        ));
    }
    if tree.root_hash != expected_root_hash {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree root_hash mismatch",
        ));
    }
    if tree.bucket_count != expected_bucket_count {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle tree bucket_count mismatch",
        ));
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
        let Some(previous) = levels.last() else {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM Merkle tree is invalid",
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
) -> CollectionResult<Vec<PrivateHnswOramMerkleSibling>> {
    if levels.is_empty() || index >= levels[0].len() {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM Merkle proof bucket index is out of range",
        ));
    }
    let sibling_level_count = levels.len().checked_sub(1).ok_or_else(|| {
        CollectionError::bad_request("private HNSW ORAM Merkle proof levels are invalid")
    })?;
    let mut siblings = Vec::with_capacity(sibling_level_count);
    for (level_index, level) in levels.iter().enumerate().take(sibling_level_count) {
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
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket has stale epoch",
        ));
    }
    Ok(())
}

fn validate_commit_manifest_context(
    manifest: &PrivateHnswOramManifest,
    old: &PrivateHnswOramEpochState,
    bucket_count: u64,
) -> CollectionResult<()> {
    if manifest.index_epoch != old.index_epoch || manifest.root_hash != old.root_hash {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM manifest epoch/root does not match commit old epoch/root",
        ));
    }
    if manifest.bucket_count != bucket_count {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM manifest bucket_count does not match commit bucket_count",
        ));
    }
    Ok(())
}

fn validate_bucket_commitment_context(
    manifest: &PrivateHnswOramManifest,
    index_epoch: u64,
    buckets: &[PrivateHnswOramBucket],
) -> CollectionResult<()> {
    for bucket in buckets {
        let expected_commitment = private_hnsw_bucket_commitment(
            PrivateHnswBucketAeadContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
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
                "private HNSW ORAM commit bucket commitment context mismatch",
            )
        })?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM commit bucket commitment context mismatch",
            ));
        }
    }
    Ok(())
}

fn validate_bucket_ciphertext_fixed_size(
    bucket: &PrivateHnswOramBucket,
    manifest: &PrivateHnswOramManifest,
) -> CollectionResult<()> {
    let expected = private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(private_hnsw_oram_error)?;
    let expected_b64_len = max_base64url_nopad_encoded_len(expected)?;
    if bucket.ciphertext.len() != expected_b64_len {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM bucket ciphertext is not base64url")
        })?;
    if ciphertext.len() != expected {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
        ));
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
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket is newer than requested epoch",
        ));
    }
    Ok(())
}

fn validate_bucket_shape(
    bucket: &PrivateHnswOramBucket,
    bucket_count: u64,
    max_ciphertext_bytes: usize,
) -> CollectionResult<()> {
    if bucket.version != 1 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket version is unsupported",
        ));
    }
    if bucket.bucket_id >= bucket_count {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket is out of range",
        ));
    }
    let max_ciphertext_b64_len = max_base64url_nopad_encoded_len(max_ciphertext_bytes)?;
    if bucket.ciphertext.len() > max_ciphertext_b64_len {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext exceeds maximum size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            CollectionError::bad_request("private HNSW ORAM bucket ciphertext is not base64url")
        })?;
    if ciphertext.len() > max_ciphertext_bytes {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext exceeds maximum size",
        ));
    }
    let sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref());
    if sha256 != bucket.ciphertext_sha256 {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM bucket ciphertext_sha256 mismatch",
        ));
    }
    decode_base64url_32(&bucket.bucket_commitment, "bucket_commitment")?;
    Ok(())
}

fn validate_upload_bundle(
    bundle: &PrivateHnswOramUploadBundle,
    max_ciphertext_bytes: usize,
) -> CollectionResult<Vec<String>> {
    let leaf_commitments =
        validate_private_hnsw_oram_upload_bundle(bundle).map_err(private_hnsw_client_error)?;
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
    bundle: &PrivateHnswOramUploadBundle,
    max_ciphertext_bytes: usize,
    validation_context: PrivateHnswManifestValidationContext<'_>,
) -> CollectionResult<Vec<String>> {
    let leaf_commitments =
        validate_private_hnsw_oram_upload_bundle_with_signature(bundle, validation_context)
            .map_err(private_hnsw_client_error)?;
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

fn private_hnsw_client_error(err: qdrant_sec::PrivateHnswClientError) -> CollectionError {
    use qdrant_sec::PrivateHnswClientError;

    let message = match err {
        PrivateHnswClientError::Encryption(_) => "private HNSW client encryption failed",
        PrivateHnswClientError::InvalidNeighborShape => {
            "private HNSW node block has invalid neighbor shape"
        }
        PrivateHnswClientError::TooManyNeighbors { .. } => {
            "private HNSW node block has too many neighbors"
        }
        PrivateHnswClientError::VectorTooLarge => "private HNSW node block vector is too large",
        PrivateHnswClientError::FixedNeighborSlotsTooLarge => {
            "private HNSW node block fixed neighbor slot count is too large"
        }
        PrivateHnswClientError::EncodedBlockOversized => {
            "private HNSW node block does not fit in configured block size"
        }
        PrivateHnswClientError::InvalidBlockEncoding => {
            "private HNSW node block encoding is malformed"
        }
        PrivateHnswClientError::UnsupportedBlockVersion(_) => {
            "private HNSW node block uses unsupported version"
        }
        PrivateHnswClientError::UnsupportedVectorEncoding(_) => {
            "private HNSW node block uses unsupported vector encoding"
        }
        PrivateHnswClientError::InvalidBlockPadding => "private HNSW node block padding is invalid",
        PrivateHnswClientError::InvalidBucketContext(_) => "private HNSW bucket context is invalid",
        PrivateHnswClientError::InvalidBucketCiphertextEncoding => {
            "private HNSW bucket ciphertext is not base64url"
        }
        PrivateHnswClientError::BucketCiphertextSizeMismatch { .. } => {
            "private HNSW bucket ciphertext length does not match expected fixed length"
        }
        PrivateHnswClientError::InvalidBucketCiphertextHash => {
            "private HNSW bucket ciphertext hash is invalid"
        }
        PrivateHnswClientError::InvalidBucketCommitment => {
            "private HNSW bucket commitment is invalid"
        }
        PrivateHnswClientError::BucketMetadataMismatch => {
            "private HNSW bucket metadata does not match the decrypt context"
        }
        PrivateHnswClientError::UnsupportedBucketCiphertextVersion(_) => {
            "private HNSW bucket uses unsupported ciphertext version"
        }
        PrivateHnswClientError::BucketOpenFailed => {
            "private HNSW bucket ciphertext authentication failed"
        }
        PrivateHnswClientError::InvalidTreeHeight => "private HNSW ORAM tree_height is invalid",
        PrivateHnswClientError::LeafOutOfRange => {
            "private HNSW ORAM leaf label is outside tree range"
        }
        PrivateHnswClientError::InvalidLeafLabelEncoding => {
            "private HNSW ORAM leaf label is not base64url"
        }
        PrivateHnswClientError::InvalidLeafLabelLength => {
            "private HNSW ORAM leaf label has invalid length"
        }
        PrivateHnswClientError::BucketCountMismatch => {
            "private HNSW ORAM bucket_count does not match tree_height"
        }
        PrivateHnswClientError::InvalidOramClientConfig(_) => {
            "private HNSW ORAM client config is invalid"
        }
        PrivateHnswClientError::InvalidBucketPlaintext => {
            "private HNSW ORAM bucket plaintext is malformed"
        }
        PrivateHnswClientError::BucketPlaintextMetadataMismatch => {
            "private HNSW ORAM bucket plaintext metadata does not match config"
        }
        PrivateHnswClientError::BucketPlaintextSlotCountMismatch => {
            "private HNSW ORAM bucket plaintext slot count does not match config"
        }
        PrivateHnswClientError::PathBucketMismatch => {
            "private HNSW ORAM path buckets do not match requested leaf"
        }
        PrivateHnswClientError::MissingPosition => {
            "private HNSW ORAM client position map is missing a node"
        }
        PrivateHnswClientError::MissingBlock => {
            "private HNSW ORAM path did not contain requested node"
        }
        PrivateHnswClientError::DuplicateBlock => {
            "private HNSW ORAM path contains duplicate node blocks"
        }
        PrivateHnswClientError::InvalidBuildConfig(_) => {
            "private HNSW ORAM build config is invalid"
        }
        PrivateHnswClientError::OramInitialPlacementOverflow { .. } => {
            "private HNSW ORAM initial placement overflowed path"
        }
        PrivateHnswClientError::UnsupportedClientStateSnapshotVersion(_) => {
            "private HNSW ORAM client state snapshot uses unsupported version"
        }
        PrivateHnswClientError::InvalidClientStateSnapshot => {
            "private HNSW ORAM client state snapshot is malformed"
        }
        PrivateHnswClientError::InvalidClientStateContext(_) => {
            "private HNSW ORAM client state context is invalid"
        }
        PrivateHnswClientError::InvalidClientStateCiphertextEncoding => {
            "private HNSW ORAM client state ciphertext is not base64url"
        }
        PrivateHnswClientError::InvalidClientStateCiphertextHash => {
            "private HNSW ORAM client state ciphertext hash is invalid"
        }
        PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(_) => {
            "private HNSW ORAM client state uses unsupported ciphertext version"
        }
        PrivateHnswClientError::ClientStateOpenFailed => {
            "private HNSW ORAM client state decryption authentication failed"
        }
        PrivateHnswClientError::InvalidSearchConfig(_) => "private HNSW search config is invalid",
        PrivateHnswClientError::UnsupportedSearchVectorEncoding => {
            "private HNSW search currently requires f32_le node vectors"
        }
        PrivateHnswClientError::InvalidF32VectorLength => {
            "private HNSW search f32 vector bytes are malformed"
        }
        PrivateHnswClientError::VectorDimensionMismatch => {
            "private HNSW search query and node vector dimensions differ"
        }
        PrivateHnswClientError::NonFiniteDistance => "private HNSW search distance is not finite",
        PrivateHnswClientError::FixedBudgetNotExhausted { .. } => {
            "private HNSW search did not exhaust the fixed access budget"
        }
        PrivateHnswClientError::MissingPayloadFetchToken => {
            "private HNSW private result mode requires payload fetch tokens"
        }
        PrivateHnswClientError::EmptyMerkleTree => {
            "private HNSW ORAM Merkle tree must contain at least one leaf"
        }
        PrivateHnswClientError::InvalidMerkleRoot => "private HNSW ORAM Merkle root is invalid",
        PrivateHnswClientError::MerkleRootMismatch => "private HNSW ORAM Merkle root mismatch",
        PrivateHnswClientError::InvalidCommitEpoch => {
            "private HNSW ORAM commit new_epoch must be greater than old_epoch"
        }
        PrivateHnswClientError::EmptyCommit => {
            "private HNSW ORAM commit must update at least one bucket"
        }
        PrivateHnswClientError::BucketOutOfRange { .. } => {
            "private HNSW ORAM bucket is out of range"
        }
        PrivateHnswClientError::DuplicateBucket { .. } => {
            "private HNSW ORAM upload contains duplicate bucket"
        }
        PrivateHnswClientError::MissingBucket { .. } => {
            "private HNSW ORAM upload is missing a configured bucket"
        }
        PrivateHnswClientError::DuplicateUpdatedBucket { .. } => {
            "private HNSW ORAM commit bucket appears more than once"
        }
        PrivateHnswClientError::StaleBucketEpoch { .. } => {
            "private HNSW ORAM commit bucket has stale epoch"
        }
        PrivateHnswClientError::UnsupportedBucketVersion(_) => {
            "private HNSW ORAM bucket uses unsupported version"
        }
        PrivateHnswClientError::InvalidCommitSignatureContext(_) => {
            "private HNSW ORAM commit signature context is invalid"
        }
        PrivateHnswClientError::InvalidManifestSignatureContext(_) => {
            "private HNSW ORAM manifest signature context is invalid"
        }
        PrivateHnswClientError::ManifestCommitMismatch => {
            "private HNSW ORAM manifest epoch/root does not match commit old epoch/root"
        }
        PrivateHnswClientError::InvalidMerkleProof => "private HNSW ORAM Merkle proof is malformed",
        PrivateHnswClientError::InvalidMerkleProofJson => {
            "private HNSW ORAM Merkle proof JSON is malformed"
        }
        PrivateHnswClientError::MerkleProofMismatch => {
            "private HNSW ORAM Merkle proof does not match buckets/root"
        }
    };
    CollectionError::bad_request(message)
}

fn private_hnsw_oram_error(err: qdrant_sec::PrivateHnswOramError) -> CollectionError {
    use qdrant_sec::PrivateHnswOramError;

    let message = match err {
        PrivateHnswOramError::UnsupportedManifestVersion(_) => {
            "private HNSW ORAM manifest version is unsupported"
        }
        PrivateHnswOramError::UnsupportedSignatureAlgorithm(_) => {
            "private HNSW ORAM signature algorithm must be ed25519"
        }
        PrivateHnswOramError::InvalidCommitSignature => {
            "private HNSW ORAM commit signature verification failed"
        }
        PrivateHnswOramError::MalformedSignature => "private HNSW ORAM signature is malformed",
        PrivateHnswOramError::InvalidProvider => "private HNSW ORAM manifest provider is invalid",
        PrivateHnswOramError::InvalidBinding => "private HNSW ORAM manifest binding is invalid",
        PrivateHnswOramError::InvalidManifestField(_) => {
            "private HNSW ORAM manifest field is invalid"
        }
        PrivateHnswOramError::ManifestContextMismatch(_) => {
            "private HNSW ORAM manifest field does not match runtime context"
        }
        PrivateHnswOramError::MissingManifestSignature => {
            "private HNSW ORAM manifest signature is missing"
        }
        PrivateHnswOramError::SignatureKeyIdMismatch => {
            "private HNSW ORAM manifest signature key id does not match runtime context"
        }
        PrivateHnswOramError::InvalidManifestSignature => {
            "private HNSW ORAM manifest signature verification failed"
        }
        PrivateHnswOramError::EmptyCommit => {
            "private HNSW ORAM commit must update at least one bucket"
        }
        PrivateHnswOramError::InvalidReadPathsSignature => {
            "private HNSW ORAM read_paths signature verification failed"
        }
        PrivateHnswOramError::InvalidResourceKeyId => {
            "private HNSW ORAM resource key id is invalid"
        }
    };
    CollectionError::bad_request(message)
}

fn max_base64url_nopad_encoded_len(byte_len: usize) -> CollectionResult<usize> {
    let full_chunks = byte_len / 3;
    let tail_len = match byte_len % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => {
            return Err(CollectionError::bad_request(
                "private HNSW ORAM bucket ciphertext size overflows",
            ));
        }
    };
    full_chunks
        .checked_mul(4)
        .and_then(|len| len.checked_add(tail_len))
        .ok_or_else(|| {
            CollectionError::bad_request("private HNSW ORAM bucket ciphertext size overflows")
        })
}

fn max_bucket_file_bytes(max_ciphertext_bytes: usize) -> CollectionResult<u64> {
    let encoded_len = max_base64url_nopad_encoded_len(max_ciphertext_bytes)?;
    let file_len = encoded_len
        .checked_add(BUCKET_JSON_OVERHEAD_BYTES)
        .ok_or_else(|| {
            CollectionError::bad_request("private HNSW ORAM bucket file size overflows")
        })?;
    u64::try_from(file_len)
        .map_err(|_| CollectionError::bad_request("private HNSW ORAM bucket file size overflows"))
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
    if !private_hnsw_oram_vector_name_is_safe_store_component(value) {
        return Err(CollectionError::bad_request(format!(
            "private HNSW ORAM {label} is not a safe store path component",
        )));
    }
    Ok(())
}

pub fn private_hnsw_oram_vector_name_is_safe_store_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && !path_component_is_client_owned_oram_state_alias(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
}

fn path_component_is_client_owned_oram_state_alias(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let compact_value = value.replace(['_', '-', '.'], "");
    if compact_path_component_is_client_owned_oram_state_alias(&compact_value) {
        return true;
    }
    let Some((stem, _extension)) = value.rsplit_once('.') else {
        return false;
    };
    compact_path_component_is_client_owned_oram_state_alias(&stem.replace(['_', '-', '.'], ""))
}

fn compact_path_component_is_client_owned_oram_state_alias(value: &str) -> bool {
    matches!(
        value,
        "clientstate"
            | "clientstatebackup"
            | "clientstatebackups"
            | "clientstatesnapshot"
            | "clientstatesnapshots"
            | "encryptedclientstate"
            | "encryptedclientstates"
            | "encryptedclientstatebackup"
            | "encryptedclientstatebackups"
            | "encryptedclientstatesnapshot"
            | "encryptedclientstatesnapshots"
            | "positionmap"
            | "positionmapbackup"
            | "positionmapbackups"
            | "positionmaps"
            | "positionmapsnapshot"
            | "positionmapsnapshots"
            | "orampositionmap"
            | "orampositionmapbackup"
            | "orampositionmapbackups"
            | "orampositionmaps"
            | "orampositionmapsnapshot"
            | "orampositionmapsnapshots"
            | "tokenpositionmap"
            | "tokenpositionmapbackup"
            | "tokenpositionmapbackups"
            | "tokenpositionmaps"
            | "tokenpositionmapsnapshot"
            | "tokenpositionmapsnapshots"
            | "stash"
            | "stashbackup"
            | "stashbackups"
            | "stashsnapshot"
            | "stashsnapshots"
    )
}

fn create_private_dir(path: &Path) -> CollectionResult<()> {
    let created = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            return Err(CollectionError::service_error(
                "private HNSW ORAM path must be a non-symlink directory",
            ));
        }
        Ok(_) => false,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| {
                CollectionError::service_error("failed to create private HNSW ORAM directory")
            })?;
            let metadata = fs::symlink_metadata(path).map_err(|_| {
                CollectionError::service_error("failed to inspect private HNSW ORAM directory")
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(CollectionError::service_error(
                    "private HNSW ORAM path must be a non-symlink directory",
                ));
            }
            true
        }
        Err(_) => {
            return Err(CollectionError::service_error(
                "failed to inspect private HNSW ORAM directory",
            ));
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if created {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
                CollectionError::service_error("failed to harden private HNSW ORAM directory")
            })?;
        }
    }
    validate_private_dir(path)
}

fn validate_private_dir(path: &Path) -> CollectionResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            return CollectionError::not_found("private HNSW ORAM directory");
        }
        CollectionError::service_error("failed to inspect private HNSW ORAM directory")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(CollectionError::service_error(
            "private HNSW ORAM path must be a non-symlink directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = nix::unistd::Uid::effective().as_raw();
        if metadata.uid() != effective_uid {
            return Err(CollectionError::service_error(
                "private HNSW ORAM directory must be owned by the current user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "private HNSW ORAM directory must not be group/world accessible",
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
        .map_err(|_| CollectionError::service_error("failed to read private HNSW ORAM file"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| CollectionError::bad_request("private HNSW ORAM file contains invalid JSON"))
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
        CollectionError::service_error("failed to serialize private HNSW ORAM file")
    })?;
    let temp_path = unique_temp_path(temp_dir);
    let mut file = open_private_file_for_write(&temp_path)?;
    file.write_all(&bytes).map_err(|_| {
        CollectionError::service_error("failed to write private HNSW ORAM temp file")
    })?;
    file.flush().map_err(|_| {
        CollectionError::service_error("failed to flush private HNSW ORAM temp file")
    })?;
    file.sync_all().map_err(|_| {
        CollectionError::service_error("failed to sync private HNSW ORAM temp file")
    })?;
    drop(file);

    fs::rename(&temp_path, target).map_err(|_| {
        let _ = fs::remove_file(&temp_path);
        CollectionError::service_error("failed to replace private HNSW ORAM file")
    })?;
    if let Some(parent) = target.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn validate_target_under_root(root: &Path, target: &Path) -> CollectionResult<()> {
    if !target.starts_with(root) {
        return Err(CollectionError::service_error(
            "private HNSW ORAM target escapes root",
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
            return CollectionError::not_found("private HNSW ORAM file");
        }
        CollectionError::service_error("failed to inspect private HNSW ORAM file")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CollectionError::service_error(
            "private HNSW ORAM file must be a non-symlink regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(CollectionError::bad_request(
            "private HNSW ORAM file exceeds maximum size",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CollectionError::service_error(
                "private HNSW ORAM file must not be group/world accessible",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| CollectionError::service_error("failed to open private HNSW ORAM file"))?;
        return Ok(file);
    }
    #[cfg(not(unix))]
    {
        File::open(path)
            .map_err(|_| CollectionError::service_error("failed to open private HNSW ORAM file"))
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
    options
        .open(path)
        .map_err(|_| CollectionError::service_error("failed to create private HNSW ORAM temp file"))
}

fn unique_temp_path(temp_dir: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    temp_dir.join(format!(
        "private-hnsw-oram-{}-{timestamp}-{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4(),
    ))
}

fn sync_dir(path: &Path) -> CollectionResult<()> {
    let file = File::open(path).map_err(|_| {
        CollectionError::service_error("failed to open private HNSW ORAM directory for sync")
    })?;
    file.sync_all()
        .map_err(|_| CollectionError::service_error("failed to sync private HNSW ORAM directory"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use qdrant_sec::{
        DistanceKind, EncryptionError, FixedBudgetParams, OramKind, OramParams,
        PRIVATE_HNSW_ORAM_BINDING, PrivateHnswBucketAeadBaseContext, PrivateHnswBucketAeadContext,
        PrivateHnswBuildPoint, PrivateHnswClientCommitBucketRef, PrivateHnswClientCommitPlan,
        PrivateHnswClientError, PrivateHnswClientKeys, PrivateHnswCommitSignatureContext,
        PrivateHnswEncryptedPathBatch, PrivateHnswManifestBuildContext,
        PrivateHnswManifestValidationContext, PrivateHnswNodeBlockPlaintext,
        PrivateHnswOramClientConfig, PrivateHnswOramError, PrivateHnswOramPlaintextBucket,
        PrivateHnswParams, PrivateHnswSearchParams, PrivateHnswSignatureVerification,
        PrivateHnswVectorEncoding, ResultPrivacyMode, SecretKey, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
        build_private_hnsw_oram_manifest_from_encrypted_index,
        build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points,
        decode_private_hnsw_oram_bucket_plaintext, empty_private_hnsw_oram_plaintext_bucket,
        encode_private_hnsw_oram_bucket_plaintext, open_private_hnsw_oram_bucket,
        package_private_hnsw_oram_upload_bundle, plan_private_hnsw_oram_commit,
        private_hnsw_oram_bucket_ids_for_leaf, private_hnsw_oram_merkle_root_for_commitments,
        seal_private_hnsw_oram_bucket, seal_private_hnsw_oram_plaintext_index,
        search_private_hnsw_oram_encrypted_verified, sign_private_hnsw_oram_commit,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::TempDir;

    use super::*;

    fn root_hash(byte: u8) -> String {
        BASE64URL_NOPAD.encode(&[byte; 32])
    }

    #[test]
    fn private_hnsw_store_debug_redacts_paths_and_hashes() {
        let store = PrivateHnswOramStore::new("/tmp/hnsw-store-debug-sentinel", "text").unwrap();
        let epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: "HNSW-STORE-ROOT-SENTINEL".to_string(),
        };
        let proof = PrivateHnswOramMerkleProof {
            kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
            index_epoch: 42,
            root_hash: "HNSW-STORE-ROOT-SENTINEL".to_string(),
            bucket_count: 8,
            leaves: vec![PrivateHnswOramMerkleProofLeaf {
                bucket_id: 123_456,
                leaf_hash: "HNSW-STORE-LEAF-SENTINEL".to_string(),
                siblings: vec![PrivateHnswOramMerkleSibling {
                    level: 0,
                    position: MerkleSiblingPosition::Left,
                    hash: "HNSW-STORE-SIBLING-SENTINEL".to_string(),
                }],
            }],
        };
        let tree = PrivateHnswOramMerkleTree {
            version: 1,
            index_epoch: 42,
            root_hash: "HNSW-STORE-ROOT-SENTINEL".to_string(),
            bucket_count: 8,
            leaf_hashes: vec!["HNSW-STORE-LEAF-SENTINEL".to_string()],
        };
        let prepared = PrivateHnswPreparedMerkleCommit {
            store: store.clone(),
            tree: tree.clone(),
        };

        let rendered = [
            format!("{store:?}"),
            format!("{epoch:?}"),
            format!("{proof:?}"),
            format!("{tree:?}"),
            format!("{prepared:?}"),
        ]
        .join("\n");
        for leaked in [
            "/tmp/hnsw-store-debug-sentinel",
            "HNSW-STORE-ROOT-SENTINEL",
            "HNSW-STORE-LEAF-SENTINEL",
            "HNSW-STORE-SIBLING-SENTINEL",
            "123456",
        ] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
    }

    #[test]
    fn private_hnsw_temp_paths_include_random_suffix() {
        let temp = TempDir::new().unwrap();
        let first = unique_temp_path(temp.path());
        let second = unique_temp_path(temp.path());

        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(temp.path()));
        assert_eq!(second.parent(), Some(temp.path()));
        assert!(
            first
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("private-hnsw-oram-")
        );
    }

    #[test]
    fn private_hnsw_store_rejects_unsafe_vector_path_components_without_reflecting_value() {
        for vector_name in [
            "../secret-vector-sentinel",
            "/tmp/secret-vector-sentinel",
            "tenant/secret-vector-sentinel",
            "secret vector sentinel",
            "client_state",
            "client-state",
            "client.state",
            "client_state.json",
            "client_state_backup",
            "clientStateBackups.json",
            "encrypted_client_state",
            "encrypted.client.state",
            "encryptedClientStates.json",
            "encrypted_client_state_backup",
            "encryptedClientStateBackup.json",
            "encryptedClientStateBackups.json",
            "position_map",
            "position_map_backup",
            "positionMapBackups.json",
            "position.map",
            "oram-position-map",
            "oramPositionMapBackup",
            "oramPositionMapBackups.json",
            "token.position.map",
            "token_position_map_backup",
            "tokenPositionMapBackups.json",
            "stash",
            "stash_backup",
            "stashBackups.json",
            "stash.snapshot",
            &"x".repeat(129),
        ] {
            let err = PrivateHnswOramStore::new("/tmp/hnsw-safe-path-test", vector_name)
                .expect_err("unsafe vector name must not become a filesystem path component");
            let rendered = err.to_string();
            assert!(rendered.contains("safe store path component"), "{rendered}");
            assert!(!rendered.contains(vector_name), "{rendered}");
        }

        for vector_name in ["text", "text_v1", "tenant-a@text.1"] {
            let store = PrivateHnswOramStore::new("/tmp/hnsw-safe-path-test", vector_name)
                .expect("safe vector name should be accepted");
            assert!(store.root_path().ends_with(vector_name));
        }
    }

    fn bucket_ciphertext(bytes: &[u8]) -> (String, String) {
        (
            BASE64URL_NOPAD.encode(bytes),
            BASE64URL_NOPAD.encode(Sha256::digest(bytes).as_ref()),
        )
    }

    #[test]
    fn private_hnsw_client_error_mapping_redacts_structured_values() {
        let cases = [
            (
                private_hnsw_client_error(PrivateHnswClientError::Encryption(
                    EncryptionError::UnsupportedAlgorithm("aead-alg-777777".to_string()),
                )),
                vec!["aead-alg-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::TooManyNeighbors {
                    actual: 777_777,
                    limit: 888_888,
                }),
                vec!["777777", "888888"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::UnsupportedBlockVersion(65_000)),
                vec!["65000"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::UnsupportedVectorEncoding(77)),
                vec!["77"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidBucketContext(
                    "bucket-context-777777",
                )),
                vec!["bucket-context-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::BucketCiphertextSizeMismatch {
                    bucket_id: 777_777,
                    expected_bytes: 888_888,
                    actual_bytes: 999_999,
                }),
                vec!["777777", "888888", "999999"],
            ),
            (
                private_hnsw_client_error(
                    PrivateHnswClientError::UnsupportedBucketCiphertextVersion(77),
                ),
                vec!["77"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidOramClientConfig(
                    "client-config-777777",
                )),
                vec!["client-config-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidBuildConfig(
                    "build-config-777777",
                )),
                vec!["build-config-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::OramInitialPlacementOverflow {
                    leaf: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_hnsw_client_error(
                    PrivateHnswClientError::UnsupportedClientStateSnapshotVersion(65_000),
                ),
                vec!["65000"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidClientStateContext(
                    "client-state-context-777777",
                )),
                vec!["client-state-context-777777", "777777"],
            ),
            (
                private_hnsw_client_error(
                    PrivateHnswClientError::UnsupportedClientStateCiphertextVersion(65_000),
                ),
                vec!["65000"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidSearchConfig(
                    "search-config-777777",
                )),
                vec!["search-config-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::BucketOutOfRange {
                    bucket_id: 777_777,
                    bucket_count: 888_888,
                }),
                vec!["777777", "888888"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::DuplicateBucket {
                    bucket_id: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::MissingBucket {
                    bucket_id: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::DuplicateUpdatedBucket {
                    bucket_id: 777_777,
                }),
                vec!["777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::StaleBucketEpoch {
                    bucket_id: 777_777,
                    expected_epoch: 888_888,
                    actual_epoch: 999_999,
                }),
                vec!["777777", "888888", "999999"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::FixedBudgetNotExhausted {
                    completed_steps: 777_777,
                    fixed_steps: 888_888,
                }),
                vec!["777777", "888888"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::UnsupportedBucketVersion(65_000)),
                vec!["65000"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidCommitSignatureContext(
                    "commit-signature-context-777777",
                )),
                vec!["commit-signature-context-777777", "777777"],
            ),
            (
                private_hnsw_client_error(PrivateHnswClientError::InvalidManifestSignatureContext(
                    "manifest-signature-context-777777",
                )),
                vec!["manifest-signature-context-777777", "777777"],
            ),
        ];

        for (err, needles) in cases {
            let rendered = err.to_string();
            for needle in needles {
                assert!(!rendered.contains(needle), "{rendered}");
            }
        }
    }

    #[test]
    fn private_hnsw_oram_error_mapping_redacts_structured_values() {
        let cases = [
            (
                private_hnsw_oram_error(PrivateHnswOramError::UnsupportedManifestVersion(65_000)),
                vec!["65000"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::UnsupportedSignatureAlgorithm(
                    "rsa-pss-777777".to_string(),
                )),
                vec!["rsa-pss-777777", "777777"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::InvalidManifestField(
                    "manifest-field-777777",
                )),
                vec!["manifest-field-777777", "777777"],
            ),
            (
                private_hnsw_oram_error(PrivateHnswOramError::ManifestContextMismatch(
                    "manifest-context-777777",
                )),
                vec!["manifest-context-777777", "777777"],
            ),
        ];

        for (err, needles) in cases {
            let rendered = err.to_string();
            for needle in needles {
                assert!(!rendered.contains(needle), "{rendered}");
            }
        }
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
                block_size_bytes: 16384,
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

    fn fixture_bucket_commitment(
        manifest: &PrivateHnswOramManifest,
        bucket_id: u64,
        index_epoch: u64,
        ciphertext_sha256: &str,
    ) -> String {
        private_hnsw_bucket_commitment(
            PrivateHnswBucketAeadContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id,
                index_epoch,
            },
            ciphertext_sha256,
        )
        .unwrap()
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

    fn fixture_client_keys() -> PrivateHnswClientKeys {
        PrivateHnswClientKeys::derive_from_resource_key_with_context(
            &SecretKey::from_bytes([13; 32]),
            "collection-uuid-1",
            "text",
            "tenant-a/vector-private-rk",
            7,
        )
        .unwrap()
    }

    fn client_oram_config() -> PrivateHnswOramClientConfig {
        PrivateHnswOramClientConfig {
            tree_height: 1,
            bucket_size: 2,
            block_size_bytes: 512,
            fixed_neighbor_slots: 4,
        }
    }

    fn fixture_upload_bundle(key_pair: &Ed25519KeyPair) -> PrivateHnswOramUploadBundle {
        let keys = fixture_client_keys();
        let config = client_oram_config();
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: [1; 32],
                point_token: [11; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: [2; 32],
                point_token: [22; 32],
                vector: vec![0.0, 1.0],
                payload_fetch_token: None,
            },
        ];
        let plaintext_build = build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points(
            config,
            DistanceKind::Euclid,
            1,
            1,
            1,
            &points,
            &[0, 1],
        )
        .unwrap();
        let encrypted_build = seal_private_hnsw_oram_plaintext_index(
            &keys,
            client_bucket_base_context(),
            42,
            &plaintext_build,
            config,
        )
        .unwrap();

        package_private_hnsw_oram_upload_bundle(
            key_pair,
            PrivateHnswManifestBuildContext {
                collection_id: "collection-uuid-1",
                vector_name: "text",
                key_id: "tenant-a/vector-private-rk",
                rk_id: "tenant-a/vector-private-rk",
                rk_epoch: 7,
                dim: 2,
                distance: DistanceKind::Euclid,
                hnsw: PrivateHnswParams {
                    m: 1,
                    ef_construction: 2,
                    max_layers: 1,
                    fixed_neighbor_slots: config.fixed_neighbor_slots as u32,
                },
                oram: OramParams {
                    kind: OramKind::PathOram,
                    bucket_size: config.bucket_size as u32,
                    block_size_bytes: config.block_size_bytes as u32,
                    tree_height: config.tree_height,
                    path_batch_size: 2,
                },
                fixed_budget: FixedBudgetParams {
                    enabled: true,
                    upper_layer_steps: 1,
                    base_layer_steps: 2,
                    paths_per_round: 2,
                    fixed_result_k: 1,
                },
                result_privacy: ResultPrivacyMode::IdsVisible,
                owner_signing_key_id: "tenant-a/private-hnsw-signing-v1",
                created_at_unix: 1_770_000_000,
            },
            &encrypted_build,
        )
        .unwrap()
    }

    fn fixture_signed_commit_update(
        key_pair: &Ed25519KeyPair,
    ) -> (
        PrivateHnswOramUploadBundle,
        PrivateHnswOramBucket,
        PrivateHnswOramEpochState,
        PrivateHnswOramSignature,
    ) {
        let bundle = fixture_upload_bundle(key_pair);
        let keys = fixture_client_keys();
        let config = client_oram_config();
        let plaintext_bucket = empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap();
        let encoded_bucket =
            encode_private_hnsw_oram_bucket_plaintext(&plaintext_bucket, config).unwrap();
        let updated_bucket = seal_private_hnsw_oram_bucket(
            &keys,
            client_bucket_base_context().for_bucket(0, 43),
            &encoded_bucket,
        )
        .unwrap();

        let mut next_commitments = bundle.bucket_commitments();
        let bucket_index = usize::try_from(updated_bucket.bucket_id).unwrap();
        next_commitments[bucket_index] = updated_bucket.bucket_commitment.clone();
        let new_epoch = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: PrivateHnswOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };
        let plan = PrivateHnswClientCommitPlan {
            old_epoch: bundle.manifest.index_epoch,
            new_epoch: new_epoch.index_epoch,
            old_root_hash: bundle.manifest.root_hash.clone(),
            new_root_hash: new_epoch.root_hash.clone(),
            leaf_commitments: next_commitments,
            updated_buckets: vec![PrivateHnswClientCommitBucketRef {
                bucket_id: updated_bucket.bucket_id,
                ciphertext_sha256: updated_bucket.ciphertext_sha256.clone(),
            }],
        };
        let signature = sign_private_hnsw_oram_commit(
            key_pair,
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
        (bundle, updated_bucket, new_epoch, signature)
    }

    fn fixture_validation_context<'a>(
        public_key: &'a [u8],
    ) -> PrivateHnswManifestValidationContext<'a> {
        PrivateHnswManifestValidationContext {
            expected_collection_id: "collection-uuid-1",
            expected_vector_name: "text",
            expected_key_id: "tenant-a/vector-private-rk",
            expected_rk_id: "tenant-a/vector-private-rk",
            min_rk_epoch: 7,
            max_rk_epoch: 7,
            expected_dim: 2,
            expected_distance: DistanceKind::Euclid,
            signature_verification: PrivateHnswSignatureVerification {
                expected_key_id: "tenant-a/private-hnsw-signing-v1",
                public_key,
            },
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
    fn initial_upload_bundle_with_signature_verifies_manifest_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
        let bundle = fixture_upload_bundle(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);

        let mut bad_alg_bundle = bundle.clone();
        let signature_alg_sentinel = "private-hnsw-signature-alg-sentinel";
        bad_alg_bundle.manifest_signature.alg = signature_alg_sentinel.to_string();
        let rendered = store
            .write_initial_upload_bundle(&bad_alg_bundle, 4096)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest signature context"));
        assert!(!rendered.contains(signature_alg_sentinel), "{rendered}");
        assert!(
            !rendered.contains(&bad_alg_bundle.manifest_signature.key_id),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.manifest_signature.sig),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.manifest.root_hash),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.buckets[0].ciphertext),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.buckets[0].ciphertext_sha256),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&bad_alg_bundle.buckets[0].bucket_commitment),
            "{rendered}"
        );
        assert!(
            !store.root_path().exists(),
            "invalid unsigned upload must not create private HNSW ORAM layout"
        );

        let epoch = store
            .write_initial_upload_bundle_with_signature(
                &bundle,
                4096,
                fixture_validation_context(key_pair.public_key().as_ref()),
            )
            .unwrap();
        assert_eq!(epoch.index_epoch, bundle.manifest.index_epoch);
        assert_eq!(epoch.root_hash, bundle.manifest.root_hash);
        assert_eq!(
            store.read_manifest().unwrap(),
            (bundle.manifest.clone(), bundle.manifest_signature.clone()),
        );
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
        assert_eq!(
            store.write_initial_upload_bundle(&bundle, 4096).unwrap(),
            epoch
        );

        let mut mismatched_signature = bundle.clone();
        mismatched_signature.manifest_signature.sig = BASE64URL_NOPAD.encode(&[9; 64]);
        let rendered = store
            .write_initial_upload_bundle(&mismatched_signature, 4096)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("does not match existing manifest"));
        assert!(!rendered.contains(&mismatched_signature.manifest_signature.sig));
        assert!(!rendered.contains(&mismatched_signature.manifest.root_hash));
        assert!(!rendered.contains(&mismatched_signature.buckets[0].ciphertext));
        assert!(!rendered.contains(&mismatched_signature.buckets[0].bucket_commitment));

        let mut tampered = bundle.clone();
        tampered.manifest_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let rendered = store
            .write_initial_upload_bundle_with_signature(
                &tampered,
                4096,
                fixture_validation_context(key_pair.public_key().as_ref()),
            )
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest signature context"));
        assert!(!rendered.contains(&tampered.manifest_signature.sig));
        assert!(!rendered.contains(&tampered.manifest_signature.key_id));
        assert!(!rendered.contains(&tampered.manifest.root_hash));
        assert!(!rendered.contains(&tampered.buckets[0].ciphertext));
        assert!(!rendered.contains(&tampered.buckets[0].ciphertext_sha256));
        assert!(!rendered.contains(&tampered.buckets[0].bucket_commitment));
        assert!(
            !store.root_path().exists(),
            "invalid signed upload must not create private HNSW ORAM layout"
        );
        assert!(matches!(
            store.read_current_epoch(),
            Err(CollectionError::NotFound { .. })
        ));
    }

    #[test]
    fn initial_upload_bundle_rejects_root_mismatch() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[18; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let mut bundle = fixture_upload_bundle(&key_pair);
        let computed_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&bundle.bucket_commitments())
                .unwrap();
        bundle.manifest.root_hash = root_hash(99);
        assert_ne!(computed_root, bundle.manifest.root_hash);

        let err = store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("Merkle root mismatch"));
        assert!(!rendered.contains(&computed_root), "{rendered}");
        assert!(
            !store.root_path().exists(),
            "invalid initial upload must not create private HNSW ORAM layout"
        );
    }

    #[test]
    fn initial_upload_bundle_preflights_existing_epoch_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[18; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle(&key_pair);
        store.write_initial_upload_bundle(&original, 4096).unwrap();

        let mut replacement = original.clone();
        let config = client_oram_config();
        let plaintext_bucket = empty_private_hnsw_oram_plaintext_bucket(0, config).unwrap();
        let encoded_bucket =
            encode_private_hnsw_oram_bucket_plaintext(&plaintext_bucket, config).unwrap();
        let replacement_bucket = seal_private_hnsw_oram_bucket(
            &fixture_client_keys(),
            client_bucket_base_context().for_bucket(0, replacement.manifest.index_epoch),
            &encoded_bucket,
        )
        .unwrap();
        replacement.buckets[0] = replacement_bucket;
        replacement.manifest.root_hash =
            PrivateHnswOramStore::merkle_root_for_commitments(&replacement.bucket_commitments())
                .unwrap();
        assert_ne!(replacement.manifest.root_hash, original.manifest.root_hash);

        let err = store
            .write_initial_upload_bundle(&replacement, 4096)
            .unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("current epoch/root"), "{rendered}");
        assert!(!rendered.contains("upload bundle"), "{rendered}");
        assert_eq!(store.read_manifest().unwrap().0, original.manifest);
        assert_eq!(
            store
                .read_bucket(
                    0,
                    original.manifest.index_epoch,
                    original.manifest.bucket_count,
                    4096,
                )
                .unwrap(),
            original.buckets[0],
        );
        let proof = store
            .read_merkle_path_batch(
                &[0],
                original.manifest.index_epoch,
                &original.manifest.root_hash,
                original.manifest.bucket_count,
            )
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            original.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_files_to_match() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[19; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle(&key_pair);
        store.write_initial_upload_bundle(&original, 4096).unwrap();
        store.write_initial_upload_bundle(&original, 4096).unwrap();

        let mut replacement = original.buckets[0].clone();
        let mut replacement_raw = BASE64URL_NOPAD
            .decode(replacement.ciphertext.as_bytes())
            .unwrap();
        replacement_raw[0] ^= 0x55;
        replacement.ciphertext = BASE64URL_NOPAD.encode(&replacement_raw);
        replacement.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&replacement_raw).as_ref());
        assert_ne!(replacement, original.buckets[0]);
        store
            .write_bucket(
                &replacement,
                original.manifest.index_epoch,
                original.manifest.bucket_count,
                4096,
            )
            .unwrap();

        let rendered = store
            .write_initial_upload_bundle(&original, 4096)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("existing bucket set"));
        assert!(!rendered.contains(&replacement.ciphertext));
        assert!(!rendered.contains(&replacement.bucket_commitment));
        assert!(!rendered.contains(&original.buckets[0].ciphertext));
        assert_eq!(
            store
                .read_bucket(
                    0,
                    original.manifest.index_epoch,
                    original.manifest.bucket_count,
                    4096,
                )
                .unwrap(),
            replacement
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_manifest_to_match() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[20; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle(&key_pair);
        store.write_initial_upload_bundle(&original, 4096).unwrap();

        let mut tampered_signature = original.manifest_signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        store
            .write_manifest(&original.manifest, &tampered_signature)
            .unwrap();

        let rendered = store
            .write_initial_upload_bundle(&original, 4096)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("existing manifest"));
        assert!(!rendered.contains(&tampered_signature.sig));
        assert!(!rendered.contains(&original.manifest_signature.sig));
        assert!(!rendered.contains(&original.manifest.root_hash));
        assert_eq!(store.read_manifest().unwrap().1, tampered_signature);
        assert_eq!(
            store.read_current_epoch().unwrap().root_hash,
            original.manifest.root_hash
        );
    }

    #[test]
    fn initial_upload_bundle_matching_epoch_requires_existing_merkle_tree_to_match() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[21; 32]).unwrap();
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let original = fixture_upload_bundle(&key_pair);
        store.write_initial_upload_bundle(&original, 4096).unwrap();

        let mut tampered_commitments = original.bucket_commitments();
        tampered_commitments[1] = root_hash(88);
        let tampered_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&tampered_commitments).unwrap();
        assert_ne!(tampered_root, original.manifest.root_hash);
        store
            .write_merkle_tree_from_commitments(
                original.manifest.index_epoch,
                tampered_root.clone(),
                tampered_commitments,
            )
            .unwrap();

        let rendered = store
            .write_initial_upload_bundle(&original, 4096)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("existing Merkle tree"));
        assert!(!rendered.contains(&tampered_root));
        assert!(!rendered.contains(&original.manifest.root_hash));
        assert_eq!(
            store.read_current_epoch().unwrap().root_hash,
            original.manifest.root_hash
        );
        assert_eq!(store.read_merkle_tree().unwrap().root_hash, tampered_root);
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
            let parent_mode = fs::metadata(store.root_path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(manifest_mode & 0o077, 0);
            assert_eq!(root_mode & 0o077, 0);
            assert_eq!(parent_mode & 0o077, 0);
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
    fn initial_epoch_reupload_is_idempotent_and_conflict_preserves_current() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let conflicting_epoch = PrivateHnswOramEpochState {
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
        let epoch = PrivateHnswOramEpochState {
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
        replacement.logical_node_count += 1;
        replacement.dummy_node_count -= 1;
        let replacement_signature = PrivateHnswOramSignature {
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
        assert!(!rendered.contains(&replacement_signature.sig));
        assert!(!rendered.contains(&signature.sig));
        assert!(!rendered.contains(&manifest.root_hash));
        assert_eq!(store.read_current_epoch().unwrap(), epoch);
        assert_eq!(store.read_manifest().unwrap(), (manifest, signature));
    }

    #[test]
    fn post_commit_manifest_refresh_allows_current_epoch_ahead_of_stored_manifest() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_manifest = fixture_manifest();
        let old_signature = fixture_signature();
        let old_epoch = PrivateHnswOramEpochState {
            index_epoch: old_manifest.index_epoch,
            root_hash: old_manifest.root_hash.clone(),
        };
        let mut new_manifest = old_manifest.clone();
        new_manifest.index_epoch = old_manifest.index_epoch + 1;
        new_manifest.root_hash = root_hash(43);
        let new_signature = PrivateHnswOramSignature {
            sig: BASE64URL_NOPAD.encode(&[8; 64]),
            ..old_signature.clone()
        };
        let new_epoch = PrivateHnswOramEpochState {
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
    fn post_commit_manifest_refresh_rejects_stale_epoch_without_overwriting() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_manifest = fixture_manifest();
        let old_signature = fixture_signature();
        let old_epoch = PrivateHnswOramEpochState {
            index_epoch: old_manifest.index_epoch,
            root_hash: old_manifest.root_hash.clone(),
        };
        let new_epoch = PrivateHnswOramEpochState {
            index_epoch: old_manifest.index_epoch + 1,
            root_hash: root_hash(43),
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

        let rendered = store
            .write_manifest_with_initial_epoch_if_absent_or_matching(
                &old_manifest,
                &old_signature,
                &old_epoch,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("current epoch/root does not match uploaded manifest"));
        assert!(!rendered.contains(&old_signature.sig), "{rendered}");
        assert!(!rendered.contains(&old_epoch.root_hash), "{rendered}");
        assert!(!rendered.contains(&new_epoch.root_hash), "{rendered}");
        assert_eq!(store.read_current_epoch().unwrap(), new_epoch);
        assert_eq!(
            store.read_manifest().unwrap(),
            (old_manifest, old_signature)
        );
    }

    #[test]
    fn manifest_initial_epoch_publish_requires_manifest_write_success() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let manifest = fixture_manifest();
        let signature = fixture_signature();
        let epoch = PrivateHnswOramEpochState {
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
            "failed initial manifest upload must not publish current epoch"
        );
    }

    #[test]
    fn bucket_write_rejects_hash_mismatch_and_oversize() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(3, 42, b"encrypted bucket");

        store
            .validate_bucket_for_write(&bucket, 42, 16, 64)
            .unwrap();
        store.write_bucket(&bucket, 42, 16, 64).unwrap();
        assert_eq!(store.read_bucket(3, 42, 16, 64).unwrap(), bucket);

        let large_max_ciphertext_bytes = 2 * 65_536 + 4_096;
        let large_bucket = fixture_bucket(6, 42, &vec![7; large_max_ciphertext_bytes]);
        store
            .write_bucket(&large_bucket, 42, 16, large_max_ciphertext_bytes)
            .unwrap();
        assert_eq!(
            store
                .read_bucket(6, 42, 16, large_max_ciphertext_bytes)
                .unwrap(),
            large_bucket
        );

        let mut bad_hash = bucket.clone();
        bad_hash.ciphertext_sha256 = root_hash(1);
        let err = store
            .validate_bucket_for_write(&bad_hash, 42, 16, 64)
            .unwrap_err();
        assert!(err.to_string().contains("ciphertext_sha256 mismatch"));
        let err = store.write_bucket(&bad_hash, 42, 16, 64).unwrap_err();
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
        encoded_oversized.ciphertext = "A".repeat(max_base64url_nopad_encoded_len(64).unwrap() + 1);
        encoded_oversized.ciphertext_sha256 = root_hash(2);
        let err = store
            .validate_bucket_for_write(&encoded_oversized, 42, 16, 64)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("exceeds maximum size"));
        assert!(!rendered.contains("ciphertext_sha256 mismatch"));
        assert!(!rendered.contains(&encoded_oversized.ciphertext));

        let out_of_range = fixture_bucket(99, 42, b"out of range private hnsw bucket");
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
        let mut mismatched_bucket = fixture_bucket(1, 42, b"encrypted bucket mismatch");
        mismatched_bucket.ciphertext =
            BASE64URL_NOPAD.encode(b"private-hnsw-bucket-ciphertext-sentinel");
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
        assert!(!err.contains("private-hnsw-bucket-ciphertext-sentinel"));
        assert!(!err.contains(&mismatched_bucket.ciphertext));
    }

    #[test]
    fn store_accepts_client_sealed_buckets_and_merkle_root_roundtrips() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let keys = fixture_client_keys();

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
        let rendered = err.to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("1"), "{rendered}");
    }

    #[test]
    fn writeback_commit_rejects_non_advancing_epoch_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let bundle = fixture_upload_bundle(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let original_bucket = bundle.buckets[0].clone();
        let updated_bucket =
            fixture_bucket(0, old.index_epoch, b"private-hnsw-non-advancing-sentinel");
        let non_advancing_new = PrivateHnswOramEpochState {
            index_epoch: old.index_epoch,
            root_hash: root_hash(99),
        };

        let err = store
            .commit_writeback(
                &old,
                &non_advancing_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("new epoch must be greater than old epoch"));
        assert!(!err.contains("private-hnsw-non-advancing-sentinel"));
        assert!(!err.contains(&updated_bucket.ciphertext), "{err}");
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            original_bucket
        );
        let proof = store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(proof.leaves[0].leaf_hash, original_bucket.bucket_commitment);
    }

    #[test]
    fn writeback_commit_preflights_stale_current_epoch_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let (bundle, updated_bucket, new, _) = fixture_signed_commit_update(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let stale_current = PrivateHnswOramEpochState {
            index_epoch: new.index_epoch,
            root_hash: root_hash(77),
        };
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let err = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("RootHashMismatch"));
        assert!(!err.contains("42"), "{err}");
        assert!(!err.contains("43"), "{err}");
        assert!(!err.contains(&old.root_hash), "{err}");
        assert!(!err.contains(&stale_current.root_hash), "{err}");
        assert_eq!(store.read_current_epoch().unwrap(), stale_current);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0]
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
    fn writeback_commit_rejects_invalid_bucket_and_wrong_root_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let (bundle, updated_bucket, new, _) = fixture_signed_commit_update(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let original_bucket = bundle.buckets[0].clone();
        let assert_writeback_target_unchanged = || {
            assert_eq!(store.read_current_epoch().unwrap(), old);
            assert_eq!(
                store
                    .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                    .unwrap(),
                original_bucket
            );
            let proof = store
                .read_merkle_path_batch(
                    &[0],
                    old.index_epoch,
                    &old.root_hash,
                    bundle.bucket_count(),
                )
                .unwrap();
            assert_eq!(proof.leaves[0].leaf_hash, original_bucket.bucket_commitment);
        };

        let mut hash_mismatch_bucket = updated_bucket.clone();
        let mut hash_mismatch_raw = BASE64URL_NOPAD
            .decode(hash_mismatch_bucket.ciphertext.as_bytes())
            .unwrap();
        hash_mismatch_raw[0] ^= 0xff;
        hash_mismatch_bucket.ciphertext = BASE64URL_NOPAD.encode(&hash_mismatch_raw);
        let err = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&hash_mismatch_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("ciphertext_sha256 mismatch"));
        assert!(!err.contains(&hash_mismatch_bucket.ciphertext), "{err}");
        assert_writeback_target_unchanged();

        let mut short_ciphertext_bucket = updated_bucket.clone();
        let short_raw = b"short-hnsw-commit";
        let short_hash = BASE64URL_NOPAD.encode(Sha256::digest(short_raw).as_ref());
        short_ciphertext_bucket.ciphertext = BASE64URL_NOPAD.encode(short_raw);
        short_ciphertext_bucket.ciphertext_sha256 = short_hash.clone();
        short_ciphertext_bucket.bucket_commitment = fixture_bucket_commitment(
            &bundle.manifest,
            short_ciphertext_bucket.bucket_id,
            short_ciphertext_bucket.index_epoch,
            &short_hash,
        );
        let mut short_commitments = bundle.bucket_commitments();
        short_commitments[0] = short_ciphertext_bucket.bucket_commitment.clone();
        let short_new = PrivateHnswOramEpochState {
            index_epoch: new.index_epoch,
            root_hash: PrivateHnswOramStore::merkle_root_for_commitments(&short_commitments)
                .unwrap(),
        };
        let err = store
            .commit_writeback(
                &old,
                &short_new,
                bundle.bucket_count(),
                std::slice::from_ref(&short_ciphertext_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("fixed ciphertext size"));
        assert!(!err.contains("short-hnsw-commit"));
        assert!(!err.contains(&short_ciphertext_bucket.ciphertext), "{err}");
        assert_writeback_target_unchanged();

        let expected_bytes =
            private_hnsw_oram_bucket_ciphertext_bytes(&bundle.manifest.oram).unwrap();
        let mut oversized_bucket = updated_bucket.clone();
        let oversized_raw = vec![7; expected_bytes + 1];
        oversized_bucket.ciphertext = BASE64URL_NOPAD.encode(&oversized_raw);
        oversized_bucket.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&oversized_raw).as_ref());

        let err = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&oversized_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("fixed ciphertext size"));
        assert!(!err.contains(&oversized_bucket.ciphertext));
        assert_writeback_target_unchanged();

        let wrong_root_new = PrivateHnswOramEpochState {
            index_epoch: new.index_epoch,
            root_hash: root_hash(99),
        };
        let err = store
            .commit_writeback(
                &old,
                &wrong_root_new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("new_root_hash mismatch"));
        assert!(!err.contains(&wrong_root_new.root_hash), "{err}");
        assert_writeback_target_unchanged();
    }

    #[test]
    fn writeback_commit_with_signature_verifies_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let (bundle, updated_bucket, new, signature) = fixture_signed_commit_update(&key_pair);

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();
        let committed = store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
                    public_key: key_pair.public_key().as_ref(),
                },
            )
            .unwrap();

        assert_eq!(committed, new);
        assert_eq!(store.read_current_epoch().unwrap(), new);
        assert_eq!(
            store
                .read_bucket(0, new.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            updated_bucket,
        );
        let proof = store
            .read_merkle_path_batch(&[0], new.index_epoch, &new.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(proof.leaves[0].leaf_hash, updated_bucket.bucket_commitment);

        let temp = TempDir::new().unwrap();
        let tampered_store = fixture_store(&temp);
        let old = tampered_store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap();
        let mut tampered_signature = signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[8; 64]);
        let rendered = tampered_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &tampered_signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
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
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0],
        );
        let proof = tampered_store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );

        let temp = TempDir::new().unwrap();
        let unsupported_alg_store = fixture_store(&temp);
        let old = unsupported_alg_store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap();
        let mut unsupported_alg_signature = signature.clone();
        unsupported_alg_signature.alg = "rsa-pss-hnsw-sentinel".to_string();
        let rendered = unsupported_alg_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &unsupported_alg_signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
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
        for sentinel in [
            unsupported_alg_signature.key_id.as_str(),
            unsupported_alg_signature.sig.as_str(),
            old.root_hash.as_str(),
            new.root_hash.as_str(),
            updated_bucket.ciphertext.as_str(),
            updated_bucket.bucket_commitment.as_str(),
        ] {
            assert!(!rendered.contains(sentinel), "{rendered}");
        }
        assert_eq!(unsupported_alg_store.read_current_epoch().unwrap(), old);
        assert_eq!(
            unsupported_alg_store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0],
        );
        let proof = unsupported_alg_store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );

        let temp = TempDir::new().unwrap();
        let wrong_key_store = fixture_store(&temp);
        let old = wrong_key_store
            .write_initial_upload_bundle(&bundle, 4096)
            .unwrap();
        let mut wrong_key_signature = signature.clone();
        wrong_key_signature.key_id = "tenant-a/private-hnsw-signing-v2".to_string();
        let rendered = wrong_key_store
            .commit_writeback_with_signature(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
                &wrong_key_signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: "tenant-a/private-hnsw-signing-v1",
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
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0],
        );
        let proof = wrong_key_store
            .read_merkle_path_batch(&[0], old.index_epoch, &old.root_hash, bundle.bucket_count())
            .unwrap();
        assert_eq!(
            proof.leaves[0].leaf_hash,
            bundle.buckets[0].bucket_commitment
        );
    }

    #[test]
    fn writeback_commit_rejects_bucket_commitment_context_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[29; 32]).unwrap();
        let (bundle, updated_bucket, _, _) = fixture_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();

        let mut tampered_bucket = updated_bucket.clone();
        tampered_bucket.bucket_commitment = root_hash(88);
        let mut next_commitments = bundle.bucket_commitments();
        next_commitments[0] = tampered_bucket.bucket_commitment.clone();
        let tampered_new = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: PrivateHnswOramStore::merkle_root_for_commitments(&next_commitments)
                .unwrap(),
        };
        let rendered = store
            .commit_writeback(
                &old,
                &tampered_new,
                bundle.bucket_count(),
                std::slice::from_ref(&tampered_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("commit bucket commitment context mismatch"));
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
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
    fn writeback_commit_preflights_manifest_epoch_root_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let (bundle, updated_bucket, new, _) = fixture_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();

        let mut tampered_manifest = bundle.manifest.clone();
        tampered_manifest.root_hash = root_hash(99);
        assert_ne!(tampered_manifest.root_hash, old.root_hash);
        store
            .write_manifest(&tampered_manifest, &bundle.manifest_signature)
            .unwrap();

        let rendered = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("manifest epoch/root"));
        assert!(
            !rendered.contains(&tampered_manifest.root_hash),
            "{rendered}"
        );
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(
            !rendered.contains(&bundle.manifest_signature.sig),
            "{rendered}"
        );
        assert!(!rendered.contains(&updated_bucket.ciphertext), "{rendered}");
        assert!(
            !rendered.contains(&updated_bucket.bucket_commitment),
            "{rendered}"
        );
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0]
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
    fn writeback_commit_preflights_manifest_bucket_count_before_writes() {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
        let (bundle, updated_bucket, new, _) = fixture_signed_commit_update(&key_pair);
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = store.write_initial_upload_bundle(&bundle, 4096).unwrap();

        let mut tampered_manifest = bundle.manifest.clone();
        tampered_manifest.bucket_count += 1;
        store
            .write_manifest(&tampered_manifest, &bundle.manifest_signature)
            .unwrap();

        let rendered = store
            .commit_writeback(
                &old,
                &new,
                bundle.bucket_count(),
                std::slice::from_ref(&updated_bucket),
                4096,
            )
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("manifest bucket_count"));
        assert!(
            !rendered.contains(&tampered_manifest.bucket_count.to_string()),
            "{rendered}"
        );
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(
            !rendered.contains(&bundle.manifest_signature.sig),
            "{rendered}"
        );
        assert!(!rendered.contains(&updated_bucket.ciphertext), "{rendered}");
        assert!(
            !rendered.contains(&updated_bucket.bucket_commitment),
            "{rendered}"
        );
        assert_eq!(store.read_current_epoch().unwrap(), old);
        assert_eq!(
            store
                .read_bucket(0, old.index_epoch, bundle.bucket_count(), 4096)
                .unwrap(),
            bundle.buckets[0]
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
    fn sdk_upload_search_fixture_roundtrips_store_read_paths_and_commit() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let keys = fixture_client_keys();
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
        let rendered = err.to_string();
        assert!(rendered.contains("RootHashMismatch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains("44"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&new.root_hash), "{rendered}");
        assert!(!rendered.contains(&newer.root_hash), "{rendered}");
    }

    #[test]
    fn crash_window_before_epoch_cas_fails_closed_instead_of_serving_mixed_root() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old_bucket = fixture_bucket(0, 42, b"old bucket");
        let other_bucket = fixture_bucket(1, 42, b"other bucket");
        let old_commitments = vec![
            old_bucket.bucket_commitment.clone(),
            other_bucket.bucket_commitment.clone(),
        ];
        let old_root = PrivateHnswOramStore::merkle_root_for_commitments(&old_commitments).unwrap();
        let old_epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: old_root.clone(),
        };

        store.write_initial_epoch(&old_epoch).unwrap();
        store.write_bucket(&old_bucket, 42, 2, 64).unwrap();
        store.write_bucket(&other_bucket, 42, 2, 64).unwrap();
        store
            .write_merkle_tree_from_commitments(42, old_root.clone(), old_commitments.clone())
            .unwrap();

        let updated_bucket = fixture_bucket(0, 43, b"new bucket");
        store.write_bucket(&updated_bucket, 43, 2, 64).unwrap();
        assert_eq!(store.read_current_epoch().unwrap(), old_epoch);
        let err = store.read_bucket(0, 42, 2, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("newer than requested epoch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("0"), "{rendered}");

        let mut new_commitments = old_commitments;
        new_commitments[0] = updated_bucket.bucket_commitment.clone();
        let new_root = PrivateHnswOramStore::merkle_root_for_commitments(&new_commitments).unwrap();
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
        assert_eq!(store.read_current_epoch().unwrap(), old_epoch);
        let err = store
            .read_merkle_path_batch(&[0], 42, &old_root, 2)
            .unwrap_err();
        assert!(err.to_string().contains("epoch mismatch"));
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
        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink regular file"));
        assert!(!rendered.contains("outside.bucket"), "{rendered}");
        assert!(!rendered.contains("00000003.bucket"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn current_epoch_symlink_rejects_without_path_or_target_leak() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside = temp.path().join("outside-current-epoch.json");
        fs::write(&outside, br#"{"index_epoch":42,"root_hash":"bad"}"#).unwrap();
        symlink(outside, store.current_epoch_path()).unwrap();

        let err = store.read_current_epoch().unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink regular file"), "{rendered}");
        assert!(!rendered.contains("outside-current-epoch"), "{rendered}");
        assert!(!rendered.contains(CURRENT_EPOCH_FILE), "{rendered}");
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn current_epoch_group_world_accessible_rejects_without_epoch_or_path_leak() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let epoch = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        store.write_initial_epoch(&epoch).unwrap();
        fs::set_permissions(
            store.current_epoch_path(),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let err = store.read_current_epoch().unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"), "{rendered}");
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains(&epoch.root_hash), "{rendered}");
        assert!(!rendered.contains(CURRENT_EPOCH_FILE), "{rendered}");
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_layout_rejects_root_symlink_without_chmod_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().unwrap();
        let outside_dir = temp.path().join("outside-private-hnsw");
        fs::create_dir(&outside_dir).unwrap();
        fs::set_permissions(&outside_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let private_hnsw_root = temp.path().join(PRIVATE_HNSW_ORAM_DIR);
        fs::create_dir(&private_hnsw_root).unwrap();
        fs::set_permissions(&private_hnsw_root, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&outside_dir, private_hnsw_root.join("text")).unwrap();
        let store = fixture_store(&temp);

        let err = store.ensure_layout().unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink directory"));
        assert!(!rendered.contains("outside-private-hnsw"), "{rendered}");
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        let outside_mode = fs::metadata(&outside_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(outside_mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn parent_directory_group_world_accessible_rejects_without_path_leak() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let private_hnsw_root = temp.path().join(PRIVATE_HNSW_ORAM_DIR);
        fs::create_dir(&private_hnsw_root).unwrap();
        fs::set_permissions(&private_hnsw_root, fs::Permissions::from_mode(0o755)).unwrap();
        let store = fixture_store(&temp);

        let err = store.ensure_layout().unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(
            !store.root_path().exists(),
            "weak parent must fail before creating vector store root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn temp_directory_symlink_rejects_without_path_or_temp_name_leak() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        store.ensure_layout().unwrap();
        let outside_temp = temp.path().join("outside-private-hnsw-temp");
        fs::create_dir(&outside_temp).unwrap();
        fs::set_permissions(&outside_temp, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir(store.root_path().join(TEMP_DIR)).unwrap();
        symlink(&outside_temp, store.root_path().join(TEMP_DIR)).unwrap();

        let err = store
            .write_initial_epoch(&PrivateHnswOramEpochState {
                index_epoch: 42,
                root_hash: root_hash(42),
            })
            .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("non-symlink directory"));
        assert!(
            !rendered.contains("outside-private-hnsw-temp"),
            "{rendered}"
        );
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(!rendered.contains("private-hnsw-oram-"), "{rendered}");
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
            .write_initial_epoch(&PrivateHnswOramEpochState {
                index_epoch: 42,
                root_hash: root_hash(42),
            })
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
        assert!(!rendered.contains("private-hnsw-oram-"), "{rendered}");
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

        let err = store.read_bucket(3, 42, 16, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("private_hnsw_oram"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn bucket_file_group_world_accessible_rejects() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket = fixture_bucket(3, 42, b"encrypted bucket");
        store.write_bucket(&bucket, 42, 16, 64).unwrap();
        fs::set_permissions(
            store.root_path().join(BUCKETS_DIR).join("00000003.bucket"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let err = store.read_bucket(3, 42, 16, 64).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("group/world accessible"));
        assert!(!rendered.contains("00000003.bucket"), "{rendered}");
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

        let duplicate_proof = store
            .read_merkle_path_batch(&[1, 3, 1], 42, &root, 4)
            .unwrap();
        assert_eq!(duplicate_proof.leaves.len(), 3);
        assert_eq!(duplicate_proof.leaves[0], duplicate_proof.leaves[2]);

        let err = store.read_merkle_path_batch(&[], 42, &root, 4).unwrap_err();
        assert!(err.to_string().contains("bucket batch is empty"));
        let err = store
            .read_merkle_path_batch(&[4], 42, &root, 4)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("4"), "{rendered}");
    }

    #[test]
    fn read_bucket_batch_with_proof_checks_current_epoch_and_commitments() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let bucket0 = fixture_bucket(0, 42, b"encrypted hnsw bucket 0");
        let bucket1 = fixture_bucket(1, 42, b"encrypted hnsw bucket 1");
        let leaf_commitments = vec![
            bucket0.bucket_commitment.clone(),
            bucket1.bucket_commitment.clone(),
        ];
        let root = PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        let current = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root.clone(),
        };

        store.write_initial_epoch(&current).unwrap();
        store
            .write_merkle_tree_from_commitments(42, root.clone(), leaf_commitments)
            .unwrap();
        store.write_bucket(&bucket0, 42, 2, 128).unwrap();
        store.write_bucket(&bucket1, 42, 2, 128).unwrap();

        let (buckets, proof) = store
            .read_bucket_batch_with_proof(&[0, 1, 0], 42, &root, 2, 128)
            .unwrap();
        assert_eq!(
            buckets,
            vec![bucket0.clone(), bucket1.clone(), bucket0.clone()]
        );
        assert_eq!(proof.leaves.len(), buckets.len());
        assert_eq!(proof.leaves[0], proof.leaves[2]);

        let mut replacement = fixture_bucket(1, 42, b"private-hnsw-read-bucket-mismatch-sentinel");
        replacement.bucket_commitment = root_hash(88);
        assert_ne!(replacement.bucket_commitment, bucket1.bucket_commitment);
        store.write_bucket(&replacement, 42, 2, 128).unwrap();

        let rendered = store
            .read_bucket_batch_with_proof(&[1], 42, &root, 2, 128)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("encrypted bucket/proof consistency validation failed"));
        assert!(!rendered.contains("private-hnsw-read-bucket-mismatch-sentinel"));
        assert!(!rendered.contains(&replacement.ciphertext));
        assert!(!rendered.contains(&replacement.bucket_commitment));

        let rendered = store
            .read_bucket_batch_with_proof(&[], 42, &root, 2, 128)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("bucket batch is empty"));
    }

    #[test]
    fn read_bucket_batch_with_proof_preflights_stale_current_epoch() {
        let temp = TempDir::new().unwrap();
        let store = fixture_store(&temp);
        let old = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: root_hash(42),
        };
        let stale_current = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: root_hash(43),
        };

        store.write_initial_epoch(&old).unwrap();
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let rendered = store
            .read_bucket_batch_with_proof(&[1], old.index_epoch, &old.root_hash, 2, 128)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("RootHashMismatch"));
        assert!(!rendered.contains("42"), "{rendered}");
        assert!(!rendered.contains("43"), "{rendered}");
        assert!(!rendered.contains(&old.root_hash), "{rendered}");
        assert!(!rendered.contains(&stale_current.root_hash), "{rendered}");
    }

    #[test]
    fn merkle_tree_validation_rejects_root_mismatch_without_computed_root() {
        let tree = PrivateHnswOramMerkleTree {
            version: 1,
            index_epoch: 42,
            root_hash: root_hash(99),
            bucket_count: 2,
            leaf_hashes: vec![root_hash(1), root_hash(2)],
        };
        let computed_root =
            PrivateHnswOramStore::merkle_root_for_commitments(&tree.leaf_hashes).unwrap();
        assert_ne!(computed_root, tree.root_hash);

        let err = validate_merkle_tree(&tree).unwrap_err();
        let rendered = err.to_string();

        assert!(rendered.contains("root_hash mismatch"));
        assert!(!rendered.contains(&computed_root), "{rendered}");
        assert!(!rendered.contains(&tree.root_hash), "{rendered}");
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
            .prepare_merkle_commit(42, &old_root, 43, &old_root, 4, &[])
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));

        let wrong_new_root = root_hash(99);
        assert_ne!(wrong_new_root, new_root);
        let err = store
            .prepare_merkle_commit(
                42,
                &old_root,
                43,
                &wrong_new_root,
                4,
                std::slice::from_ref(&updated_bucket),
            )
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("new_root_hash mismatch"));
        assert!(!rendered.contains(&wrong_new_root), "{rendered}");
        assert!(!rendered.contains(&new_root), "{rendered}");

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

        let err = store
            .prepare_merkle_commit(42, &old_root, 43, &new_root, 4, &[])
            .unwrap_err();
        assert!(err.to_string().contains("must update at least one bucket"));
    }

    #[test]
    fn merkle_commit_rejects_duplicate_updated_bucket() {
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
                &new_root,
                4,
                &[updated_bucket.clone(), updated_bucket],
            )
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("repeats a bucket"));
        assert!(!rendered.contains("2"), "{rendered}");
    }
}
