use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use collection::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams, EncryptionRuleRef,
    EncryptionSelector, private_hnsw_oram_api_required_message,
};
use collection::operations::types::CollectionError;
use collection::private_hnsw_oram_store::{
    PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND, PrivateHnswOramEpochState, PrivateHnswOramMerkleProof,
    PrivateHnswOramStore,
};
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING, PrivateHnswBucketAeadContext,
    PrivateHnswManifestValidationContext, PrivateHnswOramBucket, PrivateHnswOramCommitBucketRef,
    PrivateHnswOramCommitSignatureInput, PrivateHnswOramError, PrivateHnswOramManifest,
    PrivateHnswOramReadPathsSignatureInput, PrivateHnswOramSignature, PrivateHnswParams,
    PrivateHnswSignatureVerification, ResultPrivacyMode, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
    decode_private_hnsw_oram_leaf_label, private_hnsw_bucket_commitment,
    private_hnsw_oram_bucket_ciphertext_bytes, private_hnsw_oram_bucket_count,
    private_hnsw_oram_bucket_ids_for_leaf, private_hnsw_oram_fixed_writeback_bucket_budget,
    validate_private_hnsw_oram_commit_signature, validate_private_hnsw_oram_manifest,
    validate_private_hnsw_oram_manifest_signature_shape,
    validate_private_hnsw_oram_read_paths_signature,
};
use segment::types::Distance;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::content_manager::toc::TableOfContent;
use storage::rbac::{AccessRequirements, Auth};

use crate::common::crypto::validate_collection_crypto_runtime_with_crypto_id;
use crate::settings::{CryptoInstanceConfig, Settings};

const SIGNATURE_PUBLIC_KEYS_OPTION: &str = "signature_public_keys";
const KEY_ID_OPTION: &str = "key_id";
const EXPECTED_RK_ID_OPTION: &str = "expected_rk_id";
const MIN_RK_EPOCH_OPTION: &str = "min_rk_epoch";
const MAX_RK_EPOCH_OPTION: &str = "max_rk_epoch";
const RESULT_PRIVACY_OPTION: &str = "result_privacy";
const HNSW_OPTION: &str = "hnsw";
const ORAM_OPTION: &str = "oram";
const FIXED_BUDGET_OPTION: &str = "fixed_budget";
const ZERO_TRUST_PROFILE_STRICT: &str = "strict";
const SESSION_LEASE_SECS: u64 = 300;
const MAX_SESSION_COUNT: usize = 1024;
const PRIVATE_HNSW_ORAM_LEAF_LABEL_B64_LEN: usize = 11;
const PRIVATE_HNSW_ORAM_ROOT_HASH_B64_LEN: usize = 43;
const PRIVATE_HNSW_ORAM_SIGNATURE_B64_LEN: usize = 86;
const PRIVATE_HNSW_ORAM_CLIENT_ID_MAX_LEN: usize = 256;
const PRIVATE_HNSW_ORAM_SESSION_ID_MAX_LEN: usize = 128;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateHnswManifestRecord {
    pub manifest: PrivateHnswOramManifest,
    pub signature: PrivateHnswOramSignature,
}

impl Debug for PrivateHnswManifestRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswManifestRecord")
            .field("manifest", &self.manifest)
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateHnswSessionResponse {
    pub session_id: String,
    pub collection_id: String,
    pub vector_name: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub manifest: PrivateHnswOramManifest,
    pub lease_expires_unix: u64,
}

impl Debug for PrivateHnswSessionResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSessionResponse")
            .field("session_id", &"[redacted]")
            .field("collection_id", &self.collection_id)
            .field("vector_name", &self.vector_name)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("manifest", &self.manifest)
            .field("lease_expires_unix", &self.lease_expires_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateHnswReadPathsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<PrivateHnswOramBucket>,
    pub proof: PrivateHnswReadProof,
}

impl Debug for PrivateHnswReadPathsResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswReadPathsResponse")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &self.buckets.len())
            .field("proof", &self.proof)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateHnswReadProof {
    pub kind: String,
    pub value: String,
}

impl Debug for PrivateHnswReadProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswReadProof")
            .field("kind", &self.kind)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateHnswReadPadding {
    pub requested_paths: u32,
    pub dummy_paths_included: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateHnswClientSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

impl Debug for PrivateHnswClientSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswClientSignature")
            .field("alg", &self.alg)
            .field("key_id", &self.key_id)
            .field("sig", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
struct PrivateHnswSession {
    session_id: String,
    _client_id: String,
    collection_id: String,
    collection_path: std::path::PathBuf,
    vector_name: String,
    index_epoch: u64,
    root_hash: String,
    lease_expires_unix: u64,
    bucket_count: u64,
    tree_height: u32,
    path_batch_size: u32,
    max_bucket_ciphertext_bytes: usize,
    manifest: PrivateHnswOramManifest,
}

impl Debug for PrivateHnswSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateHnswSession")
            .field("session_id", &"[redacted]")
            .field("client_id", &"[redacted]")
            .field("collection_id", &self.collection_id)
            .field("collection_path", &"[redacted]")
            .field("vector_name", &self.vector_name)
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("lease_expires_unix", &self.lease_expires_unix)
            .field("bucket_count", &self.bucket_count)
            .field("tree_height", &self.tree_height)
            .field("path_batch_size", &self.path_batch_size)
            .field(
                "max_bucket_ciphertext_bytes",
                &self.max_bucket_ciphertext_bytes,
            )
            .field("manifest", &self.manifest)
            .finish()
    }
}

#[derive(Default)]
struct PrivateHnswSessionRegistry {
    sessions: HashMap<String, PrivateHnswSession>,
    active_writer_by_index: HashMap<String, String>,
    active_snapshot_by_collection: HashMap<String, usize>,
    active_upload_by_index: HashMap<String, usize>,
}

impl PrivateHnswSessionRegistry {
    fn open(
        &mut self,
        mut session: PrivateHnswSession,
        now_unix: u64,
    ) -> StorageResult<PrivateHnswSessionResponse> {
        self.expire(now_unix);
        if self.sessions.len() >= MAX_SESSION_COUNT {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session registry is full",
            ));
        }
        if self
            .active_snapshot_by_collection
            .contains_key(&session.collection_id)
        {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session open requires no active collection snapshot",
            ));
        }

        let index_key = session_index_key(&session.collection_id, &session.vector_name);
        if self.active_upload_by_index.contains_key(&index_key) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session open requires no active upload for this index",
            ));
        }
        if self.active_writer_by_index.contains_key(&index_key) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM ConcurrentWriter: an active session already holds this index",
            ));
        }
        while self.sessions.contains_key(&session.session_id) {
            session.session_id = new_session_id();
        }

        let response = session.response();
        self.active_writer_by_index
            .insert(index_key, session.session_id.clone());
        self.sessions.insert(session.session_id.clone(), session);
        Ok(response)
    }

    fn close(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
    ) -> bool {
        self.expire(now_unix);
        let removed = self.sessions.remove(session_id);
        if let Some(session) = removed {
            if session.collection_id == collection_id && session.vector_name == vector_name {
                let index_key = session_index_key(collection_id, vector_name);
                if self
                    .active_writer_by_index
                    .get(&index_key)
                    .is_some_and(|active| active == session_id)
                {
                    self.active_writer_by_index.remove(&index_key);
                }
                return true;
            }
            self.sessions.insert(session_id.to_string(), session);
        }
        false
    }

    fn has_active_collection(&mut self, collection_id: &str, now_unix: u64) -> bool {
        self.expire(now_unix);
        self.sessions
            .values()
            .any(|session| session.collection_id == collection_id)
    }

    fn has_active_index(&mut self, collection_id: &str, vector_name: &str, now_unix: u64) -> bool {
        self.expire(now_unix);
        self.active_writer_by_index
            .contains_key(&session_index_key(collection_id, vector_name))
    }

    fn has_active_upload_collection(&self, collection_id: &str) -> bool {
        let prefix = format!("{collection_id}\x1f");
        self.active_upload_by_index
            .keys()
            .any(|index_key| index_key.starts_with(&prefix))
    }

    fn begin_collection_snapshot(
        &mut self,
        collection_id: &str,
        now_unix: u64,
    ) -> StorageResult<()> {
        ensure_no_active_private_hnsw_collection_session_in_registry(
            self,
            collection_id,
            now_unix,
        )?;
        *self
            .active_snapshot_by_collection
            .entry(collection_id.to_string())
            .or_insert(0) += 1;
        Ok(())
    }

    fn release_collection_snapshot(&mut self, collection_id: &str) {
        let Some(count) = self.active_snapshot_by_collection.get_mut(collection_id) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.active_snapshot_by_collection.remove(collection_id);
        }
    }

    fn begin_upload(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        now_unix: u64,
    ) -> StorageResult<()> {
        ensure_private_hnsw_write_window_in_registry(self, collection_id, vector_name, now_unix)?;
        *self
            .active_upload_by_index
            .entry(session_index_key(collection_id, vector_name))
            .or_insert(0) += 1;
        Ok(())
    }

    fn release_upload(&mut self, collection_id: &str, vector_name: &str) {
        let index_key = session_index_key(collection_id, vector_name);
        let Some(count) = self.active_upload_by_index.get_mut(&index_key) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.active_upload_by_index.remove(&index_key);
        }
    }

    fn with_session_mut<T>(
        &mut self,
        collection_id: &str,
        vector_name: &str,
        session_id: &str,
        now_unix: u64,
        action: impl FnOnce(&mut PrivateHnswSession) -> StorageResult<T>,
    ) -> StorageResult<T> {
        self.expire(now_unix);
        let session = self.sessions.get_mut(session_id).ok_or_else(|| {
            StorageError::bad_request("private HNSW ORAM session is missing or expired")
        })?;
        if session.collection_id != collection_id || session.vector_name != vector_name {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session does not match collection/vector",
            ));
        }
        if session.lease_expires_unix <= now_unix {
            return Err(StorageError::bad_request(
                "private HNSW ORAM session lease expired",
            ));
        }
        action(session)
    }

    fn expire(&mut self, now_unix: u64) {
        let expired = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                (session.lease_expires_unix <= now_unix).then_some(session_id.clone())
            })
            .collect::<Vec<_>>();
        for session_id in expired {
            if let Some(session) = self.sessions.remove(&session_id) {
                let index_key = session_index_key(&session.collection_id, &session.vector_name);
                if self
                    .active_writer_by_index
                    .get(&index_key)
                    .is_some_and(|active| active == &session_id)
                {
                    self.active_writer_by_index.remove(&index_key);
                }
            }
        }
    }
}

impl PrivateHnswSession {
    fn response(&self) -> PrivateHnswSessionResponse {
        PrivateHnswSessionResponse {
            session_id: self.session_id.clone(),
            collection_id: self.collection_id.clone(),
            vector_name: self.vector_name.clone(),
            index_epoch: self.index_epoch,
            root_hash: self.root_hash.clone(),
            manifest: self.manifest.clone(),
            lease_expires_unix: self.lease_expires_unix,
        }
    }
}

struct ResolvedPrivateHnswContext {
    collection_path: std::path::PathBuf,
    collection_crypto_id: String,
    vector_name: String,
    expected_key_id: String,
    expected_rk_id: String,
    min_rk_epoch: u64,
    max_rk_epoch: u64,
    expected_dim: u32,
    expected_distance: DistanceKind,
    expected_result_privacy: ResultPrivacyMode,
    private_result_oram_binding_configured: bool,
    expected_hnsw: PrivateHnswParams,
    expected_oram: OramParams,
    expected_fixed_budget: FixedBudgetParams,
    signature_public_keys: HashMap<String, String>,
    public_key: Vec<u8>,
}

fn session_registry() -> &'static Mutex<PrivateHnswSessionRegistry> {
    static REGISTRY: OnceLock<Mutex<PrivateHnswSessionRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(PrivateHnswSessionRegistry::default()))
}

pub(crate) struct PrivateHnswCollectionSnapshotGuard {
    collection_id: String,
}

struct PrivateHnswUploadGuard {
    collection_id: String,
    vector_name: String,
}

impl Drop for PrivateHnswCollectionSnapshotGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = session_registry().lock() {
            registry.release_collection_snapshot(&self.collection_id);
        }
    }
}

impl Drop for PrivateHnswUploadGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = session_registry().lock() {
            registry.release_upload(&self.collection_id, &self.vector_name);
        }
    }
}

impl ResolvedPrivateHnswContext {
    fn manifest_context<'a>(
        &'a self,
        signature_key_id: &'a str,
    ) -> PrivateHnswManifestValidationContext<'a> {
        PrivateHnswManifestValidationContext {
            expected_collection_id: &self.collection_crypto_id,
            expected_vector_name: &self.vector_name,
            expected_key_id: &self.expected_key_id,
            expected_rk_id: &self.expected_rk_id,
            min_rk_epoch: self.min_rk_epoch,
            max_rk_epoch: self.max_rk_epoch,
            expected_dim: self.expected_dim,
            expected_distance: self.expected_distance,
            signature_verification: PrivateHnswSignatureVerification {
                expected_key_id: signature_key_id,
                public_key: &self.public_key,
            },
        }
    }

    fn validate_manifest_runtime_policy(
        &self,
        manifest: &PrivateHnswOramManifest,
    ) -> StorageResult<()> {
        self.validate_manifest_runtime_context(manifest)?;
        Ok(())
    }

    fn validate_manifest_runtime_context(
        &self,
        manifest: &PrivateHnswOramManifest,
    ) -> StorageResult<()> {
        if manifest.collection_id != self.collection_crypto_id {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest collection_id does not match runtime context",
            ));
        }
        if manifest.vector_name != self.vector_name {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest vector_name does not match runtime context",
            ));
        }
        if manifest.key_id != self.expected_key_id {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest key_id does not match runtime instance",
            ));
        }
        if manifest.rk_id != self.expected_rk_id {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest rk_id does not match runtime instance",
            ));
        }
        if manifest.rk_epoch < self.min_rk_epoch || manifest.rk_epoch > self.max_rk_epoch {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest rk_epoch does not match runtime instance",
            ));
        }
        if manifest.dim != self.expected_dim {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest dim does not match runtime vector size",
            ));
        }
        if manifest.distance != self.expected_distance {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest distance does not match runtime vector distance",
            ));
        }
        if manifest.result_privacy != self.expected_result_privacy {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest result_privacy does not match runtime instance",
            ));
        }
        if manifest.result_privacy == ResultPrivacyMode::PrivatePayloadOramRequired
            && !self.private_result_oram_binding_configured
        {
            return Err(StorageError::bad_request(format!(
                "private HNSW ORAM result_privacy=private_payload_oram_required requires a {PRIVATE_RESULT_ORAM_BINDING} payload rule backed by {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER}"
            )));
        }
        if manifest.hnsw != self.expected_hnsw {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest hnsw does not match runtime instance",
            ));
        }
        if manifest.oram != self.expected_oram {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest oram does not match runtime instance",
            ));
        }
        if manifest.fixed_budget != self.expected_fixed_budget {
            return Err(StorageError::bad_request(
                "private HNSW ORAM manifest fixed_budget does not match runtime instance",
            ));
        }
        Ok(())
    }

    fn signature_public_key(&self, signature_key_id: &str) -> StorageResult<Vec<u8>> {
        let public_key_b64 = self
            .signature_public_keys
            .get(signature_key_id)
            .ok_or_else(|| {
                StorageError::bad_request("private HNSW ORAM signature key id is not configured")
            })?;
        decode_signature_public_key(public_key_b64)
    }
}

pub async fn do_upload_private_hnsw_manifest(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    manifest: PrivateHnswOramManifest,
    signature: PrivateHnswOramSignature,
) -> StorageResult<PrivateHnswOramEpochState> {
    validate_private_hnsw_oram_manifest_signature_shape(&signature).map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
    let resolved = resolve_private_hnsw_context(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        &signature.key_id,
        "private_hnsw_manifest_upload",
        AccessRequirements::new().write(),
    )
    .await?;
    let epoch = validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_hnsw_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    let _upload_guard =
        begin_private_hnsw_upload_write_window(&resolved.collection_crypto_id, vector_name)?;

    let epoch_state = PrivateHnswOramEpochState {
        index_epoch: epoch.epoch,
        root_hash: manifest.root_hash.clone(),
    };
    let store = PrivateHnswOramStore::new(resolved.collection_path, vector_name)?;
    store
        .write_manifest_with_initial_epoch_if_absent_or_matching(
            &manifest,
            &signature,
            &epoch_state,
        )
        .map_err(private_hnsw_manifest_store_error)?;
    Ok(epoch_state)
}

pub(crate) fn begin_private_hnsw_collection_snapshot(
    collection_name: &str,
    config: &CollectionConfigInternal,
) -> StorageResult<Option<PrivateHnswCollectionSnapshotGuard>> {
    if !collection_uses_private_hnsw_oram(config) {
        return Ok(None);
    }

    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?;
    registry.begin_collection_snapshot(&collection_crypto_id, now_unix)?;
    Ok(Some(PrivateHnswCollectionSnapshotGuard {
        collection_id: collection_crypto_id,
    }))
}

pub async fn do_get_private_hnsw_manifest(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
) -> StorageResult<PrivateHnswManifestRecord> {
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "private_hnsw_manifest_read",
    )?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config.params.effective_encryption().ok_or_else(|| {
        StorageError::bad_request(format!(
            "collection {collection_name} does not configure private HNSW ORAM encryption",
        ))
    })?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    validate_private_hnsw_oram_manifest_signature_shape(&signature).map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = ResolvedPrivateHnswContext {
        collection_path: collection.path().to_path_buf(),
        public_key,
        ..runtime_context
    };
    validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_hnsw_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    Ok(PrivateHnswManifestRecord {
        manifest,
        signature,
    })
}

pub async fn do_upload_private_hnsw_buckets(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    index_epoch: u64,
    root_hash: String,
    buckets: Vec<PrivateHnswOramBucket>,
) -> StorageResult<PrivateHnswOramEpochState> {
    validate_root_hash_string(&root_hash, "root_hash")?;
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_hnsw_buckets_upload",
    )?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config.params.effective_encryption().ok_or_else(|| {
        StorageError::bad_request(format!(
            "collection {collection_name} does not configure private HNSW ORAM encryption",
        ))
    })?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    validate_private_hnsw_oram_manifest_signature_shape(&signature).map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = ResolvedPrivateHnswContext {
        collection_path: collection.path().to_path_buf(),
        public_key,
        ..runtime_context
    };
    validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_hnsw_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    let _upload_guard =
        begin_private_hnsw_upload_write_window(&resolved.collection_crypto_id, vector_name)?;
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    if current_epoch.index_epoch != index_epoch || current_epoch.root_hash != root_hash {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket upload epoch/root does not match current manifest epoch",
        ));
    }
    let max_ciphertext_bytes = max_bucket_ciphertext_bytes(&manifest)?;
    for bucket in &buckets {
        store
            .validate_bucket_for_write(
                bucket,
                index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .map_err(private_hnsw_upload_store_error)?;
        validate_bucket_ciphertext_fixed_size(bucket, &manifest)?;
    }
    let leaf_commitments =
        validate_initial_private_hnsw_upload_bundle(&manifest, index_epoch, &root_hash, &buckets)?;
    for bucket in &buckets {
        store
            .write_bucket(
                bucket,
                index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .map_err(private_hnsw_upload_store_error)?;
    }
    store
        .write_merkle_tree_from_commitments(index_epoch, root_hash.clone(), leaf_commitments)
        .map_err(private_hnsw_upload_store_error)?;
    Ok(PrivateHnswOramEpochState {
        index_epoch,
        root_hash,
    })
}

pub async fn do_open_private_hnsw_session(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    client_id: String,
    desired_epoch: u64,
    fixed_budget: bool,
    result_privacy: ResultPrivacyMode,
) -> StorageResult<PrivateHnswSessionResponse> {
    validate_private_hnsw_client_id_shape(&client_id)?;
    validate_private_hnsw_session_cluster_epoch_mode(toc.is_distributed())?;
    if is_strict(settings) && !fixed_budget {
        return Err(StorageError::bad_request(
            "private HNSW ORAM strict mode requires fixed_budget=true",
        ));
    }

    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_hnsw_session_open",
    )?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config.params.effective_encryption().ok_or_else(|| {
        StorageError::bad_request(format!(
            "collection {collection_name} does not configure private HNSW ORAM encryption",
        ))
    })?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let store = PrivateHnswOramStore::new(collection.path(), vector_name)?;
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    validate_private_hnsw_oram_manifest_signature_shape(&signature).map_err(private_hnsw_error)?;
    validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = ResolvedPrivateHnswContext {
        collection_path: collection.path().to_path_buf(),
        public_key,
        ..runtime_context
    };
    let manifest_epoch = validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_hnsw_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    if current_epoch.index_epoch != manifest_epoch.epoch
        || current_epoch.root_hash != manifest.root_hash
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM manifest epoch/root does not match current epoch",
        ));
    }
    if desired_epoch != current_epoch.index_epoch {
        return Err(StorageError::bad_request(
            "private HNSW ORAM requested epoch is not current epoch",
        ));
    }
    if manifest.result_privacy != result_privacy {
        return Err(StorageError::bad_request(
            "private HNSW ORAM requested result_privacy does not match manifest",
        ));
    }
    if !manifest.fixed_budget.enabled || !fixed_budget {
        return Err(StorageError::bad_request(
            "private HNSW ORAM sessions require fixed_budget=true",
        ));
    }
    let expected_open_epoch = current_epoch.clone();
    let expected_open_manifest = manifest.clone();
    let expected_open_signature = signature.clone();

    let now_unix = current_unix_secs()?;
    let session = PrivateHnswSession {
        session_id: new_session_id(),
        _client_id: client_id,
        collection_id: collection_crypto_id.clone(),
        collection_path: collection.path().to_path_buf(),
        vector_name: vector_name.to_string(),
        index_epoch: current_epoch.index_epoch,
        root_hash: current_epoch.root_hash.clone(),
        lease_expires_unix: now_unix.saturating_add(SESSION_LEASE_SECS),
        bucket_count: manifest.bucket_count,
        tree_height: manifest.oram.tree_height,
        path_batch_size: manifest.oram.path_batch_size,
        max_bucket_ciphertext_bytes: max_bucket_ciphertext_bytes(&manifest)?,
        manifest,
    };
    let response = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?
        .open(session, now_unix)?;
    if let Err(err) = ensure_private_hnsw_session_open_storage_matches(
        &store,
        &expected_open_epoch,
        &expected_open_manifest,
        &expected_open_signature,
    ) {
        if let Ok(mut registry) = session_registry().lock() {
            registry.close(
                &collection_crypto_id,
                vector_name,
                &response.session_id,
                now_unix,
            );
        }
        return Err(err);
    }
    Ok(response)
}

pub async fn do_read_private_hnsw_paths(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
    index_epoch: u64,
    root_hash: &str,
    paths: Vec<String>,
    padding: PrivateHnswReadPadding,
    client_signature: PrivateHnswClientSignature,
) -> StorageResult<PrivateHnswReadPathsResponse> {
    validate_client_signature_shape(&client_signature)?;
    validate_private_hnsw_session_id_shape(session_id)?;
    validate_root_hash_string(root_hash, "root_hash")?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_oram_read_paths",
        AccessRequirements::new(),
    )
    .await?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?;
    registry.with_session_mut(
        &request_context.collection_crypto_id,
        vector_name,
        session_id,
        now_unix,
        |session| {
            request_context.validate_manifest_runtime_context(&session.manifest)?;
            if session.index_epoch != index_epoch || session.root_hash != root_hash {
                return Err(StorageError::bad_request(
                    "private HNSW ORAM session epoch/root mismatch",
                ));
            }
            if padding.requested_paths != session.path_batch_size
                || paths.len() != session.path_batch_size as usize
                || !padding.dummy_paths_included
            {
                return Err(StorageError::bad_request(
                    "private HNSW ORAM read_paths request must match fixed path budget",
                ));
            }
            validate_session_signature_owner_key(session, &client_signature.key_id)?;
            let public_key = request_context.signature_public_key(&client_signature.key_id)?;
            let path_refs = paths.iter().map(String::as_str).collect::<Vec<_>>();
            validate_private_hnsw_oram_read_paths_signature(
                PrivateHnswOramReadPathsSignatureInput {
                    collection_id: &session.collection_id,
                    vector_name,
                    key_id: &session.manifest.key_id,
                    rk_id: &session.manifest.rk_id,
                    rk_epoch: session.manifest.rk_epoch,
                    index_epoch,
                    root_hash,
                    paths: &path_refs,
                    requested_paths: padding.requested_paths,
                    dummy_paths_included: padding.dummy_paths_included,
                    signature_alg: &client_signature.alg,
                    signature_key_id: &client_signature.key_id,
                },
                &client_signature.sig,
                PrivateHnswSignatureVerification {
                    expected_key_id: &client_signature.key_id,
                    public_key: &public_key,
                },
            )
            .map_err(private_hnsw_error)?;
            validate_private_hnsw_read_path_labels(&paths, session.tree_height)?;
            let bucket_ids =
                bucket_ids_for_path_batch(&paths, session.tree_height, session.bucket_count)?;
            let store = PrivateHnswOramStore::new(&session.collection_path, vector_name)?;
            ensure_private_hnsw_active_session_current_epoch(
                &store,
                session.index_epoch,
                &session.root_hash,
                "read_paths",
            )?;
            let (buckets, proof) = store
                .read_bucket_batch_with_proof(
                    &bucket_ids,
                    session.index_epoch,
                    &session.root_hash,
                    session.bucket_count,
                    session.max_bucket_ciphertext_bytes,
                )
                .map_err(private_hnsw_read_batch_store_error)?;
            ensure_private_hnsw_read_proof_matches_buckets(&proof, &buckets)?;
            validate_private_hnsw_read_bucket_ciphertexts_fixed_size(&session.manifest, &buckets)?;
            let proof_value = serde_json::to_string(&proof).map_err(|_| {
                StorageError::service_error("failed to serialize private HNSW ORAM Merkle proof")
            })?;
            Ok(PrivateHnswReadPathsResponse {
                index_epoch: session.index_epoch,
                root_hash: session.root_hash.clone(),
                buckets,
                proof: PrivateHnswReadProof {
                    kind: PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND.to_string(),
                    value: proof_value,
                },
            })
        },
    )
}

pub async fn do_commit_private_hnsw_paths(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    new_root_hash: String,
    updated_buckets: Vec<PrivateHnswOramBucket>,
    commit_signature: PrivateHnswClientSignature,
) -> StorageResult<PrivateHnswOramEpochState> {
    validate_client_signature_shape(&commit_signature)?;
    validate_private_hnsw_session_id_shape(session_id)?;
    validate_root_hash_string(&old_root_hash, "old_root_hash")?;
    validate_root_hash_string(&new_root_hash, "new_root_hash")?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_oram_commit",
        AccessRequirements::new().write(),
    )
    .await?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?;
    registry.with_session_mut(&request_context.collection_crypto_id, vector_name, session_id, now_unix, |session| {
        request_context.validate_manifest_runtime_context(&session.manifest)?;
        if session.index_epoch != old_epoch || session.root_hash != old_root_hash {
            return Err(StorageError::bad_request(
                "private HNSW ORAM commit old epoch/root does not match active session",
            ));
        }
        if new_epoch <= old_epoch {
            return Err(StorageError::bad_request(
                "private HNSW ORAM commit new_epoch must be greater than old_epoch",
            ));
        }
        let max_updated_buckets = max_updated_bucket_count(session)?;
        if updated_buckets.is_empty() || updated_buckets.len() > max_updated_buckets {
            return Err(StorageError::bad_request(format!(
                "private HNSW ORAM commit updated_buckets must contain 1..={max_updated_buckets} buckets",
            )));
        }
        let updated_bucket_refs = updated_buckets
            .iter()
            .map(|bucket| PrivateHnswOramCommitBucketRef {
                bucket_id: bucket.bucket_id,
                ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
            })
            .collect::<Vec<_>>();
        validate_session_signature_owner_key(session, &commit_signature.key_id)?;
        let public_key = request_context.signature_public_key(&commit_signature.key_id)?;
        validate_private_hnsw_oram_commit_signature(
            PrivateHnswOramCommitSignatureInput {
                collection_id: &session.collection_id,
                vector_name,
                key_id: &session.manifest.key_id,
                rk_id: &session.manifest.rk_id,
                rk_epoch: session.manifest.rk_epoch,
                old_epoch,
                new_epoch,
                old_root_hash: &old_root_hash,
                new_root_hash: &new_root_hash,
                updated_buckets: &updated_bucket_refs,
                signature_alg: &commit_signature.alg,
                signature_key_id: &commit_signature.key_id,
            },
            &commit_signature.sig,
            PrivateHnswSignatureVerification {
                expected_key_id: &commit_signature.key_id,
                public_key: &public_key,
            },
        )
        .map_err(private_hnsw_error)?;
        let mut seen_bucket_ids = HashSet::new();
        for bucket in &updated_buckets {
            if !seen_bucket_ids.insert(bucket.bucket_id) {
                return Err(StorageError::bad_request(
                    "private HNSW ORAM commit updated_buckets contains duplicate bucket id",
                ));
            }
            validate_root_hash_string(&bucket.ciphertext_sha256, "ciphertext_sha256")?;
            validate_private_hnsw_commit_bucket_ciphertexts_fixed_size(
                &session.manifest,
                std::slice::from_ref(bucket),
            )?;
        }

        let store = PrivateHnswOramStore::new(&session.collection_path, vector_name)?;
        ensure_private_hnsw_active_session_current_epoch(
            &store,
            old_epoch,
            &old_root_hash,
            "commit",
        )?;
        let old = PrivateHnswOramEpochState {
            index_epoch: old_epoch,
            root_hash: old_root_hash,
        };
        let new = PrivateHnswOramEpochState {
            index_epoch: new_epoch,
            root_hash: new_root_hash,
        };
        let store_commit_signature = PrivateHnswOramSignature {
            alg: commit_signature.alg.clone(),
            key_id: commit_signature.key_id.clone(),
            sig: commit_signature.sig.clone(),
        };
        let committed = store
            .commit_writeback_with_signature(
                &old,
                &new,
                session.bucket_count,
                &updated_buckets,
                session.max_bucket_ciphertext_bytes,
                &store_commit_signature,
                PrivateHnswSignatureVerification {
                    expected_key_id: &commit_signature.key_id,
                    public_key: &public_key,
                },
            )
            .map_err(private_hnsw_commit_writeback_store_error)?;
        session.index_epoch = committed.index_epoch;
        session.root_hash = committed.root_hash.clone();
        session.lease_expires_unix = now_unix.saturating_add(SESSION_LEASE_SECS);
        Ok(committed)
    })
}

pub async fn do_close_private_hnsw_session(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
) -> StorageResult<bool> {
    validate_private_hnsw_session_id_shape(session_id)?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_session_close",
        AccessRequirements::new().write(),
    )
    .await?;
    let now_unix = current_unix_secs()?;
    let closed = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?
        .close(
            &request_context.collection_crypto_id,
            vector_name,
            session_id,
            now_unix,
        );
    if !closed {
        return Err(StorageError::bad_request(
            "private HNSW ORAM session is missing or already closed",
        ));
    }
    Ok(true)
}

pub fn validate_recovered_private_hnsw_oram_snapshot_signatures(
    settings: &Settings,
    collection_name: &str,
    config: &CollectionConfigInternal,
    collection_path: &Path,
) -> StorageResult<()> {
    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let Some(encryption) = config.params.effective_encryption() else {
        return Ok(());
    };
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection_name,
        &collection_crypto_id,
        &config.params,
    )?;

    let mut checked_vectors = HashSet::new();
    for rule in encryption
        .rules
        .iter()
        .filter(|rule| rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING))
    {
        let EncryptionSelector::VectorNames { names } = &rule.selector else {
            return Err(StorageError::bad_request(
                "private HNSW ORAM snapshot rule must use vector_names selector",
            ));
        };
        let instance = private_hnsw_instance(settings, rule)?;
        for vector_name in names {
            if !checked_vectors.insert(vector_name.clone()) {
                continue;
            }
            let store = PrivateHnswOramStore::new(collection_path, vector_name)?;
            let (manifest, signature) = read_uploaded_manifest(&store)?;
            validate_private_hnsw_oram_manifest_signature_shape(&signature)
                .map_err(private_hnsw_error)?;
            validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature)?;
            let runtime_context = manifest_context_from_runtime(
                &config.params,
                &collection_crypto_id,
                vector_name,
                instance,
                has_private_result_oram_binding(settings, &encryption),
            )?;
            let public_key = signature_public_key(instance, &signature.key_id)?;
            let resolved = ResolvedPrivateHnswContext {
                collection_path: collection_path.to_path_buf(),
                public_key,
                ..runtime_context
            };
            validate_private_hnsw_oram_manifest(
                &manifest,
                Some(&signature),
                resolved.manifest_context(&signature.key_id),
            )
            .map_err(private_hnsw_error)?;
            resolved.validate_manifest_runtime_policy(&manifest)?;
            let expected_epoch = PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            };
            ensure_private_hnsw_restored_snapshot_storage_matches(
                &store,
                &expected_epoch,
                &manifest,
                &signature,
            )?;
        }
    }

    Ok(())
}

async fn resolve_private_hnsw_context(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    signature_key_id: &str,
    method: &str,
    requirements: AccessRequirements,
) -> StorageResult<ResolvedPrivateHnswContext> {
    let pass = auth.check_collection_access(collection_name, requirements, method)?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config.params.effective_encryption().ok_or_else(|| {
        StorageError::bad_request(format!(
            "collection {collection_name} does not configure private HNSW ORAM encryption",
        ))
    })?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    Ok(ResolvedPrivateHnswContext {
        collection_path: collection.path().to_path_buf(),
        public_key: signature_public_key(instance, signature_key_id)?,
        ..runtime_context
    })
}

fn private_hnsw_rule<'a>(
    encryption: &'a CollectionEncryptionConfig,
    vector_name: &str,
) -> StorageResult<&'a EncryptionRuleRef> {
    encryption
        .rules
        .iter()
        .find(|rule| {
            rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING)
                && matches!(
                    &rule.selector,
                    EncryptionSelector::VectorNames { names }
                        if names.iter().any(|name| name == vector_name)
                )
        })
        .ok_or_else(|| {
            StorageError::bad_request(private_hnsw_oram_api_required_message(vector_name))
        })
}

fn private_hnsw_instance<'a>(
    settings: &'a Settings,
    rule: &EncryptionRuleRef,
) -> StorageResult<&'a CryptoInstanceConfig> {
    let instance = settings
        .crypto
        .instances
        .get(&rule.instance)
        .ok_or_else(|| {
            StorageError::bad_request(
                "private HNSW ORAM collection binding references a missing runtime instance",
            )
        })?;
    if instance.provider != VECTOR_PRIVATE_HNSW_ORAM_PROVIDER {
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM collection binding must reference a {VECTOR_PRIVATE_HNSW_ORAM_PROVIDER} runtime instance",
        )));
    }
    Ok(instance)
}

fn has_private_result_oram_binding(
    settings: &Settings,
    encryption: &CollectionEncryptionConfig,
) -> bool {
    encryption.rules.iter().any(|rule| {
        rule.binding.as_deref() == Some(PRIVATE_RESULT_ORAM_BINDING)
            && settings
                .crypto
                .instances
                .get(&rule.instance)
                .is_some_and(|instance| instance.provider == PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER)
    })
}

fn read_uploaded_manifest(
    store: &PrivateHnswOramStore,
) -> StorageResult<(PrivateHnswOramManifest, PrivateHnswOramSignature)> {
    store
        .read_manifest()
        .map_err(private_hnsw_manifest_read_store_error)
}

fn validate_private_hnsw_manifest_signature_owner_key(
    manifest: &PrivateHnswOramManifest,
    signature: &PrivateHnswOramSignature,
) -> StorageResult<()> {
    if signature.key_id != manifest.owner_signing_key_id {
        return Err(private_hnsw_error(
            qdrant_sec::PrivateHnswOramError::SignatureKeyIdMismatch,
        ));
    }
    Ok(())
}

fn ensure_private_hnsw_session_open_storage_matches(
    store: &PrivateHnswOramStore,
    expected_epoch: &PrivateHnswOramEpochState,
    expected_manifest: &PrivateHnswOramManifest,
    expected_signature: &PrivateHnswOramSignature,
) -> StorageResult<()> {
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    let (stored_manifest, stored_signature) = read_uploaded_manifest(store)?;
    if current_epoch != *expected_epoch
        || stored_manifest != *expected_manifest
        || stored_signature != *expected_signature
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM session open observed concurrent manifest or epoch update",
        ));
    }
    store
        .read_bucket_batch_with_proof(
            &[0],
            expected_epoch.index_epoch,
            &expected_epoch.root_hash,
            expected_manifest.bucket_count,
            max_bucket_ciphertext_bytes(expected_manifest)?,
        )
        .map_err(private_hnsw_read_batch_store_error)?;
    Ok(())
}

fn ensure_private_hnsw_restored_snapshot_storage_matches(
    store: &PrivateHnswOramStore,
    expected_epoch: &PrivateHnswOramEpochState,
    expected_manifest: &PrivateHnswOramManifest,
    expected_signature: &PrivateHnswOramSignature,
) -> StorageResult<()> {
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    let (stored_manifest, stored_signature) = read_uploaded_manifest(store)?;
    if current_epoch != *expected_epoch
        || stored_manifest != *expected_manifest
        || stored_signature != *expected_signature
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM restored snapshot manifest or epoch does not match current storage",
        ));
    }
    let max_bucket_ciphertext_bytes = max_bucket_ciphertext_bytes(expected_manifest)?;
    for bucket_id in 0..expected_manifest.bucket_count {
        store
            .read_bucket_batch_with_proof(
                &[bucket_id],
                expected_epoch.index_epoch,
                &expected_epoch.root_hash,
                expected_manifest.bucket_count,
                max_bucket_ciphertext_bytes,
            )
            .map_err(private_hnsw_read_batch_store_error)?;
    }
    Ok(())
}

fn private_hnsw_manifest_read_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM manifest has not been uploaded")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM manifest store validation failed")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private HNSW ORAM manifest store validation failed")
        }
        _ => StorageError::service_error("private HNSW ORAM manifest store validation failed"),
    }
}

fn private_hnsw_read_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM encrypted bucket data is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM encrypted bucket store validation failed")
        }
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
        _ => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
    }
}

fn private_hnsw_read_batch_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::BadRequest { description }
            if description.contains(
                "private HNSW ORAM encrypted bucket/proof consistency validation failed",
            ) =>
        {
            StorageError::bad_request(
                "private HNSW ORAM encrypted bucket/proof consistency validation failed",
            )
        }
        other => private_hnsw_read_store_error(other),
    }
}

fn private_hnsw_manifest_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM manifest store is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM manifest store validation failed")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private HNSW ORAM manifest store validation failed")
        }
        _ => StorageError::service_error("private HNSW ORAM manifest store validation failed"),
    }
}

fn private_hnsw_epoch_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM current epoch is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM current epoch validation failed")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private HNSW ORAM current epoch validation failed")
        }
        _ => StorageError::service_error("private HNSW ORAM current epoch validation failed"),
    }
}

fn private_hnsw_upload_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM encrypted bucket store is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private HNSW ORAM encrypted bucket store validation failed")
        }
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
        _ => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
    }
}

fn private_hnsw_commit_writeback_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => StorageError::not_found(
            "private HNSW ORAM encrypted bucket store metadata is unavailable",
        ),
        CollectionError::BadRequest { description }
            if description.contains("commit signature verification failed") =>
        {
            StorageError::bad_request("private HNSW ORAM commit signature verification failed")
        }
        CollectionError::BadRequest { description }
            if description.contains("commit bucket commitment context mismatch") =>
        {
            StorageError::bad_request("private HNSW ORAM commit bucket commitment context mismatch")
        }
        CollectionError::BadRequest { description }
            if description.contains("bucket ciphertext must match fixed ciphertext size") =>
        {
            StorageError::bad_request(
                "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
            )
        }
        CollectionError::BadRequest { description }
            if description.contains("bucket ciphertext") =>
        {
            StorageError::bad_request("private HNSW ORAM bucket ciphertext validation failed")
        }
        CollectionError::BadRequest { .. } => StorageError::bad_request(
            "private HNSW ORAM encrypted bucket store metadata validation failed",
        ),
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store metadata validation failed",
        ),
        _ => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store metadata validation failed",
        ),
    }
}

fn manifest_context_from_runtime(
    params: &CollectionParams,
    collection_crypto_id: &str,
    vector_name: &str,
    instance: &CryptoInstanceConfig,
    private_result_oram_binding_configured: bool,
) -> StorageResult<ResolvedPrivateHnswContext> {
    let vector_params = params.vectors.get_params(vector_name).ok_or_else(|| {
        CollectionError::bad_input("private HNSW ORAM vector is not configured as a dense vector")
    })?;
    let key_id = required_option_string(instance, KEY_ID_OPTION)?;
    let expected_rk_id = required_option_string(instance, EXPECTED_RK_ID_OPTION)?;
    let min_rk_epoch = required_option_u64(instance, MIN_RK_EPOCH_OPTION)?;
    let max_rk_epoch = required_option_u64(instance, MAX_RK_EPOCH_OPTION)?;
    let expected_result_privacy = result_privacy_from_runtime(instance)?;
    let expected_hnsw = required_option_struct(instance, HNSW_OPTION)?;
    let expected_oram = required_option_struct(instance, ORAM_OPTION)?;
    let expected_fixed_budget = required_option_struct(instance, FIXED_BUDGET_OPTION)?;
    let verifier_public_keys = signature_public_keys(instance)?;
    let expected_distance = distance_kind(vector_params.distance);
    let expected_dim = u32::try_from(vector_params.size.get()).map_err(|_| {
        StorageError::bad_request(
            "private HNSW ORAM vector size exceeds supported manifest dim range",
        )
    })?;
    Ok(ResolvedPrivateHnswContext {
        collection_path: std::path::PathBuf::new(),
        collection_crypto_id: collection_crypto_id.to_string(),
        vector_name: vector_name.to_string(),
        expected_key_id: key_id,
        expected_rk_id,
        min_rk_epoch,
        max_rk_epoch,
        expected_dim,
        expected_distance,
        expected_result_privacy,
        private_result_oram_binding_configured,
        expected_hnsw,
        expected_oram,
        expected_fixed_budget,
        signature_public_keys: verifier_public_keys,
        public_key: Vec::new(),
    })
}

fn result_privacy_from_runtime(
    instance: &CryptoInstanceConfig,
) -> StorageResult<ResultPrivacyMode> {
    match required_option_string(instance, RESULT_PRIVACY_OPTION)?.as_str() {
        "ids_visible" => Ok(ResultPrivacyMode::IdsVisible),
        "private_payload_oram_required" => Ok(ResultPrivacyMode::PrivatePayloadOramRequired),
        _ => Err(StorageError::bad_request(format!(
            "private HNSW ORAM option {RESULT_PRIVACY_OPTION} has unsupported value",
        ))),
    }
}

fn signature_public_key(
    instance: &CryptoInstanceConfig,
    signature_key_id: &str,
) -> StorageResult<Vec<u8>> {
    let registry = signature_public_keys(instance)?;
    let public_key_b64 = registry.get(signature_key_id).ok_or_else(|| {
        StorageError::bad_request("private HNSW ORAM signature key id is not configured")
    })?;
    decode_signature_public_key(public_key_b64)
}

fn signature_public_keys(
    instance: &CryptoInstanceConfig,
) -> StorageResult<HashMap<String, String>> {
    let registry = instance
        .options
        .get(SIGNATURE_PUBLIC_KEYS_OPTION)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            StorageError::bad_request(
                "private HNSW ORAM runtime instance must configure signature_public_keys",
            )
        })?;
    registry
        .iter()
        .map(|(key_id, public_key)| {
            let public_key_b64 = public_key.as_str().ok_or_else(|| {
                StorageError::bad_request("private HNSW ORAM public key is not base64url")
            })?;
            Ok((key_id.clone(), public_key_b64.to_string()))
        })
        .collect()
}

fn decode_signature_public_key(public_key_b64: &str) -> StorageResult<Vec<u8>> {
    if public_key_b64.len() != PRIVATE_HNSW_ORAM_ROOT_HASH_B64_LEN {
        return Err(StorageError::bad_request(
            "private HNSW ORAM public key must be 32 bytes",
        ));
    }
    let public_key = BASE64URL_NOPAD
        .decode(public_key_b64.as_bytes())
        .map_err(|_| StorageError::bad_request("private HNSW ORAM public key is not base64url"))?;
    if public_key.len() != 32 {
        return Err(StorageError::bad_request(
            "private HNSW ORAM public key must be 32 bytes",
        ));
    }
    Ok(public_key)
}

async fn collection_context_for_request(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    signature_key_id: Option<&str>,
    method: &str,
    requirements: AccessRequirements,
) -> StorageResult<ResolvedPrivateHnswContext> {
    let pass = auth.check_collection_access(collection_name, requirements, method)?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config.params.effective_encryption().ok_or_else(|| {
        StorageError::bad_request(format!(
            "collection {collection_name} does not configure private HNSW ORAM encryption",
        ))
    })?;
    let rule = private_hnsw_rule(&encryption, vector_name)?;
    let instance = private_hnsw_instance(settings, rule)?;
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
        has_private_result_oram_binding(settings, &encryption),
    )?;
    let public_key = if let Some(signature_key_id) = signature_key_id {
        signature_public_key(instance, signature_key_id)?
    } else {
        Vec::new()
    };
    Ok(ResolvedPrivateHnswContext {
        collection_path: collection.path().to_path_buf(),
        public_key,
        ..runtime_context
    })
}

fn validate_client_signature_shape(signature: &PrivateHnswClientSignature) -> StorageResult<()> {
    if signature.alg != "ed25519" {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature algorithm must be ed25519",
        ));
    }
    if signature.key_id.is_empty() || signature.sig.is_empty() {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature key_id and sig are required",
        ));
    }
    validate_client_signature_key_id_shape(&signature.key_id)?;
    if signature.sig.len() != PRIVATE_HNSW_ORAM_SIGNATURE_B64_LEN {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature must encode 64 bytes",
        ));
    }
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| StorageError::bad_request("private HNSW ORAM signature is not base64url"))?;
    if signature_bytes.len() != 64 {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature must encode 64 bytes",
        ));
    }
    Ok(())
}

fn validate_client_signature_key_id_shape(key_id: &str) -> StorageResult<()> {
    if key_id.len() > 128
        || !key_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
        })
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM signature key_id is invalid",
        ));
    }
    Ok(())
}

fn validate_private_hnsw_client_id_shape(client_id: &str) -> StorageResult<()> {
    if client_id.is_empty() || client_id.len() > PRIVATE_HNSW_ORAM_CLIENT_ID_MAX_LEN {
        return Err(StorageError::bad_request(
            "private HNSW ORAM client_id must be non-empty and at most 256 bytes",
        ));
    }
    if !client_id.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
    }) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM client_id is invalid",
        ));
    }
    Ok(())
}

fn validate_private_hnsw_session_id_shape(session_id: &str) -> StorageResult<()> {
    if session_id.is_empty()
        || session_id.len() > PRIVATE_HNSW_ORAM_SESSION_ID_MAX_LEN
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM session_id is invalid",
        ));
    }
    Ok(())
}

fn required_option_string(instance: &CryptoInstanceConfig, key: &str) -> StorageResult<String> {
    instance
        .options
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| StorageError::bad_request(format!("private HNSW ORAM option {key} missing")))
}

fn required_option_u64(instance: &CryptoInstanceConfig, key: &str) -> StorageResult<u64> {
    instance
        .options
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| StorageError::bad_request(format!("private HNSW ORAM option {key} missing")))
}

fn required_option_struct<T>(instance: &CryptoInstanceConfig, key: &str) -> StorageResult<T>
where
    T: DeserializeOwned,
{
    let value = instance.options.get(key).ok_or_else(|| {
        StorageError::bad_request(format!("private HNSW ORAM option {key} missing"))
    })?;
    serde_json::from_value(value.clone()).map_err(|_| {
        StorageError::bad_request(format!("private HNSW ORAM option {key} is invalid"))
    })
}

fn distance_kind(distance: Distance) -> DistanceKind {
    match distance {
        Distance::Cosine => DistanceKind::Cosine,
        Distance::Euclid => DistanceKind::Euclid,
        Distance::Dot => DistanceKind::Dot,
        Distance::Manhattan => DistanceKind::Manhattan,
    }
}

fn private_hnsw_error(err: qdrant_sec::PrivateHnswOramError) -> StorageError {
    match err {
        qdrant_sec::PrivateHnswOramError::UnsupportedSignatureAlgorithm(_) => {
            StorageError::bad_request("private HNSW ORAM signature algorithm must be ed25519")
        }
        qdrant_sec::PrivateHnswOramError::SignatureKeyIdMismatch => StorageError::bad_request(
            "private HNSW ORAM signature key_id does not match manifest owner_signing_key_id",
        ),
        _ => StorageError::bad_request("private HNSW ORAM request validation failed"),
    }
}

fn is_strict(settings: &Settings) -> bool {
    settings.crypto.zero_trust_profile.as_deref() == Some(ZERO_TRUST_PROFILE_STRICT)
}

fn validate_private_hnsw_session_cluster_epoch_mode(distributed: bool) -> StorageResult<()> {
    if distributed {
        return Err(StorageError::bad_request(
            "private HNSW ORAM distributed sessions require consensus-backed epoch/root CAS; \
             this MVP supports private ORAM sessions only in single-node mode",
        ));
    }
    Ok(())
}

fn begin_private_hnsw_upload_write_window(
    collection_id: &str,
    vector_name: &str,
) -> StorageResult<PrivateHnswUploadGuard> {
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?;
    registry.begin_upload(collection_id, vector_name, now_unix)?;
    Ok(PrivateHnswUploadGuard {
        collection_id: collection_id.to_string(),
        vector_name: vector_name.to_string(),
    })
}

fn ensure_private_hnsw_write_window_in_registry(
    registry: &mut PrivateHnswSessionRegistry,
    collection_id: &str,
    vector_name: &str,
    now_unix: u64,
) -> StorageResult<()> {
    if registry
        .active_snapshot_by_collection
        .contains_key(collection_id)
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM upload requires no active collection snapshot",
        ));
    }
    if registry.has_active_index(collection_id, vector_name, now_unix) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM upload requires no active session for this index",
        ));
    }
    if registry
        .active_upload_by_index
        .contains_key(&session_index_key(collection_id, vector_name))
    {
        return Err(StorageError::bad_request(
            "private HNSW ORAM upload requires no active upload for this index",
        ));
    }
    Ok(())
}

fn ensure_no_active_private_hnsw_collection_session_in_registry(
    registry: &mut PrivateHnswSessionRegistry,
    collection_id: &str,
    now_unix: u64,
) -> StorageResult<()> {
    if registry.has_active_collection(collection_id, now_unix) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM collection snapshot requires no active private ORAM session",
        ));
    }
    if registry.has_active_upload_collection(collection_id) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM collection snapshot requires no active private ORAM upload",
        ));
    }
    Ok(())
}

fn collection_uses_private_hnsw_oram(config: &CollectionConfigInternal) -> bool {
    config
        .params
        .effective_encryption()
        .is_some_and(|encryption| {
            encryption
                .rules
                .iter()
                .any(|rule| rule.binding.as_deref() == Some(PRIVATE_HNSW_ORAM_BINDING))
        })
}

fn ensure_private_hnsw_active_session_current_epoch(
    store: &PrivateHnswOramStore,
    expected_epoch: u64,
    expected_root_hash: &str,
    operation: &str,
) -> StorageResult<()> {
    let current = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    if current.index_epoch != expected_epoch || current.root_hash != expected_root_hash {
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM {operation} current epoch/root does not match active session"
        )));
    }
    Ok(())
}

fn validate_session_signature_owner_key(
    session: &PrivateHnswSession,
    signature_key_id: &str,
) -> StorageResult<()> {
    if signature_key_id != session.manifest.owner_signing_key_id {
        return Err(StorageError::bad_request(
            "private HNSW ORAM request signature key_id does not match manifest owner_signing_key_id",
        ));
    }
    Ok(())
}

fn current_unix_secs() -> StorageResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| {
            StorageError::service_error(format!("system clock before UNIX epoch: {err}"))
        })
}

fn new_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn session_index_key(collection_id: &str, vector_name: &str) -> String {
    format!("{collection_id}\x1f{vector_name}")
}

fn ensure_private_hnsw_read_proof_matches_buckets(
    proof: &PrivateHnswOramMerkleProof,
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<()> {
    if proof.leaves.len() != buckets.len() {
        return Err(StorageError::bad_request(
            "private HNSW ORAM encrypted bucket/proof consistency validation failed",
        ));
    }
    for (leaf, bucket) in proof.leaves.iter().zip(buckets) {
        if leaf.bucket_id != bucket.bucket_id || leaf.leaf_hash != bucket.bucket_commitment {
            return Err(StorageError::bad_request(
                "private HNSW ORAM encrypted bucket/proof consistency validation failed",
            ));
        }
    }
    Ok(())
}

fn max_bucket_ciphertext_bytes(manifest: &PrivateHnswOramManifest) -> StorageResult<usize> {
    let block_size = usize::try_from(manifest.oram.block_size_bytes).map_err(|_| {
        StorageError::bad_request("private HNSW ORAM block_size_bytes exceeds usize")
    })?;
    let bucket_size = usize::try_from(manifest.oram.bucket_size)
        .map_err(|_| StorageError::bad_request("private HNSW ORAM bucket_size exceeds usize"))?;
    block_size
        .checked_mul(bucket_size)
        .and_then(|size| size.checked_add(4096))
        .ok_or_else(|| StorageError::bad_request("private HNSW ORAM bucket size overflows"))
}

fn expected_bucket_ciphertext_bytes(manifest: &PrivateHnswOramManifest) -> StorageResult<usize> {
    private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(private_hnsw_bucket_ciphertext_size_error)
}

fn private_hnsw_bucket_ciphertext_size_error(_err: PrivateHnswOramError) -> StorageError {
    StorageError::bad_request("private HNSW ORAM bucket ciphertext size is invalid")
}

fn validate_bucket_ciphertext_fixed_size(
    bucket: &PrivateHnswOramBucket,
    manifest: &PrivateHnswOramManifest,
) -> StorageResult<()> {
    let expected = expected_bucket_ciphertext_bytes(manifest)?;
    let expected_encoded_len = max_base64url_nopad_encoded_len(expected).ok_or_else(|| {
        StorageError::bad_request("private HNSW ORAM bucket ciphertext size is invalid")
    })?;
    if bucket.ciphertext.len() != expected_encoded_len {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            StorageError::bad_request("private HNSW ORAM bucket ciphertext is not base64url")
        })?;
    if ciphertext.len() != expected {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket ciphertext must match fixed ciphertext size",
        ));
    }
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

fn validate_private_hnsw_read_bucket_ciphertexts_fixed_size(
    manifest: &PrivateHnswOramManifest,
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<()> {
    for bucket in buckets {
        validate_bucket_ciphertext_fixed_size(bucket, manifest)?;
    }
    Ok(())
}

fn validate_private_hnsw_commit_bucket_ciphertexts_fixed_size(
    manifest: &PrivateHnswOramManifest,
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<()> {
    validate_private_hnsw_read_bucket_ciphertexts_fixed_size(manifest, buckets).map_err(|_| {
        StorageError::bad_request("private HNSW ORAM bucket ciphertext validation failed")
    })
}

fn max_updated_bucket_count(session: &PrivateHnswSession) -> StorageResult<usize> {
    private_hnsw_oram_fixed_writeback_bucket_budget(&session.manifest.oram)
        .map_err(|_| StorageError::bad_request("private HNSW ORAM writeback size overflows"))
}

fn validate_initial_private_hnsw_upload_bundle(
    manifest: &PrivateHnswOramManifest,
    index_epoch: u64,
    root_hash: &str,
    buckets: &[PrivateHnswOramBucket],
) -> StorageResult<Vec<String>> {
    if manifest.index_epoch != index_epoch || manifest.root_hash != root_hash {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket upload epoch/root does not match manifest",
        ));
    }
    let leaf_commitments =
        ordered_initial_bucket_commitments(buckets, index_epoch, manifest.bucket_count)?;
    validate_bucket_commitment_context(manifest, index_epoch, buckets, "initial upload")?;
    let computed_root = PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments)?;
    if computed_root != root_hash {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket upload Merkle root mismatch",
        ));
    }
    Ok(leaf_commitments)
}

fn validate_bucket_commitment_context(
    manifest: &PrivateHnswOramManifest,
    index_epoch: u64,
    buckets: &[PrivateHnswOramBucket],
    operation: &str,
) -> StorageResult<()> {
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
            StorageError::bad_request(format!(
                "private HNSW ORAM {operation} bucket commitment context mismatch",
            ))
        })?;
        if expected_commitment != bucket.bucket_commitment {
            return Err(StorageError::bad_request(format!(
                "private HNSW ORAM {operation} bucket commitment context mismatch",
            )));
        }
    }
    Ok(())
}

fn ordered_initial_bucket_commitments(
    buckets: &[PrivateHnswOramBucket],
    expected_epoch: u64,
    bucket_count: u64,
) -> StorageResult<Vec<String>> {
    let bucket_count_usize = usize::try_from(bucket_count).map_err(|_| {
        StorageError::bad_request("private HNSW ORAM bucket_count exceeds supported range")
    })?;
    if buckets.len() != bucket_count_usize {
        return Err(StorageError::bad_request(
            "private HNSW ORAM initial upload must include the configured bucket count",
        ));
    }
    let mut commitments = vec![None; bucket_count_usize];
    for bucket in buckets {
        if bucket.index_epoch != expected_epoch {
            return Err(StorageError::bad_request(
                "private HNSW ORAM initial upload bucket has stale epoch",
            ));
        }
        if bucket.bucket_id >= bucket_count {
            return Err(StorageError::bad_request(
                "private HNSW ORAM initial upload bucket is out of range",
            ));
        }
        validate_root_hash_string(&bucket.bucket_commitment, "bucket_commitment")?;
        let bucket_index = usize::try_from(bucket.bucket_id).map_err(|_| {
            StorageError::bad_request("private HNSW ORAM bucket id exceeds supported range")
        })?;
        if commitments[bucket_index].is_some() {
            return Err(StorageError::bad_request(
                "private HNSW ORAM initial upload contains duplicate bucket",
            ));
        }
        commitments[bucket_index] = Some(bucket.bucket_commitment.clone());
    }
    commitments
        .into_iter()
        .enumerate()
        .map(|(_bucket_id, commitment)| {
            commitment.ok_or_else(|| {
                StorageError::bad_request("private HNSW ORAM initial upload is missing a bucket")
            })
        })
        .collect()
}

fn validate_unique_path_labels(paths: &[String]) -> StorageResult<()> {
    let mut seen_paths = HashSet::new();
    for path in paths {
        if !seen_paths.insert(path.as_str()) {
            return Err(StorageError::bad_request(
                "private HNSW ORAM read_paths request contains duplicate path label",
            ));
        }
    }
    Ok(())
}

fn validate_private_hnsw_read_path_labels(paths: &[String], tree_height: u32) -> StorageResult<()> {
    validate_unique_path_labels(paths)?;
    for path in paths {
        if path.len() != PRIVATE_HNSW_ORAM_LEAF_LABEL_B64_LEN {
            return Err(StorageError::bad_request(
                "private HNSW ORAM read_paths request contains invalid path label",
            ));
        }
        decode_private_hnsw_oram_leaf_label(path, tree_height).map_err(|_| {
            StorageError::bad_request(
                "private HNSW ORAM read_paths request contains invalid path label",
            )
        })?;
    }
    Ok(())
}

fn bucket_ids_for_path_batch(
    paths: &[String],
    tree_height: u32,
    bucket_count: u64,
) -> StorageResult<Vec<u64>> {
    let expected_bucket_count = private_hnsw_oram_bucket_count(tree_height)
        .map_err(|_| StorageError::bad_request("private HNSW ORAM tree_height is invalid"))?;
    if bucket_count != expected_bucket_count {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket_count does not match tree_height",
        ));
    }

    let path_len = usize::try_from(tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or_else(|| StorageError::bad_request("private HNSW ORAM tree_height is too large"))?;
    let mut bucket_ids = Vec::with_capacity(paths.len().saturating_mul(path_len));
    for path in paths {
        let leaf = decode_private_hnsw_oram_leaf_label(path, tree_height).map_err(|_| {
            StorageError::bad_request(
                "private HNSW ORAM read_paths request contains invalid path label",
            )
        })?;
        bucket_ids.extend(
            private_hnsw_oram_bucket_ids_for_leaf(leaf, tree_height).map_err(|_| {
                StorageError::bad_request("private HNSW ORAM read_paths bucket derivation failed")
            })?,
        );
    }
    Ok(bucket_ids)
}

fn validate_root_hash_string(value: &str, field: &str) -> StorageResult<()> {
    if value.len() != PRIVATE_HNSW_ORAM_ROOT_HASH_B64_LEN {
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM {field} must encode 32 bytes",
        )));
    }
    let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        StorageError::bad_request(format!("private HNSW ORAM {field} is not base64url"))
    })?;
    if bytes.len() != 32 {
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM {field} must encode 32 bytes",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod private_hnsw_tests {
    use std::collections::BTreeMap;

    use collection::config::{CryptoMigrationState, WalConfig};
    use collection::operations::types::VectorsConfig;
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::optimizers_builder::OptimizersConfig;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        FixedBudgetParams, OramKind, OramParams, PrivateHnswBucketAeadBaseContext,
        PrivateHnswBuildPoint, PrivateHnswClientKeys, PrivateHnswManifestBuildContext,
        PrivateHnswOramClientConfig, PrivateHnswParams, PrivateHnswSignatureVerification,
        SecretKey, build_private_hnsw_oram_manifest_from_encrypted_index,
        build_private_hnsw_oram_plaintext_index_from_f32_points,
        encode_private_hnsw_oram_leaf_label, seal_private_hnsw_oram_plaintext_index,
        sign_private_hnsw_oram_manifest,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::*;
    use crate::settings::CryptoSettings;

    #[test]
    fn path_oram_leaf_labels_map_to_heap_bucket_paths() {
        let leaf = BASE64URL_NOPAD.encode(&5u64.to_be_bytes());
        let bucket_ids = bucket_ids_for_path_batch(&[leaf], 3, 15).unwrap();
        assert_eq!(bucket_ids, vec![0, 2, 5, 12]);
    }

    #[test]
    fn path_oram_batch_preserves_fixed_size_bucket_sequence() {
        let left = BASE64URL_NOPAD.encode(&4u64.to_be_bytes());
        let right = BASE64URL_NOPAD.encode(&5u64.to_be_bytes());
        let bucket_ids = bucket_ids_for_path_batch(&[left, right], 3, 15).unwrap();
        assert_eq!(bucket_ids, vec![0, 2, 5, 11, 0, 2, 5, 12]);
    }

    #[test]
    fn private_hnsw_bucket_shape_errors_are_sanitized() {
        let rendered = private_hnsw_bucket_ciphertext_size_error(
            qdrant_sec::PrivateHnswOramError::InvalidManifestField("oram.bucket_size"),
        )
        .to_string();
        assert!(rendered.contains("bucket ciphertext size is invalid"));
        assert!(!rendered.contains("oram.bucket_size"), "{rendered}");

        let leaf = BASE64URL_NOPAD.encode(&0u64.to_be_bytes());
        let rendered = bucket_ids_for_path_batch(&[leaf], 63, 1)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("tree_height is invalid"));
        assert!(!rendered.contains("63"), "{rendered}");
    }

    #[test]
    fn read_path_budget_rejects_duplicate_path_labels() {
        let leaf = BASE64URL_NOPAD.encode(&5u64.to_be_bytes());
        let err = validate_unique_path_labels(&[leaf.clone(), leaf]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("duplicate path label"));
        assert!(!rendered.contains(&BASE64URL_NOPAD.encode(&5u64.to_be_bytes())));
    }

    #[test]
    fn read_path_labels_reject_oversized_or_malformed_values_without_reflecting_label() {
        let oversized = format!(
            "{}{}",
            BASE64URL_NOPAD.encode(&5u64.to_be_bytes()),
            "A".repeat(128)
        );
        let err = validate_private_hnsw_read_path_labels(std::slice::from_ref(&oversized), 3)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("invalid path label"));
        assert!(!rendered.contains(&oversized));

        let malformed = "not-base64!".to_string();
        let err = validate_private_hnsw_read_path_labels(std::slice::from_ref(&malformed), 3)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("invalid path label"));
        assert!(!rendered.contains(&malformed), "{rendered}");
    }

    #[test]
    fn path_oram_rejects_out_of_range_leaf() {
        let leaf = BASE64URL_NOPAD.encode(&8u64.to_be_bytes());
        let err = bucket_ids_for_path_batch(&[leaf], 3, 15).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("invalid path label"));
        assert!(
            !rendered.contains(&BASE64URL_NOPAD.encode(&8u64.to_be_bytes())),
            "{rendered}"
        );

        let malformed = "qdrant-sec-private-hnsw-path-helper-sentinel".to_string();
        let err = bucket_ids_for_path_batch(std::slice::from_ref(&malformed), 3, 15).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("invalid path label"));
        assert!(!rendered.contains(&malformed), "{rendered}");
    }

    #[test]
    fn result_privacy_runtime_option_rejects_unsupported_value_without_reflecting_value() {
        let unsupported = "tenant-a-private-result-mode-sentinel";
        let instance = CryptoInstanceConfig {
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            materials: HashMap::new(),
            backend_ref: None,
            options: serde_json::json!({
                RESULT_PRIVACY_OPTION: unsupported,
            }),
        };

        let rendered = result_privacy_from_runtime(&instance)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains("option result_privacy has unsupported value"));
        assert!(!rendered.contains(unsupported), "{rendered}");
    }

    #[test]
    fn private_hnsw_instance_errors_do_not_reflect_rule_or_instance_ids() {
        let rule_id = "private_hnsw_rule_secret_sentinel";
        let instance_id = "private_hnsw_instance_secret_sentinel";
        let rule = EncryptionRuleRef {
            id: rule_id.to_string(),
            selector: EncryptionSelector::VectorNames {
                names: vec!["text".to_string()],
            },
            instance: instance_id.to_string(),
            binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
        };

        let missing_settings = Settings::new(None).unwrap();
        let rendered = private_hnsw_instance(&missing_settings, &rule)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("missing runtime instance"), "{rendered}");
        assert!(!rendered.contains(rule_id), "{rendered}");
        assert!(!rendered.contains(instance_id), "{rendered}");

        let mut wrong_provider_settings = Settings::new(None).unwrap();
        wrong_provider_settings.crypto.instances.insert(
            instance_id.to_string(),
            CryptoInstanceConfig {
                provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                materials: HashMap::new(),
                backend_ref: None,
                options: serde_json::json!({}),
            },
        );
        let rendered = private_hnsw_instance(&wrong_provider_settings, &rule)
            .unwrap_err()
            .to_string();
        assert!(
            rendered.contains(VECTOR_PRIVATE_HNSW_ORAM_PROVIDER),
            "{rendered}"
        );
        assert!(!rendered.contains(rule_id), "{rendered}");
        assert!(!rendered.contains(instance_id), "{rendered}");
    }

    #[test]
    fn manifest_context_missing_vector_error_does_not_reflect_vector_name() {
        let uuid = Uuid::from_u128(7);
        let mut manifest = fixture_session("session-1", 20).manifest;
        manifest.collection_id = uuid.to_string();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let config = recovered_snapshot_config(uuid, &manifest);
        let instance = settings
            .crypto
            .instances
            .get("docs_text_private_hnsw")
            .unwrap();
        let missing_vector = "private-hnsw-runtime-vector-secret";

        let err = match manifest_context_from_runtime(
            &config.params,
            &uuid.to_string(),
            missing_vector,
            instance,
            false,
        ) {
            Ok(_) => panic!("missing private HNSW vector must fail runtime context validation"),
            Err(err) => err,
        };
        let rendered = err.to_string();

        assert!(
            rendered.contains("not configured as a dense vector"),
            "{rendered}"
        );
        assert!(!rendered.contains(missing_vector), "{rendered}");
    }

    fn fixture_bucket(bucket_id: u64, epoch: u64) -> PrivateHnswOramBucket {
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext: BASE64URL_NOPAD.encode(&[bucket_id as u8]),
            ciphertext_sha256: BASE64URL_NOPAD.encode(&[bucket_id as u8; 32]),
            bucket_commitment: BASE64URL_NOPAD.encode(&[bucket_id as u8; 32]),
        }
    }

    fn fixture_readable_bucket(
        bucket_id: u64,
        epoch: u64,
        domain: u8,
        bucket_commitment: &str,
    ) -> PrivateHnswOramBucket {
        let ciphertext = vec![domain, bucket_id as u8];
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(Sha256::digest(&ciphertext).as_ref());
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256,
            bucket_commitment: bucket_commitment.to_string(),
        }
    }

    #[test]
    fn initial_bucket_upload_requires_complete_orderable_bucket_set() {
        let buckets = vec![fixture_bucket(1, 42), fixture_bucket(0, 42)];
        let commitments = ordered_initial_bucket_commitments(&buckets, 42, 2).unwrap();
        assert_eq!(
            commitments,
            vec![
                BASE64URL_NOPAD.encode(&[0; 32]),
                BASE64URL_NOPAD.encode(&[1; 32])
            ]
        );

        let err = ordered_initial_bucket_commitments(&buckets[..1], 42, 2).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("configured bucket count"));
        assert!(!rendered.contains("2"), "{rendered}");

        let err = ordered_initial_bucket_commitments(
            &[fixture_bucket(0, 42), fixture_bucket(0, 42)],
            42,
            2,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("duplicate bucket"));
        assert!(!rendered.contains("0"), "{rendered}");

        let err = ordered_initial_bucket_commitments(&[fixture_bucket(0, 41)], 42, 1).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("stale epoch"));
        assert!(!rendered.contains("0"), "{rendered}");
        assert!(!rendered.contains("41"), "{rendered}");
        assert!(!rendered.contains("42"), "{rendered}");

        let err = ordered_initial_bucket_commitments(
            &[fixture_bucket(0, 42), fixture_bucket(2, 42)],
            42,
            2,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("2"), "{rendered}");
    }

    #[test]
    fn read_proof_bucket_commitment_mismatch_rejects_without_ciphertext_leak() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        let bucket = fixture_bucket(0, 42);
        let root =
            PrivateHnswOramStore::merkle_root_for_commitments(&[bucket.bucket_commitment.clone()])
                .unwrap();
        store
            .write_merkle_tree_from_commitments(
                42,
                root.clone(),
                vec![bucket.bucket_commitment.clone()],
            )
            .unwrap();

        let mut proof = store.read_merkle_path_batch(&[0], 42, &root, 1).unwrap();
        proof.leaves[0].leaf_hash = BASE64URL_NOPAD.encode(&[99; 32]);

        let err = ensure_private_hnsw_read_proof_matches_buckets(&proof, &[bucket.clone()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("bucket/proof consistency validation failed"));
        assert!(!err.contains(&bucket.ciphertext));
    }

    #[test]
    fn sdk_packaged_initial_upload_bundle_matches_server_contract() {
        let collection_id = "collection-uuid-1";
        let vector_name = "text";
        let key_id = "tenant-a/vector-private-rk";
        let signing_key_id = "tenant-a/private-hnsw-signing-v1";
        let rk_epoch = 7;
        let config = PrivateHnswOramClientConfig {
            tree_height: 1,
            bucket_size: 2,
            block_size_bytes: 512,
            fixed_neighbor_slots: 2,
        };
        let keys = PrivateHnswClientKeys::derive_from_resource_key(&SecretKey::from_bytes([9; 32]))
            .unwrap();
        let base_context = PrivateHnswBucketAeadBaseContext {
            collection_id,
            vector_name,
            key_id,
            rk_id: key_id,
            rk_epoch,
        };
        let points = vec![
            PrivateHnswBuildPoint {
                node_id: [1; 32],
                point_token: [11; 32],
                vector: vec![0.0, 1.0],
                payload_fetch_token: None,
            },
            PrivateHnswBuildPoint {
                node_id: [2; 32],
                point_token: [22; 32],
                vector: vec![1.0, 0.0],
                payload_fetch_token: None,
            },
        ];
        let plaintext_build = build_private_hnsw_oram_plaintext_index_from_f32_points(
            config,
            DistanceKind::Euclid,
            1,
            &points,
            &[0, 1],
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
                collection_id,
                vector_name,
                key_id,
                rk_id: key_id,
                rk_epoch,
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
                    path_batch_size: 1,
                },
                fixed_budget: FixedBudgetParams {
                    enabled: true,
                    upper_layer_steps: 1,
                    base_layer_steps: 2,
                    paths_per_round: 1,
                    fixed_result_k: 1,
                },
                result_privacy: ResultPrivacyMode::IdsVisible,
                owner_signing_key_id: signing_key_id,
                created_at_unix: 1_770_000_000,
            },
            &encrypted_build,
        )
        .unwrap();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signature = sign_private_hnsw_oram_manifest(&key_pair, &manifest).unwrap();
        validate_private_hnsw_oram_manifest(
            &manifest,
            Some(&signature),
            PrivateHnswManifestValidationContext {
                expected_collection_id: collection_id,
                expected_vector_name: vector_name,
                expected_key_id: key_id,
                expected_rk_id: key_id,
                min_rk_epoch: rk_epoch,
                max_rk_epoch: rk_epoch,
                expected_dim: 2,
                expected_distance: DistanceKind::Euclid,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: signing_key_id,
                    public_key: key_pair.public_key().as_ref(),
                },
            },
        )
        .unwrap();

        let leaf_commitments = validate_initial_private_hnsw_upload_bundle(
            &manifest,
            encrypted_build.index_epoch,
            &encrypted_build.root_hash,
            &encrypted_build.buckets,
        )
        .unwrap();
        assert_eq!(leaf_commitments.len() as u64, manifest.bucket_count);
        assert_eq!(
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap(),
            manifest.root_hash,
        );
        for bucket in &encrypted_build.buckets {
            validate_bucket_ciphertext_fixed_size(bucket, &manifest).unwrap();
        }
        validate_private_hnsw_read_bucket_ciphertexts_fixed_size(
            &manifest,
            &encrypted_build.buckets,
        )
        .unwrap();

        let mut short_ciphertext_bucket = encrypted_build.buckets[0].clone();
        let mut short_raw = BASE64URL_NOPAD
            .decode(short_ciphertext_bucket.ciphertext.as_bytes())
            .unwrap();
        short_raw.pop().unwrap();
        short_ciphertext_bucket.ciphertext = BASE64URL_NOPAD.encode(&short_raw);
        short_ciphertext_bucket.ciphertext_sha256 =
            BASE64URL_NOPAD.encode(Sha256::digest(&short_raw).as_ref());
        let err =
            validate_bucket_ciphertext_fixed_size(&short_ciphertext_bucket, &manifest).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(!rendered.contains("0"), "{rendered}");
        assert!(
            !rendered.contains(&short_ciphertext_bucket.ciphertext),
            "{rendered}"
        );
        let rendered = validate_private_hnsw_read_bucket_ciphertexts_fixed_size(
            &manifest,
            std::slice::from_ref(&short_ciphertext_bucket),
        )
        .unwrap_err()
        .to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(!rendered.contains("0"), "{rendered}");
        assert!(
            !rendered.contains(&short_ciphertext_bucket.ciphertext),
            "{rendered}"
        );
        let rendered = validate_private_hnsw_commit_bucket_ciphertexts_fixed_size(
            &manifest,
            std::slice::from_ref(&short_ciphertext_bucket),
        )
        .unwrap_err()
        .to_string();
        assert!(rendered.contains("bucket ciphertext validation failed"));
        assert!(!rendered.contains("fixed ciphertext size"), "{rendered}");
        assert!(
            !rendered.contains(&short_ciphertext_bucket.ciphertext),
            "{rendered}"
        );

        let mut oversized_ciphertext_bucket = encrypted_build.buckets[0].clone();
        oversized_ciphertext_bucket
            .ciphertext
            .push_str("private-hnsw-oversized-ciphertext-sentinel");
        let rendered =
            validate_bucket_ciphertext_fixed_size(&oversized_ciphertext_bucket, &manifest)
                .unwrap_err()
                .to_string();
        assert!(rendered.contains("fixed ciphertext size"));
        assert!(
            !rendered.contains("private-hnsw-oversized-ciphertext-sentinel"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&oversized_ciphertext_bucket.ciphertext),
            "{rendered}"
        );

        let mut wrong_commitment_buckets = encrypted_build.buckets.clone();
        wrong_commitment_buckets[0].bucket_commitment = BASE64URL_NOPAD.encode(&[99; 32]);
        let err = validate_initial_private_hnsw_upload_bundle(
            &manifest,
            encrypted_build.index_epoch,
            &encrypted_build.root_hash,
            &wrong_commitment_buckets,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("bucket commitment context mismatch")
        );

        let first_leaf = encode_private_hnsw_oram_leaf_label(0, config.tree_height).unwrap();
        assert_eq!(
            bucket_ids_for_path_batch(
                std::slice::from_ref(&first_leaf),
                manifest.oram.tree_height,
                manifest.bucket_count
            )
            .unwrap(),
            vec![0, 1],
        );
        let second_leaf = encode_private_hnsw_oram_leaf_label(1, config.tree_height).unwrap();
        assert_eq!(
            bucket_ids_for_path_batch(
                &[first_leaf, second_leaf],
                manifest.oram.tree_height,
                manifest.bucket_count
            )
            .unwrap(),
            vec![0, 1, 0, 2],
        );
    }

    #[test]
    fn distributed_session_epoch_mode_requires_consensus_backed_cas() {
        assert!(validate_private_hnsw_session_cluster_epoch_mode(false).is_ok());

        let err = validate_private_hnsw_session_cluster_epoch_mode(true).unwrap_err();
        assert!(err.to_string().contains("consensus-backed epoch/root CAS"));
    }

    #[test]
    fn session_id_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_private_hnsw_session_id_shape("missing-session-id-sentinel").unwrap();
        validate_private_hnsw_session_id_shape(&uuid::Uuid::new_v4().to_string()).unwrap();

        let oversized = "s".repeat(PRIVATE_HNSW_ORAM_SESSION_ID_MAX_LEN + 1);
        let err = validate_private_hnsw_session_id_shape(&oversized).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session_id is invalid"));
        assert!(!rendered.contains(&oversized));

        let malformed = "bad/session-id";
        let err = validate_private_hnsw_session_id_shape(malformed).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session_id is invalid"));
        assert!(!rendered.contains(malformed));
    }

    #[test]
    fn client_id_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_private_hnsw_client_id_shape("tenant-a/sdk.instance_1@host:1").unwrap();

        let oversized = format!(
            "client-id-sentinel{}",
            "x".repeat(PRIVATE_HNSW_ORAM_CLIENT_ID_MAX_LEN)
        );
        let err = validate_private_hnsw_client_id_shape(&oversized).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("client_id must be non-empty and at most 256 bytes"));
        assert!(!rendered.contains("client-id-sentinel"));

        let malformed = "client-id!sentinel";
        let err = validate_private_hnsw_client_id_shape(malformed).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("client_id is invalid"));
        assert!(!rendered.contains(malformed));
    }

    #[test]
    fn root_hash_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_root_hash_string(&BASE64URL_NOPAD.encode(&[42; 32]), "root_hash").unwrap();

        let oversized = format!("{}{}", BASE64URL_NOPAD.encode(&[42; 32]), "A".repeat(64));
        let err = validate_root_hash_string(&oversized, "root_hash").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("root_hash must encode 32 bytes"));
        assert!(!rendered.contains(&oversized));

        let mut malformed = BASE64URL_NOPAD.encode(&[42; 32]);
        malformed.replace_range(0..1, "!");
        let err = validate_root_hash_string(&malformed, "root_hash").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("root_hash is not base64url"));
        assert!(!rendered.contains(&malformed));
    }

    #[test]
    fn client_signature_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_client_signature_shape(&PrivateHnswClientSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        })
        .unwrap();

        let oversized = format!("{}{}", BASE64URL_NOPAD.encode(&[7; 64]), "A".repeat(64));
        let err = validate_client_signature_shape(&PrivateHnswClientSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: oversized.clone(),
        })
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature must encode 64 bytes"));
        assert!(!rendered.contains(&oversized));

        let mut malformed = BASE64URL_NOPAD.encode(&[7; 64]);
        malformed.replace_range(0..1, "!");
        let err = validate_client_signature_shape(&PrivateHnswClientSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: malformed.clone(),
        })
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature is not base64url"));
        assert!(!rendered.contains(&malformed));
    }

    #[test]
    fn signature_public_key_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        decode_signature_public_key(&BASE64URL_NOPAD.encode(&[7; 32])).unwrap();

        let oversized = format!("{}{}", BASE64URL_NOPAD.encode(&[7; 32]), "A".repeat(64));
        let err = decode_signature_public_key(&oversized).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("public key must be 32 bytes"));
        assert!(!rendered.contains(&oversized));

        let mut malformed = BASE64URL_NOPAD.encode(&[7; 32]);
        malformed.replace_range(0..1, "!");
        let err = decode_signature_public_key(&malformed).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("public key is not base64url"));
        assert!(!rendered.contains(&malformed));
    }

    #[test]
    fn manifest_signature_owner_key_preflight_rejects_non_owner_key() {
        let manifest = fixture_session("session-1", 20).manifest;
        let signature = PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v3".to_string(),
            sig: BASE64URL_NOPAD.encode(&[9; 64]),
        };

        let err =
            validate_private_hnsw_manifest_signature_owner_key(&manifest, &signature).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature key_id does not match manifest owner_signing_key_id"));
        assert!(!rendered.contains(&signature.key_id));
        assert!(!rendered.contains("not configured"));
    }

    #[test]
    fn private_hnsw_error_mapping_redacts_qdrant_sec_fields() {
        let err = private_hnsw_error(qdrant_sec::PrivateHnswOramError::InvalidManifestField(
            "secret_manifest_field",
        ));
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM request validation failed"));
        assert!(!rendered.contains("secret_manifest_field"), "{rendered}");
    }

    #[test]
    fn private_hnsw_store_error_mapping_redacts_store_details() {
        let sentinel = "qdrant-sec-private-hnsw-store-detail-sentinel";
        let rendered =
            private_hnsw_manifest_store_error(CollectionError::bad_request(sentinel)).to_string();
        assert!(rendered.contains("manifest store validation failed"));
        assert!(!rendered.contains(sentinel), "{rendered}");

        let rendered =
            private_hnsw_upload_store_error(CollectionError::bad_request(sentinel)).to_string();
        assert!(rendered.contains("encrypted bucket store validation failed"));
        assert!(!rendered.contains(sentinel), "{rendered}");

        let unexpected = || CollectionError::BadInput {
            description: sentinel.to_string(),
        };
        let rendered_errors = [
            private_hnsw_manifest_read_store_error(unexpected()).to_string(),
            private_hnsw_read_store_error(unexpected()).to_string(),
            private_hnsw_read_batch_store_error(unexpected()).to_string(),
            private_hnsw_manifest_store_error(unexpected()).to_string(),
            private_hnsw_epoch_store_error(unexpected()).to_string(),
            private_hnsw_upload_store_error(unexpected()).to_string(),
            private_hnsw_commit_writeback_store_error(unexpected()).to_string(),
        ];
        for rendered in rendered_errors {
            assert!(rendered.contains("private HNSW ORAM"));
            assert!(!rendered.contains(sentinel), "{rendered}");
        }
    }

    #[test]
    fn recovered_snapshot_signature_preflight_verifies_manifest_signature() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-recovered-signature")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut manifest = fixture_session("session-1", 20).manifest;
        manifest.collection_id = uuid.to_string();
        let leaf_commitments = recovered_snapshot_leaf_commitments(manifest.bucket_count, 31);
        manifest.root_hash =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signature = sign_private_hnsw_oram_manifest(&key_pair, &manifest)
            .expect("fixture manifest should sign");
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let config = recovered_snapshot_config(uuid, &manifest);
        let store = PrivateHnswOramStore::new(temp_dir.path(), "text").unwrap();
        store.write_manifest(&manifest, &signature).unwrap();
        install_recovered_private_hnsw_snapshot_storage(&store, &manifest, leaf_commitments);

        validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap();

        let mut tampered_signature = signature.clone();
        tampered_signature.sig = BASE64URL_NOPAD.encode(&[9; 64]);
        store
            .write_manifest(&manifest, &tampered_signature)
            .unwrap();
        let err = validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("private HNSW ORAM request validation failed"));
        assert!(!rendered.contains(&tampered_signature.sig));
        assert!(!rendered.contains(&manifest.root_hash));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_BINDING));

        let mut mismatched_manifest = manifest.clone();
        mismatched_manifest.root_hash = BASE64URL_NOPAD.encode(&[88; 32]);
        let mismatched_signature = sign_private_hnsw_oram_manifest(&key_pair, &mismatched_manifest)
            .expect("fixture manifest should sign");
        store
            .write_manifest(&mismatched_manifest, &mismatched_signature)
            .unwrap();
        let err = validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("restored snapshot manifest or epoch does not match current storage")
        );
        assert!(!rendered.contains(&mismatched_manifest.root_hash));
        assert!(!rendered.contains(PRIVATE_HNSW_ORAM_BINDING));
    }

    #[test]
    fn recovered_snapshot_signature_preflight_validates_runtime_key_epoch_pinning() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-recovered-runtime")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut manifest = fixture_session("session-1", 20).manifest;
        manifest.collection_id = uuid.to_string();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let mut config = recovered_snapshot_config(uuid, &manifest);
        let encryption = config.params.encryption.as_mut().unwrap();
        encryption.key_id = Some("tenant-a/other-private-hnsw-rk".to_string());

        let err = validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private HNSW ORAM key_id must match collection key_id"),
            "{rendered}"
        );
        assert!(!rendered.contains("tenant-a/other-private-hnsw-rk"));
        assert!(!rendered.contains(&manifest.key_id));
        assert!(!rendered.contains("manifest has not been uploaded"));
    }

    #[test]
    fn recovered_snapshot_signature_preflight_rejects_wrong_selector_without_rule_details() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-hnsw-recovered-wrong-selector")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut manifest = fixture_session("session-1", 20).manifest;
        manifest.collection_id = uuid.to_string();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let mut config = recovered_snapshot_config(uuid, &manifest);
        let encryption = config.params.encryption.as_mut().unwrap();
        encryption.rules[0].id = "private_hnsw_restore_secret_rule".to_string();
        encryption.rules[0].selector = EncryptionSelector::PayloadPaths {
            paths: vec!["private.hnsw.secret.payload".to_string()],
        };

        let err = validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("vector_names selector"), "{rendered}");
        assert!(!rendered.contains("private_hnsw_restore_secret_rule"));
        assert!(!rendered.contains("private.hnsw.secret.payload"));
        assert!(!rendered.contains("manifest has not been uploaded"));
    }

    fn recovered_snapshot_leaf_commitments(bucket_count: u64, domain: u8) -> Vec<String> {
        (0..bucket_count)
            .map(|bucket_id| {
                let mut bytes = [domain; 32];
                bytes[..8].copy_from_slice(&bucket_id.to_be_bytes());
                BASE64URL_NOPAD.encode(&bytes)
            })
            .collect()
    }

    fn install_recovered_private_hnsw_snapshot_storage(
        store: &PrivateHnswOramStore,
        manifest: &PrivateHnswOramManifest,
        leaf_commitments: Vec<String>,
    ) {
        store
            .write_initial_epoch(&PrivateHnswOramEpochState {
                index_epoch: manifest.index_epoch,
                root_hash: manifest.root_hash.clone(),
            })
            .unwrap();
        store
            .write_merkle_tree_from_commitments(
                manifest.index_epoch,
                manifest.root_hash.clone(),
                leaf_commitments.clone(),
            )
            .unwrap();
        for (bucket_id, bucket_commitment) in leaf_commitments.iter().enumerate() {
            let bucket = fixture_readable_bucket(
                bucket_id as u64,
                manifest.index_epoch,
                31,
                bucket_commitment,
            );
            store
                .write_bucket(
                    &bucket,
                    manifest.index_epoch,
                    manifest.bucket_count,
                    max_bucket_ciphertext_bytes(manifest).unwrap(),
                )
                .unwrap();
        }
    }

    #[test]
    fn restored_snapshot_storage_recheck_requires_bucket_file() {
        let mut session = fixture_session("session-1", 20);
        let bucket_count = 3;
        let leaf_commitments = recovered_snapshot_leaf_commitments(bucket_count, 53);
        let root_hash =
            PrivateHnswOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        session.bucket_count = bucket_count;
        session.root_hash = root_hash.clone();
        session.manifest.bucket_count = bucket_count;
        session.manifest.root_hash = root_hash;
        let expected_epoch = PrivateHnswOramEpochState {
            index_epoch: session.index_epoch,
            root_hash: session.root_hash.clone(),
        };
        let signature = fixture_signature();

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                leaf_commitments.clone(),
            )
            .unwrap();
        for (bucket_id, bucket_commitment) in leaf_commitments.iter().enumerate() {
            let bucket = fixture_readable_bucket(
                bucket_id as u64,
                expected_epoch.index_epoch,
                17,
                bucket_commitment,
            );
            store
                .write_bucket(
                    &bucket,
                    expected_epoch.index_epoch,
                    session.manifest.bucket_count,
                    4096,
                )
                .unwrap();
        }
        ensure_private_hnsw_restored_snapshot_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap();

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                leaf_commitments.clone(),
            )
            .unwrap();
        for (bucket_id, bucket_commitment) in leaf_commitments.iter().enumerate() {
            if bucket_id == 1 {
                continue;
            }
            let bucket = fixture_readable_bucket(
                bucket_id as u64,
                expected_epoch.index_epoch,
                19,
                bucket_commitment,
            );
            store
                .write_bucket(
                    &bucket,
                    expected_epoch.index_epoch,
                    session.manifest.bucket_count,
                    4096,
                )
                .unwrap();
        }
        let err = ensure_private_hnsw_restored_snapshot_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("encrypted bucket data is unavailable")
        );
        assert!(!err.to_string().contains("00000001.bucket"));
        assert!(!err.to_string().contains(&expected_epoch.root_hash));
    }

    #[test]
    fn active_session_current_epoch_preflight_rejects_stale_store_epoch() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        let old_root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let old = PrivateHnswOramEpochState {
            index_epoch: 42,
            root_hash: old_root_hash.clone(),
        };
        let stale_current = PrivateHnswOramEpochState {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
        };

        store.write_initial_epoch(&old).unwrap();
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let err = ensure_private_hnsw_active_session_current_epoch(
            &store,
            old.index_epoch,
            &old.root_hash,
            "commit",
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("commit current epoch/root does not match active session")
        );
        let err = ensure_private_hnsw_active_session_current_epoch(
            &store,
            old.index_epoch,
            &old.root_hash,
            "read_paths",
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("read_paths current epoch/root does not match active session")
        );
    }

    #[test]
    fn session_open_storage_recheck_rejects_manifest_or_epoch_drift() {
        let mut session = fixture_session("session-1", 20);
        session.bucket_count = 1;
        session.manifest.bucket_count = 1;
        let signature = fixture_signature();
        let expected_epoch = PrivateHnswOramEpochState {
            index_epoch: session.index_epoch,
            root_hash: session.root_hash.clone(),
        };

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                vec![expected_epoch.root_hash.clone()],
            )
            .unwrap();
        let bucket =
            fixture_readable_bucket(0, expected_epoch.index_epoch, 11, &expected_epoch.root_hash);
        store
            .write_bucket(
                &bucket,
                expected_epoch.index_epoch,
                session.manifest.bucket_count,
                4096,
            )
            .unwrap();
        ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap();

        let stale_epoch = PrivateHnswOramEpochState {
            index_epoch: session.index_epoch + 1,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
        };
        store
            .compare_and_swap_epoch(&expected_epoch, &stale_epoch)
            .unwrap();
        let err = ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("session open observed concurrent manifest or epoch update")
        );
        assert!(!err.to_string().contains(&stale_epoch.root_hash));

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                vec![expected_epoch.root_hash.clone()],
            )
            .unwrap();
        let bucket =
            fixture_readable_bucket(0, expected_epoch.index_epoch, 12, &expected_epoch.root_hash);
        store
            .write_bucket(
                &bucket,
                expected_epoch.index_epoch,
                session.manifest.bucket_count,
                4096,
            )
            .unwrap();
        let mut changed_manifest = session.manifest.clone();
        changed_manifest.logical_node_count += 1;
        store.write_manifest(&changed_manifest, &signature).unwrap();
        let err = ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("session open observed concurrent manifest or epoch update")
        );

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        let err = ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("encrypted bucket data is unavailable")
        );

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateHnswOramStore::new(temp.path(), "text").unwrap();
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                vec![expected_epoch.root_hash.clone()],
            )
            .unwrap();
        let err = ensure_private_hnsw_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("encrypted bucket data is unavailable")
        );
    }

    fn fixture_signature() -> PrivateHnswOramSignature {
        PrivateHnswOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        }
    }

    fn fixture_session(session_id: &str, lease_expires_unix: u64) -> PrivateHnswSession {
        let manifest = PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: "collection-uuid-1".to_string(),
            vector_name: "text".to_string(),
            key_id: "tenant-a/vector-private-rk".to_string(),
            rk_id: "tenant-a/vector-private-rk".to_string(),
            rk_epoch: 7,
            dim: 2,
            distance: DistanceKind::Cosine,
            hnsw: qdrant_sec::PrivateHnswParams {
                m: 2,
                ef_construction: 4,
                max_layers: 2,
                fixed_neighbor_slots: 4,
            },
            oram: qdrant_sec::OramParams {
                kind: qdrant_sec::OramKind::PathOram,
                bucket_size: 4,
                block_size_bytes: 4096,
                tree_height: 3,
                path_batch_size: 1,
            },
            fixed_budget: qdrant_sec::FixedBudgetParams {
                enabled: true,
                upper_layer_steps: 1,
                base_layer_steps: 1,
                paths_per_round: 1,
                fixed_result_k: 1,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: 15,
            logical_node_count: 1,
            dummy_node_count: 0,
            result_privacy: ResultPrivacyMode::IdsVisible,
            owner_signing_key_id: "tenant-a/private-hnsw-signing-v1".to_string(),
            created_at_unix: 1,
        };
        PrivateHnswSession {
            session_id: session_id.to_string(),
            _client_id: "client".to_string(),
            collection_id: "collection-uuid-1".to_string(),
            collection_path: std::path::PathBuf::from("/tmp/qdrant-private-hnsw-test"),
            vector_name: "text".to_string(),
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            lease_expires_unix,
            bucket_count: 15,
            tree_height: 3,
            path_batch_size: 1,
            max_bucket_ciphertext_bytes: 4096,
            manifest,
        }
    }

    fn fixture_runtime_context(manifest: &PrivateHnswOramManifest) -> ResolvedPrivateHnswContext {
        ResolvedPrivateHnswContext {
            collection_path: std::path::PathBuf::from("/tmp/qdrant-private-hnsw-test"),
            collection_crypto_id: manifest.collection_id.clone(),
            vector_name: manifest.vector_name.clone(),
            expected_key_id: manifest.key_id.clone(),
            expected_rk_id: manifest.rk_id.clone(),
            min_rk_epoch: manifest.rk_epoch,
            max_rk_epoch: manifest.rk_epoch,
            expected_dim: manifest.dim,
            expected_distance: manifest.distance,
            expected_result_privacy: manifest.result_privacy,
            private_result_oram_binding_configured: false,
            expected_hnsw: manifest.hnsw.clone(),
            expected_oram: manifest.oram.clone(),
            expected_fixed_budget: manifest.fixed_budget.clone(),
            signature_public_keys: HashMap::new(),
            public_key: vec![0; 32],
        }
    }

    fn recovered_snapshot_config(
        uuid: Uuid,
        manifest: &PrivateHnswOramManifest,
    ) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                vectors: VectorsConfig::Multi(BTreeMap::from([(
                    manifest.vector_name.clone().into(),
                    VectorParamsBuilder::new(u64::from(manifest.dim), Distance::Cosine).build(),
                )])),
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some(manifest.key_id.clone()),
                    crypto_schema_version: 1,
                    encryption_epoch: manifest.rk_epoch,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "docs_text_private_hnsw".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec![manifest.vector_name.clone()],
                        },
                        instance: "docs_text_private_hnsw".to_string(),
                        binding: Some(PRIVATE_HNSW_ORAM_BINDING.to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            hnsw_config: segment::types::HnswConfig::default(),
            optimizer_config: OptimizersConfig {
                deleted_threshold: 0.1,
                vacuum_min_vector_number: 1000,
                default_segment_number: 0,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: None,
                indexing_threshold: Some(100_000),
                flush_interval_sec: 60,
                max_optimization_threads: Some(0),
                prevent_unoptimized: None,
            },
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid: Some(uuid),
            metadata: None,
        }
    }

    fn recovered_snapshot_settings(
        manifest: &PrivateHnswOramManifest,
        public_key: &[u8],
    ) -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            zero_trust_profile: Some(ZERO_TRUST_PROFILE_STRICT.to_string()),
            instances: HashMap::from([(
                "docs_text_private_hnsw".to_string(),
                CryptoInstanceConfig {
                    provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: serde_json::json!({
                        KEY_ID_OPTION: manifest.key_id,
                        EXPECTED_RK_ID_OPTION: manifest.rk_id,
                        MIN_RK_EPOCH_OPTION: manifest.rk_epoch,
                        MAX_RK_EPOCH_OPTION: manifest.rk_epoch,
                        "search_execution": "client_led",
                        "search_mode": "private_hnsw_oram",
                        RESULT_PRIVACY_OPTION: "ids_visible",
                        "distance": "cosine",
                        "dim": manifest.dim,
                        HNSW_OPTION: manifest.hnsw,
                        ORAM_OPTION: manifest.oram,
                        FIXED_BUDGET_OPTION: manifest.fixed_budget,
                        "integrity": {
                            "manifest_signature_required": true,
                            "commit_signature_required": true,
                            "merkle_root_required": true,
                        },
                        SIGNATURE_PUBLIC_KEYS_OPTION: {
                            "tenant-a/private-hnsw-signing-v1": BASE64URL_NOPAD.encode(public_key),
                        },
                    }),
                },
            )]),
            ..CryptoSettings::default()
        };
        settings
    }

    #[test]
    fn manifest_runtime_context_rejects_lineage_and_policy_drift() {
        let session = fixture_session("session-1", 20);
        let manifest = session.manifest;
        fixture_runtime_context(&manifest)
            .validate_manifest_runtime_context(&manifest)
            .unwrap();

        let mut context = fixture_runtime_context(&manifest);
        context.expected_key_id = "runtime-key-id-sentinel".to_string();
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest key_id does not match runtime instance"));
        assert!(!rendered.contains("runtime-key-id-sentinel"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_rk_id = "runtime-rk-id-sentinel".to_string();
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest rk_id does not match runtime instance"));
        assert!(!rendered.contains("runtime-rk-id-sentinel"));

        let mut context = fixture_runtime_context(&manifest);
        context.min_rk_epoch = manifest.rk_epoch + 1;
        context.max_rk_epoch = manifest.rk_epoch + 1;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest rk_epoch does not match runtime instance"));
        assert!(!rendered.contains(&(manifest.rk_epoch + 1).to_string()));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_dim = 1536;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest dim does not match runtime vector size"));
        assert!(!rendered.contains("1536"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_distance = DistanceKind::Dot;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest distance does not match runtime vector distance"));
        assert!(!rendered.contains("Dot"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_result_privacy = ResultPrivacyMode::PrivatePayloadOramRequired;
        context.private_result_oram_binding_configured = true;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest result_privacy does not match runtime instance"));
        assert!(!rendered.contains("private_payload_oram_required"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_hnsw.m = 99;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest hnsw does not match runtime instance"));
        assert!(!rendered.contains("99"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_oram.bucket_size = 99;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest oram does not match runtime instance"));
        assert!(!rendered.contains("99"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_fixed_budget.fixed_result_k = 99;
        let rendered = context
            .validate_manifest_runtime_context(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest fixed_budget does not match runtime instance"));
        assert!(!rendered.contains("99"));
    }

    #[test]
    fn session_registry_enforces_single_writer() {
        let now = 10;
        let session = fixture_session("session-1", 20);
        let mut registry = PrivateHnswSessionRegistry::default();
        registry.open(session.clone(), now).unwrap();
        assert!(registry.has_active_collection("collection-uuid-1", now));
        assert!(!registry.has_active_collection("other-collection", now));
        assert!(registry.has_active_index("collection-uuid-1", "text", now));
        assert!(!registry.has_active_index("collection-uuid-1", "other-vector", now));
        let err = registry.open(
            PrivateHnswSession {
                session_id: "session-2".to_string(),
                ..session
            },
            now,
        );
        assert!(err.unwrap_err().to_string().contains("ConcurrentWriter"));
        assert!(registry.close("collection-uuid-1", "text", "session-1", now));
        assert!(!registry.has_active_collection("collection-uuid-1", now));
        assert!(!registry.has_active_index("collection-uuid-1", "text", now));
    }

    #[test]
    fn session_registry_keeps_writer_lock_after_failed_action() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        let err = registry
            .with_session_mut(
                "collection-uuid-1",
                "text",
                "session-1",
                now,
                |_| -> StorageResult<()> {
                    Err(StorageError::bad_request("synthetic failed session action"))
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("synthetic failed session action"));
        assert!(registry.has_active_collection("collection-uuid-1", now));
        assert!(registry.has_active_index("collection-uuid-1", "text", now));

        let err = registry
            .open(fixture_session("session-2", 20), now)
            .unwrap_err();
        assert!(err.to_string().contains("ConcurrentWriter"));

        assert!(registry.close("collection-uuid-1", "text", "session-1", now));
        registry
            .open(fixture_session("session-2", 20), now)
            .unwrap();
    }

    #[test]
    fn session_registry_wrong_close_keeps_writer_lock() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        assert!(!registry.close("other-collection", "text", "session-1", now));
        assert!(registry.has_active_collection("collection-uuid-1", now));
        assert!(registry.has_active_index("collection-uuid-1", "text", now));

        assert!(!registry.close("collection-uuid-1", "other-vector", "session-1", now));
        assert!(registry.has_active_collection("collection-uuid-1", now));
        assert!(registry.has_active_index("collection-uuid-1", "text", now));

        let err = registry
            .open(fixture_session("session-2", 20), now)
            .unwrap_err();
        assert!(err.to_string().contains("ConcurrentWriter"));

        assert!(registry.close("collection-uuid-1", "text", "session-1", now));
        assert!(!registry.has_active_index("collection-uuid-1", "text", now));
    }

    #[test]
    fn collection_snapshot_guard_rejects_active_collection_session() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        let err = ensure_no_active_private_hnsw_collection_session_in_registry(
            &mut registry,
            "collection-uuid-1",
            now,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("snapshot requires no active private ORAM session")
        );
        assert!(
            ensure_no_active_private_hnsw_collection_session_in_registry(
                &mut registry,
                "other-collection",
                now,
            )
            .is_ok()
        );
    }

    #[test]
    fn session_registry_rejects_session_open_during_collection_snapshot() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();

        let err = registry
            .open(fixture_session("session-1", 20), now)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("session open requires no active collection snapshot")
        );

        registry.release_collection_snapshot("collection-uuid-1");
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();
    }

    #[test]
    fn collection_snapshot_guard_rejects_private_hnsw_upload_write_window() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();

        let err = ensure_private_hnsw_write_window_in_registry(
            &mut registry,
            "collection-uuid-1",
            "text",
            now,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("upload requires no active collection snapshot")
        );

        registry.release_collection_snapshot("collection-uuid-1");
        ensure_private_hnsw_write_window_in_registry(
            &mut registry,
            "collection-uuid-1",
            "text",
            now,
        )
        .unwrap();
    }

    #[test]
    fn upload_write_window_rejects_concurrent_session_and_upload() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap();

        let err = registry
            .open(fixture_session("session-1", 20), now)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("session open requires no active upload")
        );

        let err = registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap_err();
        assert!(err.to_string().contains("upload requires no active upload"));

        registry.release_upload("collection-uuid-1", "text");
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();
    }

    #[test]
    fn upload_write_window_rejects_collection_snapshot() {
        let now = 10;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .begin_upload("collection-uuid-1", "text", now)
            .unwrap();

        let err = registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("snapshot requires no active private ORAM upload")
        );
        registry
            .begin_collection_snapshot("other-collection", now)
            .unwrap();
        registry.release_collection_snapshot("other-collection");

        registry.release_upload("collection-uuid-1", "text");
        registry
            .begin_collection_snapshot("collection-uuid-1", now)
            .unwrap();
    }

    #[test]
    fn session_registry_expiration_releases_writer_lock() {
        let now = 10;
        let expired_at = 20;
        let mut registry = PrivateHnswSessionRegistry::default();
        registry
            .open(fixture_session("session-1", expired_at), now)
            .unwrap();

        let err = registry
            .with_session_mut("collection-uuid-1", "text", "session-1", expired_at, |_| {
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("session is missing or expired"));
        assert!(!registry.has_active_collection("collection-uuid-1", expired_at));
        assert!(!registry.has_active_index("collection-uuid-1", "text", expired_at));
        assert!(!registry.close("collection-uuid-1", "text", "session-1", expired_at));

        registry
            .open(fixture_session("session-2", expired_at + 10), expired_at)
            .unwrap();
        assert!(registry.has_active_index("collection-uuid-1", "text", expired_at));
    }
}
