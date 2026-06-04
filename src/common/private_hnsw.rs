use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use collection::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams, EncryptionRuleRef,
    EncryptionSelector,
};
use collection::operations::types::CollectionError;
use collection::private_hnsw_oram_store::{
    PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND, PrivateHnswOramEpochState, PrivateHnswOramStore,
};
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    DistanceKind, FixedBudgetParams, OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER,
    PRIVATE_HNSW_ORAM_BINDING, PrivateHnswBucketAeadContext, PrivateHnswManifestValidationContext,
    PrivateHnswOramBucket, PrivateHnswOramCommitBucketRef, PrivateHnswOramCommitSignatureInput,
    PrivateHnswOramManifest, PrivateHnswOramReadPathsSignatureInput, PrivateHnswOramSignature,
    PrivateHnswParams, PrivateHnswSignatureVerification, ResultPrivacyMode,
    VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, decode_private_hnsw_oram_leaf_label,
    private_hnsw_bucket_commitment, private_hnsw_oram_bucket_count,
    private_hnsw_oram_bucket_ids_for_leaf, validate_private_hnsw_oram_commit_signature,
    validate_private_hnsw_oram_manifest, validate_private_hnsw_oram_manifest_signature_shape,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateHnswManifestRecord {
    pub manifest: PrivateHnswOramManifest,
    pub signature: PrivateHnswOramSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateHnswSessionResponse {
    pub session_id: String,
    pub collection_id: String,
    pub vector_name: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub manifest: PrivateHnswOramManifest,
    pub lease_expires_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateHnswReadPathsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<PrivateHnswOramBucket>,
    pub proof: PrivateHnswReadProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateHnswReadProof {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateHnswReadPadding {
    pub requested_paths: u32,
    pub dummy_paths_included: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateHnswClientSignature {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

#[derive(Clone, Debug)]
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
        if manifest.result_privacy != ResultPrivacyMode::IdsVisible {
            return Err(StorageError::bad_request(format!(
                "private HNSW ORAM result_privacy=private_payload_oram_required requires {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER}, which is not implemented in this MVP"
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
    let resolved = resolve_private_hnsw_context(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        &signature.key_id,
        "private_hnsw_manifest_upload",
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
        .write_initial_epoch_if_absent_or_matching(&epoch_state)
        .map_err(private_hnsw_manifest_store_error)?;
    store
        .write_manifest(&manifest, &signature)
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
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
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
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
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
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
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
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_hnsw_epoch_store_error)?;
    if current_epoch.index_epoch != index_epoch || current_epoch.root_hash != root_hash {
        return Err(StorageError::bad_request(
            "private HNSW ORAM bucket upload epoch/root does not match current manifest epoch",
        ));
    }
    let _upload_guard =
        begin_private_hnsw_upload_write_window(&resolved.collection_crypto_id, vector_name)?;
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
    if client_id.is_empty() || client_id.len() > 256 {
        return Err(StorageError::bad_request(
            "private HNSW ORAM client_id must be non-empty and at most 256 bytes",
        ));
    }
    validate_private_hnsw_session_cluster_epoch_mode(toc.is_distributed())?;
    if is_strict(settings) && !fixed_budget {
        return Err(StorageError::bad_request(
            "private HNSW ORAM strict mode requires fixed_budget=true",
        ));
    }

    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
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
    let runtime_context = manifest_context_from_runtime(
        &config.params,
        &collection_crypto_id,
        vector_name,
        instance,
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
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM requested epoch {desired_epoch} is not current epoch {}",
            current_epoch.index_epoch,
        )));
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

    let now_unix = current_unix_secs()?;
    let session = PrivateHnswSession {
        session_id: new_session_id(),
        _client_id: client_id,
        collection_id: collection_crypto_id,
        collection_path: collection.path().to_path_buf(),
        vector_name: vector_name.to_string(),
        index_epoch: current_epoch.index_epoch,
        root_hash: current_epoch.root_hash,
        lease_expires_unix: now_unix.saturating_add(SESSION_LEASE_SECS),
        bucket_count: manifest.bucket_count,
        tree_height: manifest.oram.tree_height,
        path_batch_size: manifest.oram.path_batch_size,
        max_bucket_ciphertext_bytes: max_bucket_ciphertext_bytes(&manifest)?,
        manifest,
    };
    session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private HNSW ORAM session registry poisoned"))?
        .open(session, now_unix)
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
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_oram_read_paths",
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
            validate_unique_path_labels(&paths)?;
            let bucket_ids =
                bucket_ids_for_path_batch(&paths, session.tree_height, session.bucket_count)?;
            let store = PrivateHnswOramStore::new(&session.collection_path, vector_name)?;
            ensure_private_hnsw_active_session_current_epoch(
                &store,
                session.index_epoch,
                &session.root_hash,
                "read_paths",
            )?;
            let mut buckets = Vec::with_capacity(bucket_ids.len());
            for bucket_id in bucket_ids {
                buckets.push(
                    store
                        .read_bucket(
                            bucket_id,
                            session.index_epoch,
                            session.bucket_count,
                            session.max_bucket_ciphertext_bytes,
                        )
                        .map_err(private_hnsw_read_store_error)?,
                );
            }
            let proof = store
                .read_merkle_path_batch(
                    &buckets
                        .iter()
                        .map(|bucket| bucket.bucket_id)
                        .collect::<Vec<_>>(),
                    session.index_epoch,
                    &session.root_hash,
                    session.bucket_count,
                )
                .map_err(private_hnsw_read_store_error)?;
            let proof_value = serde_json::to_string(&proof).map_err(|err| {
                StorageError::service_error(format!(
                    "failed to serialize private HNSW ORAM Merkle proof: {err}",
                ))
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
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_oram_commit",
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
        let mut seen_bucket_ids = HashSet::new();
        for bucket in &updated_buckets {
            if !seen_bucket_ids.insert(bucket.bucket_id) {
                return Err(StorageError::bad_request(
                    "private HNSW ORAM commit updated_buckets contains duplicate bucket id",
                ));
            }
        }
        let commit_bucket_refs = updated_buckets
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
                updated_buckets: &commit_bucket_refs,
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
        validate_root_hash_string(&new_root_hash, "new_root_hash")?;

        let store = PrivateHnswOramStore::new(&session.collection_path, vector_name)?;
        ensure_private_hnsw_active_session_current_epoch(
            &store,
            old_epoch,
            &old_root_hash,
            "commit",
        )?;
        for bucket in &updated_buckets {
            store
                .validate_bucket_for_write(
                    bucket,
                    new_epoch,
                    session.bucket_count,
                    session.max_bucket_ciphertext_bytes,
                )
                .map_err(private_hnsw_commit_bucket_store_error)?;
        }
        validate_bucket_commitment_context(
            &session.manifest,
            new_epoch,
            &updated_buckets,
            "commit",
        )?;
        let prepared_merkle_commit = store.prepare_merkle_commit(
            old_epoch,
            &old_root_hash,
            new_epoch,
            &new_root_hash,
            session.bucket_count,
            &updated_buckets,
        ).map_err(private_hnsw_commit_metadata_store_error)?;
        for bucket in &updated_buckets {
            store.write_bucket(
                bucket,
                new_epoch,
                session.bucket_count,
                session.max_bucket_ciphertext_bytes,
            ).map_err(private_hnsw_commit_bucket_store_error)?;
        }
        prepared_merkle_commit
            .write()
            .map_err(private_hnsw_commit_metadata_store_error)?;
        let old = PrivateHnswOramEpochState {
            index_epoch: old_epoch,
            root_hash: old_root_hash,
        };
        let new = PrivateHnswOramEpochState {
            index_epoch: new_epoch,
            root_hash: new_root_hash,
        };
        store
            .compare_and_swap_epoch(&old, &new)
            .map_err(private_hnsw_commit_metadata_store_error)?;
        session.index_epoch = new.index_epoch;
        session.root_hash = new.root_hash.clone();
        session.lease_expires_unix = now_unix.saturating_add(SESSION_LEASE_SECS);
        Ok(new)
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
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        vector_name,
        None,
        "private_hnsw_session_close",
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

async fn resolve_private_hnsw_context(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    signature_key_id: &str,
    method: &str,
) -> StorageResult<ResolvedPrivateHnswContext> {
    let pass = auth.check_collection_access(collection_name, AccessRequirements::new(), method)?;
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
            StorageError::bad_request(format!(
                "vector/private-hnsw-oram@v1 requires client-led private ORAM sessions for vector '{vector_name}'",
            ))
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
            StorageError::bad_request(format!(
                "private HNSW ORAM rule {} references missing runtime instance {}",
                rule.id, rule.instance,
            ))
        })?;
    if instance.provider != VECTOR_PRIVATE_HNSW_ORAM_PROVIDER {
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM rule {} runtime instance {} must use provider {VECTOR_PRIVATE_HNSW_ORAM_PROVIDER}",
            rule.id, rule.instance,
        )));
    }
    Ok(instance)
}

fn read_uploaded_manifest(
    store: &PrivateHnswOramStore,
) -> StorageResult<(PrivateHnswOramManifest, PrivateHnswOramSignature)> {
    store
        .read_manifest()
        .map_err(private_hnsw_manifest_read_store_error)
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
        other => StorageError::from(other),
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
        other => StorageError::from(other),
    }
}

fn private_hnsw_manifest_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM manifest store is unavailable")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private HNSW ORAM manifest store validation failed")
        }
        other => StorageError::from(other),
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
        other => StorageError::from(other),
    }
}

fn private_hnsw_upload_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM encrypted bucket store is unavailable")
        }
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
        other => StorageError::from(other),
    }
}

fn private_hnsw_commit_metadata_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => StorageError::not_found(
            "private HNSW ORAM encrypted bucket store metadata is unavailable",
        ),
        CollectionError::BadRequest { .. } => StorageError::bad_request(
            "private HNSW ORAM encrypted bucket store metadata validation failed",
        ),
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store metadata validation failed",
        ),
        other => StorageError::from(other),
    }
}

fn private_hnsw_commit_bucket_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private HNSW ORAM encrypted bucket store is unavailable")
        }
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private HNSW ORAM encrypted bucket store validation failed",
        ),
        other => StorageError::from(other),
    }
}

fn manifest_context_from_runtime(
    params: &CollectionParams,
    collection_crypto_id: &str,
    vector_name: &str,
    instance: &CryptoInstanceConfig,
) -> StorageResult<ResolvedPrivateHnswContext> {
    let vector_params = params.vectors.get_params(vector_name).ok_or_else(|| {
        CollectionError::bad_input(format!(
            "private HNSW ORAM vector '{vector_name}' is not configured as a dense vector",
        ))
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
        StorageError::bad_request(format!(
            "private HNSW ORAM vector '{vector_name}' size exceeds supported manifest dim range",
        ))
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
        "private_payload_oram_required" => Err(StorageError::bad_request(format!(
            "private HNSW ORAM result_privacy=private_payload_oram_required requires {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER}, which is not implemented in this MVP"
        ))),
        value => Err(StorageError::bad_request(format!(
            "private HNSW ORAM option {RESULT_PRIVACY_OPTION} has unsupported value {value}",
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
) -> StorageResult<ResolvedPrivateHnswContext> {
    let pass = auth.check_collection_access(collection_name, AccessRequirements::new(), method)?;
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
        err => StorageError::bad_request(err.to_string()),
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

fn max_updated_bucket_count(session: &PrivateHnswSession) -> StorageResult<usize> {
    let levels = usize::try_from(session.tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or_else(|| StorageError::bad_request("private HNSW ORAM tree height overflows"))?;
    let paths = usize::try_from(session.path_batch_size)
        .map_err(|_| StorageError::bad_request("private HNSW ORAM path batch size overflows"))?;
    levels
        .checked_mul(paths)
        .ok_or_else(|| StorageError::bad_request("private HNSW ORAM writeback size overflows"))
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
        return Err(StorageError::bad_request(format!(
            "private HNSW ORAM initial upload must include exactly {bucket_count} buckets",
        )));
    }
    let mut commitments = vec![None; bucket_count_usize];
    for bucket in buckets {
        if bucket.index_epoch != expected_epoch {
            return Err(StorageError::bad_request(format!(
                "private HNSW ORAM initial upload bucket {} has stale epoch {}",
                bucket.bucket_id, bucket.index_epoch,
            )));
        }
        if bucket.bucket_id >= bucket_count {
            return Err(StorageError::bad_request(format!(
                "private HNSW ORAM initial upload bucket {} is out of range",
                bucket.bucket_id,
            )));
        }
        validate_root_hash_string(&bucket.bucket_commitment, "bucket_commitment")?;
        let bucket_index = usize::try_from(bucket.bucket_id).map_err(|_| {
            StorageError::bad_request("private HNSW ORAM bucket id exceeds supported range")
        })?;
        if commitments[bucket_index].is_some() {
            return Err(StorageError::bad_request(format!(
                "private HNSW ORAM initial upload bucket {} is duplicated",
                bucket.bucket_id,
            )));
        }
        commitments[bucket_index] = Some(bucket.bucket_commitment.clone());
    }
    commitments
        .into_iter()
        .enumerate()
        .map(|(bucket_id, commitment)| {
            commitment.ok_or_else(|| {
                StorageError::bad_request(format!(
                    "private HNSW ORAM initial upload missing bucket {bucket_id}",
                ))
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

fn bucket_ids_for_path_batch(
    paths: &[String],
    tree_height: u32,
    bucket_count: u64,
) -> StorageResult<Vec<u64>> {
    let expected_bucket_count = private_hnsw_oram_bucket_count(tree_height)
        .map_err(|err| StorageError::bad_request(err.to_string()))?;
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
        let leaf = decode_private_hnsw_oram_leaf_label(path, tree_height)
            .map_err(|err| StorageError::bad_request(err.to_string()))?;
        bucket_ids.extend(
            private_hnsw_oram_bucket_ids_for_leaf(leaf, tree_height)
                .map_err(|err| StorageError::bad_request(err.to_string()))?,
        );
    }
    Ok(bucket_ids)
}

fn validate_root_hash_string(value: &str, field: &str) -> StorageResult<()> {
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

    use super::*;

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
    fn read_path_budget_rejects_duplicate_path_labels() {
        let leaf = BASE64URL_NOPAD.encode(&5u64.to_be_bytes());
        let err = validate_unique_path_labels(&[leaf.clone(), leaf]).unwrap_err();
        assert!(err.to_string().contains("duplicate path label"));
    }

    #[test]
    fn path_oram_rejects_out_of_range_leaf() {
        let leaf = BASE64URL_NOPAD.encode(&8u64.to_be_bytes());
        let err = bucket_ids_for_path_batch(&[leaf], 3, 15).unwrap_err();
        assert!(err.to_string().contains("outside ORAM tree range"));
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
        assert!(err.to_string().contains("exactly 2 buckets"));

        let err = ordered_initial_bucket_commitments(
            &[fixture_bucket(0, 42), fixture_bucket(0, 42)],
            42,
            2,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicated"));

        let err = ordered_initial_bucket_commitments(&[fixture_bucket(0, 41)], 42, 1).unwrap_err();
        assert!(err.to_string().contains("stale epoch"));
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
