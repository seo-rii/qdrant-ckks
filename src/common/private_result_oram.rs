use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use collection::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, EncryptionRuleRef, EncryptionSelector,
};
use collection::operations::types::CollectionError;
use collection::private_result_oram_store::{PrivateResultOramEpochState, PrivateResultOramStore};
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING,
    PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PrivateResultOramCommitBucketRef,
    PrivateResultOramCommitSignatureInput, PrivateResultOramManifest,
    PrivateResultOramManifestValidationContext, PrivateResultOramMerkleProof,
    PrivateResultOramReadBucketsSignatureInput, PrivateResultOramSignature,
    PrivateResultOramSignatureVerification, PrivateResultOramUploadBundle,
    private_result_oram_bucket_ciphertext_bytes, private_result_oram_fixed_writeback_bucket_budget,
    validate_private_result_oram_commit_signature, validate_private_result_oram_manifest,
    validate_private_result_oram_manifest_signature_shape,
    validate_private_result_oram_read_buckets_signature,
    validate_private_result_oram_upload_bundle,
};
use serde::Serialize;
use serde_json::Value;
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::content_manager::toc::TableOfContent;
use storage::rbac::{AccessRequirements, Auth};

use crate::common::crypto::{
    PRIVATE_ORAM_JSON_MERKLE_TREE_HEIGHT_MAX, PRIVATE_ORAM_PATH_BATCH_SIZE_MAX,
    validate_collection_crypto_runtime_with_crypto_id,
};
use crate::settings::{CryptoInstanceConfig, Settings};

const KEY_ID_OPTION: &str = "key_id";
const EXPECTED_RK_ID_OPTION: &str = "expected_rk_id";
const MIN_RK_EPOCH_OPTION: &str = "min_rk_epoch";
const MAX_RK_EPOCH_OPTION: &str = "max_rk_epoch";
const ORAM_OPTION: &str = "oram";
const SIGNATURE_PUBLIC_KEYS_OPTION: &str = "signature_public_keys";
const ZERO_TRUST_PROFILE_STRICT: &str = "strict";
const SESSION_LEASE_SECS: u64 = 300;
const MAX_SESSION_COUNT: usize = 1024;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const PRIVATE_RESULT_ORAM_CLIENT_ID_MAX_LEN: usize = 256;
const PRIVATE_RESULT_ORAM_SESSION_ID_MAX_LEN: usize = 128;
const PRIVATE_RESULT_ORAM_PATH_BATCH_SIZE_MAX: usize = PRIVATE_ORAM_PATH_BATCH_SIZE_MAX as usize;
const PRIVATE_RESULT_ORAM_TREE_HEIGHT_MAX: usize =
    PRIVATE_ORAM_JSON_MERKLE_TREE_HEIGHT_MAX as usize;
const PRIVATE_RESULT_ORAM_READ_BUCKET_IDS_MAX: usize =
    PRIVATE_RESULT_ORAM_PATH_BATCH_SIZE_MAX * (PRIVATE_RESULT_ORAM_TREE_HEIGHT_MAX + 1);
const PRIVATE_RESULT_ORAM_UPLOAD_BUCKETS_MAX: usize =
    (1usize << PRIVATE_RESULT_ORAM_TREE_HEIGHT_MAX) * 2 - 1;
const PRIVATE_RESULT_ORAM_ENCRYPTION_REQUIRED: &str =
    "collection does not configure private result ORAM encryption";

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateResultOramManifestRecord {
    pub manifest: PrivateResultOramManifest,
    pub signature: PrivateResultOramSignature,
}

impl Debug for PrivateResultOramManifestRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramManifestRecord")
            .field("manifest", &self.manifest)
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateResultOramSessionResponse {
    pub session_id: String,
    pub collection_id: String,
    pub index_epoch: u64,
    pub root_hash: String,
    pub manifest: PrivateResultOramManifest,
    pub lease_expires_unix: u64,
}

impl Debug for PrivateResultOramSessionResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramSessionResponse")
            .field("session_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("manifest", &"[redacted]")
            .field("lease_expires_unix", &self.lease_expires_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateResultOramReadBucketsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
    pub proof: PrivateResultOramReadProof,
}

impl Debug for PrivateResultOramReadBucketsResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadBucketsResponse")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("bucket_count", &"[redacted]")
            .field("proof", &self.proof)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateResultOramReadProof {
    pub kind: String,
    pub value: String,
}

impl Debug for PrivateResultOramReadProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramReadProof")
            .field("kind", &self.kind)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
struct PrivateResultOramSession {
    session_id: String,
    _client_id: String,
    collection_id: String,
    collection_path: std::path::PathBuf,
    index_epoch: u64,
    root_hash: String,
    lease_expires_unix: u64,
    bucket_count: u64,
    max_bucket_ciphertext_bytes: usize,
    manifest: PrivateResultOramManifest,
}

impl Debug for PrivateResultOramSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateResultOramSession")
            .field("session_id", &"[redacted]")
            .field("client_id", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("collection_path", &"[redacted]")
            .field("index_epoch", &self.index_epoch)
            .field("root_hash", &"[redacted]")
            .field("lease_expires_unix", &self.lease_expires_unix)
            .field("bucket_count", &"[redacted]")
            .field("max_bucket_ciphertext_bytes", &"[redacted]")
            .field("manifest", &"[redacted]")
            .finish()
    }
}

#[derive(Default)]
struct PrivateResultOramSessionRegistry {
    sessions: HashMap<String, PrivateResultOramSession>,
    active_writer_by_collection: HashMap<String, String>,
    active_snapshot_by_collection: HashMap<String, usize>,
    active_lifecycle_by_collection: HashSet<String>,
    active_upload_by_collection: HashSet<String>,
}

impl PrivateResultOramSessionRegistry {
    fn open(
        &mut self,
        mut session: PrivateResultOramSession,
        now_unix: u64,
    ) -> StorageResult<PrivateResultOramSessionResponse> {
        self.expire(now_unix);
        if self.sessions.len() >= MAX_SESSION_COUNT {
            return Err(StorageError::bad_request(
                "private result ORAM session registry is full",
            ));
        }
        if self
            .active_snapshot_by_collection
            .contains_key(&session.collection_id)
        {
            return Err(StorageError::bad_request(
                "private result ORAM session open requires no active collection snapshot",
            ));
        }
        if self
            .active_lifecycle_by_collection
            .contains(&session.collection_id)
        {
            return Err(StorageError::bad_request(
                "private result ORAM session open requires no active collection lifecycle operation",
            ));
        }
        if self
            .active_upload_by_collection
            .contains(&session.collection_id)
        {
            return Err(StorageError::bad_request(
                "private result ORAM session open requires no active upload for this collection",
            ));
        }
        if self
            .active_writer_by_collection
            .contains_key(&session.collection_id)
        {
            return Err(StorageError::bad_request(
                "private result ORAM ConcurrentWriter: an active session already holds this collection",
            ));
        }
        while self.sessions.contains_key(&session.session_id) {
            session.session_id = new_session_id();
        }

        let response = session.response();
        self.active_writer_by_collection
            .insert(session.collection_id.clone(), session.session_id.clone());
        self.sessions.insert(session.session_id.clone(), session);
        Ok(response)
    }

    fn close(&mut self, collection_id: &str, session_id: &str, now_unix: u64) -> bool {
        self.expire(now_unix);
        let removed = self.sessions.remove(session_id);
        if let Some(session) = removed {
            if session.collection_id == collection_id {
                if self
                    .active_writer_by_collection
                    .get(collection_id)
                    .is_some_and(|active| active == session_id)
                {
                    self.active_writer_by_collection.remove(collection_id);
                    return true;
                }
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

    fn has_active_upload_collection(&self, collection_id: &str) -> bool {
        self.active_upload_by_collection.contains(collection_id)
    }

    fn begin_collection_snapshot(
        &mut self,
        collection_id: &str,
        now_unix: u64,
    ) -> StorageResult<()> {
        if self.active_lifecycle_by_collection.contains(collection_id) {
            return Err(StorageError::bad_request(
                "private result ORAM collection snapshot requires no active collection lifecycle operation",
            ));
        }
        ensure_no_active_private_result_oram_collection_session_in_registry(
            self,
            collection_id,
            now_unix,
        )?;
        let count = self
            .active_snapshot_by_collection
            .entry(collection_id.to_string())
            .or_insert(0);
        *count = count.checked_add(1).ok_or_else(|| {
            StorageError::service_error("private result ORAM snapshot reference count overflowed")
        })?;
        Ok(())
    }

    fn begin_collection_lifecycle_operation(
        &mut self,
        collection_id: &str,
        now_unix: u64,
    ) -> StorageResult<()> {
        if self
            .active_snapshot_by_collection
            .contains_key(collection_id)
        {
            return Err(StorageError::bad_request(
                "private result ORAM collection lifecycle operation requires no active collection snapshot",
            ));
        }
        if self.active_lifecycle_by_collection.contains(collection_id) {
            return Err(StorageError::bad_request(
                "private result ORAM collection lifecycle operation requires no active collection lifecycle operation",
            ));
        }
        ensure_no_active_private_result_oram_collection_lifecycle_in_registry(
            self,
            collection_id,
            now_unix,
        )?;
        self.active_lifecycle_by_collection
            .insert(collection_id.to_string());
        Ok(())
    }

    fn release_collection_snapshot(&mut self, collection_id: &str) {
        let Some(count) = self.active_snapshot_by_collection.get_mut(collection_id) else {
            return;
        };
        if *count <= 1 {
            self.active_snapshot_by_collection.remove(collection_id);
        } else {
            *count -= 1;
        }
    }

    fn release_collection_lifecycle_operation(&mut self, collection_id: &str) {
        self.active_lifecycle_by_collection.remove(collection_id);
    }

    fn begin_upload(&mut self, collection_id: &str, now_unix: u64) -> StorageResult<()> {
        ensure_private_result_oram_write_window_in_registry(self, collection_id, now_unix)?;
        self.active_upload_by_collection
            .insert(collection_id.to_string());
        Ok(())
    }

    fn release_upload(&mut self, collection_id: &str) {
        self.active_upload_by_collection.remove(collection_id);
    }

    fn with_session_mut<T>(
        &mut self,
        collection_id: &str,
        session_id: &str,
        now_unix: u64,
        action: impl FnOnce(&mut PrivateResultOramSession) -> StorageResult<T>,
    ) -> StorageResult<T> {
        self.expire(now_unix);
        let session = self.sessions.get_mut(session_id).ok_or_else(|| {
            StorageError::bad_request("private result ORAM session is missing or expired")
        })?;
        if session.collection_id != collection_id {
            return Err(StorageError::bad_request(
                "private result ORAM session does not match collection",
            ));
        }
        if !self
            .active_writer_by_collection
            .get(collection_id)
            .is_some_and(|active| active == session_id)
        {
            return Err(StorageError::bad_request(
                "private result ORAM session writer lock is missing or stale",
            ));
        }
        if session.lease_expires_unix <= now_unix {
            return Err(StorageError::bad_request(
                "private result ORAM session lease expired",
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
                if self
                    .active_writer_by_collection
                    .get(&session.collection_id)
                    .is_some_and(|active| active == &session_id)
                {
                    self.active_writer_by_collection
                        .remove(&session.collection_id);
                }
            }
        }
    }
}

impl PrivateResultOramSession {
    fn response(&self) -> PrivateResultOramSessionResponse {
        PrivateResultOramSessionResponse {
            session_id: self.session_id.clone(),
            collection_id: self.collection_id.clone(),
            index_epoch: self.index_epoch,
            root_hash: self.root_hash.clone(),
            manifest: self.manifest.clone(),
            lease_expires_unix: self.lease_expires_unix,
        }
    }
}

struct ResolvedPrivateResultOramContext {
    collection_path: std::path::PathBuf,
    collection_crypto_id: String,
    expected_key_id: String,
    expected_rk_id: String,
    min_rk_epoch: u64,
    max_rk_epoch: u64,
    expected_oram: OramParams,
    signature_public_keys: HashMap<String, String>,
    public_key: Vec<u8>,
}

impl ResolvedPrivateResultOramContext {
    fn manifest_context<'a>(
        &'a self,
        signature_key_id: &'a str,
    ) -> PrivateResultOramManifestValidationContext<'a> {
        PrivateResultOramManifestValidationContext {
            expected_collection_id: &self.collection_crypto_id,
            expected_key_id: &self.expected_key_id,
            expected_rk_id: &self.expected_rk_id,
            min_rk_epoch: self.min_rk_epoch,
            max_rk_epoch: self.max_rk_epoch,
            signature_verification: PrivateResultOramSignatureVerification {
                expected_key_id: signature_key_id,
                public_key: &self.public_key,
            },
        }
    }

    fn validate_manifest_runtime_policy(
        &self,
        manifest: &PrivateResultOramManifest,
    ) -> StorageResult<()> {
        if manifest.collection_id != self.collection_crypto_id {
            return Err(StorageError::bad_request(
                "private result ORAM manifest collection_id does not match runtime context",
            ));
        }
        if manifest.key_id != self.expected_key_id {
            return Err(StorageError::bad_request(
                "private result ORAM manifest key_id does not match runtime instance",
            ));
        }
        if manifest.rk_id != self.expected_rk_id {
            return Err(StorageError::bad_request(
                "private result ORAM manifest rk_id does not match runtime instance",
            ));
        }
        if manifest.rk_epoch < self.min_rk_epoch || manifest.rk_epoch > self.max_rk_epoch {
            return Err(StorageError::bad_request(
                "private result ORAM manifest rk_epoch does not match runtime instance",
            ));
        }
        if manifest.oram != self.expected_oram {
            return Err(StorageError::bad_request(
                "private result ORAM manifest oram does not match runtime instance",
            ));
        }
        Ok(())
    }

    fn signature_public_key(&self, signature_key_id: &str) -> StorageResult<Vec<u8>> {
        let public_key_b64 = self
            .signature_public_keys
            .get(signature_key_id)
            .ok_or_else(|| {
                StorageError::bad_request("private result ORAM signature key id is not configured")
            })?;
        decode_signature_public_key(public_key_b64)
    }
}

fn session_registry() -> &'static Mutex<PrivateResultOramSessionRegistry> {
    static REGISTRY: OnceLock<Mutex<PrivateResultOramSessionRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(PrivateResultOramSessionRegistry::default()))
}

enum PrivateResultOramCollectionGuardKind {
    Snapshot,
    Lifecycle,
}

pub(crate) struct PrivateResultOramCollectionSnapshotGuard {
    collection_id: String,
    kind: PrivateResultOramCollectionGuardKind,
}

struct PrivateResultOramUploadGuard {
    collection_id: String,
}

impl Drop for PrivateResultOramCollectionSnapshotGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = session_registry().lock() {
            match self.kind {
                PrivateResultOramCollectionGuardKind::Snapshot => {
                    registry.release_collection_snapshot(&self.collection_id)
                }
                PrivateResultOramCollectionGuardKind::Lifecycle => {
                    registry.release_collection_lifecycle_operation(&self.collection_id)
                }
            }
        }
    }
}

impl Drop for PrivateResultOramUploadGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = session_registry().lock() {
            registry.release_upload(&self.collection_id);
        }
    }
}

pub async fn do_upload_private_result_oram_manifest(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    manifest: PrivateResultOramManifest,
    signature: PrivateResultOramSignature,
) -> StorageResult<PrivateResultOramEpochState> {
    validate_private_result_oram_manifest_signature_shape(&signature)
        .map_err(private_result_oram_error)?;
    validate_private_result_oram_manifest_signature_owner_key(&manifest, &signature)?;
    let resolved = resolve_private_result_oram_context(
        toc,
        auth,
        settings,
        collection_name,
        &signature.key_id,
        "private_result_oram_manifest_upload",
        AccessRequirements::new().write(),
    )
    .await?;
    validate_private_result_oram_single_node_epoch_mode(toc.is_distributed())?;
    let epoch = validate_private_result_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_result_oram_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    let _upload_guard =
        begin_private_result_oram_upload_write_window(&resolved.collection_crypto_id)?;

    let epoch_state = PrivateResultOramEpochState {
        index_epoch: epoch.epoch,
        root_hash: manifest.root_hash.clone(),
    };
    let store = PrivateResultOramStore::new(resolved.collection_path);
    store
        .write_manifest_with_initial_epoch_if_absent_or_matching(
            &manifest,
            &signature,
            &epoch_state,
        )
        .map_err(private_result_oram_manifest_store_error)?;
    Ok(epoch_state)
}

pub async fn do_get_private_result_oram_manifest(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
) -> StorageResult<PrivateResultOramManifestRecord> {
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "private_result_oram_manifest_read",
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
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_RESULT_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_result_oram_rule(&encryption)?;
    let instance = private_result_oram_instance(settings, rule)?;
    let store = PrivateResultOramStore::new(collection.path());
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    validate_private_result_oram_manifest_signature_shape(&signature)
        .map_err(private_result_oram_error)?;
    validate_private_result_oram_manifest_signature_owner_key(&manifest, &signature)?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = manifest_context_from_runtime(&collection_crypto_id, instance, public_key)?;
    validate_private_result_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_result_oram_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    Ok(PrivateResultOramManifestRecord {
        manifest,
        signature,
    })
}

pub async fn do_open_private_result_oram_session(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    client_id: String,
    desired_epoch: u64,
    fixed_budget: bool,
) -> StorageResult<PrivateResultOramSessionResponse> {
    validate_private_result_oram_client_id_shape(&client_id)?;
    if is_strict(settings) && !fixed_budget {
        return Err(StorageError::bad_request(
            "private result ORAM strict mode requires fixed_budget=true",
        ));
    }
    if !fixed_budget {
        return Err(StorageError::bad_request(
            "private result ORAM sessions require fixed_budget=true",
        ));
    }

    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_result_oram_session_open",
    )?;
    validate_private_result_oram_single_node_epoch_mode(toc.is_distributed())?;
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
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_RESULT_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_result_oram_rule(&encryption)?;
    let instance = private_result_oram_instance(settings, rule)?;
    let store = PrivateResultOramStore::new(collection.path());
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    validate_private_result_oram_manifest_signature_shape(&signature)
        .map_err(private_result_oram_error)?;
    validate_private_result_oram_manifest_signature_owner_key(&manifest, &signature)?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = ResolvedPrivateResultOramContext {
        collection_path: collection.path().to_path_buf(),
        ..manifest_context_from_runtime(&collection_crypto_id, instance, public_key)?
    };
    let manifest_epoch = validate_private_result_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_result_oram_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_result_oram_epoch_store_error)?;
    if current_epoch.index_epoch < manifest_epoch.epoch
        || (current_epoch.index_epoch == manifest_epoch.epoch
            && current_epoch.root_hash != manifest.root_hash)
    {
        return Err(StorageError::bad_request(
            "private result ORAM current epoch is inconsistent with manifest epoch",
        ));
    }
    if desired_epoch != current_epoch.index_epoch {
        return Err(StorageError::bad_request(
            "private result ORAM requested epoch is not current epoch",
        ));
    }
    let expected_open_epoch = current_epoch.clone();
    let expected_open_manifest = manifest.clone();
    let expected_open_signature = signature.clone();

    let now_unix = current_unix_secs()?;
    let session = PrivateResultOramSession {
        session_id: new_session_id(),
        _client_id: client_id,
        collection_id: collection_crypto_id.clone(),
        collection_path: collection.path().to_path_buf(),
        index_epoch: current_epoch.index_epoch,
        root_hash: current_epoch.root_hash.clone(),
        lease_expires_unix: session_lease_expires_unix(now_unix)?,
        bucket_count: manifest.bucket_count,
        max_bucket_ciphertext_bytes: max_bucket_ciphertext_bytes(&manifest.oram)?,
        manifest,
    };
    let response = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private result ORAM session registry poisoned"))?
        .open(session, now_unix)?;
    if let Err(err) = ensure_private_result_oram_session_open_storage_matches(
        &store,
        &expected_open_epoch,
        &expected_open_manifest,
        &expected_open_signature,
    ) {
        if let Ok(mut registry) = session_registry().lock() {
            registry.close(&collection_crypto_id, &response.session_id, now_unix);
        }
        return Err(err);
    }
    Ok(response)
}

pub async fn do_upload_private_result_oram_buckets(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    index_epoch: u64,
    root_hash: String,
    buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
) -> StorageResult<PrivateResultOramEpochState> {
    validate_base64url_32_string(&root_hash, "root_hash")?;
    validate_upload_bucket_request_shape(&buckets)?;
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_result_oram_buckets_upload",
    )?;
    let collection: std::sync::Arc<collection::collection::Collection> =
        toc.get_collection(&pass).await?;
    validate_private_result_oram_single_node_epoch_mode(toc.is_distributed())?;
    let config: CollectionConfigInternal = collection.config_snapshot().await;
    let collection_crypto_id = config.stable_crypto_id(collection.name())?;
    validate_collection_crypto_runtime_with_crypto_id(
        settings,
        collection.name(),
        &collection_crypto_id,
        &config.params,
    )?;
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_RESULT_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_result_oram_rule(&encryption)?;
    let instance = private_result_oram_instance(settings, rule)?;
    let store = PrivateResultOramStore::new(collection.path());
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    validate_private_result_oram_manifest_signature_shape(&signature)
        .map_err(private_result_oram_error)?;
    validate_private_result_oram_manifest_signature_owner_key(&manifest, &signature)?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = manifest_context_from_runtime(&collection_crypto_id, instance, public_key)?;
    validate_private_result_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_result_oram_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    let _upload_guard =
        begin_private_result_oram_upload_write_window(&resolved.collection_crypto_id)?;
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_result_oram_epoch_store_error)?;
    if current_epoch.index_epoch != index_epoch || current_epoch.root_hash != root_hash {
        return Err(StorageError::bad_request(
            "private result ORAM bucket upload epoch/root does not match current manifest epoch",
        ));
    }

    let max_ciphertext_bytes = max_bucket_ciphertext_bytes(&manifest.oram)?;
    let bundle = PrivateResultOramUploadBundle {
        manifest: manifest.clone(),
        manifest_signature: signature.clone(),
        buckets,
    };
    let leaf_commitments =
        validate_private_result_oram_upload_bundle(&bundle).map_err(private_result_oram_error)?;
    for bucket in &bundle.buckets {
        store
            .validate_bucket_for_write(
                bucket,
                index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .map_err(private_result_oram_upload_store_error)?;
        validate_bucket_ciphertext_fixed_size(bucket, &manifest)?;
    }
    for bucket in &bundle.buckets {
        store
            .write_bucket(
                bucket,
                index_epoch,
                manifest.bucket_count,
                max_ciphertext_bytes,
            )
            .map_err(private_result_oram_upload_store_error)?;
    }
    store
        .write_merkle_tree_from_commitments(index_epoch, root_hash.clone(), leaf_commitments)
        .map_err(private_result_oram_upload_store_error)?;
    Ok(PrivateResultOramEpochState {
        index_epoch,
        root_hash,
    })
}

pub async fn do_read_private_result_oram_buckets(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    session_id: &str,
    index_epoch: u64,
    root_hash: String,
    bucket_ids: Vec<u64>,
    read_signature: PrivateResultOramSignature,
) -> StorageResult<PrivateResultOramReadBucketsResponse> {
    validate_private_result_oram_manifest_signature_shape(&read_signature)
        .map_err(private_result_oram_error)?;
    validate_private_result_oram_session_id_shape(session_id)?;
    validate_base64url_32_string(&root_hash, "root_hash")?;
    validate_read_bucket_request_shape(&bucket_ids)?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        None,
        "private_result_oram_buckets_read",
        AccessRequirements::new(),
    )
    .await?;
    validate_private_result_oram_single_node_epoch_mode(toc.is_distributed())?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private result ORAM session registry poisoned")
    })?;
    registry.with_session_mut(
        &request_context.collection_crypto_id,
        session_id,
        now_unix,
        |session| {
            request_context.validate_manifest_runtime_policy(&session.manifest)?;
            if session.index_epoch != index_epoch || session.root_hash != root_hash {
                return Err(StorageError::bad_request(
                    "private result ORAM session epoch/root mismatch",
                ));
            }
            validate_bucket_read_request_budget(&session.manifest, &bucket_ids)?;
            validate_session_signature_owner_key(session, &read_signature.key_id)?;
            let public_key = request_context.signature_public_key(&read_signature.key_id)?;
            validate_private_result_oram_read_buckets_signature(
                PrivateResultOramReadBucketsSignatureInput {
                    collection_id: &session.manifest.collection_id,
                    key_id: &session.manifest.key_id,
                    rk_id: &session.manifest.rk_id,
                    rk_epoch: session.manifest.rk_epoch,
                    index_epoch,
                    root_hash: &root_hash,
                    bucket_count: session.bucket_count,
                    bucket_ids: &bucket_ids,
                    signature_alg: &read_signature.alg,
                    signature_key_id: &read_signature.key_id,
                },
                &read_signature.sig,
                PrivateResultOramSignatureVerification {
                    expected_key_id: &read_signature.key_id,
                    public_key: &public_key,
                },
            )
            .map_err(private_result_oram_error)?;
            validate_bucket_read_request_details(&session.manifest, &bucket_ids)?;
            let store = PrivateResultOramStore::new(&session.collection_path);
            ensure_private_result_oram_active_session_current_epoch(
                &store,
                session.index_epoch,
                &session.root_hash,
            )?;
            let (buckets, proof) = store
                .read_bucket_batch_with_proof(
                    &bucket_ids,
                    session.index_epoch,
                    &session.root_hash,
                    session.bucket_count,
                    session.max_bucket_ciphertext_bytes,
                )
                .map_err(private_result_oram_read_store_error)?;
            ensure_private_result_oram_read_proof_matches_buckets(&proof, &buckets)?;
            validate_private_result_oram_read_bucket_ciphertexts_fixed_size(
                &session.manifest,
                &buckets,
            )?;
            let proof_value = serde_json::to_string(&proof).map_err(|_| {
                StorageError::service_error("failed to serialize private result ORAM Merkle proof")
            })?;
            Ok(PrivateResultOramReadBucketsResponse {
                index_epoch: session.index_epoch,
                root_hash: session.root_hash.clone(),
                buckets,
                proof: PrivateResultOramReadProof {
                    kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
                    value: proof_value,
                },
            })
        },
    )
}

pub async fn do_commit_private_result_oram_buckets(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    session_id: &str,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    new_root_hash: String,
    updated_buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
    commit_signature: PrivateResultOramSignature,
) -> StorageResult<PrivateResultOramEpochState> {
    validate_private_result_oram_manifest_signature_shape(&commit_signature)
        .map_err(private_result_oram_error)?;
    validate_private_result_oram_session_id_shape(session_id)?;
    validate_base64url_32_string(&old_root_hash, "old_root_hash")?;
    validate_base64url_32_string(&new_root_hash, "new_root_hash")?;
    validate_commit_bucket_request_shape(&updated_buckets)?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        None,
        "private_result_oram_commit",
        AccessRequirements::new().write(),
    )
    .await?;
    validate_private_result_oram_single_node_epoch_mode(toc.is_distributed())?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private result ORAM session registry poisoned")
    })?;
    registry.with_session_mut(
        &request_context.collection_crypto_id,
        session_id,
        now_unix,
        |session| {
            request_context.validate_manifest_runtime_policy(&session.manifest)?;
            if session.index_epoch != old_epoch || session.root_hash != old_root_hash {
                return Err(StorageError::bad_request(
                    "private result ORAM commit old epoch/root does not match active session",
                ));
            }
            if new_epoch <= old_epoch {
                return Err(StorageError::bad_request(
                    "private result ORAM commit new_epoch must be greater than old_epoch",
                ));
            }
            let max_updated_buckets = max_updated_bucket_count(session)?;
            if updated_buckets.is_empty() || updated_buckets.len() > max_updated_buckets {
                return Err(StorageError::bad_request(
                    "private result ORAM commit updated_buckets must contain at least one bucket and fit the fixed writeback budget",
                ));
            }
            let updated_bucket_refs = updated_buckets
                .iter()
                .map(|bucket| PrivateResultOramCommitBucketRef {
                    bucket_id: bucket.bucket_id,
                    ciphertext_sha256: bucket.ciphertext_sha256.as_str(),
                })
                .collect::<Vec<_>>();
            validate_session_signature_owner_key(session, &commit_signature.key_id)?;
            let public_key = request_context.signature_public_key(&commit_signature.key_id)?;
            validate_private_result_oram_commit_signature(
                PrivateResultOramCommitSignatureInput {
                    collection_id: &session.manifest.collection_id,
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
                PrivateResultOramSignatureVerification {
                    expected_key_id: &commit_signature.key_id,
                    public_key: &public_key,
                },
            )
            .map_err(private_result_oram_error)?;
            for bucket in &updated_buckets {
                validate_bucket_ciphertext_fixed_size(bucket, &session.manifest)?;
            }
            let store = PrivateResultOramStore::new(&session.collection_path);
            ensure_private_result_oram_active_session_current_epoch(
                &store,
                old_epoch,
                &old_root_hash,
            )?;
            let old = PrivateResultOramEpochState {
                index_epoch: old_epoch,
                root_hash: old_root_hash,
            };
            let new = PrivateResultOramEpochState {
                index_epoch: new_epoch,
                root_hash: new_root_hash,
            };
            let committed = store
                .commit_writeback_with_signature(
                    &old,
                    &new,
                    session.bucket_count,
                    &updated_buckets,
                    session.max_bucket_ciphertext_bytes,
                    &commit_signature,
                    PrivateResultOramSignatureVerification {
                        expected_key_id: &commit_signature.key_id,
                        public_key: &public_key,
                    },
                )
                .map_err(private_result_oram_commit_writeback_store_error)?;
            session.index_epoch = committed.index_epoch;
            session.root_hash = committed.root_hash.clone();
            session.lease_expires_unix = session_lease_expires_unix(now_unix)?;
            Ok(committed)
        },
    )
}

pub async fn do_close_private_result_oram_session(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    session_id: &str,
) -> StorageResult<bool> {
    validate_private_result_oram_session_id_shape(session_id)?;
    let request_context = collection_context_for_request(
        toc,
        auth,
        settings,
        collection_name,
        None,
        "private_result_oram_session_close",
        AccessRequirements::new().write(),
    )
    .await?;
    let now_unix = current_unix_secs()?;
    let closed = session_registry()
        .lock()
        .map_err(|_| StorageError::service_error("private result ORAM session registry poisoned"))?
        .close(&request_context.collection_crypto_id, session_id, now_unix);
    if !closed {
        return Err(StorageError::bad_request(
            "private result ORAM session is missing or already closed",
        ));
    }
    Ok(true)
}

pub fn validate_recovered_private_result_oram_snapshot_signatures(
    settings: &Settings,
    collection_name: &str,
    config: &CollectionConfigInternal,
    collection_path: &std::path::Path,
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

    for rule in encryption
        .rules
        .iter()
        .filter(|rule| rule.binding.as_deref() == Some(PRIVATE_RESULT_ORAM_BINDING))
    {
        if !matches!(rule.selector, EncryptionSelector::PayloadPaths { .. }) {
            return Err(StorageError::bad_request(
                "private result ORAM snapshot rule must use payload_paths selector",
            ));
        }
        let instance = private_result_oram_instance(settings, rule)?;
        let store = PrivateResultOramStore::new(collection_path);
        let (manifest, signature) = read_uploaded_manifest(&store)?;
        validate_private_result_oram_manifest_signature_shape(&signature)
            .map_err(private_result_oram_error)?;
        validate_private_result_oram_manifest_signature_owner_key(&manifest, &signature)?;
        let public_key = signature_public_key(instance, &signature.key_id)?;
        let resolved = manifest_context_from_runtime(&collection_crypto_id, instance, public_key)?;
        validate_private_result_oram_manifest(
            &manifest,
            Some(&signature),
            resolved.manifest_context(&signature.key_id),
        )
        .map_err(private_result_oram_error)?;
        resolved.validate_manifest_runtime_policy(&manifest)?;
        let expected_epoch = PrivateResultOramEpochState {
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
        };
        ensure_private_result_oram_restored_snapshot_storage_matches(
            &store,
            &expected_epoch,
            &manifest,
            &signature,
        )?;
    }

    Ok(())
}

async fn collection_context_for_request(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    signature_key_id: Option<&str>,
    method: &str,
    requirements: AccessRequirements,
) -> StorageResult<ResolvedPrivateResultOramContext> {
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
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_RESULT_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_result_oram_rule(&encryption)?;
    let instance = private_result_oram_instance(settings, rule)?;
    let public_key = if let Some(signature_key_id) = signature_key_id {
        signature_public_key(instance, signature_key_id)?
    } else {
        Vec::new()
    };
    Ok(ResolvedPrivateResultOramContext {
        collection_path: collection.path().to_path_buf(),
        ..manifest_context_from_runtime(&collection_crypto_id, instance, public_key)?
    })
}

async fn resolve_private_result_oram_context(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    signature_key_id: &str,
    method: &str,
    requirements: AccessRequirements,
) -> StorageResult<ResolvedPrivateResultOramContext> {
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
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(|| StorageError::bad_request(PRIVATE_RESULT_ORAM_ENCRYPTION_REQUIRED))?;
    let rule = private_result_oram_rule(&encryption)?;
    let instance = private_result_oram_instance(settings, rule)?;
    let public_key = signature_public_key(instance, signature_key_id)?;
    Ok(ResolvedPrivateResultOramContext {
        collection_path: collection.path().to_path_buf(),
        ..manifest_context_from_runtime(&collection_crypto_id, instance, public_key)?
    })
}

fn private_result_oram_rule(
    encryption: &CollectionEncryptionConfig,
) -> StorageResult<&EncryptionRuleRef> {
    encryption
        .rules
        .iter()
        .find(|rule| rule.binding.as_deref() == Some(PRIVATE_RESULT_ORAM_BINDING))
        .ok_or_else(|| {
            StorageError::bad_request(format!(
                "{PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER} requires private-result-oram/v1 collection binding"
            ))
        })
}

fn private_result_oram_instance<'a>(
    settings: &'a Settings,
    rule: &EncryptionRuleRef,
) -> StorageResult<&'a CryptoInstanceConfig> {
    let instance = settings
        .crypto
        .instances
        .get(&rule.instance)
        .ok_or_else(|| {
            StorageError::bad_request(
                "private result ORAM collection binding references a missing runtime instance",
            )
        })?;
    if instance.provider != PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER {
        return Err(StorageError::bad_request(format!(
            "private result ORAM collection binding must reference a {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER} runtime instance",
        )));
    }
    Ok(instance)
}

fn manifest_context_from_runtime(
    collection_crypto_id: &str,
    instance: &CryptoInstanceConfig,
    public_key: Vec<u8>,
) -> StorageResult<ResolvedPrivateResultOramContext> {
    let expected_key_id = required_option_string(instance, KEY_ID_OPTION)?.to_string();
    let expected_rk_id = required_option_string(instance, EXPECTED_RK_ID_OPTION)?.to_string();
    let min_rk_epoch = required_option_u64(instance, MIN_RK_EPOCH_OPTION)?;
    let max_rk_epoch = required_option_u64(instance, MAX_RK_EPOCH_OPTION)?;
    let expected_oram = required_oram_params(instance)?;
    let signature_public_keys = signature_public_keys(instance)?;
    Ok(ResolvedPrivateResultOramContext {
        collection_path: std::path::PathBuf::new(),
        collection_crypto_id: collection_crypto_id.to_string(),
        expected_key_id,
        expected_rk_id,
        min_rk_epoch,
        max_rk_epoch,
        expected_oram,
        signature_public_keys,
        public_key,
    })
}

fn read_uploaded_manifest(
    store: &PrivateResultOramStore,
) -> StorageResult<(PrivateResultOramManifest, PrivateResultOramSignature)> {
    store
        .read_manifest()
        .map_err(private_result_oram_manifest_read_store_error)
}

fn validate_private_result_oram_manifest_signature_owner_key(
    manifest: &PrivateResultOramManifest,
    signature: &PrivateResultOramSignature,
) -> StorageResult<()> {
    if signature.key_id != manifest.owner_signing_key_id {
        return Err(private_result_oram_error(
            qdrant_sec::PrivateResultOramError::SignatureKeyIdMismatch,
        ));
    }
    Ok(())
}

fn ensure_private_result_oram_session_open_storage_matches(
    store: &PrivateResultOramStore,
    expected_epoch: &PrivateResultOramEpochState,
    expected_manifest: &PrivateResultOramManifest,
    expected_signature: &PrivateResultOramSignature,
) -> StorageResult<()> {
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_result_oram_epoch_store_error)?;
    let (stored_manifest, stored_signature) = read_uploaded_manifest(store)?;
    if current_epoch != *expected_epoch
        || stored_manifest != *expected_manifest
        || stored_signature != *expected_signature
    {
        return Err(StorageError::bad_request(
            "private result ORAM session open observed concurrent manifest or epoch update",
        ));
    }
    store
        .read_bucket_batch_with_proof(
            &[0],
            expected_epoch.index_epoch,
            &expected_epoch.root_hash,
            expected_manifest.bucket_count,
            max_bucket_ciphertext_bytes(&expected_manifest.oram)?,
        )
        .map_err(private_result_oram_read_store_error)?;
    Ok(())
}

fn ensure_private_result_oram_restored_snapshot_storage_matches(
    store: &PrivateResultOramStore,
    expected_epoch: &PrivateResultOramEpochState,
    expected_manifest: &PrivateResultOramManifest,
    expected_signature: &PrivateResultOramSignature,
) -> StorageResult<()> {
    let current_epoch = store
        .read_current_epoch()
        .map_err(private_result_oram_epoch_store_error)?;
    let (stored_manifest, stored_signature) = read_uploaded_manifest(store)?;
    if current_epoch != *expected_epoch
        || stored_manifest != *expected_manifest
        || stored_signature != *expected_signature
    {
        return Err(StorageError::bad_request(
            "private result ORAM restored snapshot manifest or epoch does not match current storage",
        ));
    }
    let max_bucket_ciphertext_bytes = max_bucket_ciphertext_bytes(&expected_manifest.oram)?;
    for bucket_id in 0..expected_manifest.bucket_count {
        store
            .read_bucket_batch_with_proof(
                &[bucket_id],
                expected_epoch.index_epoch,
                &expected_epoch.root_hash,
                expected_manifest.bucket_count,
                max_bucket_ciphertext_bytes,
            )
            .map_err(private_result_oram_read_store_error)?;
    }
    Ok(())
}

pub(crate) fn begin_private_result_oram_collection_snapshot(
    collection_name: &str,
    config: &CollectionConfigInternal,
) -> StorageResult<Option<PrivateResultOramCollectionSnapshotGuard>> {
    if !collection_uses_private_result_oram(config) {
        return Ok(None);
    }

    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private result ORAM session registry poisoned")
    })?;
    registry.begin_collection_snapshot(&collection_crypto_id, now_unix)?;
    Ok(Some(PrivateResultOramCollectionSnapshotGuard {
        collection_id: collection_crypto_id,
        kind: PrivateResultOramCollectionGuardKind::Snapshot,
    }))
}

pub(crate) fn begin_private_result_oram_collection_lifecycle(
    collection_name: &str,
    config: &CollectionConfigInternal,
) -> StorageResult<Option<PrivateResultOramCollectionSnapshotGuard>> {
    if !collection_uses_private_result_oram(config) {
        return Ok(None);
    }

    let collection_crypto_id = config.stable_crypto_id(collection_name)?;
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private result ORAM session registry poisoned")
    })?;
    registry.begin_collection_lifecycle_operation(&collection_crypto_id, now_unix)?;
    Ok(Some(PrivateResultOramCollectionSnapshotGuard {
        collection_id: collection_crypto_id,
        kind: PrivateResultOramCollectionGuardKind::Lifecycle,
    }))
}

fn begin_private_result_oram_upload_write_window(
    collection_id: &str,
) -> StorageResult<PrivateResultOramUploadGuard> {
    let now_unix = current_unix_secs()?;
    let mut registry = session_registry().lock().map_err(|_| {
        StorageError::service_error("private result ORAM session registry poisoned")
    })?;
    registry.begin_upload(collection_id, now_unix)?;
    Ok(PrivateResultOramUploadGuard {
        collection_id: collection_id.to_string(),
    })
}

fn ensure_private_result_oram_write_window_in_registry(
    registry: &mut PrivateResultOramSessionRegistry,
    collection_id: &str,
    now_unix: u64,
) -> StorageResult<()> {
    if registry
        .active_snapshot_by_collection
        .contains_key(collection_id)
    {
        return Err(StorageError::bad_request(
            "private result ORAM upload requires no active collection snapshot",
        ));
    }
    if registry
        .active_lifecycle_by_collection
        .contains(collection_id)
    {
        return Err(StorageError::bad_request(
            "private result ORAM upload requires no active collection lifecycle operation",
        ));
    }
    if registry.has_active_collection(collection_id, now_unix) {
        return Err(StorageError::bad_request(
            "private result ORAM upload requires no active session for this collection",
        ));
    }
    if registry.active_upload_by_collection.contains(collection_id) {
        return Err(StorageError::bad_request(
            "private result ORAM upload requires no active upload for this collection",
        ));
    }
    Ok(())
}

fn ensure_no_active_private_result_oram_collection_session_in_registry(
    registry: &mut PrivateResultOramSessionRegistry,
    collection_id: &str,
    now_unix: u64,
) -> StorageResult<()> {
    if registry.has_active_collection(collection_id, now_unix) {
        return Err(StorageError::bad_request(
            "private result ORAM collection snapshot requires no active private ORAM session",
        ));
    }
    if registry.has_active_upload_collection(collection_id) {
        return Err(StorageError::bad_request(
            "private result ORAM collection snapshot requires no active private ORAM upload",
        ));
    }
    Ok(())
}

fn ensure_no_active_private_result_oram_collection_lifecycle_in_registry(
    registry: &mut PrivateResultOramSessionRegistry,
    collection_id: &str,
    now_unix: u64,
) -> StorageResult<()> {
    if registry.has_active_collection(collection_id, now_unix) {
        return Err(StorageError::bad_request(
            "private result ORAM collection lifecycle operation requires no active private ORAM session",
        ));
    }
    if registry.has_active_upload_collection(collection_id) {
        return Err(StorageError::bad_request(
            "private result ORAM collection lifecycle operation requires no active private ORAM upload",
        ));
    }
    Ok(())
}

fn collection_uses_private_result_oram(config: &CollectionConfigInternal) -> bool {
    config
        .params
        .effective_encryption()
        .is_some_and(|encryption| {
            encryption
                .rules
                .iter()
                .any(|rule| rule.binding.as_deref() == Some(PRIVATE_RESULT_ORAM_BINDING))
        })
}

fn ensure_private_result_oram_active_session_current_epoch(
    store: &PrivateResultOramStore,
    expected_epoch: u64,
    expected_root_hash: &str,
) -> StorageResult<()> {
    let current = store
        .read_current_epoch()
        .map_err(private_result_oram_epoch_store_error)?;
    if current.index_epoch != expected_epoch || current.root_hash != expected_root_hash {
        return Err(StorageError::bad_request(
            "private result ORAM current epoch/root does not match active session",
        ));
    }
    Ok(())
}

fn validate_session_signature_owner_key(
    session: &PrivateResultOramSession,
    signature_key_id: &str,
) -> StorageResult<()> {
    if signature_key_id != session.manifest.owner_signing_key_id {
        return Err(StorageError::bad_request(
            "private result ORAM request signature key_id does not match manifest owner_signing_key_id",
        ));
    }
    Ok(())
}

fn ensure_private_result_oram_read_proof_matches_buckets(
    proof: &PrivateResultOramMerkleProof,
    buckets: &[qdrant_sec::PrivateResultOramBucket],
) -> StorageResult<()> {
    if proof.leaves.len() != buckets.len() {
        return Err(StorageError::bad_request(
            "private result ORAM encrypted bucket/proof consistency validation failed",
        ));
    }
    for (leaf, bucket) in proof.leaves.iter().zip(buckets) {
        if leaf.bucket_id != bucket.bucket_id || leaf.leaf_hash != bucket.bucket_commitment {
            return Err(StorageError::bad_request(
                "private result ORAM encrypted bucket/proof consistency validation failed",
            ));
        }
    }
    Ok(())
}

fn max_updated_bucket_count(session: &PrivateResultOramSession) -> StorageResult<usize> {
    private_result_oram_fixed_writeback_bucket_budget(&session.manifest.oram)
        .map_err(|_| StorageError::bad_request("private result ORAM writeback size overflows"))
}

fn current_unix_secs() -> StorageResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StorageError::service_error("system clock before UNIX epoch"))
}

fn session_lease_expires_unix(now_unix: u64) -> StorageResult<u64> {
    now_unix.checked_add(SESSION_LEASE_SECS).ok_or_else(|| {
        StorageError::service_error("private result ORAM session lease calculation overflowed")
    })
}

fn new_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn is_strict(settings: &Settings) -> bool {
    settings.crypto.zero_trust_profile.as_deref() == Some(ZERO_TRUST_PROFILE_STRICT)
}

fn validate_private_result_oram_single_node_epoch_mode(distributed: bool) -> StorageResult<()> {
    if distributed {
        return Err(StorageError::bad_request(
            "private result ORAM distributed operations require consensus-backed epoch/root CAS; \
             this MVP supports private ORAM sessions only in single-node mode",
        ));
    }
    Ok(())
}

fn validate_private_result_oram_client_id_shape(client_id: &str) -> StorageResult<()> {
    if client_id.is_empty() || client_id.len() > PRIVATE_RESULT_ORAM_CLIENT_ID_MAX_LEN {
        return Err(StorageError::bad_request(
            "private result ORAM client_id must be non-empty and at most 256 bytes",
        ));
    }
    if !client_id.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'-')
    }) {
        return Err(StorageError::bad_request(
            "private result ORAM client_id is invalid",
        ));
    }
    Ok(())
}

fn validate_private_result_oram_session_id_shape(session_id: &str) -> StorageResult<()> {
    if session_id.is_empty()
        || session_id.len() > PRIVATE_RESULT_ORAM_SESSION_ID_MAX_LEN
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(StorageError::bad_request(
            "private result ORAM session_id is invalid",
        ));
    }
    Ok(())
}

fn signature_public_key(
    instance: &CryptoInstanceConfig,
    signature_key_id: &str,
) -> StorageResult<Vec<u8>> {
    let registry = signature_public_keys(instance)?;
    let public_key_b64 = registry.get(signature_key_id).ok_or_else(|| {
        StorageError::bad_request("private result ORAM signature key id is not configured")
    })?;
    decode_signature_public_key(public_key_b64)
}

fn signature_public_keys(
    instance: &CryptoInstanceConfig,
) -> StorageResult<HashMap<String, String>> {
    instance
        .options
        .get(SIGNATURE_PUBLIC_KEYS_OPTION)
        .and_then(Value::as_object)
        .ok_or_else(|| {
            StorageError::bad_request(
                "private result ORAM runtime instance must configure signature_public_keys",
            )
        })?
        .iter()
        .map(|(key_id, value)| {
            let public_key = value.as_str().ok_or_else(|| {
                StorageError::bad_request(
                    "private result ORAM runtime signature public key is invalid",
                )
            })?;
            Ok((key_id.clone(), public_key.to_string()))
        })
        .collect()
}

fn decode_signature_public_key(public_key_b64: &str) -> StorageResult<Vec<u8>> {
    if public_key_b64.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(StorageError::bad_request(
            "private result ORAM signature public key has invalid encoded length",
        ));
    }
    let public_key = BASE64URL_NOPAD
        .decode(public_key_b64.as_bytes())
        .map_err(|_| {
            StorageError::bad_request(
                "private result ORAM signature public key must be base64url without padding",
            )
        })?;
    if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(StorageError::bad_request(
            "private result ORAM signature public key has invalid encoded length",
        ));
    }
    Ok(public_key)
}

fn required_option_string<'a>(
    instance: &'a CryptoInstanceConfig,
    option: &str,
) -> StorageResult<&'a str> {
    instance
        .options
        .get(option)
        .and_then(Value::as_str)
        .ok_or_else(|| StorageError::bad_request("private result ORAM runtime option is missing"))
}

fn required_option_u64(instance: &CryptoInstanceConfig, option: &str) -> StorageResult<u64> {
    instance
        .options
        .get(option)
        .and_then(Value::as_u64)
        .ok_or_else(|| StorageError::bad_request("private result ORAM runtime option is missing"))
}

fn required_oram_params(instance: &CryptoInstanceConfig) -> StorageResult<OramParams> {
    let value = instance.options.get(ORAM_OPTION).cloned().ok_or_else(|| {
        StorageError::bad_request("private result ORAM runtime ORAM policy is missing")
    })?;
    serde_json::from_value(value).map_err(|_| {
        StorageError::bad_request("private result ORAM runtime instance oram policy is invalid")
    })
}

fn max_bucket_ciphertext_bytes(oram: &OramParams) -> StorageResult<usize> {
    let block_size = usize::try_from(oram.block_size_bytes).map_err(|_| {
        StorageError::bad_request("private result ORAM block_size_bytes is invalid")
    })?;
    let bucket_size = usize::try_from(oram.bucket_size)
        .map_err(|_| StorageError::bad_request("private result ORAM bucket_size is invalid"))?;
    block_size
        .checked_mul(bucket_size)
        .and_then(|size| size.checked_add(4096))
        .ok_or_else(|| StorageError::bad_request("private result ORAM bucket size is invalid"))
}

fn validate_bucket_ciphertext_fixed_size(
    bucket: &qdrant_sec::PrivateResultOramBucket,
    manifest: &PrivateResultOramManifest,
) -> StorageResult<()> {
    let expected = private_result_oram_bucket_ciphertext_bytes(&manifest.oram)
        .map_err(|_| StorageError::bad_request("private result ORAM bucket size is invalid"))?;
    let expected_encoded_len = max_base64url_nopad_encoded_len(expected)
        .ok_or_else(|| StorageError::bad_request("private result ORAM bucket size is invalid"))?;
    if bucket.ciphertext.len() != expected_encoded_len {
        return Err(StorageError::bad_request(
            "private result ORAM bucket ciphertext validation failed",
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(bucket.ciphertext.as_bytes())
        .map_err(|_| {
            StorageError::bad_request("private result ORAM bucket ciphertext validation failed")
        })?;
    if ciphertext.len() != expected {
        return Err(StorageError::bad_request(
            "private result ORAM bucket ciphertext validation failed",
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

fn validate_private_result_oram_read_bucket_ciphertexts_fixed_size(
    manifest: &PrivateResultOramManifest,
    buckets: &[qdrant_sec::PrivateResultOramBucket],
) -> StorageResult<()> {
    for bucket in buckets {
        validate_bucket_ciphertext_fixed_size(bucket, manifest)?;
    }
    Ok(())
}

#[cfg(test)]
fn validate_bucket_read_request(
    manifest: &PrivateResultOramManifest,
    bucket_ids: &[u64],
) -> StorageResult<()> {
    validate_bucket_read_request_budget(manifest, bucket_ids)?;
    validate_bucket_read_request_details(manifest, bucket_ids)
}

fn validate_read_bucket_request_shape(bucket_ids: &[u64]) -> StorageResult<()> {
    if bucket_ids.is_empty() {
        return Err(StorageError::bad_request(
            "private result ORAM read_buckets request is empty",
        ));
    }
    if bucket_ids.len() > PRIVATE_RESULT_ORAM_READ_BUCKET_IDS_MAX {
        return Err(StorageError::bad_request(
            "private result ORAM read_buckets request exceeds maximum bucket batch size",
        ));
    }
    Ok(())
}

fn validate_commit_bucket_request_shape(
    updated_buckets: &[qdrant_sec::PrivateResultOramBucket],
) -> StorageResult<()> {
    if updated_buckets.is_empty() {
        return Err(StorageError::bad_request(
            "private result ORAM commit updated_buckets must contain at least one bucket",
        ));
    }
    if updated_buckets.len() > PRIVATE_RESULT_ORAM_READ_BUCKET_IDS_MAX {
        return Err(StorageError::bad_request(
            "private result ORAM commit updated_buckets exceeds maximum writeback bucket batch size",
        ));
    }
    let mut seen_bucket_ids = HashSet::with_capacity(updated_buckets.len());
    for bucket in updated_buckets {
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(StorageError::bad_request(
                "private result ORAM commit updated_buckets contains duplicate bucket",
            ));
        }
        validate_base64url_32_string(&bucket.ciphertext_sha256, "ciphertext_sha256")?;
        validate_base64url_32_string(&bucket.bucket_commitment, "bucket_commitment")?;
    }
    Ok(())
}

fn validate_upload_bucket_request_shape(
    buckets: &[qdrant_sec::PrivateResultOramBucket],
) -> StorageResult<()> {
    if buckets.is_empty() {
        return Err(StorageError::bad_request(
            "private result ORAM bucket upload must contain at least one bucket",
        ));
    }
    validate_private_result_oram_upload_bucket_count_shape(buckets.len())?;
    let mut seen_bucket_ids = HashSet::with_capacity(buckets.len());
    for bucket in buckets {
        if !seen_bucket_ids.insert(bucket.bucket_id) {
            return Err(StorageError::bad_request(
                "private result ORAM bucket upload contains duplicate bucket",
            ));
        }
        validate_base64url_32_string(&bucket.ciphertext_sha256, "ciphertext_sha256")?;
        validate_base64url_32_string(&bucket.bucket_commitment, "bucket_commitment")?;
    }
    Ok(())
}

fn validate_private_result_oram_upload_bucket_count_shape(
    bucket_count: usize,
) -> StorageResult<()> {
    if bucket_count > PRIVATE_RESULT_ORAM_UPLOAD_BUCKETS_MAX {
        return Err(StorageError::bad_request(
            "private result ORAM bucket upload exceeds maximum bucket batch size",
        ));
    }
    Ok(())
}

fn validate_bucket_read_request_budget(
    manifest: &PrivateResultOramManifest,
    bucket_ids: &[u64],
) -> StorageResult<()> {
    validate_read_bucket_request_shape(bucket_ids)?;
    let path_len_u64 = u64::from(manifest.oram.tree_height)
        .checked_add(1)
        .ok_or_else(|| {
            StorageError::bad_request("private result ORAM read_buckets budget is invalid")
        })?;
    let expected_bucket_ids = u64::from(manifest.oram.path_batch_size)
        .checked_mul(path_len_u64)
        .ok_or_else(|| {
            StorageError::bad_request("private result ORAM read_buckets budget is invalid")
        })?;
    let path_len = usize::try_from(path_len_u64).map_err(|_| {
        StorageError::bad_request("private result ORAM read_buckets budget is invalid")
    })?;
    let actual_bucket_ids = u64::try_from(bucket_ids.len()).map_err(|_| {
        StorageError::bad_request("private result ORAM read_buckets budget is invalid")
    })?;
    if bucket_ids.len() % path_len != 0 {
        return Err(StorageError::bad_request(
            "private result ORAM read_buckets must contain whole ORAM paths",
        ));
    }
    if actual_bucket_ids != expected_bucket_ids {
        return Err(StorageError::bad_request(
            "private result ORAM read_buckets request must match fixed path budget",
        ));
    }
    let mut seen_paths = HashSet::new();
    for path in bucket_ids.chunks(path_len) {
        if !seen_paths.insert(path) {
            return Err(StorageError::bad_request(
                "private result ORAM read_buckets request contains duplicate ORAM path",
            ));
        }
    }
    Ok(())
}

fn validate_bucket_read_request_details(
    manifest: &PrivateResultOramManifest,
    bucket_ids: &[u64],
) -> StorageResult<()> {
    let path_len = usize::try_from(manifest.oram.tree_height)
        .ok()
        .and_then(|height| height.checked_add(1))
        .ok_or_else(|| {
            StorageError::bad_request("private result ORAM read_buckets budget is invalid")
        })?;
    for &bucket_id in bucket_ids {
        if bucket_id >= manifest.bucket_count {
            return Err(StorageError::bad_request(
                "private result ORAM read_buckets bucket id is out of range",
            ));
        }
    }
    for path in bucket_ids.chunks(path_len) {
        validate_bucket_read_path_shape(path)?;
    }
    Ok(())
}

fn validate_bucket_read_path_shape(path: &[u64]) -> StorageResult<()> {
    if path.first().copied() != Some(0) {
        return Err(StorageError::bad_request(
            "private result ORAM read_buckets must contain valid ORAM paths",
        ));
    }
    for window in path.windows(2) {
        let parent = window[0];
        let child = window[1];
        let Some(left_child) = parent.checked_mul(2).and_then(|value| value.checked_add(1)) else {
            return Err(StorageError::bad_request(
                "private result ORAM read_buckets must contain valid ORAM paths",
            ));
        };
        let Some(right_child) = parent.checked_mul(2).and_then(|value| value.checked_add(2)) else {
            return Err(StorageError::bad_request(
                "private result ORAM read_buckets must contain valid ORAM paths",
            ));
        };
        if child != left_child && child != right_child {
            return Err(StorageError::bad_request(
                "private result ORAM read_buckets must contain valid ORAM paths",
            ));
        }
    }
    Ok(())
}

fn validate_base64url_32_string(value: &str, field: &str) -> StorageResult<()> {
    if value.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(StorageError::bad_request(format!(
            "private result ORAM {field} must be a base64url sha256 value"
        )));
    }
    let decoded = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        StorageError::bad_request(format!(
            "private result ORAM {field} must be base64url without padding"
        ))
    })?;
    if decoded.len() != 32 {
        return Err(StorageError::bad_request(format!(
            "private result ORAM {field} must decode to 32 bytes"
        )));
    }
    Ok(())
}

fn private_result_oram_manifest_read_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private result ORAM manifest has not been uploaded")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private result ORAM manifest store validation failed")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private result ORAM manifest store validation failed")
        }
        _ => StorageError::service_error("private result ORAM manifest store validation failed"),
    }
}

fn private_result_oram_manifest_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private result ORAM manifest store is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private result ORAM manifest store validation failed")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private result ORAM manifest store validation failed")
        }
        _ => StorageError::service_error("private result ORAM manifest store validation failed"),
    }
}

fn private_result_oram_epoch_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private result ORAM current epoch is unavailable")
        }
        CollectionError::BadRequest { .. } => {
            StorageError::bad_request("private result ORAM current epoch validation failed")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private result ORAM current epoch validation failed")
        }
        _ => StorageError::service_error("private result ORAM current epoch validation failed"),
    }
}

fn private_result_oram_upload_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private result ORAM encrypted bucket store is unavailable")
        }
        CollectionError::BadRequest { .. } => StorageError::bad_request(
            "private result ORAM encrypted bucket store validation failed",
        ),
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private result ORAM encrypted bucket store validation failed",
        ),
        _ => StorageError::service_error(
            "private result ORAM encrypted bucket store validation failed",
        ),
    }
}

fn private_result_oram_read_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private result ORAM encrypted bucket data is unavailable")
        }
        CollectionError::BadRequest { .. } => StorageError::bad_request(
            "private result ORAM encrypted bucket store validation failed",
        ),
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private result ORAM encrypted bucket store validation failed",
        ),
        _ => StorageError::service_error(
            "private result ORAM encrypted bucket store validation failed",
        ),
    }
}

fn private_result_oram_commit_writeback_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => StorageError::not_found(
            "private result ORAM encrypted bucket store metadata is unavailable",
        ),
        CollectionError::BadRequest { description }
            if description.contains("commit signature verification failed") =>
        {
            StorageError::bad_request("private result ORAM commit signature verification failed")
        }
        CollectionError::BadRequest { description }
            if description.contains("bucket commitment context mismatch") =>
        {
            StorageError::bad_request(
                "private result ORAM commit bucket commitment context mismatch",
            )
        }
        CollectionError::BadRequest { description }
            if description.contains("bucket ciphertext") =>
        {
            StorageError::bad_request("private result ORAM bucket ciphertext validation failed")
        }
        CollectionError::BadRequest { .. } => StorageError::bad_request(
            "private result ORAM encrypted bucket store metadata validation failed",
        ),
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private result ORAM encrypted bucket store metadata validation failed",
        ),
        _ => StorageError::service_error(
            "private result ORAM encrypted bucket store metadata validation failed",
        ),
    }
}

fn private_result_oram_error(err: qdrant_sec::PrivateResultOramError) -> StorageError {
    match err {
        qdrant_sec::PrivateResultOramError::InvalidManifestSignature => {
            StorageError::bad_request("private result ORAM manifest signature verification failed")
        }
        qdrant_sec::PrivateResultOramError::InvalidCommitSignature => {
            StorageError::bad_request("private result ORAM commit signature verification failed")
        }
        qdrant_sec::PrivateResultOramError::InvalidReadBucketsSignature => {
            StorageError::bad_request(
                "private result ORAM read_buckets signature verification failed",
            )
        }
        qdrant_sec::PrivateResultOramError::SignatureKeyIdMismatch => StorageError::bad_request(
            "private result ORAM signature key_id does not match manifest owner_signing_key_id",
        ),
        qdrant_sec::PrivateResultOramError::InvalidBucketHash => {
            StorageError::bad_request("private result ORAM bucket ciphertext validation failed")
        }
        qdrant_sec::PrivateResultOramError::BucketOversized => {
            StorageError::bad_request("private result ORAM bucket ciphertext validation failed")
        }
        _ => StorageError::bad_request("private result ORAM request validation failed"),
    }
}

#[cfg(test)]
mod private_result_oram_tests {
    use collection::config::{CollectionParams, CryptoMigrationState, WalConfig};
    use collection::optimizers_builder::OptimizersConfig;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use segment::types::HnswConfig;
    use serde_json::json;
    use sha2::Digest;
    use uuid::Uuid;

    use super::*;
    use crate::settings::CryptoSettings;

    const SIGNING_KEY_ID: &str = "tenant-a/private-result-signing-v1";

    #[test]
    fn client_id_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_private_result_oram_client_id_shape("tenant-a/sdk.instance_1@host:1").unwrap();

        let oversized = format!(
            "client-id-sentinel{}",
            "x".repeat(PRIVATE_RESULT_ORAM_CLIENT_ID_MAX_LEN)
        );
        let err = validate_private_result_oram_client_id_shape(&oversized).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("client_id must be non-empty and at most 256 bytes"));
        assert!(!rendered.contains("client-id-sentinel"));

        let malformed = "client-id!sentinel";
        let err = validate_private_result_oram_client_id_shape(malformed).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("client_id is invalid"));
        assert!(!rendered.contains(malformed));

        for alias_client_id in [
            "client_state_ciphertext!sentinel",
            "client_state_ciphertext_hash.bin!sentinel",
            "clientStateCiphertextHash!sentinel",
            "encrypted.client.state!sentinel",
            "encrypted_client_state_snapshot!sentinel",
            "encrypted_client_state_ciphertext_hash.bin!sentinel",
            "encrypted_client_state_ciphertext_hash.json!sentinel",
            "oramPositionMapBackup!sentinel",
            "stashBackup.json!sentinel",
            "stashBackups.json!sentinel",
            "state_ciphertext_hashes.bin!sentinel",
            "state_ciphertext_hashes.json!sentinel",
            "tokenMapBackups!sentinel",
            "token_map_backups!sentinel",
            "token_position_map_backups!sentinel",
        ] {
            let err = validate_private_result_oram_client_id_shape(alias_client_id).unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("client_id is invalid"));
            assert!(!rendered.contains(alias_client_id));
        }
    }

    #[test]
    fn session_id_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_private_result_oram_session_id_shape("missing-session-id-sentinel").unwrap();
        validate_private_result_oram_session_id_shape(&uuid::Uuid::new_v4().to_string()).unwrap();

        let oversized = "s".repeat(PRIVATE_RESULT_ORAM_SESSION_ID_MAX_LEN + 1);
        let err = validate_private_result_oram_session_id_shape(&oversized).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session_id is invalid"));
        assert!(!rendered.contains(&oversized));

        let malformed = "bad/session-id";
        let err = validate_private_result_oram_session_id_shape(malformed).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session_id is invalid"));
        assert!(!rendered.contains(malformed));

        for alias_session_id in [
            "stashBackup/session",
            "stashBackup.json/session",
            "stashBackups/session",
            "stashBackups.json/session",
            "clientStateCiphertextHash/session",
            "client_state_ciphertext_hash.bin/session",
            "encrypted.client.state/session",
            "encrypted_client_state_snapshot/session",
            "encrypted_client_state_ciphertext_hash.bin/session",
            "encrypted_client_state_ciphertext_hash.json/session",
            "oramPositionMapBackup/session",
            "state_ciphertext_hashes.bin/session",
            "state_ciphertext_hashes.json/session",
            "tokenMapBackups/session",
            "token_map_backups/session",
            "token_position_map_backups/session",
        ] {
            let err = validate_private_result_oram_session_id_shape(alias_session_id).unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("session_id is invalid"));
            assert!(!rendered.contains(alias_session_id));
        }
    }

    #[test]
    fn private_result_oram_instance_errors_do_not_reflect_rule_or_instance_ids() {
        let rule_id = "private_result_rule_secret_sentinel";
        let instance_id = "private_result_instance_secret_sentinel";
        let rule = EncryptionRuleRef {
            id: rule_id.to_string(),
            selector: EncryptionSelector::PayloadPaths {
                paths: vec!["body".to_string()],
            },
            instance: instance_id.to_string(),
            binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
        };

        let missing_settings = Settings::new(None).unwrap();
        let rendered = private_result_oram_instance(&missing_settings, &rule)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("missing runtime instance"), "{rendered}");
        assert!(!rendered.contains(rule_id), "{rendered}");
        assert!(!rendered.contains(instance_id), "{rendered}");

        let mut wrong_provider_settings = Settings::new(None).unwrap();
        wrong_provider_settings.crypto.instances.insert(
            instance_id.to_string(),
            CryptoInstanceConfig {
                provider: qdrant_sec::VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
                materials: HashMap::new(),
                backend_ref: None,
                options: json!({}),
            },
        );
        let rendered = private_result_oram_instance(&wrong_provider_settings, &rule)
            .unwrap_err()
            .to_string();
        assert!(
            rendered.contains(PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER),
            "{rendered}"
        );
        assert!(!rendered.contains(rule_id), "{rendered}");
        assert!(!rendered.contains(instance_id), "{rendered}");
    }

    #[test]
    fn root_hash_shape_rejects_oversized_or_malformed_values_without_reflecting_value() {
        validate_base64url_32_string(&BASE64URL_NOPAD.encode(&[42; 32]), "root_hash").unwrap();

        let oversized = format!("{}{}", BASE64URL_NOPAD.encode(&[42; 32]), "A");
        let err = validate_base64url_32_string(&oversized, "root_hash").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("root_hash must be a base64url sha256 value"));
        assert!(!rendered.contains(&oversized));

        let mut malformed = BASE64URL_NOPAD.encode(&[42; 32]);
        malformed.replace_range(0..1, "!");
        let err = validate_base64url_32_string(&malformed, "root_hash").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("root_hash must be base64url without padding"));
        assert!(!rendered.contains(&malformed));

        for alias_root_hash in [
            "encrypted.client.state",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "stashBackup.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
        ] {
            let err = validate_base64url_32_string(alias_root_hash, "root_hash").unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("root_hash"));
            assert!(!rendered.contains(alias_root_hash), "{rendered}");
        }
    }

    #[test]
    fn bucket_ciphertext_fixed_size_rejects_volume_drift_without_reflecting_value() {
        let manifest = read_shape_manifest();
        let expected_len = private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap();
        let ciphertext = vec![7; expected_len];
        let mut bucket = qdrant_sec::PrivateResultOramBucket {
            version: 1,
            bucket_id: 0,
            index_epoch: manifest.index_epoch,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256: BASE64URL_NOPAD.encode(&sha2::Sha256::digest(&ciphertext)),
            bucket_commitment: BASE64URL_NOPAD.encode(&[8; 32]),
        };

        validate_bucket_ciphertext_fixed_size(&bucket, &manifest).unwrap();
        validate_private_result_oram_read_bucket_ciphertexts_fixed_size(
            &manifest,
            std::slice::from_ref(&bucket),
        )
        .unwrap();

        let sentinel = b"private-result-fixed-size-sentinel";
        bucket.ciphertext = BASE64URL_NOPAD.encode(sentinel);
        let rendered = validate_bucket_ciphertext_fixed_size(&bucket, &manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("bucket ciphertext validation failed"));
        assert!(!rendered.contains("private-result-fixed-size-sentinel"));
        assert!(!rendered.contains(&bucket.ciphertext));

        let rendered = validate_private_result_oram_read_bucket_ciphertexts_fixed_size(
            &manifest,
            std::slice::from_ref(&bucket),
        )
        .unwrap_err()
        .to_string();
        assert!(rendered.contains("bucket ciphertext validation failed"));
        assert!(!rendered.contains("private-result-fixed-size-sentinel"));
        assert!(!rendered.contains(&bucket.ciphertext));

        let mut oversized_bucket = bucket.clone();
        oversized_bucket.ciphertext = BASE64URL_NOPAD.encode(&ciphertext);
        oversized_bucket
            .ciphertext
            .push_str("private-result-oversized-ciphertext-sentinel");
        let rendered = validate_bucket_ciphertext_fixed_size(&oversized_bucket, &manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("bucket ciphertext validation failed"));
        assert!(!rendered.contains("private-result-oversized-ciphertext-sentinel"));
        assert!(!rendered.contains(&oversized_bucket.ciphertext));
    }

    #[test]
    fn signature_public_key_shape_rejects_values_without_reflecting_value() {
        let valid = BASE64URL_NOPAD.encode(&[7; 32]);
        let instance = instance_with_signature_public_key(&valid);
        assert_eq!(
            signature_public_key(&instance, SIGNING_KEY_ID).unwrap(),
            [7; 32]
        );

        let missing_key_id = "tenant-a/missing-key-sentinel";
        let err = signature_public_key(&instance, missing_key_id).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature key id is not configured"));
        assert!(!rendered.contains(missing_key_id));

        for missing_alias_key_id in [
            "encrypted.client.state",
            "encrypted_client_state_ciphertext_hash",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "encrypted_client_state_ciphertext_sha256",
            "stashBackup.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
        ] {
            let err = signature_public_key(&instance, missing_alias_key_id).unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("signature key id is not configured"));
            assert!(!rendered.contains(missing_alias_key_id), "{rendered}");
        }

        let wrong_len = BASE64URL_NOPAD.encode(&[7; 33]);
        let err = signature_public_key(
            &instance_with_signature_public_key(&wrong_len),
            SIGNING_KEY_ID,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature public key has invalid encoded length"));
        assert!(!rendered.contains(&wrong_len));

        let oversized = format!("{valid}{}", "A".repeat(4096));
        let err = signature_public_key(
            &instance_with_signature_public_key(&oversized),
            SIGNING_KEY_ID,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature public key has invalid encoded length"));
        assert!(!rendered.contains(&oversized));

        let mut malformed = BASE64URL_NOPAD.encode(&[7; 32]);
        malformed.replace_range(0..1, "!");
        let err = signature_public_key(
            &instance_with_signature_public_key(&malformed),
            SIGNING_KEY_ID,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature public key must be base64url without padding"));
        assert!(!rendered.contains(&malformed));
    }

    #[test]
    fn common_debug_redacts_private_result_oram_session_and_read_values() {
        let mut session = fixture_session("result-common-session-sentinel", 20);
        session._client_id = "result-common-client-sentinel".to_string();
        session.collection_id = "result-common-collection-sentinel".to_string();
        session.manifest.collection_id = session.collection_id.clone();
        session.collection_path =
            std::path::PathBuf::from("/tmp/qdrant-private-result-common-path-sentinel");
        let root_hash = session.root_hash.clone();
        let response = session.response();
        let bucket = fixture_readable_bucket(0, session.index_epoch, 21, &root_hash);
        let ciphertext = bucket.ciphertext.clone();
        let read_response = PrivateResultOramReadBucketsResponse {
            index_epoch: session.index_epoch,
            root_hash: root_hash.clone(),
            buckets: vec![bucket],
            proof: PrivateResultOramReadProof {
                kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
                value: "result-common-proof-sentinel".to_string(),
            },
        };

        let rendered = [
            format!("{session:?}"),
            format!("{response:?}"),
            format!("{read_response:?}"),
        ]
        .join("\n");
        let session_debug = format!("{session:?}");
        for leaked_session_value in [
            "PrivateResultOramManifest".to_string(),
            format!("bucket_count: {}", session.bucket_count),
            format!(
                "max_bucket_ciphertext_bytes: {}",
                session.max_bucket_ciphertext_bytes
            ),
        ] {
            assert!(
                !session_debug.contains(&leaked_session_value),
                "{session_debug}"
            );
        }
        let response_debug = format!("{response:?}");
        for leaked_response_value in [
            "PrivateResultOramManifest".to_string(),
            format!("bucket_count: {}", response.manifest.bucket_count),
            format!("tree_height: {}", response.manifest.oram.tree_height),
            format!(
                "path_batch_size: {}",
                response.manifest.oram.path_batch_size
            ),
        ] {
            assert!(
                !response_debug.contains(&leaked_response_value),
                "{response_debug}"
            );
        }
        for leaked in [
            "result-common-session-sentinel",
            "result-common-client-sentinel",
            "result-common-collection-sentinel",
            "qdrant-private-result-common-path-sentinel",
            root_hash.as_str(),
            ciphertext.as_str(),
            "result-common-proof-sentinel",
            "client_state_ciphertext",
            "state_ciphertext_hash",
            "state_ciphertext_sha256",
            "token_map_backup",
            "token_map_backups",
            "token_position_map_backup",
            "token_position_map_backups",
            "payload_fetch_token",
            "stashBackup",
            "stashBackups",
        ] {
            assert!(!rendered.contains(leaked), "{rendered}");
        }
        let read_response_debug = format!("{read_response:?}");
        assert!(
            !read_response_debug.contains("bucket_count: 1"),
            "{read_response_debug}"
        );
    }

    #[test]
    fn signature_shape_errors_do_not_reflect_submitted_values() {
        let unsupported_alg = "rsa-pss-result-signature-sentinel";
        let rendered = private_result_oram_error(
            validate_private_result_oram_manifest_signature_shape(&PrivateResultOramSignature {
                alg: unsupported_alg.to_string(),
                key_id: SIGNING_KEY_ID.to_string(),
                sig: BASE64URL_NOPAD.encode(&[7; 64]),
            })
            .unwrap_err(),
        )
        .to_string();
        assert!(rendered.contains("request validation failed"));
        assert!(!rendered.contains(unsupported_alg), "{rendered}");

        let malformed_key_id = "tenant-a/private-result-signing-v1!sentinel";
        let rendered = private_result_oram_error(
            validate_private_result_oram_manifest_signature_shape(&PrivateResultOramSignature {
                alg: "ed25519".to_string(),
                key_id: malformed_key_id.to_string(),
                sig: BASE64URL_NOPAD.encode(&[7; 64]),
            })
            .unwrap_err(),
        )
        .to_string();
        assert!(rendered.contains("request validation failed"));
        assert!(!rendered.contains(malformed_key_id), "{rendered}");

        for alias_key_id in [
            "encrypted.client.state!sentinel",
            "encrypted_client_state_ciphertext_hash.bin!sentinel",
            "encrypted_client_state_ciphertext_hash.json!sentinel",
            "stashBackup.json!sentinel",
            "state_ciphertext_hashes.bin!sentinel",
            "state_ciphertext_hashes.json!sentinel",
        ] {
            let rendered = private_result_oram_error(
                validate_private_result_oram_manifest_signature_shape(
                    &PrivateResultOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: alias_key_id.to_string(),
                        sig: BASE64URL_NOPAD.encode(&[7; 64]),
                    },
                )
                .unwrap_err(),
            )
            .to_string();
            assert!(rendered.contains("request validation failed"));
            assert!(!rendered.contains(alias_key_id), "{rendered}");
        }

        let oversized_signature = format!("{}{}", BASE64URL_NOPAD.encode(&[7; 64]), "A".repeat(64));
        let rendered = private_result_oram_error(
            validate_private_result_oram_manifest_signature_shape(&PrivateResultOramSignature {
                alg: "ed25519".to_string(),
                key_id: SIGNING_KEY_ID.to_string(),
                sig: oversized_signature.clone(),
            })
            .unwrap_err(),
        )
        .to_string();
        assert!(rendered.contains("request validation failed"));
        assert!(!rendered.contains(&oversized_signature), "{rendered}");

        let mut malformed_signature = BASE64URL_NOPAD.encode(&[7; 64]);
        malformed_signature.replace_range(0..1, "!");
        let rendered = private_result_oram_error(
            validate_private_result_oram_manifest_signature_shape(&PrivateResultOramSignature {
                alg: "ed25519".to_string(),
                key_id: SIGNING_KEY_ID.to_string(),
                sig: malformed_signature.clone(),
            })
            .unwrap_err(),
        )
        .to_string();
        assert!(rendered.contains("request validation failed"));
        assert!(!rendered.contains(&malformed_signature), "{rendered}");

        for alias_signature in [
            "encrypted.client.state",
            "encrypted_client_state_ciphertext_hash.bin",
            "encrypted_client_state_ciphertext_hash.json",
            "stashBackup.json",
            "state_ciphertext_hashes.bin",
            "state_ciphertext_hashes.json",
        ] {
            let rendered = private_result_oram_error(
                validate_private_result_oram_manifest_signature_shape(
                    &PrivateResultOramSignature {
                        alg: "ed25519".to_string(),
                        key_id: SIGNING_KEY_ID.to_string(),
                        sig: alias_signature.to_string(),
                    },
                )
                .unwrap_err(),
            )
            .to_string();
            assert!(rendered.contains("request validation failed"));
            assert!(!rendered.contains(alias_signature), "{rendered}");
        }
    }

    #[test]
    fn manifest_signature_owner_key_preflight_rejects_non_owner_key() {
        let manifest = read_shape_manifest();
        let signature = PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: "tenant-a/private-result-signing-v3".to_string(),
            sig: BASE64URL_NOPAD.encode(&[9; 64]),
        };

        let err = validate_private_result_oram_manifest_signature_owner_key(&manifest, &signature)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("signature key_id does not match manifest owner_signing_key_id"));
        assert!(!rendered.contains(&signature.key_id));
        assert!(!rendered.contains(&manifest.owner_signing_key_id));
        assert!(!rendered.contains("not configured"));
    }

    #[test]
    fn private_result_oram_store_error_mapping_redacts_store_details() {
        let sentinels = [
            "qdrant-sec-private-result-store-detail-sentinel",
            "private_result_oram/buckets/00000000.bucket",
            "private-result-bucket-ciphertext-sentinel",
            "private_result_oram/clientStateSnapshot.json",
            "private_result_oram/clientStateSnapshots.json",
            "private_result_oram/client_state_snapshot.bin",
            "private_result_oram/client_state_snapshot.json",
            "private_result_oram/client_state_snapshots.json",
            "private_result_oram/client_state_ciphertext_hash.bin",
            "private_result_oram/client_state_ciphertext_hash.json",
            "private_result_oram/client_state_ciphertext_hashes.json",
            "private_result_oram/client_state_ciphertext_sha256.bin",
            "private_result_oram/client_state_ciphertext_sha256.json",
            "private_result_oram/client_state_ciphertexts_sha256.bin",
            "private_result_oram/client_state_ciphertexts_sha256.json",
            "private_result_oram/encryptedClientStateSnapshot.json",
            "private_result_oram/encryptedClientStateSnapshots.json",
            "private_result_oram/encrypted_client_state_snapshot.bin",
            "private_result_oram/encrypted_client_state_snapshot.json",
            "private_result_oram/encrypted_client_state_snapshots.json",
            "private_result_oram/encrypted_client_state_ciphertext_hash.json",
            "private_result_oram/encrypted_client_state_ciphertext_hashes.json",
            "private_result_oram/encrypted_client_state_ciphertext_sha256.json",
            "private_result_oram/encrypted_client_state_ciphertexts_sha256.bin",
            "private_result_oram/encrypted_client_state_ciphertexts_sha256.json",
            "private_result_oram/state_ciphertext_hash.json",
            "private_result_oram/state_ciphertext_hashes.json",
            "private_result_oram/state_ciphertext_sha256.json",
            "private_result_oram/stateCiphertextSha256.json",
            "private_result_oram/state_ciphertexts_sha256.bin",
            "private_result_oram/state_ciphertexts_sha256.json",
            "private_result_oram/oramPositionMapBackup.json",
            "private_result_oram/oramPositionMapBackups.json",
            "private_result_oram/oram_position_map_backup.json",
            "private_result_oram/oram_position_map_backups.json",
            "private_result_oram/positionMapBackup.json",
            "private_result_oram/positionMapBackups.json",
            "private_result_oram/position_map_backup.json",
            "private_result_oram/position_map_backups.json",
            "private_result_oram/tokenPositionMapBackup.json",
            "private_result_oram/tokenPositionMapBackups.json",
            "private_result_oram/tokenMapBackup.json",
            "private_result_oram/tokenMapBackups.json",
            "private_result_oram/token_map_backup.json",
            "private_result_oram/token_map_backups.json",
            "private_result_oram/token_position_map_backup.json",
            "private_result_oram/token_position_map_backups.json",
            "private_result_oram/payload_fetch_token.json",
            "private_result_oram/stashBackup.json",
            "private_result_oram/stashBackups.json",
        ];
        for sentinel in sentinels {
            let rendered =
                private_result_oram_manifest_store_error(CollectionError::bad_request(sentinel))
                    .to_string();
            assert!(rendered.contains("manifest store validation failed"));
            assert!(!rendered.contains(sentinel), "{rendered}");

            let rendered =
                private_result_oram_upload_store_error(CollectionError::bad_request(sentinel))
                    .to_string();
            assert!(rendered.contains("encrypted bucket store validation failed"));
            assert!(!rendered.contains(sentinel), "{rendered}");
        }

        let unexpected = || CollectionError::BadInput {
            description: sentinels.join(" "),
        };
        let rendered_errors = [
            private_result_oram_manifest_read_store_error(unexpected()).to_string(),
            private_result_oram_manifest_store_error(unexpected()).to_string(),
            private_result_oram_epoch_store_error(unexpected()).to_string(),
            private_result_oram_upload_store_error(unexpected()).to_string(),
            private_result_oram_read_store_error(unexpected()).to_string(),
            private_result_oram_commit_writeback_store_error(unexpected()).to_string(),
        ];
        for rendered in rendered_errors {
            assert!(rendered.contains("private result ORAM"));
            for sentinel in sentinels {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }
    }

    #[test]
    fn manifest_runtime_policy_rejects_oram_drift_without_reflecting_values() {
        let manifest = read_shape_manifest();
        fixture_runtime_context(&manifest)
            .validate_manifest_runtime_policy(&manifest)
            .unwrap();

        let mut context = fixture_runtime_context(&manifest);
        context.collection_crypto_id = "other-private-result-collection".to_string();
        let rendered = context
            .validate_manifest_runtime_policy(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest collection_id does not match runtime context"));
        assert!(!rendered.contains("other-private-result-collection"));
        assert!(!rendered.contains(&manifest.collection_id));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_key_id = "tenant-a/private-result-rk-next".to_string();
        let rendered = context
            .validate_manifest_runtime_policy(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest key_id does not match runtime instance"));
        assert!(!rendered.contains("private-result-rk-next"));
        assert!(!rendered.contains(&manifest.key_id));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_rk_id = "tenant-a/private-result-rk-next".to_string();
        let rendered = context
            .validate_manifest_runtime_policy(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest rk_id does not match runtime instance"));
        assert!(!rendered.contains("private-result-rk-next"));
        assert!(!rendered.contains(&manifest.rk_id));

        let mut context = fixture_runtime_context(&manifest);
        context.min_rk_epoch = manifest.rk_epoch + 1;
        context.max_rk_epoch = manifest.rk_epoch + 1;
        let rendered = context
            .validate_manifest_runtime_policy(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest rk_epoch does not match runtime instance"));
        assert!(!rendered.contains(&(manifest.rk_epoch + 1).to_string()));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_oram.bucket_size = 99;
        let rendered = context
            .validate_manifest_runtime_policy(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest oram does not match runtime instance"));
        assert!(!rendered.contains("99"));

        let mut context = fixture_runtime_context(&manifest);
        context.expected_oram.tree_height = 99;
        let rendered = context
            .validate_manifest_runtime_policy(&manifest)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("manifest oram does not match runtime instance"));
        assert!(!rendered.contains("99"));
    }

    #[test]
    fn bucket_read_request_preserves_path_shape_and_allows_shared_buckets() {
        let manifest = read_shape_manifest();
        validate_bucket_read_request(&manifest, &[0, 1, 3, 0, 1, 4]).unwrap();
        validate_bucket_read_request_budget(&manifest, &[0, 2, 3, 0, 1, 4]).unwrap();
        validate_bucket_read_request_budget(&manifest, &[0, 1, 7, 0, 1, 4]).unwrap();

        let empty = validate_bucket_read_request(&manifest, &[]).unwrap_err();
        let rendered = empty.to_string();
        assert!(rendered.contains("read_buckets request is empty"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_result_oram"));

        let deduped = validate_bucket_read_request(&manifest, &[0, 1, 3, 4]).unwrap_err();
        let rendered = deduped.to_string();
        assert!(rendered.contains("whole ORAM paths"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains("4"), "{rendered}");

        let under_budget = validate_bucket_read_request(&manifest, &[0, 1, 3]).unwrap_err();
        let rendered = under_budget.to_string();
        assert!(rendered.contains("fixed path budget"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains("3"), "{rendered}");

        let sentinel_bucket_id = 987_654_321_u64;
        let under_budget_with_sentinel =
            validate_bucket_read_request(&manifest, &[0, 1, sentinel_bucket_id]).unwrap_err();
        let rendered = under_budget_with_sentinel.to_string();
        assert!(rendered.contains("fixed path budget"));
        assert!(
            !rendered.contains(&sentinel_bucket_id.to_string()),
            "{rendered}"
        );

        let duplicate_path =
            validate_bucket_read_request(&manifest, &[0, 1, 3, 0, 1, 3]).unwrap_err();
        let rendered = duplicate_path.to_string();
        assert!(rendered.contains("duplicate ORAM path"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains("3"), "{rendered}");

        let duplicate_path_with_sentinel = validate_bucket_read_request(
            &manifest,
            &[0, 1, sentinel_bucket_id, 0, 1, sentinel_bucket_id],
        )
        .unwrap_err();
        let rendered = duplicate_path_with_sentinel.to_string();
        assert!(rendered.contains("duplicate ORAM path"));
        assert!(
            !rendered.contains(&sentinel_bucket_id.to_string()),
            "{rendered}"
        );

        let malformed_path =
            validate_bucket_read_request(&manifest, &[0, 2, 3, 0, 1, 4]).unwrap_err();
        let rendered = malformed_path.to_string();
        assert!(rendered.contains("valid ORAM paths"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains("2"), "{rendered}");
        assert!(!rendered.contains("3"), "{rendered}");

        let over_budget =
            validate_bucket_read_request(&manifest, &[0, 1, 3, 0, 1, 4, 0, 2, 5]).unwrap_err();
        let rendered = over_budget.to_string();
        assert!(rendered.contains("fixed path budget"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains("5"), "{rendered}");

        let out_of_range =
            validate_bucket_read_request(&manifest, &[0, 1, 7, 0, 1, 4]).unwrap_err();
        let rendered = out_of_range.to_string();
        assert!(rendered.contains("out of range"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains("7"), "{rendered}");
    }

    #[test]
    fn bucket_read_request_shape_rejects_empty_before_session_lookup() {
        validate_read_bucket_request_shape(&[0]).unwrap();

        let err = validate_read_bucket_request_shape(&[]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("read_buckets request is empty"));
        assert!(!rendered.contains("session is missing or expired"));
    }

    #[test]
    fn bucket_read_request_shape_rejects_oversized_batch_before_session_lookup() {
        let bucket_ids = vec![0; PRIVATE_RESULT_ORAM_READ_BUCKET_IDS_MAX + 1];

        let err = validate_read_bucket_request_shape(&bucket_ids).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("maximum bucket batch size"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(
            !rendered.contains(&(bucket_ids.len()).to_string()),
            "{rendered}"
        );
    }

    #[test]
    fn commit_bucket_request_shape_rejects_empty_before_session_lookup() {
        let updated_bucket = fixture_readable_bucket(0, 43, 7, &BASE64URL_NOPAD.encode(&[8; 32]));
        validate_commit_bucket_request_shape(std::slice::from_ref(&updated_bucket)).unwrap();

        let err = validate_commit_bucket_request_shape(&[]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("commit updated_buckets must contain"));
        assert!(!rendered.contains("session is missing or expired"));
    }

    #[test]
    fn commit_bucket_request_shape_rejects_oversized_writeback_before_session_lookup() {
        let commitment = BASE64URL_NOPAD.encode(&[8; 32]);
        let buckets = (0..=PRIVATE_RESULT_ORAM_READ_BUCKET_IDS_MAX)
            .map(|bucket_id| fixture_readable_bucket(bucket_id as u64, 43, 7, &commitment))
            .collect::<Vec<_>>();

        let err = validate_commit_bucket_request_shape(&buckets).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("maximum writeback bucket batch size"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains(&buckets[0].ciphertext), "{rendered}");
        assert!(!rendered.contains(&buckets.len().to_string()), "{rendered}");
    }

    #[test]
    fn commit_bucket_request_shape_rejects_duplicate_bucket_before_session_lookup() {
        let bucket = fixture_readable_bucket(0, 43, 7, &BASE64URL_NOPAD.encode(&[8; 32]));
        let duplicate = vec![bucket.clone(), bucket];

        let err = validate_commit_bucket_request_shape(&duplicate).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("duplicate bucket"));
        assert!(!rendered.contains("session is missing or expired"));
        assert!(!rendered.contains(&duplicate[0].ciphertext), "{rendered}");
    }

    #[test]
    fn commit_bucket_request_shape_rejects_malformed_bucket_hash_before_session_lookup() {
        let mut bucket = fixture_readable_bucket(0, 43, 7, &BASE64URL_NOPAD.encode(&[8; 32]));
        let sentinel = "result-commit-hash-sentinel";
        bucket.ciphertext_sha256 = sentinel.to_string();

        let err = validate_commit_bucket_request_shape(std::slice::from_ref(&bucket)).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("ciphertext_sha256"), "{rendered}");
        assert!(
            !rendered.contains("session is missing or expired"),
            "{rendered}"
        );
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn commit_bucket_request_shape_rejects_malformed_bucket_commitment_before_session_lookup() {
        let mut bucket = fixture_readable_bucket(0, 43, 7, &BASE64URL_NOPAD.encode(&[8; 32]));
        let sentinel = "result-commit-commitment-sentinel";
        bucket.bucket_commitment = sentinel.to_string();

        let err = validate_commit_bucket_request_shape(std::slice::from_ref(&bucket)).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket_commitment"), "{rendered}");
        assert!(
            !rendered.contains("session is missing or expired"),
            "{rendered}"
        );
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn upload_bucket_request_shape_rejects_empty_bucket_set_before_store_lookup() {
        let bucket = fixture_readable_bucket(0, 42, 7, &BASE64URL_NOPAD.encode(&[8; 32]));
        validate_upload_bucket_request_shape(std::slice::from_ref(&bucket)).unwrap();

        let err = validate_upload_bucket_request_shape(&[]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket upload must contain"));
        assert!(!rendered.contains("manifest"));
        assert!(!rendered.contains("private_result_oram"));
    }

    #[test]
    fn upload_bucket_request_shape_static_limit_matches_max_runtime_tree_height() {
        validate_private_result_oram_upload_bucket_count_shape(
            PRIVATE_RESULT_ORAM_UPLOAD_BUCKETS_MAX,
        )
        .unwrap();

        let err = validate_private_result_oram_upload_bucket_count_shape(
            PRIVATE_RESULT_ORAM_UPLOAD_BUCKETS_MAX + 1,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("maximum bucket batch size"));
        assert!(!rendered.contains(&(PRIVATE_RESULT_ORAM_UPLOAD_BUCKETS_MAX + 1).to_string()));
        assert!(!rendered.contains("private_result_oram"));
    }

    #[test]
    fn upload_bucket_request_shape_rejects_duplicate_bucket_before_store_lookup() {
        let bucket = fixture_readable_bucket(0, 42, 7, &BASE64URL_NOPAD.encode(&[8; 32]));
        let duplicate = vec![bucket.clone(), bucket];

        let err = validate_upload_bucket_request_shape(&duplicate).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("duplicate bucket"));
        assert!(!rendered.contains("manifest"));
        assert!(!rendered.contains("private_result_oram"));
        assert!(!rendered.contains(&duplicate[0].ciphertext));
    }

    #[test]
    fn upload_bucket_request_shape_rejects_malformed_bucket_hash_before_store_lookup() {
        let mut bucket = fixture_readable_bucket(0, 42, 7, &BASE64URL_NOPAD.encode(&[8; 32]));
        let sentinel = "result-upload-hash-sentinel";
        bucket.ciphertext_sha256 = sentinel.to_string();

        let err = validate_upload_bucket_request_shape(std::slice::from_ref(&bucket)).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("ciphertext_sha256"), "{rendered}");
        assert!(!rendered.contains("manifest"), "{rendered}");
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn upload_bucket_request_shape_rejects_malformed_bucket_commitment_before_store_lookup() {
        let mut bucket = fixture_readable_bucket(0, 42, 7, &BASE64URL_NOPAD.encode(&[8; 32]));
        let sentinel = "result-upload-commitment-sentinel";
        bucket.bucket_commitment = sentinel.to_string();

        let err = validate_upload_bucket_request_shape(std::slice::from_ref(&bucket)).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("bucket_commitment"), "{rendered}");
        assert!(!rendered.contains("manifest"), "{rendered}");
        assert!(!rendered.contains("private_result_oram"), "{rendered}");
        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(!rendered.contains(&bucket.ciphertext), "{rendered}");
    }

    #[test]
    fn commit_writeback_budget_is_capped_to_fixed_path_batch() {
        let mut session = fixture_session("session-1", 20);
        session.manifest.oram.path_batch_size = 1;

        let max_updated_buckets = max_updated_bucket_count(&session).unwrap();
        assert_eq!(max_updated_buckets, 3);
        assert!(
            max_updated_buckets < usize::try_from(session.bucket_count).unwrap(),
            "writeback budget must not expand to the full ORAM bucket count",
        );
    }

    #[test]
    fn session_lease_expiry_fails_closed_on_overflow() {
        assert_eq!(
            session_lease_expires_unix(10).unwrap(),
            10 + SESSION_LEASE_SECS
        );
        let err = session_lease_expires_unix(u64::MAX).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lease calculation overflowed"));
        assert!(!rendered.contains(&u64::MAX.to_string()), "{rendered}");
    }

    #[test]
    fn distributed_epoch_operations_require_consensus_backed_cas() {
        assert!(validate_private_result_oram_single_node_epoch_mode(false).is_ok());

        let err = validate_private_result_oram_single_node_epoch_mode(true).unwrap_err();
        assert!(err.to_string().contains("consensus-backed epoch/root CAS"));
    }

    #[test]
    fn session_registry_enforces_single_writer_and_expiration() {
        let now = 10;
        let expired_at = 20;
        let mut registry = PrivateResultOramSessionRegistry::default();
        let session = fixture_session("session-1", expired_at);

        registry.open(session.clone(), now).unwrap();
        assert!(registry.has_active_collection("collection-private-result-test", now));
        assert!(!registry.has_active_collection("other-collection", now));

        let err = registry
            .open(
                PrivateResultOramSession {
                    session_id: "session-2".to_string(),
                    ..session
                },
                now,
            )
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("ConcurrentWriter"));
        assert_private_result_registry_error_redacts_ids(&rendered);

        let err = registry
            .with_session_mut(
                "collection-private-result-test",
                "session-1",
                expired_at,
                |_| Ok(()),
            )
            .unwrap_err();
        assert!(err.to_string().contains("session is missing or expired"));
        assert!(!registry.has_active_collection("collection-private-result-test", expired_at));
        assert!(!registry.close("collection-private-result-test", "session-1", expired_at));

        registry
            .open(fixture_session("session-2", expired_at + 10), expired_at)
            .unwrap();
        assert!(registry.has_active_collection("collection-private-result-test", expired_at,));
        assert!(registry.close("collection-private-result-test", "session-2", expired_at,));
    }

    #[test]
    fn session_registry_rejects_full_registry_without_reflecting_values() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        for index in 0..MAX_SESSION_COUNT {
            let mut session = fixture_session(&format!("capacity-session-{index}"), 20);
            session.collection_id = format!("capacity-collection-{index}");
            session.manifest.collection_id = session.collection_id.clone();
            registry.open(session, now).unwrap();
        }

        let mut overflow = fixture_session("capacity-overflow-session-sentinel", 20);
        overflow.collection_id = "capacity-overflow-collection-sentinel".to_string();
        overflow.manifest.collection_id = overflow.collection_id.clone();
        let rendered = registry.open(overflow, now).unwrap_err().to_string();
        assert!(rendered.contains("session registry is full"));
        for sentinel in [
            "capacity-overflow-session-sentinel",
            "capacity-overflow-collection-sentinel",
        ] {
            assert!(!rendered.contains(sentinel), "{rendered}");
        }

        let mut replacement = fixture_session("capacity-replacement-session", 30);
        replacement.collection_id = "capacity-replacement-collection".to_string();
        replacement.manifest.collection_id = replacement.collection_id.clone();
        registry.open(replacement, 20).unwrap();
        assert_eq!(registry.sessions.len(), 1);
        assert_eq!(registry.active_writer_by_collection.len(), 1);
        assert!(registry.has_active_collection("capacity-replacement-collection", 20));
    }

    #[test]
    fn session_registry_keeps_writer_lock_after_failed_action() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        let err = registry
            .with_session_mut(
                "collection-private-result-test",
                "session-1",
                now,
                |_| -> StorageResult<()> {
                    Err(StorageError::bad_request("synthetic failed session action"))
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("synthetic failed session action"));
        assert!(registry.has_active_collection("collection-private-result-test", now));

        let err = registry
            .open(fixture_session("session-2", 20), now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("ConcurrentWriter"));
        assert_private_result_registry_error_redacts_ids(&rendered);

        assert!(registry.close("collection-private-result-test", "session-1", now,));
        registry
            .open(fixture_session("session-2", 20), now)
            .unwrap();
    }

    #[test]
    fn session_registry_requires_writer_lock_for_session_action() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        registry.active_writer_by_collection.insert(
            "collection-private-result-test".to_string(),
            "session-2".to_string(),
        );
        let err = registry
            .with_session_mut(
                "collection-private-result-test",
                "session-1",
                now,
                |_| -> StorageResult<()> {
                    panic!("private result ORAM action must not run without the writer lock")
                },
            )
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("writer lock is missing or stale"));
        assert_private_result_registry_error_redacts_ids(&rendered);

        registry
            .active_writer_by_collection
            .remove("collection-private-result-test");
        let err = registry
            .with_session_mut(
                "collection-private-result-test",
                "session-1",
                now,
                |_| -> StorageResult<()> {
                    panic!("private result ORAM action must not run with a missing writer lock")
                },
            )
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("writer lock is missing or stale"));
        assert_private_result_registry_error_redacts_ids(&rendered);
    }

    #[test]
    fn session_registry_close_requires_matching_writer_lock() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        registry.active_writer_by_collection.insert(
            "collection-private-result-test".to_string(),
            "session-2".to_string(),
        );
        assert!(!registry.close("collection-private-result-test", "session-1", now));
        assert!(registry.sessions.contains_key("session-1"));
        assert_eq!(
            registry
                .active_writer_by_collection
                .get("collection-private-result-test"),
            Some(&"session-2".to_string())
        );

        registry
            .active_writer_by_collection
            .remove("collection-private-result-test");
        assert!(!registry.close("collection-private-result-test", "session-1", now));
        assert!(registry.sessions.contains_key("session-1"));
        assert!(
            !registry
                .active_writer_by_collection
                .contains_key("collection-private-result-test")
        );
    }

    #[test]
    fn session_registry_wrong_close_keeps_writer_lock() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        assert!(!registry.close("other-collection", "session-1", now));
        assert!(registry.has_active_collection("collection-private-result-test", now));

        let err = registry
            .open(fixture_session("session-2", 20), now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("ConcurrentWriter"));
        assert_private_result_registry_error_redacts_ids(&rendered);

        assert!(registry.close("collection-private-result-test", "session-1", now,));
        assert!(!registry.has_active_collection("collection-private-result-test", now));
    }

    #[test]
    fn session_registry_blocks_snapshot_and_upload_windows() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();

        registry
            .begin_collection_snapshot("collection-private-result-test", now)
            .unwrap();
        let err = registry
            .open(fixture_session("session-1", 20), now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session open requires no active collection snapshot"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        let err = ensure_private_result_oram_write_window_in_registry(
            &mut registry,
            "collection-private-result-test",
            now,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active collection snapshot"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        registry.release_collection_snapshot("collection-private-result-test");

        registry
            .begin_upload("collection-private-result-test", now)
            .unwrap();
        let err = registry
            .open(fixture_session("session-1", 20), now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session open requires no active upload"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        let err = registry
            .begin_collection_snapshot("collection-private-result-test", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("snapshot requires no active private ORAM upload"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        registry.release_upload("collection-private-result-test");

        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();
        assert!(
            ensure_no_active_private_result_oram_collection_session_in_registry(
                &mut registry,
                "collection-private-result-test-suffix",
                now,
            )
            .is_ok()
        );
        assert!(
            ensure_private_result_oram_write_window_in_registry(
                &mut registry,
                "collection-private-result-test-suffix",
                now,
            )
            .is_ok()
        );
        let err = ensure_private_result_oram_write_window_in_registry(
            &mut registry,
            "collection-private-result-test",
            now,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active session"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        assert!(registry.close("collection-private-result-test", "session-1", now,));

        registry
            .begin_collection_snapshot("collection-private-result-test", now)
            .unwrap();
        registry.release_collection_snapshot("collection-private-result-test");
        registry
            .begin_upload("collection-private-result-test", now)
            .unwrap();
        registry.release_upload("collection-private-result-test");
    }

    #[test]
    fn collection_lifecycle_guard_rejects_active_collection_session() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .open(fixture_session("session-1", 20), now)
            .unwrap();

        let err = registry
            .begin_collection_lifecycle_operation("collection-private-result-test", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lifecycle operation requires no active private ORAM session"));
        assert!(!rendered.contains("collection snapshot requires"));
        assert_private_result_registry_error_redacts_ids(&rendered);

        assert!(
            registry
                .begin_collection_lifecycle_operation("other-private-result-collection", now)
                .is_ok()
        );
        registry.release_collection_lifecycle_operation("other-private-result-collection");
    }

    #[test]
    fn session_registry_blocks_snapshot_during_collection_lifecycle() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .begin_collection_lifecycle_operation("collection-private-result-test", now)
            .unwrap();

        let err = registry
            .begin_collection_snapshot("collection-private-result-test", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("snapshot requires no active collection lifecycle operation"));
        assert_private_result_registry_error_redacts_ids(&rendered);

        let err = registry
            .open(fixture_session("session-1", 20), now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("session open requires no active collection lifecycle operation")
        );
        assert_private_result_registry_error_redacts_ids(&rendered);

        let err = ensure_private_result_oram_write_window_in_registry(
            &mut registry,
            "collection-private-result-test",
            now,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active collection lifecycle operation"));
        assert_private_result_registry_error_redacts_ids(&rendered);

        registry.release_collection_lifecycle_operation("collection-private-result-test");
        registry
            .begin_collection_snapshot("collection-private-result-test", now)
            .unwrap();
        registry.release_collection_snapshot("collection-private-result-test");
    }

    #[test]
    fn collection_lifecycle_guard_rejects_active_collection_snapshot() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .begin_collection_snapshot("collection-private-result-test", now)
            .unwrap();

        let err = registry
            .begin_collection_lifecycle_operation("collection-private-result-test", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lifecycle operation requires no active collection snapshot"));
        assert_private_result_registry_error_redacts_ids(&rendered);

        registry.release_collection_snapshot("collection-private-result-test");
        registry
            .begin_collection_lifecycle_operation("collection-private-result-test", now)
            .unwrap();
        registry.release_collection_lifecycle_operation("collection-private-result-test");
    }

    #[test]
    fn collection_snapshot_guard_uses_exact_private_result_upload_collection() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .begin_upload("collection-private-result-test-suffix", now)
            .unwrap();

        registry
            .begin_collection_snapshot("collection-private-result-test", now)
            .unwrap();
        registry.release_collection_snapshot("collection-private-result-test");

        let err = registry
            .begin_collection_snapshot("collection-private-result-test-suffix", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("snapshot requires no active private ORAM upload"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        assert!(
            !rendered.contains("collection-private-result-test-suffix"),
            "{rendered}"
        );
    }

    #[test]
    fn upload_write_window_rejects_collection_lifecycle() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .begin_upload("collection-private-result-test", now)
            .unwrap();

        let err = registry
            .begin_collection_lifecycle_operation("collection-private-result-test", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lifecycle operation requires no active private ORAM upload"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        registry
            .begin_collection_lifecycle_operation("other-private-result-collection", now)
            .unwrap();
        registry.release_collection_lifecycle_operation("other-private-result-collection");

        registry.release_upload("collection-private-result-test");
        registry
            .begin_collection_lifecycle_operation("collection-private-result-test", now)
            .unwrap();
    }

    #[test]
    fn collection_lifecycle_guard_uses_exact_private_result_upload_collection() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .begin_upload("collection-private-result-test-suffix", now)
            .unwrap();

        registry
            .begin_collection_lifecycle_operation("collection-private-result-test", now)
            .unwrap();
        registry.release_collection_lifecycle_operation("collection-private-result-test");

        let err = registry
            .begin_collection_lifecycle_operation("collection-private-result-test-suffix", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("lifecycle operation requires no active private ORAM upload"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        assert!(
            !rendered.contains("collection-private-result-test-suffix"),
            "{rendered}"
        );
    }

    #[test]
    fn upload_write_window_uses_exact_private_result_collection() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();

        registry
            .begin_upload("collection-private-result-test-suffix", now)
            .unwrap();
        ensure_private_result_oram_write_window_in_registry(
            &mut registry,
            "collection-private-result-test",
            now,
        )
        .unwrap();
        registry
            .begin_upload("collection-private-result-test", now)
            .unwrap();

        let err = registry
            .begin_upload("collection-private-result-test", now)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active upload"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        assert!(
            !rendered.contains("collection-private-result-test"),
            "{rendered}"
        );

        registry.release_upload("collection-private-result-test");
        registry.release_upload("collection-private-result-test-suffix");

        registry
            .begin_collection_snapshot("collection-private-result-test-suffix", now)
            .unwrap();
        ensure_private_result_oram_write_window_in_registry(
            &mut registry,
            "collection-private-result-test",
            now,
        )
        .unwrap();
        registry.release_collection_snapshot("collection-private-result-test-suffix");

        registry
            .begin_collection_snapshot("collection-private-result-test", now)
            .unwrap();
        let err = ensure_private_result_oram_write_window_in_registry(
            &mut registry,
            "collection-private-result-test",
            now,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("upload requires no active collection snapshot"));
        assert_private_result_registry_error_redacts_ids(&rendered);
        assert!(
            !rendered.contains("collection-private-result-test"),
            "{rendered}"
        );
    }

    #[test]
    fn session_registry_snapshot_refcounts_and_upload_marker_cleanup_fail_closed() {
        let now = 10;
        let mut registry = PrivateResultOramSessionRegistry::default();
        registry
            .active_snapshot_by_collection
            .insert("collection-private-result-test".to_string(), usize::MAX);
        let err = registry
            .begin_collection_snapshot("collection-private-result-test", now)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("snapshot reference count overflowed")
        );

        registry
            .active_snapshot_by_collection
            .insert("collection-private-result-test".to_string(), 0);
        registry.release_collection_snapshot("collection-private-result-test");
        assert!(
            !registry
                .active_snapshot_by_collection
                .contains_key("collection-private-result-test")
        );

        registry
            .active_upload_by_collection
            .insert("collection-private-result-test".to_string());
        registry.release_upload("collection-private-result-test");
        assert!(
            !registry
                .active_upload_by_collection
                .contains("collection-private-result-test")
        );
    }

    #[test]
    fn recovered_snapshot_signature_preflight_verifies_manifest_signature() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-recovered-signature")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let mut manifest = recovered_snapshot_manifest();
        manifest.collection_id = uuid.to_string();
        let leaf_commitments = recovered_snapshot_leaf_commitments(manifest.bucket_count, 43);
        manifest.root_hash =
            PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap();
        let signature = qdrant_sec::sign_private_result_oram_manifest(&key_pair, &manifest)
            .expect("fixture manifest should sign");
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let config = recovered_snapshot_config(uuid);
        let store = PrivateResultOramStore::new(temp_dir.path());
        store.write_manifest(&manifest, &signature).unwrap();
        install_recovered_private_result_oram_snapshot_storage(&store, &manifest, leaf_commitments);

        validate_recovered_private_result_oram_snapshot_signatures(
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
        let err = validate_recovered_private_result_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("manifest signature verification failed"));
        assert!(!rendered.contains(&tampered_signature.sig));
        assert!(!rendered.contains(&manifest.root_hash));
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_BINDING));

        let mut mismatched_manifest = manifest.clone();
        mismatched_manifest.root_hash = BASE64URL_NOPAD.encode(&[88; 32]);
        let mismatched_signature =
            qdrant_sec::sign_private_result_oram_manifest(&key_pair, &mismatched_manifest)
                .expect("fixture manifest should sign");
        store
            .write_manifest(&mismatched_manifest, &mismatched_signature)
            .unwrap();
        let err = validate_recovered_private_result_oram_snapshot_signatures(
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
        assert!(!rendered.contains(PRIVATE_RESULT_ORAM_BINDING));
    }

    #[test]
    fn recovered_snapshot_signature_preflight_validates_runtime_key_epoch_pinning() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-recovered-runtime")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let manifest = recovered_snapshot_manifest();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap();
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let mut config = recovered_snapshot_config(uuid);
        let encryption = config.params.encryption.as_mut().unwrap();
        encryption.key_id = Some("tenant-a/other-private-result-rk".to_string());

        let err = validate_recovered_private_result_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("private result ORAM key_id must match collection key_id"),
            "{rendered}"
        );
        assert!(!rendered.contains("tenant-a/other-private-result-rk"));
        assert!(!rendered.contains(&manifest.key_id));
        assert!(!rendered.contains("manifest has not been uploaded"));
    }

    #[test]
    fn recovered_snapshot_signature_preflight_rejects_wrong_selector_without_rule_details() {
        let temp_dir = tempfile::Builder::new()
            .prefix("private-result-recovered-wrong-selector")
            .tempdir()
            .unwrap();
        let uuid = Uuid::from_u128(7);
        let manifest = recovered_snapshot_manifest();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap();
        let settings = recovered_snapshot_settings(&manifest, key_pair.public_key().as_ref());
        let mut config = recovered_snapshot_config(uuid);
        let encryption = config.params.encryption.as_mut().unwrap();
        encryption.rules[0].id = "private_result_restore_secret_rule".to_string();
        encryption.rules[0].selector = EncryptionSelector::VectorNames {
            names: vec!["private-result-secret-vector".to_string()],
        };

        let err = validate_recovered_private_result_oram_snapshot_signatures(
            &settings,
            "docs",
            &config,
            temp_dir.path(),
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("payload_paths selector"), "{rendered}");
        assert!(!rendered.contains("private_result_restore_secret_rule"));
        assert!(!rendered.contains("private-result-secret-vector"));
        assert!(!rendered.contains("manifest has not been uploaded"));
    }

    fn recovered_snapshot_leaf_commitments(bucket_count: u64, domain: u8) -> Vec<String> {
        (0..bucket_count)
            .map(|bucket_id| {
                let mut bytes = [domain; 32];
                bytes[..8].copy_from_slice(&bucket_id.to_be_bytes());
                let leaf_commitment = BASE64URL_NOPAD.encode(&bytes);
                leaf_commitment
            })
            .collect()
    }

    fn install_recovered_private_result_oram_snapshot_storage(
        store: &PrivateResultOramStore,
        manifest: &PrivateResultOramManifest,
        leaf_commitments: Vec<String>,
    ) {
        store
            .write_initial_epoch(&PrivateResultOramEpochState {
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
                    max_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
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
            PrivateResultOramStore::merkle_root_for_commitments(&leaf_commitments).unwrap();
        session.bucket_count = bucket_count;
        session.root_hash = root_hash.clone();
        session.manifest.bucket_count = bucket_count;
        session.manifest.root_hash = root_hash;
        let expected_epoch = PrivateResultOramEpochState {
            index_epoch: session.index_epoch,
            root_hash: session.root_hash.clone(),
        };
        let signature = fixture_signature();

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateResultOramStore::new(temp.path());
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
        ensure_private_result_oram_restored_snapshot_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap();

        for missing_bucket_id in [0_u64, 1, bucket_count - 1] {
            let temp = tempfile::TempDir::new().unwrap();
            let store = PrivateResultOramStore::new(temp.path());
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
                if bucket_id as u64 == missing_bucket_id {
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
            let err = ensure_private_result_oram_restored_snapshot_storage_matches(
                &store,
                &expected_epoch,
                &session.manifest,
                &signature,
            )
            .unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains("encrypted bucket data is unavailable"));
            assert!(!rendered.contains(&format!("{missing_bucket_id:08}.bucket")));
            assert!(!rendered.contains(&expected_epoch.root_hash));
        }
    }

    fn read_shape_manifest() -> PrivateResultOramManifest {
        PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: "collection-private-result-test".to_string(),
            key_id: "tenant-a/private-result-rk".to_string(),
            rk_id: "tenant-a/private-result-rk".to_string(),
            rk_epoch: 7,
            oram: OramParams {
                kind: qdrant_sec::OramKind::PathOram,
                bucket_size: 2,
                block_size_bytes: 128,
                tree_height: 2,
                path_batch_size: 2,
            },
            index_epoch: 42,
            root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
            bucket_count: 7,
            logical_result_count: 2,
            dummy_result_count: 0,
            owner_signing_key_id: SIGNING_KEY_ID.to_string(),
            created_at_unix: 1_700_000_000,
        }
    }

    fn fixture_signature() -> PrivateResultOramSignature {
        PrivateResultOramSignature {
            alg: "ed25519".to_string(),
            key_id: SIGNING_KEY_ID.to_string(),
            sig: BASE64URL_NOPAD.encode(&[7; 64]),
        }
    }

    fn fixture_readable_bucket(
        bucket_id: u64,
        epoch: u64,
        domain: u8,
        bucket_commitment: &str,
    ) -> qdrant_sec::PrivateResultOramBucket {
        let ciphertext = vec![domain, bucket_id as u8];
        let ciphertext_sha256 = BASE64URL_NOPAD.encode(sha2::Sha256::digest(&ciphertext).as_ref());
        qdrant_sec::PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            ciphertext_sha256,
            bucket_commitment: bucket_commitment.to_string(),
        }
    }

    #[test]
    fn active_session_current_epoch_preflight_rejects_stale_store_epoch() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateResultOramStore::new(temp.path());
        let old_root_hash = BASE64URL_NOPAD.encode(&[42; 32]);
        let old = PrivateResultOramEpochState {
            index_epoch: 42,
            root_hash: old_root_hash.clone(),
        };
        let stale_current = PrivateResultOramEpochState {
            index_epoch: 43,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
        };

        store.write_initial_epoch(&old).unwrap();
        store.compare_and_swap_epoch(&old, &stale_current).unwrap();

        let err = ensure_private_result_oram_active_session_current_epoch(
            &store,
            old.index_epoch,
            &old.root_hash,
        )
        .unwrap_err()
        .to_string();

        for operation in [
            "commit",
            "read_buckets",
            "private-result-operation-sentinel",
        ] {
            assert!(err.contains("current epoch/root does not match active session"));
            assert!(!err.contains(operation), "{err}");
            assert!(!err.contains("42"), "{err}");
            assert!(!err.contains("43"), "{err}");
            assert!(!err.contains(&old.root_hash), "{err}");
            assert!(!err.contains(&stale_current.root_hash), "{err}");
        }
    }

    #[test]
    fn read_proof_bucket_commitment_mismatch_rejects_without_ciphertext_leak() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateResultOramStore::new(temp.path());
        let bucket_commitment = BASE64URL_NOPAD.encode(&[7; 32]);
        let bucket = fixture_readable_bucket(0, 42, 11, &bucket_commitment);
        let root = PrivateResultOramStore::merkle_root_for_commitments(&[bucket
            .bucket_commitment
            .clone()])
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

        let err = ensure_private_result_oram_read_proof_matches_buckets(&proof, &[bucket.clone()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("bucket/proof consistency validation failed"));
        assert!(!err.contains(&bucket.ciphertext));
        assert!(!err.contains(&bucket.bucket_commitment));
    }

    #[test]
    fn session_open_storage_recheck_rejects_manifest_or_epoch_drift() {
        let mut session = fixture_session("session-1", 20);
        session.bucket_count = 1;
        session.manifest.bucket_count = 1;
        let expected_epoch = PrivateResultOramEpochState {
            index_epoch: session.index_epoch,
            root_hash: session.root_hash.clone(),
        };
        let signature = fixture_signature();

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateResultOramStore::new(temp.path());
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
        ensure_private_result_oram_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap();

        let stale_epoch = PrivateResultOramEpochState {
            index_epoch: session.index_epoch + 1,
            root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
        };
        store
            .compare_and_swap_epoch(&expected_epoch, &stale_epoch)
            .unwrap();
        let err = ensure_private_result_oram_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session open observed concurrent manifest or epoch update"));
        assert!(!rendered.contains(&stale_epoch.root_hash));
        assert!(!rendered.contains(&expected_epoch.root_hash));

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateResultOramStore::new(temp.path());
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
        changed_manifest.logical_result_count += 1;
        store.write_manifest(&changed_manifest, &signature).unwrap();
        let err = ensure_private_result_oram_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("session open observed concurrent manifest or epoch update"));
        assert!(!rendered.contains(&expected_epoch.root_hash));
        assert!(!rendered.contains(&signature.sig));

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateResultOramStore::new(temp.path());
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        let err = ensure_private_result_oram_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("encrypted bucket data is unavailable"));
        assert!(!rendered.contains(&expected_epoch.root_hash));

        let temp = tempfile::TempDir::new().unwrap();
        let store = PrivateResultOramStore::new(temp.path());
        store.write_initial_epoch(&expected_epoch).unwrap();
        store.write_manifest(&session.manifest, &signature).unwrap();
        store
            .write_merkle_tree_from_commitments(
                expected_epoch.index_epoch,
                expected_epoch.root_hash.clone(),
                vec![expected_epoch.root_hash.clone()],
            )
            .unwrap();
        let err = ensure_private_result_oram_session_open_storage_matches(
            &store,
            &expected_epoch,
            &session.manifest,
            &signature,
        )
        .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("encrypted bucket data is unavailable"));
        assert!(!rendered.contains("00000000.bucket"));
        assert!(!rendered.contains(&expected_epoch.root_hash));
    }

    fn recovered_snapshot_manifest() -> PrivateResultOramManifest {
        let mut manifest = read_shape_manifest();
        manifest.oram.block_size_bytes = 1024;
        manifest
    }

    fn recovered_snapshot_config(uuid: Uuid) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params: CollectionParams {
                encryption: Some(CollectionEncryptionConfig {
                    version: 1,
                    key_id: Some("tenant-a/private-result-rk".to_string()),
                    crypto_schema_version: 1,
                    encryption_epoch: 7,
                    migration_state: CryptoMigrationState::Active,
                    rules: vec![EncryptionRuleRef {
                        id: "docs_body_private_result".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["body".to_string()],
                        },
                        instance: "docs_private_result_oram".to_string(),
                        binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                    }],
                }),
                ..CollectionParams::empty()
            },
            hnsw_config: HnswConfig::default(),
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
        manifest: &PrivateResultOramManifest,
        public_key: &[u8],
    ) -> Settings {
        let mut settings = Settings::new(None).unwrap();
        settings.crypto = CryptoSettings {
            zero_trust_profile: Some(ZERO_TRUST_PROFILE_STRICT.to_string()),
            instances: HashMap::from([(
                "docs_private_result_oram".to_string(),
                CryptoInstanceConfig {
                    provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: json!({
                        KEY_ID_OPTION: manifest.key_id,
                        EXPECTED_RK_ID_OPTION: manifest.rk_id,
                        MIN_RK_EPOCH_OPTION: manifest.rk_epoch,
                        MAX_RK_EPOCH_OPTION: manifest.rk_epoch,
                        ORAM_OPTION: manifest.oram,
                        "integrity": {
                            "manifest_signature_required": true,
                            "commit_signature_required": true,
                            "merkle_root_required": true,
                        },
                        SIGNATURE_PUBLIC_KEYS_OPTION: {
                            SIGNING_KEY_ID: BASE64URL_NOPAD.encode(public_key),
                        },
                    }),
                },
            )]),
            ..CryptoSettings::default()
        };
        settings
    }

    fn fixture_runtime_context(
        manifest: &PrivateResultOramManifest,
    ) -> ResolvedPrivateResultOramContext {
        ResolvedPrivateResultOramContext {
            collection_path: std::path::PathBuf::from("/tmp/qdrant-private-result-oram-test"),
            collection_crypto_id: manifest.collection_id.clone(),
            expected_key_id: manifest.key_id.clone(),
            expected_rk_id: manifest.rk_id.clone(),
            min_rk_epoch: manifest.rk_epoch,
            max_rk_epoch: manifest.rk_epoch,
            expected_oram: manifest.oram.clone(),
            signature_public_keys: HashMap::new(),
            public_key: vec![0; 32],
        }
    }

    fn fixture_session(session_id: &str, lease_expires_unix: u64) -> PrivateResultOramSession {
        let manifest = read_shape_manifest();
        PrivateResultOramSession {
            session_id: session_id.to_string(),
            _client_id: "tenant-a/sdk-instance-1".to_string(),
            collection_id: manifest.collection_id.clone(),
            collection_path: std::path::PathBuf::from("/tmp/qdrant-private-result-oram-test"),
            index_epoch: manifest.index_epoch,
            root_hash: manifest.root_hash.clone(),
            lease_expires_unix,
            bucket_count: manifest.bucket_count,
            max_bucket_ciphertext_bytes: 4096,
            manifest,
        }
    }

    fn assert_private_result_registry_error_redacts_ids(rendered: &str) {
        for sentinel in [
            "collection-private-result-test",
            "session-1",
            "session-2",
            "tenant-a/sdk-instance-1",
            "tenant-a/private-result-rk",
            "OioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio",
            "qdrant-private-result-oram-test",
            "client_state",
            "clientState",
            "client_states",
            "clientStates",
            "client_state_ciphertext",
            "clientStateCiphertext",
            "client_state_ciphertexts",
            "clientStateCiphertexts",
            "client_state_ciphertext_hash",
            "clientStateCiphertextHash",
            "client_state_ciphertext_hashes",
            "clientStateCiphertextHashes",
            "client_state_ciphertext_sha256",
            "clientStateCiphertextSha256",
            "client_state_ciphertexts_sha256",
            "clientStateCiphertextsSha256",
            "encrypted_client_state",
            "encryptedClientState",
            "encrypted_client_states",
            "encryptedClientStates",
            "encrypted_client_state_ciphertext",
            "encryptedClientStateCiphertext",
            "encrypted_client_state_ciphertexts",
            "encryptedClientStateCiphertexts",
            "encrypted_client_state_ciphertext_hash",
            "encryptedClientStateCiphertextHash",
            "encrypted_client_state_ciphertext_hashes",
            "encryptedClientStateCiphertextHashes",
            "encrypted_client_state_ciphertext_sha256",
            "encryptedClientStateCiphertextSha256",
            "encrypted_client_state_ciphertexts_sha256",
            "encryptedClientStateCiphertextsSha256",
            "oram_position_map",
            "oram_position_maps",
            "oram_position_map_backup",
            "oram_position_map_backups",
            "oramPositionMap",
            "oramPositionMaps",
            "oramPositionMapBackup",
            "oramPositionMapBackups",
            "oram_position_map_snapshot",
            "oram_position_map_snapshots",
            "oramPositionMapSnapshot",
            "oramPositionMapSnapshots",
            "position_map",
            "position_maps",
            "position_map_backup",
            "position_map_backups",
            "positionMap",
            "positionMaps",
            "positionMapBackup",
            "positionMapBackups",
            "position_map_snapshot",
            "position_map_snapshots",
            "positionMapSnapshot",
            "positionMapSnapshots",
            "state_ciphertext",
            "stateCiphertext",
            "state_ciphertexts",
            "stateCiphertexts",
            "state_ciphertext_hash",
            "stateCiphertextHash",
            "state_ciphertext_hashes",
            "stateCiphertextHashes",
            "state_ciphertext_sha256",
            "stateCiphertextSha256",
            "state_ciphertexts_sha256",
            "stateCiphertextsSha256",
            "payload_fetch_token",
            "payloadFetchToken",
            "token_map",
            "token_maps",
            "token_map_backup",
            "token_map_backups",
            "tokenMap",
            "tokenMaps",
            "tokenMapBackup",
            "tokenMapBackups",
            "token_map_snapshot",
            "token_map_snapshots",
            "tokenMapSnapshot",
            "tokenMapSnapshots",
            "token_position_map",
            "token_position_maps",
            "token_position_map_backup",
            "token_position_map_backups",
            "tokenPositionMap",
            "tokenPositionMaps",
            "tokenPositionMapBackup",
            "tokenPositionMapBackups",
            "token_position_map_snapshot",
            "token_position_map_snapshots",
            "tokenPositionMapSnapshot",
            "tokenPositionMapSnapshots",
            "stash",
            "stashBackup",
            "stashBackups",
            "stash_backup",
            "stash_backups",
            "stash_snapshot",
            "stash_snapshots",
            "stashSnapshot",
            "stashSnapshots",
        ] {
            assert!(
                !rendered.contains(sentinel),
                "private result ORAM registry error leaked `{sentinel}`: {rendered}",
            );
        }
    }

    fn instance_with_signature_public_key(public_key: &str) -> CryptoInstanceConfig {
        CryptoInstanceConfig {
            provider: qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            materials: HashMap::new(),
            backend_ref: None,
            options: json!({
                SIGNATURE_PUBLIC_KEYS_OPTION: {
                    SIGNING_KEY_ID: public_key,
                }
            }),
        }
    }
}
