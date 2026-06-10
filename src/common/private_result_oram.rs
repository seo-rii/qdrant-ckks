use std::collections::HashSet;

use collection::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, EncryptionRuleRef, EncryptionSelector,
};
use collection::operations::types::CollectionError;
use collection::private_result_oram_store::{PrivateResultOramEpochState, PrivateResultOramStore};
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    OramParams, PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_RESULT_ORAM_BINDING,
    PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND, PrivateResultOramManifest,
    PrivateResultOramManifestValidationContext, PrivateResultOramSignature,
    PrivateResultOramSignatureVerification, PrivateResultOramUploadBundle,
    validate_private_result_oram_manifest, validate_private_result_oram_manifest_signature_shape,
    validate_private_result_oram_upload_bundle,
};
use serde::Serialize;
use serde_json::Value;
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::content_manager::toc::TableOfContent;
use storage::rbac::{AccessRequirements, Auth};

use crate::common::crypto::validate_collection_crypto_runtime_with_crypto_id;
use crate::settings::{CryptoInstanceConfig, Settings};

const KEY_ID_OPTION: &str = "key_id";
const EXPECTED_RK_ID_OPTION: &str = "expected_rk_id";
const MIN_RK_EPOCH_OPTION: &str = "min_rk_epoch";
const MAX_RK_EPOCH_OPTION: &str = "max_rk_epoch";
const ORAM_OPTION: &str = "oram";
const SIGNATURE_PUBLIC_KEYS_OPTION: &str = "signature_public_keys";
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateResultOramManifestRecord {
    pub manifest: PrivateResultOramManifest,
    pub signature: PrivateResultOramSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateResultOramReadBucketsResponse {
    pub index_epoch: u64,
    pub root_hash: String,
    pub buckets: Vec<qdrant_sec::PrivateResultOramBucket>,
    pub proof: PrivateResultOramReadProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrivateResultOramReadProof {
    pub kind: String,
    pub value: String,
}

struct ResolvedPrivateResultOramContext {
    collection_path: std::path::PathBuf,
    collection_crypto_id: String,
    expected_key_id: String,
    expected_rk_id: String,
    min_rk_epoch: u64,
    max_rk_epoch: u64,
    expected_oram: OramParams,
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
        if manifest.oram != self.expected_oram {
            return Err(StorageError::bad_request(
                "private result ORAM manifest oram does not match runtime instance",
            ));
        }
        Ok(())
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
    let resolved = resolve_private_result_oram_context(
        toc,
        auth,
        settings,
        collection_name,
        &signature.key_id,
        "private_result_oram_manifest_upload",
    )
    .await?;
    let epoch = validate_private_result_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_result_oram_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;

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
    let encryption = config.params.effective_encryption().ok_or_else(|| {
        StorageError::bad_request(format!(
            "collection {collection_name} does not configure private result ORAM encryption",
        ))
    })?;
    let rule = private_result_oram_rule(&encryption)?;
    let instance = private_result_oram_instance(settings, rule)?;
    let store = PrivateResultOramStore::new(collection.path());
    let (manifest, signature) = read_uploaded_manifest(&store)?;
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
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "private_result_oram_buckets_upload",
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
            "collection {collection_name} does not configure private result ORAM encryption",
        ))
    })?;
    let rule = private_result_oram_rule(&encryption)?;
    let instance = private_result_oram_instance(settings, rule)?;
    let store = PrivateResultOramStore::new(collection.path());
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = manifest_context_from_runtime(&collection_crypto_id, instance, public_key)?;
    validate_private_result_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_result_oram_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
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
    index_epoch: u64,
    root_hash: String,
    bucket_ids: Vec<u64>,
) -> StorageResult<PrivateResultOramReadBucketsResponse> {
    validate_base64url_32_string(&root_hash, "root_hash")?;
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new(),
        "private_result_oram_buckets_read",
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
            "collection {collection_name} does not configure private result ORAM encryption",
        ))
    })?;
    let rule = private_result_oram_rule(&encryption)?;
    let instance = private_result_oram_instance(settings, rule)?;
    let store = PrivateResultOramStore::new(collection.path());
    let (manifest, signature) = read_uploaded_manifest(&store)?;
    let public_key = signature_public_key(instance, &signature.key_id)?;
    let resolved = manifest_context_from_runtime(&collection_crypto_id, instance, public_key)?;
    validate_private_result_oram_manifest(
        &manifest,
        Some(&signature),
        resolved.manifest_context(&signature.key_id),
    )
    .map_err(private_result_oram_error)?;
    resolved.validate_manifest_runtime_policy(&manifest)?;
    validate_bucket_read_request(&manifest, &bucket_ids)?;
    let max_ciphertext_bytes = max_bucket_ciphertext_bytes(&manifest.oram)?;
    let (buckets, proof) = store
        .read_bucket_batch_with_proof(
            &bucket_ids,
            index_epoch,
            &root_hash,
            manifest.bucket_count,
            max_ciphertext_bytes,
        )
        .map_err(private_result_oram_read_store_error)?;
    let proof_value = serde_json::to_string(&proof).map_err(|_| {
        StorageError::service_error("failed to serialize private result ORAM Merkle proof")
    })?;
    Ok(PrivateResultOramReadBucketsResponse {
        index_epoch,
        root_hash,
        buckets,
        proof: PrivateResultOramReadProof {
            kind: PRIVATE_RESULT_ORAM_MERKLE_PROOF_KIND.to_string(),
            value: proof_value,
        },
    })
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

    for rule in encryption
        .rules
        .iter()
        .filter(|rule| rule.binding.as_deref() == Some(PRIVATE_RESULT_ORAM_BINDING))
    {
        if !matches!(rule.selector, EncryptionSelector::PayloadPaths { .. }) {
            return Err(StorageError::bad_request(format!(
                "private result ORAM snapshot rule {} must use payload_paths selector",
                rule.id,
            )));
        }
        let instance = private_result_oram_instance(settings, rule)?;
        let store = PrivateResultOramStore::new(collection_path);
        let (manifest, signature) = read_uploaded_manifest(&store)?;
        let public_key = signature_public_key(instance, &signature.key_id)?;
        let resolved = manifest_context_from_runtime(&collection_crypto_id, instance, public_key)?;
        validate_private_result_oram_manifest(
            &manifest,
            Some(&signature),
            resolved.manifest_context(&signature.key_id),
        )
        .map_err(private_result_oram_error)?;
        resolved.validate_manifest_runtime_policy(&manifest)?;
    }

    Ok(())
}

async fn resolve_private_result_oram_context(
    toc: &TableOfContent,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    signature_key_id: &str,
    method: &str,
) -> StorageResult<ResolvedPrivateResultOramContext> {
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
            "collection {collection_name} does not configure private result ORAM encryption",
        ))
    })?;
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
            StorageError::bad_request(format!(
                "private result ORAM rule {} references missing runtime instance {}",
                rule.id, rule.instance,
            ))
        })?;
    if instance.provider != PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER {
        return Err(StorageError::bad_request(format!(
            "private result ORAM rule {} runtime instance {} must use provider {PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER}",
            rule.id, rule.instance,
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
    Ok(ResolvedPrivateResultOramContext {
        collection_path: std::path::PathBuf::new(),
        collection_crypto_id: collection_crypto_id.to_string(),
        expected_key_id,
        expected_rk_id,
        min_rk_epoch,
        max_rk_epoch,
        expected_oram,
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

fn signature_public_key(
    instance: &CryptoInstanceConfig,
    signature_key_id: &str,
) -> StorageResult<Vec<u8>> {
    let public_key_b64 = instance
        .options
        .get(SIGNATURE_PUBLIC_KEYS_OPTION)
        .and_then(Value::as_object)
        .and_then(|keys| keys.get(signature_key_id))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            StorageError::bad_request("private result ORAM signature key id is not configured")
        })?;
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
        .ok_or_else(|| {
            StorageError::bad_request(format!(
                "private result ORAM runtime instance must set {option}"
            ))
        })
}

fn required_option_u64(instance: &CryptoInstanceConfig, option: &str) -> StorageResult<u64> {
    instance
        .options
        .get(option)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            StorageError::bad_request(format!(
                "private result ORAM runtime instance must set {option}"
            ))
        })
}

fn required_oram_params(instance: &CryptoInstanceConfig) -> StorageResult<OramParams> {
    let value = instance.options.get(ORAM_OPTION).cloned().ok_or_else(|| {
        StorageError::bad_request("private result ORAM runtime instance must set oram")
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

fn validate_bucket_read_request(
    manifest: &PrivateResultOramManifest,
    bucket_ids: &[u64],
) -> StorageResult<()> {
    if bucket_ids.is_empty() {
        return Err(StorageError::bad_request(
            "private result ORAM read_buckets request is empty",
        ));
    }
    let max_bucket_ids = u64::from(manifest.oram.path_batch_size)
        .checked_mul(u64::from(manifest.oram.tree_height).saturating_add(1))
        .ok_or_else(|| {
            StorageError::bad_request("private result ORAM read_buckets budget is invalid")
        })?;
    if u64::try_from(bucket_ids.len()).unwrap_or(u64::MAX) > max_bucket_ids {
        return Err(StorageError::bad_request(
            "private result ORAM read_buckets request exceeds fixed path budget",
        ));
    }
    let mut seen = HashSet::new();
    for &bucket_id in bucket_ids {
        if bucket_id >= manifest.bucket_count {
            return Err(StorageError::bad_request(
                "private result ORAM read_buckets bucket id is out of range",
            ));
        }
        if !seen.insert(bucket_id) {
            return Err(StorageError::bad_request(
                "private result ORAM read_buckets contains duplicate bucket id",
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
        other => StorageError::from(other),
    }
}

fn private_result_oram_manifest_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private result ORAM manifest store is unavailable")
        }
        CollectionError::ServiceError { .. } => {
            StorageError::service_error("private result ORAM manifest store validation failed")
        }
        other => StorageError::from(other),
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
        other => StorageError::from(other),
    }
}

fn private_result_oram_upload_store_error(err: CollectionError) -> StorageError {
    match err {
        CollectionError::NotFound { .. } => {
            StorageError::not_found("private result ORAM encrypted bucket store is unavailable")
        }
        CollectionError::ServiceError { .. } => StorageError::service_error(
            "private result ORAM encrypted bucket store validation failed",
        ),
        other => StorageError::from(other),
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
        other => StorageError::from(other),
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
        qdrant_sec::PrivateResultOramError::InvalidBucketHash => {
            StorageError::bad_request("private result ORAM bucket ciphertext validation failed")
        }
        qdrant_sec::PrivateResultOramError::BucketOversized => {
            StorageError::bad_request("private result ORAM bucket ciphertext validation failed")
        }
        _ => StorageError::bad_request("private result ORAM request validation failed"),
    }
}
