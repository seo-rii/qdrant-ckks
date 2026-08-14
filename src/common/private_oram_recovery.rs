use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use collection::PrivateOramOwnerRecoveryStorePairResourcesV1;
use collection::collection::Collection;
use collection::config::{CollectionConfigInternal, EncryptionRuleRef};
use collection::operations::verification::new_unchecked_verification_pass;
use collection::private_hnsw_oram_store::PrivateHnswOramStore;
use collection::private_oram_owner_journal::PrivateOramOwnerJournal;
use collection::private_result_oram_store::PrivateResultOramStore;
use collection::shards::channel_service::PrivateOramAuthenticatedOwnerRecoveryResponse;
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::shard::{PeerId, ShardId};
use qdrant_sec::{
    PRIVATE_HNSW_ORAM_BINDING, PRIVATE_RESULT_ORAM_BINDING,
    PrivateOramExternalRecoveryCheckpointBundle, PrivateOramOwnerCapsuleInstallRequestV2,
    PrivateOramPeerRecoveryPublicKeyV1, PrivateOramPeerRecoveryRequestV2,
    PrivateOramPeerRecoveryTerminalV2, PrivateOramRecoveryValidationContext,
    PrivateOramSignatureVerification, validate_private_hnsw_oram_manifest,
    validate_private_hnsw_oram_manifest_signature_shape,
    validate_private_oram_external_recovery_checkpoint, validate_private_result_oram_manifest,
    validate_private_result_oram_manifest_signature_shape,
};
use serde::Serialize;
use storage::content_manager::consensus_manager::ConsensusStateRef;
use storage::content_manager::consensus_ops::{
    CompareAndSwapPrivateOramExternalRecovery, ConsensusOperations, PrivateOramConsensusLayout,
    PrivateOramExternalRecoveryKey, PrivateOramExternalRecoveryLease,
    PrivateOramExternalRecoveryLeasePhase, PrivateOramExternalRecoveryOperation,
    PrivateOramExternalRecoveryPhase, PrivateOramExternalRecoveryState,
    PrivateOramLayoutIndexStateBinding, PrivateOramLayoutKey, PrivateOramMutationKey,
    PrivateOramShardLayoutEntry, canonical_private_oram_index_state_digest,
    canonical_private_oram_shard_layout_digest, private_oram_index_keys_for_config,
};
use storage::content_manager::errors::{StorageError, StorageResult};
use storage::content_manager::private_oram_mutation_journal::{
    PrivateOramMutationCleanupV2, PrivateOramMutationJournal, PrivateOramMutationNeedClearV2,
    PrivateOramMutationNeedLocalCleanupV2, PrivateOramMutationResumeV2,
    PrivateOramOwnerRecoveryCapsuleInstallReceiptV2, PrivateOramOwnerRecoveryCapsuleStoreV2,
    decode_private_oram_owner_recovery_capsule_package_v2,
};
use storage::content_manager::snapshots::private_oram_external_recovery::{
    PrivateOramExternalRecoveryInstallPhase, PrivateOramExternalRecoveryInstallTransaction,
    PrivateOramExternalRecoveryStaging, PrivateOramExternalRecoveryStagingPhase,
    PrivateOramExternalRecoveryStagingStatus, new_private_oram_external_recovery_operation_token,
    private_oram_external_recovery_checkpoint_digest,
    private_oram_external_recovery_operation_id_hash,
};
use storage::content_manager::snapshots::recover::{
    SnapshotConfigValidator, verify_private_oram_external_recovery_snapshot,
};
use storage::content_manager::toc::{
    PrivateOramExternalRecoveryCollectionInstallGuard, TableOfContent,
};
use storage::dispatcher::Dispatcher;
use storage::rbac::{Access, AccessRequirements};

use crate::common::auth::Auth;
use crate::common::crypto::validate_recovered_collection_crypto_config;
use crate::common::private_hnsw::{
    begin_private_hnsw_collection_lifecycle,
    max_bucket_ciphertext_bytes as max_hnsw_bucket_ciphertext_bytes,
    resolve_private_hnsw_context_from_snapshot,
    resolve_private_hnsw_external_recovery_owner_public_key,
    validate_recovered_private_hnsw_oram_snapshot_signatures,
};
use crate::common::private_oram_mutation_session::complete_private_oram_detached_job_local_cleanup_v2;
use crate::common::private_oram_peer_identity::PrivateOramPeerRecoveryIdentity;
use crate::common::private_result_oram::{
    begin_private_result_oram_collection_lifecycle,
    max_bucket_ciphertext_bytes as max_result_bucket_ciphertext_bytes,
    resolve_private_result_oram_context_from_snapshot,
    resolve_private_result_oram_external_recovery_owner_public_key,
    validate_recovered_private_result_oram_snapshot_signatures,
};
use crate::settings::Settings;

const PRIVATE_ORAM_EXTERNAL_RECOVERY_LEASE_SECS: u64 = 3_600;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_RENEW_WINDOW_SECS: u64 = 1_800;
const PRIVATE_ORAM_TERMINAL_RESUME_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

async fn acquire_private_oram_mutation_execution_v2(
    key: &PrivateOramMutationKey,
) -> StorageResult<tokio::sync::OwnedMutexGuard<()>> {
    static EXECUTION_LOCKS: OnceLock<
        Mutex<HashMap<PrivateOramMutationKey, Weak<tokio::sync::Mutex<()>>>>,
    > = OnceLock::new();
    let execution = {
        let mut locks = EXECUTION_LOCKS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .map_err(|_| {
                StorageError::service_error(
                    "private ORAM mutation execution lock registry poisoned",
                )
            })?;
        locks.retain(|_, lock| lock.strong_count() != 0);
        match locks.get(key).and_then(Weak::upgrade) {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                locks.insert(key.clone(), Arc::downgrade(&lock));
                lock
            }
        }
    };
    Ok(execution.lock_owned().await)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateOramMutationTerminalResumeOutcomeV2 {
    Advanced,
    AwaitingCleanup,
}

enum PreparedPrivateOramMutationCleanupV2 {
    CleanupWitness(ConsensusOperations),
    LocalCleanup(PrivateOramMutationNeedLocalCleanupV2),
    Clear(PrivateOramMutationNeedClearV2),
}

struct PrivateOramOwnerCapsuleInstallStorageRequestV2 {
    collection_name: String,
    collection_id: String,
    mutation_id: String,
    parent_descriptor_digest: String,
    coordinator_peer_id: PeerId,
    owner_peer_id: PeerId,
    vector_name: String,
    owner_signing_key_id: String,
    activation_registry_generation: u64,
    activation_manifest_digest: String,
    capsule_digest: String,
    capsule_set_digest: String,
}

pub(crate) async fn do_install_private_oram_owner_recovery_capsule_v2(
    toc: &TableOfContent,
    settings: &Settings,
    consensus_state: &ConsensusStateRef,
    request: &PrivateOramOwnerCapsuleInstallRequestV2,
    package_canonical_json: &[u8],
) -> StorageResult<PrivateOramOwnerRecoveryCapsuleInstallReceiptV2> {
    let storage_request = PrivateOramOwnerCapsuleInstallStorageRequestV2 {
        collection_name: request.collection_name.clone(),
        collection_id: request.collection_id.clone(),
        mutation_id: request.mutation_id.clone(),
        parent_descriptor_digest: request.parent_descriptor_digest.clone(),
        coordinator_peer_id: request.coordinator_peer_id,
        owner_peer_id: request.owner_peer_id,
        vector_name: request.vector_name.clone(),
        owner_signing_key_id: request.owner_signing_key_id.clone(),
        activation_registry_generation: request.activation_registry_generation,
        activation_manifest_digest: request.activation_manifest_digest.clone(),
        capsule_digest: request.capsule_digest.clone(),
        capsule_set_digest: request.capsule_set_digest.clone(),
    };
    do_install_private_oram_owner_recovery_capsule_storage_v2(
        toc,
        settings,
        consensus_state,
        &storage_request,
        package_canonical_json,
    )
    .await
}

pub(crate) async fn do_install_local_private_oram_owner_recovery_capsule_v2(
    toc: &TableOfContent,
    settings: &Settings,
    consensus_state: &ConsensusStateRef,
    collection_name: &str,
    local_owner_peer_id: PeerId,
    package_canonical_json: &[u8],
) -> StorageResult<PrivateOramOwnerRecoveryCapsuleInstallReceiptV2> {
    let package = decode_private_oram_owner_recovery_capsule_package_v2(package_canonical_json)
        .map_err(|_| invalid_owner_recovery_request())?;
    if package.owner_peer_id() != local_owner_peer_id
        || package.coordinator_peer_id() != local_owner_peer_id
    {
        return Err(invalid_owner_recovery_request());
    }
    let storage_request = PrivateOramOwnerCapsuleInstallStorageRequestV2 {
        collection_name: collection_name.to_string(),
        collection_id: package.collection_id().to_string(),
        mutation_id: package.mutation_id().to_string(),
        parent_descriptor_digest: package.parent_descriptor_digest().to_string(),
        coordinator_peer_id: package.coordinator_peer_id(),
        owner_peer_id: package.owner_peer_id(),
        vector_name: package
            .hnsw_vector_name()
            .map_err(|_| invalid_owner_recovery_request())?
            .to_string(),
        owner_signing_key_id: package.owner_signing_key_id().to_string(),
        activation_registry_generation: package.activation_authority().registry_generation(),
        activation_manifest_digest: package.activation_authority().manifest_digest().to_string(),
        capsule_digest: package.capsule_digest().to_string(),
        capsule_set_digest: package.capsule_set_digest().to_string(),
    };
    do_install_private_oram_owner_recovery_capsule_storage_v2(
        toc,
        settings,
        consensus_state,
        &storage_request,
        package_canonical_json,
    )
    .await
}

async fn do_install_private_oram_owner_recovery_capsule_storage_v2(
    toc: &TableOfContent,
    settings: &Settings,
    consensus_state: &ConsensusStateRef,
    request: &PrivateOramOwnerCapsuleInstallStorageRequestV2,
    package_canonical_json: &[u8],
) -> StorageResult<PrivateOramOwnerRecoveryCapsuleInstallReceiptV2> {
    let auth = Auth::new_internal(Access::full("private ORAM owner recovery capsule install"));
    let pass = auth.check_collection_access(
        &request.collection_name,
        AccessRequirements::new().write(),
        "private_oram_owner_recovery_capsule_install_v2",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let collection_id = config.stable_crypto_id(collection.name())?;
    if collection_id != request.collection_id {
        return Err(invalid_owner_recovery_request());
    }

    let package = decode_private_oram_owner_recovery_capsule_package_v2(package_canonical_json)
        .map_err(|_| invalid_owner_recovery_request())?;
    if package.collection_id() != request.collection_id
        || package.mutation_id() != request.mutation_id
        || package.parent_descriptor_digest() != request.parent_descriptor_digest
        || package.coordinator_peer_id() != request.coordinator_peer_id
        || package.owner_peer_id() != request.owner_peer_id
        || package.owner_signing_key_id() != request.owner_signing_key_id
        || package
            .hnsw_vector_name()
            .map_err(|_| invalid_owner_recovery_request())?
            != request.vector_name
        || package.capsule_digest() != request.capsule_digest
        || package.capsule_set_digest() != request.capsule_set_digest
        || package.activation_authority().registry_generation()
            != request.activation_registry_generation
        || package.activation_authority().manifest_digest() != request.activation_manifest_digest
    {
        return Err(invalid_owner_recovery_request());
    }

    let _hnsw_lifecycle = begin_private_hnsw_collection_lifecycle(collection.name(), &config)?;
    let _result_lifecycle =
        begin_private_result_oram_collection_lifecycle(collection.name(), &config)?;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &request.vector_name,
        &request.owner_signing_key_id,
    )?;
    let result_context = resolve_private_result_oram_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &request.owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != result_context.collection_crypto_id()
        || hnsw_context.collection_crypto_id() != request.collection_id
        || hnsw_context.collection_path() != result_context.collection_path()
        || hnsw_context.public_key() != result_context.public_key()
    {
        return Err(invalid_owner_recovery_request());
    }

    let hnsw_store =
        PrivateHnswOramStore::new(hnsw_context.collection_path(), &request.vector_name)?;
    let result_store = PrivateResultOramStore::new(result_context.collection_path());
    let (hnsw_manifest, hnsw_signature) = hnsw_store
        .read_manifest()
        .map_err(|_| invalid_owner_recovery_storage())?;
    let (result_manifest, result_signature) = result_store
        .read_manifest()
        .map_err(|_| invalid_owner_recovery_storage())?;
    if hnsw_signature.key_id != request.owner_signing_key_id
        || hnsw_manifest.owner_signing_key_id != request.owner_signing_key_id
        || result_signature.key_id != request.owner_signing_key_id
        || result_manifest.owner_signing_key_id != request.owner_signing_key_id
    {
        return Err(invalid_owner_recovery_request());
    }
    validate_private_hnsw_oram_manifest_signature_shape(&hnsw_signature)
        .map_err(|_| invalid_owner_recovery_request())?;
    validate_private_hnsw_oram_manifest(
        &hnsw_manifest,
        Some(&hnsw_signature),
        hnsw_context.manifest_context(&request.owner_signing_key_id),
    )
    .map_err(|_| invalid_owner_recovery_request())?;
    hnsw_context.validate_manifest_runtime_policy(&hnsw_manifest)?;
    validate_private_result_oram_manifest_signature_shape(&result_signature)
        .map_err(|_| invalid_owner_recovery_request())?;
    validate_private_result_oram_manifest(
        &result_manifest,
        Some(&result_signature),
        result_context.manifest_context(&request.owner_signing_key_id),
    )
    .map_err(|_| invalid_owner_recovery_request())?;
    result_context.validate_manifest_runtime_policy(&result_manifest)?;

    let reconcile = consensus_state
        .private_oram_mutation_reconcile_snapshot(&PrivateOramMutationKey {
            collection_id: request.collection_id.clone(),
        })
        .ok_or_else(invalid_owner_recovery_state)?;
    let capsule_store = PrivateOramOwnerRecoveryCapsuleStoreV2::new(
        collection.path(),
        request.collection_id.clone(),
        request.owner_peer_id,
        request.owner_signing_key_id.clone(),
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_recovery_storage())?;
    let owner_journal = PrivateOramOwnerJournal::new(hnsw_store.root_path());
    let receipt = capsule_store
        .install_for_reconcile_v2(
            &package,
            &reconcile,
            PrivateOramOwnerRecoveryStorePairResourcesV1 {
                owner_journal: &owner_journal,
                immutable_manifest: package.immutable_manifest_for_install_v2(),
                mutation_bundle: package.mutation_bundle_for_install_v2(),
                signature_verification: PrivateOramSignatureVerification {
                    expected_key_id: &request.owner_signing_key_id,
                    public_key: hnsw_context.public_key(),
                },
                hnsw_store: &hnsw_store,
                hnsw_manifest_validation: hnsw_context
                    .manifest_context(&request.owner_signing_key_id),
                hnsw_max_ciphertext_bytes: max_hnsw_bucket_ciphertext_bytes(&hnsw_manifest)?,
                result_store: &result_store,
                result_manifest_validation: result_context
                    .manifest_context(&request.owner_signing_key_id),
                result_max_ciphertext_bytes: max_result_bucket_ciphertext_bytes(
                    &result_manifest.oram,
                )?,
            },
        )
        .map_err(|_| invalid_owner_recovery_storage())?;
    if collection.config_snapshot().await != config {
        return Err(invalid_owner_recovery_state());
    }
    Ok(receipt)
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateOramExternalRecoveryBeginResponse {
    pub operation_token: String,
    pub status: PrivateOramExternalRecoveryStagingStatus,
}

pub(crate) struct PrivateOramExternalRecoveryChunk<'a> {
    pub operation_token: &'a str,
    pub chunk_index: u64,
    pub path: &'a Path,
    pub sha256: &'a str,
}

impl Debug for PrivateOramExternalRecoveryBeginResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryBeginResponse")
            .field("operation_token", &"[redacted]")
            .field("status", &self.status)
            .finish()
    }
}

struct PrivateOramExternalRecoveryContext {
    collection_id: String,
    config: CollectionConfigInternal,
    layout: PrivateOramConsensusLayout,
    index_states: Vec<PrivateOramLayoutIndexStateBinding>,
    source_shard_ids: Vec<ShardId>,
    this_peer_id: PeerId,
}

struct ActivePrivateOramExternalRecovery {
    context: PrivateOramExternalRecoveryContext,
    key: PrivateOramExternalRecoveryKey,
    lease: PrivateOramExternalRecoveryLease,
    staging: PrivateOramExternalRecoveryStaging,
    status: PrivateOramExternalRecoveryStagingStatus,
}

pub(crate) async fn do_recover_private_oram_mutation_owner_v2(
    toc: &TableOfContent,
    settings: &Settings,
    consensus_state: &ConsensusStateRef,
    request: &PrivateOramPeerRecoveryRequestV2,
) -> StorageResult<PrivateOramPeerRecoveryTerminalV2> {
    let auth = Auth::new_internal(Access::full("private ORAM paired owner recovery"));
    let pass = auth.check_collection_access(
        &request.collection_name,
        AccessRequirements::new().write(),
        "private_oram_mutation_owner_recovery_v2",
    )?;
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    let collection_id = config.stable_crypto_id(collection.name())?;
    if collection_id != request.collection_id {
        return Err(invalid_owner_recovery_request());
    }

    let _hnsw_lifecycle = begin_private_hnsw_collection_lifecycle(collection.name(), &config)?;
    let _result_lifecycle =
        begin_private_result_oram_collection_lifecycle(collection.name(), &config)?;
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &request.vector_name,
        &request.owner_signing_key_id,
    )?;
    let result_context = resolve_private_result_oram_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &request.owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != result_context.collection_crypto_id()
        || hnsw_context.collection_crypto_id() != request.collection_id
        || hnsw_context.collection_path() != result_context.collection_path()
        || hnsw_context.public_key() != result_context.public_key()
    {
        return Err(invalid_owner_recovery_request());
    }

    let hnsw_store =
        PrivateHnswOramStore::new(hnsw_context.collection_path(), &request.vector_name)?;
    let result_store = PrivateResultOramStore::new(result_context.collection_path());
    let (hnsw_manifest, hnsw_signature) = hnsw_store
        .read_manifest()
        .map_err(|_| invalid_owner_recovery_storage())?;
    let (result_manifest, result_signature) = result_store
        .read_manifest()
        .map_err(|_| invalid_owner_recovery_storage())?;
    if hnsw_signature.key_id != request.owner_signing_key_id
        || hnsw_manifest.owner_signing_key_id != request.owner_signing_key_id
        || result_signature.key_id != request.owner_signing_key_id
        || result_manifest.owner_signing_key_id != request.owner_signing_key_id
    {
        return Err(invalid_owner_recovery_request());
    }
    validate_private_hnsw_oram_manifest_signature_shape(&hnsw_signature)
        .map_err(|_| invalid_owner_recovery_request())?;
    validate_private_hnsw_oram_manifest(
        &hnsw_manifest,
        Some(&hnsw_signature),
        hnsw_context.manifest_context(&request.owner_signing_key_id),
    )
    .map_err(|_| invalid_owner_recovery_request())?;
    hnsw_context.validate_manifest_runtime_policy(&hnsw_manifest)?;
    validate_private_result_oram_manifest_signature_shape(&result_signature)
        .map_err(|_| invalid_owner_recovery_request())?;
    validate_private_result_oram_manifest(
        &result_manifest,
        Some(&result_signature),
        result_context.manifest_context(&request.owner_signing_key_id),
    )
    .map_err(|_| invalid_owner_recovery_request())?;
    result_context.validate_manifest_runtime_policy(&result_manifest)?;

    let key = PrivateOramMutationKey {
        collection_id: request.collection_id.clone(),
    };
    let reconcile = consensus_state
        .private_oram_mutation_reconcile_snapshot(&key)
        .ok_or_else(invalid_owner_recovery_state)?;
    let capsule_store = PrivateOramOwnerRecoveryCapsuleStoreV2::new(
        collection.path(),
        request.collection_id.clone(),
        request.owner_peer_id,
        request.owner_signing_key_id.clone(),
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_recovery_storage())?;
    let material = capsule_store
        .load_recovery_material_for_reconcile_v2(&reconcile)
        .map_err(|_| invalid_owner_recovery_storage())?;
    let owner_journal = PrivateOramOwnerJournal::new(hnsw_store.root_path());
    let terminal = capsule_store
        .recover_remote_owner_pair_v2(
            &reconcile,
            request,
            PrivateOramOwnerRecoveryStorePairResourcesV1 {
                owner_journal: &owner_journal,
                immutable_manifest: material.immutable_manifest(),
                mutation_bundle: material.mutation_bundle(),
                signature_verification: PrivateOramSignatureVerification {
                    expected_key_id: &request.owner_signing_key_id,
                    public_key: hnsw_context.public_key(),
                },
                hnsw_store: &hnsw_store,
                hnsw_manifest_validation: hnsw_context
                    .manifest_context(&request.owner_signing_key_id),
                hnsw_max_ciphertext_bytes: max_hnsw_bucket_ciphertext_bytes(&hnsw_manifest)?,
                result_store: &result_store,
                result_manifest_validation: result_context
                    .manifest_context(&request.owner_signing_key_id),
                result_max_ciphertext_bytes: max_result_bucket_ciphertext_bytes(
                    &result_manifest.oram,
                )?,
            },
        )
        .map_err(|_| invalid_owner_recovery_storage())?;

    if collection.config_snapshot().await != config {
        return Err(invalid_owner_recovery_state());
    }
    Ok(terminal)
}

fn invalid_owner_recovery_request() -> StorageError {
    StorageError::bad_request("private ORAM owner recovery authority is invalid")
}

fn invalid_owner_recovery_storage() -> StorageError {
    StorageError::service_error("private ORAM owner recovery storage validation failed")
}

fn invalid_owner_recovery_state() -> StorageError {
    StorageError::service_error("private ORAM owner recovery state is unavailable")
}

pub(crate) async fn do_fetch_authenticated_private_oram_owner_terminal_v2(
    toc: &TableOfContent,
    consensus_state: &ConsensusStateRef,
    request: PrivateOramPeerRecoveryRequestV2,
    coordinator_identity: &PrivateOramPeerRecoveryPublicKeyV1,
) -> StorageResult<PrivateOramAuthenticatedOwnerRecoveryResponse> {
    if request.coordinator_peer_id != toc.this_peer_id
        || request.owner_peer_id == request.coordinator_peer_id
    {
        return Err(invalid_owner_recovery_request());
    }
    let before = consensus_state.private_oram_peer_recovery_signer_pair_pin(
        request.owner_peer_id,
        request.coordinator_peer_id,
    )?;
    if before.coordinator().signer() != coordinator_identity {
        return Err(invalid_owner_recovery_state());
    }
    let expected_request = request.clone();
    let response = toc
        .get_channel_service()
        .recover_private_oram_mutation_owner(
            request.owner_peer_id,
            request,
            before.owner().signer(),
        )
        .await
        .map_err(|_| invalid_owner_recovery_storage())?;
    let after = consensus_state.private_oram_peer_recovery_signer_pair_pin(
        expected_request.owner_peer_id,
        expected_request.coordinator_peer_id,
    )?;
    if after != before || after.coordinator().signer() != coordinator_identity {
        return Err(invalid_owner_recovery_state());
    }
    let actual_request = response.verified().request();
    let mut rebound_expected = expected_request;
    rebound_expected.challenge_nonce = actual_request.challenge_nonce.clone();
    if actual_request != &rebound_expected {
        return Err(invalid_owner_recovery_state());
    }
    Ok(response)
}

pub(crate) async fn resume_private_oram_mutation_terminal_once_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    key: &PrivateOramMutationKey,
) -> StorageResult<PrivateOramMutationTerminalResumeOutcomeV2> {
    let _execution = acquire_private_oram_mutation_execution_v2(key).await?;
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_recovery_state)?;
    let slot = consensus
        .private_oram_mutation_lease_slot(key)
        .ok_or_else(invalid_owner_recovery_state)?;
    let lease = slot
        .active
        .as_ref()
        .ok_or_else(invalid_owner_recovery_state)?;
    if lease.collection_id != key.collection_id
        || lease.owner_peer_id != identity.peer_id()
        || lease.owner_peer_id != dispatcher.this_peer_id()
    {
        return Err(invalid_owner_recovery_state());
    }
    let retained = consensus
        .private_oram_mutation_v2_exact_admitted_recovery_manifest(key, lease)?
        .ok_or_else(invalid_owner_recovery_state)?;
    let (package, _) = retained
        .coordinator_recovery_envelope()
        .map_err(|_| invalid_owner_recovery_state())?;
    if package.collection_name != collection_name
        || package.collection_id != key.collection_id
        || package.coordinator_peer_id != identity.peer_id()
        || package.owner_peer_id != identity.peer_id()
    {
        return Err(invalid_owner_recovery_state());
    }

    let auth = Auth::new_internal(Access::full("private ORAM terminal recovery coordinator"));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_terminal_recovery_coordinator_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != key.collection_id {
        return Err(invalid_owner_recovery_state());
    }
    let hnsw_context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &package.vector_name,
        &package.owner_signing_key_id,
    )?;
    if hnsw_context.collection_crypto_id() != key.collection_id {
        return Err(invalid_owner_recovery_state());
    }
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        package.owner_signing_key_id.clone(),
        hnsw_context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_recovery_storage())?;
    let authority = consensus
        .linearizable_private_oram_mutation_reconcile_snapshot_v2(
            key,
            identity.peer_id(),
            Some(PRIVATE_ORAM_TERMINAL_RESUME_WAIT),
        )
        .await?;
    let resume = journal
        .open_private_oram_mutation_resume_v2(authority, collection_name)
        .map_err(|_| invalid_owner_recovery_storage())?;

    match resume {
        PrivateOramMutationResumeV2::NeedParentProgress(progress) => {
            dispatcher
                .submit_private_oram_mutation_parent_progress_v2(
                    progress,
                    Some(PRIVATE_ORAM_TERMINAL_RESUME_WAIT),
                )
                .await?;
        }
        PrivateOramMutationResumeV2::NeedDecision(permit) => {
            journal
                .resume_private_oram_decision_v2(permit)
                .map_err(|_| invalid_owner_recovery_storage())?;
        }
        PrivateOramMutationResumeV2::NeedRemoteTerminals(plan) => {
            let requests = plan.requests().to_vec();
            let mut responses = Vec::with_capacity(requests.len());
            for request in requests {
                responses.push(
                    do_fetch_authenticated_private_oram_owner_terminal_v2(
                        toc,
                        consensus,
                        request,
                        identity.public_key(),
                    )
                    .await?,
                );
            }
            let authority = consensus
                .linearizable_private_oram_mutation_reconcile_snapshot_v2(
                    key,
                    identity.peer_id(),
                    Some(PRIVATE_ORAM_TERMINAL_RESUME_WAIT),
                )
                .await?;
            journal
                .resume_private_oram_remote_terminals_v2(plan, authority, &responses)
                .map_err(|_| invalid_owner_recovery_storage())?;
        }
        PrivateOramMutationResumeV2::NeedLocalTerminal(permit) => {
            let _hnsw_lifecycle =
                begin_private_hnsw_collection_lifecycle(collection.name(), &config)?;
            let _result_lifecycle =
                begin_private_result_oram_collection_lifecycle(collection.name(), &config)?;
            let result_context = resolve_private_result_oram_context_from_snapshot(
                settings,
                collection.name(),
                collection.path(),
                &config,
                &package.owner_signing_key_id,
            )?;
            if result_context.collection_crypto_id() != hnsw_context.collection_crypto_id()
                || result_context.collection_path() != hnsw_context.collection_path()
                || result_context.public_key() != hnsw_context.public_key()
            {
                return Err(invalid_owner_recovery_state());
            }
            let hnsw_store = PrivateHnswOramStore::new(collection.path(), &package.vector_name)?;
            let result_store = PrivateResultOramStore::new(collection.path());
            let (hnsw_manifest, hnsw_signature) = hnsw_store
                .read_manifest()
                .map_err(|_| invalid_owner_recovery_storage())?;
            let (result_manifest, result_signature) = result_store
                .read_manifest()
                .map_err(|_| invalid_owner_recovery_storage())?;
            if hnsw_signature.key_id != package.owner_signing_key_id
                || hnsw_manifest.owner_signing_key_id != package.owner_signing_key_id
                || result_signature.key_id != package.owner_signing_key_id
                || result_manifest.owner_signing_key_id != package.owner_signing_key_id
            {
                return Err(invalid_owner_recovery_state());
            }
            validate_private_hnsw_oram_manifest_signature_shape(&hnsw_signature)
                .map_err(|_| invalid_owner_recovery_request())?;
            validate_private_hnsw_oram_manifest(
                &hnsw_manifest,
                Some(&hnsw_signature),
                hnsw_context.manifest_context(&package.owner_signing_key_id),
            )
            .map_err(|_| invalid_owner_recovery_request())?;
            hnsw_context.validate_manifest_runtime_policy(&hnsw_manifest)?;
            validate_private_result_oram_manifest_signature_shape(&result_signature)
                .map_err(|_| invalid_owner_recovery_request())?;
            validate_private_result_oram_manifest(
                &result_manifest,
                Some(&result_signature),
                result_context.manifest_context(&package.owner_signing_key_id),
            )
            .map_err(|_| invalid_owner_recovery_request())?;
            result_context.validate_manifest_runtime_policy(&result_manifest)?;

            let material = journal
                .load_recovery_material_v2()
                .map_err(|_| invalid_owner_recovery_storage())?;
            let owner_journal = PrivateOramOwnerJournal::new(hnsw_store.root_path());
            journal
                .resume_private_oram_local_terminal_v2(
                    permit,
                    identity.peer_id(),
                    PrivateOramOwnerRecoveryStorePairResourcesV1 {
                        owner_journal: &owner_journal,
                        immutable_manifest: material.immutable_manifest(),
                        mutation_bundle: material.mutation_bundle(),
                        signature_verification: PrivateOramSignatureVerification {
                            expected_key_id: &package.owner_signing_key_id,
                            public_key: hnsw_context.public_key(),
                        },
                        hnsw_store: &hnsw_store,
                        hnsw_manifest_validation: hnsw_context
                            .manifest_context(&package.owner_signing_key_id),
                        hnsw_max_ciphertext_bytes: max_hnsw_bucket_ciphertext_bytes(
                            &hnsw_manifest,
                        )?,
                        result_store: &result_store,
                        result_manifest_validation: result_context
                            .manifest_context(&package.owner_signing_key_id),
                        result_max_ciphertext_bytes: max_result_bucket_ciphertext_bytes(
                            &result_manifest.oram,
                        )?,
                    },
                )
                .map_err(|_| invalid_owner_recovery_storage())?;
        }
        PrivateOramMutationResumeV2::NeedPointResolution(permit) => {
            journal
                .resume_private_oram_no_server_point_resolution_v2(permit)
                .map_err(|_| invalid_owner_recovery_storage())?;
        }
        PrivateOramMutationResumeV2::Complete(terminal) => {
            let cleanup = match journal
                .open_private_oram_mutation_cleanup_v2(terminal)
                .map_err(|_| invalid_owner_recovery_storage())?
            {
                PrivateOramMutationCleanupV2::NeedCleanupWitness(permit) => {
                    PreparedPrivateOramMutationCleanupV2::CleanupWitness(
                        dispatcher.private_oram_mutation_cleanup_witness_operation_v2(permit)?,
                    )
                }
                PrivateOramMutationCleanupV2::NeedLocalCleanup(permit) => {
                    PreparedPrivateOramMutationCleanupV2::LocalCleanup(permit)
                }
                PrivateOramMutationCleanupV2::NeedClear(permit) => {
                    PreparedPrivateOramMutationCleanupV2::Clear(permit)
                }
            };
            match cleanup {
                PreparedPrivateOramMutationCleanupV2::CleanupWitness(operation) => {
                    if !consensus
                        .propose_consensus_op_with_await(
                            operation,
                            Some(PRIVATE_ORAM_TERMINAL_RESUME_WAIT),
                        )
                        .await?
                    {
                        return Err(StorageError::service_error(
                            "private ORAM mutation cleanup witness was not applied",
                        ));
                    }
                }
                PreparedPrivateOramMutationCleanupV2::LocalCleanup(permit) => {
                    let quiesced =
                        complete_private_oram_detached_job_local_cleanup_v2(identity, &permit)
                            .await?;
                    quiesced.validate(identity, &permit)?;
                    let proposal = journal
                        .complete_private_oram_mutation_local_cleanup_v2(permit)
                        .map_err(|_| invalid_owner_recovery_storage())?;
                    dispatcher
                        .submit_private_oram_mutation_clear_pending_v2(
                            proposal,
                            Some(PRIVATE_ORAM_TERMINAL_RESUME_WAIT),
                        )
                        .await?;
                }
                PreparedPrivateOramMutationCleanupV2::Clear(permit) => {
                    dispatcher
                        .submit_private_oram_mutation_clear_v2(
                            permit,
                            Some(PRIVATE_ORAM_TERMINAL_RESUME_WAIT),
                        )
                        .await?;
                }
            }
            return Ok(PrivateOramMutationTerminalResumeOutcomeV2::AwaitingCleanup);
        }
    }
    if collection.config_snapshot().await != config {
        return Err(invalid_owner_recovery_state());
    }
    Ok(PrivateOramMutationTerminalResumeOutcomeV2::Advanced)
}

pub(crate) async fn archive_private_oram_mutation_before_acknowledgement_v2(
    dispatcher: &Dispatcher,
    settings: &Settings,
    identity: &PrivateOramPeerRecoveryIdentity,
    collection_name: &str,
    key: &PrivateOramMutationKey,
    generation: u64,
) -> StorageResult<()> {
    let _execution = acquire_private_oram_mutation_execution_v2(key).await?;
    let consensus = dispatcher
        .consensus_state()
        .ok_or_else(invalid_owner_recovery_state)?;
    let permit = consensus.private_oram_mutation_cleared_pending_archive_permit(
        key,
        identity.peer_id(),
        generation,
    )?;
    let auth = Auth::new_internal(Access::full("private ORAM terminal archive coordinator"));
    let pass = auth.check_collection_access(
        collection_name,
        AccessRequirements::new().write(),
        "private_oram_terminal_archive_coordinator_v2",
    )?;
    let verification = new_unchecked_verification_pass();
    let toc = dispatcher.toc(&auth, &verification);
    let collection = toc.get_collection(&pass).await?;
    let config = collection.config_snapshot().await;
    if config.stable_crypto_id(collection.name())? != key.collection_id {
        return Err(invalid_owner_recovery_state());
    }
    let vector_name = permit.vector_name().to_string();
    let owner_signing_key_id = permit.owner_signing_key_id().to_string();
    let store = PrivateHnswOramStore::new(collection.path(), &vector_name)
        .map_err(|_| invalid_owner_recovery_storage())?;
    let (manifest, signature) = store
        .read_manifest()
        .map_err(|_| invalid_owner_recovery_storage())?;
    let context = resolve_private_hnsw_context_from_snapshot(
        settings,
        collection.name(),
        collection.path(),
        &config,
        &vector_name,
        &owner_signing_key_id,
    )?;
    if manifest.vector_name != vector_name
        || manifest.owner_signing_key_id != owner_signing_key_id
        || signature.key_id != owner_signing_key_id
        || context.collection_crypto_id() != key.collection_id
    {
        return Err(invalid_owner_recovery_state());
    }
    validate_private_hnsw_oram_manifest_signature_shape(&signature)
        .map_err(|_| invalid_owner_recovery_request())?;
    validate_private_hnsw_oram_manifest(
        &manifest,
        Some(&signature),
        context.manifest_context(&owner_signing_key_id),
    )
    .map_err(|_| invalid_owner_recovery_request())?;
    context.validate_manifest_runtime_policy(&manifest)?;
    let journal = PrivateOramMutationJournal::new(
        collection.path(),
        owner_signing_key_id,
        context.public_key().to_vec(),
    )
    .map_err(|_| invalid_owner_recovery_storage())?;
    journal
        .archive_private_oram_mutation_after_clear_v2(permit)
        .map_err(|_| invalid_owner_recovery_storage())?;
    if collection.config_snapshot().await != config {
        return Err(invalid_owner_recovery_state());
    }
    Ok(())
}

pub async fn do_begin_private_oram_external_recovery(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    checkpoint_bundle: PrivateOramExternalRecoveryCheckpointBundle,
) -> StorageResult<PrivateOramExternalRecoveryBeginResponse> {
    let context = resolve_private_oram_external_recovery_context(
        dispatcher,
        auth,
        settings,
        collection_name,
        None,
    )
    .await?;
    let _private_hnsw_lifecycle =
        begin_private_hnsw_collection_lifecycle(collection_name, &context.config)?;
    let _private_result_lifecycle =
        begin_private_result_oram_collection_lifecycle(collection_name, &context.config)?;
    let public_key = resolve_external_recovery_owner_public_key(
        settings,
        &context.config,
        &checkpoint_bundle.checkpoint.owner_signing_key_id,
    )?;
    validate_external_recovery_checkpoint(&checkpoint_bundle, &context, &public_key)?;

    let now_unix = current_unix_secs()?;
    let lease_expires_at_unix = now_unix
        .checked_add(PRIVATE_ORAM_EXTERNAL_RECOVERY_LEASE_SECS)
        .ok_or_else(invalid_external_recovery_request)?;
    let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&checkpoint_bundle)?;
    let operation_token = new_private_oram_external_recovery_operation_token();
    let operation_id_hash = private_oram_external_recovery_operation_id_hash(&operation_token)?;
    let key = PrivateOramExternalRecoveryKey {
        collection_id: context.collection_id.clone(),
    };
    let expected = dispatcher.private_oram_consensus_external_recovery(&key)?;
    if expected.as_ref().is_some_and(|state| {
        checkpoint_bundle.checkpoint.backup_generation <= state.committed_backup_generation
            || state.active_lease.as_ref().is_some_and(|lease| {
                lease.phase == PrivateOramExternalRecoveryLeasePhase::Installing
                    || lease.expires_at_unix > now_unix
            })
    }) {
        return Err(StorageError::bad_request(
            "private ORAM external recovery conflicts with current recovery state",
        ));
    }

    let lease = PrivateOramExternalRecoveryLease {
        owner_peer_id: context.this_peer_id,
        operation_id_hash: operation_id_hash.clone(),
        checkpoint_digest: checkpoint_digest.clone(),
        backup_generation: checkpoint_bundle.checkpoint.backup_generation,
        issued_at_unix: now_unix,
        expires_at_unix: lease_expires_at_unix,
        install_intent_digest: None,
        phase: PrivateOramExternalRecoveryLeasePhase::Staging,
    };
    let mut desired = expected
        .clone()
        .unwrap_or(PrivateOramExternalRecoveryState {
            committed_backup_generation: 0,
            committed_checkpoint_digest: None,
            committed_install_intent_digest: None,
            active_lease: None,
        });
    desired.active_lease = Some(lease);

    let staging = PrivateOramExternalRecoveryStaging::new(
        dispatcher
            .toc(auth, &new_unchecked_verification_pass())
            .storage_path(),
        &context.collection_id,
        &operation_id_hash,
    )?;
    staging.begin(&checkpoint_digest, checkpoint_bundle, lease_expires_at_unix)?;

    let operation = recovery_operation(
        PrivateOramExternalRecoveryPhase::Begin,
        key.clone(),
        expected.clone(),
        Some(desired.clone()),
        &context,
    );
    if let Err(error) = dispatcher
        .submit_private_oram_external_recovery(operation, None)
        .await
    {
        let observed = dispatcher.private_oram_consensus_external_recovery(&key)?;
        if observed.as_ref() != Some(&desired) {
            let _ = staging.abort();
            return Err(error);
        }
    }
    if let Some(superseded_lease) = expected
        .as_ref()
        .and_then(|state| state.active_lease.as_ref())
    {
        let superseded_staging = PrivateOramExternalRecoveryStaging::new(
            dispatcher
                .toc(auth, &new_unchecked_verification_pass())
                .storage_path(),
            &context.collection_id,
            &superseded_lease.operation_id_hash,
        )?;
        let _ = superseded_staging.abort();
    }

    let backup_generation = desired
        .active_lease
        .as_ref()
        .ok_or_else(invalid_external_recovery_state)?
        .backup_generation;
    let status = staging.status_for_consensus_lease(
        &checkpoint_digest,
        backup_generation,
        lease_expires_at_unix,
    )?;
    Ok(PrivateOramExternalRecoveryBeginResponse {
        operation_token,
        status,
    })
}

pub async fn do_get_private_oram_external_recovery_status(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    operation_token: &str,
) -> StorageResult<PrivateOramExternalRecoveryStagingStatus> {
    let active = resolve_active_private_oram_external_recovery(
        dispatcher,
        auth,
        settings,
        collection_name,
        operation_token,
        false,
        false,
        None,
    )
    .await?;
    ensure_active_recovery_unchanged(dispatcher, &active.key, &active.lease)?;
    Ok(active.status)
}

pub async fn do_upload_private_oram_external_recovery_chunk(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    chunk: PrivateOramExternalRecoveryChunk<'_>,
) -> StorageResult<PrivateOramExternalRecoveryStagingStatus> {
    let active = resolve_active_private_oram_external_recovery(
        dispatcher,
        auth,
        settings,
        collection_name,
        chunk.operation_token,
        true,
        false,
        Some(PrivateOramExternalRecoveryLeasePhase::Staging),
    )
    .await?;
    let status = active
        .staging
        .append_chunk(chunk.chunk_index, chunk.path, chunk.sha256)?;
    ensure_active_recovery_unchanged(dispatcher, &active.key, &active.lease)?;
    Ok(status)
}

pub async fn do_verify_private_oram_external_recovery(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    operation_token: &str,
) -> StorageResult<PrivateOramExternalRecoveryStagingStatus> {
    let active = resolve_active_private_oram_external_recovery(
        dispatcher,
        auth,
        settings,
        collection_name,
        operation_token,
        true,
        true,
        Some(PrivateOramExternalRecoveryLeasePhase::Staging),
    )
    .await?;
    let verification = active.staging.prepare_verification()?;
    let checkpoint_bundle = verification.checkpoint_bundle();
    let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(checkpoint_bundle)?;
    if checkpoint_digest != active.lease.checkpoint_digest {
        return Err(invalid_external_recovery_state());
    }
    let public_key = resolve_external_recovery_owner_public_key(
        settings,
        &active.context.config,
        &checkpoint_bundle.checkpoint.owner_signing_key_id,
    )?;
    validate_external_recovery_checkpoint(checkpoint_bundle, &active.context, &public_key)?;

    let validator = recovered_snapshot_validator(settings.clone());
    let collection_name = collection_name.to_string();
    let existing_config = active.context.config.clone();
    let this_peer_id = active.context.this_peer_id;
    let recovery_mode = settings.storage.recovery_mode.clone();
    let verification = tokio::task::spawn_blocking(move || {
        verify_private_oram_external_recovery_snapshot(
            &collection_name,
            &verification,
            this_peer_id,
            &existing_config,
            recovery_mode.as_deref(),
            Some(&validator),
        )?;
        Ok::<_, StorageError>(verification)
    })
    .await
    .map_err(|_| {
        StorageError::service_error("private ORAM external recovery verify task failed")
    })??;

    let status = active.staging.mark_verified(verification)?;
    ensure_active_recovery_unchanged(dispatcher, &active.key, &active.lease)?;
    Ok(status)
}

pub async fn do_commit_private_oram_external_recovery(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    operation_token: &str,
) -> StorageResult<bool> {
    let operation_id_hash = private_oram_external_recovery_operation_id_hash(operation_token)?;
    let context = match resolve_private_oram_external_recovery_context(
        dispatcher,
        auth,
        settings,
        collection_name,
        Some(&operation_id_hash),
    )
    .await
    {
        Ok(context) => context,
        Err(_) => {
            resolve_private_oram_external_recovery_context(
                dispatcher,
                auth,
                settings,
                collection_name,
                None,
            )
            .await?
        }
    };
    let key = PrivateOramExternalRecoveryKey {
        collection_id: context.collection_id.clone(),
    };
    let mut state = dispatcher
        .private_oram_consensus_external_recovery(&key)?
        .ok_or_else(invalid_external_recovery_state)?;
    let pass = new_unchecked_verification_pass();
    let toc = dispatcher.toc(auth, &pass);
    let staging = PrivateOramExternalRecoveryStaging::new(
        toc.storage_path(),
        &context.collection_id,
        &operation_id_hash,
    )?;
    if state.active_lease.is_none() {
        let backup_generation = state.committed_backup_generation;
        let checkpoint_digest = state
            .committed_checkpoint_digest
            .as_deref()
            .ok_or_else(invalid_external_recovery_state)?;
        let install_intent_digest = state
            .committed_install_intent_digest
            .as_deref()
            .ok_or_else(invalid_external_recovery_state)?;
        let mut transaction = staging.resume_committed_install(collection_name, &state)?;
        let install_guard = toc
            .acquire_committed_private_oram_external_recovery_install_guard(
                collection_name,
                &context.collection_id,
                &operation_id_hash,
                backup_generation,
                checkpoint_digest,
                install_intent_digest,
            )
            .await?;
        install_guard.unload_current_collection().await?;
        if transaction.phase() == PrivateOramExternalRecoveryInstallPhase::Loaded {
            transaction.mark_consensus_committed()?;
        } else if transaction.phase() != PrivateOramExternalRecoveryInstallPhase::ConsensusCommitted
        {
            return Err(invalid_external_recovery_state());
        }
        let loaded = install_guard.load_live_collection_strict().await?;
        if let Err(error) =
            validate_loaded_private_oram_recovery_collection(&loaded, &context).await
        {
            loaded.stop_gracefully().await;
            return Err(error);
        }
        if let Err(error) = transaction.finalize_committed() {
            loaded.stop_gracefully().await;
            return Err(error);
        }
        install_guard
            .publish_committed_collection(
                loaded,
                backup_generation,
                checkpoint_digest,
                install_intent_digest,
            )
            .await?;
        return Ok(true);
    }
    let mut lease = state
        .active_lease
        .clone()
        .ok_or_else(invalid_external_recovery_state)?;
    validate_lease_owner_and_operation(&lease, context.this_peer_id, &operation_id_hash)?;
    if lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging {
        validate_active_lease(&lease, context.this_peer_id, &operation_id_hash, None)?;
    }

    let status = staging.status_for_consensus_lease(
        &lease.checkpoint_digest,
        lease.backup_generation,
        lease.expires_at_unix,
    )?;
    if status.phase != PrivateOramExternalRecoveryStagingPhase::Verified {
        return Err(invalid_external_recovery_state());
    }

    let install_guard = toc
        .acquire_private_oram_external_recovery_install_guard(
            collection_name,
            &context.collection_id,
            &operation_id_hash,
        )
        .await?;
    install_guard.unload_current_collection().await?;
    let mut transaction = match staging.prepare_install(collection_name, &lease) {
        Ok(transaction) => transaction,
        Err(error) => {
            if lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging
                && !staging.install_marker_is_present()?
            {
                let collection = install_guard.load_live_collection_strict().await?;
                if let Err(validation_error) =
                    validate_loaded_private_oram_recovery_collection(&collection, &context).await
                {
                    collection.stop_gracefully().await;
                    return Err(validation_error);
                }
                install_guard.publish_fenced_collection(collection).await?;
            }
            return Err(error);
        }
    };
    if lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging
        && matches!(
            transaction.phase(),
            PrivateOramExternalRecoveryInstallPhase::RollbackInProgress
                | PrivateOramExternalRecoveryInstallPhase::RollbackComplete
        )
    {
        transaction.finalize_rolled_back()?;
        let collection = install_guard.load_live_collection_strict().await?;
        if let Err(error) =
            validate_loaded_private_oram_recovery_collection(&collection, &context).await
        {
            collection.stop_gracefully().await;
            return Err(error);
        }
        install_guard.publish_fenced_collection(collection).await?;
        return Err(invalid_external_recovery_state());
    }
    let install_intent_digest = transaction.install_intent_digest();

    if lease.phase == PrivateOramExternalRecoveryLeasePhase::Staging {
        if transaction.phase() != PrivateOramExternalRecoveryInstallPhase::Prepared {
            return Err(invalid_external_recovery_state());
        }
        let mut installing_lease = lease.clone();
        installing_lease.phase = PrivateOramExternalRecoveryLeasePhase::Installing;
        installing_lease.install_intent_digest = Some(install_intent_digest.clone());
        let mut installing_state = state.clone();
        installing_state.active_lease = Some(installing_lease.clone());
        let prepare = recovery_operation(
            PrivateOramExternalRecoveryPhase::PrepareInstall,
            key.clone(),
            Some(state.clone()),
            Some(installing_state.clone()),
            &context,
        );
        let prepare_result = dispatcher
            .submit_private_oram_external_recovery(prepare, None)
            .await;
        if dispatcher
            .private_oram_consensus_external_recovery(&key)?
            .as_ref()
            != Some(&installing_state)
        {
            return Err(prepare_result
                .err()
                .unwrap_or_else(invalid_external_recovery_state));
        }
        state = installing_state;
        lease = installing_lease;
    } else if lease.phase != PrivateOramExternalRecoveryLeasePhase::Installing
        || lease.install_intent_digest.as_deref() != Some(install_intent_digest.as_str())
    {
        return Err(invalid_external_recovery_state());
    }

    if dispatcher
        .private_oram_consensus_external_recovery(&key)?
        .as_ref()
        != Some(&state)
    {
        return Err(invalid_external_recovery_state());
    }

    match transaction.phase() {
        PrivateOramExternalRecoveryInstallPhase::Prepared => {
            if let Err(error) = transaction.move_live_to_backup() {
                rollback_installing_private_oram_recovery(
                    dispatcher,
                    &context,
                    collection_name,
                    &key,
                    &state,
                    &staging,
                    &install_guard,
                    transaction,
                )
                .await?;
                return Err(error);
            }
            if let Err(error) = transaction.promote_verified_collection() {
                rollback_installing_private_oram_recovery(
                    dispatcher,
                    &context,
                    collection_name,
                    &key,
                    &state,
                    &staging,
                    &install_guard,
                    transaction,
                )
                .await?;
                return Err(error);
            }
            if let Err(error) = transaction.mark_load_in_progress() {
                rollback_installing_private_oram_recovery(
                    dispatcher,
                    &context,
                    collection_name,
                    &key,
                    &state,
                    &staging,
                    &install_guard,
                    transaction,
                )
                .await?;
                return Err(error);
            }
        }
        PrivateOramExternalRecoveryInstallPhase::OldMoved => {
            if let Err(error) = transaction.promote_verified_collection() {
                rollback_installing_private_oram_recovery(
                    dispatcher,
                    &context,
                    collection_name,
                    &key,
                    &state,
                    &staging,
                    &install_guard,
                    transaction,
                )
                .await?;
                return Err(error);
            }
            if let Err(error) = transaction.mark_load_in_progress() {
                rollback_installing_private_oram_recovery(
                    dispatcher,
                    &context,
                    collection_name,
                    &key,
                    &state,
                    &staging,
                    &install_guard,
                    transaction,
                )
                .await?;
                return Err(error);
            }
        }
        PrivateOramExternalRecoveryInstallPhase::NewPromoted => {
            if let Err(error) = transaction.mark_load_in_progress() {
                rollback_installing_private_oram_recovery(
                    dispatcher,
                    &context,
                    collection_name,
                    &key,
                    &state,
                    &staging,
                    &install_guard,
                    transaction,
                )
                .await?;
                return Err(error);
            }
        }
        PrivateOramExternalRecoveryInstallPhase::LoadInProgress
        | PrivateOramExternalRecoveryInstallPhase::Loaded => {}
        PrivateOramExternalRecoveryInstallPhase::RollbackInProgress
        | PrivateOramExternalRecoveryInstallPhase::RollbackComplete => {
            rollback_installing_private_oram_recovery(
                dispatcher,
                &context,
                collection_name,
                &key,
                &state,
                &staging,
                &install_guard,
                transaction,
            )
            .await?;
            return Err(invalid_external_recovery_state());
        }
        _ => return Err(invalid_external_recovery_state()),
    }

    let loaded = match install_guard.load_live_collection_strict().await {
        Ok(collection) => collection,
        Err(error)
            if transaction.phase() == PrivateOramExternalRecoveryInstallPhase::LoadInProgress =>
        {
            rollback_installing_private_oram_recovery(
                dispatcher,
                &context,
                collection_name,
                &key,
                &state,
                &staging,
                &install_guard,
                transaction,
            )
            .await?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    if let Err(error) = validate_loaded_private_oram_recovery_collection(&loaded, &context).await {
        loaded.stop_gracefully().await;
        if transaction.phase() == PrivateOramExternalRecoveryInstallPhase::LoadInProgress {
            rollback_installing_private_oram_recovery(
                dispatcher,
                &context,
                collection_name,
                &key,
                &state,
                &staging,
                &install_guard,
                transaction,
            )
            .await?;
        }
        return Err(error);
    }
    if transaction.phase() == PrivateOramExternalRecoveryInstallPhase::LoadInProgress
        && let Err(error) = transaction.mark_ready_to_commit()
    {
        loaded.stop_gracefully().await;
        rollback_installing_private_oram_recovery(
            dispatcher,
            &context,
            collection_name,
            &key,
            &state,
            &staging,
            &install_guard,
            transaction,
        )
        .await?;
        return Err(error);
    }

    let committed = PrivateOramExternalRecoveryState {
        committed_backup_generation: lease.backup_generation,
        committed_checkpoint_digest: Some(lease.checkpoint_digest.clone()),
        committed_install_intent_digest: Some(install_intent_digest.clone()),
        active_lease: None,
    };
    let commit = recovery_operation(
        PrivateOramExternalRecoveryPhase::Commit,
        key.clone(),
        Some(state),
        Some(committed.clone()),
        &context,
    );
    let commit_result = dispatcher
        .submit_private_oram_external_recovery(commit, None)
        .await;
    if dispatcher
        .private_oram_consensus_external_recovery(&key)?
        .as_ref()
        != Some(&committed)
    {
        loaded.stop_gracefully().await;
        return Err(commit_result
            .err()
            .unwrap_or_else(invalid_external_recovery_state));
    }

    if let Err(error) = transaction.mark_consensus_committed() {
        loaded.stop_gracefully().await;
        return Err(error);
    }
    if let Err(error) = transaction.finalize_committed() {
        loaded.stop_gracefully().await;
        return Err(error);
    }
    install_guard
        .publish_committed_collection(
            loaded,
            lease.backup_generation,
            &lease.checkpoint_digest,
            &install_intent_digest,
        )
        .await?;
    Ok(true)
}

pub async fn do_abort_private_oram_external_recovery(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    operation_token: &str,
) -> StorageResult<bool> {
    let operation_id_hash = private_oram_external_recovery_operation_id_hash(operation_token)?;
    let context = match resolve_private_oram_external_recovery_context(
        dispatcher,
        auth,
        settings,
        collection_name,
        Some(&operation_id_hash),
    )
    .await
    {
        Ok(context) => context,
        Err(_) => {
            resolve_private_oram_external_recovery_context(
                dispatcher,
                auth,
                settings,
                collection_name,
                None,
            )
            .await?
        }
    };
    let key = PrivateOramExternalRecoveryKey {
        collection_id: context.collection_id.clone(),
    };
    let staging = PrivateOramExternalRecoveryStaging::new(
        dispatcher
            .toc(auth, &new_unchecked_verification_pass())
            .storage_path(),
        &context.collection_id,
        &operation_id_hash,
    )?;
    let Some(expected) = dispatcher.private_oram_consensus_external_recovery(&key)? else {
        abort_staging_idempotent(&staging)?;
        return Ok(true);
    };
    let Some(lease) = expected.active_lease.as_ref() else {
        abort_staging_idempotent(&staging)?;
        return Ok(true);
    };
    validate_lease_owner_and_operation(lease, context.this_peer_id, &operation_id_hash)?;
    if lease.phase != PrivateOramExternalRecoveryLeasePhase::Staging {
        return Err(invalid_external_recovery_state());
    }
    staging.cancel_prepared_install_if_present(collection_name, lease)?;

    let new = if expected.committed_backup_generation == 0 {
        None
    } else {
        Some(PrivateOramExternalRecoveryState {
            committed_backup_generation: expected.committed_backup_generation,
            committed_checkpoint_digest: expected.committed_checkpoint_digest.clone(),
            committed_install_intent_digest: expected.committed_install_intent_digest.clone(),
            active_lease: None,
        })
    };
    let operation = recovery_operation(
        PrivateOramExternalRecoveryPhase::Abort,
        key.clone(),
        Some(expected.clone()),
        new.clone(),
        &context,
    );
    if let Err(error) = dispatcher
        .submit_private_oram_external_recovery(operation, None)
        .await
        && dispatcher.private_oram_consensus_external_recovery(&key)? != new
    {
        return Err(error);
    }
    abort_staging_idempotent(&staging)?;
    Ok(true)
}

async fn rollback_installing_private_oram_recovery(
    dispatcher: &Dispatcher,
    context: &PrivateOramExternalRecoveryContext,
    collection_name: &str,
    key: &PrivateOramExternalRecoveryKey,
    installing_state: &PrivateOramExternalRecoveryState,
    staging: &PrivateOramExternalRecoveryStaging,
    install_guard: &PrivateOramExternalRecoveryCollectionInstallGuard<'_>,
    transaction: PrivateOramExternalRecoveryInstallTransaction,
) -> StorageResult<()> {
    transaction.rollback_uncommitted()?;
    let installing_lease = installing_state
        .active_lease
        .as_ref()
        .filter(|lease| lease.phase == PrivateOramExternalRecoveryLeasePhase::Installing)
        .ok_or_else(invalid_external_recovery_state)?;
    let mut staging_lease = installing_lease.clone();
    staging_lease.phase = PrivateOramExternalRecoveryLeasePhase::Staging;
    staging_lease.install_intent_digest = None;
    let mut restored_state = installing_state.clone();
    restored_state.active_lease = Some(staging_lease.clone());
    let rollback = recovery_operation(
        PrivateOramExternalRecoveryPhase::RollbackInstall,
        key.clone(),
        Some(installing_state.clone()),
        Some(restored_state.clone()),
        context,
    );
    let rollback_result = dispatcher
        .submit_private_oram_external_recovery(rollback, None)
        .await;
    if dispatcher
        .private_oram_consensus_external_recovery(key)?
        .as_ref()
        != Some(&restored_state)
    {
        return Err(rollback_result
            .err()
            .unwrap_or_else(invalid_external_recovery_state));
    }
    staging.cancel_prepared_install_if_present(collection_name, &staging_lease)?;
    let collection = install_guard.load_live_collection_strict().await?;
    if let Err(error) = validate_loaded_private_oram_recovery_collection(&collection, context).await
    {
        collection.stop_gracefully().await;
        return Err(error);
    }
    install_guard.publish_fenced_collection(collection).await
}

async fn validate_loaded_private_oram_recovery_collection(
    collection: &Collection,
    context: &PrivateOramExternalRecoveryContext,
) -> StorageResult<()> {
    let state = collection.state().await;
    if state.config != context.config
        || state.resharding.is_some()
        || !state.transfers.is_empty()
        || state.shards.is_empty()
    {
        return Err(invalid_external_recovery_state());
    }

    let mut entries = Vec::with_capacity(state.shards.len());
    let mut metadata_local_shard_ids = Vec::new();
    for (shard_id, shard) in &state.shards {
        if shard.replicas.is_empty()
            || shard
                .replicas
                .values()
                .any(|replica_state| *replica_state != ReplicaState::Active)
        {
            return Err(invalid_external_recovery_state());
        }
        if shard.replicas.contains_key(&context.this_peer_id) {
            metadata_local_shard_ids.push(*shard_id);
        }
        entries.push(PrivateOramShardLayoutEntry {
            shard_id: *shard_id,
            shard_key: state.shards_key_mapping.shard_key(*shard_id),
            owner_peer_ids: shard.replicas.keys().copied().collect(),
        });
    }
    metadata_local_shard_ids.sort_unstable();
    let mut actual_local_shard_ids = collection.get_local_shards().await;
    actual_local_shard_ids.sort_unstable();
    let (owner_peer_ids, layout_digest) = canonical_private_oram_shard_layout_digest(
        &context.collection_id,
        state.config.params.sharding_method.unwrap_or_default(),
        &entries,
    )?;
    if metadata_local_shard_ids != context.source_shard_ids
        || actual_local_shard_ids != context.source_shard_ids
        || actual_local_shard_ids != metadata_local_shard_ids
        || owner_peer_ids != context.layout.owner_peer_ids
        || layout_digest != context.layout.layout_digest
    {
        return Err(invalid_external_recovery_state());
    }
    Ok(())
}

async fn resolve_active_private_oram_external_recovery(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    operation_token: &str,
    renew_if_expiring: bool,
    force_renew: bool,
    required_phase: Option<PrivateOramExternalRecoveryLeasePhase>,
) -> StorageResult<ActivePrivateOramExternalRecovery> {
    let operation_id_hash = private_oram_external_recovery_operation_id_hash(operation_token)?;
    let context = resolve_private_oram_external_recovery_context(
        dispatcher,
        auth,
        settings,
        collection_name,
        Some(&operation_id_hash),
    )
    .await?;
    let key = PrivateOramExternalRecoveryKey {
        collection_id: context.collection_id.clone(),
    };
    let state = dispatcher
        .private_oram_consensus_external_recovery(&key)?
        .ok_or_else(invalid_external_recovery_state)?;
    let mut lease = state
        .active_lease
        .clone()
        .ok_or_else(invalid_external_recovery_state)?;
    validate_active_lease(
        &lease,
        context.this_peer_id,
        &operation_id_hash,
        required_phase,
    )?;

    let now_unix = current_unix_secs()?;
    let renewed_expiry = now_unix
        .checked_add(PRIVATE_ORAM_EXTERNAL_RECOVERY_LEASE_SECS)
        .ok_or_else(invalid_external_recovery_request)?;
    let should_renew = (force_renew
        || renew_if_expiring
            && lease.expires_at_unix
                <= now_unix.saturating_add(PRIVATE_ORAM_EXTERNAL_RECOVERY_RENEW_WINDOW_SECS))
        && renewed_expiry > lease.expires_at_unix;
    if should_renew {
        let mut renewed = lease.clone();
        renewed.issued_at_unix = now_unix;
        renewed.expires_at_unix = renewed_expiry;
        let mut desired = state.clone();
        desired.active_lease = Some(renewed.clone());
        let operation = recovery_operation(
            PrivateOramExternalRecoveryPhase::Renew,
            key.clone(),
            Some(state.clone()),
            Some(desired.clone()),
            &context,
        );
        if let Err(error) = dispatcher
            .submit_private_oram_external_recovery(operation, None)
            .await
            && dispatcher
                .private_oram_consensus_external_recovery(&key)?
                .as_ref()
                != Some(&desired)
        {
            return Err(error);
        }
        lease = renewed;
    }

    let staging = PrivateOramExternalRecoveryStaging::new(
        dispatcher
            .toc(auth, &new_unchecked_verification_pass())
            .storage_path(),
        &context.collection_id,
        &operation_id_hash,
    )?;
    let status = staging.status_for_consensus_lease(
        &lease.checkpoint_digest,
        lease.backup_generation,
        lease.expires_at_unix,
    )?;
    Ok(ActivePrivateOramExternalRecovery {
        context,
        key,
        lease,
        staging,
        status,
    })
}

async fn resolve_private_oram_external_recovery_context(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    recovery_operation_id_hash: Option<&str>,
) -> StorageResult<PrivateOramExternalRecoveryContext> {
    let collection_pass = auth
        .check_global_access(
            AccessRequirements::new().manage(),
            "private_oram_external_recovery",
        )?
        .issue_pass(collection_name);
    let pass = new_unchecked_verification_pass();
    let toc = dispatcher.toc(auth, &pass);
    if !toc.is_distributed() {
        return Err(StorageError::bad_request(
            "private ORAM external recovery requires distributed mode",
        ));
    }
    let detached = recovery_operation_id_hash.and_then(|operation_id_hash| {
        toc.private_oram_external_recovery_detached_state(collection_name, operation_id_hash)
    });
    let (config, collection_id, source_shard_ids, observed_layout) =
        if let Some((detached_collection_id, detached)) = detached {
            if detached.resharding.is_some()
                || !detached.transfers.is_empty()
                || detached.shards.is_empty()
            {
                return Err(invalid_external_recovery_state());
            }
            let detached_id = detached.config.stable_crypto_id(collection_name)?;
            if detached_id != detached_collection_id {
                return Err(invalid_external_recovery_state());
            }
            let mut entries = Vec::with_capacity(detached.shards.len());
            let mut local_shard_ids = Vec::new();
            for (shard_id, shard) in &detached.shards {
                if shard.replicas.is_empty()
                    || shard
                        .replicas
                        .values()
                        .any(|state| *state != ReplicaState::Active)
                {
                    return Err(invalid_external_recovery_state());
                }
                if shard.replicas.contains_key(&toc.this_peer_id) {
                    local_shard_ids.push(*shard_id);
                }
                entries.push(PrivateOramShardLayoutEntry {
                    shard_id: *shard_id,
                    shard_key: detached.shards_key_mapping.shard_key(*shard_id),
                    owner_peer_ids: shard.replicas.keys().copied().collect(),
                });
            }
            local_shard_ids.sort_unstable();
            let layout = canonical_private_oram_shard_layout_digest(
                &detached_collection_id,
                detached.config.params.sharding_method.unwrap_or_default(),
                &entries,
            )?;
            (
                detached.config,
                detached_collection_id,
                local_shard_ids,
                layout,
            )
        } else {
            let collection = match recovery_operation_id_hash {
                Some(operation_id_hash) => {
                    toc.get_collection_for_private_oram_external_recovery(
                        &collection_pass,
                        operation_id_hash,
                    )
                    .await?
                }
                None => toc.get_collection(&collection_pass).await?,
            };
            toc.require_private_oram_snapshot_recovery_complete(&collection)?;
            let config = collection.config_snapshot().await;
            let collection_id = config.stable_crypto_id(collection_name)?;
            let collection_name_owned = collection_name.to_string();
            let observed_layout = dispatcher
                .private_oram_stable_shard_layout_digest(&collection_name_owned, &collection_id)
                .await?;
            let mut local_shard_ids = collection.get_local_shards().await;
            local_shard_ids.sort_unstable();
            (config, collection_id, local_shard_ids, observed_layout)
        };
    validate_recovered_collection_crypto_config(settings, collection_name, &config)?;
    let keys = private_oram_index_keys_for_config(&config, collection_name)?;
    if keys.is_empty() {
        return Err(StorageError::bad_request(
            "private ORAM external recovery requires a private ORAM collection",
        ));
    }

    let (owner_peer_ids, layout_digest) = observed_layout;
    let layout_key = PrivateOramLayoutKey {
        collection_id: collection_id.clone(),
    };
    let layout = dispatcher
        .private_oram_consensus_layout(&layout_key)?
        .ok_or_else(invalid_external_recovery_state)?;
    if layout.owner_peer_ids != owner_peer_ids || layout.layout_digest != layout_digest {
        return Err(invalid_external_recovery_state());
    }

    let mut index_states = Vec::with_capacity(keys.len());
    let mut digest_states = Vec::with_capacity(keys.len());
    for key in keys {
        if dispatcher
            .private_oram_consensus_session_lease(&key)?
            .is_some()
        {
            return Err(StorageError::bad_request(
                "private ORAM external recovery conflicts with an active session",
            ));
        }
        let state = dispatcher
            .private_oram_consensus_epoch(&key)?
            .ok_or_else(invalid_external_recovery_state)?;
        digest_states.push((key.clone(), state.clone()));
        index_states.push(PrivateOramLayoutIndexStateBinding { key, state });
    }
    let index_state_digest =
        canonical_private_oram_index_state_digest(&collection_id, &digest_states)?;
    if layout.index_state_digest != index_state_digest
        || dispatcher
            .private_oram_consensus_layout(&layout_key)?
            .as_ref()
            != Some(&layout)
    {
        return Err(invalid_external_recovery_state());
    }
    for binding in &index_states {
        if dispatcher
            .private_oram_consensus_epoch(&binding.key)?
            .as_ref()
            != Some(&binding.state)
        {
            return Err(invalid_external_recovery_state());
        }
    }

    if source_shard_ids.is_empty() {
        return Err(StorageError::bad_request(
            "private ORAM external recovery requires local source shards",
        ));
    }
    Ok(PrivateOramExternalRecoveryContext {
        collection_id,
        config,
        layout,
        index_states,
        source_shard_ids,
        this_peer_id: toc.this_peer_id,
    })
}

fn resolve_external_recovery_owner_public_key(
    settings: &Settings,
    config: &CollectionConfigInternal,
    signing_key_id: &str,
) -> StorageResult<Vec<u8>> {
    let encryption = config
        .params
        .effective_encryption()
        .ok_or_else(invalid_external_recovery_request)?;
    let mut resolved = None;
    for rule in encryption.rules.iter().filter(|rule| {
        matches!(
            rule.binding.as_deref(),
            Some(PRIVATE_HNSW_ORAM_BINDING) | Some(PRIVATE_RESULT_ORAM_BINDING)
        )
    }) {
        let public_key = resolve_rule_owner_public_key(settings, rule, signing_key_id)?;
        if resolved
            .as_ref()
            .is_some_and(|resolved: &Vec<u8>| resolved != &public_key)
        {
            return Err(StorageError::bad_request(
                "private ORAM external recovery owner signing key is inconsistent",
            ));
        }
        resolved = Some(public_key);
    }
    resolved.ok_or_else(invalid_external_recovery_request)
}

fn resolve_rule_owner_public_key(
    settings: &Settings,
    rule: &EncryptionRuleRef,
    signing_key_id: &str,
) -> StorageResult<Vec<u8>> {
    match rule.binding.as_deref() {
        Some(PRIVATE_HNSW_ORAM_BINDING) => {
            resolve_private_hnsw_external_recovery_owner_public_key(settings, rule, signing_key_id)
        }
        Some(PRIVATE_RESULT_ORAM_BINDING) => {
            resolve_private_result_oram_external_recovery_owner_public_key(
                settings,
                rule,
                signing_key_id,
            )
        }
        _ => Err(invalid_external_recovery_request()),
    }
}

fn validate_external_recovery_checkpoint(
    bundle: &PrivateOramExternalRecoveryCheckpointBundle,
    context: &PrivateOramExternalRecoveryContext,
    public_key: &[u8],
) -> StorageResult<()> {
    let checkpoint = &bundle.checkpoint;
    validate_private_oram_external_recovery_checkpoint(
        checkpoint,
        Some(&bundle.signature),
        PrivateOramRecoveryValidationContext {
            expected_collection_id: &context.collection_id,
            expected_backup_generation: checkpoint.backup_generation,
            expected_source_peer_id: context.this_peer_id,
            expected_source_shard_ids: &context.source_shard_ids,
            expected_layout_generation: context.layout.generation,
            expected_owner_peer_ids: &context.layout.owner_peer_ids,
            expected_layout_digest: &context.layout.layout_digest,
            expected_index_state_digest: &context.layout.index_state_digest,
            expected_snapshot_size_bytes: checkpoint.snapshot_size_bytes,
            expected_snapshot_sha256: &checkpoint.snapshot_sha256,
            expected_client_recovery_state_digest: &checkpoint.client_recovery_state_digest,
            expected_owner_signing_key_id: &checkpoint.owner_signing_key_id,
            public_key,
        },
    )
    .map_err(|_| {
        StorageError::bad_request("private ORAM external recovery checkpoint validation failed")
    })
}

fn recovered_snapshot_validator(settings: Settings) -> SnapshotConfigValidator {
    Arc::new(move |collection_name, config, collection_path| {
        validate_recovered_collection_crypto_config(&settings, collection_name, config)?;
        validate_recovered_private_hnsw_oram_snapshot_signatures(
            &settings,
            collection_name,
            config,
            collection_path,
        )?;
        validate_recovered_private_result_oram_snapshot_signatures(
            &settings,
            collection_name,
            config,
            collection_path,
        )
    })
}

fn recovery_operation(
    phase: PrivateOramExternalRecoveryPhase,
    key: PrivateOramExternalRecoveryKey,
    expected: Option<PrivateOramExternalRecoveryState>,
    new: Option<PrivateOramExternalRecoveryState>,
    context: &PrivateOramExternalRecoveryContext,
) -> PrivateOramExternalRecoveryOperation {
    PrivateOramExternalRecoveryOperation {
        phase,
        recovery: CompareAndSwapPrivateOramExternalRecovery { key, expected, new },
        layout: context.layout.clone(),
        index_states: context.index_states.clone(),
    }
}

fn validate_active_lease(
    lease: &PrivateOramExternalRecoveryLease,
    this_peer_id: PeerId,
    operation_id_hash: &str,
    required_phase: Option<PrivateOramExternalRecoveryLeasePhase>,
) -> StorageResult<()> {
    validate_lease_owner_and_operation(lease, this_peer_id, operation_id_hash)?;
    if required_phase.is_some_and(|required_phase| lease.phase != required_phase) {
        return Err(invalid_external_recovery_state());
    }
    let now_unix = current_unix_secs()?;
    if lease.issued_at_unix > now_unix || lease.expires_at_unix <= now_unix {
        return Err(invalid_external_recovery_state());
    }
    Ok(())
}

fn validate_lease_owner_and_operation(
    lease: &PrivateOramExternalRecoveryLease,
    this_peer_id: PeerId,
    operation_id_hash: &str,
) -> StorageResult<()> {
    if lease.owner_peer_id != this_peer_id || lease.operation_id_hash != operation_id_hash {
        return Err(invalid_external_recovery_state());
    }
    Ok(())
}

fn ensure_active_recovery_unchanged(
    dispatcher: &Dispatcher,
    key: &PrivateOramExternalRecoveryKey,
    lease: &PrivateOramExternalRecoveryLease,
) -> StorageResult<()> {
    let current = dispatcher
        .private_oram_consensus_external_recovery(key)?
        .and_then(|state| state.active_lease);
    if current.as_ref() != Some(lease) {
        return Err(invalid_external_recovery_state());
    }
    validate_active_lease(
        lease,
        dispatcher.this_peer_id(),
        &lease.operation_id_hash,
        None,
    )
}

fn abort_staging_idempotent(staging: &PrivateOramExternalRecoveryStaging) -> StorageResult<()> {
    match staging.abort() {
        Ok(()) | Err(StorageError::NotFound { .. }) => Ok(()),
        Err(error) => Err(error),
    }
}

fn current_unix_secs() -> StorageResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StorageError::service_error("private ORAM external recovery clock is invalid"))
}

fn invalid_external_recovery_request() -> StorageError {
    StorageError::bad_request("private ORAM external recovery request is invalid")
}

fn invalid_external_recovery_state() -> StorageError {
    StorageError::bad_request("private ORAM external recovery state is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mutation_execution_serializes_only_the_same_collection() {
        let first_key = PrivateOramMutationKey {
            collection_id: "collection-a".to_string(),
        };
        let other_key = PrivateOramMutationKey {
            collection_id: "collection-b".to_string(),
        };
        let first_guard = acquire_private_oram_mutation_execution_v2(&first_key)
            .await
            .unwrap();

        let (acquired_tx, mut acquired_rx) = tokio::sync::oneshot::channel();
        let waiting_key = first_key.clone();
        let waiting = tokio::spawn(async move {
            let guard = acquire_private_oram_mutation_execution_v2(&waiting_key)
                .await
                .unwrap();
            acquired_tx.send(()).unwrap();
            guard
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut acquired_rx)
                .await
                .is_err()
        );
        let other_guard = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            acquire_private_oram_mutation_execution_v2(&other_key),
        )
        .await
        .unwrap()
        .unwrap();
        drop(other_guard);

        drop(first_guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut acquired_rx)
            .await
            .unwrap()
            .unwrap();
        drop(waiting.await.unwrap());
    }

    #[test]
    fn begin_response_debug_redacts_operation_token() {
        let token = "private-oram-external-recovery-token-sentinel";
        let response = PrivateOramExternalRecoveryBeginResponse {
            operation_token: token.to_string(),
            status: PrivateOramExternalRecoveryStagingStatus {
                phase: storage::content_manager::snapshots::private_oram_external_recovery::PrivateOramExternalRecoveryStagingPhase::Uploading,
                backup_generation: 7,
                bytes_received: 0,
                snapshot_size_bytes: 8,
                next_chunk_index: 0,
                chunk_size_bytes: 8,
                lease_expires_at_unix: 100,
            },
        };
        let rendered = format!("{response:?}");
        assert!(!rendered.contains(token));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn active_lease_validation_rejects_wrong_operation_without_disclosure() {
        let now = current_unix_secs().unwrap();
        let operation_id_hash = "A".repeat(43);
        let lease = PrivateOramExternalRecoveryLease {
            owner_peer_id: 11,
            operation_id_hash: operation_id_hash.clone(),
            checkpoint_digest: "B".repeat(43),
            backup_generation: 7,
            issued_at_unix: now,
            expires_at_unix: now + 10,
            install_intent_digest: None,
            phase: PrivateOramExternalRecoveryLeasePhase::Staging,
        };
        let error = validate_active_lease(&lease, 11, &"C".repeat(43), None)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(&operation_id_hash));
        assert!(!error.contains(&lease.checkpoint_digest));
    }

    #[test]
    fn staging_mutations_reject_an_installing_lease() {
        let now = current_unix_secs().unwrap();
        let operation_id_hash = "A".repeat(43);
        let lease = PrivateOramExternalRecoveryLease {
            owner_peer_id: 11,
            operation_id_hash: operation_id_hash.clone(),
            checkpoint_digest: "B".repeat(43),
            backup_generation: 7,
            issued_at_unix: now,
            expires_at_unix: now + 10,
            install_intent_digest: Some("C".repeat(43)),
            phase: PrivateOramExternalRecoveryLeasePhase::Installing,
        };

        assert!(
            validate_active_lease(
                &lease,
                11,
                &operation_id_hash,
                Some(PrivateOramExternalRecoveryLeasePhase::Staging),
            )
            .is_err()
        );
    }

    #[test]
    fn expired_lease_owner_can_abort_but_cannot_continue_recovery() {
        let now = current_unix_secs().unwrap();
        let operation_id_hash = "A".repeat(43);
        let lease = PrivateOramExternalRecoveryLease {
            owner_peer_id: 11,
            operation_id_hash: operation_id_hash.clone(),
            checkpoint_digest: "B".repeat(43),
            backup_generation: 7,
            issued_at_unix: now.saturating_sub(20),
            expires_at_unix: now.saturating_sub(10),
            install_intent_digest: None,
            phase: PrivateOramExternalRecoveryLeasePhase::Staging,
        };

        validate_lease_owner_and_operation(&lease, 11, &operation_id_hash).unwrap();
        assert!(validate_active_lease(&lease, 11, &operation_id_hash, None).is_err());
    }
}
