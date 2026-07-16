use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use api::grpc::qdrant_internal_server::QdrantInternal;
use api::grpc::{
    CompletePrivateOramWritebackRequest, CompletePrivateOramWritebackResponse, GetAuditLogRequest,
    GetAuditLogResponse, GetConsensusCommitRequest, GetConsensusCommitResponse,
    GetTelemetryRequest, GetTelemetryResponse, InstallPrivateOramIndexRequest,
    InstallPrivateOramIndexResponse, InstallPrivateOramLiveReplicaRequest,
    InstallPrivateOramLiveReplicaResponse, PeerTelemetry, PreparePrivateOramWritebackRequest,
    PreparePrivateOramWritebackResponse, PrivateOramReplicationEpochState,
    PrivateOramReplicationIndexKind, PrivateOramReplicationTransition,
    WaitOnConsensusCommitRequest, WaitOnConsensusCommitResponse,
    install_private_oram_index_request, install_private_oram_live_replica_request,
};
use chrono::DateTime;
use collection::config::{
    CollectionConfigInternal, EncryptionSelector, encryption_rule_uses_private_hnsw_oram,
    encryption_rule_uses_private_result_oram,
};
use collection::operations::verification::new_unchecked_verification_pass;
use collection::private_hnsw_oram_store::{
    PrivateHnswOramConsensusWriteback, PrivateHnswOramEpochState,
    PrivateHnswOramLiveReplicationBundle, PrivateHnswOramWritebackBatch,
};
use collection::private_result_oram_store::{
    PrivateResultOramConsensusWriteback, PrivateResultOramEpochState,
    PrivateResultOramLiveReplicationBundle, PrivateResultOramWritebackBatch,
};
use collection::shards::shard::PeerId;
use common::types::{DetailsLevel, TelemetryDetail};
use data_encoding::BASE64URL_NOPAD;
use prost::Message;
use qdrant_sec::{
    PrivateHnswOramBucket, PrivateHnswOramSignature, PrivateHnswOramUploadBundle,
    PrivateResultOramBucket, PrivateResultOramSignature, PrivateResultOramUploadBundle,
    ResultPrivacyMode,
};
use sha2::{Digest, Sha256};
use storage::audit::AuditConfig;
use storage::audit_reader::{AuditLogQuery, read_local_audit_logs};
use storage::content_manager::consensus_manager::ConsensusStateRef;
use storage::content_manager::consensus_ops::{
    CompareAndSwapPrivateOramSessionLease, PrivateOramConsensusEpoch, PrivateOramEpochKey,
    PrivateOramIndexKind, PrivateOramSessionLease,
};
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::{
    Dispatcher, PrivateOramEpochRef, PrivateOramPendingTransitionRef, PrivateOramRecoveryAction,
    classify_private_oram_recovery,
};
use storage::rbac::{Access, Auth};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::common::telemetry::TelemetryCollector;
use crate::common::{private_hnsw, private_result_oram};
use crate::settings::Settings;
use crate::tonic::api::{private_hnsw_api, private_result_oram_api};

pub struct QdrantInternalService {
    /// Telemetry collector
    telemetry_collector: Arc<Mutex<TelemetryCollector>>,
    /// Qdrant settings
    settings: Settings,
    /// Consensus state
    consensus_state: ConsensusStateRef,
    /// Audit configuration
    audit_config: Option<AuditConfig>,
    toc: Arc<TableOfContent>,
    private_oram_replication_lock: Mutex<()>,
}

impl QdrantInternalService {
    pub fn new(
        telemetry_collector: Arc<Mutex<TelemetryCollector>>,
        settings: Settings,
        consensus_state: ConsensusStateRef,
        toc: Arc<TableOfContent>,
    ) -> Self {
        let audit_config = settings.audit.clone();
        Self {
            telemetry_collector,
            settings,
            consensus_state,
            audit_config,
            toc,
            private_oram_replication_lock: Mutex::new(()),
        }
    }

    async fn complete_private_oram_writeback(
        &self,
        request: CompletePrivateOramWritebackRequest,
        abort: bool,
    ) -> Result<CompletePrivateOramWritebackResponse, Status> {
        validate_completion_request_shape(&request)?;
        let kind = PrivateOramReplicationIndexKind::try_from(request.index_kind)
            .map_err(|_| Status::invalid_argument("private ORAM index kind is invalid"))?;
        let transition = required_transition(request.transition)?;
        let old = transition.old.expect("validated transition old state");
        let new = transition.new.expect("validated transition new state");
        let auth = Auth::new_internal(Access::full("private ORAM replication"));
        let _lock = self.private_oram_replication_lock.lock().await;

        let completed = match kind {
            PrivateOramReplicationIndexKind::Hnsw => {
                if request.vector_name.is_empty() || request.vector_name.len() > 255 {
                    return Err(Status::invalid_argument(
                        "private HNSW ORAM replication vector name is invalid",
                    ));
                }
                private_hnsw::do_complete_private_hnsw_replica_writeback(
                    &self.toc,
                    &auth,
                    &self.settings,
                    &request.collection_name,
                    &request.vector_name,
                    &request.collection_id,
                    &request.signing_key_id,
                    &PrivateHnswOramConsensusWriteback {
                        old: PrivateHnswOramEpochState {
                            index_epoch: old.index_epoch,
                            root_hash: old.root_hash,
                        },
                        new: PrivateHnswOramEpochState {
                            index_epoch: new.index_epoch,
                            root_hash: new.root_hash,
                        },
                        writeback_digest: transition.writeback_digest,
                    },
                    abort,
                )
                .await?
            }
            PrivateOramReplicationIndexKind::Result => {
                if !request.vector_name.is_empty() {
                    return Err(Status::invalid_argument(
                        "private result ORAM replication vector name must be empty",
                    ));
                }
                private_result_oram::do_complete_private_result_oram_replica_writeback(
                    &self.toc,
                    &auth,
                    &self.settings,
                    &request.collection_name,
                    &request.collection_id,
                    &request.signing_key_id,
                    &PrivateResultOramConsensusWriteback {
                        old: PrivateResultOramEpochState {
                            index_epoch: old.index_epoch,
                            root_hash: old.root_hash,
                        },
                        new: PrivateResultOramEpochState {
                            index_epoch: new.index_epoch,
                            root_hash: new.root_hash,
                        },
                        writeback_digest: transition.writeback_digest,
                    },
                    abort,
                )
                .await?
            }
            PrivateOramReplicationIndexKind::Unspecified => {
                return Err(Status::invalid_argument(
                    "private ORAM index kind is required",
                ));
            }
        };
        Ok(CompletePrivateOramWritebackResponse { completed })
    }
}

const MAX_PRIVATE_ORAM_REPLICATION_BUCKETS: usize = 65_536;
const MAX_PRIVATE_ORAM_REPLICATION_CIPHERTEXT_CHARS: usize = 32 * 1024 * 1024;
const MAX_PRIVATE_ORAM_REPLICATION_TOTAL_CIPHERTEXT_CHARS: usize = 512 * 1024 * 1024;

fn validate_replication_request_bounds(
    request: &PreparePrivateOramWritebackRequest,
) -> Result<(), Status> {
    if request.collection_name.is_empty()
        || request.collection_name.len() > 255
        || request.collection_id.is_empty()
        || request.collection_id.len() > 255
        || request.updated_buckets.is_empty()
        || request.updated_buckets.len() > MAX_PRIVATE_ORAM_REPLICATION_BUCKETS
    {
        return Err(Status::invalid_argument(
            "private ORAM replication request shape is invalid",
        ));
    }
    let mut total = 0usize;
    for bucket in &request.updated_buckets {
        if u16::try_from(bucket.version).is_err()
            || bucket.ciphertext.len() > MAX_PRIVATE_ORAM_REPLICATION_CIPHERTEXT_CHARS
            || bucket.ciphertext_sha256.len() > 128
            || bucket.bucket_commitment.len() > 128
        {
            return Err(Status::invalid_argument(
                "private ORAM replication bucket shape is invalid",
            ));
        }
        total = total.checked_add(bucket.ciphertext.len()).ok_or_else(|| {
            Status::invalid_argument("private ORAM replication request is oversized")
        })?;
    }
    if total > MAX_PRIVATE_ORAM_REPLICATION_TOTAL_CIPHERTEXT_CHARS {
        return Err(Status::invalid_argument(
            "private ORAM replication request is oversized",
        ));
    }
    Ok(())
}

fn validate_completion_request_shape(
    request: &CompletePrivateOramWritebackRequest,
) -> Result<(), Status> {
    if request.collection_name.is_empty()
        || request.collection_name.len() > 255
        || request.collection_id.is_empty()
        || request.collection_id.len() > 255
        || request.signing_key_id.is_empty()
        || request.signing_key_id.len() > 128
    {
        return Err(Status::invalid_argument(
            "private ORAM completion request shape is invalid",
        ));
    }
    Ok(())
}

fn validate_initial_install_bucket_bounds(
    bucket_sizes: impl IntoIterator<Item = (usize, usize, usize)>,
) -> Result<(), Status> {
    let mut count = 0usize;
    let mut total = 0usize;
    for (ciphertext, ciphertext_hash, commitment) in bucket_sizes {
        count = count.checked_add(1).ok_or_else(|| {
            Status::invalid_argument("private ORAM initial install request is oversized")
        })?;
        if ciphertext > MAX_PRIVATE_ORAM_REPLICATION_CIPHERTEXT_CHARS
            || ciphertext_hash > 128
            || commitment > 128
        {
            return Err(Status::invalid_argument(
                "private ORAM initial install bucket shape is invalid",
            ));
        }
        total = total.checked_add(ciphertext).ok_or_else(|| {
            Status::invalid_argument("private ORAM initial install request is oversized")
        })?;
    }
    if count == 0
        || count > MAX_PRIVATE_ORAM_REPLICATION_BUCKETS
        || total > MAX_PRIVATE_ORAM_REPLICATION_TOTAL_CIPHERTEXT_CHARS
    {
        return Err(Status::invalid_argument(
            "private ORAM initial install request is oversized",
        ));
    }
    Ok(())
}

fn validate_live_install_bucket_bounds(
    bucket_sizes: impl IntoIterator<Item = (usize, usize, usize)>,
) -> Result<(), Status> {
    validate_initial_install_bucket_bounds(bucket_sizes)
        .map_err(|_| Status::invalid_argument("private ORAM live install bucket set is invalid"))
}

fn required_live_install_current(
    current: Option<PrivateOramReplicationEpochState>,
) -> Result<PrivateOramReplicationEpochState, Status> {
    let current = current.ok_or_else(|| {
        Status::invalid_argument("private ORAM live install current state is required")
    })?;
    let decoded = BASE64URL_NOPAD
        .decode(current.root_hash.as_bytes())
        .map_err(|_| {
            Status::invalid_argument("private ORAM live install current state is invalid")
        })?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != current.root_hash {
        return Err(Status::invalid_argument(
            "private ORAM live install current state is invalid",
        ));
    }
    Ok(current)
}

fn validate_live_install_digest(writeback_digest: Option<&str>) -> Result<(), Status> {
    let Some(writeback_digest) = writeback_digest else {
        return Ok(());
    };
    let decoded = BASE64URL_NOPAD
        .decode(writeback_digest.as_bytes())
        .map_err(|_| Status::invalid_argument("private ORAM live install digest is invalid"))?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != writeback_digest {
        return Err(Status::invalid_argument(
            "private ORAM live install digest is invalid",
        ));
    }
    Ok(())
}

fn validate_live_install_transfer_lease(
    lease: Option<&PrivateOramSessionLease>,
    transfer_lease_id_hash: &str,
    now_unix: u64,
) -> Result<(), Status> {
    if !transfer_lease_id_hash.is_empty() {
        let decoded = BASE64URL_NOPAD
            .decode(transfer_lease_id_hash.as_bytes())
            .map_err(|_| {
                Status::invalid_argument(
                    "private ORAM live install transfer reservation is invalid",
                )
            })?;
        if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != transfer_lease_id_hash {
            return Err(Status::invalid_argument(
                "private ORAM live install transfer reservation is invalid",
            ));
        }
    }

    let active_lease = lease.filter(|lease| lease.expires_at_unix > now_unix);
    match (active_lease, transfer_lease_id_hash.is_empty()) {
        (None, true) => Ok(()),
        (Some(lease), false) if lease.lease_id_hash == transfer_lease_id_hash => Ok(()),
        _ => Err(Status::failed_precondition(
            "private ORAM live install transfer reservation does not match consensus",
        )),
    }
}

const BYTES_PER_MIB: usize = 1024 * 1024;
const PRIVATE_ORAM_SESSION_LEASE_HASH_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-session-lease-id/v1";
const PRIVATE_ORAM_SESSION_LEASE_RENEW_SECS: u64 = 300;
const PRIVATE_ORAM_TRANSFER_RESERVATION_SECS: u64 = 3_600;

fn validate_private_oram_wire_request_budget(
    request: &impl Message,
    max_request_bytes: usize,
    error_message: &'static str,
) -> Result<(), StorageError> {
    if max_request_bytes == 0 || request.encoded_len() > max_request_bytes {
        return Err(StorageError::bad_request(error_message));
    }
    Ok(())
}

pub(crate) fn private_oram_session_lease_hash(session_id: &str) -> Result<String, StorageError> {
    if session_id.is_empty() || session_id.len() > 256 {
        return Err(StorageError::bad_request(
            "private ORAM session lease id is invalid",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_SESSION_LEASE_HASH_DOMAIN);
    hasher.update((session_id.len() as u64).to_be_bytes());
    hasher.update(session_id.as_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub(crate) async fn acquire_private_oram_session_lease(
    dispatcher: &Dispatcher,
    key: PrivateOramEpochKey,
    session_id: &str,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> Result<PrivateOramSessionLease, StorageError> {
    if expires_at_unix <= issued_at_unix {
        return Err(StorageError::bad_request(
            "private ORAM session lease interval is invalid",
        ));
    }
    let current = dispatcher.private_oram_consensus_session_lease(&key)?;
    if current
        .as_ref()
        .is_some_and(|lease| lease.expires_at_unix > issued_at_unix)
    {
        return Err(StorageError::bad_request(
            "private ORAM session lease is already active",
        ));
    }
    let lease = PrivateOramSessionLease {
        owner_peer_id: dispatcher.this_peer_id(),
        lease_id_hash: private_oram_session_lease_hash(session_id)?,
        issued_at_unix,
        expires_at_unix,
    };
    dispatcher
        .submit_private_oram_session_lease_cas(
            CompareAndSwapPrivateOramSessionLease {
                key,
                expected: current,
                new: Some(lease.clone()),
            },
            None,
        )
        .await?;
    Ok(lease)
}

pub(crate) fn require_private_oram_session_lease(
    dispatcher: &Dispatcher,
    key: &PrivateOramEpochKey,
    session_id: &str,
    now_unix: u64,
) -> Result<PrivateOramSessionLease, StorageError> {
    let lease = dispatcher
        .private_oram_consensus_session_lease(key)?
        .ok_or_else(|| StorageError::bad_request("private ORAM session lease is missing"))?;
    if lease.owner_peer_id != dispatcher.this_peer_id()
        || lease.lease_id_hash != private_oram_session_lease_hash(session_id)?
        || lease.expires_at_unix <= now_unix
    {
        return Err(StorageError::bad_request(
            "private ORAM session lease does not match active session",
        ));
    }
    Ok(lease)
}

fn renewed_private_oram_session_lease(
    current: &PrivateOramSessionLease,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> Result<PrivateOramSessionLease, StorageError> {
    if issued_at_unix < current.issued_at_unix
        || expires_at_unix <= issued_at_unix
        || expires_at_unix <= current.expires_at_unix
    {
        return Err(StorageError::bad_request(
            "private ORAM session lease renewal interval is invalid",
        ));
    }
    Ok(PrivateOramSessionLease {
        owner_peer_id: current.owner_peer_id,
        lease_id_hash: current.lease_id_hash.clone(),
        issued_at_unix,
        expires_at_unix,
    })
}

pub(crate) async fn renew_private_oram_session_lease(
    dispatcher: &Dispatcher,
    key: PrivateOramEpochKey,
    session_id: &str,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> Result<PrivateOramSessionLease, StorageError> {
    let current = require_private_oram_session_lease(dispatcher, &key, session_id, issued_at_unix)?;
    let renewed = renewed_private_oram_session_lease(&current, issued_at_unix, expires_at_unix)?;
    dispatcher
        .submit_private_oram_session_lease_cas(
            CompareAndSwapPrivateOramSessionLease {
                key,
                expected: Some(current),
                new: Some(renewed.clone()),
            },
            None,
        )
        .await?;
    Ok(renewed)
}

pub(crate) async fn release_private_oram_session_lease(
    dispatcher: &Dispatcher,
    key: PrivateOramEpochKey,
    session_id: &str,
) -> Result<(), StorageError> {
    let lease = dispatcher
        .private_oram_consensus_session_lease(&key)?
        .ok_or_else(|| StorageError::bad_request("private ORAM session lease is missing"))?;
    if lease.owner_peer_id != dispatcher.this_peer_id()
        || lease.lease_id_hash != private_oram_session_lease_hash(session_id)?
    {
        return Err(StorageError::bad_request(
            "private ORAM session lease does not match active session",
        ));
    }
    dispatcher
        .submit_private_oram_session_lease_cas(
            CompareAndSwapPrivateOramSessionLease {
                key,
                expected: Some(lease),
                new: None,
            },
            None,
        )
        .await
}

pub(crate) struct PrivateOramTransferReservation {
    session_id: String,
    keys: Vec<PrivateOramEpochKey>,
}

pub(crate) fn private_oram_transfer_index_keys(
    config: &CollectionConfigInternal,
    collection_name: &str,
) -> Result<Vec<PrivateOramEpochKey>, StorageError> {
    let collection_id = config.stable_crypto_id(collection_name)?;
    let Some(encryption) = config.params.effective_encryption() else {
        return Ok(Vec::new());
    };
    let mut hnsw_vectors = BTreeSet::new();
    let mut has_result_payload = false;
    for rule in &encryption.rules {
        if encryption_rule_uses_private_hnsw_oram(rule) {
            let EncryptionSelector::VectorNames { names } = &rule.selector else {
                return Err(StorageError::bad_request(
                    "private ORAM transfer configuration is invalid",
                ));
            };
            hnsw_vectors.extend(names.iter().cloned());
        } else if encryption_rule_uses_private_result_oram(rule) {
            has_result_payload = true;
        }
    }

    let mut keys = hnsw_vectors
        .into_iter()
        .map(|index_name| PrivateOramEpochKey {
            collection_id: collection_id.clone(),
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name,
        })
        .collect::<Vec<_>>();
    if has_result_payload {
        keys.push(PrivateOramEpochKey {
            collection_id,
            index_kind: PrivateOramIndexKind::ResultPayload,
            index_name: String::new(),
        });
    }
    Ok(keys)
}

async fn release_private_oram_transfer_reservation_keys(
    dispatcher: &Dispatcher,
    keys: &[PrivateOramEpochKey],
    session_id: &str,
) -> Result<(), StorageError> {
    let mut first_error = None;
    for key in keys.iter().rev() {
        if let Err(error) =
            release_private_oram_session_lease(dispatcher, key.clone(), session_id).await
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

pub(crate) async fn prepare_private_oram_shard_transfer(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    config: &CollectionConfigInternal,
    target_peer: PeerId,
) -> Result<PrivateOramTransferReservation, StorageError> {
    let keys = private_oram_transfer_index_keys(config, collection_name)?;
    if keys.is_empty() {
        return Err(StorageError::bad_request(
            "private ORAM transfer requires at least one encrypted ORAM index",
        ));
    }
    let session_id = Uuid::new_v4().to_string();
    let lease_id_hash = private_oram_session_lease_hash(&session_id)?;
    let issued_at_unix = current_private_oram_unix_secs()?;
    let expires_at_unix = issued_at_unix
        .checked_add(PRIVATE_ORAM_TRANSFER_RESERVATION_SECS)
        .ok_or_else(|| StorageError::service_error("private ORAM transfer clock overflow"))?;

    let mut acquired_keys = Vec::with_capacity(keys.len());
    for key in &keys {
        if let Err(error) = acquire_private_oram_session_lease(
            dispatcher,
            key.clone(),
            &session_id,
            issued_at_unix,
            expires_at_unix,
        )
        .await
        {
            if release_private_oram_transfer_reservation_keys(
                dispatcher,
                &acquired_keys,
                &session_id,
            )
            .await
            .is_err()
            {
                log::warn!(
                    "failed to release private ORAM transfer reservation after lease acquisition failure"
                );
            }
            return Err(error);
        }
        acquired_keys.push(key.clone());
    }

    for key in &keys {
        let install_result = match key.index_kind {
            PrivateOramIndexKind::Hnsw => {
                install_private_hnsw_live_replica_on_peer(
                    dispatcher,
                    auth,
                    settings,
                    collection_name,
                    &key.index_name,
                    target_peer,
                    &lease_id_hash,
                )
                .await
            }
            PrivateOramIndexKind::ResultPayload => {
                install_private_result_oram_live_replica_on_peer(
                    dispatcher,
                    auth,
                    settings,
                    collection_name,
                    target_peer,
                    &lease_id_hash,
                )
                .await
            }
        };
        if let Err(error) = install_result {
            if release_private_oram_transfer_reservation_keys(
                dispatcher,
                &acquired_keys,
                &session_id,
            )
            .await
            .is_err()
            {
                log::warn!(
                    "failed to release private ORAM transfer reservation after live install failure"
                );
            }
            return Err(error);
        }
    }

    Ok(PrivateOramTransferReservation {
        session_id,
        keys: acquired_keys,
    })
}

pub(crate) async fn release_private_oram_transfer_reservation(
    dispatcher: &Dispatcher,
    reservation: &PrivateOramTransferReservation,
) -> Result<(), StorageError> {
    release_private_oram_transfer_reservation_keys(
        dispatcher,
        &reservation.keys,
        &reservation.session_id,
    )
    .await
}

async fn release_orphaned_private_oram_session_lease(
    dispatcher: &Dispatcher,
    key: PrivateOramEpochKey,
    has_local_session: bool,
) -> Result<(), StorageError> {
    if has_local_session {
        return Ok(());
    }
    let Some(lease) = dispatcher.private_oram_consensus_session_lease(&key)? else {
        return Ok(());
    };
    let now_unix = current_private_oram_unix_secs()?;
    if !private_oram_orphaned_lease_releasable(&lease, dispatcher.this_peer_id(), now_unix) {
        return Ok(());
    }
    let result = dispatcher
        .submit_private_oram_session_lease_cas(
            CompareAndSwapPrivateOramSessionLease {
                key: key.clone(),
                expected: Some(lease),
                new: None,
            },
            None,
        )
        .await;
    if result.is_err()
        && dispatcher
            .private_oram_consensus_session_lease(&key)?
            .is_none()
    {
        return Ok(());
    }
    result
}

fn private_oram_orphaned_lease_releasable(
    lease: &PrivateOramSessionLease,
    local_peer_id: PeerId,
    now_unix: u64,
) -> bool {
    lease.owner_peer_id == local_peer_id && lease.expires_at_unix <= now_unix
}

fn current_private_oram_unix_secs() -> Result<u64, StorageError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StorageError::service_error("system clock is before UNIX epoch"))
}

fn private_oram_renewal_expiry(
    current: &PrivateOramSessionLease,
    now_unix: u64,
) -> Result<u64, StorageError> {
    let ttl_expiry = now_unix
        .checked_add(PRIVATE_ORAM_SESSION_LEASE_RENEW_SECS)
        .ok_or_else(|| StorageError::service_error("private ORAM session lease overflowed"))?;
    let monotonic_expiry = current
        .expires_at_unix
        .checked_add(1)
        .ok_or_else(|| StorageError::service_error("private ORAM session lease overflowed"))?;
    Ok(ttl_expiry.max(monotonic_expiry))
}

fn classify_failed_private_oram_owner_writeback(
    consensus: Option<&PrivateOramConsensusEpoch>,
    old_epoch: u64,
    old_root_hash: &str,
    new_epoch: u64,
    new_root_hash: &str,
    writeback_digest: &str,
) -> Result<PrivateOramRecoveryAction, StorageError> {
    if consensus.is_some_and(|state| {
        state.index_epoch == new_epoch
            && state.root_hash == new_root_hash
            && state.writeback_digest.as_deref() == Some(writeback_digest)
    }) {
        return Ok(PrivateOramRecoveryAction::FinalizePending);
    }
    if consensus
        .is_some_and(|state| state.index_epoch == old_epoch && state.root_hash == old_root_hash)
    {
        return Ok(PrivateOramRecoveryAction::AbortPending);
    }
    Err(StorageError::service_error(
        "private ORAM consensus state is ambiguous after commit failure",
    ))
}

pub(crate) async fn coordinate_private_hnsw_initial_upload(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
) -> Result<(), StorageError> {
    let pass = new_unchecked_verification_pass();
    let max_bundle_bytes = settings
        .service
        .max_request_size_mb
        .saturating_mul(BYTES_PER_MIB);
    let bundle = private_hnsw::do_export_private_hnsw_initial_replication_bundle(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        vector_name,
        max_bundle_bytes,
    )
    .await?;
    let collection_id = bundle.manifest.collection_id.clone();
    let index_epoch = bundle.manifest.index_epoch;
    let root_hash = bundle.manifest.root_hash.clone();
    let request = InstallPrivateOramIndexRequest {
        collection_name: collection_name.to_string(),
        collection_id: collection_id.clone(),
        index_kind: PrivateOramReplicationIndexKind::Hnsw as i32,
        vector_name: vector_name.to_string(),
        bundle: Some(install_private_oram_index_request::Bundle::Hnsw(
            api::grpc::PrivateHnswInitialReplicationBundle {
                manifest: Some(private_hnsw_api::manifest_to_proto(bundle.manifest)),
                manifest_signature: Some(private_hnsw_api::signature_to_proto(
                    bundle.manifest_signature,
                )),
                buckets: bundle
                    .buckets
                    .into_iter()
                    .map(private_hnsw_api::bucket_to_proto)
                    .collect(),
            },
        )),
    };
    validate_private_oram_wire_request_budget(
        &request,
        max_bundle_bytes,
        "private HNSW ORAM initial install request exceeds service request limit",
    )?;
    dispatcher
        .coordinate_private_oram_initial_install(
            &collection_name.to_string(),
            PrivateOramEpochKey {
                collection_id,
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: vector_name.to_string(),
            },
            request,
            index_epoch,
            &root_hash,
            None,
        )
        .await
}

pub(crate) async fn coordinate_private_result_oram_initial_upload(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
) -> Result<(), StorageError> {
    let pass = new_unchecked_verification_pass();
    let max_bundle_bytes = settings
        .service
        .max_request_size_mb
        .saturating_mul(BYTES_PER_MIB);
    let bundle = private_result_oram::do_export_private_result_oram_initial_replication_bundle(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        max_bundle_bytes,
    )
    .await?;
    let collection_id = bundle.manifest.collection_id.clone();
    let index_epoch = bundle.manifest.index_epoch;
    let root_hash = bundle.manifest.root_hash.clone();
    let request = InstallPrivateOramIndexRequest {
        collection_name: collection_name.to_string(),
        collection_id: collection_id.clone(),
        index_kind: PrivateOramReplicationIndexKind::Result as i32,
        vector_name: String::new(),
        bundle: Some(install_private_oram_index_request::Bundle::Result(
            api::grpc::PrivateResultOramInitialReplicationBundle {
                manifest: Some(private_result_oram_api::manifest_to_proto(bundle.manifest)),
                manifest_signature: Some(private_result_oram_api::signature_to_proto(
                    bundle.manifest_signature,
                )),
                buckets: bundle
                    .buckets
                    .into_iter()
                    .map(private_result_oram_api::bucket_to_proto)
                    .collect(),
            },
        )),
    };
    validate_private_oram_wire_request_budget(
        &request,
        max_bundle_bytes,
        "private result ORAM initial install request exceeds service request limit",
    )?;
    dispatcher
        .coordinate_private_oram_initial_install(
            &collection_name.to_string(),
            PrivateOramEpochKey {
                collection_id,
                index_kind: PrivateOramIndexKind::ResultPayload,
                index_name: String::new(),
            },
            request,
            index_epoch,
            &root_hash,
            None,
        )
        .await
}

pub(crate) async fn install_private_hnsw_live_replica_on_peer(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    target_peer: PeerId,
    transfer_lease_id_hash: &str,
) -> Result<(), StorageError> {
    let pass = new_unchecked_verification_pass();
    let max_bundle_bytes = settings
        .service
        .max_request_size_mb
        .saturating_mul(BYTES_PER_MIB);
    let bundle = private_hnsw::do_export_private_hnsw_live_replication_bundle(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        vector_name,
        max_bundle_bytes,
    )
    .await?;
    let collection_id = bundle.manifest.collection_id.clone();
    let expected = PrivateOramConsensusEpoch {
        index_epoch: bundle.current.index_epoch,
        root_hash: bundle.current.root_hash.clone(),
        writeback_digest: bundle.writeback_digest.clone(),
    };
    let key = PrivateOramEpochKey {
        collection_id: collection_id.clone(),
        index_kind: PrivateOramIndexKind::Hnsw,
        index_name: vector_name.to_string(),
    };
    if dispatcher.private_oram_consensus_epoch(&key)?.as_ref() != Some(&expected) {
        return Err(StorageError::bad_request(
            "private HNSW ORAM live replica export does not match consensus",
        ));
    }
    let request = InstallPrivateOramLiveReplicaRequest {
        collection_name: collection_name.to_string(),
        collection_id,
        index_kind: PrivateOramReplicationIndexKind::Hnsw as i32,
        vector_name: vector_name.to_string(),
        bundle: Some(install_private_oram_live_replica_request::Bundle::Hnsw(
            api::grpc::PrivateHnswLiveReplicationBundle {
                manifest: Some(private_hnsw_api::manifest_to_proto(bundle.manifest)),
                manifest_signature: Some(private_hnsw_api::signature_to_proto(
                    bundle.manifest_signature,
                )),
                current: Some(PrivateOramReplicationEpochState {
                    index_epoch: bundle.current.index_epoch,
                    root_hash: bundle.current.root_hash,
                }),
                writeback_digest: bundle.writeback_digest,
                buckets: bundle
                    .buckets
                    .into_iter()
                    .map(private_hnsw_api::bucket_to_proto)
                    .collect(),
            },
        )),
        transfer_lease_id_hash: transfer_lease_id_hash.to_string(),
    };
    validate_private_oram_wire_request_budget(
        &request,
        max_bundle_bytes,
        "private HNSW ORAM live install request exceeds service request limit",
    )?;
    let response = dispatcher
        .toc(auth, &pass)
        .get_channel_service()
        .install_private_oram_live_replica(target_peer, request)
        .await?;
    validate_live_install_ack(target_peer, &expected, response)
}

pub(crate) async fn install_private_result_oram_live_replica_on_peer(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    target_peer: PeerId,
    transfer_lease_id_hash: &str,
) -> Result<(), StorageError> {
    let pass = new_unchecked_verification_pass();
    let max_bundle_bytes = settings
        .service
        .max_request_size_mb
        .saturating_mul(BYTES_PER_MIB);
    let bundle = private_result_oram::do_export_private_result_oram_live_replication_bundle(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        max_bundle_bytes,
    )
    .await?;
    let collection_id = bundle.manifest.collection_id.clone();
    let expected = PrivateOramConsensusEpoch {
        index_epoch: bundle.current.index_epoch,
        root_hash: bundle.current.root_hash.clone(),
        writeback_digest: bundle.writeback_digest.clone(),
    };
    let key = PrivateOramEpochKey {
        collection_id: collection_id.clone(),
        index_kind: PrivateOramIndexKind::ResultPayload,
        index_name: String::new(),
    };
    if dispatcher.private_oram_consensus_epoch(&key)?.as_ref() != Some(&expected) {
        return Err(StorageError::bad_request(
            "private result ORAM live replica export does not match consensus",
        ));
    }
    let request = InstallPrivateOramLiveReplicaRequest {
        collection_name: collection_name.to_string(),
        collection_id,
        index_kind: PrivateOramReplicationIndexKind::Result as i32,
        vector_name: String::new(),
        bundle: Some(install_private_oram_live_replica_request::Bundle::Result(
            api::grpc::PrivateResultOramLiveReplicationBundle {
                manifest: Some(private_result_oram_api::manifest_to_proto(bundle.manifest)),
                manifest_signature: Some(private_result_oram_api::signature_to_proto(
                    bundle.manifest_signature,
                )),
                current: Some(PrivateOramReplicationEpochState {
                    index_epoch: bundle.current.index_epoch,
                    root_hash: bundle.current.root_hash,
                }),
                writeback_digest: bundle.writeback_digest,
                buckets: bundle
                    .buckets
                    .into_iter()
                    .map(private_result_oram_api::bucket_to_proto)
                    .collect(),
            },
        )),
        transfer_lease_id_hash: transfer_lease_id_hash.to_string(),
    };
    validate_private_oram_wire_request_budget(
        &request,
        max_bundle_bytes,
        "private result ORAM live install request exceeds service request limit",
    )?;
    let response = dispatcher
        .toc(auth, &pass)
        .get_channel_service()
        .install_private_oram_live_replica(target_peer, request)
        .await?;
    validate_live_install_ack(target_peer, &expected, response)
}

fn validate_live_install_ack(
    target_peer: PeerId,
    expected: &PrivateOramConsensusEpoch,
    response: InstallPrivateOramLiveReplicaResponse,
) -> Result<(), StorageError> {
    if response.index_epoch == expected.index_epoch
        && response.root_hash == expected.root_hash
        && response.writeback_digest == expected.writeback_digest
    {
        return Ok(());
    }
    Err(StorageError::service_error(format!(
        "private ORAM live install acknowledgement is invalid on peer {target_peer}"
    )))
}

pub(crate) async fn recover_private_hnsw_replication(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
) -> Result<(), StorageError> {
    let pass = new_unchecked_verification_pass();
    let context = private_hnsw::do_inspect_private_hnsw_recovery(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        vector_name,
    )
    .await?;
    let key = PrivateOramEpochKey {
        collection_id: context.collection_id.clone(),
        index_kind: PrivateOramIndexKind::Hnsw,
        index_name: vector_name.to_string(),
    };
    let consensus = dispatcher.private_oram_consensus_epoch(&key)?;
    let pending = context
        .pending
        .as_ref()
        .map(|(_, transition)| PrivateOramPendingTransitionRef {
            old: PrivateOramEpochRef {
                index_epoch: transition.old.index_epoch,
                root_hash: &transition.old.root_hash,
            },
            new: PrivateOramEpochRef {
                index_epoch: transition.new.index_epoch,
                root_hash: &transition.new.root_hash,
            },
            writeback_digest: &transition.writeback_digest,
        });
    let action = classify_private_oram_recovery(
        consensus.as_ref(),
        PrivateOramEpochRef {
            index_epoch: context.current.index_epoch,
            root_hash: &context.current.root_hash,
        },
        pending,
    )?;
    let abort = match action {
        PrivateOramRecoveryAction::Clean => {
            let has_local_session =
                private_hnsw::private_hnsw_has_active_session(&context.collection_id, vector_name)?;
            release_orphaned_private_oram_session_lease(dispatcher, key, has_local_session).await?;
            return Ok(());
        }
        PrivateOramRecoveryAction::AbortPending => true,
        PrivateOramRecoveryAction::FinalizePending => false,
    };
    let (batch, transition) = context.pending.as_ref().ok_or_else(|| {
        StorageError::service_error("private HNSW ORAM recovery transition is unavailable")
    })?;
    dispatcher
        .complete_private_hnsw_oram_recovery_replicas(
            &collection_name.to_string(),
            &context.collection_id,
            vector_name,
            transition,
            &batch.commit_signature.key_id,
            abort,
        )
        .await?;
    if !context.complete_pending(transition, abort)? {
        return Err(StorageError::service_error(
            "private HNSW ORAM local recovery was not completed",
        ));
    }
    let has_local_session = private_hnsw::recover_private_hnsw_session_writeback(
        &context.collection_id,
        vector_name,
        if abort {
            &transition.old
        } else {
            &transition.new
        },
        abort,
    )?;
    release_orphaned_private_oram_session_lease(dispatcher, key, has_local_session).await?;
    Ok(())
}

pub(crate) async fn recover_private_result_oram_replication(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
) -> Result<(), StorageError> {
    let pass = new_unchecked_verification_pass();
    let context = private_result_oram::do_inspect_private_result_oram_recovery(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
    )
    .await?;
    let key = PrivateOramEpochKey {
        collection_id: context.collection_id.clone(),
        index_kind: PrivateOramIndexKind::ResultPayload,
        index_name: String::new(),
    };
    let consensus = dispatcher.private_oram_consensus_epoch(&key)?;
    let pending = context
        .pending
        .as_ref()
        .map(|(_, transition)| PrivateOramPendingTransitionRef {
            old: PrivateOramEpochRef {
                index_epoch: transition.old.index_epoch,
                root_hash: &transition.old.root_hash,
            },
            new: PrivateOramEpochRef {
                index_epoch: transition.new.index_epoch,
                root_hash: &transition.new.root_hash,
            },
            writeback_digest: &transition.writeback_digest,
        });
    let action = classify_private_oram_recovery(
        consensus.as_ref(),
        PrivateOramEpochRef {
            index_epoch: context.current.index_epoch,
            root_hash: &context.current.root_hash,
        },
        pending,
    )?;
    let abort = match action {
        PrivateOramRecoveryAction::Clean => {
            let has_local_session = private_result_oram::private_result_oram_has_active_session(
                &context.collection_id,
            )?;
            release_orphaned_private_oram_session_lease(dispatcher, key, has_local_session).await?;
            return Ok(());
        }
        PrivateOramRecoveryAction::AbortPending => true,
        PrivateOramRecoveryAction::FinalizePending => false,
    };
    let (batch, transition) = context.pending.as_ref().ok_or_else(|| {
        StorageError::service_error("private result ORAM recovery transition is unavailable")
    })?;
    dispatcher
        .complete_private_result_oram_recovery_replicas(
            &collection_name.to_string(),
            &context.collection_id,
            transition,
            &batch.commit_signature.key_id,
            abort,
        )
        .await?;
    if !context.complete_pending(transition, abort)? {
        return Err(StorageError::service_error(
            "private result ORAM local recovery was not completed",
        ));
    }
    let has_local_session = private_result_oram::recover_private_result_oram_session_writeback(
        &context.collection_id,
        if abort {
            &transition.old
        } else {
            &transition.new
        },
        abort,
    )?;
    release_orphaned_private_oram_session_lease(dispatcher, key, has_local_session).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn open_private_hnsw_session_coordinated(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    client_id: String,
    desired_epoch: u64,
    fixed_budget: bool,
    result_privacy: ResultPrivacyMode,
) -> Result<private_hnsw::PrivateHnswSessionResponse, StorageError> {
    recover_private_hnsw_replication(dispatcher, auth, settings, collection_name, vector_name)
        .await?;
    let pass = new_unchecked_verification_pass();
    let session = private_hnsw::do_open_private_hnsw_session_coordinated(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        vector_name,
        client_id,
        desired_epoch,
        fixed_budget,
        result_privacy,
    )
    .await?;
    let key = PrivateOramEpochKey {
        collection_id: session.collection_id.clone(),
        index_kind: PrivateOramIndexKind::Hnsw,
        index_name: vector_name.to_string(),
    };
    let lease_result = async {
        let consensus = dispatcher.private_oram_consensus_epoch(&key)?;
        if !consensus.as_ref().is_some_and(|state| {
            state.index_epoch == session.index_epoch && state.root_hash == session.root_hash
        }) {
            return Err(StorageError::service_error(
                "private HNSW ORAM local epoch/root does not match consensus",
            ));
        }
        let now_unix = current_private_oram_unix_secs()?;
        acquire_private_oram_session_lease(
            dispatcher,
            key,
            &session.session_id,
            now_unix,
            session.lease_expires_unix,
        )
        .await
        .map(|_| ())
    }
    .await;
    if let Err(error) = lease_result {
        let cleanup_pass = new_unchecked_verification_pass();
        private_hnsw::do_close_private_hnsw_session(
            dispatcher.toc(auth, &cleanup_pass),
            auth,
            settings,
            collection_name,
            vector_name,
            &session.session_id,
        )
        .await?;
        return Err(error);
    }
    Ok(session)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_private_hnsw_paths_coordinated(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
    index_epoch: u64,
    root_hash: &str,
    paths: Vec<String>,
    padding: private_hnsw::PrivateHnswReadPadding,
    client_signature: private_hnsw::PrivateHnswClientSignature,
) -> Result<private_hnsw::PrivateHnswReadPathsResponse, StorageError> {
    let now_unix = current_private_oram_unix_secs()?;
    let (collection_id, _) = private_hnsw::private_hnsw_session_consensus_lease_identity(
        vector_name,
        session_id,
        now_unix,
    )?;
    require_private_oram_session_lease(
        dispatcher,
        &PrivateOramEpochKey {
            collection_id,
            index_kind: PrivateOramIndexKind::Hnsw,
            index_name: vector_name.to_string(),
        },
        session_id,
        now_unix,
    )?;
    let pass = new_unchecked_verification_pass();
    private_hnsw::do_read_private_hnsw_paths_coordinated(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        vector_name,
        session_id,
        index_epoch,
        root_hash,
        paths,
        padding,
        client_signature,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_private_hnsw_paths_coordinated(
    dispatcher: &Dispatcher,
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
    commit_signature: private_hnsw::PrivateHnswClientSignature,
) -> Result<PrivateHnswOramEpochState, StorageError> {
    let now_unix = current_private_oram_unix_secs()?;
    let (collection_id, _) = private_hnsw::private_hnsw_session_consensus_lease_identity(
        vector_name,
        session_id,
        now_unix,
    )?;
    let key = PrivateOramEpochKey {
        collection_id: collection_id.clone(),
        index_kind: PrivateOramIndexKind::Hnsw,
        index_name: vector_name.to_string(),
    };
    let current_lease = require_private_oram_session_lease(dispatcher, &key, session_id, now_unix)?;
    let pass = new_unchecked_verification_pass();
    let context = private_hnsw::do_stage_private_hnsw_owner_writeback(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        vector_name,
        session_id,
        old_epoch,
        new_epoch,
        old_root_hash,
        new_root_hash,
        updated_buckets,
        commit_signature,
    )
    .await?;
    if context.collection_id() != collection_id {
        context.cancel_staged_session()?;
        return Err(StorageError::service_error(
            "private HNSW ORAM session identity changed during commit staging",
        ));
    }
    let lease_expires_unix = match private_oram_renewal_expiry(&current_lease, now_unix) {
        Ok(expires_at) => expires_at,
        Err(error) => {
            context.cancel_staged_session()?;
            return Err(error);
        }
    };
    if let Err(error) = renew_private_oram_session_lease(
        dispatcher,
        key.clone(),
        session_id,
        now_unix,
        lease_expires_unix,
    )
    .await
    {
        context.cancel_staged_session()?;
        return Err(error);
    }
    let batch = context.batch().clone();
    let transition = context.transition().clone();
    let prepare_context = context.clone();
    let abort_context = context.clone();
    let finalize_context = context.clone();
    let result = dispatcher
        .coordinate_private_hnsw_oram_writeback(
            collection_name.to_string(),
            collection_id,
            vector_name.to_string(),
            batch,
            transition.clone(),
            None,
            move || prepare_context.prepare_local(),
            move || abort_context.abort_local(),
            move || finalize_context.finalize_local(lease_expires_unix),
        )
        .await;
    match result {
        Ok(()) => Ok(transition.new),
        Err(coordinate_error) => {
            let consensus = dispatcher.private_oram_consensus_epoch(&key)?;
            match classify_failed_private_oram_owner_writeback(
                consensus.as_ref(),
                transition.old.index_epoch,
                &transition.old.root_hash,
                transition.new.index_epoch,
                &transition.new.root_hash,
                &transition.writeback_digest,
            )? {
                PrivateOramRecoveryAction::FinalizePending => {
                    dispatcher
                        .complete_private_hnsw_oram_recovery_replicas(
                            &collection_name.to_string(),
                            context.collection_id(),
                            vector_name,
                            &transition,
                            &context.batch().commit_signature.key_id,
                            false,
                        )
                        .await?;
                    context.finalize_local(lease_expires_unix)?;
                    Ok(transition.new)
                }
                PrivateOramRecoveryAction::AbortPending => {
                    let remote_abort = dispatcher
                        .complete_private_hnsw_oram_recovery_replicas(
                            &collection_name.to_string(),
                            context.collection_id(),
                            vector_name,
                            &transition,
                            &context.batch().commit_signature.key_id,
                            true,
                        )
                        .await;
                    let local_abort = context.abort_local();
                    remote_abort?;
                    local_abort?;
                    Err(coordinate_error)
                }
                PrivateOramRecoveryAction::Clean => Err(StorageError::service_error(
                    "private HNSW ORAM commit recovery classification is invalid",
                )),
            }
        }
    }
}

pub(crate) async fn close_private_hnsw_session_coordinated(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    vector_name: &str,
    session_id: &str,
) -> Result<bool, StorageError> {
    let now_unix = current_private_oram_unix_secs()?;
    let (collection_id, _) = private_hnsw::private_hnsw_session_consensus_lease_identity(
        vector_name,
        session_id,
        now_unix,
    )?;
    let key = PrivateOramEpochKey {
        collection_id,
        index_kind: PrivateOramIndexKind::Hnsw,
        index_name: vector_name.to_string(),
    };
    require_private_oram_session_lease(dispatcher, &key, session_id, now_unix)?;
    let pass = new_unchecked_verification_pass();
    let closed = private_hnsw::do_close_private_hnsw_session(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        vector_name,
        session_id,
    )
    .await?;
    release_private_oram_session_lease(dispatcher, key, session_id).await?;
    Ok(closed)
}

pub(crate) async fn open_private_result_oram_session_coordinated(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    client_id: String,
    desired_epoch: u64,
    fixed_budget: bool,
) -> Result<private_result_oram::PrivateResultOramSessionResponse, StorageError> {
    recover_private_result_oram_replication(dispatcher, auth, settings, collection_name).await?;
    let pass = new_unchecked_verification_pass();
    let session = private_result_oram::do_open_private_result_oram_session_coordinated(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        client_id,
        desired_epoch,
        fixed_budget,
    )
    .await?;
    let key = PrivateOramEpochKey {
        collection_id: session.collection_id.clone(),
        index_kind: PrivateOramIndexKind::ResultPayload,
        index_name: String::new(),
    };
    let lease_result = async {
        let consensus = dispatcher.private_oram_consensus_epoch(&key)?;
        if !consensus.as_ref().is_some_and(|state| {
            state.index_epoch == session.index_epoch && state.root_hash == session.root_hash
        }) {
            return Err(StorageError::service_error(
                "private result ORAM local epoch/root does not match consensus",
            ));
        }
        let now_unix = current_private_oram_unix_secs()?;
        acquire_private_oram_session_lease(
            dispatcher,
            key,
            &session.session_id,
            now_unix,
            session.lease_expires_unix,
        )
        .await
        .map(|_| ())
    }
    .await;
    if let Err(error) = lease_result {
        let cleanup_pass = new_unchecked_verification_pass();
        private_result_oram::do_close_private_result_oram_session(
            dispatcher.toc(auth, &cleanup_pass),
            auth,
            settings,
            collection_name,
            &session.session_id,
        )
        .await?;
        return Err(error);
    }
    Ok(session)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_private_result_oram_buckets_coordinated(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    session_id: &str,
    index_epoch: u64,
    root_hash: String,
    bucket_ids: Vec<u64>,
    read_signature: PrivateResultOramSignature,
) -> Result<private_result_oram::PrivateResultOramReadBucketsResponse, StorageError> {
    let now_unix = current_private_oram_unix_secs()?;
    let (collection_id, _) =
        private_result_oram::private_result_oram_session_consensus_lease_identity(
            session_id, now_unix,
        )?;
    require_private_oram_session_lease(
        dispatcher,
        &PrivateOramEpochKey {
            collection_id,
            index_kind: PrivateOramIndexKind::ResultPayload,
            index_name: String::new(),
        },
        session_id,
        now_unix,
    )?;
    let pass = new_unchecked_verification_pass();
    private_result_oram::do_read_private_result_oram_buckets_coordinated(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        session_id,
        index_epoch,
        root_hash,
        bucket_ids,
        read_signature,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_private_result_oram_buckets_coordinated(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    session_id: &str,
    old_epoch: u64,
    new_epoch: u64,
    old_root_hash: String,
    new_root_hash: String,
    updated_buckets: Vec<PrivateResultOramBucket>,
    commit_signature: PrivateResultOramSignature,
) -> Result<PrivateResultOramEpochState, StorageError> {
    let now_unix = current_private_oram_unix_secs()?;
    let (collection_id, _) =
        private_result_oram::private_result_oram_session_consensus_lease_identity(
            session_id, now_unix,
        )?;
    let key = PrivateOramEpochKey {
        collection_id: collection_id.clone(),
        index_kind: PrivateOramIndexKind::ResultPayload,
        index_name: String::new(),
    };
    let current_lease = require_private_oram_session_lease(dispatcher, &key, session_id, now_unix)?;
    let pass = new_unchecked_verification_pass();
    let context = private_result_oram::do_stage_private_result_oram_owner_writeback(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        session_id,
        old_epoch,
        new_epoch,
        old_root_hash,
        new_root_hash,
        updated_buckets,
        commit_signature,
    )
    .await?;
    if context.collection_id() != collection_id {
        context.cancel_staged_session()?;
        return Err(StorageError::service_error(
            "private result ORAM session identity changed during commit staging",
        ));
    }
    let lease_expires_unix = match private_oram_renewal_expiry(&current_lease, now_unix) {
        Ok(expires_at) => expires_at,
        Err(error) => {
            context.cancel_staged_session()?;
            return Err(error);
        }
    };
    if let Err(error) = renew_private_oram_session_lease(
        dispatcher,
        key.clone(),
        session_id,
        now_unix,
        lease_expires_unix,
    )
    .await
    {
        context.cancel_staged_session()?;
        return Err(error);
    }
    let batch = context.batch().clone();
    let transition = context.transition().clone();
    let prepare_context = context.clone();
    let abort_context = context.clone();
    let finalize_context = context.clone();
    let result = dispatcher
        .coordinate_private_result_oram_writeback(
            collection_name.to_string(),
            collection_id,
            batch,
            transition.clone(),
            None,
            move || prepare_context.prepare_local(),
            move || abort_context.abort_local(),
            move || finalize_context.finalize_local(lease_expires_unix),
        )
        .await;
    match result {
        Ok(()) => Ok(transition.new),
        Err(coordinate_error) => {
            let consensus = dispatcher.private_oram_consensus_epoch(&key)?;
            match classify_failed_private_oram_owner_writeback(
                consensus.as_ref(),
                transition.old.index_epoch,
                &transition.old.root_hash,
                transition.new.index_epoch,
                &transition.new.root_hash,
                &transition.writeback_digest,
            )? {
                PrivateOramRecoveryAction::FinalizePending => {
                    dispatcher
                        .complete_private_result_oram_recovery_replicas(
                            &collection_name.to_string(),
                            context.collection_id(),
                            &transition,
                            &context.batch().commit_signature.key_id,
                            false,
                        )
                        .await?;
                    context.finalize_local(lease_expires_unix)?;
                    Ok(transition.new)
                }
                PrivateOramRecoveryAction::AbortPending => {
                    let remote_abort = dispatcher
                        .complete_private_result_oram_recovery_replicas(
                            &collection_name.to_string(),
                            context.collection_id(),
                            &transition,
                            &context.batch().commit_signature.key_id,
                            true,
                        )
                        .await;
                    let local_abort = context.abort_local();
                    remote_abort?;
                    local_abort?;
                    Err(coordinate_error)
                }
                PrivateOramRecoveryAction::Clean => Err(StorageError::service_error(
                    "private result ORAM commit recovery classification is invalid",
                )),
            }
        }
    }
}

pub(crate) async fn close_private_result_oram_session_coordinated(
    dispatcher: &Dispatcher,
    auth: &Auth,
    settings: &Settings,
    collection_name: &str,
    session_id: &str,
) -> Result<bool, StorageError> {
    let now_unix = current_private_oram_unix_secs()?;
    let (collection_id, _) =
        private_result_oram::private_result_oram_session_consensus_lease_identity(
            session_id, now_unix,
        )?;
    let key = PrivateOramEpochKey {
        collection_id,
        index_kind: PrivateOramIndexKind::ResultPayload,
        index_name: String::new(),
    };
    require_private_oram_session_lease(dispatcher, &key, session_id, now_unix)?;
    let pass = new_unchecked_verification_pass();
    let closed = private_result_oram::do_close_private_result_oram_session(
        dispatcher.toc(auth, &pass),
        auth,
        settings,
        collection_name,
        session_id,
    )
    .await?;
    release_private_oram_session_lease(dispatcher, key, session_id).await?;
    Ok(closed)
}

fn required_transition(
    transition: Option<PrivateOramReplicationTransition>,
) -> Result<PrivateOramReplicationTransition, Status> {
    let transition = transition
        .ok_or_else(|| Status::invalid_argument("private ORAM transition is required"))?;
    let Some(old) = transition.old.as_ref() else {
        return Err(Status::invalid_argument(
            "private ORAM transition shape is invalid",
        ));
    };
    let Some(new) = transition.new.as_ref() else {
        return Err(Status::invalid_argument(
            "private ORAM transition shape is invalid",
        ));
    };
    if old.root_hash.is_empty()
        || old.root_hash.len() > 128
        || new.root_hash.is_empty()
        || new.root_hash.len() > 128
        || transition.writeback_digest.is_empty()
        || transition.writeback_digest.len() > 128
    {
        return Err(Status::invalid_argument(
            "private ORAM transition shape is invalid",
        ));
    }
    Ok(transition)
}

fn parse_audit_log_time(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<DateTime<chrono::Utc>>, Status> {
    value
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|_| Status::invalid_argument(format!("Invalid {field}")))
        })
        .transpose()
}

#[tonic::async_trait]
impl QdrantInternal for QdrantInternalService {
    async fn get_consensus_commit(
        &self,
        _: tonic::Request<GetConsensusCommitRequest>,
    ) -> Result<Response<GetConsensusCommitResponse>, Status> {
        let persistent = self.consensus_state.persistent.read();
        let commit = persistent.state.hard_state.commit as _;
        let term = persistent.state.hard_state.term as _;
        Ok(Response::new(GetConsensusCommitResponse { commit, term }))
    }

    async fn wait_on_consensus_commit(
        &self,
        request: Request<WaitOnConsensusCommitRequest>,
    ) -> Result<Response<WaitOnConsensusCommitResponse>, Status> {
        let request = request.into_inner();
        let commit = request.commit as u64;
        let term = request.term as u64;
        let timeout = Duration::from_secs(request.timeout as u64);
        let consensus_tick = Duration::from_millis(self.settings.cluster.consensus.tick_period_ms);
        let ok = self
            .consensus_state
            .wait_for_consensus_commit(commit, term, consensus_tick, timeout)
            .await
            .is_ok();
        Ok(Response::new(WaitOnConsensusCommitResponse { ok }))
    }

    async fn get_telemetry(
        &self,
        request: Request<GetTelemetryRequest>,
    ) -> Result<Response<GetTelemetryResponse>, Status> {
        let GetTelemetryRequest {
            details_level,
            collections_selector,
            timeout,
        } = request.into_inner();

        if details_level < 2 {
            return Err(Status::invalid_argument(
                "details_level for internal service must be >= 2",
            ));
        }

        let details_level = DetailsLevel::from(details_level.max(2) as usize);

        let detail = TelemetryDetail {
            level: details_level,
            histograms: false,
            per_collection: false,
        };

        let only_collections =
            collections_selector.map(|selector| selector.only_collections.into_iter().collect());

        let timing = Instant::now();
        let timeout = Duration::from_secs(timeout);

        let auth = Auth::new_internal(Access::full("internal service"));

        let telemetry_collector = self.telemetry_collector.lock().await;
        let telemetry_data = telemetry_collector
            .prepare_data(&auth, detail, only_collections, Some(timeout))
            .await?;

        let response = GetTelemetryResponse {
            result: Some(PeerTelemetry::try_from(telemetry_data)?),
            time: timing.elapsed().as_secs_f64(),
        };

        Ok(Response::new(response))
    }

    async fn get_audit_log(
        &self,
        request: Request<GetAuditLogRequest>,
    ) -> Result<Response<GetAuditLogResponse>, Status> {
        let GetAuditLogRequest {
            time_from,
            time_to,
            filters,
            limit,
        } = request.into_inner();

        let audit_config = self
            .audit_config
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("Audit logging is not configured"))?;

        let time_from = parse_audit_log_time(time_from.as_deref(), "time_from")?;

        let time_to = parse_audit_log_time(time_to.as_deref(), "time_to")?;

        let filters: HashMap<String, String> = filters;

        let limit = if limit == 0 {
            None
        } else {
            Some(limit as usize)
        };

        let query = AuditLogQuery::new(time_from, time_to, filters, limit);

        let config = audit_config.clone();
        let entries = cancel::blocking::spawn_cancel_on_drop(move |cancel| {
            read_local_audit_logs(&config, &query, &cancel)
        })
        .await
        .map_err(|e| Status::internal(format!("Failed to read local audit logs: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;

        let entries: Vec<String> = entries
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect();

        Ok(Response::new(GetAuditLogResponse { entries }))
    }

    async fn prepare_private_oram_writeback(
        &self,
        request: Request<PreparePrivateOramWritebackRequest>,
    ) -> Result<Response<PreparePrivateOramWritebackResponse>, Status> {
        let request = request.into_inner();
        validate_replication_request_bounds(&request)?;
        let kind = PrivateOramReplicationIndexKind::try_from(request.index_kind)
            .map_err(|_| Status::invalid_argument("private ORAM index kind is invalid"))?;
        let transition = required_transition(request.transition)?;
        let old = transition.old.expect("validated transition old state");
        let new = transition.new.expect("validated transition new state");
        let signature = request.commit_signature.ok_or_else(|| {
            Status::invalid_argument("private ORAM replication commit signature is required")
        })?;
        if signature.alg.len() > 32 || signature.key_id.len() > 128 || signature.sig.len() > 128 {
            return Err(Status::invalid_argument(
                "private ORAM replication commit signature shape is invalid",
            ));
        }
        let version = u16::try_from(request.version)
            .map_err(|_| Status::invalid_argument("private ORAM writeback version is invalid"))?;
        let auth = Auth::new_internal(Access::full("private ORAM replication"));
        let _lock = self.private_oram_replication_lock.lock().await;

        let writeback_digest = match kind {
            PrivateOramReplicationIndexKind::Hnsw => {
                if request.vector_name.is_empty() || request.vector_name.len() > 255 {
                    return Err(Status::invalid_argument(
                        "private HNSW ORAM replication vector name is invalid",
                    ));
                }
                let expected = PrivateHnswOramConsensusWriteback {
                    old: PrivateHnswOramEpochState {
                        index_epoch: old.index_epoch,
                        root_hash: old.root_hash,
                    },
                    new: PrivateHnswOramEpochState {
                        index_epoch: new.index_epoch,
                        root_hash: new.root_hash,
                    },
                    writeback_digest: transition.writeback_digest,
                };
                let batch = PrivateHnswOramWritebackBatch {
                    version,
                    old: expected.old.clone(),
                    new: expected.new.clone(),
                    bucket_count: request.bucket_count,
                    updated_buckets: request
                        .updated_buckets
                        .into_iter()
                        .map(|bucket| PrivateHnswOramBucket {
                            version: u16::try_from(bucket.version)
                                .expect("validated private ORAM bucket version"),
                            bucket_id: bucket.bucket_id,
                            index_epoch: bucket.index_epoch,
                            ciphertext: bucket.ciphertext,
                            ciphertext_sha256: bucket.ciphertext_sha256,
                            bucket_commitment: bucket.bucket_commitment,
                        })
                        .collect(),
                    commit_signature: PrivateHnswOramSignature {
                        alg: signature.alg,
                        key_id: signature.key_id,
                        sig: signature.sig,
                    },
                };
                private_hnsw::do_prepare_private_hnsw_replica_writeback(
                    &self.toc,
                    &auth,
                    &self.settings,
                    &request.collection_name,
                    &request.vector_name,
                    &request.collection_id,
                    &batch,
                    &expected,
                )
                .await?
                .writeback_digest
            }
            PrivateOramReplicationIndexKind::Result => {
                if !request.vector_name.is_empty() {
                    return Err(Status::invalid_argument(
                        "private result ORAM replication vector name must be empty",
                    ));
                }
                let expected = PrivateResultOramConsensusWriteback {
                    old: PrivateResultOramEpochState {
                        index_epoch: old.index_epoch,
                        root_hash: old.root_hash,
                    },
                    new: PrivateResultOramEpochState {
                        index_epoch: new.index_epoch,
                        root_hash: new.root_hash,
                    },
                    writeback_digest: transition.writeback_digest,
                };
                let batch = PrivateResultOramWritebackBatch {
                    version,
                    old: expected.old.clone(),
                    new: expected.new.clone(),
                    bucket_count: request.bucket_count,
                    updated_buckets: request
                        .updated_buckets
                        .into_iter()
                        .map(|bucket| PrivateResultOramBucket {
                            version: u16::try_from(bucket.version)
                                .expect("validated private ORAM bucket version"),
                            bucket_id: bucket.bucket_id,
                            index_epoch: bucket.index_epoch,
                            ciphertext: bucket.ciphertext,
                            ciphertext_sha256: bucket.ciphertext_sha256,
                            bucket_commitment: bucket.bucket_commitment,
                        })
                        .collect(),
                    commit_signature: PrivateResultOramSignature {
                        alg: signature.alg,
                        key_id: signature.key_id,
                        sig: signature.sig,
                    },
                };
                private_result_oram::do_prepare_private_result_oram_replica_writeback(
                    &self.toc,
                    &auth,
                    &self.settings,
                    &request.collection_name,
                    &request.collection_id,
                    &batch,
                    &expected,
                )
                .await?
                .writeback_digest
            }
            PrivateOramReplicationIndexKind::Unspecified => {
                return Err(Status::invalid_argument(
                    "private ORAM index kind is required",
                ));
            }
        };
        Ok(Response::new(PreparePrivateOramWritebackResponse {
            writeback_digest,
        }))
    }

    async fn finalize_private_oram_writeback(
        &self,
        request: Request<CompletePrivateOramWritebackRequest>,
    ) -> Result<Response<CompletePrivateOramWritebackResponse>, Status> {
        self.complete_private_oram_writeback(request.into_inner(), false)
            .await
            .map(Response::new)
    }

    async fn abort_private_oram_writeback(
        &self,
        request: Request<CompletePrivateOramWritebackRequest>,
    ) -> Result<Response<CompletePrivateOramWritebackResponse>, Status> {
        self.complete_private_oram_writeback(request.into_inner(), true)
            .await
            .map(Response::new)
    }

    async fn install_private_oram_index(
        &self,
        request: Request<InstallPrivateOramIndexRequest>,
    ) -> Result<Response<InstallPrivateOramIndexResponse>, Status> {
        let request = request.into_inner();
        if request.collection_name.is_empty()
            || request.collection_name.len() > 255
            || request.collection_id.is_empty()
            || request.collection_id.len() > 255
        {
            return Err(Status::invalid_argument(
                "private ORAM initial install request shape is invalid",
            ));
        }
        let kind = PrivateOramReplicationIndexKind::try_from(request.index_kind)
            .map_err(|_| Status::invalid_argument("private ORAM index kind is invalid"))?;
        let auth = Auth::new_internal(Access::full("private ORAM replication"));

        enum InitialBundle {
            Hnsw(PrivateHnswOramUploadBundle),
            Result(PrivateResultOramUploadBundle),
        }
        let bundle = match (kind, request.bundle) {
            (
                PrivateOramReplicationIndexKind::Hnsw,
                Some(install_private_oram_index_request::Bundle::Hnsw(bundle)),
            ) if !request.vector_name.is_empty() && request.vector_name.len() <= 255 => {
                validate_initial_install_bucket_bounds(bundle.buckets.iter().map(|bucket| {
                    (
                        bucket.ciphertext.len(),
                        bucket.ciphertext_sha256.len(),
                        bucket.bucket_commitment.len(),
                    )
                }))?;
                InitialBundle::Hnsw(PrivateHnswOramUploadBundle {
                    manifest: private_hnsw_api::manifest_from_proto(bundle.manifest.ok_or_else(
                        || Status::invalid_argument("private HNSW ORAM manifest is required"),
                    )?)?,
                    manifest_signature: private_hnsw_api::signature_from_proto(
                        bundle.manifest_signature.ok_or_else(|| {
                            Status::invalid_argument(
                                "private HNSW ORAM manifest signature is required",
                            )
                        })?,
                    ),
                    buckets: bundle
                        .buckets
                        .into_iter()
                        .map(private_hnsw_api::bucket_from_proto)
                        .collect::<Result<Vec<_>, _>>()?,
                })
            }
            (
                PrivateOramReplicationIndexKind::Result,
                Some(install_private_oram_index_request::Bundle::Result(bundle)),
            ) if request.vector_name.is_empty() => {
                validate_initial_install_bucket_bounds(bundle.buckets.iter().map(|bucket| {
                    (
                        bucket.ciphertext.len(),
                        bucket.ciphertext_sha256.len(),
                        bucket.bucket_commitment.len(),
                    )
                }))?;
                InitialBundle::Result(PrivateResultOramUploadBundle {
                    manifest: private_result_oram_api::manifest_from_proto(
                        bundle.manifest.ok_or_else(|| {
                            Status::invalid_argument("private result ORAM manifest is required")
                        })?,
                    )?,
                    manifest_signature: private_result_oram_api::signature_from_proto(
                        bundle.manifest_signature.ok_or_else(|| {
                            Status::invalid_argument(
                                "private result ORAM manifest signature is required",
                            )
                        })?,
                    ),
                    buckets: bundle
                        .buckets
                        .into_iter()
                        .map(private_result_oram_api::bucket_from_proto)
                        .collect::<Result<Vec<_>, _>>()?,
                })
            }
            _ => {
                return Err(Status::invalid_argument(
                    "private ORAM initial install index kind and bundle do not match",
                ));
            }
        };

        let _lock = self.private_oram_replication_lock.lock().await;
        let (index_epoch, root_hash) = match bundle {
            InitialBundle::Hnsw(bundle) => {
                let epoch = private_hnsw::do_install_private_hnsw_replica_bundle(
                    &self.toc,
                    &auth,
                    &self.settings,
                    &request.collection_name,
                    &request.vector_name,
                    &request.collection_id,
                    &bundle,
                )
                .await?;
                (epoch.index_epoch, epoch.root_hash)
            }
            InitialBundle::Result(bundle) => {
                let epoch = private_result_oram::do_install_private_result_oram_replica_bundle(
                    &self.toc,
                    &auth,
                    &self.settings,
                    &request.collection_name,
                    &request.collection_id,
                    &bundle,
                )
                .await?;
                (epoch.index_epoch, epoch.root_hash)
            }
        };
        Ok(Response::new(InstallPrivateOramIndexResponse {
            index_epoch,
            root_hash,
        }))
    }

    async fn install_private_oram_live_replica(
        &self,
        request: Request<InstallPrivateOramLiveReplicaRequest>,
    ) -> Result<Response<InstallPrivateOramLiveReplicaResponse>, Status> {
        let request = request.into_inner();
        if request.collection_name.is_empty()
            || request.collection_name.len() > 255
            || request.collection_id.is_empty()
            || request.collection_id.len() > 255
        {
            return Err(Status::invalid_argument(
                "private ORAM live install request shape is invalid",
            ));
        }
        let kind = PrivateOramReplicationIndexKind::try_from(request.index_kind)
            .map_err(|_| Status::invalid_argument("private ORAM index kind is invalid"))?;
        let auth = Auth::new_internal(Access::full("private ORAM replication"));

        enum LiveBundle {
            Hnsw(PrivateHnswOramLiveReplicationBundle),
            Result(PrivateResultOramLiveReplicationBundle),
        }

        let (bundle, current, writeback_digest, key) = match (kind, request.bundle) {
            (
                PrivateOramReplicationIndexKind::Hnsw,
                Some(install_private_oram_live_replica_request::Bundle::Hnsw(bundle)),
            ) if !request.vector_name.is_empty() && request.vector_name.len() <= 255 => {
                validate_live_install_bucket_bounds(bundle.buckets.iter().map(|bucket| {
                    (
                        bucket.ciphertext.len(),
                        bucket.ciphertext_sha256.len(),
                        bucket.bucket_commitment.len(),
                    )
                }))?;
                let current = required_live_install_current(bundle.current)?;
                let current = PrivateHnswOramEpochState {
                    index_epoch: current.index_epoch,
                    root_hash: current.root_hash,
                };
                let writeback_digest = bundle.writeback_digest;
                validate_live_install_digest(writeback_digest.as_deref())?;
                let key = PrivateOramEpochKey {
                    collection_id: request.collection_id.clone(),
                    index_kind: PrivateOramIndexKind::Hnsw,
                    index_name: request.vector_name.clone(),
                };
                (
                    LiveBundle::Hnsw(PrivateHnswOramLiveReplicationBundle {
                        manifest: private_hnsw_api::manifest_from_proto(
                            bundle.manifest.ok_or_else(|| {
                                Status::invalid_argument(
                                    "private HNSW ORAM live install manifest is required",
                                )
                            })?,
                        )?,
                        manifest_signature: private_hnsw_api::signature_from_proto(
                            bundle.manifest_signature.ok_or_else(|| {
                                Status::invalid_argument(
                                    "private HNSW ORAM live install manifest signature is required",
                                )
                            })?,
                        ),
                        current: current.clone(),
                        writeback_digest: writeback_digest.clone(),
                        buckets: bundle
                            .buckets
                            .into_iter()
                            .map(private_hnsw_api::bucket_from_proto)
                            .collect::<Result<Vec<_>, _>>()?,
                    }),
                    PrivateOramConsensusEpoch {
                        index_epoch: current.index_epoch,
                        root_hash: current.root_hash,
                        writeback_digest: writeback_digest.clone(),
                    },
                    writeback_digest,
                    key,
                )
            }
            (
                PrivateOramReplicationIndexKind::Result,
                Some(install_private_oram_live_replica_request::Bundle::Result(bundle)),
            ) if request.vector_name.is_empty() => {
                validate_live_install_bucket_bounds(bundle.buckets.iter().map(|bucket| {
                    (
                        bucket.ciphertext.len(),
                        bucket.ciphertext_sha256.len(),
                        bucket.bucket_commitment.len(),
                    )
                }))?;
                let current = required_live_install_current(bundle.current)?;
                let current = PrivateResultOramEpochState {
                    index_epoch: current.index_epoch,
                    root_hash: current.root_hash,
                };
                let writeback_digest = bundle.writeback_digest;
                validate_live_install_digest(writeback_digest.as_deref())?;
                let key = PrivateOramEpochKey {
                    collection_id: request.collection_id.clone(),
                    index_kind: PrivateOramIndexKind::ResultPayload,
                    index_name: String::new(),
                };
                (
                    LiveBundle::Result(PrivateResultOramLiveReplicationBundle {
                        manifest: private_result_oram_api::manifest_from_proto(
                            bundle.manifest.ok_or_else(|| {
                                Status::invalid_argument(
                                    "private result ORAM live install manifest is required",
                                )
                            })?,
                        )?,
                        manifest_signature: private_result_oram_api::signature_from_proto(
                            bundle.manifest_signature.ok_or_else(|| {
                                Status::invalid_argument(
                                    "private result ORAM live install manifest signature is required",
                                )
                            })?,
                        ),
                        current: current.clone(),
                        writeback_digest: writeback_digest.clone(),
                        buckets: bundle
                            .buckets
                            .into_iter()
                            .map(private_result_oram_api::bucket_from_proto)
                            .collect::<Result<Vec<_>, _>>()?,
                    }),
                    PrivateOramConsensusEpoch {
                        index_epoch: current.index_epoch,
                        root_hash: current.root_hash,
                        writeback_digest: writeback_digest.clone(),
                    },
                    writeback_digest,
                    key,
                )
            }
            _ => {
                return Err(Status::invalid_argument(
                    "private ORAM live install index kind and bundle do not match",
                ));
            }
        };

        let _lock = self.private_oram_replication_lock.lock().await;
        let consensus = self
            .consensus_state
            .private_oram_epoch(&key)
            .ok_or_else(|| Status::failed_precondition("private ORAM ownership is missing"))?;
        if consensus != current {
            return Err(Status::failed_precondition(
                "private ORAM live install does not match consensus",
            ));
        }
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("private ORAM live install clock is invalid"))?
            .as_secs();
        let lease = self.consensus_state.private_oram_session_lease(&key);
        validate_live_install_transfer_lease(
            lease.as_ref(),
            &request.transfer_lease_id_hash,
            now_unix,
        )?;

        let (index_epoch, root_hash) = match bundle {
            LiveBundle::Hnsw(bundle) => {
                let epoch = private_hnsw::do_install_private_hnsw_live_replica_bundle(
                    &self.toc,
                    &auth,
                    &self.settings,
                    &request.collection_name,
                    &request.vector_name,
                    &request.collection_id,
                    &bundle,
                    &bundle.current,
                    writeback_digest.as_deref(),
                )
                .await?;
                (epoch.index_epoch, epoch.root_hash)
            }
            LiveBundle::Result(bundle) => {
                let epoch =
                    private_result_oram::do_install_private_result_oram_live_replica_bundle(
                        &self.toc,
                        &auth,
                        &self.settings,
                        &request.collection_name,
                        &request.collection_id,
                        &bundle,
                        &bundle.current,
                        writeback_digest.as_deref(),
                    )
                    .await?;
                (epoch.index_epoch, epoch.root_hash)
            }
        };
        Ok(Response::new(InstallPrivateOramLiveReplicaResponse {
            index_epoch,
            root_hash,
            writeback_digest,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_oram_session_lease_hash_is_domain_separated_and_bounded() {
        let first = private_oram_session_lease_hash("session-1").unwrap();
        let replay = private_oram_session_lease_hash("session-1").unwrap();
        let second = private_oram_session_lease_hash("session-2").unwrap();
        assert_eq!(first, replay);
        assert_ne!(first, second);
        assert_eq!(BASE64URL_NOPAD.decode(first.as_bytes()).unwrap().len(), 32);

        let sentinel = "private-oram-session-lease-id-sentinel".repeat(8);
        let rendered = private_oram_session_lease_hash(&sentinel)
            .unwrap_err()
            .to_string();
        assert!(rendered.contains("lease id is invalid"));
        assert!(!rendered.contains(&sentinel));
    }

    #[test]
    fn private_oram_session_lease_renewal_must_advance_monotonically() {
        let current = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[9; 32]),
            issued_at_unix: 100,
            expires_at_unix: 400,
        };
        let renewed = renewed_private_oram_session_lease(&current, 101, 401).unwrap();
        assert_eq!(renewed.owner_peer_id, current.owner_peer_id);
        assert_eq!(renewed.lease_id_hash, current.lease_id_hash);
        assert_eq!(renewed.issued_at_unix, 101);
        assert_eq!(renewed.expires_at_unix, 401);

        for (issued_at_unix, expires_at_unix) in [(99, 401), (101, 400), (401, 401)] {
            let rendered =
                renewed_private_oram_session_lease(&current, issued_at_unix, expires_at_unix)
                    .unwrap_err()
                    .to_string();
            assert!(rendered.contains("renewal interval is invalid"));
            assert!(!rendered.contains(&current.lease_id_hash));
        }

        assert_eq!(private_oram_renewal_expiry(&current, 101).unwrap(), 401);
        assert_eq!(private_oram_renewal_expiry(&current, 200).unwrap(), 500);
        assert!(private_oram_renewal_expiry(&current, u64::MAX).is_err());
    }

    #[test]
    fn private_oram_orphaned_lease_cleanup_waits_for_expiry() {
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: BASE64URL_NOPAD.encode(&[14; 32]),
            issued_at_unix: 100,
            expires_at_unix: 400,
        };
        assert!(!private_oram_orphaned_lease_releasable(&lease, 7, 399));
        assert!(private_oram_orphaned_lease_releasable(&lease, 7, 400));
        assert!(!private_oram_orphaned_lease_releasable(&lease, 8, 400));
    }

    #[test]
    fn failed_owner_writeback_recovery_requires_exact_consensus_state() {
        let old = PrivateOramConsensusEpoch {
            index_epoch: 42,
            root_hash: "old-root-sentinel".to_string(),
            writeback_digest: Some("prior-digest-sentinel".to_string()),
        };
        let new = PrivateOramConsensusEpoch {
            index_epoch: 43,
            root_hash: "new-root-sentinel".to_string(),
            writeback_digest: Some("writeback-digest-sentinel".to_string()),
        };
        assert_eq!(
            classify_failed_private_oram_owner_writeback(
                Some(&old),
                42,
                "old-root-sentinel",
                43,
                "new-root-sentinel",
                "writeback-digest-sentinel",
            )
            .unwrap(),
            PrivateOramRecoveryAction::AbortPending
        );
        assert_eq!(
            classify_failed_private_oram_owner_writeback(
                Some(&new),
                42,
                "old-root-sentinel",
                43,
                "new-root-sentinel",
                "writeback-digest-sentinel",
            )
            .unwrap(),
            PrivateOramRecoveryAction::FinalizePending
        );

        let mut conflicting = new;
        conflicting.writeback_digest = Some("conflicting-digest-sentinel".to_string());
        for consensus in [Some(&conflicting), None] {
            let rendered = classify_failed_private_oram_owner_writeback(
                consensus,
                42,
                "old-root-sentinel",
                43,
                "new-root-sentinel",
                "writeback-digest-sentinel",
            )
            .unwrap_err()
            .to_string();
            assert!(rendered.contains("consensus state is ambiguous"));
            for secret in [
                "old-root-sentinel",
                "new-root-sentinel",
                "writeback-digest-sentinel",
                "conflicting-digest-sentinel",
            ] {
                assert!(!rendered.contains(secret));
            }
        }
    }

    fn replication_request_fixture() -> PreparePrivateOramWritebackRequest {
        PreparePrivateOramWritebackRequest {
            collection_name: "docs".to_string(),
            collection_id: "collection-crypto-id".to_string(),
            index_kind: PrivateOramReplicationIndexKind::Hnsw as i32,
            vector_name: "text".to_string(),
            version: 1,
            transition: Some(PrivateOramReplicationTransition {
                old: Some(api::grpc::PrivateOramReplicationEpochState {
                    index_epoch: 42,
                    root_hash: "old-root".to_string(),
                }),
                new: Some(api::grpc::PrivateOramReplicationEpochState {
                    index_epoch: 43,
                    root_hash: "new-root".to_string(),
                }),
                writeback_digest: "digest".to_string(),
            }),
            bucket_count: 1,
            updated_buckets: vec![api::grpc::PrivateOramReplicationBucket {
                version: 1,
                bucket_id: 0,
                index_epoch: 43,
                ciphertext: "ciphertext".to_string(),
                ciphertext_sha256: "hash".to_string(),
                bucket_commitment: "commitment".to_string(),
            }],
            commit_signature: Some(api::grpc::PrivateOramReplicationSignature {
                alg: "ed25519".to_string(),
                key_id: "signing-key".to_string(),
                sig: "signature".to_string(),
            }),
        }
    }

    #[test]
    fn audit_log_time_parse_errors_do_not_reflect_inputs() {
        let time_sentinel = "audit-time-secret-sentinel";

        let err = parse_audit_log_time(Some(time_sentinel), "time_from").unwrap_err();
        assert_eq!(err.message(), "Invalid time_from");
        assert!(!err.message().contains(time_sentinel));

        let err = parse_audit_log_time(Some(time_sentinel), "time_to").unwrap_err();
        assert_eq!(err.message(), "Invalid time_to");
        assert!(!err.message().contains(time_sentinel));
    }

    #[test]
    fn private_oram_replication_wire_bounds_fail_closed_without_reflection() {
        let valid = replication_request_fixture();
        validate_replication_request_bounds(&valid).unwrap();
        required_transition(valid.transition.clone()).unwrap();

        let mut invalid_bucket = valid.clone();
        invalid_bucket.updated_buckets[0].version = u32::from(u16::MAX) + 1;
        let ciphertext_sentinel = invalid_bucket.updated_buckets[0].ciphertext.clone();
        let err = validate_replication_request_bounds(&invalid_bucket).unwrap_err();
        assert_eq!(
            err.message(),
            "private ORAM replication bucket shape is invalid"
        );
        assert!(!err.message().contains(&ciphertext_sentinel));

        let transition_sentinel = "private-oram-transition-secret-sentinel".repeat(8);
        let mut invalid_transition = valid.transition.unwrap();
        invalid_transition.writeback_digest = transition_sentinel.clone();
        let err = required_transition(Some(invalid_transition)).unwrap_err();
        assert_eq!(err.message(), "private ORAM transition shape is invalid");
        assert!(!err.message().contains(&transition_sentinel));
    }

    #[test]
    fn private_oram_completion_wire_bounds_fail_closed_without_reflection() {
        let sentinel = "private-oram-signing-key-secret-sentinel".repeat(4);
        let request = CompletePrivateOramWritebackRequest {
            collection_name: "docs".to_string(),
            collection_id: "collection-crypto-id".to_string(),
            index_kind: PrivateOramReplicationIndexKind::Hnsw as i32,
            vector_name: "text".to_string(),
            transition: replication_request_fixture().transition,
            signing_key_id: sentinel.clone(),
        };
        let err = validate_completion_request_shape(&request).unwrap_err();
        assert_eq!(
            err.message(),
            "private ORAM completion request shape is invalid"
        );
        assert!(!err.message().contains(&sentinel));
    }

    #[test]
    fn private_oram_initial_install_bounds_fail_closed() {
        validate_initial_install_bucket_bounds([(1024, 43, 43)]).unwrap();

        let empty = validate_initial_install_bucket_bounds(std::iter::empty()).unwrap_err();
        assert_eq!(
            empty.message(),
            "private ORAM initial install request is oversized"
        );

        let oversized_hash = validate_initial_install_bucket_bounds([(1024, 129, 43)]).unwrap_err();
        assert_eq!(
            oversized_hash.message(),
            "private ORAM initial install bucket shape is invalid"
        );

        let oversized_ciphertext = validate_initial_install_bucket_bounds([(
            MAX_PRIVATE_ORAM_REPLICATION_CIPHERTEXT_CHARS + 1,
            43,
            43,
        )])
        .unwrap_err();
        assert_eq!(
            oversized_ciphertext.message(),
            "private ORAM initial install bucket shape is invalid"
        );
    }

    #[test]
    fn private_oram_wire_request_budget_uses_full_protobuf_envelope() {
        let sentinel = "private-oram-wire-budget-sentinel".repeat(8);
        let request = InstallPrivateOramLiveReplicaRequest {
            collection_name: "docs".to_string(),
            collection_id: "collection-crypto-id".to_string(),
            index_kind: PrivateOramReplicationIndexKind::Hnsw as i32,
            vector_name: "text".to_string(),
            bundle: None,
            transfer_lease_id_hash: sentinel.clone(),
        };
        let encoded_len = request.encoded_len();
        assert!(encoded_len > sentinel.len());
        validate_private_oram_wire_request_budget(
            &request,
            encoded_len,
            "private ORAM wire request is oversized",
        )
        .unwrap();

        for limit in [0, encoded_len - 1] {
            let rendered = validate_private_oram_wire_request_budget(
                &request,
                limit,
                "private ORAM wire request is oversized",
            )
            .unwrap_err()
            .to_string();
            assert!(rendered.contains("wire request is oversized"));
            assert!(!rendered.contains(&sentinel));
        }
    }

    #[test]
    fn private_oram_live_install_wire_bounds_fail_closed_without_reflection() {
        validate_live_install_bucket_bounds([(1024, 43, 43)]).unwrap();
        let root_hash = BASE64URL_NOPAD.encode(&[7; 32]);
        assert_eq!(
            required_live_install_current(Some(PrivateOramReplicationEpochState {
                index_epoch: 43,
                root_hash: root_hash.clone(),
            }))
            .unwrap()
            .root_hash,
            root_hash,
        );
        let digest = BASE64URL_NOPAD.encode(&[8; 32]);
        validate_live_install_digest(Some(&digest)).unwrap();
        validate_live_install_digest(None).unwrap();

        let empty = validate_live_install_bucket_bounds(std::iter::empty()).unwrap_err();
        assert_eq!(
            empty.message(),
            "private ORAM live install bucket set is invalid"
        );
        let oversized_chars = MAX_PRIVATE_ORAM_REPLICATION_CIPHERTEXT_CHARS + 1;
        let oversized =
            validate_live_install_bucket_bounds([(oversized_chars, 43, 43)]).unwrap_err();
        assert_eq!(
            oversized.message(),
            "private ORAM live install bucket set is invalid"
        );
        assert!(!oversized.message().contains(&oversized_chars.to_string()));

        for sentinel in [
            "private-oram-live-root-sentinel",
            "private-oram-live-digest-sentinel",
        ] {
            let err = if sentinel.contains("root") {
                required_live_install_current(Some(PrivateOramReplicationEpochState {
                    index_epoch: 43,
                    root_hash: sentinel.to_string(),
                }))
                .unwrap_err()
            } else {
                validate_live_install_digest(Some(sentinel)).unwrap_err()
            };
            assert!(!err.message().contains(sentinel));
        }
    }

    #[test]
    fn private_oram_live_install_requires_exact_transfer_reservation() {
        let lease_hash = BASE64URL_NOPAD.encode(&[12; 32]);
        let lease = PrivateOramSessionLease {
            owner_peer_id: 7,
            lease_id_hash: lease_hash.clone(),
            issued_at_unix: 100,
            expires_at_unix: 400,
        };

        validate_live_install_transfer_lease(None, "", 200).unwrap();
        validate_live_install_transfer_lease(Some(&lease), &lease_hash, 200).unwrap();
        validate_live_install_transfer_lease(Some(&lease), "", 400).unwrap();

        for requested in [
            "".to_string(),
            BASE64URL_NOPAD.encode(&[13; 32]),
            "transfer-reservation-sentinel".to_string(),
        ] {
            let err =
                validate_live_install_transfer_lease(Some(&lease), &requested, 200).unwrap_err();
            assert!(!err.message().contains(&lease_hash));
            if !requested.is_empty() {
                assert!(!err.message().contains(&requested));
            }
        }

        let expired =
            validate_live_install_transfer_lease(Some(&lease), &lease_hash, 400).unwrap_err();
        assert_eq!(expired.code(), tonic::Code::FailedPrecondition);
        assert!(!expired.message().contains(&lease_hash));

        let missing = validate_live_install_transfer_lease(None, &lease_hash, 200).unwrap_err();
        assert_eq!(missing.code(), tonic::Code::FailedPrecondition);
        assert!(!missing.message().contains(&lease_hash));
    }

    #[test]
    fn private_oram_live_install_ack_is_exact_and_redacted() {
        let root_hash = BASE64URL_NOPAD.encode(&[9; 32]);
        let digest = BASE64URL_NOPAD.encode(&[10; 32]);
        let expected = PrivateOramConsensusEpoch {
            index_epoch: 43,
            root_hash: root_hash.clone(),
            writeback_digest: Some(digest.clone()),
        };
        validate_live_install_ack(
            7,
            &expected,
            InstallPrivateOramLiveReplicaResponse {
                index_epoch: 43,
                root_hash: root_hash.clone(),
                writeback_digest: Some(digest.clone()),
            },
        )
        .unwrap();

        for response in [
            InstallPrivateOramLiveReplicaResponse {
                index_epoch: 44,
                root_hash: root_hash.clone(),
                writeback_digest: Some(digest.clone()),
            },
            InstallPrivateOramLiveReplicaResponse {
                index_epoch: 43,
                root_hash: BASE64URL_NOPAD.encode(&[11; 32]),
                writeback_digest: Some(digest.clone()),
            },
            InstallPrivateOramLiveReplicaResponse {
                index_epoch: 43,
                root_hash: root_hash.clone(),
                writeback_digest: None,
            },
        ] {
            let rendered = validate_live_install_ack(7, &expected, response)
                .unwrap_err()
                .to_string();
            assert!(rendered.contains("peer 7"));
            assert!(!rendered.contains(&root_hash));
            assert!(!rendered.contains(&digest));
        }
    }
}
