use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use api::grpc::qdrant_internal_server::QdrantInternal;
use api::grpc::{
    CompletePrivateOramWritebackRequest, CompletePrivateOramWritebackResponse, GetAuditLogRequest,
    GetAuditLogResponse, GetConsensusCommitRequest, GetConsensusCommitResponse,
    GetTelemetryRequest, GetTelemetryResponse, InstallPrivateOramIndexRequest,
    InstallPrivateOramIndexResponse, PeerTelemetry, PreparePrivateOramWritebackRequest,
    PreparePrivateOramWritebackResponse, PrivateOramReplicationIndexKind,
    PrivateOramReplicationTransition, WaitOnConsensusCommitRequest, WaitOnConsensusCommitResponse,
    install_private_oram_index_request,
};
use chrono::DateTime;
use collection::operations::verification::new_unchecked_verification_pass;
use collection::private_hnsw_oram_store::{
    PrivateHnswOramConsensusWriteback, PrivateHnswOramEpochState, PrivateHnswOramWritebackBatch,
};
use collection::private_result_oram_store::{
    PrivateResultOramConsensusWriteback, PrivateResultOramEpochState,
    PrivateResultOramWritebackBatch,
};
use common::types::{DetailsLevel, TelemetryDetail};
use qdrant_sec::{
    PrivateHnswOramBucket, PrivateHnswOramSignature, PrivateHnswOramUploadBundle,
    PrivateResultOramBucket, PrivateResultOramSignature, PrivateResultOramUploadBundle,
};
use storage::audit::AuditConfig;
use storage::audit_reader::{AuditLogQuery, read_local_audit_logs};
use storage::content_manager::consensus_manager::ConsensusStateRef;
use storage::content_manager::consensus_ops::{PrivateOramEpochKey, PrivateOramIndexKind};
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::dispatcher::{
    Dispatcher, PrivateOramEpochRef, PrivateOramPendingTransitionRef, PrivateOramRecoveryAction,
    classify_private_oram_recovery,
};
use storage::rbac::{Access, Auth};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

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

const BYTES_PER_MIB: usize = 1024 * 1024;

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

#[allow(dead_code)]
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
        PrivateOramRecoveryAction::Clean => return Ok(()),
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
    Ok(())
}

#[allow(dead_code)]
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
        PrivateOramRecoveryAction::Clean => return Ok(()),
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
    Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
