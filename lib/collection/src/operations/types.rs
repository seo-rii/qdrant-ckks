use std::backtrace::Backtrace;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error as _;
use std::fmt::{Debug, Write as _};
use std::iter;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, SystemTimeError};

use api::grpc::transport_channel_pool::RequestError;
use api::rest::{
    BaseGroupRequest, LookupLocation, RecommendStrategy, SearchGroupsRequestInternal,
    SearchRequestInternal, ShardKeySelector, VectorStructOutput,
};
use common::ext::OptionExt;
use common::fs::FileStorageError;
use common::rate_limiting::{RateLimitError, RetryError};
use common::types::ScoreType;
use common::validation::validate_range_generic;
use common::{defaults, save_on_disk};
use data_encoding::BASE64URL_NOPAD;
use issues::IssueRecord;
use qdrant_sec::{
    CkksVectorSidecarDeleteTarget, CkksVectorSidecarEnvelopeKey,
    CkksVectorVerifiedSidecarDeleteKey, CkksVectorVerifiedSidecarKey,
    ClientCkksVectorSidecarEnvelopeKey, ClientCkksVectorVerifiedSidecarKey,
    ClientPayloadEnvelopeKey, ClientPayloadVerifiedEnvelopeKey, ENCRYPTED_VECTOR_SIDECAR_FIELD,
    ServerPayloadEnvelopeKey, ServerPayloadVerifiedEnvelopeKey,
    ckks_vector_verified_sidecar_delete_key,
};
use schemars::JsonSchema;
use segment::common::anonymize::Anonymize;
use segment::common::operation_error::{CancelledError, OperationError};
use segment::data_types::groups::GroupId;
use segment::data_types::modifier::Modifier;
use segment::data_types::vectors::{DEFAULT_VECTOR_NAME, DenseVector};
use segment::json_path::{JsonPath, JsonPathItem};
use segment::types::{
    Distance, Filter, HnswConfig, MultiVectorConfig, Payload, PayloadIndexInfo, PayloadKeyType,
    PointIdType, QuantizationConfig, SearchParams, SeqNumberType, ShardKey,
    SparseVectorStorageType, StrictModeConfigOutput, VectorName, VectorNameBuf,
    VectorStorageDatatype, WithPayloadInterface, WithVector,
};
use semver::Version;
use serde::{self, Deserialize, Serialize};
use serde_json::{Error as JsonError, Map, Value};
use sha2::{Digest, Sha256};
pub use shard::count::CountRequestInternal;
use shard::payload_index_schema::PayloadIndexSchema;
pub use shard::query::scroll::{QueryScrollRequestInternal, ScrollOrder};
pub use shard::scroll::ScrollRequestInternal;
pub use shard::search::CoreSearchRequest;
use shard::wal::WalError;
use sparse::common::sparse_vector::SparseVector;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::oneshot::error::RecvError as OneshotRecvError;
use tokio::task::JoinError;
use tonic::codegen::http::uri::InvalidUri;
use uuid::Uuid;
use validator::{Validate, ValidationError, ValidationErrors};

use super::ClockTag;
use crate::config::{CollectionConfigInternal, CollectionParams, WalConfig};
use crate::operations::cluster_ops::ReshardingDirection;
use crate::operations::config_diff::{HnswConfigDiff, QuantizationConfigDiff};
use crate::optimizers_builder::OptimizersConfig;
use crate::shards::replica_set::replica_set_state::ReplicaState;
use crate::shards::resharding::ReshardingStage;
use crate::shards::shard::{PeerId, ShardId};
use crate::shards::transfer::ShardTransferMethod;

/// Current state of the collection.
/// `Green` - all good. `Yellow` - optimization is running, 'Grey' - optimizations are possible but not triggered, `Red` - some operations failed and was not recovered
#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CollectionStatus {
    // Collection is completely ready for requests
    Green,
    // Collection is available, but some segments are under optimization
    Yellow,
    // Collection is available, but some segments are pending optimization
    Grey,
    // Something is not OK:
    // - some operations failed and was not recovered
    Red,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CollectionUpdateProvenance {
    server_envelopes: Option<RuntimeEncryptedPayloadEnvelopes>,
    vector_sidecars: Option<RuntimeEncryptedVectorSidecars>,
    client_vector_sidecars: Option<RuntimeVerifiedClientVectorSidecars>,
    vector_sidecar_deletes: Option<RuntimeEncryptedVectorSidecarDeletes>,
    verified_client_envelopes: Option<RuntimeVerifiedClientEnvelopes>,
}

impl Default for CollectionUpdateProvenance {
    fn default() -> Self {
        Self::client_plaintext()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct RuntimeVerifiedClientEnvelopes {
    verified_envelope_keys: Arc<HashSet<ClientPayloadVerifiedEnvelopeKey>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct RuntimeEncryptedPayloadEnvelopes {
    verified_envelope_keys: Arc<HashSet<ServerPayloadVerifiedEnvelopeKey>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct RuntimeEncryptedVectorSidecars {
    verified_sidecar_keys: Arc<HashSet<CkksVectorVerifiedSidecarKey>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct RuntimeVerifiedClientVectorSidecars {
    verified_sidecar_keys: Arc<HashSet<ClientCkksVectorVerifiedSidecarKey>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct RuntimeEncryptedVectorSidecarDeletes {
    verified_delete_keys: Arc<HashSet<CkksVectorVerifiedSidecarDeleteKey>>,
}

impl RuntimeEncryptedPayloadEnvelopes {
    fn from_verified(
        verified_envelope_keys: impl IntoIterator<Item = ServerPayloadVerifiedEnvelopeKey>,
    ) -> Self {
        Self {
            verified_envelope_keys: Arc::new(verified_envelope_keys.into_iter().collect()),
        }
    }

    fn proof_for(
        &self,
        envelope_key: &ServerPayloadEnvelopeKey,
    ) -> Option<ServerPayloadVerifiedEnvelopeKey> {
        self.verified_envelope_keys
            .iter()
            .find(|verified| verified.envelope_key() == envelope_key)
            .cloned()
    }
}

impl RuntimeVerifiedClientEnvelopes {
    fn from_verified(
        verified_envelope_keys: impl IntoIterator<Item = ClientPayloadVerifiedEnvelopeKey>,
    ) -> Self {
        Self {
            verified_envelope_keys: Arc::new(verified_envelope_keys.into_iter().collect()),
        }
    }

    fn proof_for(
        &self,
        envelope_key: &ClientPayloadEnvelopeKey,
    ) -> Option<ClientPayloadVerifiedEnvelopeKey> {
        self.verified_envelope_keys
            .iter()
            .find(|verified| verified.envelope_key() == envelope_key)
            .cloned()
    }
}

impl RuntimeEncryptedVectorSidecars {
    fn from_verified(
        verified_sidecar_keys: impl IntoIterator<Item = CkksVectorVerifiedSidecarKey>,
    ) -> Self {
        Self {
            verified_sidecar_keys: Arc::new(verified_sidecar_keys.into_iter().collect()),
        }
    }

    fn proof_for(
        &self,
        sidecar_key: &CkksVectorSidecarEnvelopeKey,
    ) -> Option<CkksVectorVerifiedSidecarKey> {
        self.verified_sidecar_keys
            .iter()
            .find(|verified| verified.envelope_key() == sidecar_key)
            .cloned()
    }
}

impl RuntimeVerifiedClientVectorSidecars {
    fn from_verified(
        verified_sidecar_keys: impl IntoIterator<Item = ClientCkksVectorVerifiedSidecarKey>,
    ) -> Self {
        Self {
            verified_sidecar_keys: Arc::new(verified_sidecar_keys.into_iter().collect()),
        }
    }

    fn proof_for(
        &self,
        sidecar_key: &ClientCkksVectorSidecarEnvelopeKey,
    ) -> Option<ClientCkksVectorVerifiedSidecarKey> {
        self.verified_sidecar_keys
            .iter()
            .find(|verified| verified.envelope_key() == sidecar_key)
            .cloned()
    }
}

impl RuntimeEncryptedVectorSidecarDeletes {
    fn from_verified(
        verified_delete_keys: impl IntoIterator<Item = CkksVectorVerifiedSidecarDeleteKey>,
    ) -> Self {
        Self {
            verified_delete_keys: Arc::new(verified_delete_keys.into_iter().collect()),
        }
    }

    fn allows_key(
        &self,
        collection_id: &str,
        key: &JsonPath,
        target: &CkksVectorSidecarDeleteTarget,
    ) -> bool {
        if key.first_key != ENCRYPTED_VECTOR_SIDECAR_FIELD {
            return false;
        }
        let [JsonPathItem::Key(vector_name)] = key.rest.as_slice() else {
            return false;
        };
        self.verified_delete_keys
            .iter()
            .any(|verified| verified.matches_binding(collection_id, vector_name, target))
    }
}

impl CollectionUpdateProvenance {
    pub const fn client_plaintext() -> Self {
        Self {
            server_envelopes: None,
            vector_sidecars: None,
            client_vector_sidecars: None,
            vector_sidecar_deletes: None,
            verified_client_envelopes: None,
        }
    }

    pub fn runtime_encrypted_payloads(
        verified_envelope_keys: impl IntoIterator<Item = ServerPayloadVerifiedEnvelopeKey>,
    ) -> Self {
        let verified = RuntimeEncryptedPayloadEnvelopes::from_verified(verified_envelope_keys);
        if verified.verified_envelope_keys.is_empty() {
            return Self::client_plaintext();
        }
        Self {
            server_envelopes: Some(verified),
            vector_sidecars: None,
            client_vector_sidecars: None,
            vector_sidecar_deletes: None,
            verified_client_envelopes: None,
        }
    }

    pub fn runtime_encrypted_vectors(
        verified_sidecar_keys: impl IntoIterator<Item = CkksVectorVerifiedSidecarKey>,
    ) -> Self {
        let verified = RuntimeEncryptedVectorSidecars::from_verified(verified_sidecar_keys);
        if verified.verified_sidecar_keys.is_empty() {
            return Self::client_plaintext();
        }
        Self {
            server_envelopes: None,
            vector_sidecars: Some(verified),
            client_vector_sidecars: None,
            vector_sidecar_deletes: None,
            verified_client_envelopes: None,
        }
    }

    pub fn runtime_verified_client_vectors(
        verified_sidecar_keys: impl IntoIterator<Item = ClientCkksVectorVerifiedSidecarKey>,
    ) -> Self {
        let verified = RuntimeVerifiedClientVectorSidecars::from_verified(verified_sidecar_keys);
        if verified.verified_sidecar_keys.is_empty() {
            return Self::client_plaintext();
        }
        Self {
            server_envelopes: None,
            vector_sidecars: None,
            client_vector_sidecars: Some(verified),
            vector_sidecar_deletes: None,
            verified_client_envelopes: None,
        }
    }

    pub fn runtime_encrypted_vector_deletes_for_target(
        collection_id: &str,
        vector_names: impl IntoIterator<Item = String>,
        target: CkksVectorSidecarDeleteTarget,
    ) -> Result<Self, qdrant_sec::CkksError> {
        let verified_delete_keys = vector_names
            .into_iter()
            .map(|vector_name| {
                ckks_vector_verified_sidecar_delete_key(collection_id, vector_name, target.clone())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let verified = RuntimeEncryptedVectorSidecarDeletes::from_verified(verified_delete_keys);
        if verified.verified_delete_keys.is_empty() {
            return Ok(Self::client_plaintext());
        }
        Ok(Self {
            server_envelopes: None,
            vector_sidecars: None,
            client_vector_sidecars: None,
            vector_sidecar_deletes: Some(verified),
            verified_client_envelopes: None,
        })
    }

    pub fn runtime_verified_client_envelopes(
        verified_envelope_keys: impl IntoIterator<Item = ClientPayloadVerifiedEnvelopeKey>,
    ) -> Self {
        let verified = RuntimeVerifiedClientEnvelopes::from_verified(verified_envelope_keys);
        if verified.verified_envelope_keys.is_empty() {
            return Self::client_plaintext();
        }
        Self {
            server_envelopes: None,
            vector_sidecars: None,
            client_vector_sidecars: None,
            vector_sidecar_deletes: None,
            verified_client_envelopes: Some(verified),
        }
    }

    pub fn runtime_encrypted_payloads_and_verified_client_envelopes(
        verified_server_envelope_keys: impl IntoIterator<Item = ServerPayloadVerifiedEnvelopeKey>,
        verified_envelope_keys: impl IntoIterator<Item = ClientPayloadVerifiedEnvelopeKey>,
    ) -> Self {
        let server_verified =
            RuntimeEncryptedPayloadEnvelopes::from_verified(verified_server_envelope_keys);
        let verified = RuntimeVerifiedClientEnvelopes::from_verified(verified_envelope_keys);
        if server_verified.verified_envelope_keys.is_empty() {
            return if verified.verified_envelope_keys.is_empty() {
                Self::client_plaintext()
            } else {
                Self {
                    server_envelopes: None,
                    vector_sidecars: None,
                    client_vector_sidecars: None,
                    vector_sidecar_deletes: None,
                    verified_client_envelopes: Some(verified),
                }
            };
        }
        if verified.verified_envelope_keys.is_empty() {
            return Self {
                server_envelopes: Some(server_verified),
                vector_sidecars: None,
                client_vector_sidecars: None,
                vector_sidecar_deletes: None,
                verified_client_envelopes: None,
            };
        }
        Self {
            server_envelopes: Some(server_verified),
            vector_sidecars: None,
            client_vector_sidecars: None,
            vector_sidecar_deletes: None,
            verified_client_envelopes: Some(verified),
        }
    }

    pub fn with_runtime_encrypted_vector_provenance(mut self, provenance: Self) -> Self {
        if provenance.vector_sidecars.is_some() {
            self.vector_sidecars = provenance.vector_sidecars;
        }
        if provenance.client_vector_sidecars.is_some() {
            self.client_vector_sidecars = provenance.client_vector_sidecars;
        }
        if provenance.vector_sidecar_deletes.is_some() {
            self.vector_sidecar_deletes = provenance.vector_sidecar_deletes;
        }
        self
    }

    pub fn verified_server_envelope_key_for_binding(
        &self,
        envelope_key: &ServerPayloadEnvelopeKey,
        collection_id: &str,
        point_id: &str,
        field_path: &str,
    ) -> Option<ServerPayloadVerifiedEnvelopeKey> {
        if !envelope_key.matches_binding(collection_id, point_id, field_path) {
            return None;
        }
        self.server_envelopes
            .as_ref()
            .and_then(|verified| verified.proof_for(envelope_key))
    }

    pub const fn allows_vector_sidecars(&self) -> bool {
        self.vector_sidecars.is_some() || self.client_vector_sidecars.is_some()
    }

    pub fn allows_vector_sidecar_delete_key(
        &self,
        collection_id: &str,
        key: &JsonPath,
        target: &CkksVectorSidecarDeleteTarget,
    ) -> bool {
        self.vector_sidecar_deletes
            .as_ref()
            .is_some_and(|verified| verified.allows_key(collection_id, key, target))
    }

    pub fn verified_vector_sidecar_key_for_binding(
        &self,
        sidecar_key: &CkksVectorSidecarEnvelopeKey,
        collection_id: &str,
        point_id: &str,
        vector_name: &str,
    ) -> Option<CkksVectorVerifiedSidecarKey> {
        if !sidecar_key.matches_binding(collection_id, point_id, vector_name) {
            return None;
        }
        self.vector_sidecars
            .as_ref()
            .and_then(|verified| verified.proof_for(sidecar_key))
    }

    pub fn verified_client_vector_sidecar_key_for_binding(
        &self,
        sidecar_key: &ClientCkksVectorSidecarEnvelopeKey,
        collection_id: &str,
        point_id: &str,
        vector_name: &str,
    ) -> Option<ClientCkksVectorVerifiedSidecarKey> {
        if !sidecar_key.matches_binding(collection_id, point_id, vector_name) {
            return None;
        }
        self.client_vector_sidecars
            .as_ref()
            .and_then(|verified| verified.proof_for(sidecar_key))
    }

    pub fn verified_client_envelope_key_for_binding(
        &self,
        envelope_key: &ClientPayloadEnvelopeKey,
        collection_id: &str,
        point_id: &str,
        field_path: &str,
    ) -> Option<ClientPayloadVerifiedEnvelopeKey> {
        if !envelope_key.matches_binding(collection_id, point_id, field_path) {
            return None;
        }
        self.verified_client_envelopes
            .as_ref()
            .and_then(|verified| verified.proof_for(envelope_key))
    }

    pub fn has_verified_client_blind_index_binding(
        &self,
        collection_id: &str,
        point_id: &str,
        field_path: &str,
        token: &str,
    ) -> bool {
        self.verified_client_envelopes
            .as_ref()
            .is_some_and(|verified| {
                verified.verified_envelope_keys.iter().any(|proof| {
                    proof.binds_blind_index(collection_id, point_id, field_path, token)
                })
            })
    }
}

pub fn ckks_vector_sidecar_delete_target(
    points: Option<&[PointIdType]>,
    filter: Option<&Filter>,
) -> Option<CkksVectorSidecarDeleteTarget> {
    if let Some(points) = points {
        let mut point_ids = points
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>();
        point_ids.sort();
        let digest_b64 = digest_delete_target("point_ids", &point_ids);
        return Some(CkksVectorSidecarDeleteTarget::PointIds { digest_b64 });
    }
    filter.map(|filter| {
        let digest_b64 = digest_delete_target("filter", filter);
        CkksVectorSidecarDeleteTarget::Filter { digest_b64 }
    })
}

fn digest_delete_target(kind: &str, target: &impl Serialize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"qdrant-sec/vector-sidecar-delete-target/v1\0");
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    let target_bytes = serde_json::to_vec(target).unwrap_or_default();
    hasher.update((target_bytes.len() as u64).to_be_bytes());
    hasher.update(target_bytes);
    BASE64URL_NOPAD.encode(&hasher.finalize())
}

/// Current state of the shard (supports same states as the collection)
///
/// `Green` - all good. `Yellow` - optimization is running, 'Grey' - optimizations are possible but not triggered, `Red` - some operations failed and was not recovered
#[derive(Debug, Serialize, JsonSchema, Anonymize, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    // Shard is completely ready for requests
    Green,
    // Shard is available, but some segments are under optimization
    Yellow,
    // Shard is available, but some segments are pending optimization
    Grey,
    // Something is not OK:
    // - some operations failed and was not recovered
    Red,
}

impl From<ShardStatus> for CollectionStatus {
    fn from(info: ShardStatus) -> Self {
        match info {
            ShardStatus::Green => Self::Green,
            ShardStatus::Yellow => Self::Yellow,
            ShardStatus::Grey => Self::Grey,
            ShardStatus::Red => Self::Red,
        }
    }
}

/// State of existence of a collection,
/// true = exists, false = does not exist
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct CollectionExistence {
    pub exists: bool,
}

/// Current state of the collection
#[derive(
    Debug, Default, Serialize, JsonSchema, Anonymize, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[serde(rename_all = "snake_case")]
pub enum OptimizersStatus {
    /// Optimizers are reporting as expected
    #[default]
    Ok,
    /// Something wrong happened with optimizers
    #[anonymize(false)]
    Error(String),
}

#[derive(
    Debug, Default, Serialize, JsonSchema, Anonymize, PartialEq, Eq, PartialOrd, Ord, Clone,
)]
#[serde(rename_all = "snake_case")]
pub struct CollectionWarning {
    /// Warning message
    #[anonymize(true)] // Might contain vector names
    pub message: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema, Default, Anonymize)]
pub struct ShardUpdateQueueInfo {
    /// Number of elements in the queue
    #[anonymize(false)]
    pub length: usize,

    /// last operation number processed
    #[anonymize(false)]
    pub op_num: Option<usize>,

    /// Number of points that are deferred (i.e hidden from search as they're not yet optimized).
    #[anonymize(false)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_points: Option<usize>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, Default, Anonymize)]
pub struct UpdateQueueInfo {
    /// Number of elements in the queue
    #[anonymize(false)]
    pub length: usize,

    /// Number of points that are deferred (i.e hidden from search as they're not yet optimized).
    #[anonymize(false)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_points: Option<usize>,
}

// Version of the collection config we can present to the user
/// Information about the collection configuration
#[derive(Debug, Serialize, JsonSchema)]
pub struct CollectionConfig {
    pub params: CollectionParams,
    pub hnsw_config: HnswConfig,
    pub optimizer_config: OptimizersConfig,
    pub wal_config: Option<WalConfig>,
    #[serde(default)]
    pub quantization_config: Option<QuantizationConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_mode_config: Option<StrictModeConfigOutput>,
    /// Arbitrary JSON metadata for the collection
    /// This can be used to store application-specific information
    /// such as creation time, migration data, inference model info, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Payload>,
}

impl From<CollectionConfigInternal> for CollectionConfig {
    fn from(config: CollectionConfigInternal) -> Self {
        let CollectionConfigInternal {
            params,
            hnsw_config,
            optimizer_config,
            wal_config,
            quantization_config,
            strict_mode_config,
            // Internal UUID to identify unique collections in consensus snapshots
            uuid: _,
            metadata,
        } = config;

        CollectionConfig {
            params,
            hnsw_config,
            optimizer_config,
            wal_config: Some(wal_config),
            quantization_config,
            strict_mode_config: strict_mode_config.map(StrictModeConfigOutput::from),
            metadata,
        }
    }
}

/// Current statistics and configuration of the collection
#[derive(Debug, Serialize, JsonSchema)]
pub struct CollectionInfo {
    /// Status of the collection
    pub status: CollectionStatus,
    /// Status of optimizers
    pub optimizer_status: OptimizersStatus,
    /// Warnings related to the collection
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<CollectionWarning>,
    /// Approximate number of indexed vectors in the collection.
    /// Indexed vectors in large segments are faster to query,
    /// as it is stored in a specialized vector index.
    pub indexed_vectors_count: Option<usize>,
    /// Approximate number of points (vectors + payloads) in collection.
    /// Each point could be accessed by unique id.
    pub points_count: Option<usize>,
    /// Number of segments in collection.
    /// Each segment has independent vector as payload indexes
    pub segments_count: usize,
    /// Collection settings
    pub config: CollectionConfig,
    /// Types of stored payload
    pub payload_schema: HashMap<PayloadKeyType, PayloadIndexInfo>,
    /// Update queue info
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_queue: Option<UpdateQueueInfo>,
}

impl CollectionInfo {
    pub fn empty(
        collection_config: CollectionConfigInternal,
        payload_schema: PayloadIndexSchema,
    ) -> Self {
        Self {
            status: CollectionStatus::Green,
            optimizer_status: OptimizersStatus::Ok,
            warnings: collection_config.get_warnings(),
            indexed_vectors_count: Some(0),
            points_count: Some(0),
            segments_count: 0,
            config: CollectionConfig::from(collection_config),
            payload_schema: payload_schema
                .schema
                .into_iter()
                .map(|(k, v)| (k, PayloadIndexInfo::new(v, 0)))
                .collect(),
            update_queue: Some(UpdateQueueInfo::default()),
        }
    }
}

impl From<ShardInfoInternal> for CollectionInfo {
    fn from(info: ShardInfoInternal) -> Self {
        let ShardInfoInternal {
            status,
            optimizer_status,
            indexed_vectors_count,
            points_count,
            segments_count,
            config,
            payload_schema,
            update_queue,
        } = info;
        Self {
            status: status.into(),
            optimizer_status,
            warnings: config.get_warnings(),
            indexed_vectors_count: Some(indexed_vectors_count),
            points_count: Some(points_count),
            segments_count,
            config: CollectionConfig::from(config),
            payload_schema,
            update_queue: Some(UpdateQueueInfo::from(update_queue)),
        }
    }
}

impl From<ShardUpdateQueueInfo> for UpdateQueueInfo {
    fn from(value: ShardUpdateQueueInfo) -> Self {
        // ignore field `op_num`, no sane way to aggregate across shards
        let ShardUpdateQueueInfo {
            length,
            op_num: _,
            deferred_points,
        } = value;
        UpdateQueueInfo {
            length,
            deferred_points,
        }
    }
}

/// Internal statistics and configuration of the collection.
#[derive(Debug)]
pub struct ShardInfoInternal {
    /// Status of the shard
    pub status: ShardStatus,
    /// Status of optimizers
    pub optimizer_status: OptimizersStatus,
    /// Approximate number of indexed vectors in the shard.
    /// Indexed vectors in large segments are faster to query,
    /// as it is stored in vector index (HNSW).
    pub indexed_vectors_count: usize,
    /// Approximate number of points (vectors + payloads) in shard.
    /// Each point could be accessed by unique id.
    pub points_count: usize,
    /// Number of segments in shard.
    /// Each segment has independent vector as payload indexes
    pub segments_count: usize,
    /// Collection settings
    pub config: CollectionConfigInternal,
    /// Types of stored payload
    pub payload_schema: HashMap<PayloadKeyType, PayloadIndexInfo>,
    /// Update queue state
    pub update_queue: ShardUpdateQueueInfo,
}

/// Current clustering distribution for the collection
#[derive(Debug, Serialize, JsonSchema)]
pub struct CollectionClusterInfo {
    /// ID of this peer
    pub peer_id: PeerId,
    /// Total number of shards
    pub shard_count: usize,
    /// Local shards
    pub local_shards: Vec<LocalShardInfo>,
    /// Remote shards
    pub remote_shards: Vec<RemoteShardInfo>,
    /// Shard transfers
    pub shard_transfers: Vec<ShardTransferInfo>,
    /// Resharding operations
    // TODO(resharding): remove this skip when releasing resharding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resharding_operations: Option<Vec<ReshardingInfo>>,
}

#[derive(Debug, Serialize, JsonSchema, Clone, Anonymize)]
pub struct ShardTransferInfo {
    #[anonymize(false)]
    pub shard_id: ShardId,

    /// Target shard ID if different than source shard ID
    ///
    /// Used exclusively with `ReshardingStreamRecords` transfer method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[anonymize(false)]
    pub to_shard_id: Option<ShardId>,

    /// Source peer id
    #[anonymize(false)]
    pub from: PeerId,

    /// Destination peer id
    #[anonymize(false)]
    pub to: PeerId,

    /// If `true` transfer is a synchronization of a replicas
    /// If `false` transfer is a moving of a shard from one peer to another
    #[anonymize(false)]
    pub sync: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[anonymize(false)]
    pub method: Option<ShardTransferMethod>,

    /// A human-readable report of the transfer progress. Available only on the source peer.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[anonymize(false)]
    pub comment: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema, Clone, Anonymize)]
pub struct ReshardingInfo {
    #[schemars(skip)]
    pub uuid: Uuid,

    #[anonymize(false)]
    pub direction: ReshardingDirection,

    #[anonymize(false)]
    pub shard_id: ShardId,

    #[anonymize(false)]
    pub peer_id: PeerId,

    pub shard_key: Option<ShardKey>,

    /// Only included in peer telemetry
    #[serde(skip)]
    #[anonymize(false)]
    pub stage: ReshardingStage,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct LocalShardInfo {
    /// Local shard id
    pub shard_id: ShardId,
    /// User-defined sharding key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKey>,
    /// Number of points in the shard
    pub points_count: usize,
    /// Is replica active
    pub state: ReplicaState,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct RemoteShardInfo {
    /// Remote shard id
    pub shard_id: ShardId,
    /// User-defined sharding key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKey>,
    /// Remote peer id
    pub peer_id: PeerId,
    /// Is replica active
    pub state: ReplicaState,
}

/// `Acknowledged` - Request is saved to WAL and will be process in a queue.
/// `Completed` - Request is completed, changes are actual.
/// `WaitTimeout` - Request is waiting for timeout.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Acknowledged,
    Completed,
    WaitTimeout,
    /// Internal: update is rejected due to an outdated clock
    #[schemars(skip)]
    ClockRejected,
}

impl UpdateStatus {
    /// Returns priority of the update status
    ///
    /// A higher value means the status is more significant
    pub fn priority(&self) -> i32 {
        match self {
            UpdateStatus::Acknowledged => 0,
            UpdateStatus::Completed => 1,
            UpdateStatus::WaitTimeout => 2,
            UpdateStatus::ClockRejected => 3,
        }
    }

    pub fn is_timeout(&self) -> bool {
        match self {
            UpdateStatus::WaitTimeout => true,
            UpdateStatus::Acknowledged => false,
            UpdateStatus::Completed => false,
            UpdateStatus::ClockRejected => false,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct UpdateResult {
    /// Sequential number of the operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<SeqNumberType>,

    /// Update status
    pub status: UpdateStatus,

    /// Updated value for the external clock tick
    /// Provided if incoming update request also specify clock tick
    #[serde(skip)]
    pub clock_tag: Option<ClockTag>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ScrollRequest {
    #[serde(flatten)]
    #[validate(nested)]
    pub scroll_request: ScrollRequestInternal,
    /// Specify in which shards to look for the points, if not specified - look in all shards
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKeySelector>,
}

fn points_example() -> Vec<api::rest::Record> {
    let mut payload_map_1 = Map::new();
    payload_map_1.insert("city".to_string(), Value::String("London".to_string()));
    payload_map_1.insert("color".to_string(), Value::String("green".to_string()));

    let mut payload_map_2 = Map::new();
    payload_map_2.insert("city".to_string(), Value::String("Paris".to_string()));
    payload_map_2.insert("color".to_string(), Value::String("red".to_string()));

    vec![
        api::rest::Record {
            id: PointIdType::NumId(40),
            payload: Some(Payload(payload_map_1)),
            vector: Some(VectorStructOutput::Single(vec![0.875, 0.140625, 0.897_6])),
            shard_key: Some("region_1".into()),
            order_value: None,
        },
        api::rest::Record {
            id: PointIdType::NumId(41),
            payload: Some(Payload(payload_map_2)),
            vector: Some(VectorStructOutput::Single(vec![0.75, 0.640625, 0.8945])),
            shard_key: Some("region_1".into()),
            order_value: None,
        },
    ]
}

/// Result of the points read request
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ScrollResult {
    /// List of retrieved points
    #[schemars(example = "points_example")]
    pub points: Vec<api::rest::Record>,
    /// Offset which should be used to retrieve a next page result
    pub next_page_offset: Option<PointIdType>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SearchRequest {
    #[serde(flatten)]
    #[validate(nested)]
    pub search_request: SearchRequestInternal,
    /// Specify in which shards to look for the points, if not specified - look in all shards
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKeySelector>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SearchRequestBatch {
    #[validate(nested)]
    pub searches: Vec<SearchRequest>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone)]
pub struct SearchGroupsRequest {
    #[serde(flatten)]
    #[validate(nested)]
    pub search_group_request: SearchGroupsRequestInternal,
    /// Specify in which shards to look for the points, if not specified - look in all shards
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKeySelector>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
pub struct PointRequest {
    #[serde(flatten)]
    #[validate(nested)]
    pub point_request: PointRequestInternal,
    /// Specify in which shards to look for the points, if not specified - look in all shards
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKeySelector>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone, PartialEq, Hash)]
#[serde(rename_all = "snake_case")]
pub struct PointRequestInternal {
    /// Look for points with ids
    pub ids: Vec<PointIdType>,
    /// Select which payload to return with the response. Default is true.
    pub with_payload: Option<WithPayloadInterface>,
    /// Options for specifying which vectors to include into response. Default is false.
    #[serde(default, alias = "with_vectors")]
    pub with_vector: WithVector,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[serde(untagged)]
pub enum RecommendExample {
    PointId(PointIdType),
    Dense(DenseVector),
    Sparse(SparseVector),
}

impl RecommendExample {
    pub fn as_point_id(&self) -> Option<PointIdType> {
        match self {
            RecommendExample::PointId(id) => Some(*id),
            _ => None,
        }
    }
}

impl Validate for RecommendExample {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            RecommendExample::PointId(_) => Ok(()),
            RecommendExample::Dense(_) => Ok(()),
            RecommendExample::Sparse(sparse) => sparse.validate(),
        }
    }
}

impl From<u64> for RecommendExample {
    fn from(id: u64) -> Self {
        RecommendExample::PointId(id.into())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq)]
#[serde(rename_all = "snake_case", untagged)]
pub enum UsingVector {
    Name(VectorNameBuf),
}

impl UsingVector {
    pub fn as_name(&self) -> VectorNameBuf {
        match self {
            UsingVector::Name(name) => name.clone(),
        }
    }
}

impl From<VectorNameBuf> for UsingVector {
    fn from(name: VectorNameBuf) -> Self {
        UsingVector::Name(name)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Default, Clone)]
#[serde(rename_all = "snake_case")]
pub struct RecommendRequest {
    #[serde(flatten)]
    #[validate(nested)]
    pub recommend_request: RecommendRequestInternal,
    /// Specify in which shards to look for the points, if not specified - look in all shards
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKeySelector>,
}

/// Recommendation request.
/// Provides positive and negative examples of the vectors, which can be ids of points that
/// are already stored in the collection, raw vectors, or even ids and vectors combined.
///
/// Service should look for the points which are closer to positive examples and at the same time
/// further to negative examples. The concrete way of how to compare negative and positive distances
/// is up to the `strategy` chosen.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Default, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RecommendRequestInternal {
    /// Look for vectors closest to those
    #[serde(default)]
    #[validate(nested)]
    pub positive: Vec<RecommendExample>,

    /// Try to avoid vectors like this
    #[serde(default)]
    #[validate(nested)]
    pub negative: Vec<RecommendExample>,

    /// How to use positive and negative examples to find the results
    pub strategy: Option<api::rest::RecommendStrategy>,

    /// Look only for points which satisfies this conditions
    #[validate(nested)]
    pub filter: Option<Filter>,

    /// Additional search params
    #[validate(nested)]
    pub params: Option<SearchParams>,

    /// Max number of result to return
    #[serde(alias = "top")]
    #[validate(range(min = 1))]
    pub limit: usize,

    /// Offset of the first result to return.
    /// May be used to paginate results.
    /// Note: large offset values may cause performance issues.
    pub offset: Option<usize>,

    /// Select which payload to return with the response. Default is false.
    pub with_payload: Option<WithPayloadInterface>,

    /// Options for specifying which vectors to include into response. Default is false.
    #[serde(default, alias = "with_vectors")]
    pub with_vector: Option<WithVector>,

    /// Define a minimal score threshold for the result.
    /// If defined, less similar results will not be returned.
    /// Score of the returned result might be higher or smaller than the threshold depending on the
    /// Distance function used. E.g. for cosine similarity only higher scores will be returned.
    pub score_threshold: Option<ScoreType>,

    /// Define which vector to use for recommendation, if not specified - try to use default vector
    #[serde(default)]
    pub using: Option<UsingVector>,

    /// The location used to lookup vectors. If not specified - use current collection.
    /// Note: the other collection should have the same vector size as the current collection
    #[serde(default)]
    pub lookup_from: Option<LookupLocation>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
#[serde(rename_all = "snake_case")]
pub struct RecommendRequestBatch {
    #[validate(nested)]
    pub searches: Vec<RecommendRequest>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone)]
#[serde(rename_all = "snake_case")]
pub struct RecommendGroupsRequest {
    #[serde(flatten)]
    #[validate(nested)]
    pub recommend_group_request: RecommendGroupsRequestInternal,
    /// Specify in which shards to look for the points, if not specified - look in all shards
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKeySelector>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone, PartialEq)]
pub struct RecommendGroupsRequestInternal {
    /// Look for vectors closest to those
    #[serde(default)]
    pub positive: Vec<RecommendExample>,

    /// Try to avoid vectors like this
    #[serde(default)]
    pub negative: Vec<RecommendExample>,

    /// How to use positive and negative examples to find the results
    #[serde(default)]
    pub strategy: Option<RecommendStrategy>,

    /// Look only for points which satisfies this conditions
    #[validate(nested)]
    pub filter: Option<Filter>,

    /// Additional search params
    #[validate(nested)]
    pub params: Option<SearchParams>,

    /// Select which payload to return with the response. Default is false.
    pub with_payload: Option<WithPayloadInterface>,

    /// Options for specifying which vectors to include into response. Default is false.
    #[serde(default, alias = "with_vectors")]
    pub with_vector: Option<WithVector>,

    /// Define a minimal score threshold for the result.
    /// If defined, less similar results will not be returned.
    /// Score of the returned result might be higher or smaller than the threshold depending on the
    /// Distance function used. E.g. for cosine similarity only higher scores will be returned.
    pub score_threshold: Option<ScoreType>,

    /// Define which vector to use for recommendation, if not specified - try to use default vector
    #[serde(default)]
    pub using: Option<UsingVector>,

    /// The location used to lookup vectors. If not specified - use current collection.
    /// Note: the other collection should have the same vector size as the current collection
    #[serde(default)]
    pub lookup_from: Option<LookupLocation>,

    #[serde(flatten)]
    pub group_request: BaseGroupRequest,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone, PartialEq)]
pub struct ContextExamplePair {
    #[validate(nested)]
    pub positive: RecommendExample,
    #[validate(nested)]
    pub negative: RecommendExample,
}

impl ContextExamplePair {
    pub fn iter(&self) -> impl Iterator<Item = &RecommendExample> {
        iter::once(&self.positive).chain(iter::once(&self.negative))
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone)]
pub struct DiscoverRequest {
    #[serde(flatten)]
    #[validate(nested)]
    pub discover_request: DiscoverRequestInternal,
    /// Specify in which shards to look for the points, if not specified - look in all shards
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKeySelector>,
}

/// Use context and a target to find the most similar points, constrained by the context.
#[derive(Deserialize, Serialize, JsonSchema, Validate, Clone, Debug, PartialEq)]
pub struct DiscoverRequestInternal {
    /// Look for vectors closest to this.
    ///
    /// When using the target (with or without context), the integer part of the score represents
    /// the rank with respect to the context, while the decimal part of the score relates to the
    /// distance to the target.
    #[validate(nested)]
    pub target: Option<RecommendExample>,

    /// Pairs of { positive, negative } examples to constrain the search.
    ///
    /// When using only the context (without a target), a special search - called context search - is
    /// performed where pairs of points are used to generate a loss that guides the search towards the
    /// zone where most positive examples overlap. This means that the score minimizes the scenario of
    /// finding a point closer to a negative than to a positive part of a pair.
    ///
    /// Since the score of a context relates to loss, the maximum score a point can get is 0.0,
    /// and it becomes normal that many points can have a score of 0.0.
    ///
    /// For discovery search (when including a target), the context part of the score for each pair
    /// is calculated +1 if the point is closer to a positive than to a negative part of a pair,
    /// and -1 otherwise.
    #[validate(nested)]
    pub context: Option<Vec<ContextExamplePair>>,

    /// Look only for points which satisfies this conditions
    #[validate(nested)]
    pub filter: Option<Filter>,

    /// Additional search params
    #[validate(nested)]
    pub params: Option<SearchParams>,

    /// Max number of result to return
    #[serde(alias = "top")]
    #[validate(range(min = 1))]
    pub limit: usize,

    /// Offset of the first result to return.
    /// May be used to paginate results.
    /// Note: large offset values may cause performance issues.
    pub offset: Option<usize>,

    /// Select which payload to return with the response. Default is false.
    pub with_payload: Option<WithPayloadInterface>,

    /// Options for specifying which vectors to include into response. Default is false.
    pub with_vector: Option<WithVector>,

    /// Define which vector to use for recommendation, if not specified - try to use default vector
    #[serde(default)]
    pub using: Option<UsingVector>,

    /// The location used to lookup vectors. If not specified - use current collection.
    /// Note: the other collection should have the same vector size as the current collection
    #[serde(default)]
    pub lookup_from: Option<LookupLocation>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, Clone)]
pub struct DiscoverRequestBatch {
    #[validate(nested)]
    pub searches: Vec<DiscoverRequest>,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct PointGroup {
    /// Scored points that have the same value of the group_by key
    pub hits: Vec<api::rest::ScoredPoint>,
    /// Value of the group_by key, shared across all the hits in the group
    pub id: GroupId,
    /// Record that has been looked up using the group id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup: Option<api::rest::Record>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GroupsResult {
    pub groups: Vec<PointGroup>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate)]
#[serde(rename_all = "snake_case")]
pub struct CountRequest {
    #[serde(flatten)]
    #[validate(nested)]
    pub count_request: CountRequestInternal,
    /// Specify in which shards to look for the points, if not specified - look in all shards
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_key: Option<ShardKeySelector>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct CountResult {
    /// Number of points which satisfy the conditions
    pub count: usize,
}

#[derive(Error, Debug, Clone, PartialEq)]
#[error("{0}")]
pub enum CollectionError {
    #[error("Wrong input: {description}")]
    BadInput { description: String },
    #[error("{what} not found")]
    NotFound { what: String },
    #[error("No point with id {missed_point_id} found")]
    PointNotFound { missed_point_id: PointIdType },
    #[error("Service internal error: {error}")]
    ServiceError {
        error: String,
        backtrace: Option<String>,
    },
    #[error("Bad request: {description}")]
    BadRequest { description: String },
    #[error("Operation Cancelled: {description}")]
    Cancelled { description: String },
    #[error("Bad shard selection: {description}")]
    BadShardSelection { description: String },
    #[error(
        "{shards_failed} out of {shards_total} shards failed to apply operation. First error captured: {first_err}"
    )]
    InconsistentShardFailure {
        shards_total: u32,
        shards_failed: u32,
        first_err: Box<CollectionError>,
    },
    #[error("Remote shard on {peer_id} failed during forward proxy operation: {error}")]
    ForwardProxyError { peer_id: PeerId, error: Box<Self> },
    #[error("Out of memory, free: {free}, {description}")]
    OutOfMemory { description: String, free: u64 },
    #[error("Timeout error: {description}")]
    Timeout { description: String },
    #[error("Precondition failed: {description}")]
    PreConditionFailed { description: String },
    #[error("Object Store error: {what}")]
    ObjectStoreError { what: String },
    #[error("Strict mode error: {description}")]
    StrictMode { description: String },
    #[error("{description}")]
    InferenceError { description: String },
    #[error("Rate limiting exceeded: {description}")]
    RateLimitExceeded {
        description: String,
        retry_after: Option<Duration>,
    },
    #[error("Shard temporarily unavailable: {description}")]
    ShardUnavailable { description: String },
}

impl CollectionError {
    pub fn timeout(timeout: Duration, operation: impl Into<String>) -> Self {
        Self::Timeout {
            description: format!(
                "Operation '{}' timed out after {timeout:?}",
                operation.into(),
            ),
        }
    }

    pub fn service_error(error: impl Into<String>) -> Self {
        Self::ServiceError {
            error: error.into(),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }

    pub fn bad_input(description: impl Into<String>) -> Self {
        Self::BadInput {
            description: description.into(),
        }
    }

    pub fn not_found(what: impl Into<String>) -> Self {
        Self::NotFound { what: what.into() }
    }

    pub fn cancelled(description: impl Into<String>) -> Self {
        Self::Cancelled {
            description: description.into(),
        }
    }

    pub fn bad_request(description: impl Into<String>) -> Self {
        Self::BadRequest {
            description: description.into(),
        }
    }

    pub fn bad_shard_selection(description: String) -> Self {
        Self::BadShardSelection { description }
    }

    pub fn object_storage_error(what: impl Into<String>) -> Self {
        Self::ObjectStoreError { what: what.into() }
    }

    pub fn forward_proxy_error(peer_id: PeerId, error: impl Into<Self>) -> Self {
        Self::ForwardProxyError {
            peer_id,
            error: Box::new(error.into()),
        }
    }

    pub fn remote_peer_id(&self) -> Option<PeerId> {
        match self {
            Self::ForwardProxyError { peer_id, .. } => Some(*peer_id),
            _ => None,
        }
    }

    pub fn shard_key_not_found(shard_key: &Option<ShardKey>) -> Self {
        match shard_key {
            Some(shard_key) => Self::NotFound {
                what: format!("Shard key {shard_key} not found"),
            },
            None => Self::NotFound {
                what: "Shard expected, but not provided".to_string(),
            },
        }
    }

    pub fn pre_condition_failed(description: impl Into<String>) -> Self {
        Self::PreConditionFailed {
            description: description.into(),
        }
    }

    pub fn strict_mode(error: impl Into<String>, solution: impl Into<String>) -> Self {
        let description = format!("{}. Help: {}", error.into(), solution.into());
        Self::StrictMode { description }
    }

    pub fn rate_limit_error(
        rate_limit_error: RateLimitError,
        cost: usize,
        write_limit_type: bool, // false = read rate limit; true = write rate limit.
    ) -> Self {
        let rate_limiter_type = if write_limit_type { "Write" } else { "Read" };
        let (description, retry_after) = match rate_limit_error {
            RateLimitError::AlwaysOverBudget(msg) => {
                let description = format!("{rate_limiter_type} rate limit exceeded, {msg}",);
                // no point in retrying this one
                (description, None)
            }
            RateLimitError::Retry(retry_error) => {
                let RetryError {
                    tokens_available,
                    retry_after,
                } = retry_error;
                let description = format!(
                    "{rate_limiter_type} rate limit exceeded: Operation requires {cost} tokens but only {tokens_available:.1} were available. Retry after {}s",
                    retry_after.as_secs_f32().ceil() as u32,
                );
                (description, Some(retry_after))
            }
        };
        Self::RateLimitExceeded {
            description,
            retry_after,
        }
    }

    pub fn shard_unavailable(description: impl Into<String>) -> Self {
        Self::ShardUnavailable {
            description: description.into(),
        }
    }

    /// Returns true if the error is transient and the operation can be retried.
    /// Returns false if the error is not transient and the operation should fail on all replicas.
    pub fn is_transient(&self) -> bool {
        match self {
            // Transient
            Self::ServiceError { .. } => true,
            Self::Timeout { .. } => true,
            Self::Cancelled { .. } => true,
            Self::OutOfMemory { .. } => true,
            Self::PreConditionFailed { .. } => true,
            Self::ShardUnavailable { .. } => true,
            // Not transient
            Self::BadInput { .. } => false,
            Self::NotFound { .. } => false,
            Self::PointNotFound { .. } => false,
            Self::BadRequest { .. } => false,
            Self::BadShardSelection { .. } => false,
            Self::InconsistentShardFailure { .. } => false,
            Self::ForwardProxyError { .. } => false,
            Self::ObjectStoreError { .. } => false,
            Self::StrictMode { .. } => false,
            Self::InferenceError { .. } => false,
            Self::RateLimitExceeded { .. } => false,
        }
    }

    pub fn is_pre_condition_failed(&self) -> bool {
        matches!(self, Self::PreConditionFailed { .. })
    }

    pub fn is_missing_point(&self) -> bool {
        match self {
            Self::NotFound { what } => what.contains("No point with id"),
            Self::PointNotFound { .. } => true,
            _ => false,
        }
    }
}

impl From<SystemTimeError> for CollectionError {
    fn from(error: SystemTimeError) -> CollectionError {
        CollectionError::ServiceError {
            error: format!("System time error: {error}"),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<String> for CollectionError {
    fn from(error: String) -> CollectionError {
        CollectionError::ServiceError {
            error,
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<OperationError> for CollectionError {
    fn from(err: OperationError) -> Self {
        match err {
            OperationError::WrongVectorDimension { .. } => Self::BadInput {
                description: format!("{err}"),
            },
            OperationError::VectorNameNotExists { .. } => Self::BadInput {
                description: format!("{err}"),
            },
            OperationError::PointIdError { missed_point_id } => {
                Self::PointNotFound { missed_point_id }
            }
            OperationError::ServiceError {
                description,
                backtrace,
            } => Self::ServiceError {
                error: description,
                backtrace,
            },
            OperationError::TypeError { .. } => Self::BadInput {
                description: format!("{err}"),
            },
            OperationError::Cancelled { description } => Self::Cancelled { description },
            OperationError::TypeInferenceError { .. } => Self::BadInput {
                description: format!("{err}"),
            },
            OperationError::OutOfMemory { description, free } => {
                Self::OutOfMemory { description, free }
            }
            OperationError::Timeout { description } => Self::Timeout { description },
            OperationError::InconsistentStorage { .. } => Self::ServiceError {
                error: format!("{err}"),
                backtrace: None,
            },
            OperationError::ValidationError { .. } => Self::BadInput {
                description: format!("{err}"),
            },
            OperationError::WrongSparse => Self::BadInput {
                description: "Conversion between sparse and regular vectors failed".to_string(),
            },
            OperationError::WrongMulti => Self::BadInput {
                description: "Conversion between multi and regular vectors failed".to_string(),
            },
            OperationError::MissingRangeIndexForOrderBy { .. } => Self::bad_input(format!("{err}")),
            OperationError::MissingMapIndexForFacet { .. } => Self::bad_input(format!("{err}")),
            OperationError::VariableTypeError { .. } => Self::bad_input(format!("{err}")),
            OperationError::NonFiniteNumber { .. } => Self::bad_input(format!("{err}")),
            OperationError::RocksDbColumnFamilyNotFound { .. } => Self::ServiceError {
                error: format!("{err}"),
                backtrace: None,
            },
        }
    }
}

impl From<CancelledError> for CollectionError {
    fn from(error: CancelledError) -> Self {
        OperationError::from(error).into()
    }
}

impl From<OneshotRecvError> for CollectionError {
    fn from(err: OneshotRecvError) -> Self {
        Self::ServiceError {
            error: format!("{err}"),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<JoinError> for CollectionError {
    fn from(err: JoinError) -> Self {
        Self::ServiceError {
            error: format!("{err}"),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<WalError> for CollectionError {
    fn from(err: WalError) -> Self {
        Self::ServiceError {
            error: format!("{err}"),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl<T> From<SendError<T>> for CollectionError {
    fn from(err: SendError<T>) -> Self {
        Self::ServiceError {
            error: format!("Can't reach one of the workers: {err}"),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<JsonError> for CollectionError {
    fn from(err: JsonError) -> Self {
        CollectionError::ServiceError {
            error: format!("Json error: {err}"),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<std::io::Error> for CollectionError {
    fn from(err: std::io::Error) -> Self {
        CollectionError::ServiceError {
            error: format!("File IO error: {err}"),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<tonic::transport::Error> for CollectionError {
    fn from(err: tonic::transport::Error) -> Self {
        CollectionError::ServiceError {
            error: format!("Tonic transport error: {err}"),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<InvalidUri> for CollectionError {
    fn from(_err: InvalidUri) -> Self {
        CollectionError::ServiceError {
            error: "Invalid URI error".to_string(),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<tonic::Status> for CollectionError {
    fn from(err: tonic::Status) -> Self {
        match err.code() {
            tonic::Code::InvalidArgument => CollectionError::BadInput {
                description: "InvalidArgument".to_string(),
            },
            tonic::Code::AlreadyExists => CollectionError::BadInput {
                description: format!("AlreadyExists: {err}"),
            },
            tonic::Code::NotFound => CollectionError::NotFound {
                what: format!("{err}"),
            },
            tonic::Code::Internal => CollectionError::ServiceError {
                error: format!("Internal error: {err}"),
                backtrace: Some(Backtrace::force_capture().to_string()),
            },
            tonic::Code::DeadlineExceeded => CollectionError::Timeout {
                description: format!("Deadline Exceeded: {err}"),
            },
            tonic::Code::Cancelled => CollectionError::Cancelled {
                description: format!("{err}"),
            },
            tonic::Code::FailedPrecondition => CollectionError::PreConditionFailed {
                description: format!("{err}"),
            },
            tonic::Code::ResourceExhausted => {
                // extract retry-after from metadata
                // the value is passed as a String containing an integer number of seconds
                let retry_after = err.metadata().get("retry-after").and_then(|v| {
                    v.to_str()
                        .inspect_err(|e| log::info!("Failed to parse retry-after header: {e}"))
                        .ok()
                        .and_then(|v| {
                            v.parse::<u64>()
                                .inspect_err(|e| {
                                    log::info!("Failed to parse retry-after value in gRPC metadata (value: {v}): {e}")
                                })
                                .ok()
                        })
                        .map(Duration::from_secs)
                });
                CollectionError::RateLimitExceeded {
                    description: format!("{err}"),
                    retry_after,
                }
            }
            tonic::Code::Ok
            | tonic::Code::Unknown
            | tonic::Code::PermissionDenied
            | tonic::Code::Aborted
            | tonic::Code::OutOfRange
            | tonic::Code::Unimplemented
            | tonic::Code::Unavailable
            | tonic::Code::DataLoss
            | tonic::Code::Unauthenticated => CollectionError::ServiceError {
                error: format!("Tonic status error: {err}"),
                backtrace: Some(Backtrace::force_capture().to_string()),
            },
        }
    }
}

impl<Guard> From<std::sync::PoisonError<Guard>> for CollectionError {
    fn from(err: std::sync::PoisonError<Guard>) -> Self {
        CollectionError::ServiceError {
            error: format!("Mutex lock poisoned: {err}"),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<FileStorageError> for CollectionError {
    fn from(err: FileStorageError) -> Self {
        Self::service_error(err.to_string())
    }
}

impl From<RequestError<tonic::Status>> for CollectionError {
    fn from(err: RequestError<tonic::Status>) -> Self {
        match err {
            RequestError::FromClosure(status) => status.into(),
            RequestError::Tonic(err) => {
                let mut msg = err.to_string();
                for src in iter::successors(err.source(), |&src| src.source()) {
                    let _ = write!(&mut msg, ": {src}");
                }
                CollectionError::service_error(msg)
            }
        }
    }
}

impl From<save_on_disk::Error> for CollectionError {
    fn from(err: save_on_disk::Error) -> Self {
        CollectionError::ServiceError {
            error: err.to_string(),
            backtrace: Some(Backtrace::force_capture().to_string()),
        }
    }
}

impl From<validator::ValidationErrors> for CollectionError {
    fn from(err: validator::ValidationErrors) -> Self {
        CollectionError::BadInput {
            description: format!("{err}"),
        }
    }
}

impl From<cancel::Error> for CollectionError {
    fn from(err: cancel::Error) -> Self {
        match err {
            cancel::Error::Join(err) => err.into(),
            cancel::Error::Cancelled => Self::Cancelled {
                description: err.to_string(),
            },
        }
    }
}

impl From<tempfile::PathPersistError> for CollectionError {
    fn from(err: tempfile::PathPersistError) -> Self {
        Self::service_error(format!(
            "failed to persist temporary file path {}: {}",
            err.path.display(),
            err.error,
        ))
    }
}

pub type CollectionResult<T> = Result<T, CollectionError>;

#[derive(
    Default, Debug, Deserialize, Serialize, JsonSchema, Anonymize, Eq, PartialEq, Copy, Clone, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum Datatype {
    #[default]
    Float32,
    Uint8,
    Float16,
}

impl From<Datatype> for VectorStorageDatatype {
    fn from(value: Datatype) -> Self {
        match value {
            Datatype::Float32 => VectorStorageDatatype::Float32,
            Datatype::Uint8 => VectorStorageDatatype::Uint8,
            Datatype::Float16 => VectorStorageDatatype::Float16,
        }
    }
}

/// Params of single vector data storage
#[derive(
    Debug, Hash, Deserialize, Serialize, JsonSchema, Validate, Anonymize, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
#[anonymize(false)]
pub struct VectorParams {
    /// Size of a vectors used
    #[validate(custom(function = "validate_nonzerou64_range_min_1_max_65536"))]
    pub size: NonZeroU64,
    /// Type of distance function used for measuring distance between vectors
    pub distance: Distance,
    /// Custom params for HNSW index. If none - values from collection configuration are used.
    #[serde(default, skip_serializing_if = "is_hnsw_diff_empty")]
    #[validate(nested)]
    pub hnsw_config: Option<HnswConfigDiff>,
    /// Custom params for quantization. If none - values from collection configuration are used.
    #[serde(
        default,
        alias = "quantization",
        skip_serializing_if = "Option::is_none"
    )]
    #[validate(nested)]
    pub quantization_config: Option<QuantizationConfig>,
    /// If true, vectors are served from disk, improving RAM usage at the cost of latency
    /// Default: false
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_disk: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Defines which datatype should be used to represent vectors in the storage.
    /// Choosing different datatypes allows to optimize memory usage and performance vs accuracy.
    ///
    /// - For `float32` datatype - vectors are stored as single-precision floating point numbers,
    ///   4 bytes.
    /// - For `float16` datatype - vectors are stored as half-precision floating point numbers,
    ///   2 bytes.
    /// - For `uint8` datatype - vectors are stored as unsigned 8-bit integers, 1 byte.
    ///   It expects vector elements to be in range `[0, 255]`.
    pub datatype: Option<Datatype>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multivector_config: Option<MultiVectorConfig>,
}

/// Validate the value is in `[1, 65536]` or `None`.
pub fn validate_nonzerou64_range_min_1_max_65536(
    value: &NonZeroU64,
) -> Result<(), ValidationError> {
    validate_range_generic(value.get(), Some(1), Some(65536))
}

/// Is considered empty if `None` or if diff has no field specified
fn is_hnsw_diff_empty(hnsw_config: &Option<HnswConfigDiff>) -> bool {
    hnsw_config.is_none() || *hnsw_config == Some(HnswConfigDiff::default())
}

/// Params of single sparse vector data storage
#[derive(
    Debug, Hash, Deserialize, Serialize, JsonSchema, Validate, Anonymize, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub struct SparseVectorParams {
    /// Custom params for index. If none - values from collection configuration are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<SparseIndexParams>,

    /// Configures addition value modifications for sparse vectors.
    /// Default: none
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modifier: Option<Modifier>,
}

impl SparseVectorParams {
    pub fn storage_type(&self) -> SparseVectorStorageType {
        SparseVectorStorageType::default()
    }
}

/// Configuration for sparse inverted index.
#[derive(
    Debug, Hash, Deserialize, Serialize, JsonSchema, Anonymize, Copy, Clone, PartialEq, Eq, Default,
)]
#[serde(rename_all = "snake_case")]
pub struct SparseIndexParams {
    /// We prefer a full scan search upto (excluding) this number of vectors.
    ///
    /// Note: this is number of vectors, not KiloBytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[anonymize(false)]
    pub full_scan_threshold: Option<usize>,
    /// Store index on disk. If set to false, the index will be stored in RAM. Default: false
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_disk: Option<bool>,
    /// Defines which datatype should be used for the index.
    /// Choosing different datatypes allows to optimize memory usage and performance vs accuracy.
    ///
    /// - For `float32` datatype - vectors are stored as single-precision floating point numbers,
    ///   4 bytes.
    /// - For `float16` datatype - vectors are stored as half-precision floating point numbers,
    ///   2 bytes.
    /// - For `uint8` datatype - vectors are quantized to unsigned 8-bit integers, 1 byte.
    ///   Quantization to fit byte range `[0, 255]` happens during indexing automatically, so the
    ///   actual vector data does not need to conform to this range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datatype: Option<Datatype>,
}

impl SparseIndexParams {
    pub fn update_from_other(&mut self, other: SparseIndexParams) {
        let SparseIndexParams {
            full_scan_threshold,
            on_disk,
            datatype,
        } = other;

        self.full_scan_threshold
            .replace_if_some(full_scan_threshold);
        self.on_disk.replace_if_some(on_disk);
        self.datatype.replace_if_some(datatype);
    }
}

/// Vector params separator for single and multiple vector modes
/// Single mode:
///
/// { "size": 128, "distance": "Cosine" }
///
/// or multiple mode:
///
/// {
///      "default": {
///          "size": 128,
///          "distance": "Cosine"
///      }
/// }
#[derive(Debug, Deserialize, Serialize, JsonSchema, Anonymize, Clone, PartialEq, Hash, Eq)]
#[serde(rename_all = "snake_case", untagged)]
pub enum VectorsConfig {
    Single(VectorParams),
    Multi(BTreeMap<VectorNameBuf, VectorParams>),
}

impl Default for VectorsConfig {
    fn default() -> Self {
        VectorsConfig::Multi(Default::default())
    }
}

impl VectorsConfig {
    pub fn empty() -> Self {
        VectorsConfig::Multi(BTreeMap::new())
    }

    pub fn vectors_num(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Multi(vectors) => vectors.len(),
        }
    }

    pub fn get_params(&self, name: &VectorName) -> Option<&VectorParams> {
        match self {
            VectorsConfig::Single(params) => (name == DEFAULT_VECTOR_NAME).then_some(params),
            VectorsConfig::Multi(params) => params.get(name),
        }
    }

    pub fn get_params_mut(&mut self, name: &VectorName) -> Option<&mut VectorParams> {
        match self {
            VectorsConfig::Single(params) => (name == DEFAULT_VECTOR_NAME).then_some(params),
            VectorsConfig::Multi(params) => params.get_mut(name),
        }
    }

    /// Iterate over the named vector parameters.
    ///
    /// If this is `Single` it iterates over a single parameter named [`DEFAULT_VECTOR_NAME`].
    pub fn params_iter<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = (&'a VectorName, &'a VectorParams)> + 'a> {
        match self {
            VectorsConfig::Single(p) => Box::new(std::iter::once((DEFAULT_VECTOR_NAME, p))),
            VectorsConfig::Multi(p) => Box::new(p.iter().map(|(n, p)| (n.as_ref(), p))),
        }
    }

    // TODO: Further unify `check_compatible` and `check_compatible_with_segment_config`?
    pub fn check_compatible(&self, other: &Self) -> CollectionResult<()> {
        match (self, other) {
            (Self::Single(_), Self::Single(_)) | (Self::Multi(_), Self::Multi(_)) => (),
            _ => {
                return Err(incompatible_vectors_error(
                    self.params_iter().map(|(name, _)| name),
                    other.params_iter().map(|(name, _)| name),
                ));
            }
        };

        for (vector_name, this) in self.params_iter() {
            let Some(other) = other.get_params(vector_name) else {
                return Err(missing_vector_error(vector_name));
            };

            VectorParamsBase::from(this).check_compatibility(&other.into(), vector_name)?;
        }

        Ok(())
    }

    // TODO: Further unify `check_compatible` and `check_compatible_with_segment_config`?
    pub fn check_compatible_with_segment_config(
        &self,
        other: &HashMap<VectorNameBuf, segment::types::VectorDataConfig>,
        exact: bool,
    ) -> CollectionResult<()> {
        if exact && self.vectors_num() != other.len() {
            return Err(incompatible_vectors_error(
                self.params_iter().map(|(name, _)| name),
                other.keys().map(AsRef::as_ref),
            ));
        }

        for (vector_name, this) in self.params_iter() {
            let Some(other) = other.get(vector_name) else {
                return Err(missing_vector_error(vector_name));
            };

            VectorParamsBase::from(this).check_compatibility(&other.into(), vector_name)?;
        }

        Ok(())
    }
}

pub fn check_sparse_compatible_with_segment_config(
    self_config: &BTreeMap<VectorNameBuf, SparseVectorParams>,
    other: &HashMap<VectorNameBuf, segment::types::SparseVectorDataConfig>,
    exact: bool,
) -> CollectionResult<()> {
    if exact && self_config.len() != other.len() {
        return Err(incompatible_vectors_error(
            self_config.keys().map(AsRef::as_ref),
            other.keys().map(AsRef::as_ref),
        ));
    }

    for (vector_name, _) in self_config.iter() {
        if other.get(vector_name).is_none() {
            return Err(missing_vector_error(vector_name));
        };
    }

    Ok(())
}

fn incompatible_vectors_error<'a, 'b>(
    this: impl Iterator<Item = &'a VectorName>,
    other: impl Iterator<Item = &'b VectorName>,
) -> CollectionError {
    let this_vectors = this.collect::<Vec<_>>().join(", ");
    let other_vectors = other.collect::<Vec<_>>().join(", ");

    CollectionError::BadInput {
        description: format!(
            "Vectors configuration is not compatible: \
             origin collection have vectors [{this_vectors}], \
             while other vectors [{other_vectors}]"
        ),
    }
}

fn missing_vector_error(vector_name: &VectorName) -> CollectionError {
    CollectionError::BadInput {
        description: format!(
            "Vectors configuration is not compatible: \
             origin collection have vector {vector_name}, while other collection does not"
        ),
    }
}

impl Validate for VectorsConfig {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            VectorsConfig::Single(single) => single.validate(),
            VectorsConfig::Multi(multi) => common::validation::validate_iter(multi.values()),
        }
    }
}

impl From<VectorParams> for VectorsConfig {
    fn from(params: VectorParams) -> Self {
        VectorsConfig::Single(params)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct VectorParamsBase {
    /// Size of a vectors used
    size: usize,
    /// Type of distance function used for measuring distance between vectors
    distance: Distance,
}

impl VectorParamsBase {
    fn check_compatibility(&self, other: &Self, vector_name: &VectorName) -> CollectionResult<()> {
        if self.size != other.size {
            return Err(CollectionError::BadInput {
                description: format!(
                    "Vectors configuration is not compatible: \
                     origin vector {} size: {}, while other vector size: {}",
                    vector_name, self.size, other.size
                ),
            });
        }

        if self.distance != other.distance {
            return Err(CollectionError::BadInput {
                description: format!(
                    "Vectors configuration is not compatible: \
                     origin vector {} distance: {:?}, while other vector distance: {:?}",
                    vector_name, self.distance, other.distance
                ),
            });
        }

        Ok(())
    }
}

impl From<&VectorParams> for VectorParamsBase {
    fn from(params: &VectorParams) -> Self {
        let &VectorParams {
            size,
            distance,
            hnsw_config: _,
            quantization_config: _,
            on_disk: _,
            datatype: _,
            multivector_config: _,
        } = params;
        Self {
            size: size.get() as _, // TODO!?
            distance,
        }
    }
}

impl From<&segment::types::VectorDataConfig> for VectorParamsBase {
    fn from(config: &segment::types::VectorDataConfig) -> Self {
        let &segment::types::VectorDataConfig {
            size,
            distance,
            storage_type: _,
            index: _,
            quantization_config: _,
            multivector_config: _,
            datatype: _,
        } = config;
        Self { size, distance }
    }
}

#[derive(Debug, Hash, Deserialize, Serialize, JsonSchema, Validate, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VectorParamsDiff {
    /// Update params for HNSW index. If empty object - it will be unset.
    #[serde(default, skip_serializing_if = "is_hnsw_diff_empty")]
    #[validate(nested)]
    pub hnsw_config: Option<HnswConfigDiff>,
    /// Update params for quantization. If none - it is left unchanged.
    #[serde(
        default,
        alias = "quantization",
        skip_serializing_if = "Option::is_none"
    )]
    #[validate(nested)]
    pub quantization_config: Option<QuantizationConfigDiff>,
    /// If true, vectors are served from disk, improving RAM usage at the cost of latency
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_disk: Option<bool>,
}

/// Vector update params for multiple vectors
///
/// {
///     "vector_name": {
///         "hnsw_config": { "m": 8 }
///     }
/// }
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, PartialEq, Hash, Eq)]
pub struct VectorsConfigDiff(pub BTreeMap<VectorNameBuf, VectorParamsDiff>);

impl VectorsConfigDiff {
    /// Check that the vector names in this config are part of the given collection.
    ///
    /// Returns an error if incompatible.
    pub fn check_vector_names(&self, collection: &CollectionParams) -> CollectionResult<()> {
        for vector_name in self.0.keys() {
            collection
                .vectors
                .get_params(vector_name)
                .map(|_| ())
                .ok_or_else(|| OperationError::VectorNameNotExists {
                    received_name: vector_name.clone(),
                })?;
        }
        Ok(())
    }
}

impl Validate for VectorsConfigDiff {
    fn validate(&self) -> Result<(), ValidationErrors> {
        common::validation::validate_iter(self.0.values())
    }
}

impl From<VectorParamsDiff> for VectorsConfigDiff {
    fn from(params: VectorParamsDiff) -> Self {
        VectorsConfigDiff(BTreeMap::from([(DEFAULT_VECTOR_NAME.into(), params)]))
    }
}

#[derive(Debug, Hash, Deserialize, Serialize, JsonSchema, Clone, PartialEq, Eq)]
pub struct SparseVectorsConfig(pub BTreeMap<VectorNameBuf, SparseVectorParams>);

impl SparseVectorsConfig {
    /// Check that the vector names in this config are part of the given collection.
    ///
    /// Returns an error if incompatible.
    pub fn check_vector_names(&self, collection: &CollectionParams) -> CollectionResult<()> {
        for vector_name in self.0.keys() {
            collection
                .sparse_vectors
                .as_ref()
                .and_then(|v| v.get(vector_name).map(|_| ()))
                .ok_or_else(|| OperationError::vector_name_not_exists(vector_name))?;
        }
        Ok(())
    }
}

impl Validate for SparseVectorsConfig {
    fn validate(&self) -> Result<(), ValidationErrors> {
        common::validation::validate_iter(self.0.values())
    }
}

fn alias_description_example() -> AliasDescription {
    AliasDescription {
        alias_name: "blogs-title".to_string(),
        collection_name: "arivx-title".to_string(),
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(example = "alias_description_example")]
pub struct AliasDescription {
    pub alias_name: String,
    pub collection_name: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct CollectionsAliasesResponse {
    pub aliases: Vec<AliasDescription>,
}

#[derive(Clone, Debug, Deserialize, Default, Copy, PartialEq)]
pub enum NodeType {
    /// Regular node, participates in the cluster
    #[default]
    Normal,
    /// Node that does only receive data, but is not used for search/read operations
    /// This is useful for nodes that are only used for writing data
    /// and backup purposes
    Listener,
}

/// All the unresolved issues in a Qdrant instance
#[derive(Serialize, JsonSchema, Debug)]
pub struct IssuesReport {
    pub issues: Vec<IssueRecord>,
}

/// Metadata describing extra properties for each peer
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize, JsonSchema)]
pub struct PeerMetadata {
    /// Peer Qdrant version
    #[schemars(schema_with = "String::json_schema")]
    pub(crate) version: Version,
    /// Non-secret digest of the crypto runtime capability policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) crypto_runtime_capability_fingerprint: Option<String>,
}

impl Debug for PeerMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerMetadata")
            .field("version", &self.version)
            .field(
                "crypto_runtime_capability_fingerprint_present",
                &self.crypto_runtime_capability_fingerprint().is_some(),
            )
            .finish()
    }
}

impl PeerMetadata {
    pub fn current() -> Self {
        Self {
            version: defaults::QDRANT_VERSION.clone(),
            crypto_runtime_capability_fingerprint: None,
        }
    }

    pub fn current_with_crypto_runtime_capability_fingerprint(
        crypto_runtime_capability_fingerprint: Option<String>,
    ) -> Self {
        Self {
            version: defaults::QDRANT_VERSION.clone(),
            crypto_runtime_capability_fingerprint,
        }
    }

    /// Whether this metadata has a different version than our current Qdrant instance.
    pub fn is_different_version(&self) -> bool {
        self.version != *defaults::QDRANT_VERSION
    }

    pub fn is_different_from(&self, current: &Self) -> bool {
        self.version != current.version
            || self.crypto_runtime_capability_fingerprint
                != current.crypto_runtime_capability_fingerprint
    }

    pub fn crypto_runtime_capability_fingerprint(&self) -> Option<&str> {
        self.crypto_runtime_capability_fingerprint
            .as_deref()
            .filter(|fingerprint| !fingerprint.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use qdrant_sec::ENCRYPTED_VECTOR_SIDECAR_FIELD;
    use segment::json_path::{JsonPath, JsonPathItem};
    use segment::types::PointIdType;

    use super::{
        CollectionError, CollectionUpdateProvenance, PeerMetadata,
        ckks_vector_sidecar_delete_target,
    };

    #[test]
    fn peer_metadata_treats_empty_crypto_runtime_fingerprint_as_missing() {
        let metadata =
            PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(String::new()));

        assert_eq!(metadata.crypto_runtime_capability_fingerprint(), None);
    }

    #[test]
    fn peer_metadata_debug_redacts_crypto_runtime_fingerprint() {
        let metadata = PeerMetadata::current_with_crypto_runtime_capability_fingerprint(Some(
            "qdrant-sec-peer-fingerprint-sentinel".to_string(),
        ));

        let rendered = format!("{metadata:?}");

        assert!(rendered.contains("crypto_runtime_capability_fingerprint_present"));
        assert!(!rendered.contains("qdrant-sec-peer-fingerprint-sentinel"));
    }

    #[test]
    fn invalid_uri_conversion_does_not_reflect_uri_or_parser_detail() {
        let invalid_uri = "http://uri-user:uri-password@exa mple.com/uri-secret-token"
            .parse::<tonic::transport::Uri>()
            .unwrap_err();
        let err = CollectionError::from(invalid_uri);

        match err {
            CollectionError::ServiceError { error, .. } => {
                assert_eq!(error, "Invalid URI error");
                assert!(!error.contains("uri-user"));
                assert!(!error.contains("uri-password"));
                assert!(!error.contains("uri-secret-token"));
                assert!(!error.contains("invalid"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn invalid_argument_status_conversion_does_not_reflect_status_message() {
        let err = CollectionError::from(tonic::Status::invalid_argument(
            "status-secret-sentinel invalid input detail",
        ));

        match err {
            CollectionError::BadInput { description } => {
                assert_eq!(description, "InvalidArgument");
                assert!(!description.contains("status-secret-sentinel"));
                assert!(!description.contains("invalid input detail"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn runtime_encrypted_vector_delete_provenance_is_bound_to_target() {
        let point_ids: Vec<PointIdType> = vec![42.into(), 7.into()];
        let target = ckks_vector_sidecar_delete_target(Some(&point_ids), None).unwrap();
        let provenance = CollectionUpdateProvenance::runtime_encrypted_vector_deletes_for_target(
            "collection-uuid",
            vec!["embedding".to_string()],
            target.clone(),
        )
        .expect("valid target-bound delete provenance");
        let key = JsonPath {
            first_key: ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
            rest: vec![JsonPathItem::Key("embedding".to_string())],
        };

        assert!(provenance.allows_vector_sidecar_delete_key("collection-uuid", &key, &target));
        assert!(!provenance.allows_vector_sidecar_delete_key("other-collection", &key, &target));

        let other_key = JsonPath {
            first_key: ENCRYPTED_VECTOR_SIDECAR_FIELD.to_string(),
            rest: vec![JsonPathItem::Key("other-vector".to_string())],
        };
        assert!(!provenance.allows_vector_sidecar_delete_key(
            "collection-uuid",
            &other_key,
            &target
        ));

        let other_point_ids: Vec<PointIdType> = vec![99.into()];
        let other_target = ckks_vector_sidecar_delete_target(Some(&other_point_ids), None).unwrap();
        assert!(!provenance.allows_vector_sidecar_delete_key(
            "collection-uuid",
            &key,
            &other_target
        ));
    }
}
