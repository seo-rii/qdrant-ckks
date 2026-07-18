use std::collections::BTreeMap;
use std::fmt;

use collection::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams, CryptoMigrationPlan,
    ShardingMethod,
};
use collection::operations::config_diff::{
    CollectionParamsDiff, HnswConfigDiff, OptimizersConfigDiff, QuantizationConfigDiff,
    WalConfigDiff,
};
use collection::operations::types::{
    SparseVectorParams, SparseVectorsConfig, VectorsConfig, VectorsConfigDiff,
};
use collection::shards::replica_set::replica_set_state::ReplicaState;
use collection::shards::resharding::ReshardKey;
use collection::shards::shard::{PeerId, ShardId, ShardsPlacement};
use collection::shards::transfer::{ShardTransfer, ShardTransferKey, ShardTransferRestart};
use collection::shards::{CollectionId, replica_set};
use schemars::JsonSchema;
use segment::types::{
    Filter, Payload, PayloadFieldSchema, PayloadKeyType, QuantizationConfig, ShardKey,
    StrictModeConfig, VectorNameBuf,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

// Re-export staging types when the feature is enabled
#[cfg(feature = "staging")]
pub use super::staging::TestSlowDown;
use crate::content_manager::errors::{StorageError, StorageResult};
use crate::content_manager::shard_distribution::ShardDistributionProposal;

// *Operation wrapper structure is only required for better OpenAPI generation

/// Create alternative name for a collection.
/// Collection will be available under both names for search, retrieve,
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct CreateAlias {
    pub collection_name: String,
    pub alias_name: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct CreateAliasOperation {
    pub create_alias: CreateAlias,
}

/// Delete alias if exists
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DeleteAlias {
    pub alias_name: String,
}

/// Delete alias if exists
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DeleteAliasOperation {
    pub delete_alias: DeleteAlias,
}

/// Change alias to a new one
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct RenameAlias {
    pub old_alias_name: String,
    pub new_alias_name: String,
}

/// Change alias to a new one
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct RenameAliasOperation {
    pub rename_alias: RenameAlias,
}

/// Group of all the possible operations related to collection aliases
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum AliasOperations {
    CreateAlias(CreateAliasOperation),
    DeleteAlias(DeleteAliasOperation),
    RenameAlias(RenameAliasOperation),
}

impl From<CreateAlias> for AliasOperations {
    fn from(create_alias: CreateAlias) -> Self {
        AliasOperations::CreateAlias(CreateAliasOperation { create_alias })
    }
}

impl From<DeleteAlias> for AliasOperations {
    fn from(delete_alias: DeleteAlias) -> Self {
        AliasOperations::DeleteAlias(DeleteAliasOperation { delete_alias })
    }
}

impl From<RenameAlias> for AliasOperations {
    fn from(rename_alias: RenameAlias) -> Self {
        AliasOperations::RenameAlias(RenameAliasOperation { rename_alias })
    }
}

/// Operation for creating new collection and (optionally) specify index params
#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct CreateCollection {
    /// Vector data config.
    /// It is possible to provide one config for single vector mode and list of configs for multiple vectors mode.
    #[serde(default)]
    #[validate(nested)]
    pub vectors: VectorsConfig,
    /// For auto sharding:
    /// Number of shards in collection.
    ///  - Default is 1 for standalone, otherwise equal to the number of nodes
    ///  - Minimum is 1
    ///
    /// For custom sharding:
    /// Number of shards in collection per shard group.
    ///  - Default is 1, meaning that each shard key will be mapped to a single shard
    ///  - Minimum is 1
    #[serde(default)]
    #[validate(range(min = 1))]
    pub shard_number: Option<u32>,
    /// Sharding method
    /// Default is Auto - points are distributed across all available shards
    /// Custom - points are distributed across shards according to shard key
    #[serde(default)]
    pub sharding_method: Option<ShardingMethod>,
    /// Number of shards replicas.
    /// Default is 1
    /// Minimum is 1
    #[serde(default)]
    #[validate(range(min = 1))]
    pub replication_factor: Option<u32>,
    /// Defines how many replicas should apply the operation for us to consider it successful.
    /// Increasing this number will make the collection more resilient to inconsistencies, but will
    /// also make it fail if not enough replicas are available.
    /// Does not have any performance impact.
    #[serde(default)]
    #[validate(range(min = 1))]
    pub write_consistency_factor: Option<u32>,
    /// If true - point's payload will not be stored in memory.
    /// It will be read from the disk every time it is requested.
    /// This setting saves RAM by (slightly) increasing the response time.
    /// Note: those payload values that are involved in filtering and are indexed - remain in RAM.
    ///
    /// Default: true
    #[serde(default)]
    pub on_disk_payload: Option<bool>,
    /// Custom params for HNSW index. If none - values from service configuration file are used.
    #[validate(nested)]
    pub hnsw_config: Option<HnswConfigDiff>,
    /// Custom params for WAL. If none - values from service configuration file are used.
    #[validate(nested)]
    pub wal_config: Option<WalConfigDiff>,
    /// Custom params for Optimizers.  If none - values from service configuration file are used.
    #[serde(alias = "optimizer_config")]
    #[validate(nested)]
    pub optimizers_config: Option<OptimizersConfigDiff>,
    /// Quantization parameters. If none - quantization is disabled.
    #[serde(default, alias = "quantization")]
    #[validate(nested)]
    pub quantization_config: Option<QuantizationConfig>,
    /// Sparse vector data config.
    #[validate(nested)]
    pub sparse_vectors: Option<BTreeMap<VectorNameBuf, SparseVectorParams>>,
    /// Capability-oriented collection encryption rules. Secret key material is never stored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    pub encryption: Option<CollectionEncryptionConfig>,
    /// Strict-mode config.
    #[validate(nested)]
    pub strict_mode_config: Option<StrictModeConfig>,
    #[serde(default)]
    #[schemars(skip)]
    pub uuid: Option<Uuid>,
    /// Arbitrary JSON metadata for the collection
    /// This can be used to store application-specific information
    /// such as creation time, migration data, inference model info, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Payload>,
}

/// Operation for creating new collection and (optionally) specify index params
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct CreateCollectionOperation {
    pub collection_name: String,
    pub create_collection: CreateCollection,
    distribution: Option<ShardDistributionProposal>,
    #[serde(default)]
    preserve_explicit_uuid: bool,
}

impl CreateCollectionOperation {
    pub fn new(
        collection_name: String,
        mut create_collection: CreateCollection,
    ) -> StorageResult<Self> {
        // validate vector names are unique between dense and sparse vectors
        if let Some(sparse_config) = &create_collection.sparse_vectors {
            let mut dense_names = create_collection.vectors.params_iter().map(|p| p.0);
            if let Some(duplicate_name) = dense_names.find(|name| sparse_config.contains_key(*name))
            {
                return Err(StorageError::bad_input(format!(
                    "Dense and sparse vector names must be unique - duplicate found with '{duplicate_name}'",
                )));
            }
        }

        if create_collection.encryption.is_some() && create_collection.uuid.is_none() {
            create_collection.uuid = Some(Uuid::new_v4());
        }
        create_collection.validate().map_err(|err| {
            StorageError::bad_input(format!("invalid create collection config: {err}"))
        })?;

        Ok(Self {
            collection_name,
            create_collection,
            distribution: None,
            preserve_explicit_uuid: false,
        })
    }

    pub fn preserve_explicit_uuid_for_internal_migration(&mut self) {
        self.preserve_explicit_uuid = true;
    }

    pub fn should_preserve_explicit_uuid(&self) -> bool {
        self.preserve_explicit_uuid
    }

    pub fn is_distribution_set(&self) -> bool {
        self.distribution.is_some()
    }

    pub fn take_distribution(&mut self) -> Option<ShardDistributionProposal> {
        self.distribution.take()
    }

    pub fn set_distribution(&mut self, distribution: ShardDistributionProposal) {
        self.distribution = Some(distribution);
    }
}

/// Operation for updating parameters of the existing collection
#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct UpdateCollection {
    /// Map of vector data parameters to update for each named vector.
    /// To update parameters in a collection having a single unnamed vector, use an empty string as name.
    #[validate(nested)]
    pub vectors: Option<VectorsConfigDiff>,
    /// Custom params for Optimizers.  If none - it is left unchanged.
    /// This operation is blocking, it will only proceed once all current optimizations are complete
    #[serde(alias = "optimizer_config")]
    #[validate(nested)]
    pub optimizers_config: Option<OptimizersConfigDiff>, // TODO: Allow updates for other configuration params as well
    /// Collection base params. If none - it is left unchanged.
    pub params: Option<CollectionParamsDiff>,
    /// HNSW parameters to update for the collection index. If none - it is left unchanged.
    #[validate(nested)]
    pub hnsw_config: Option<HnswConfigDiff>,
    /// Quantization parameters to update. If none - it is left unchanged.
    #[serde(default, alias = "quantization")]
    #[validate(nested)]
    pub quantization_config: Option<QuantizationConfigDiff>,
    /// Map of sparse vector data parameters to update for each sparse vector.
    #[validate(nested)]
    pub sparse_vectors: Option<SparseVectorsConfig>,
    #[validate(nested)]
    pub strict_mode_config: Option<StrictModeConfig>,
    /// Metadata to update for the collection. If provided, this will merge with existing metadata.
    /// To remove metadata, set it to an empty object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Payload>,
}

/// Operation for updating parameters of the existing collection
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct UpdateCollectionOperation {
    pub collection_name: String,
    pub update_collection: UpdateCollection,
    shard_replica_changes: Option<Vec<replica_set::Change>>,
    #[serde(default)]
    private_oram_replica_removal_reserved: bool,
}

impl UpdateCollectionOperation {
    pub fn new_empty(collection_name: String) -> Self {
        Self {
            collection_name,
            update_collection: UpdateCollection {
                vectors: None,
                hnsw_config: None,
                params: None,
                optimizers_config: None,
                quantization_config: None,
                sparse_vectors: None,
                strict_mode_config: None,
                metadata: None,
            },
            shard_replica_changes: None,
            private_oram_replica_removal_reserved: false,
        }
    }

    pub fn new(collection_name: String, update_collection: UpdateCollection) -> Self {
        Self {
            collection_name,
            update_collection,
            shard_replica_changes: None,
            private_oram_replica_removal_reserved: false,
        }
    }

    pub fn take_shard_replica_changes(&mut self) -> Option<Vec<replica_set::Change>> {
        self.shard_replica_changes.take()
    }

    pub fn set_shard_replica_changes(&mut self, changes: Vec<replica_set::Change>) {
        if changes.is_empty() {
            self.shard_replica_changes = None;
        } else {
            self.shard_replica_changes = Some(changes);
        }
    }

    pub fn mark_private_oram_replica_removal_reserved(&mut self) {
        self.private_oram_replica_removal_reserved = true;
    }

    pub fn private_oram_replica_removal_reserved(&self) -> bool {
        self.private_oram_replica_removal_reserved
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ApplyCryptoMigrationPlan {
    pub collection_name: String,
    #[validate(nested)]
    pub plan: CryptoMigrationPlan,
}

/// Operation for performing changes of collection aliases.
/// Alias changes are atomic, meaning that no collection modifications can happen between
/// alias operations.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Validate, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ChangeAliasesOperation {
    pub actions: Vec<AliasOperations>,
}

/// Operation for deleting collection with given name
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DeleteCollectionOperation(pub String);

#[derive(Clone, Debug, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub enum ReshardingOperation {
    Start(ReshardKey),
    CommitRead(ReshardKey),
    CommitWrite(ReshardKey),
    Finish(ReshardKey),
    Abort(ReshardKey),
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub enum ShardTransferOperations {
    Start(ShardTransfer),
    /// Restart an existing transfer with a new configuration
    ///
    /// If the given transfer is ongoing, it is aborted and restarted with the new configuration.
    Restart(ShardTransferRestart),
    Finish(ShardTransfer),
    /// Deprecated since Qdrant 1.9.0, used in Qdrant 1.7.0 and 1.8.0
    ///
    /// Used in `ShardTransferMethod::Snapshot`
    ///
    /// Called when the snapshot has successfully been recovered on the remote, brings the transfer
    /// to the next stage.
    SnapshotRecovered(ShardTransferKey),
    /// Used in `ShardTransferMethod::Snapshot` and `ShardTransferMethod::WalDelta`
    ///
    /// Called when the first stage of the transfer has been successfully finished, brings the
    /// transfer to the next stage.
    RecoveryToPartial(ShardTransferKey),
    Abort {
        transfer: ShardTransferKey,
        reason: String,
    },
}

impl ShardTransferOperations {
    pub(crate) fn redacted_log(&self) -> RedactedShardTransferOperation<'_> {
        RedactedShardTransferOperation(self)
    }
}

pub(crate) struct RedactedShardTransferOperation<'a>(&'a ShardTransferOperations);

impl fmt::Debug for RedactedShardTransferOperation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ShardTransferOperations::Start(transfer) => f
                .debug_struct("Start")
                .field("transfer", &RedactedShardTransfer(transfer))
                .finish(),
            ShardTransferOperations::Restart(transfer) => f
                .debug_struct("Restart")
                .field("transfer", &RedactedShardTransferRestart(transfer))
                .finish(),
            ShardTransferOperations::Finish(transfer) => f
                .debug_struct("Finish")
                .field("transfer", &RedactedShardTransfer(transfer))
                .finish(),
            ShardTransferOperations::SnapshotRecovered(transfer) => f
                .debug_struct("SnapshotRecovered")
                .field("transfer", &RedactedShardTransferKey(transfer))
                .finish(),
            ShardTransferOperations::RecoveryToPartial(transfer) => f
                .debug_struct("RecoveryToPartial")
                .field("transfer", &RedactedShardTransferKey(transfer))
                .finish(),
            ShardTransferOperations::Abort { transfer, reason } => f
                .debug_struct("Abort")
                .field("transfer", &RedactedShardTransferKey(transfer))
                .field("reason_present", &(!reason.is_empty()))
                .finish(),
        }
    }
}

struct RedactedShardTransfer<'a>(&'a ShardTransfer);

impl fmt::Debug for RedactedShardTransfer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transfer = self.0;
        let mut debug = f.debug_struct("ShardTransfer");
        debug
            .field("shard_id", &transfer.shard_id)
            .field("to_shard_id", &transfer.to_shard_id)
            .field("from", &transfer.from)
            .field("to", &transfer.to)
            .field("sync", &transfer.sync)
            .field("method", &transfer.method);
        append_redacted_filter_fields(&mut debug, transfer.filter.as_ref());
        debug.finish()
    }
}

struct RedactedShardTransferRestart<'a>(&'a ShardTransferRestart);

impl fmt::Debug for RedactedShardTransferRestart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transfer = self.0;
        f.debug_struct("ShardTransferRestart")
            .field("shard_id", &transfer.shard_id)
            .field("to_shard_id", &transfer.to_shard_id)
            .field("from", &transfer.from)
            .field("to", &transfer.to)
            .field("method", &transfer.method)
            .field("filter_present", &false)
            .field("filter_condition_count", &Option::<usize>::None)
            .finish()
    }
}

struct RedactedShardTransferKey<'a>(&'a ShardTransferKey);

impl fmt::Debug for RedactedShardTransferKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transfer = self.0;
        f.debug_struct("ShardTransferKey")
            .field("shard_id", &transfer.shard_id)
            .field("to_shard_id", &transfer.to_shard_id)
            .field("from", &transfer.from)
            .field("to", &transfer.to)
            .finish()
    }
}

fn append_redacted_filter_fields(debug: &mut fmt::DebugStruct<'_, '_>, filter: Option<&Filter>) {
    debug.field("filter_present", &filter.is_some()).field(
        "filter_condition_count",
        &filter.map(Filter::total_conditions_count),
    );
}

/// Sets the state of shard replica
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct SetShardReplicaState {
    pub collection_name: String,
    pub shard_id: ShardId,
    pub peer_id: PeerId,
    /// If `Active` then the replica is up to date and can receive updates and answer requests
    pub state: ReplicaState,
    /// If `Some` then check that the replica is in this state before changing it
    /// If `None` then the replica can be in any state
    /// This is useful for example when we want to make sure
    /// we only make transition from `Initializing` to `Active`, and not from `Dead` to `Active`.
    /// If `from_state` does not match the current state of the replica, then the operation will be dismissed.
    #[serde(default)]
    pub from_state: Option<ReplicaState>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct CreateShardKey {
    pub collection_name: String,
    pub shard_key: ShardKey,
    pub placement: ShardsPlacement,
    pub initial_state: Option<ReplicaState>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct DropShardKey {
    pub collection_name: String,
    pub shard_key: ShardKey,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct CreatePayloadIndex {
    pub collection_name: String,
    pub field_name: PayloadKeyType,
    pub field_schema: PayloadFieldSchema,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
pub struct DropPayloadIndex {
    pub collection_name: String,
    pub field_name: PayloadKeyType,
}

/// Enumeration of all possible collection update operations
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CollectionMetaOperations {
    CreateCollection(CreateCollectionOperation),
    UpdateCollection(UpdateCollectionOperation),
    ApplyCryptoMigration(ApplyCryptoMigrationPlan),
    DeleteCollection(DeleteCollectionOperation),
    ChangeAliases(ChangeAliasesOperation),
    Resharding(CollectionId, ReshardingOperation),
    TransferShard(CollectionId, ShardTransferOperations),
    SetShardReplicaState(SetShardReplicaState),
    CreateShardKey(CreateShardKey),
    DropShardKey(DropShardKey),
    CreatePayloadIndex(CreatePayloadIndex),
    DropPayloadIndex(DropPayloadIndex),
    Nop {
        token: usize,
    }, // Empty operation
    /// Introduce artificial delay to a specific peer node
    #[cfg(feature = "staging")]
    TestSlowDown(TestSlowDown),
}

impl CollectionMetaOperations {
    pub(crate) fn redacted_log(&self) -> RedactedCollectionMetaOperation<'_> {
        RedactedCollectionMetaOperation(self)
    }
}

pub(crate) struct RedactedCollectionMetaOperation<'a>(&'a CollectionMetaOperations);

impl fmt::Debug for RedactedCollectionMetaOperation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            CollectionMetaOperations::CreateCollection(operation) => f
                .debug_struct("CreateCollection")
                .field("collection_name", &operation.collection_name)
                .field(
                    "has_encryption",
                    &operation.create_collection.encryption.is_some(),
                )
                .field("has_uuid", &operation.create_collection.uuid.is_some())
                .field(
                    "metadata_present",
                    &operation.create_collection.metadata.is_some(),
                )
                .field("distribution_present", &operation.is_distribution_set())
                .finish(),
            CollectionMetaOperations::UpdateCollection(operation) => f
                .debug_struct("UpdateCollection")
                .field("collection_name", &operation.collection_name)
                .field("has_params", &operation.update_collection.params.is_some())
                .field(
                    "metadata_present",
                    &operation.update_collection.metadata.is_some(),
                )
                .field(
                    "private_oram_replica_removal_reserved",
                    &operation.private_oram_replica_removal_reserved(),
                )
                .finish(),
            CollectionMetaOperations::ApplyCryptoMigration(operation) => f
                .debug_struct("ApplyCryptoMigration")
                .field("collection_name", &operation.collection_name)
                .field("from", &operation.plan.from)
                .field("to", &operation.plan.to)
                .field("target_epoch", &operation.plan.target_epoch)
                .field(
                    "active_rk_id_present",
                    &operation.plan.active_rk_id.is_some(),
                )
                .field(
                    "retired_rk_id_present",
                    &operation.plan.retired_rk_id.is_some(),
                )
                .field("dry_run", &operation.plan.dry_run)
                .field("checkpoint_count", &operation.plan.checkpoints.len())
                .finish(),
            CollectionMetaOperations::DeleteCollection(operation) => f
                .debug_tuple("DeleteCollection")
                .field(&operation.0)
                .finish(),
            CollectionMetaOperations::ChangeAliases(operation) => f
                .debug_struct("ChangeAliases")
                .field("action_count", &operation.actions.len())
                .finish(),
            CollectionMetaOperations::Resharding(collection_id, operation) => f
                .debug_struct("Resharding")
                .field("collection_id", collection_id)
                .field(
                    "operation",
                    &match operation {
                        ReshardingOperation::Start(_) => "start",
                        ReshardingOperation::CommitRead(_) => "commit_read",
                        ReshardingOperation::CommitWrite(_) => "commit_write",
                        ReshardingOperation::Finish(_) => "finish",
                        ReshardingOperation::Abort(_) => "abort",
                    },
                )
                .field(
                    "peer_id",
                    &match operation {
                        ReshardingOperation::Start(key)
                        | ReshardingOperation::CommitRead(key)
                        | ReshardingOperation::CommitWrite(key)
                        | ReshardingOperation::Finish(key)
                        | ReshardingOperation::Abort(key) => key.peer_id,
                    },
                )
                .field(
                    "shard_id",
                    &match operation {
                        ReshardingOperation::Start(key)
                        | ReshardingOperation::CommitRead(key)
                        | ReshardingOperation::CommitWrite(key)
                        | ReshardingOperation::Finish(key)
                        | ReshardingOperation::Abort(key) => key.shard_id,
                    },
                )
                .field(
                    "shard_key_present",
                    &match operation {
                        ReshardingOperation::Start(key)
                        | ReshardingOperation::CommitRead(key)
                        | ReshardingOperation::CommitWrite(key)
                        | ReshardingOperation::Finish(key)
                        | ReshardingOperation::Abort(key) => key.shard_key.is_some(),
                    },
                )
                .finish(),
            CollectionMetaOperations::TransferShard(collection_id, operation) => f
                .debug_struct("TransferShard")
                .field("collection_id", collection_id)
                .field("operation", &operation.redacted_log())
                .finish(),
            CollectionMetaOperations::SetShardReplicaState(operation) => f
                .debug_struct("SetShardReplicaState")
                .field("collection_name", &operation.collection_name)
                .field("shard_id", &operation.shard_id)
                .field("peer_id", &operation.peer_id)
                .field("state", &operation.state)
                .field("from_state", &operation.from_state)
                .finish(),
            CollectionMetaOperations::CreateShardKey(operation) => f
                .debug_struct("CreateShardKey")
                .field("collection_name", &operation.collection_name)
                .field("placement", &operation.placement)
                .field("initial_state", &operation.initial_state)
                .field("shard_key_present", &true)
                .finish(),
            CollectionMetaOperations::DropShardKey(operation) => f
                .debug_struct("DropShardKey")
                .field("collection_name", &operation.collection_name)
                .field("shard_key_present", &true)
                .finish(),
            CollectionMetaOperations::CreatePayloadIndex(operation) => f
                .debug_struct("CreatePayloadIndex")
                .field("collection_name", &operation.collection_name)
                .field("field_name_present", &true)
                .field("field_schema", &operation.field_schema)
                .finish(),
            CollectionMetaOperations::DropPayloadIndex(operation) => f
                .debug_struct("DropPayloadIndex")
                .field("collection_name", &operation.collection_name)
                .field("field_name_present", &true)
                .finish(),
            CollectionMetaOperations::Nop { token } => {
                f.debug_struct("Nop").field("token", token).finish()
            }
            #[cfg(feature = "staging")]
            CollectionMetaOperations::TestSlowDown(operation) => {
                f.debug_tuple("TestSlowDown").field(operation).finish()
            }
        }
    }
}

/// Use config of the existing collection to generate a create collection operation
/// for the new collection
impl From<CollectionConfigInternal> for CreateCollection {
    fn from(value: CollectionConfigInternal) -> Self {
        let CollectionConfigInternal {
            params,
            hnsw_config,
            optimizer_config,
            wal_config,
            quantization_config,
            strict_mode_config,
            uuid,
            metadata,
        } = value;

        let CollectionParams {
            vectors,
            shard_number,
            sharding_method,
            replication_factor,
            write_consistency_factor,
            read_fan_out_factor: _,
            read_fan_out_delay_ms: _,
            on_disk_payload,
            sparse_vectors,
            encryption,
        } = params;

        Self {
            vectors,
            shard_number: Some(shard_number.get()),
            sharding_method,
            replication_factor: Some(replication_factor.get()),
            write_consistency_factor: Some(write_consistency_factor.get()),
            on_disk_payload: Some(on_disk_payload),
            hnsw_config: Some(hnsw_config.into()),
            wal_config: Some(wal_config.into()),
            optimizers_config: Some(optimizer_config.into()),
            quantization_config,
            sparse_vectors,
            encryption,
            strict_mode_config,
            uuid,
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use collection::config::{
        CollectionEncryptionConfig, CryptoMigrationCheckpoint, CryptoMigrationCheckpointStatus,
        CryptoMigrationPlan, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector,
    };
    use collection::shards::transfer::ShardTransferMethod;
    use segment::types::{Condition, FieldCondition, PayloadFieldSchema, PayloadSchemaType};
    use serde_json::json;

    use super::*;

    fn create_collection(encryption: Option<CollectionEncryptionConfig>) -> CreateCollection {
        CreateCollection {
            vectors: VectorsConfig::default(),
            shard_number: None,
            sharding_method: None,
            replication_factor: None,
            write_consistency_factor: None,
            on_disk_payload: None,
            hnsw_config: None,
            wal_config: None,
            optimizers_config: None,
            quantization_config: None,
            sparse_vectors: None,
            encryption,
            strict_mode_config: None,
            uuid: None,
            metadata: None,
        }
    }

    fn encrypted_config() -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a:docs".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 0,
            migration_state: CryptoMigrationState::Active,
            rules: vec![EncryptionRuleRef {
                id: "body_conf".to_string(),
                selector: EncryptionSelector::PayloadPaths {
                    paths: vec!["body".to_string()],
                },
                instance: "docs_payload_v1".to_string(),
                binding: Some("payload-field/v1".to_string()),
            }],
        }
    }

    fn private_oram_encrypted_config() -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
            version: 1,
            key_id: Some("tenant-a/private-oram-rk-sentinel".to_string()),
            crypto_schema_version: 1,
            encryption_epoch: 7,
            migration_state: CryptoMigrationState::Active,
            rules: vec![
                EncryptionRuleRef {
                    id: "docs_text_private_hnsw_sentinel".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["private-hnsw-vector-sentinel".to_string()],
                    },
                    instance: "docs_private_hnsw_instance_sentinel".to_string(),
                    binding: Some("private-hnsw-oram/v1".to_string()),
                },
                EncryptionRuleRef {
                    id: "docs_body_private_result_sentinel".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["document.private-result-path-sentinel".to_string()],
                    },
                    instance: "docs_private_result_instance_sentinel".to_string(),
                    binding: Some("private-result-oram/v1".to_string()),
                },
            ],
        }
    }

    #[test]
    fn encrypted_create_collection_gets_stable_uuid() {
        let operation = CreateCollectionOperation::new(
            "docs".to_string(),
            create_collection(Some(encrypted_config())),
        )
        .unwrap();

        assert!(operation.create_collection.uuid.is_some());
    }

    #[test]
    fn plaintext_create_collection_keeps_uuid_empty() {
        let operation =
            CreateCollectionOperation::new("docs".to_string(), create_collection(None)).unwrap();

        assert!(operation.create_collection.uuid.is_none());
    }

    #[test]
    fn encrypted_create_collection_preserves_existing_uuid() {
        let uuid = Uuid::from_u128(7);
        let mut create_collection = create_collection(Some(encrypted_config()));
        create_collection.uuid = Some(uuid);

        let operation =
            CreateCollectionOperation::new("docs".to_string(), create_collection).unwrap();

        assert_eq!(operation.create_collection.uuid, Some(uuid));
        assert!(!operation.should_preserve_explicit_uuid());
    }

    #[test]
    fn explicit_uuid_preservation_requires_internal_migration_opt_in() {
        let uuid = Uuid::from_u128(7);
        let mut create_collection = create_collection(Some(encrypted_config()));
        create_collection.uuid = Some(uuid);

        let mut operation =
            CreateCollectionOperation::new("docs".to_string(), create_collection).unwrap();

        assert!(!operation.should_preserve_explicit_uuid());
        operation.preserve_explicit_uuid_for_internal_migration();
        assert!(operation.should_preserve_explicit_uuid());
        assert_eq!(operation.create_collection.uuid, Some(uuid));
    }

    #[test]
    fn apply_crypto_migration_plan_validates_nested_plan() {
        let operation = ApplyCryptoMigrationPlan {
            collection_name: "docs".to_string(),
            plan: CryptoMigrationPlan {
                from: CryptoMigrationState::Active,
                to: CryptoMigrationState::Active,
                target_epoch: 3,
                active_rk_id: Some("rk/docs/3".to_string()),
                retired_rk_id: None,
                dry_run: false,
                checkpoints: Vec::new(),
            },
        };

        let err = operation.validate().unwrap_err();
        assert!(
            format!("{err:?}").contains("invalid_crypto_migration_transition"),
            "nested ApplyCryptoMigrationPlan validation must reject unsafe migration plans: {err:?}",
        );
    }

    #[test]
    fn private_oram_replica_removal_reservation_marker_round_trips_and_defaults_closed() {
        let operation = UpdateCollectionOperation::new_empty("docs".to_string());
        assert!(!operation.private_oram_replica_removal_reserved());

        let mut legacy_value = serde_json::to_value(&operation).unwrap();
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("private_oram_replica_removal_reserved");
        let legacy_operation: UpdateCollectionOperation =
            serde_json::from_value(legacy_value).unwrap();
        assert!(!legacy_operation.private_oram_replica_removal_reserved());

        let mut reserved = operation;
        reserved.mark_private_oram_replica_removal_reserved();
        let encoded = serde_json::to_value(&reserved).unwrap();
        let decoded: UpdateCollectionOperation = serde_json::from_value(encoded).unwrap();
        assert!(decoded.private_oram_replica_removal_reserved());

        let meta_operation = CollectionMetaOperations::UpdateCollection(decoded);
        let log_line = format!("{:?}", meta_operation.redacted_log());
        assert!(
            log_line.contains("private_oram_replica_removal_reserved: true"),
            "{log_line}",
        );
    }

    #[test]
    fn shard_transfer_log_projection_redacts_filter_literals() {
        let operation = ShardTransferOperations::Start(ShardTransfer {
            shard_id: 1,
            to_shard_id: Some(2),
            from: 3,
            to: 4,
            sync: true,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: false,
            filter: Some(Filter::new_must(Condition::Field(
                FieldCondition::new_match(
                    "document.body".parse().unwrap(),
                    serde_json::from_value(json!({
                        "value": "qdrant-sec-transfer-filter-sentinel",
                    }))
                    .unwrap(),
                ),
            ))),
        });

        let log_line = format!("{:?}", operation.redacted_log());

        assert!(!log_line.contains("qdrant-sec-transfer-filter-sentinel"));
        assert!(log_line.contains("filter_present: true"), "{log_line}");
        assert!(
            log_line.contains("filter_condition_count: Some(1)"),
            "{log_line}",
        );
    }

    #[test]
    fn shard_transfer_log_projection_redacts_abort_reason() {
        let operation = ShardTransferOperations::Abort {
            transfer: ShardTransferKey {
                shard_id: 1,
                to_shard_id: None,
                from: 3,
                to: 4,
            },
            reason: "qdrant-sec-transfer-abort-sentinel".to_string(),
        };

        let log_line = format!("{:?}", operation.redacted_log());

        assert!(!log_line.contains("qdrant-sec-transfer-abort-sentinel"));
        assert!(log_line.contains("reason_present: true"), "{log_line}");
    }

    #[test]
    fn shard_transfer_key_stage_log_projection_uses_redacted_key_wrapper() {
        let transfer = ShardTransferKey {
            shard_id: 1,
            to_shard_id: Some(2),
            from: 3,
            to: 4,
        };

        for operation in [
            ShardTransferOperations::SnapshotRecovered(transfer),
            ShardTransferOperations::RecoveryToPartial(transfer),
            ShardTransferOperations::Abort {
                transfer,
                reason: "qdrant-sec-transfer-key-stage-abort-sentinel".to_string(),
            },
        ] {
            let log_line = format!("{:?}", operation.redacted_log());

            assert!(log_line.contains("ShardTransferKey"), "{log_line}");
            assert!(log_line.contains("shard_id: 1"), "{log_line}");
            assert!(log_line.contains("to_shard_id: Some(2)"), "{log_line}");
            assert!(log_line.contains("from: 3"), "{log_line}");
            assert!(log_line.contains("to: 4"), "{log_line}");
            assert!(
                !log_line.contains("qdrant-sec-transfer-key-stage-abort-sentinel"),
                "{log_line}",
            );
        }
    }

    #[test]
    fn collection_meta_log_projection_redacts_crypto_migration_key_ids() {
        let operation = CollectionMetaOperations::ApplyCryptoMigration(ApplyCryptoMigrationPlan {
            collection_name: "docs".to_string(),
            plan: CryptoMigrationPlan {
                from: CryptoMigrationState::Encrypting,
                to: CryptoMigrationState::Active,
                target_epoch: 7,
                active_rk_id: Some("rk/secret-active-sentinel".to_string()),
                retired_rk_id: Some("rk/secret-retired-sentinel".to_string()),
                dry_run: false,
                checkpoints: vec![CryptoMigrationCheckpoint {
                    shard_id: 1,
                    total_points: 10,
                    processed_points: 10,
                    rewritten_points: 10,
                    changed_points: 10,
                    status: CryptoMigrationCheckpointStatus::Verified,
                }],
            },
        });

        let log_line = format!("{:?}", operation.redacted_log());

        assert!(!log_line.contains("secret-active-sentinel"), "{log_line}");
        assert!(!log_line.contains("secret-retired-sentinel"), "{log_line}");
        assert!(
            log_line.contains("active_rk_id_present: true"),
            "{log_line}"
        );
        assert!(log_line.contains("checkpoint_count: 1"), "{log_line}");
    }

    #[test]
    fn collection_meta_log_projection_redacts_private_oram_collection_encryption() {
        let operation = CollectionMetaOperations::CreateCollection(
            CreateCollectionOperation::new(
                "docs".to_string(),
                create_collection(Some(private_oram_encrypted_config())),
            )
            .unwrap(),
        );

        let log_line = format!("{:?}", operation.redacted_log());

        assert!(log_line.contains("has_encryption: true"), "{log_line}");
        assert!(log_line.contains("has_uuid: true"), "{log_line}");
        for sentinel in [
            "private-oram-rk-sentinel",
            "docs_text_private_hnsw_sentinel",
            "private-hnsw-vector-sentinel",
            "docs_private_hnsw_instance_sentinel",
            "private-hnsw-oram/v1",
            "docs_body_private_result_sentinel",
            "document.private-result-path-sentinel",
            "docs_private_result_instance_sentinel",
            "private-result-oram/v1",
        ] {
            assert!(
                !log_line.contains(sentinel),
                "collection meta redacted log leaked private ORAM sentinel `{sentinel}`: {log_line}",
            );
        }
    }

    #[test]
    fn collection_meta_log_projection_redacts_payload_index_path() {
        let operation = CollectionMetaOperations::CreatePayloadIndex(CreatePayloadIndex {
            collection_name: "docs".to_string(),
            field_name: "document.body.secret-sentinel".parse().unwrap(),
            field_schema: PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
        });

        let log_line = format!("{:?}", operation.redacted_log());

        assert!(!log_line.contains("document.body.secret-sentinel"));
        assert!(log_line.contains("field_name_present: true"), "{log_line}");
    }

    #[test]
    fn collection_meta_log_projection_redacts_resharding_shard_key() {
        let operation = CollectionMetaOperations::Resharding(
            "docs".to_string(),
            ReshardingOperation::Start(ReshardKey {
                uuid: Uuid::from_u128(7),
                direction: Default::default(),
                peer_id: 3,
                shard_id: 4,
                shard_key: Some("tenant-secret-shard-sentinel".into()),
            }),
        );

        let log_line = format!("{:?}", operation.redacted_log());

        assert!(!log_line.contains("tenant-secret-shard-sentinel"));
        assert!(log_line.contains("shard_key_present: true"), "{log_line}");
        assert!(log_line.contains("operation: \"start\""), "{log_line}");
    }
}
