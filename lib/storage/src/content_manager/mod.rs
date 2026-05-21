use collection::shards::shard::PeerId;

use self::collection_meta_ops::CollectionMetaOperations;
use self::consensus_manager::CollectionsSnapshot;
use self::errors::StorageError;

pub mod alias_mapping;
pub mod collection_meta_ops;
pub mod collection_verification;
mod collections_ops;
pub mod consensus;
pub mod consensus_manager;
pub mod conversions;
pub mod errors;
pub mod shard_distribution;
pub mod snapshots;
#[cfg(feature = "staging")]
pub mod staging;
pub mod toc;

pub mod consensus_ops {
    use std::fmt;

    use collection::operations::types::PeerMetadata;
    use collection::shards::replica_set::replica_set_state::ReplicaState;
    use collection::shards::replica_set::replica_set_state::ReplicaState::Initializing;
    use collection::shards::resharding::ReshardKey;
    use collection::shards::shard::PeerId;
    use collection::shards::transfer::ShardTransfer;
    use collection::shards::{CollectionId, replica_set};
    use raft::eraftpb::Entry as RaftEntry;
    use serde::{Deserialize, Serialize};

    use super::collection_meta_ops::ReshardingOperation;
    use crate::content_manager::collection_meta_ops::{
        CollectionMetaOperations, SetShardReplicaState, ShardTransferOperations, UpdateCollection,
        UpdateCollectionOperation,
    };

    /// Operation that should pass consensus
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub enum ConsensusOperations {
        CollectionMeta(Box<CollectionMetaOperations>),
        AddPeer {
            peer_id: PeerId,
            uri: String,
        },
        RemovePeer(PeerId),
        UpdatePeerMetadata {
            peer_id: PeerId,
            metadata: PeerMetadata,
        },
        UpdateClusterMetadata {
            key: String,
            value: serde_json::Value,
        },
        RequestSnapshot,
        ReportSnapshot {
            peer_id: PeerId,
            status: SnapshotStatus,
        },
    }

    impl TryFrom<&RaftEntry> for ConsensusOperations {
        type Error = serde_cbor::Error;

        fn try_from(entry: &RaftEntry) -> Result<Self, Self::Error> {
            serde_cbor::from_slice(entry.get_data())
        }
    }

    impl ConsensusOperations {
        pub fn redacted_log(&self) -> RedactedConsensusOperation<'_> {
            RedactedConsensusOperation(self)
        }

        pub fn abort_transfer(
            collection_id: CollectionId,
            transfer: ShardTransfer,
            reason: &str,
        ) -> Self {
            ConsensusOperations::CollectionMeta(Box::new(CollectionMetaOperations::TransferShard(
                collection_id,
                ShardTransferOperations::Abort {
                    transfer: transfer.key(),
                    reason: reason.to_string(),
                },
            )))
        }

        pub fn finish_transfer(collection_id: CollectionId, transfer: ShardTransfer) -> Self {
            ConsensusOperations::CollectionMeta(Box::new(CollectionMetaOperations::TransferShard(
                collection_id,
                ShardTransferOperations::Finish(transfer),
            )))
        }

        pub fn abort_resharding(collection_id: CollectionId, reshard_key: ReshardKey) -> Self {
            ConsensusOperations::CollectionMeta(Box::new(CollectionMetaOperations::Resharding(
                collection_id,
                ReshardingOperation::Abort(reshard_key),
            )))
        }

        pub fn finish_resharding(collection_id: CollectionId, reshard_key: ReshardKey) -> Self {
            ConsensusOperations::CollectionMeta(Box::new(CollectionMetaOperations::Resharding(
                collection_id,
                ReshardingOperation::Finish(reshard_key),
            )))
        }

        pub fn set_replica_state(
            collection_name: CollectionId,
            shard_id: u32,
            peer_id: PeerId,
            state: ReplicaState,
            from_state: Option<ReplicaState>,
        ) -> Self {
            ConsensusOperations::CollectionMeta(
                CollectionMetaOperations::SetShardReplicaState(SetShardReplicaState {
                    collection_name,
                    shard_id,
                    peer_id,
                    state,
                    from_state,
                })
                .into(),
            )
        }

        pub fn remove_replica(
            collection_name: CollectionId,
            shard_id: u32,
            peer_id: PeerId,
        ) -> Self {
            let mut operation = UpdateCollectionOperation::new(
                collection_name,
                UpdateCollection {
                    vectors: None,
                    optimizers_config: None,
                    params: None,
                    hnsw_config: None,
                    quantization_config: None,
                    sparse_vectors: None,
                    strict_mode_config: None,
                    metadata: None,
                },
            );
            operation
                .set_shard_replica_changes(vec![replica_set::Change::Remove(shard_id, peer_id)]);

            ConsensusOperations::CollectionMeta(
                CollectionMetaOperations::UpdateCollection(operation).into(),
            )
        }

        /// Report that a replica was initialized
        pub fn initialize_replica(
            collection_name: CollectionId,
            shard_id: u32,
            peer_id: PeerId,
        ) -> Self {
            Self::set_replica_state(
                collection_name,
                shard_id,
                peer_id,
                ReplicaState::Active,
                Some(Initializing),
            )
        }

        pub fn start_transfer(collection_id: CollectionId, transfer: ShardTransfer) -> Self {
            ConsensusOperations::CollectionMeta(Box::new(CollectionMetaOperations::TransferShard(
                collection_id,
                ShardTransferOperations::Start(transfer),
            )))
        }

        pub fn request_snapshot() -> Self {
            Self::RequestSnapshot
        }

        pub fn report_snapshot(peer_id: PeerId, status: impl Into<SnapshotStatus>) -> Self {
            Self::ReportSnapshot {
                peer_id,
                status: status.into(),
            }
        }
    }

    pub struct RedactedConsensusOperation<'a>(&'a ConsensusOperations);

    impl fmt::Debug for RedactedConsensusOperation<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0 {
                ConsensusOperations::CollectionMeta(operation) => f
                    .debug_tuple("CollectionMeta")
                    .field(&operation.redacted_log())
                    .finish(),
                ConsensusOperations::AddPeer { peer_id, uri } => f
                    .debug_struct("AddPeer")
                    .field("peer_id", peer_id)
                    .field("uri_present", &(!uri.is_empty()))
                    .finish(),
                ConsensusOperations::RemovePeer(peer_id) => {
                    f.debug_tuple("RemovePeer").field(peer_id).finish()
                }
                ConsensusOperations::UpdatePeerMetadata { peer_id, metadata } => f
                    .debug_struct("UpdatePeerMetadata")
                    .field("peer_id", peer_id)
                    .field(
                        "crypto_fingerprint_present",
                        &peer_metadata_has_crypto_fingerprint(metadata),
                    )
                    .finish(),
                ConsensusOperations::UpdateClusterMetadata { key, value } => f
                    .debug_struct("UpdateClusterMetadata")
                    .field("key", key)
                    .field("value_type", &json_value_type(value))
                    .finish(),
                ConsensusOperations::RequestSnapshot => f.write_str("RequestSnapshot"),
                ConsensusOperations::ReportSnapshot { peer_id, status } => f
                    .debug_struct("ReportSnapshot")
                    .field("peer_id", peer_id)
                    .field("status", status)
                    .finish(),
            }
        }
    }

    fn peer_metadata_has_crypto_fingerprint(metadata: &PeerMetadata) -> bool {
        metadata
            .crypto_runtime_capability_fingerprint()
            .is_some_and(|fingerprint| !fingerprint.is_empty())
    }

    fn json_value_type(value: &serde_json::Value) -> &'static str {
        match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "bool",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        }
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Deserialize, Serialize)]
    pub enum SnapshotStatus {
        Finish,
        Failure,
    }

    impl From<raft::SnapshotStatus> for SnapshotStatus {
        fn from(status: raft::SnapshotStatus) -> Self {
            match status {
                raft::SnapshotStatus::Finish => Self::Finish,
                raft::SnapshotStatus::Failure => Self::Failure,
            }
        }
    }

    impl From<SnapshotStatus> for raft::SnapshotStatus {
        fn from(status: SnapshotStatus) -> Self {
            match status {
                SnapshotStatus::Finish => Self::Finish,
                SnapshotStatus::Failure => Self::Failure,
            }
        }
    }
}

/// Collection container abstraction for consensus
/// Used to mock ToC in consensus state tests
pub trait CollectionContainer {
    fn perform_collection_meta_op(
        &self,
        operation: CollectionMetaOperations,
    ) -> Result<bool, StorageError>;

    fn collections_snapshot(&self) -> CollectionsSnapshot;

    fn apply_collections_snapshot(&self, data: CollectionsSnapshot) -> Result<(), StorageError>;

    fn remove_peer(&self, peer_id: PeerId) -> Result<(), StorageError>;

    fn sync_local_state(&self) -> Result<(), StorageError>;
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::consensus_ops::ConsensusOperations;

    // Consensus messages are serialized to CBOR when sent over network and written into WAL.
    //
    // We are using `serde_json::Value` in `ConsensusOperations::UpdateClusterMetadata`,
    // but the way `serde` works, it is not *strictly* guaranteed that all possible JSON values
    // can be serialized to CBOR, there might be some minor inconsistencies between formats.
    //
    // These tests check that `serde_json::Value` can be serialized to (and deserialized from) CBOR.

    #[test]
    fn serde_json_null_combatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!(null));
    }

    #[test]
    fn consensus_operation_log_projection_redacts_cluster_metadata_value() {
        let operation = ConsensusOperations::UpdateClusterMetadata {
            key: "crypto-policy".to_string(),
            value: json!({
                "secret": "qdrant-sec-consensus-secret-sentinel",
                "rk_id": "rk/secret-sentinel",
            }),
        };

        let log_line = format!("{:?}", operation.redacted_log());

        assert!(!log_line.contains("qdrant-sec-consensus-secret-sentinel"));
        assert!(!log_line.contains("rk/secret-sentinel"));
        assert!(log_line.contains("value_type: \"object\""), "{log_line}");
    }

    #[test]
    fn raw_consensus_operation_debug_still_contains_cluster_metadata_value() {
        let operation = ConsensusOperations::UpdateClusterMetadata {
            key: "crypto-policy".to_string(),
            value: json!({ "secret": "qdrant-sec-raw-consensus-sentinel" }),
        };

        let raw_debug = format!("{operation:?}");

        assert!(raw_debug.contains("qdrant-sec-raw-consensus-sentinel"));
    }

    #[test]
    fn serde_json_integer_combatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!(1337));
    }

    #[test]
    fn serde_json_float_combatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!(42.69));
    }

    #[test]
    fn serde_json_string_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!(
            "Qdrant is the best vector search engine on the market 💪😎👍"
        ));
    }

    #[test]
    fn serde_json_basic_array_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json_array());
    }

    #[test]
    fn serde_json_basic_object_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json_object());
    }

    #[test]
    fn serde_json_nested_array_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!([
            json!([json_array(), json_object()]),
            json!({ "array": json_array(), "object": json_object() }),
        ]));
    }

    #[test]
    fn serde_json_nested_object_compatible_with_cbor() {
        serde_json_value_compatible_with_cbor(json!({
            "array": json!([ json_array(), json_object() ]),
            "object": json!({ "array": json_array(), "object": json_object() }),
        }))
    }

    fn serde_json_value_compatible_with_cbor(input: serde_json::Value) {
        let cbor = serde_cbor::to_vec(&input)
            .unwrap_or_else(|_| panic!("JSON value {input} can be serialized to CBOR"));

        let output: serde_json::Value = serde_cbor::from_slice(&cbor)
            .unwrap_or_else(|_| panic!("JSON value {input} can be deserialized from CBOR"));

        assert_eq!(input, output);
    }

    fn json_array() -> serde_json::Value {
        json!([null, 1337, 42.69, "string"])
    }

    fn json_object() -> serde_json::Value {
        json!({
            "null": null,
            "integer": 1337,
            "float": 42.69,
            "string": "string",
        })
    }
}
