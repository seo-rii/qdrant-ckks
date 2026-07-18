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

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone, Copy)]
    #[serde(rename_all = "snake_case")]
    pub enum PrivateOramIndexKind {
        Hnsw,
        ResultPayload,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramEpochKey {
        pub collection_id: CollectionId,
        pub index_kind: PrivateOramIndexKind,
        /// Vector name for HNSW; empty for the collection-wide result payload ORAM.
        pub index_name: String,
    }

    impl fmt::Debug for PrivateOramEpochKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramEpochKey")
                .field("index_kind", &self.index_kind)
                .field("collection_id", &"[redacted]")
                .field("index_name", &"[redacted]")
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramConsensusEpoch {
        pub index_epoch: u64,
        pub root_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub writeback_digest: Option<String>,
    }

    impl fmt::Debug for PrivateOramConsensusEpoch {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramConsensusEpoch")
                .field("index_epoch", &self.index_epoch)
                .field("root_hash", &"[redacted]")
                .field("has_writeback_digest", &self.writeback_digest.is_some())
                .finish()
        }
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct CompareAndSwapPrivateOramEpoch {
        pub key: PrivateOramEpochKey,
        pub expected: Option<PrivateOramConsensusEpoch>,
        pub new: PrivateOramConsensusEpoch,
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramSessionLease {
        pub owner_peer_id: PeerId,
        pub lease_id_hash: String,
        pub issued_at_unix: u64,
        pub expires_at_unix: u64,
    }

    impl fmt::Debug for PrivateOramSessionLease {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramSessionLease")
                .field("owner_peer_id", &self.owner_peer_id)
                .field("lease_id_hash", &"[redacted]")
                .field("issued_at_unix", &self.issued_at_unix)
                .field("expires_at_unix", &self.expires_at_unix)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct CompareAndSwapPrivateOramSessionLease {
        pub key: PrivateOramEpochKey,
        pub expected: Option<PrivateOramSessionLease>,
        pub new: Option<PrivateOramSessionLease>,
    }

    impl fmt::Debug for CompareAndSwapPrivateOramSessionLease {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CompareAndSwapPrivateOramSessionLease")
                .field("key", &self.key)
                .field("has_expected", &self.expected.is_some())
                .field("has_new", &self.new.is_some())
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramLayoutKey {
        pub collection_id: CollectionId,
    }

    impl fmt::Debug for PrivateOramLayoutKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramLayoutKey")
                .field("collection_id", &"[redacted]")
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramConsensusLayout {
        /// Starts at one and advances by exactly one for every accepted layout transition.
        pub generation: u64,
        /// Canonical strictly increasing union of peers that own fully-active shard replicas.
        pub owner_peer_ids: Vec<PeerId>,
        /// Base64url SHA-256 of the canonical shard layout.
        pub layout_digest: String,
        /// Base64url SHA-256 of the private ORAM index epoch/root set at this transition.
        pub index_state_digest: String,
    }

    impl fmt::Debug for PrivateOramConsensusLayout {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramConsensusLayout")
                .field("generation", &self.generation)
                .field("owner_peer_count", &self.owner_peer_ids.len())
                .field("layout_digest", &"[redacted]")
                .field("index_state_digest", &"[redacted]")
                .finish()
        }
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct CompareAndSwapPrivateOramLayout {
        pub key: PrivateOramLayoutKey,
        pub expected: Option<PrivateOramConsensusLayout>,
        pub new: PrivateOramConsensusLayout,
    }

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
        CompareAndSwapPrivateOramEpoch(CompareAndSwapPrivateOramEpoch),
        CompareAndSwapPrivateOramSessionLease(CompareAndSwapPrivateOramSessionLease),
        CompareAndSwapPrivateOramLayout(CompareAndSwapPrivateOramLayout),
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
                ConsensusOperations::CompareAndSwapPrivateOramEpoch(operation) => f
                    .debug_struct("CompareAndSwapPrivateOramEpoch")
                    .field("index_kind", &operation.key.index_kind)
                    .field("has_expected", &operation.expected.is_some())
                    .field("new_epoch", &operation.new.index_epoch)
                    .finish(),
                ConsensusOperations::CompareAndSwapPrivateOramSessionLease(operation) => f
                    .debug_struct("CompareAndSwapPrivateOramSessionLease")
                    .field("index_kind", &operation.key.index_kind)
                    .field("has_expected", &operation.expected.is_some())
                    .field("has_new", &operation.new.is_some())
                    .finish(),
                ConsensusOperations::CompareAndSwapPrivateOramLayout(operation) => f
                    .debug_struct("CompareAndSwapPrivateOramLayout")
                    .field("has_expected", &operation.expected.is_some())
                    .field("new_generation", &operation.new.generation)
                    .field("owner_peer_count", &operation.new.owner_peer_ids.len())
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

    use super::consensus_ops::{
        CompareAndSwapPrivateOramEpoch, CompareAndSwapPrivateOramLayout,
        CompareAndSwapPrivateOramSessionLease, ConsensusOperations, PrivateOramConsensusEpoch,
        PrivateOramConsensusLayout, PrivateOramEpochKey, PrivateOramIndexKind,
        PrivateOramLayoutKey, PrivateOramSessionLease,
    };

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
    fn private_oram_epoch_cas_log_projection_redacts_identity_and_roots() {
        let operation =
            ConsensusOperations::CompareAndSwapPrivateOramEpoch(CompareAndSwapPrivateOramEpoch {
                key: PrivateOramEpochKey {
                    collection_id: "qdrant-sec-private-oram-collection-sentinel".to_string(),
                    index_kind: PrivateOramIndexKind::Hnsw,
                    index_name: "qdrant-sec-private-oram-vector-sentinel".to_string(),
                },
                expected: Some(PrivateOramConsensusEpoch {
                    index_epoch: 42,
                    root_hash: "qdrant-sec-private-oram-old-root-sentinel".to_string(),
                    writeback_digest: Some(
                        "qdrant-sec-private-oram-old-digest-sentinel".to_string(),
                    ),
                }),
                new: PrivateOramConsensusEpoch {
                    index_epoch: 43,
                    root_hash: "qdrant-sec-private-oram-new-root-sentinel".to_string(),
                    writeback_digest: Some(
                        "qdrant-sec-private-oram-new-digest-sentinel".to_string(),
                    ),
                },
            });

        let redacted = format!("{:?}", operation.redacted_log());
        let raw = format!("{operation:?}");

        for rendered in [&redacted, &raw] {
            assert!(
                !rendered.contains("qdrant-sec-private-oram-collection-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-vector-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-old-root-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-new-root-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-old-digest-sentinel"),
                "{rendered}",
            );
            assert!(
                !rendered.contains("qdrant-sec-private-oram-new-digest-sentinel"),
                "{rendered}",
            );
        }
        assert!(redacted.contains("has_expected: true"), "{redacted}");
        assert!(redacted.contains("new_epoch: 43"), "{redacted}");
    }

    #[test]
    fn private_oram_session_lease_log_projection_redacts_identity_and_hash() {
        let lease_hash = "qdrant-sec-private-oram-lease-hash-sentinel";
        let operation = ConsensusOperations::CompareAndSwapPrivateOramSessionLease(
            CompareAndSwapPrivateOramSessionLease {
                key: PrivateOramEpochKey {
                    collection_id: "qdrant-sec-private-oram-lease-collection-sentinel".to_string(),
                    index_kind: PrivateOramIndexKind::Hnsw,
                    index_name: "qdrant-sec-private-oram-lease-vector-sentinel".to_string(),
                },
                expected: None,
                new: Some(PrivateOramSessionLease {
                    owner_peer_id: 7,
                    lease_id_hash: lease_hash.to_string(),
                    issued_at_unix: 100,
                    expires_at_unix: 160,
                }),
            },
        );

        for rendered in [
            format!("{operation:?}"),
            format!("{:?}", operation.redacted_log()),
        ] {
            assert!(rendered.contains("CompareAndSwapPrivateOramSessionLease"));
            assert!(!rendered.contains(lease_hash), "{rendered}");
            assert!(
                !rendered.contains("lease-collection-sentinel"),
                "{rendered}"
            );
            assert!(!rendered.contains("lease-vector-sentinel"), "{rendered}");
        }
    }

    #[test]
    fn private_oram_layout_log_projection_redacts_identity_and_digests() {
        let collection_sentinel = "qdrant-sec-private-oram-layout-collection-sentinel";
        let layout_digest_sentinel = "qdrant-sec-private-oram-layout-digest-sentinel";
        let index_digest_sentinel = "qdrant-sec-private-oram-index-digest-sentinel";
        let operation =
            ConsensusOperations::CompareAndSwapPrivateOramLayout(CompareAndSwapPrivateOramLayout {
                key: PrivateOramLayoutKey {
                    collection_id: collection_sentinel.to_string(),
                },
                expected: None,
                new: PrivateOramConsensusLayout {
                    generation: 1,
                    owner_peer_ids: vec![7, 9],
                    layout_digest: layout_digest_sentinel.to_string(),
                    index_state_digest: index_digest_sentinel.to_string(),
                },
            });

        for rendered in [
            format!("{operation:?}"),
            format!("{:?}", operation.redacted_log()),
        ] {
            assert!(rendered.contains("CompareAndSwapPrivateOramLayout"));
            assert!(rendered.contains("generation: 1"), "{rendered}");
            assert!(!rendered.contains(collection_sentinel), "{rendered}");
            assert!(!rendered.contains(layout_digest_sentinel), "{rendered}");
            assert!(!rendered.contains(index_digest_sentinel), "{rendered}");
        }
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
