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
    use std::collections::BTreeSet;
    use std::fmt;

    use collection::config::ShardingMethod;
    use collection::operations::types::PeerMetadata;
    use collection::shards::replica_set::replica_set_state::ReplicaState;
    use collection::shards::replica_set::replica_set_state::ReplicaState::Initializing;
    use collection::shards::resharding::ReshardKey;
    use collection::shards::shard::{PeerId, ShardId};
    use collection::shards::transfer::ShardTransfer;
    use collection::shards::{CollectionId, replica_set};
    use data_encoding::BASE64URL_NOPAD;
    use raft::eraftpb::Entry as RaftEntry;
    use segment::types::ShardKey;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use super::collection_meta_ops::ReshardingOperation;
    use crate::content_manager::collection_meta_ops::{
        CollectionMetaOperations, SetShardReplicaState, ShardTransferOperations, UpdateCollection,
        UpdateCollectionOperation,
    };
    use crate::content_manager::errors::StorageError;

    const PRIVATE_ORAM_SHARD_LAYOUT_DIGEST_DOMAIN: &[u8] =
        b"qdrant-sec/private-oram-shard-layout-digest/v1";
    const PRIVATE_ORAM_INDEX_STATE_DIGEST_DOMAIN: &[u8] =
        b"qdrant-sec/private-oram-index-state-digest/v1";
    const PRIVATE_ORAM_CONSENSUS_MAX_RECORDS: usize = 1_000_000;
    const PRIVATE_ORAM_LAYOUT_MAX_OWNERS: usize = 10_000;

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
        /// Base64url SHA-256 of the private ORAM index epoch/root/completion set.
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

    #[derive(PartialEq, Eq, Clone)]
    pub struct PrivateOramShardLayoutEntry {
        pub shard_id: ShardId,
        pub shard_key: Option<ShardKey>,
        pub owner_peer_ids: Vec<PeerId>,
    }

    impl fmt::Debug for PrivateOramShardLayoutEntry {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramShardLayoutEntry")
                .field("shard_id", &self.shard_id)
                .field("shard_key_present", &self.shard_key.is_some())
                .field("owner_peer_count", &self.owner_peer_ids.len())
                .finish()
        }
    }

    pub fn canonical_private_oram_shard_layout_digest(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
    ) -> Result<(Vec<PeerId>, String), StorageError> {
        if !valid_private_oram_collection_id(collection_id)
            || entries.is_empty()
            || entries.len() > PRIVATE_ORAM_CONSENSUS_MAX_RECORDS
        {
            return Err(invalid_private_oram_layout_digest_input());
        }

        let mut entries = entries.to_vec();
        entries.sort_by_key(|entry| entry.shard_id);
        if entries
            .windows(2)
            .any(|entries| entries[0].shard_id == entries[1].shard_id)
        {
            return Err(invalid_private_oram_layout_digest_input());
        }

        let mut owner_union = BTreeSet::new();
        for entry in &mut entries {
            let valid_shard_key = matches!(
                (sharding_method, entry.shard_key.as_ref()),
                (ShardingMethod::Auto, None) | (ShardingMethod::Custom, Some(_))
            );
            if !valid_shard_key
                || entry.owner_peer_ids.is_empty()
                || entry.owner_peer_ids.len() > PRIVATE_ORAM_LAYOUT_MAX_OWNERS
            {
                return Err(invalid_private_oram_layout_digest_input());
            }
            entry.owner_peer_ids.sort_unstable();
            if entry
                .owner_peer_ids
                .windows(2)
                .any(|owners| owners[0] == owners[1])
            {
                return Err(invalid_private_oram_layout_digest_input());
            }
            owner_union.extend(entry.owner_peer_ids.iter().copied());
        }
        if owner_union.len() > PRIVATE_ORAM_LAYOUT_MAX_OWNERS {
            return Err(invalid_private_oram_layout_digest_input());
        }

        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_ORAM_SHARD_LAYOUT_DIGEST_DOMAIN);
        update_private_oram_length_prefixed(&mut hasher, collection_id.as_bytes());
        hasher.update([match sharding_method {
            ShardingMethod::Auto => 1,
            ShardingMethod::Custom => 2,
        }]);
        hasher.update((entries.len() as u64).to_be_bytes());
        for entry in entries {
            hasher.update(entry.shard_id.to_be_bytes());
            match entry.shard_key {
                None => hasher.update([0]),
                Some(ShardKey::Keyword(value)) => {
                    hasher.update([1]);
                    update_private_oram_length_prefixed(&mut hasher, value.as_bytes());
                }
                Some(ShardKey::Number(value)) => {
                    hasher.update([2]);
                    hasher.update(value.to_be_bytes());
                }
            }
            hasher.update((entry.owner_peer_ids.len() as u64).to_be_bytes());
            for peer_id in entry.owner_peer_ids {
                hasher.update(peer_id.to_be_bytes());
            }
        }

        Ok((
            owner_union.into_iter().collect(),
            BASE64URL_NOPAD.encode(&hasher.finalize()),
        ))
    }

    pub fn canonical_private_oram_index_state_digest(
        collection_id: &str,
        states: &[(PrivateOramEpochKey, PrivateOramConsensusEpoch)],
    ) -> Result<String, StorageError> {
        if !valid_private_oram_collection_id(collection_id)
            || states.is_empty()
            || states.len() > PRIVATE_ORAM_CONSENSUS_MAX_RECORDS
        {
            return Err(invalid_private_oram_index_state_digest_input());
        }

        let mut states = states.to_vec();
        states.sort_by(|(left, _), (right, _)| {
            private_oram_index_kind_tag(left.index_kind)
                .cmp(&private_oram_index_kind_tag(right.index_kind))
                .then_with(|| left.index_name.as_bytes().cmp(right.index_name.as_bytes()))
        });
        if states.windows(2).any(|states| {
            states[0].0.index_kind == states[1].0.index_kind
                && states[0].0.index_name == states[1].0.index_name
        }) {
            return Err(invalid_private_oram_index_state_digest_input());
        }

        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_ORAM_INDEX_STATE_DIGEST_DOMAIN);
        update_private_oram_length_prefixed(&mut hasher, collection_id.as_bytes());
        hasher.update((states.len() as u64).to_be_bytes());
        for (key, state) in states {
            let valid_key = key.collection_id == collection_id
                && match key.index_kind {
                    PrivateOramIndexKind::Hnsw => {
                        !key.index_name.is_empty() && key.index_name.len() <= 128
                    }
                    PrivateOramIndexKind::ResultPayload => key.index_name.is_empty(),
                };
            let Some(root_hash) = decode_private_oram_sha256_digest(&state.root_hash) else {
                return Err(invalid_private_oram_index_state_digest_input());
            };
            let writeback_digest = match state.writeback_digest {
                Some(digest) => Some(
                    decode_private_oram_sha256_digest(&digest)
                        .ok_or_else(invalid_private_oram_index_state_digest_input)?,
                ),
                None => None,
            };
            if !valid_key {
                return Err(invalid_private_oram_index_state_digest_input());
            }

            hasher.update([private_oram_index_kind_tag(key.index_kind)]);
            update_private_oram_length_prefixed(&mut hasher, key.index_name.as_bytes());
            hasher.update(state.index_epoch.to_be_bytes());
            hasher.update(root_hash);
            match writeback_digest {
                Some(digest) => {
                    hasher.update([1]);
                    hasher.update(digest);
                }
                None => hasher.update([0]),
            }
        }
        Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
    }

    fn valid_private_oram_collection_id(collection_id: &str) -> bool {
        !collection_id.is_empty() && collection_id.len() <= 1024
    }

    fn private_oram_index_kind_tag(index_kind: PrivateOramIndexKind) -> u8 {
        match index_kind {
            PrivateOramIndexKind::Hnsw => 1,
            PrivateOramIndexKind::ResultPayload => 2,
        }
    }

    fn decode_private_oram_sha256_digest(value: &str) -> Option<[u8; 32]> {
        let decoded = BASE64URL_NOPAD.decode(value.as_bytes()).ok()?;
        let digest: [u8; 32] = decoded.try_into().ok()?;
        (BASE64URL_NOPAD.encode(&digest) == value).then_some(digest)
    }

    fn update_private_oram_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    fn invalid_private_oram_layout_digest_input() -> StorageError {
        StorageError::bad_request("private ORAM consensus layout digest input is invalid")
    }

    fn invalid_private_oram_index_state_digest_input() -> StorageError {
        StorageError::bad_request("private ORAM consensus index-state digest input is invalid")
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
    use collection::config::ShardingMethod;
    use data_encoding::BASE64URL_NOPAD;
    use segment::types::ShardKey;
    use serde_json::json;

    use super::consensus_ops::{
        CompareAndSwapPrivateOramEpoch, CompareAndSwapPrivateOramLayout,
        CompareAndSwapPrivateOramSessionLease, ConsensusOperations, PrivateOramConsensusEpoch,
        PrivateOramConsensusLayout, PrivateOramEpochKey, PrivateOramIndexKind,
        PrivateOramLayoutKey, PrivateOramSessionLease, PrivateOramShardLayoutEntry,
        canonical_private_oram_index_state_digest, canonical_private_oram_shard_layout_digest,
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
    fn private_oram_shard_layout_digest_is_canonical_and_context_bound() {
        let collection_id = "collection-uuid-1";
        let entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 7,
                shard_key: None,
                owner_peer_ids: vec![9, 7],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: None,
                owner_peer_ids: vec![11, 7],
            },
        ];
        let (owners, digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &entries,
        )
        .unwrap();
        assert_eq!(owners, vec![7, 9, 11]);
        assert_eq!(digest, "qi72wYzZybKDizqgH4R6vJgGR9su3NW21ud7WGBDTXo");

        let mut reordered = entries.clone();
        reordered.reverse();
        for entry in &mut reordered {
            entry.owner_peer_ids.reverse();
        }
        assert_eq!(
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &reordered,
            )
            .unwrap(),
            (owners, digest.clone()),
        );
        assert_ne!(
            canonical_private_oram_shard_layout_digest(
                "collection-uuid-2",
                ShardingMethod::Auto,
                &entries,
            )
            .unwrap()
            .1,
            digest,
        );

        for invalid_entries in [
            Vec::new(),
            vec![entries[0].clone(), entries[0].clone()],
            vec![PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![7, 7],
            }],
        ] {
            let error = canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &invalid_entries,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("layout digest input is invalid"), "{error}");
        }

        let shard_key_sentinel = "qdrant-sec-layout-shard-key-sentinel";
        let custom_entry = PrivateOramShardLayoutEntry {
            shard_id: 1,
            shard_key: Some(ShardKey::from(shard_key_sentinel)),
            owner_peer_ids: vec![7],
        };
        let rendered = format!("{custom_entry:?}");
        assert!(!rendered.contains(shard_key_sentinel), "{rendered}");
        assert!(
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &[custom_entry],
            )
            .unwrap_err()
            .to_string()
            .contains("layout digest input is invalid"),
        );
    }

    #[test]
    fn private_oram_index_state_digest_is_canonical_and_context_bound() {
        let collection_id = "collection-uuid-1";
        let hnsw = (
            PrivateOramEpochKey {
                collection_id: collection_id.to_string(),
                index_kind: PrivateOramIndexKind::Hnsw,
                index_name: "text".to_string(),
            },
            PrivateOramConsensusEpoch {
                index_epoch: 42,
                root_hash: BASE64URL_NOPAD.encode(&[42; 32]),
                writeback_digest: Some(BASE64URL_NOPAD.encode(&[12; 32])),
            },
        );
        let result = (
            PrivateOramEpochKey {
                collection_id: collection_id.to_string(),
                index_kind: PrivateOramIndexKind::ResultPayload,
                index_name: String::new(),
            },
            PrivateOramConsensusEpoch {
                index_epoch: 43,
                root_hash: BASE64URL_NOPAD.encode(&[43; 32]),
                writeback_digest: None,
            },
        );
        let digest = canonical_private_oram_index_state_digest(
            collection_id,
            &[result.clone(), hnsw.clone()],
        )
        .unwrap();
        assert_eq!(digest, "n7nIXIYcknwRMw-RNISCQyIc51XTAfh2mKJDV3-qvFQ");
        assert_eq!(
            canonical_private_oram_index_state_digest(collection_id, &[hnsw.clone(), result])
                .unwrap(),
            digest,
        );

        let malformed_digest_sentinel = "qdrant-sec-index-state-digest-sentinel";
        let malformed = (
            hnsw.0.clone(),
            PrivateOramConsensusEpoch {
                root_hash: malformed_digest_sentinel.to_string(),
                ..hnsw.1.clone()
            },
        );
        for invalid_states in [
            Vec::new(),
            vec![hnsw.clone(), hnsw.clone()],
            vec![malformed],
        ] {
            let error = canonical_private_oram_index_state_digest(collection_id, &invalid_states)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("index-state digest input is invalid"),
                "{error}"
            );
            assert!(!error.contains(malformed_digest_sentinel), "{error}");
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
