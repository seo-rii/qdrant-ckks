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

    use collection::config::{
        CollectionConfigInternal, EncryptionSelector, ShardingMethod,
        encryption_rule_uses_private_hnsw_oram, encryption_rule_uses_private_result_oram,
    };
    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::operations::types::PeerMetadata;
    use collection::shards::replica_set::replica_set_state::ReplicaState;
    use collection::shards::replica_set::replica_set_state::ReplicaState::Initializing;
    use collection::shards::resharding::ReshardKey;
    use collection::shards::shard::{PeerId, ShardId};
    use collection::shards::transfer::{
        PrivateOramTransferIndexKind, PrivateOramTransferLayoutState,
        PrivateOramTransferLayoutTransition, ShardTransfer, ShardTransferMethod,
    };
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
        /// Base64url SHA-256 of the index epoch/root/completion set at this layout transition.
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

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramLayoutLeaseBinding {
        pub key: PrivateOramEpochKey,
        pub lease: PrivateOramSessionLease,
    }

    impl fmt::Debug for PrivateOramLayoutLeaseBinding {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramLayoutLeaseBinding")
                .field("index_kind", &self.key.index_kind)
                .field("owner_peer_id", &self.lease.owner_peer_id)
                .field("issued_at_unix", &self.lease.issued_at_unix)
                .field("expires_at_unix", &self.lease.expires_at_unix)
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramCollectionLayoutTransition {
        pub layout: CompareAndSwapPrivateOramLayout,
        pub leases: Vec<PrivateOramLayoutLeaseBinding>,
        pub collection_meta: Box<CollectionMetaOperations>,
    }

    impl fmt::Debug for PrivateOramCollectionLayoutTransition {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramCollectionLayoutTransition")
                .field("has_expected", &self.layout.expected.is_some())
                .field("new_generation", &self.layout.new.generation)
                .field("lease_count", &self.leases.len())
                .field("collection_meta", &self.collection_meta.redacted_log())
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramShardTransferStart {
        pub leases: Vec<PrivateOramLayoutLeaseBinding>,
        pub collection_meta: Box<CollectionMetaOperations>,
    }

    impl fmt::Debug for PrivateOramShardTransferStart {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramShardTransferStart")
                .field("lease_count", &self.leases.len())
                .field("collection_meta", &self.collection_meta.redacted_log())
                .finish()
        }
    }

    #[derive(Deserialize, Serialize, PartialEq, Eq, Hash, Clone)]
    pub struct PrivateOramShardTransferFinish {
        pub collection_meta: Box<CollectionMetaOperations>,
    }

    impl fmt::Debug for PrivateOramShardTransferFinish {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PrivateOramShardTransferFinish")
                .field("collection_meta", &self.collection_meta.redacted_log())
                .finish()
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum PrivateOramLayoutTransitionState {
        Pending,
        Applied,
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

    pub fn canonical_private_oram_resharding_post_layout_digest(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        resharding_key: &ReshardKey,
    ) -> Result<(Vec<PeerId>, String), StorageError> {
        // Validate the complete pre-layout before removing or adding an entry. Otherwise a
        // malformed scale-down target could disappear before canonical validation sees it.
        canonical_private_oram_shard_layout_digest(collection_id, sharding_method, entries)?;

        let mut post_entries = entries.to_vec();
        match resharding_key.direction {
            ReshardingDirection::Up => {
                if post_entries
                    .iter()
                    .any(|entry| entry.shard_id == resharding_key.shard_id)
                {
                    return Err(invalid_private_oram_resharding_layout_input());
                }
                post_entries.push(PrivateOramShardLayoutEntry {
                    shard_id: resharding_key.shard_id,
                    shard_key: resharding_key.shard_key.clone(),
                    owner_peer_ids: vec![resharding_key.peer_id],
                });
            }
            ReshardingDirection::Down => {
                let entry_index = post_entries
                    .iter()
                    .position(|entry| entry.shard_id == resharding_key.shard_id)
                    .ok_or_else(invalid_private_oram_resharding_layout_input)?;
                let target = &post_entries[entry_index];
                if target.shard_key != resharding_key.shard_key
                    || !target.owner_peer_ids.contains(&resharding_key.peer_id)
                {
                    return Err(invalid_private_oram_resharding_layout_input());
                }
                post_entries.remove(entry_index);
                if !post_entries
                    .iter()
                    .any(|entry| entry.shard_key == resharding_key.shard_key)
                {
                    return Err(invalid_private_oram_resharding_layout_input());
                }
            }
        }

        canonical_private_oram_shard_layout_digest(collection_id, sharding_method, &post_entries)
            .map_err(|_| invalid_private_oram_resharding_layout_input())
    }

    pub fn classify_private_oram_replica_removal_layout_transition(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        shard_id: ShardId,
        peer_id: PeerId,
        expected: &PrivateOramConsensusLayout,
        new: &PrivateOramConsensusLayout,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        let (owner_peer_ids, layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, entries)?;
        if private_oram_layout_topology_matches(expected, &owner_peer_ids, &layout_digest) {
            let mut post_entries = entries.to_vec();
            let entry = post_entries
                .iter_mut()
                .find(|entry| entry.shard_id == shard_id)
                .ok_or_else(invalid_private_oram_layout_transition_input)?;
            let owner_index = entry
                .owner_peer_ids
                .iter()
                .position(|owner| *owner == peer_id)
                .ok_or_else(invalid_private_oram_layout_transition_input)?;
            entry.owner_peer_ids.remove(owner_index);
            let (new_owner_peer_ids, new_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &post_entries,
                )?;
            if private_oram_layout_topology_matches(new, &new_owner_peer_ids, &new_layout_digest) {
                return Ok(PrivateOramLayoutTransitionState::Pending);
            }
        } else if private_oram_layout_topology_matches(new, &owner_peer_ids, &layout_digest) {
            let mut pre_entries = entries.to_vec();
            let entry = pre_entries
                .iter_mut()
                .find(|entry| entry.shard_id == shard_id)
                .ok_or_else(invalid_private_oram_layout_transition_input)?;
            if entry.owner_peer_ids.contains(&peer_id) {
                return Err(invalid_private_oram_layout_transition_input());
            }
            entry.owner_peer_ids.push(peer_id);
            let (old_owner_peer_ids, old_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &pre_entries,
                )?;
            if private_oram_layout_topology_matches(
                expected,
                &old_owner_peer_ids,
                &old_layout_digest,
            ) {
                return Ok(PrivateOramLayoutTransitionState::Applied);
            }
        }
        Err(invalid_private_oram_layout_transition_input())
    }

    pub fn private_oram_transfer_consensus_layouts(
        transition: &PrivateOramTransferLayoutTransition,
    ) -> (
        PrivateOramLayoutKey,
        PrivateOramConsensusLayout,
        PrivateOramConsensusLayout,
    ) {
        (
            PrivateOramLayoutKey {
                collection_id: transition.collection_id.clone(),
            },
            private_oram_transfer_consensus_layout(&transition.expected),
            private_oram_transfer_consensus_layout(&transition.new),
        )
    }

    pub fn private_oram_transfer_consensus_states(
        transition: &PrivateOramTransferLayoutTransition,
    ) -> Vec<(PrivateOramEpochKey, PrivateOramConsensusEpoch)> {
        transition
            .index_states
            .iter()
            .map(|state| {
                (
                    PrivateOramEpochKey {
                        collection_id: transition.collection_id.clone(),
                        index_kind: match state.index_kind {
                            PrivateOramTransferIndexKind::Hnsw => PrivateOramIndexKind::Hnsw,
                            PrivateOramTransferIndexKind::ResultPayload => {
                                PrivateOramIndexKind::ResultPayload
                            }
                        },
                        index_name: state.index_name.clone(),
                    },
                    PrivateOramConsensusEpoch {
                        index_epoch: state.index_epoch,
                        root_hash: state.root_hash.clone(),
                        writeback_digest: state.writeback_digest.clone(),
                    },
                )
            })
            .collect()
    }

    pub fn classify_private_oram_shard_transfer_layout_transition(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        transfer: &ShardTransfer,
        expected: &PrivateOramConsensusLayout,
        new: &PrivateOramConsensusLayout,
    ) -> Result<PrivateOramLayoutTransitionState, StorageError> {
        validate_private_oram_shard_transfer_shape(transfer)?;
        let transition = transfer
            .private_oram_layout_transition
            .as_ref()
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        let (_, transfer_expected, transfer_new) =
            private_oram_transfer_consensus_layouts(transition);
        if transition.collection_id != collection_id
            || &transfer_expected != expected
            || &transfer_new != new
        {
            return Err(invalid_private_oram_layout_transition_input());
        }
        let (owner_peer_ids, layout_digest) =
            canonical_private_oram_shard_layout_digest(collection_id, sharding_method, entries)?;
        if private_oram_layout_topology_matches(expected, &owner_peer_ids, &layout_digest) {
            let post_entries = private_oram_transfer_post_entries(entries, transfer)?;
            let (new_owner_peer_ids, new_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &post_entries,
                )?;
            if private_oram_layout_topology_matches(new, &new_owner_peer_ids, &new_layout_digest) {
                return Ok(PrivateOramLayoutTransitionState::Pending);
            }
        } else if private_oram_layout_topology_matches(new, &owner_peer_ids, &layout_digest) {
            let pre_entries = private_oram_transfer_pre_entries(entries, transfer)?;
            let (old_owner_peer_ids, old_layout_digest) =
                canonical_private_oram_shard_layout_digest(
                    collection_id,
                    sharding_method,
                    &pre_entries,
                )?;
            if private_oram_layout_topology_matches(
                expected,
                &old_owner_peer_ids,
                &old_layout_digest,
            ) {
                return Ok(PrivateOramLayoutTransitionState::Applied);
            }
        }
        Err(invalid_private_oram_layout_transition_input())
    }

    pub fn canonical_private_oram_shard_transfer_post_layout_digest(
        collection_id: &str,
        sharding_method: ShardingMethod,
        entries: &[PrivateOramShardLayoutEntry],
        transfer: &ShardTransfer,
    ) -> Result<(Vec<PeerId>, String), StorageError> {
        validate_private_oram_shard_transfer_shape(transfer)?;
        canonical_private_oram_shard_layout_digest(
            collection_id,
            sharding_method,
            &private_oram_transfer_post_entries(entries, transfer)?,
        )
    }

    fn private_oram_transfer_consensus_layout(
        state: &PrivateOramTransferLayoutState,
    ) -> PrivateOramConsensusLayout {
        PrivateOramConsensusLayout {
            generation: state.generation,
            owner_peer_ids: state.owner_peer_ids.clone(),
            layout_digest: state.layout_digest.clone(),
            index_state_digest: state.index_state_digest.clone(),
        }
    }

    fn validate_private_oram_shard_transfer_shape(
        transfer: &ShardTransfer,
    ) -> Result<(), StorageError> {
        if !transfer.private_oram_preinstalled
            || transfer.to_shard_id.is_some()
            || transfer.from == transfer.to
            || transfer.method != Some(ShardTransferMethod::StreamRecords)
            || transfer.filter.is_some()
        {
            return Err(invalid_private_oram_layout_transition_input());
        }
        Ok(())
    }

    fn private_oram_transfer_post_entries(
        entries: &[PrivateOramShardLayoutEntry],
        transfer: &ShardTransfer,
    ) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
        let mut entries = entries.to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.shard_id == transfer.shard_id)
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        if entry.owner_peer_ids.contains(&transfer.to) {
            return Err(invalid_private_oram_layout_transition_input());
        }
        let source_index = entry
            .owner_peer_ids
            .iter()
            .position(|owner| *owner == transfer.from)
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        if !transfer.sync {
            entry.owner_peer_ids.remove(source_index);
        }
        entry.owner_peer_ids.push(transfer.to);
        Ok(entries)
    }

    fn private_oram_transfer_pre_entries(
        entries: &[PrivateOramShardLayoutEntry],
        transfer: &ShardTransfer,
    ) -> Result<Vec<PrivateOramShardLayoutEntry>, StorageError> {
        let mut entries = entries.to_vec();
        let entry = entries
            .iter_mut()
            .find(|entry| entry.shard_id == transfer.shard_id)
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        let target_index = entry
            .owner_peer_ids
            .iter()
            .position(|owner| *owner == transfer.to)
            .ok_or_else(invalid_private_oram_layout_transition_input)?;
        entry.owner_peer_ids.remove(target_index);
        if !transfer.sync {
            if entry.owner_peer_ids.contains(&transfer.from) {
                return Err(invalid_private_oram_layout_transition_input());
            }
            entry.owner_peer_ids.push(transfer.from);
        }
        Ok(entries)
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

    pub fn private_oram_index_keys_for_config(
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
                        "private ORAM consensus index configuration is invalid",
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

    fn private_oram_layout_topology_matches(
        layout: &PrivateOramConsensusLayout,
        owner_peer_ids: &[PeerId],
        layout_digest: &str,
    ) -> bool {
        layout.owner_peer_ids == owner_peer_ids && layout.layout_digest == layout_digest
    }

    fn invalid_private_oram_layout_transition_input() -> StorageError {
        StorageError::bad_request("private ORAM collection layout transition is invalid")
    }

    fn invalid_private_oram_resharding_layout_input() -> StorageError {
        StorageError::bad_request("private ORAM resharding layout transition is invalid")
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
        ApplyPrivateOramCollectionLayout(PrivateOramCollectionLayoutTransition),
        StartPrivateOramShardTransfer(PrivateOramShardTransferStart),
        FinishPrivateOramShardTransfer(PrivateOramShardTransferFinish),
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
            let collection_meta = Box::new(CollectionMetaOperations::TransferShard(
                collection_id,
                ShardTransferOperations::Finish(transfer.clone()),
            ));
            if transfer.private_oram_layout_transition.is_some() {
                ConsensusOperations::FinishPrivateOramShardTransfer(
                    PrivateOramShardTransferFinish { collection_meta },
                )
            } else {
                ConsensusOperations::CollectionMeta(collection_meta)
            }
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
                ConsensusOperations::ApplyPrivateOramCollectionLayout(operation) => f
                    .debug_struct("ApplyPrivateOramCollectionLayout")
                    .field("has_expected", &operation.layout.expected.is_some())
                    .field("new_generation", &operation.layout.new.generation)
                    .field("lease_count", &operation.leases.len())
                    .field("collection_meta", &operation.collection_meta.redacted_log())
                    .finish(),
                ConsensusOperations::StartPrivateOramShardTransfer(operation) => f
                    .debug_struct("StartPrivateOramShardTransfer")
                    .field("lease_count", &operation.leases.len())
                    .field("collection_meta", &operation.collection_meta.redacted_log())
                    .finish(),
                ConsensusOperations::FinishPrivateOramShardTransfer(operation) => f
                    .debug_struct("FinishPrivateOramShardTransfer")
                    .field("collection_meta", &operation.collection_meta.redacted_log())
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

    fn private_oram_layout_transition_state(
        &self,
        transition: &consensus_ops::PrivateOramCollectionLayoutTransition,
    ) -> Result<consensus_ops::PrivateOramLayoutTransitionState, StorageError>;

    fn private_oram_shard_transfer_start_state(
        &self,
        operation: &consensus_ops::PrivateOramShardTransferStart,
    ) -> Result<consensus_ops::PrivateOramLayoutTransitionState, StorageError>;

    fn private_oram_shard_transfer_finish_state(
        &self,
        operation: &consensus_ops::PrivateOramShardTransferFinish,
    ) -> Result<consensus_ops::PrivateOramLayoutTransitionState, StorageError>;

    fn collections_snapshot(&self) -> CollectionsSnapshot;

    fn apply_collections_snapshot(&self, data: CollectionsSnapshot) -> Result<(), StorageError>;

    fn remove_peer(&self, peer_id: PeerId) -> Result<(), StorageError>;

    fn sync_local_state(&self) -> Result<(), StorageError>;
}

#[cfg(test)]
mod test {
    use collection::config::ShardingMethod;
    use collection::operations::cluster_ops::ReshardingDirection;
    use collection::shards::resharding::ReshardKey;
    use collection::shards::transfer::{
        PrivateOramTransferIndexKind, PrivateOramTransferIndexState,
        PrivateOramTransferLayoutState, PrivateOramTransferLayoutTransition, ShardTransfer,
        ShardTransferMethod,
    };
    use data_encoding::BASE64URL_NOPAD;
    use segment::types::ShardKey;
    use serde_json::json;
    use uuid::Uuid;

    use super::collection_meta_ops::CollectionMetaOperations;
    use super::consensus_ops::{
        CompareAndSwapPrivateOramEpoch, CompareAndSwapPrivateOramLayout,
        CompareAndSwapPrivateOramSessionLease, ConsensusOperations,
        PrivateOramCollectionLayoutTransition, PrivateOramConsensusEpoch,
        PrivateOramConsensusLayout, PrivateOramEpochKey, PrivateOramIndexKind,
        PrivateOramLayoutKey, PrivateOramLayoutLeaseBinding, PrivateOramLayoutTransitionState,
        PrivateOramSessionLease, PrivateOramShardLayoutEntry,
        canonical_private_oram_index_state_digest,
        canonical_private_oram_resharding_post_layout_digest,
        canonical_private_oram_shard_layout_digest,
        classify_private_oram_replica_removal_layout_transition,
        classify_private_oram_shard_transfer_layout_transition,
    };

    fn private_oram_shard_transfer_fixture(
        sync: bool,
    ) -> (
        Vec<PrivateOramShardLayoutEntry>,
        Vec<PrivateOramShardLayoutEntry>,
        ShardTransfer,
        PrivateOramConsensusLayout,
        PrivateOramConsensusLayout,
    ) {
        let collection_id = "collection-uuid-1";
        let pre_entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![7, 11],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: None,
                owner_peer_ids: vec![11],
            },
        ];
        let mut post_entries = pre_entries.clone();
        if !sync {
            post_entries[0].owner_peer_ids.retain(|owner| *owner != 7);
        }
        post_entries[0].owner_peer_ids.push(9);
        let (pre_owners, pre_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &pre_entries,
        )
        .unwrap();
        let (post_owners, post_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &post_entries,
        )
        .unwrap();
        let expected = PrivateOramConsensusLayout {
            generation: 4,
            owner_peer_ids: pre_owners,
            layout_digest: pre_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[61; 32]),
        };
        let new = PrivateOramConsensusLayout {
            generation: 5,
            owner_peer_ids: post_owners,
            layout_digest: post_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[62; 32]),
        };
        let transfer = ShardTransfer {
            shard_id: 1,
            to_shard_id: None,
            from: 7,
            to: 9,
            sync,
            method: Some(ShardTransferMethod::StreamRecords),
            private_oram_preinstalled: true,
            private_oram_layout_transition: Some(PrivateOramTransferLayoutTransition {
                collection_id: collection_id.to_string(),
                expected: PrivateOramTransferLayoutState {
                    generation: expected.generation,
                    owner_peer_ids: expected.owner_peer_ids.clone(),
                    layout_digest: expected.layout_digest.clone(),
                    index_state_digest: expected.index_state_digest.clone(),
                },
                new: PrivateOramTransferLayoutState {
                    generation: new.generation,
                    owner_peer_ids: new.owner_peer_ids.clone(),
                    layout_digest: new.layout_digest.clone(),
                    index_state_digest: new.index_state_digest.clone(),
                },
                index_states: vec![PrivateOramTransferIndexState {
                    index_kind: PrivateOramTransferIndexKind::Hnsw,
                    index_name: "text".to_string(),
                    index_epoch: 42,
                    root_hash: BASE64URL_NOPAD.encode(&[63; 32]),
                    writeback_digest: None,
                }],
            }),
            filter: None,
        };
        (pre_entries, post_entries, transfer, expected, new)
    }

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
    fn private_oram_collection_layout_transition_logs_redact_bound_state() {
        let collection_sentinel = "qdrant-sec-layout-transition-collection-sentinel";
        let lease_sentinel = "qdrant-sec-layout-transition-lease-sentinel";
        let operation = ConsensusOperations::ApplyPrivateOramCollectionLayout(
            PrivateOramCollectionLayoutTransition {
                layout: CompareAndSwapPrivateOramLayout {
                    key: PrivateOramLayoutKey {
                        collection_id: collection_sentinel.to_string(),
                    },
                    expected: Some(PrivateOramConsensusLayout {
                        generation: 1,
                        owner_peer_ids: vec![7, 9],
                        layout_digest: BASE64URL_NOPAD.encode(&[51; 32]),
                        index_state_digest: BASE64URL_NOPAD.encode(&[52; 32]),
                    }),
                    new: PrivateOramConsensusLayout {
                        generation: 2,
                        owner_peer_ids: vec![7],
                        layout_digest: BASE64URL_NOPAD.encode(&[53; 32]),
                        index_state_digest: BASE64URL_NOPAD.encode(&[54; 32]),
                    },
                },
                leases: vec![PrivateOramLayoutLeaseBinding {
                    key: PrivateOramEpochKey {
                        collection_id: collection_sentinel.to_string(),
                        index_kind: PrivateOramIndexKind::Hnsw,
                        index_name: "qdrant-sec-layout-transition-index-sentinel".to_string(),
                    },
                    lease: PrivateOramSessionLease {
                        owner_peer_id: 7,
                        lease_id_hash: lease_sentinel.to_string(),
                        issued_at_unix: 100,
                        expires_at_unix: 160,
                    },
                }],
                collection_meta: Box::new(CollectionMetaOperations::Nop { token: 7 }),
            },
        );

        for rendered in [
            format!("{operation:?}"),
            format!("{:?}", operation.redacted_log()),
        ] {
            assert!(rendered.contains("ApplyPrivateOramCollectionLayout"));
            assert!(rendered.contains("new_generation: 2"), "{rendered}");
            assert!(!rendered.contains(collection_sentinel), "{rendered}");
            assert!(!rendered.contains(lease_sentinel), "{rendered}");
            assert!(!rendered.contains("layout-transition-index-sentinel"));
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
    fn private_oram_resharding_post_layout_is_canonical_and_fail_closed() {
        let collection_id = "collection-uuid-1";
        let entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 0,
                shard_key: None,
                owner_peer_ids: vec![7, 11],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![9],
            },
        ];
        let scale_up = ReshardKey {
            uuid: Uuid::from_u128(1),
            direction: ReshardingDirection::Up,
            peer_id: 9,
            shard_id: 2,
            shard_key: None,
        };
        let mut scaled_up_entries = entries.clone();
        scaled_up_entries.push(PrivateOramShardLayoutEntry {
            shard_id: 2,
            shard_key: None,
            owner_peer_ids: vec![9],
        });
        assert_eq!(
            canonical_private_oram_resharding_post_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &entries,
                &scale_up,
            )
            .unwrap(),
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &scaled_up_entries,
            )
            .unwrap(),
        );

        let scale_down = ReshardKey {
            uuid: Uuid::from_u128(2),
            direction: ReshardingDirection::Down,
            peer_id: 9,
            shard_id: 1,
            shard_key: None,
        };
        assert_eq!(
            canonical_private_oram_resharding_post_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &entries,
                &scale_down,
            )
            .unwrap(),
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Auto,
                &entries[..1],
            )
            .unwrap(),
        );

        let custom_key = ShardKey::from("tenant-a");
        let custom_entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 4,
                shard_key: Some(custom_key.clone()),
                owner_peer_ids: vec![7],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 5,
                shard_key: Some(custom_key.clone()),
                owner_peer_ids: vec![9],
            },
        ];
        let custom_scale_down = ReshardKey {
            uuid: Uuid::from_u128(3),
            direction: ReshardingDirection::Down,
            peer_id: 9,
            shard_id: 5,
            shard_key: Some(custom_key),
        };
        assert_eq!(
            canonical_private_oram_resharding_post_layout_digest(
                collection_id,
                ShardingMethod::Custom,
                &custom_entries,
                &custom_scale_down,
            )
            .unwrap(),
            canonical_private_oram_shard_layout_digest(
                collection_id,
                ShardingMethod::Custom,
                &custom_entries[..1],
            )
            .unwrap(),
        );

        let invalid_keys = [
            ReshardKey {
                shard_id: 1,
                ..scale_up.clone()
            },
            ReshardKey {
                peer_id: 13,
                ..scale_down.clone()
            },
            ReshardKey {
                shard_id: 99,
                ..scale_down.clone()
            },
        ];
        for invalid_key in invalid_keys {
            let error = canonical_private_oram_resharding_post_layout_digest(
                "qdrant-sec-resharding-collection-sentinel",
                ShardingMethod::Auto,
                &entries,
                &invalid_key,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("resharding layout transition is invalid"));
            assert!(!error.contains("qdrant-sec-resharding-collection-sentinel"));
        }

        let final_shard = ReshardKey {
            uuid: Uuid::from_u128(4),
            direction: ReshardingDirection::Down,
            peer_id: 7,
            shard_id: 0,
            shard_key: None,
        };
        let error = canonical_private_oram_resharding_post_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &entries[..1],
            &final_shard,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("resharding layout transition is invalid"));
    }

    #[test]
    fn private_oram_replica_removal_layout_classifier_is_replay_safe() {
        let collection_id = "collection-uuid-1";
        let pre_entries = vec![
            PrivateOramShardLayoutEntry {
                shard_id: 1,
                shard_key: None,
                owner_peer_ids: vec![7, 9],
            },
            PrivateOramShardLayoutEntry {
                shard_id: 2,
                shard_key: None,
                owner_peer_ids: vec![7],
            },
        ];
        let mut post_entries = pre_entries.clone();
        post_entries[0].owner_peer_ids.retain(|owner| *owner != 9);
        let (pre_owners, pre_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &pre_entries,
        )
        .unwrap();
        let (post_owners, post_digest) = canonical_private_oram_shard_layout_digest(
            collection_id,
            ShardingMethod::Auto,
            &post_entries,
        )
        .unwrap();
        let expected = PrivateOramConsensusLayout {
            generation: 1,
            owner_peer_ids: pre_owners,
            layout_digest: pre_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[61; 32]),
        };
        let new = PrivateOramConsensusLayout {
            generation: 2,
            owner_peer_ids: post_owners,
            layout_digest: post_digest,
            index_state_digest: BASE64URL_NOPAD.encode(&[62; 32]),
        };

        assert_eq!(
            classify_private_oram_replica_removal_layout_transition(
                collection_id,
                ShardingMethod::Auto,
                &pre_entries,
                1,
                9,
                &expected,
                &new,
            )
            .unwrap(),
            PrivateOramLayoutTransitionState::Pending,
        );
        assert_eq!(
            classify_private_oram_replica_removal_layout_transition(
                collection_id,
                ShardingMethod::Auto,
                &post_entries,
                1,
                9,
                &expected,
                &new,
            )
            .unwrap(),
            PrivateOramLayoutTransitionState::Applied,
        );

        let wrong_new = PrivateOramConsensusLayout {
            layout_digest: BASE64URL_NOPAD.encode(&[63; 32]),
            ..new
        };
        let error = classify_private_oram_replica_removal_layout_transition(
            collection_id,
            ShardingMethod::Auto,
            &pre_entries,
            1,
            9,
            &expected,
            &wrong_new,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("layout transition is invalid"), "{error}");
        assert!(!error.contains(collection_id), "{error}");
        assert!(!error.contains(&wrong_new.layout_digest), "{error}");
    }

    #[test]
    fn private_oram_shard_transfer_layout_classifier_is_replay_safe() {
        let collection_id = "collection-uuid-1";
        for sync in [true, false] {
            let (pre_entries, post_entries, transfer, expected, new) =
                private_oram_shard_transfer_fixture(sync);
            assert_eq!(
                classify_private_oram_shard_transfer_layout_transition(
                    collection_id,
                    ShardingMethod::Auto,
                    &pre_entries,
                    &transfer,
                    &expected,
                    &new,
                )
                .unwrap(),
                PrivateOramLayoutTransitionState::Pending,
            );
            assert_eq!(
                classify_private_oram_shard_transfer_layout_transition(
                    collection_id,
                    ShardingMethod::Auto,
                    &post_entries,
                    &transfer,
                    &expected,
                    &new,
                )
                .unwrap(),
                PrivateOramLayoutTransitionState::Applied,
            );

            let mut malformed = transfer.clone();
            malformed
                .private_oram_layout_transition
                .as_mut()
                .unwrap()
                .collection_id = "qdrant-sec-transfer-collection-sentinel".to_string();
            let error = classify_private_oram_shard_transfer_layout_transition(
                collection_id,
                ShardingMethod::Auto,
                &pre_entries,
                &malformed,
                &expected,
                &new,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("layout transition is invalid"), "{error}");
            assert!(!error.contains("qdrant-sec-transfer-collection-sentinel"));
        }
    }

    #[test]
    fn private_oram_finish_transfer_uses_bound_consensus_operation() {
        let (_, _, transfer, _, _) = private_oram_shard_transfer_fixture(true);
        let root_hash = transfer
            .private_oram_layout_transition
            .as_ref()
            .unwrap()
            .index_states[0]
            .root_hash
            .clone();
        let operation = ConsensusOperations::finish_transfer("docs".to_string(), transfer.clone());
        assert!(matches!(
            operation,
            ConsensusOperations::FinishPrivateOramShardTransfer(_)
        ));
        for rendered in [
            format!("{operation:?}"),
            format!("{:?}", operation.redacted_log()),
        ] {
            assert!(rendered.contains("FinishPrivateOramShardTransfer"));
            assert!(!rendered.contains(&root_hash), "{rendered}");
        }

        let legacy = ShardTransfer {
            private_oram_layout_transition: None,
            ..transfer
        };
        assert!(matches!(
            ConsensusOperations::finish_transfer("docs".to_string(), legacy),
            ConsensusOperations::CollectionMeta(_)
        ));
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
