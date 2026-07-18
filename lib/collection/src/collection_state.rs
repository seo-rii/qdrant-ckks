use std::collections::{HashMap, HashSet};

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

use crate::collection::payload_index_schema::PayloadIndexSchema;
use crate::config::CollectionConfigInternal;
use crate::shards::replica_set::replica_set_state::ReplicaState;
use crate::shards::resharding::ReshardState;
use crate::shards::shard::{PeerId, ShardId};
use crate::shards::shard_holder::shard_mapping::ShardKeyMapping;
use crate::shards::transfer::ShardTransfer;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ShardInfo {
    pub replicas: HashMap<PeerId, ReplicaState>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct State {
    pub config: CollectionConfigInternal,
    pub shards: AHashMap<ShardId, ShardInfo>,
    pub resharding: Option<ReshardState>,
    #[serde(default)]
    pub transfers: HashSet<ShardTransfer>,
    #[serde(default)]
    pub shards_key_mapping: ShardKeyMapping,
    #[serde(default)]
    pub payload_index_schema: PayloadIndexSchema,
}

impl State {
    pub fn max_shard_id(&self) -> ShardId {
        self.shards_key_mapping.iter_shard_ids().max().unwrap_or(0)
    }

    pub fn private_oram_replica_removal_preserves_fully_active_layout(
        &self,
        shard_id: ShardId,
        peer_id: PeerId,
        coordinator_peer_id: Option<PeerId>,
    ) -> bool {
        private_oram_replica_removal_preserves_fully_active_layout(
            &self.shards,
            self.resharding.is_some(),
            !self.transfers.is_empty(),
            shard_id,
            peer_id,
            coordinator_peer_id,
        )
    }
}

fn private_oram_replica_removal_preserves_fully_active_layout(
    shards: &AHashMap<ShardId, ShardInfo>,
    has_resharding: bool,
    has_transfers: bool,
    shard_id: ShardId,
    peer_id: PeerId,
    coordinator_peer_id: Option<PeerId>,
) -> bool {
    if shards.is_empty()
        || has_resharding
        || has_transfers
        || shards.values().any(|shard| {
            shard.replicas.is_empty()
                || shard
                    .replicas
                    .values()
                    .any(|state| *state != ReplicaState::Active)
        })
    {
        return false;
    }

    let Some(target_shard) = shards.get(&shard_id) else {
        return false;
    };
    if !target_shard.replicas.contains_key(&peer_id) || target_shard.replicas.len() <= 1 {
        return false;
    }

    coordinator_peer_id.is_none_or(|coordinator_peer_id| {
        shards.iter().any(|(candidate_shard_id, shard)| {
            shard.replicas.keys().any(|candidate_peer_id| {
                *candidate_peer_id == coordinator_peer_id
                    && !(*candidate_shard_id == shard_id && *candidate_peer_id == peer_id)
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_shards() -> AHashMap<ShardId, ShardInfo> {
        AHashMap::from([
            (
                1,
                ShardInfo {
                    replicas: HashMap::from([(7, ReplicaState::Active), (9, ReplicaState::Active)]),
                },
            ),
            (
                2,
                ShardInfo {
                    replicas: HashMap::from([(7, ReplicaState::Active)]),
                },
            ),
        ])
    }

    #[test]
    fn private_oram_replica_removal_preserves_only_fully_active_owner_layout() {
        let shards = active_shards();
        assert!(private_oram_replica_removal_preserves_fully_active_layout(
            &shards,
            false,
            false,
            1,
            9,
            Some(7),
        ));
        assert!(!private_oram_replica_removal_preserves_fully_active_layout(
            &shards,
            false,
            false,
            1,
            9,
            Some(9),
        ));

        let mut transitioning = shards.clone();
        transitioning
            .get_mut(&1)
            .unwrap()
            .replicas
            .insert(9, ReplicaState::Dead);
        for (candidate, has_resharding, has_transfers, shard_id, peer_id) in [
            (transitioning, false, false, 1, 9),
            (shards.clone(), true, false, 1, 9),
            (shards.clone(), false, true, 1, 9),
            (shards.clone(), false, false, 2, 7),
            (shards.clone(), false, false, 3, 9),
            (shards, false, false, 1, 11),
        ] {
            assert!(!private_oram_replica_removal_preserves_fully_active_layout(
                &candidate,
                has_resharding,
                has_transfers,
                shard_id,
                peer_id,
                Some(7),
            ));
        }
    }
}
