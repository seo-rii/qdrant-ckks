use std::ops::Deref as _;

use segment::types::ShardKey;

use super::ShardReplicaSet;
use crate::collection::ckks_search::CkksCiphertextSegmentSearchSnapshot;
use crate::operations::types::CollectionResult;
use crate::shards::shard::Shard;

impl ShardReplicaSet {
    pub async fn ckks_ciphertext_segment_search_snapshot(
        &self,
        vector_name: &str,
        shard_key: Option<ShardKey>,
    ) -> CollectionResult<CkksCiphertextSegmentSearchSnapshot> {
        let local = self.local.read().await;
        let Some(local) = local.deref() else {
            return Ok(CkksCiphertextSegmentSearchSnapshot {
                complete: false,
                ..Default::default()
            });
        };
        let Shard::Local(local_shard) = local else {
            return Ok(CkksCiphertextSegmentSearchSnapshot {
                complete: false,
                ..Default::default()
            });
        };

        local_shard.ckks_ciphertext_segment_search_snapshot(vector_name, shard_key)
    }
}
