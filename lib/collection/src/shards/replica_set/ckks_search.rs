use std::ops::Deref as _;

use segment::types::ShardKey;

use super::ShardReplicaSet;
use crate::collection::ckks_search::CkksCiphertextSegmentIndexSnapshot;
use crate::operations::types::CollectionResult;
use crate::shards::shard::Shard;

impl ShardReplicaSet {
    pub async fn ckks_ciphertext_hnsw_index_snapshots(
        &self,
        vector_name: &str,
        shard_key: Option<ShardKey>,
    ) -> CollectionResult<Vec<CkksCiphertextSegmentIndexSnapshot>> {
        let local = self.local.read().await;
        let Some(local) = local.deref() else {
            return Ok(Vec::new());
        };
        let Shard::Local(local_shard) = local else {
            return Ok(Vec::new());
        };

        local_shard.ckks_ciphertext_hnsw_index_snapshots(vector_name, shard_key)
    }
}
