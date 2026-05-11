use qdrant_sec::EncryptedCkksVector;
use segment::index::hnsw_index::ckks_ciphertext_graph::{
    CkksCiphertextHnswGraph, CkksCiphertextIndexedRecord,
};
use segment::types::{PointIdType, ShardKey};

use super::Collection;
use crate::operations::shard_selector_internal::ShardSelectorInternal;
use crate::operations::types::CollectionResult;

#[derive(Clone, Debug)]
pub struct CkksCiphertextSegmentSearchRecord {
    pub id: PointIdType,
    pub shard_key: Option<ShardKey>,
    pub point_id: String,
    pub indexed_record: CkksCiphertextIndexedRecord,
    pub encrypted: EncryptedCkksVector,
}

#[derive(Clone, Debug)]
pub struct CkksCiphertextSegmentIndexSnapshot {
    pub records: Vec<CkksCiphertextSegmentSearchRecord>,
    pub graph: CkksCiphertextHnswGraph,
}

impl Collection {
    pub async fn ckks_ciphertext_hnsw_index_snapshots(
        &self,
        vector_name: &str,
        shard_selection: &ShardSelectorInternal,
    ) -> CollectionResult<Vec<CkksCiphertextSegmentIndexSnapshot>> {
        let shard_holder = self.shards_holder.read().await;
        let target_shards = shard_holder.select_shards(shard_selection)?;
        let mut snapshots = Vec::new();

        for (replica_set, shard_key) in target_shards {
            snapshots.extend(
                replica_set
                    .ckks_ciphertext_hnsw_index_snapshots(vector_name, shard_key.cloned())
                    .await?,
            );
        }

        Ok(snapshots)
    }
}
