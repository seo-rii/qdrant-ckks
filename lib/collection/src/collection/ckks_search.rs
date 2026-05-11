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

#[derive(Clone, Debug, Default)]
pub struct CkksCiphertextSegmentSearchSnapshot {
    pub indexed_segments: Vec<CkksCiphertextSegmentIndexSnapshot>,
    pub residual_records: Vec<CkksCiphertextSegmentSearchRecord>,
    pub complete: bool,
}

impl Collection {
    pub async fn ckks_ciphertext_segment_search_snapshot(
        &self,
        vector_name: &str,
        shard_selection: &ShardSelectorInternal,
    ) -> CollectionResult<CkksCiphertextSegmentSearchSnapshot> {
        let shard_holder = self.shards_holder.read().await;
        let target_shards = shard_holder.select_shards(shard_selection)?;
        let mut snapshot = CkksCiphertextSegmentSearchSnapshot {
            indexed_segments: Vec::new(),
            residual_records: Vec::new(),
            complete: true,
        };

        for (replica_set, shard_key) in target_shards {
            let shard_snapshot = replica_set
                .ckks_ciphertext_segment_search_snapshot(vector_name, shard_key.cloned())
                .await?;
            snapshot
                .indexed_segments
                .extend(shard_snapshot.indexed_segments);
            snapshot
                .residual_records
                .extend(shard_snapshot.residual_records);
            snapshot.complete &= shard_snapshot.complete;
        }

        Ok(snapshot)
    }
}
