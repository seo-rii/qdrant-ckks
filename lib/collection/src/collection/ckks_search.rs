use qdrant_sec::EncryptedCkksVector;
use segment::index::hnsw_index::ckks_ciphertext_graph::{
    CkksCiphertextHnswGraph, CkksCiphertextIndexedRecord,
};
use segment::types::{PointIdType, ShardKey};

use super::Collection;
use crate::operations::shard_selector_internal::ShardSelectorInternal;
use crate::operations::types::CollectionResult;

#[derive(Clone)]
pub struct CkksCiphertextSegmentSearchRecord {
    pub id: PointIdType,
    pub shard_key: Option<ShardKey>,
    pub point_id: String,
    pub indexed_record: CkksCiphertextIndexedRecord,
    pub encrypted: EncryptedCkksVector,
}

impl std::fmt::Debug for CkksCiphertextSegmentSearchRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksCiphertextSegmentSearchRecord")
            .field("id", &"[redacted]")
            .field("shard_key_present", &self.shard_key.is_some())
            .field("point_id", &"[redacted]")
            .field("indexed_record", &self.indexed_record)
            .field("encrypted", &self.encrypted)
            .finish()
    }
}

#[derive(Clone)]
pub struct CkksCiphertextSegmentIndexSnapshot {
    pub records: Vec<CkksCiphertextSegmentSearchRecord>,
    pub graph: CkksCiphertextHnswGraph,
}

impl std::fmt::Debug for CkksCiphertextSegmentIndexSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksCiphertextSegmentIndexSnapshot")
            .field("record_count", &"[redacted]")
            .field("graph", &self.graph)
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct CkksCiphertextSegmentSearchSnapshot {
    pub indexed_segments: Vec<CkksCiphertextSegmentIndexSnapshot>,
    pub residual_records: Vec<CkksCiphertextSegmentSearchRecord>,
    pub complete: bool,
}

impl std::fmt::Debug for CkksCiphertextSegmentSearchSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkksCiphertextSegmentSearchSnapshot")
            .field("indexed_segment_count", &"[redacted]")
            .field("residual_record_count", &"[redacted]")
            .field("complete", &self.complete)
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_vector() -> EncryptedCkksVector {
        EncryptedCkksVector {
            version: 1,
            scheme: qdrant_sec::CKKS_SCHEME.to_string(),
            envelope: qdrant_sec::EncryptedEnvelope {
                version: 1,
                algorithm: "AES-256-GCM".to_string(),
                key_id: "COLLECTION-CKKS-KEY-SENTINEL".to_string(),
                material_fingerprint: "COLLECTION-CKKS-MATERIAL-SENTINEL".to_string(),
                rk_id: "COLLECTION-CKKS-RK-SENTINEL".to_string(),
                rk_epoch: Some(7),
                nonce: "COLLECTION-CKKS-NONCE-SENTINEL".to_string(),
                ciphertext: "COLLECTION-CKKS-CIPHERTEXT-SENTINEL".to_string(),
            },
        }
    }

    #[test]
    fn ckks_segment_snapshot_debug_redacts_ids_and_ciphertext_values() {
        let record = CkksCiphertextSegmentSearchRecord {
            id: PointIdType::NumId(77),
            shard_key: Some(ShardKey::from("COLLECTION-CKKS-SHARD-SENTINEL".to_string())),
            point_id: "COLLECTION-CKKS-POINT-SENTINEL".to_string(),
            indexed_record: CkksCiphertextIndexedRecord::new(
                88,
                b"COLLECTION-CKKS-INDEXED-CIPHERTEXT-SENTINEL".to_vec(),
            ),
            encrypted: encrypted_vector(),
        };
        let graph = CkksCiphertextHnswGraph::from_validated_links(vec![vec![1], vec![0]])
            .expect("test graph must be valid");
        let index_snapshot = CkksCiphertextSegmentIndexSnapshot {
            records: vec![record.clone(), record.clone()],
            graph,
        };
        let search_snapshot = CkksCiphertextSegmentSearchSnapshot {
            indexed_segments: vec![index_snapshot.clone()],
            residual_records: vec![record.clone()],
            complete: true,
        };

        for rendered in [
            format!("{record:?}"),
            format!("{index_snapshot:?}"),
            format!("{search_snapshot:?}"),
        ] {
            assert!(rendered.contains("[redacted]"), "{rendered}");
            assert!(
                !rendered.contains("COLLECTION-CKKS-SHARD-SENTINEL"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("COLLECTION-CKKS-POINT-SENTINEL"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("COLLECTION-CKKS-KEY-SENTINEL"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("COLLECTION-CKKS-MATERIAL-SENTINEL"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("COLLECTION-CKKS-RK-SENTINEL"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("COLLECTION-CKKS-NONCE-SENTINEL"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("COLLECTION-CKKS-CIPHERTEXT-SENTINEL"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("COLLECTION-CKKS-INDEXED-CIPHERTEXT-SENTINEL"),
                "{rendered}"
            );
            assert!(!rendered.contains("NumId(77)"), "{rendered}");
            assert!(!rendered.contains("point_offset: 88"), "{rendered}");
            assert!(!rendered.contains("record_count: 2"), "{rendered}");
        }
    }
}
