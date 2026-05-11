use std::collections::{HashMap, HashSet};

use common::counter::hardware_counter::HardwareCounterCell;
use common::types::PointOffsetType;
use qdrant_sec::{
    ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector,
};
use segment::common::operation_error::OperationError;
use segment::id_tracker::IdTracker as _;
use segment::index::hnsw_index::ckks_ciphertext_graph::CkksCiphertextIndexedRecord;
use segment::index::{PayloadIndex as _, VectorIndexEnum};
use segment::types::{Payload, ShardKey};
use shard::locked_segment::LockedSegment;

use super::LocalShard;
use crate::collection::ckks_search::{
    CkksCiphertextSegmentIndexSnapshot, CkksCiphertextSegmentSearchRecord,
    CkksCiphertextSegmentSearchSnapshot,
};
use crate::operations::types::{CollectionError, CollectionResult};

impl LocalShard {
    pub(crate) fn ckks_ciphertext_segment_search_snapshot(
        &self,
        vector_name: &str,
        shard_key: Option<ShardKey>,
    ) -> CollectionResult<CkksCiphertextSegmentSearchSnapshot> {
        let segments = self
            .segments
            .read()
            .non_appendable_then_appendable_segments()
            .collect::<Vec<_>>();
        let mut snapshot = CkksCiphertextSegmentSearchSnapshot {
            indexed_segments: Vec::new(),
            residual_records: Vec::new(),
            complete: true,
        };

        for locked_segment in segments {
            let LockedSegment::Original(segment) = locked_segment else {
                continue;
            };
            let segment = segment.read();
            let id_tracker = segment.id_tracker.borrow();
            let payload_index = segment.payload_index.borrow();
            let mut sidecar_by_offset =
                HashMap::<PointOffsetType, CkksCiphertextSegmentSearchRecord>::new();
            for point_offset in id_tracker.point_mappings().iter_internal() {
                let Some(id) = id_tracker.external_id(point_offset) else {
                    continue;
                };
                let payload = payload_index
                    .get_payload_sequential(point_offset, &HardwareCounterCell::disposable())
                    .map_err(collection_error_from_operation_error)?;
                let Some(encrypted) = ckks_encrypted_vector_from_payload(&payload, vector_name)?
                else {
                    continue;
                };
                sidecar_by_offset.insert(
                    point_offset,
                    CkksCiphertextSegmentSearchRecord {
                        id,
                        shard_key: shard_key.clone(),
                        point_id: id.to_string(),
                        indexed_record: CkksCiphertextIndexedRecord::new(
                            point_offset,
                            encrypted.envelope.ciphertext.as_bytes().to_vec(),
                        ),
                        encrypted,
                    },
                );
            }

            let Some(vector_data) = segment.vector_data.get(vector_name) else {
                snapshot
                    .residual_records
                    .extend(sidecar_by_offset.into_values());
                continue;
            };
            let vector_index = vector_data.vector_index.borrow();
            let VectorIndexEnum::CkksCiphertextHnsw(index) = &*vector_index else {
                snapshot
                    .residual_records
                    .extend(sidecar_by_offset.into_values());
                continue;
            };

            let mut records = Vec::new();
            let mut indexed_offsets = HashSet::<PointOffsetType>::new();
            for indexed_record in index.records() {
                let Some(record) = sidecar_by_offset.get(&indexed_record.point_offset) else {
                    return Err(CollectionError::service_error(format!(
                        "CKKS ciphertext HNSW index for vector '{vector_name}' references point offset {} without encrypted vector sidecar",
                        indexed_record.point_offset,
                    )));
                };
                if record.encrypted.envelope.ciphertext.as_bytes() != indexed_record.ciphertext {
                    return Err(CollectionError::service_error(format!(
                        "CKKS ciphertext HNSW index for vector '{vector_name}' references stale ciphertext for point {}",
                        record.id,
                    )));
                }
                indexed_offsets.insert(indexed_record.point_offset);
                let mut record = record.clone();
                record.indexed_record = indexed_record.clone();
                records.push(record);
            }

            if !records.is_empty() {
                snapshot
                    .indexed_segments
                    .push(CkksCiphertextSegmentIndexSnapshot {
                        records,
                        graph: index.graph().clone(),
                    });
            }

            snapshot
                .residual_records
                .extend(
                    sidecar_by_offset
                        .into_iter()
                        .filter_map(|(point_offset, record)| {
                            (!indexed_offsets.contains(&point_offset)).then_some(record)
                        }),
                );
        }

        Ok(snapshot)
    }
}

fn ckks_encrypted_vector_from_payload(
    payload: &Payload,
    vector_name: &str,
) -> CollectionResult<Option<EncryptedCkksVector>> {
    let Some(sidecar) = payload
        .0
        .get(ENCRYPTED_VECTOR_SIDECAR_FIELD)
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let Some(value) = sidecar.get(vector_name) else {
        return Ok(None);
    };
    let Some(marker) = value
        .as_object()
        .and_then(|object| object.get(ENCRYPTED_CKKS_VECTOR_MARKER))
    else {
        return Err(CollectionError::service_error(format!(
            "stored CKKS vector sidecar entry '{vector_name}' is malformed",
        )));
    };
    let encrypted = serde_json::from_value(marker.clone()).map_err(|err| {
        CollectionError::service_error(format!(
            "stored CKKS vector sidecar entry '{vector_name}' is malformed: {err}",
        ))
    })?;
    Ok(Some(encrypted))
}

fn collection_error_from_operation_error(err: OperationError) -> CollectionError {
    CollectionError::service_error(err.to_string())
}
