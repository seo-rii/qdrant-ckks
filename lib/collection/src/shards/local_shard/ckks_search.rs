use common::counter::hardware_counter::HardwareCounterCell;
use qdrant_sec::{
    ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector,
};
use segment::common::operation_error::OperationError;
use segment::id_tracker::IdTracker as _;
use segment::index::{PayloadIndex as _, VectorIndexEnum};
use segment::types::{Payload, ShardKey};
use shard::locked_segment::LockedSegment;

use super::LocalShard;
use crate::collection::ckks_search::{
    CkksCiphertextSegmentIndexSnapshot, CkksCiphertextSegmentSearchRecord,
};
use crate::operations::types::{CollectionError, CollectionResult};

impl LocalShard {
    pub(crate) fn ckks_ciphertext_hnsw_index_snapshots(
        &self,
        vector_name: &str,
        shard_key: Option<ShardKey>,
    ) -> CollectionResult<Vec<CkksCiphertextSegmentIndexSnapshot>> {
        let segments = self
            .segments
            .read()
            .non_appendable_then_appendable_segments()
            .collect::<Vec<_>>();
        let mut snapshots = Vec::new();

        for locked_segment in segments {
            let LockedSegment::Original(segment) = locked_segment else {
                continue;
            };
            let segment = segment.read();
            let Some(vector_data) = segment.vector_data.get(vector_name) else {
                continue;
            };
            let vector_index = vector_data.vector_index.borrow();
            let VectorIndexEnum::CkksCiphertextHnsw(index) = &*vector_index else {
                continue;
            };

            let id_tracker = segment.id_tracker.borrow();
            let payload_index = segment.payload_index.borrow();
            let mut records = Vec::new();
            for indexed_record in index.records() {
                let Some(id) = id_tracker.external_id(indexed_record.point_offset) else {
                    continue;
                };
                let payload = payload_index
                    .get_payload_sequential(
                        indexed_record.point_offset,
                        &HardwareCounterCell::disposable(),
                    )
                    .map_err(collection_error_from_operation_error)?;
                let encrypted = ckks_encrypted_vector_from_payload(&payload, vector_name)?;
                let Some(encrypted) = encrypted else {
                    return Err(CollectionError::service_error(format!(
                        "CKKS ciphertext HNSW index for vector '{vector_name}' references point {id} without encrypted vector sidecar",
                    )));
                };
                if encrypted.envelope.ciphertext.as_bytes() != indexed_record.ciphertext {
                    return Err(CollectionError::service_error(format!(
                        "CKKS ciphertext HNSW index for vector '{vector_name}' references stale ciphertext for point {id}",
                    )));
                }
                records.push(CkksCiphertextSegmentSearchRecord {
                    id,
                    shard_key: shard_key.clone(),
                    point_id: id.to_string(),
                    indexed_record: indexed_record.clone(),
                    encrypted,
                });
            }

            if !records.is_empty() {
                snapshots.push(CkksCiphertextSegmentIndexSnapshot {
                    records,
                    graph: index.graph().clone(),
                });
            }
        }

        Ok(snapshots)
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
