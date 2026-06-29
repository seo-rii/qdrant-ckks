use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;

use common::counter::hardware_counter::HardwareCounterCell;
use common::types::{DeferredBehavior, PointOffsetType};
use qdrant_sec::{
    ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector,
};
use segment::common::operation_error::OperationError;
use segment::entry::ReadSegmentEntry;
use segment::id_tracker::IdTracker as _;
use segment::index::hnsw_index::ckks_ciphertext_graph::ckks_ciphertext_indexed_record_from_payload;
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
                let segment = locked_segment.get_read().read();
                snapshot.residual_records.extend(
                    ckks_ciphertext_residual_records_from_read_segment(
                        &*segment,
                        vector_name,
                        shard_key.clone(),
                    )?,
                );
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
                let indexed_record = ckks_ciphertext_indexed_record_from_payload(
                    point_offset,
                    &payload,
                    vector_name,
                )
                .map_err(|_err| {
                    CollectionError::service_error(
                        "stored CKKS vector sidecar entry failed validation",
                    )
                })?;
                let Some(indexed_record) = indexed_record else {
                    return Err(CollectionError::service_error(
                        "stored CKKS vector sidecar entry disappeared during validation",
                    ));
                };
                sidecar_by_offset.insert(
                    point_offset,
                    CkksCiphertextSegmentSearchRecord {
                        id,
                        shard_key: shard_key.clone(),
                        point_id: id.to_string(),
                        indexed_record,
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

            if index.graph().is_optimizer_candidate_graph() {
                snapshot
                    .residual_records
                    .extend(sidecar_by_offset.into_values());
                continue;
            }

            let mut records = Vec::new();
            let mut indexed_offsets = HashSet::<PointOffsetType>::new();
            let mut stale_artifact = false;
            for indexed_record in index.records() {
                let Some(record) = sidecar_by_offset.get(&indexed_record.point_offset) else {
                    stale_artifact = true;
                    break;
                };
                if record.indexed_record.sidecar_identity != indexed_record.sidecar_identity {
                    stale_artifact = true;
                    break;
                }
                indexed_offsets.insert(indexed_record.point_offset);
                let mut record = record.clone();
                record.indexed_record = indexed_record.clone();
                records.push(record);
            }

            if stale_artifact {
                snapshot.complete = false;
                snapshot
                    .residual_records
                    .extend(sidecar_by_offset.into_values());
                continue;
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

fn ckks_ciphertext_residual_records_from_read_segment(
    segment: &dyn ReadSegmentEntry,
    vector_name: &str,
    shard_key: Option<ShardKey>,
) -> CollectionResult<Vec<CkksCiphertextSegmentSearchRecord>> {
    let mut records = Vec::new();
    let point_ids = segment
        .read_filtered(
            None,
            None,
            None,
            &AtomicBool::new(false),
            &HardwareCounterCell::disposable(),
            DeferredBehavior::Exclude,
        )
        .map_err(collection_error_from_operation_error)?;
    for id in point_ids {
        let payload = segment
            .payload(id, &HardwareCounterCell::disposable())
            .map_err(collection_error_from_operation_error)?;
        let Some(encrypted) = ckks_encrypted_vector_from_payload(&payload, vector_name)? else {
            continue;
        };
        let Some(indexed_record) = ckks_ciphertext_indexed_record_from_payload(
            0,
            &payload,
            vector_name,
        )
        .map_err(|_err| {
            CollectionError::service_error("stored CKKS vector sidecar entry failed validation")
        })?
        else {
            return Err(CollectionError::service_error(
                "stored CKKS vector sidecar entry disappeared during validation",
            ));
        };
        records.push(CkksCiphertextSegmentSearchRecord {
            id,
            shard_key: shard_key.clone(),
            point_id: id.to_string(),
            indexed_record,
            encrypted,
        });
    }
    Ok(records)
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
        return Err(CollectionError::service_error(
            "stored CKKS vector sidecar entry is malformed",
        ));
    };
    let encrypted = serde_json::from_value(marker.clone()).map_err(|_err| {
        CollectionError::service_error("stored CKKS vector sidecar entry is malformed")
    })?;
    Ok(Some(encrypted))
}

fn collection_error_from_operation_error(err: OperationError) -> CollectionError {
    CollectionError::service_error(err.to_string())
}

#[cfg(test)]
mod tests {
    use common::counter::hardware_counter::HardwareCounterCell;
    use segment::data_types::vectors::{DEFAULT_VECTOR_NAME, only_default_vector};
    use segment::entry::SegmentEntry as _;
    use segment::segment_constructor::simple_segment_constructor::build_simple_segment;
    use segment::types::{Distance, Payload};
    use shard::locked_segment::LockedSegment;
    use shard::proxy_segment::ProxySegment;
    use tempfile::Builder;

    use super::*;

    #[test]
    fn ckks_encrypted_vector_from_payload_error_redacts_sidecar_identifiers() {
        let payload = Payload(
            serde_json::from_value(serde_json::json!({
                ENCRYPTED_VECTOR_SIDECAR_FIELD: {
                    "embedding-sensitive-sentinel": {
                        ENCRYPTED_CKKS_VECTOR_MARKER: {
                            "version": "version-sensitive-sentinel",
                            "scheme": "openfhe-ckks",
                            "envelope": {
                                "version": 1,
                                "algorithm": "AES-256-GCM",
                                "key_id": "tenant-a:vector-sensitive-sentinel",
                                "material_fingerprint": "tenant-a/vector-sensitive-sentinel@v1",
                                "rk_id": "tenant-a/vector-rk-sensitive-sentinel@v1",
                                "rk_epoch": 1,
                                "nonce": "nonce-sensitive-sentinel",
                                "ciphertext": "ciphertext-sensitive-sentinel"
                            }
                        }
                    }
                }
            }))
            .unwrap(),
        );

        let rendered = format!(
            "{:?}",
            ckks_encrypted_vector_from_payload(&payload, "embedding-sensitive-sentinel")
                .expect_err("malformed local shard CKKS sidecar must be rejected")
        );

        assert!(rendered.contains("stored CKKS vector sidecar entry is malformed"));
        for leaked in [
            "embedding-sensitive-sentinel",
            "version-sensitive-sentinel",
            "tenant-a:vector-sensitive-sentinel",
            "tenant-a/vector-sensitive-sentinel@v1",
            "tenant-a/vector-rk-sensitive-sentinel@v1",
            "nonce-sensitive-sentinel",
            "ciphertext-sensitive-sentinel",
        ] {
            assert!(
                !rendered.contains(leaked),
                "local shard CKKS sidecar error leaked {leaked}: {rendered}",
            );
        }
    }

    #[test]
    fn ckks_proxy_segment_visible_sidecars_are_residual_records() {
        let directory = Builder::new()
            .prefix("ckks-proxy-segment")
            .tempdir()
            .unwrap();
        let hw_counter = HardwareCounterCell::new();
        let mut segment = build_simple_segment(directory.path(), 2, Distance::Dot).unwrap();
        segment
            .upsert_point(1, 1.into(), only_default_vector(&[1.0, 0.0]), &hw_counter)
            .unwrap();

        let payload = Payload(
            serde_json::from_value(serde_json::json!({
                ENCRYPTED_VECTOR_SIDECAR_FIELD: {
                    DEFAULT_VECTOR_NAME: {
                        ENCRYPTED_CKKS_VECTOR_MARKER: {
                            "version": 1,
                            "scheme": "openfhe-ckks",
                            "envelope": {
                                "version": 1,
                                "algorithm": "AES-256-GCM",
                                "key_id": "tenant-a:vector",
                                "material_fingerprint": "tenant-a/vector@v1",
                                "rk_id": "tenant-a/vector-rk@v1",
                                "rk_epoch": 1,
                                "nonce": "AAAAAAAAAAAAAAAA",
                                "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
                            }
                        }
                    }
                }
            }))
            .unwrap(),
        );
        segment
            .set_full_payload(2, 1.into(), &payload, &hw_counter)
            .unwrap();

        let proxy = ProxySegment::new(LockedSegment::from(segment));
        let locked_proxy = LockedSegment::from(proxy);
        let proxy = locked_proxy.get_read().read();
        let records =
            ckks_ciphertext_residual_records_from_read_segment(&*proxy, DEFAULT_VECTOR_NAME, None)
                .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, 1.into());
        assert_eq!(records[0].point_id, "1");
        assert_eq!(
            records[0].indexed_record.ciphertext,
            b"AAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(records[0].indexed_record.point_offset, 0);
    }
}
