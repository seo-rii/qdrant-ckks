use std::fmt;

use common::counter::hardware_counter::HardwareCounterCell;
use segment::common::operation_error::{OperationError, OperationResult};
use segment::json_path::JsonPath;
use segment::types::Payload;
use serde_json::Value;
use shard::operations::payload_ops::PayloadOps;
use shard::operations::point_ops::{
    ConditionalInsertOperationInternal, PointInsertOperationsInternal, PointOperations,
};
use shard::operations::{CollectionUpdateOperations, FieldIndexOperations};
use shard::update::*;
use shard::wal::WalRawRecord;

use crate::EdgeShard;

const SERVER_PAYLOAD_MARKER: &str = "$qdrant_sec";
const CLIENT_PAYLOAD_MARKER: &str = "$qdrant_client_aead";
const VECTOR_SIDECAR_FIELD: &str = "$qdrant_sec_vectors";

impl EdgeShard {
    pub fn update(&self, operation: CollectionUpdateOperations) -> OperationResult<()> {
        reject_qdrant_sec_payload_material(&operation)?;

        let record = WalRawRecord::new(&operation).map_err(service_error)?;

        let mut wal = self.wal.lock();

        let operation_id = wal.write(&record).map_err(service_error)?;
        let hw_counter = HardwareCounterCell::disposable();
        let _update_guard = self.segments.acquire_updates_lock();

        let segments_guard = self.segments.read();

        let result = match operation {
            CollectionUpdateOperations::PointOperation(point_operation) => {
                process_point_operation(&segments_guard, operation_id, point_operation, &hw_counter)
            }
            CollectionUpdateOperations::VectorOperation(vector_operation) => {
                process_vector_operation(
                    &segments_guard,
                    operation_id,
                    vector_operation,
                    &hw_counter,
                )
            }
            CollectionUpdateOperations::PayloadOperation(payload_operation) => {
                process_payload_operation(
                    &segments_guard,
                    operation_id,
                    payload_operation,
                    &hw_counter,
                )
            }
            CollectionUpdateOperations::FieldIndexOperation(index_operation) => {
                process_field_index_operation(
                    &segments_guard,
                    operation_id,
                    &index_operation,
                    &hw_counter,
                )
            }
            #[cfg(feature = "staging")]
            CollectionUpdateOperations::StagingOperation(staging_operation) => {
                shard::update::process_staging_operation(
                    &segments_guard,
                    operation_id,
                    staging_operation,
                )
            }
        };

        result.map(|_| ())
    }
}

fn service_error(err: impl fmt::Display) -> OperationError {
    OperationError::service_error(err.to_string())
}

fn reject_qdrant_sec_payload_material(
    operation: &CollectionUpdateOperations,
) -> OperationResult<()> {
    match operation {
        CollectionUpdateOperations::PointOperation(operation) => match operation {
            PointOperations::UpsertPoints(points)
            | PointOperations::UpsertPointsConditional(ConditionalInsertOperationInternal {
                points_op: points,
                ..
            }) => reject_point_insert_payload_markers(points)?,
            PointOperations::SyncPoints(operation) => {
                for point in &operation.points {
                    if let Some(payload) = &point.payload {
                        reject_payload_markers(payload)?;
                    }
                }
            }
            PointOperations::DeletePoints { .. } | PointOperations::DeletePointsByFilter(_) => {}
        },
        CollectionUpdateOperations::PayloadOperation(operation) => match operation {
            PayloadOps::SetPayload(operation) | PayloadOps::OverwritePayload(operation) => {
                reject_payload_markers(&operation.payload)?;
                if operation
                    .key
                    .as_ref()
                    .is_some_and(json_path_contains_qdrant_sec_marker)
                {
                    return Err(edge_crypto_unsupported_error());
                }
            }
            PayloadOps::DeletePayload(operation) => {
                if operation
                    .keys
                    .iter()
                    .any(json_path_contains_qdrant_sec_marker)
                {
                    return Err(edge_crypto_unsupported_error());
                }
            }
            PayloadOps::ClearPayload { .. } | PayloadOps::ClearPayloadByFilter(_) => {}
        },
        CollectionUpdateOperations::FieldIndexOperation(operation) => match operation {
            FieldIndexOperations::CreateIndex(operation) => {
                if json_path_contains_qdrant_sec_marker(&operation.field_name) {
                    return Err(edge_crypto_unsupported_error());
                }
            }
            FieldIndexOperations::DeleteIndex(path) => {
                if json_path_contains_qdrant_sec_marker(path) {
                    return Err(edge_crypto_unsupported_error());
                }
            }
        },
        CollectionUpdateOperations::VectorOperation(_) => {}
        #[cfg(feature = "staging")]
        CollectionUpdateOperations::StagingOperation(_) => {}
    }

    Ok(())
}

fn reject_point_insert_payload_markers(
    operation: &PointInsertOperationsInternal,
) -> OperationResult<()> {
    match operation {
        PointInsertOperationsInternal::PointsBatch(batch) => {
            if let Some(payloads) = &batch.payloads {
                for payload in payloads.iter().flatten() {
                    reject_payload_markers(payload)?;
                }
            }
        }
        PointInsertOperationsInternal::PointsList(points) => {
            for point in points {
                if let Some(payload) = &point.payload {
                    reject_payload_markers(payload)?;
                }
            }
        }
    }

    Ok(())
}

fn reject_payload_markers(payload: &Payload) -> OperationResult<()> {
    if payload.0.iter().any(|(key, value)| {
        is_qdrant_sec_payload_key(key) || value_contains_qdrant_sec_marker(value)
    }) {
        return Err(edge_crypto_unsupported_error());
    }

    Ok(())
}

fn value_contains_qdrant_sec_marker(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            is_qdrant_sec_payload_key(key) || value_contains_qdrant_sec_marker(value)
        }),
        Value::Array(values) => values.iter().any(value_contains_qdrant_sec_marker),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn is_qdrant_sec_payload_key(key: &str) -> bool {
    matches!(
        key,
        SERVER_PAYLOAD_MARKER | CLIENT_PAYLOAD_MARKER | VECTOR_SIDECAR_FIELD
    )
}

fn json_path_contains_qdrant_sec_marker(path: &JsonPath) -> bool {
    let path = path.to_string();
    [
        SERVER_PAYLOAD_MARKER,
        CLIENT_PAYLOAD_MARKER,
        VECTOR_SIDECAR_FIELD,
    ]
    .iter()
    .any(|marker| path.contains(marker))
}

fn edge_crypto_unsupported_error() -> OperationError {
    OperationError::validation_error(
        "edge shards do not support qdrant-sec encrypted payload markers or vector sidecars",
    )
}

#[cfg(test)]
mod tests {
    use segment::types::{ExtendedPointId, Payload};
    use serde_json::json;
    use shard::operations::CollectionUpdateOperations;
    use shard::operations::payload_ops::{PayloadOps, SetPayloadOp};
    use shard::operations::point_ops::{
        PointInsertOperationsInternal, PointOperations, PointStructPersisted, VectorStructPersisted,
    };

    use super::{CLIENT_PAYLOAD_MARKER, VECTOR_SIDECAR_FIELD, reject_qdrant_sec_payload_material};

    fn payload(value: serde_json::Value) -> Payload {
        let serde_json::Value::Object(map) = value else {
            panic!("payload fixture must be an object");
        };
        Payload(map.into_iter().collect())
    }

    #[test]
    fn edge_update_rejects_client_envelope_marker_before_wal() {
        let operation = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::PointsList(vec![PointStructPersisted {
                id: ExtendedPointId::NumId(1),
                vector: VectorStructPersisted::Single(vec![1.0]),
                payload: Some(payload(json!({
                    "body": {
                        CLIENT_PAYLOAD_MARKER: {
                            "version": 1,
                            "ciphertext": "opaque-client-ciphertext"
                        }
                    }
                }))),
            }]),
        ));

        let err = reject_qdrant_sec_payload_material(&operation)
            .expect_err("edge must reject client encrypted payload markers before WAL write");

        assert!(
            err.to_string()
                .contains("edge shards do not support qdrant-sec encrypted payload markers")
        );
    }

    #[test]
    fn edge_update_rejects_vector_sidecar_payload_path_before_wal() {
        let operation =
            CollectionUpdateOperations::PayloadOperation(PayloadOps::SetPayload(SetPayloadOp {
                payload: Payload(Default::default()),
                points: Some(vec![ExtendedPointId::NumId(1)]),
                filter: None,
                key: Some(format!("\"{VECTOR_SIDECAR_FIELD}\"").parse().unwrap()),
            }));

        let err = reject_qdrant_sec_payload_material(&operation).expect_err(
            "edge must reject qdrant-sec vector sidecar payload paths before WAL write",
        );

        assert!(
            err.to_string()
                .contains("edge shards do not support qdrant-sec encrypted payload markers")
        );
    }
}
