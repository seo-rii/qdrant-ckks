use itertools::Itertools;
use segment::types::{Payload, PointIdType};
use serde_json::Value;
use shard::operations::payload_ops::{PayloadOps, SetPayloadOp};
use shard::operations::point_ops::{
    BatchPersisted, BatchVectorStructPersisted, ConditionalInsertOperationInternal,
    PointInsertOperationsInternal, PointOperations, PointStructPersisted, PointSyncOperation,
    VectorPersisted, VectorStructPersisted,
};
use shard::operations::vector_ops::{PointVectorsPersisted, UpdateVectorsOp, VectorOperations};
use shard::operations::{CollectionUpdateOperations, FieldIndexOperations};
use sparse::common::sparse_vector::SparseVector;
use sparse::common::types::DimId;

use crate::operations::generalizer::Generalizer;

impl Generalizer for Payload {
    fn remove_details(&self) -> Self {
        let mut stripped_payload = Payload::default();
        stripped_payload.0.insert(
            "keys".to_string(),
            Value::Array(self.keys().cloned().sorted().map(Value::String).collect()),
        );
        stripped_payload
    }
}

impl Generalizer for CollectionUpdateOperations {
    fn remove_details(&self) -> Self {
        match self {
            CollectionUpdateOperations::PointOperation(point_operation) => {
                CollectionUpdateOperations::PointOperation(point_operation.remove_details())
            }
            CollectionUpdateOperations::VectorOperation(vector_operation) => {
                CollectionUpdateOperations::VectorOperation(vector_operation.remove_details())
            }
            CollectionUpdateOperations::PayloadOperation(payload_operation) => {
                CollectionUpdateOperations::PayloadOperation(payload_operation.remove_details())
            }
            CollectionUpdateOperations::FieldIndexOperation(field_operation) => {
                CollectionUpdateOperations::FieldIndexOperation(field_operation.remove_details())
            }
            #[cfg(feature = "staging")]
            CollectionUpdateOperations::StagingOperation(op) => {
                CollectionUpdateOperations::StagingOperation(op.clone())
            }
        }
    }
}

impl Generalizer for PointOperations {
    fn remove_details(&self) -> Self {
        match self {
            PointOperations::UpsertPoints(upsert_operation) => {
                PointOperations::UpsertPoints(upsert_operation.remove_details())
            }
            PointOperations::UpsertPointsConditional(upsert_conditional_operation) => {
                PointOperations::UpsertPointsConditional(
                    upsert_conditional_operation.remove_details(),
                )
            }
            PointOperations::DeletePoints { ids } => {
                PointOperations::DeletePoints { ids: ids.clone() }
            }
            PointOperations::DeletePointsByFilter(filter) => {
                PointOperations::DeletePointsByFilter(filter.remove_details())
            }
            PointOperations::SyncPoints(sync_operation) => {
                PointOperations::SyncPoints(sync_operation.remove_details())
            }
        }
    }
}

impl Generalizer for PointSyncOperation {
    fn remove_details(&self) -> Self {
        let Self {
            from_id,
            to_id,
            points,
        } = self;

        Self {
            from_id: *from_id,
            to_id: *to_id,
            points: points.iter().map(|point| point.remove_details()).collect(),
        }
    }
}

impl Generalizer for PointStructPersisted {
    fn remove_details(&self) -> Self {
        let Self {
            id: _, // ignore actual id for generalization
            vector,
            payload,
        } = self;

        Self {
            id: PointIdType::NumId(0),
            vector: vector.remove_details(),
            payload: payload.as_ref().map(|p| p.remove_details()),
        }
    }
}

impl Generalizer for ConditionalInsertOperationInternal {
    fn remove_details(&self) -> Self {
        let Self {
            points_op,
            condition,
            update_mode,
        } = self;

        Self {
            condition: condition.remove_details(),
            points_op: points_op.remove_details(),
            update_mode: *update_mode,
        }
    }
}

impl Generalizer for PointInsertOperationsInternal {
    fn remove_details(&self) -> Self {
        match self {
            PointInsertOperationsInternal::PointsBatch(batch) => {
                PointInsertOperationsInternal::PointsBatch(batch.remove_details())
            }
            PointInsertOperationsInternal::PointsList(list) => {
                PointInsertOperationsInternal::PointsList(
                    list.iter().map(|point| point.remove_details()).collect(),
                )
            }
        }
    }
}

impl Generalizer for BatchPersisted {
    fn remove_details(&self) -> Self {
        let Self {
            ids: _, // Remove ids for generalization
            vectors,
            payloads,
        } = self;

        let vectors = match vectors {
            BatchVectorStructPersisted::Single(vectors) => BatchVectorStructPersisted::Single(
                vectors.iter().map(|v| vec![v.len() as f32]).collect(),
            ),
            BatchVectorStructPersisted::MultiDense(multi) => {
                BatchVectorStructPersisted::MultiDense(
                    multi
                        .iter()
                        .map(|v| {
                            let dim = if v.is_empty() { 0 } else { v[0].len() };
                            vec![vec![v.len() as f32, dim as f32]]
                        })
                        .collect(),
                )
            }
            BatchVectorStructPersisted::Named(named) => {
                let generalized_named = named
                    .iter()
                    .map(|(name, vectors)| {
                        let generalized_vectors = vectors
                            .iter()
                            .map(|vector| vector.remove_details())
                            .collect();
                        (name.clone(), generalized_vectors)
                    })
                    .collect();
                BatchVectorStructPersisted::Named(generalized_named)
            }
        };

        Self {
            ids: vec![], // Remove ids for generalization
            vectors,
            payloads: payloads.as_ref().map(|pls| {
                pls.iter()
                    .map(|payload| payload.as_ref().map(|pl| pl.remove_details()))
                    .collect()
            }),
        }
    }
}

impl Generalizer for VectorOperations {
    fn remove_details(&self) -> Self {
        match self {
            VectorOperations::UpdateVectors(update_vectors) => {
                VectorOperations::UpdateVectors(update_vectors.remove_details())
            }
            VectorOperations::DeleteVectors(_, _) => self.clone(),
            VectorOperations::DeleteVectorsByFilter(filter, vector_names) => {
                VectorOperations::DeleteVectorsByFilter(
                    filter.remove_details(),
                    vector_names.clone(),
                )
            }
        }
    }
}

impl Generalizer for UpdateVectorsOp {
    fn remove_details(&self) -> Self {
        let UpdateVectorsOp {
            points,
            update_filter,
        } = self;

        Self {
            points: points.iter().map(|point| point.remove_details()).collect(),
            update_filter: update_filter.as_ref().map(|filter| filter.remove_details()),
        }
    }
}

impl Generalizer for PointVectorsPersisted {
    fn remove_details(&self) -> Self {
        let PointVectorsPersisted { id: _, vector } = self;
        Self {
            id: PointIdType::NumId(0),
            vector: vector.remove_details(),
        }
    }
}

impl Generalizer for VectorStructPersisted {
    fn remove_details(&self) -> Self {
        match self {
            VectorStructPersisted::Single(dense) => {
                VectorStructPersisted::Single(vec![dense.len() as f32])
            }
            VectorStructPersisted::MultiDense(multi) => {
                let dim = if multi.is_empty() { 0 } else { multi[0].len() };
                VectorStructPersisted::MultiDense(vec![vec![multi.len() as f32, dim as f32]])
            }
            VectorStructPersisted::Named(named) => {
                let generalized_named = named
                    .iter()
                    .map(|(name, vector)| (name.clone(), vector.remove_details()))
                    .collect();
                VectorStructPersisted::Named(generalized_named)
            }
        }
    }
}

impl Generalizer for VectorPersisted {
    fn remove_details(&self) -> Self {
        match self {
            VectorPersisted::Dense(dense) => VectorPersisted::Dense(vec![dense.len() as f32]),
            VectorPersisted::Sparse(sparse) => {
                VectorPersisted::Sparse(generalized_sparse_vector(sparse.len()))
            }
            VectorPersisted::MultiDense(multi) => {
                let dim = if multi.is_empty() { 0 } else { multi[0].len() };
                VectorPersisted::MultiDense(vec![vec![multi.len() as f32, dim as f32]])
            }
        }
    }
}

fn generalized_sparse_vector(len: usize) -> SparseVector {
    SparseVector {
        indices: vec![len.min(DimId::MAX as usize) as DimId],
        values: vec![0.0],
    }
}

impl Generalizer for PayloadOps {
    fn remove_details(&self) -> Self {
        match self {
            PayloadOps::SetPayload(set_payload) => {
                PayloadOps::SetPayload(set_payload.remove_details())
            }
            PayloadOps::DeletePayload(delete_payload) => {
                let mut delete_payload = delete_payload.clone();
                delete_payload.filter = delete_payload
                    .filter
                    .as_ref()
                    .map(|filter| filter.remove_details());
                PayloadOps::DeletePayload(delete_payload)
            }
            PayloadOps::ClearPayload { points } => PayloadOps::ClearPayload {
                points: points.clone(),
            },
            PayloadOps::ClearPayloadByFilter(filter) => {
                PayloadOps::ClearPayloadByFilter(filter.remove_details())
            }
            PayloadOps::OverwritePayload(overwrite_payload) => {
                PayloadOps::OverwritePayload(overwrite_payload.remove_details())
            }
        }
    }
}

impl Generalizer for SetPayloadOp {
    fn remove_details(&self) -> Self {
        let Self {
            payload,
            points,
            filter,
            key,
        } = self;

        Self {
            payload: payload.remove_details(),
            points: points.clone(),
            filter: filter.as_ref().map(|filter| filter.remove_details()),
            key: key.clone(),
        }
    }
}

impl Generalizer for FieldIndexOperations {
    fn remove_details(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use shard::operations::CollectionUpdateOperations;
    use shard::operations::point_ops::{
        PointInsertOperationsInternal, PointOperations, PointStructPersisted,
    };

    use super::*;

    #[test]
    fn update_operation_generalizer_strips_encrypted_payload_marker_values() {
        let payload = Payload(
            json!({
                "body": {
                    "$qdrant_sec": {
                        "kind": "payload_text",
                        "schema_version": 1,
                        "encryption_epoch": 3,
                        "envelope": {
                            "ciphertext": "server-secret-log-sentinel",
                        },
                    },
                },
                "client_body": {
                    "$qdrant_client_aead": {
                        "ciphertext": "client-secret-log-sentinel",
                        "signature": {
                            "sig": "client-signature-log-sentinel",
                        },
                    },
                },
                "$qdrant_sec_vectors": {
                    "embedding": {
                        "ciphertext": "vector-secret-log-sentinel",
                    },
                },
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let point = PointStructPersisted {
            id: 42.into(),
            vector: VectorStructPersisted::Single(vec![0.1, 0.2, 0.3]),
            payload: Some(payload),
        };
        let operation = CollectionUpdateOperations::PointOperation(PointOperations::UpsertPoints(
            PointInsertOperationsInternal::PointsList(vec![point]),
        ));

        let loggable_operation = operation.remove_details();
        let serialized = serde_json::to_string(&loggable_operation).unwrap();

        assert!(!serialized.contains("server-secret-log-sentinel"));
        assert!(!serialized.contains("client-secret-log-sentinel"));
        assert!(!serialized.contains("client-signature-log-sentinel"));
        assert!(!serialized.contains("vector-secret-log-sentinel"));
        assert!(serialized.contains("body"));
        assert!(serialized.contains("client_body"));
        assert!(serialized.contains("$qdrant_sec_vectors"));
    }
}
