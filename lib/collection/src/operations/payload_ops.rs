pub use shard::operations::payload_ops::*;

use super::{OperationToShard, SplitByShard, split_iter_by_shard};
use crate::hash_ring::HashRingRouter;

impl SplitByShard for PayloadOps {
    fn split_by_shard(self, ring: &HashRingRouter) -> OperationToShard<Self> {
        match self {
            PayloadOps::SetPayload(operation) => {
                operation.split_by_shard(ring).map(PayloadOps::SetPayload)
            }
            PayloadOps::DeletePayload(operation) => operation
                .split_by_shard(ring)
                .map(PayloadOps::DeletePayload),
            PayloadOps::ClearPayload { points } => split_iter_by_shard(points, |id| *id, ring)
                .map(|points| PayloadOps::ClearPayload { points }),
            operation @ PayloadOps::ClearPayloadByFilter(_) => OperationToShard::to_all(operation),
            PayloadOps::OverwritePayload(operation) => operation
                .split_by_shard(ring)
                .map(PayloadOps::OverwritePayload),
        }
    }
}

impl SplitByShard for DeletePayloadOp {
    fn split_by_shard(self, ring: &HashRingRouter) -> OperationToShard<Self> {
        let DeletePayloadOp {
            points,
            keys,
            filter,
        } = self;
        match (points, filter) {
            (Some(points), filter) => {
                split_iter_by_shard(points, |id| *id, ring).map(|points| DeletePayloadOp {
                    points: Some(points),
                    keys: keys.clone(),
                    filter: filter.clone(),
                })
            }
            (None, Some(filter)) => OperationToShard::to_all(DeletePayloadOp {
                points: None,
                keys,
                filter: Some(filter),
            }),
            (None, None) => OperationToShard::to_none(),
        }
    }
}

impl SplitByShard for SetPayloadOp {
    fn split_by_shard(self, ring: &HashRingRouter) -> OperationToShard<Self> {
        let SetPayloadOp {
            points,
            payload,
            filter,
            key,
        } = self;
        match (points, filter) {
            (Some(points), filter) => {
                split_iter_by_shard(points, |id| *id, ring).map(|points| SetPayloadOp {
                    points: Some(points),
                    payload: payload.clone(),
                    filter: filter.clone(),
                    key: key.clone(),
                })
            }
            (None, Some(filter)) => OperationToShard::to_all(SetPayloadOp {
                points: None,
                payload,
                filter: Some(filter),
                key,
            }),
            (None, None) => OperationToShard::to_none(),
        }
    }
}
