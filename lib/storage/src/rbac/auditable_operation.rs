use std::collections::BTreeMap;

use shard::operations::payload_ops::PayloadOps;
use shard::operations::point_ops::PointOperations;
use shard::operations::vector_ops::VectorOperations;
use shard::operations::{CollectionUpdateOperations, FieldIndexOperations};

use crate::content_manager::collection_meta_ops::CollectionMetaOperations;

pub trait AuditableOperation {
    fn operation_name(&self) -> &'static str;

    fn audit_metadata(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
}

impl AuditableOperation for CollectionUpdateOperations {
    fn operation_name(&self) -> &'static str {
        match self {
            CollectionUpdateOperations::PointOperation(op) => match op {
                PointOperations::UpsertPoints(_) => "upsert_points",
                PointOperations::UpsertPointsConditional(_) => "upsert_points_conditional",
                PointOperations::DeletePoints { .. } => "delete_points",
                PointOperations::DeletePointsByFilter(_) => "delete_points_by_filter",
                PointOperations::SyncPoints(_) => "sync_points",
            },
            CollectionUpdateOperations::VectorOperation(op) => match op {
                VectorOperations::UpdateVectors(_) => "update_vectors",
                VectorOperations::DeleteVectors(_, _) => "delete_vectors",
                VectorOperations::DeleteVectorsByFilter(_, _) => "delete_vectors_by_filter",
            },
            CollectionUpdateOperations::PayloadOperation(op) => match op {
                PayloadOps::SetPayload(_) => "set_payload",
                PayloadOps::DeletePayload(_) => "delete_payload",
                PayloadOps::ClearPayload { .. } => "clear_payload",
                PayloadOps::ClearPayloadByFilter(_) => "clear_payload_by_filter",
                PayloadOps::OverwritePayload(_) => "overwrite_payload",
            },
            CollectionUpdateOperations::FieldIndexOperation(op) => match op {
                FieldIndexOperations::CreateIndex(_) => "create_field_index",
                FieldIndexOperations::DeleteIndex(_) => "delete_field_index",
            },
            #[cfg(feature = "staging")]
            CollectionUpdateOperations::StagingOperation(_) => "debug",
        }
    }
}

impl AuditableOperation for CollectionMetaOperations {
    fn operation_name(&self) -> &'static str {
        match self {
            CollectionMetaOperations::CreateCollection(_) => "create_collection",
            CollectionMetaOperations::UpdateCollection(_) => "update_collection",
            CollectionMetaOperations::ApplyCryptoMigration(_) => "apply_crypto_migration",
            CollectionMetaOperations::DeleteCollection(_) => "delete_collection",
            CollectionMetaOperations::ChangeAliases(_) => "change_aliases",
            CollectionMetaOperations::Resharding(_, _) => "resharding",
            CollectionMetaOperations::TransferShard(_, _) => "transfer_shard",
            CollectionMetaOperations::SetShardReplicaState(_) => "set_shard_replica_state",
            CollectionMetaOperations::CreateShardKey(_) => "create_shard_key",
            CollectionMetaOperations::DropShardKey(_) => "drop_shard_key",
            CollectionMetaOperations::CreatePayloadIndex(_) => "create_payload_index",
            CollectionMetaOperations::DropPayloadIndex(_) => "drop_payload_index",
            CollectionMetaOperations::Nop { .. } => "nop",
            #[cfg(feature = "staging")]
            CollectionMetaOperations::TestSlowDown(_) => "debug",
        }
    }

    fn audit_metadata(&self) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::new();
        if let CollectionMetaOperations::ApplyCryptoMigration(operation) = self {
            metadata.insert(
                "collection_name".to_string(),
                operation.collection_name.clone(),
            );
            metadata.insert(
                "from_state".to_string(),
                format!("{:?}", operation.plan.from),
            );
            metadata.insert("to_state".to_string(), format!("{:?}", operation.plan.to));
            metadata.insert(
                "target_epoch".to_string(),
                operation.plan.target_epoch.to_string(),
            );
            metadata.insert("dry_run".to_string(), operation.plan.dry_run.to_string());
            metadata.insert(
                "checkpoint_count".to_string(),
                operation.plan.checkpoints.len().to_string(),
            );
            let total_points: u64 = operation
                .plan
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.total_points)
                .sum();
            let processed_points: u64 = operation
                .plan
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.processed_points)
                .sum();
            let rewritten_points: u64 = operation
                .plan
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.rewritten_points)
                .sum();
            metadata.insert("total_points".to_string(), total_points.to_string());
            metadata.insert("processed_points".to_string(), processed_points.to_string());
            metadata.insert("rewritten_points".to_string(), rewritten_points.to_string());
            if let Some(active_rk_id) = operation.plan.active_rk_id.as_deref() {
                metadata.insert("active_rk_id".to_string(), active_rk_id.to_string());
            }
            if let Some(retired_rk_id) = operation.plan.retired_rk_id.as_deref() {
                metadata.insert("retired_rk_id".to_string(), retired_rk_id.to_string());
            }
        }
        metadata
    }
}

#[cfg(test)]
mod tests {
    use collection::config::{
        CryptoMigrationCheckpoint, CryptoMigrationCheckpointStatus, CryptoMigrationPlan,
        CryptoMigrationState,
    };

    use crate::content_manager::collection_meta_ops::{
        ApplyCryptoMigrationPlan, CollectionMetaOperations,
    };
    use crate::rbac::auditable_operation::AuditableOperation;

    #[test]
    fn crypto_migration_audit_metadata_contains_safe_targets() {
        let operation = CollectionMetaOperations::ApplyCryptoMigration(ApplyCryptoMigrationPlan {
            collection_name: "docs".to_string(),
            plan: CryptoMigrationPlan {
                from: CryptoMigrationState::Rotating,
                to: CryptoMigrationState::Active,
                target_epoch: 7,
                active_rk_id: Some("rk-docs-7".to_string()),
                retired_rk_id: Some("rk-docs-6".to_string()),
                dry_run: false,
                checkpoints: vec![CryptoMigrationCheckpoint {
                    shard_id: 1,
                    total_points: 10,
                    processed_points: 10,
                    rewritten_points: 4,
                    changed_points: 3,
                    status: CryptoMigrationCheckpointStatus::Verified,
                }],
            },
        });

        let metadata = operation.audit_metadata();

        assert_eq!(
            metadata.get("collection_name").map(String::as_str),
            Some("docs")
        );
        assert_eq!(
            metadata.get("from_state").map(String::as_str),
            Some("Rotating")
        );
        assert_eq!(metadata.get("to_state").map(String::as_str), Some("Active"));
        assert_eq!(metadata.get("target_epoch").map(String::as_str), Some("7"));
        assert_eq!(
            metadata.get("active_rk_id").map(String::as_str),
            Some("rk-docs-7")
        );
        assert_eq!(
            metadata.get("retired_rk_id").map(String::as_str),
            Some("rk-docs-6")
        );
        assert_eq!(
            metadata.get("checkpoint_count").map(String::as_str),
            Some("1")
        );
        assert!(!metadata.contains_key("wrapped_key_b64"));
        assert!(!metadata.contains_key("nonce"));
        assert!(!metadata.contains_key("ciphertext"));
    }
}
