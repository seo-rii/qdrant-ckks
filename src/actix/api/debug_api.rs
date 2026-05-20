use actix_web::{Responder, get, patch, web};
use storage::rbac::AccessRequirements;

use crate::actix::auth::ActixAuth;
use crate::common::debugger::{DebugConfigPatch, DebuggerState};

#[get("/debugger")]
async fn get_debugger_config(
    ActixAuth(auth): ActixAuth,
    debugger_state: web::Data<DebuggerState>,
) -> impl Responder {
    crate::actix::helpers::time(async move {
        auth.check_global_access(AccessRequirements::new().manage(), "get_debugger_config")?;
        Ok(debugger_state.get_config())
    })
    .await
}

#[patch("/debugger")]
async fn update_debugger_config(
    ActixAuth(auth): ActixAuth,
    debugger_state: web::Data<DebuggerState>,
    debug_patch: web::Json<DebugConfigPatch>,
) -> impl Responder {
    crate::actix::helpers::time(async move {
        auth.check_global_access(AccessRequirements::new().manage(), "update_debugger_config")?;
        Ok(debugger_state.apply_config_patch(debug_patch.into_inner()))
    })
    .await
}

#[cfg(feature = "staging")]
mod staging {
    use collection::operations::loggable::Loggable;
    use collection::operations::verification;
    use collection::shards::shard::ShardId;
    use segment::types::SeqNumberType;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use shard::operations::{ClockTag, OperationWithClockTag};
    use storage::content_manager::errors::StorageError;
    use storage::dispatcher::Dispatcher;

    use super::*;
    use crate::actix::helpers;

    const DEFAULT_SHARD_WAL_ENTRIES: u64 = 10;
    const MAX_SHARD_WAL_ENTRIES: u64 = 100;

    #[get("/collections/{collection_name}/shards/{shard}/wal")]
    pub async fn get_shard_wal(
        dispatcher: web::Data<Dispatcher>,
        path: web::Path<(String, ShardId)>,
        query: web::Query<GetShardWalQuery>,
        ActixAuth(auth): ActixAuth,
    ) -> impl Responder {
        helpers::time(async move {
            let (collection, shard) = path.into_inner();
            let GetShardWalQuery { entries } = query.into_inner();
            let entries = validate_shard_wal_entries(entries)?;

            let pass = verification::new_unchecked_verification_pass();
            let collection_pass = auth.check_collection_access(
                &collection,
                AccessRequirements::new().write().manage().extras(),
                "get_shard_wal",
            )?;

            let entries = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await?
                .get_shard_wal_entries(shard, entries)
                .await?;

            Ok(redacted_shard_wal_entries(entries))
        })
        .await
    }

    #[derive(Serialize)]
    struct RedactedWalEntry {
        id: SeqNumberType,
        operation: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clock_tag: Option<ClockTag>,
    }

    fn validate_shard_wal_entries(entries: u64) -> Result<u64, StorageError> {
        if entries > MAX_SHARD_WAL_ENTRIES {
            return Err(StorageError::bad_request(format!(
                "shard WAL debug entries must not exceed {MAX_SHARD_WAL_ENTRIES}"
            )));
        }

        Ok(entries)
    }

    fn redacted_shard_wal_entries(
        entries: Vec<(SeqNumberType, OperationWithClockTag)>,
    ) -> Vec<RedactedWalEntry> {
        entries
            .into_iter()
            .map(|(id, operation)| RedactedWalEntry {
                id,
                operation: operation.operation.to_log_value(),
                clock_tag: operation.clock_tag,
            })
            .collect()
    }

    #[derive(Deserialize)]
    #[serde(default)]
    struct GetShardWalQuery {
        entries: u64,
    }

    impl Default for GetShardWalQuery {
        fn default() -> Self {
            Self {
                entries: DEFAULT_SHARD_WAL_ENTRIES,
            }
        }
    }

    #[get("/collections/{collection_name}/shards/{shard}/recovery_point")]
    pub async fn get_shard_recovery_point(
        dispatcher: web::Data<Dispatcher>,
        path: web::Path<(String, ShardId)>,
        ActixAuth(auth): ActixAuth,
    ) -> impl Responder {
        helpers::time(async move {
            let (collection, shard) = path.into_inner();

            let pass = verification::new_unchecked_verification_pass();
            let collection_pass = auth.check_collection_access(
                &collection,
                AccessRequirements::new().write().manage().extras(),
                "get_shard_recovery_point",
            )?;

            let recovery_point: Vec<_> = dispatcher
                .toc(&auth, &pass)
                .get_collection(&collection_pass)
                .await?
                .shard_recovery_point(shard)
                .await?
                .iter_as_clock_tags()
                .collect();

            Ok(recovery_point)
        })
        .await
    }

    #[cfg(test)]
    mod tests {
        use collection::operations::CollectionUpdateOperations;
        use collection::operations::payload_ops::{PayloadOps, SetPayloadOp};
        use segment::types::Payload;
        use serde_json::json;

        use super::*;

        #[test]
        fn debug_wal_entries_are_bounded() {
            assert!(validate_shard_wal_entries(MAX_SHARD_WAL_ENTRIES).is_ok());
            assert!(validate_shard_wal_entries(MAX_SHARD_WAL_ENTRIES + 1).is_err());
        }

        #[test]
        fn debug_wal_entries_redact_encrypted_payload_material() {
            let payload: Payload = serde_json::from_value(json!({
                "body": {
                    "$qdrant_client_aead": {
                        "version": 1,
                        "nonce": "nonce-sentinel",
                        "ciphertext": "ciphertext-sentinel",
                        "signature": { "sig": "signature-sentinel" }
                    }
                }
            }))
            .unwrap();
            let operation =
                OperationWithClockTag::from(CollectionUpdateOperations::PayloadOperation(
                    PayloadOps::SetPayload(SetPayloadOp {
                        payload,
                        points: Some(vec![1.into()]),
                        filter: None,
                        key: None,
                    }),
                ));

            let entries = redacted_shard_wal_entries(vec![(7, operation)]);
            let response = serde_json::to_string(&entries).unwrap();

            assert!(response.contains("redacted"));
            assert!(!response.contains("nonce-sentinel"));
            assert!(!response.contains("ciphertext-sentinel"));
            assert!(!response.contains("signature-sentinel"));
            assert!(!response.contains("$qdrant_client_aead"));
        }
    }
}

// Configure services
pub fn config_debugger_api(cfg: &mut web::ServiceConfig) {
    cfg.service(get_debugger_config)
        .service(update_debugger_config);

    #[cfg(feature = "staging")]
    cfg.service(staging::get_shard_wal)
        .service(staging::get_shard_recovery_point);
}
