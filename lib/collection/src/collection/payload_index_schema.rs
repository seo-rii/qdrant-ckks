use std::path::{Path, PathBuf};

use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::save_on_disk::SaveOnDisk;
use qdrant_sec::ENCRYPTED_VECTOR_SIDECAR_FIELD;
use segment::json_path::JsonPath;
use segment::types::{Filter, PayloadFieldSchema, PayloadSchemaType};
use shard::files::PAYLOAD_INDEX_CONFIG_FILE;
pub use shard::payload_index_schema::PayloadIndexSchema;

use crate::collection::Collection;
use crate::config::{CollectionParams, EncryptionSelector};
use crate::operations::types::{CollectionError, CollectionResult, UpdateResult};
use crate::operations::universal_query::formula::ExpressionInternal;
use crate::operations::{CollectionUpdateOperations, CreateIndex, FieldIndexOperations};
use crate::problems::unindexed_field;
use crate::shards::shard_trait::WaitUntil;

pub fn validate_payload_index_paths_for_encrypted_paths<'a>(
    field_names: impl IntoIterator<Item = &'a JsonPath>,
    collection_params: &CollectionParams,
    action: &str,
) -> CollectionResult<()> {
    let field_names: Vec<_> = field_names.into_iter().collect();
    let Some(encryption) = collection_params.effective_encryption() else {
        return Ok(());
    };

    if encryption
        .rules
        .iter()
        .any(|rule| matches!(rule.selector, EncryptionSelector::VectorNames { .. }))
    {
        let sidecar_path = encrypted_vector_sidecar_path()?;
        for field_name in &field_names {
            if field_name.compatible(&sidecar_path) {
                return Err(CollectionError::bad_input(format!(
                    "cannot {action} payload index schema on encrypted vector sidecar field '{field_name}'; use encrypted vector search APIs instead",
                )));
            }
        }
    }

    for rule in &encryption.rules {
        let EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
            continue;
        };

        for encrypted_path in paths {
            let encrypted_json_path = encrypted_path.parse::<JsonPath>().map_err(|err| {
                CollectionError::bad_input(format!(
                    "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                ))
            })?;

            for field_name in &field_names {
                if field_name.compatible(&encrypted_json_path) {
                    return Err(CollectionError::bad_input(format!(
                        "cannot {action} payload index schema on encrypted payload field '{field_name}' because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                    )));
                }
            }
        }
    }

    Ok(())
}

pub fn validate_payload_index_entry_for_encryption(
    field_name: &JsonPath,
    field_schema: &PayloadFieldSchema,
    collection_params: &CollectionParams,
    action: &str,
) -> CollectionResult<()> {
    validate_payload_index_paths_for_encrypted_paths([field_name], collection_params, action)?;

    let Some(encryption) = collection_params.effective_encryption() else {
        return Ok(());
    };

    for rule in &encryption.rules {
        let EncryptionSelector::MetadataKeys { keys } = &rule.selector else {
            continue;
        };

        for metadata_key in keys {
            let metadata_path = metadata_key.parse::<JsonPath>().map_err(|err| {
                CollectionError::bad_input(format!(
                    "metadata blind-index field path '{metadata_key}' is invalid: {err:?}",
                ))
            })?;
            if field_name.compatible(&metadata_path)
                && field_schema.kind() != PayloadSchemaType::Keyword
            {
                return Err(CollectionError::bad_input(format!(
                    "cannot {action} payload index schema on metadata blind-index field '{field_name}' because it overlaps token field '{metadata_key}'; blind-index token indexes must use keyword schema",
                )));
            }
        }
    }

    Ok(())
}

pub fn validate_payload_index_schema_for_encryption<'a>(
    entries: impl IntoIterator<Item = (&'a JsonPath, &'a PayloadFieldSchema)>,
    collection_params: &CollectionParams,
    action: &str,
) -> CollectionResult<()> {
    for (field_name, field_schema) in entries {
        validate_payload_index_entry_for_encryption(
            field_name,
            field_schema,
            collection_params,
            action,
        )?;
    }

    Ok(())
}

impl Collection {
    pub(crate) fn payload_index_file(collection_path: &Path) -> PathBuf {
        collection_path.join(PAYLOAD_INDEX_CONFIG_FILE)
    }

    pub(crate) fn load_payload_index_schema(
        collection_path: &Path,
        collection_params: &CollectionParams,
    ) -> CollectionResult<SaveOnDisk<PayloadIndexSchema>> {
        let payload_index_file = Self::payload_index_file(collection_path);
        let schema: SaveOnDisk<PayloadIndexSchema> =
            SaveOnDisk::load_or_init_default(payload_index_file)?;
        let stored_schema = schema.read();
        validate_payload_index_paths_for_encrypted_paths(
            stored_schema.schema.keys(),
            collection_params,
            "load",
        )?;
        drop(stored_schema);
        Ok(schema)
    }

    pub async fn create_payload_index(
        &self,
        field_name: JsonPath,
        field_schema: PayloadFieldSchema,
        hw_acc: HwMeasurementAcc,
    ) -> CollectionResult<Option<UpdateResult>> {
        // This function is called from consensus, so we use `wait = false`, because we can't afford
        // to wait for the result as indexation may take a long time
        self.create_payload_index_with_wait(field_name, field_schema, false, hw_acc)
            .await
    }

    pub async fn create_payload_index_with_wait(
        &self,
        field_name: JsonPath,
        field_schema: PayloadFieldSchema,
        wait: bool,
        hw_acc: HwMeasurementAcc,
    ) -> CollectionResult<Option<UpdateResult>> {
        let collection_params = self.collection_config.read().await.params.clone();
        validate_payload_index_entry_for_encryption(
            &field_name,
            &field_schema,
            &collection_params,
            "create",
        )?;

        self.payload_index_schema.write(|schema| {
            schema
                .schema
                .insert(field_name.clone(), field_schema.clone());
        })?;

        // This operation might be redundant, if we also create index as a regular collection op,
        // but it looks better in long term to also have it here, so
        // the creation of payload index may be eventually completely converted
        // into the consensus operation
        let create_index_operation = CollectionUpdateOperations::FieldIndexOperation(
            FieldIndexOperations::CreateIndex(CreateIndex {
                field_name,
                field_schema: Some(field_schema),
            }),
        );

        self.update_all_local(create_index_operation, WaitUntil::from(wait), hw_acc)
            .await
    }

    pub async fn drop_payload_index(
        &self,
        field_name: JsonPath,
    ) -> CollectionResult<Option<UpdateResult>> {
        self.payload_index_schema.write(|schema| {
            schema.schema.remove(&field_name);
        })?;

        let delete_index_operation = CollectionUpdateOperations::FieldIndexOperation(
            FieldIndexOperations::DeleteIndex(field_name),
        );

        let result = self
            .update_all_local(
                delete_index_operation,
                WaitUntil::from(false),
                HwMeasurementAcc::disposable(), // Unmeasured API
            )
            .await?;

        Ok(result)
    }

    pub fn payload_key_index_schema(&self, key: &JsonPath) -> Option<PayloadFieldSchema> {
        self.payload_index_schema.read().schema.get(key).cloned()
    }

    /// Returns an arbitrary payload key along with acceptable
    /// schemas used by `filter` which can be indexed but currently is not.
    /// If this function returns `None` all indexable keys in `filter` are indexed.
    pub fn one_unindexed_key(
        &self,
        filter: &Filter,
    ) -> Option<(JsonPath, Vec<PayloadFieldSchema>)> {
        one_unindexed_filter_key(&self.payload_index_schema.read(), filter)
    }

    pub fn one_unindexed_expression_key(
        &self,
        expr: &ExpressionInternal,
    ) -> Option<(JsonPath, Vec<PayloadFieldSchema>)> {
        one_unindexed_expression_key(&self.payload_index_schema.read(), expr)
    }
}

fn encrypted_vector_sidecar_path() -> CollectionResult<JsonPath> {
    format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
        .parse::<JsonPath>()
        .map_err(|err| {
            CollectionError::bad_input(format!(
                "encrypted vector sidecar field path '{ENCRYPTED_VECTOR_SIDECAR_FIELD}' is invalid: {err:?}",
            ))
        })
}

enum PotentiallyUnindexed<'a> {
    Filter(&'a Filter),
    Expression(&'a ExpressionInternal),
}

/// Returns an arbitrary payload key with acceptable schemas
/// used by `filter` which can be indexed but currently is not.
/// If this function returns `None` all indexable keys in `filter` are indexed.
fn one_unindexed_key(
    schema: &PayloadIndexSchema,
    suspect: PotentiallyUnindexed<'_>,
) -> Option<(JsonPath, Vec<PayloadFieldSchema>)> {
    let mut extractor = unindexed_field::Extractor::new(&schema.schema);

    match suspect {
        PotentiallyUnindexed::Filter(filter) => {
            extractor.update_from_filter_once(None, filter);
        }
        PotentiallyUnindexed::Expression(expression) => {
            extractor.update_from_expression(expression);
        }
    }

    // Get the first unindexed field from the extractor.
    extractor
        .unindexed_schema()
        .iter()
        .next()
        .map(|(key, schema)| (key.clone(), schema.clone()))
}

/// Returns an arbitrary payload key with acceptable schemas
/// used by `filter` which can be indexed but currently is not.
/// If this function returns `None` all indexable keys in `filter` are indexed.
pub fn one_unindexed_filter_key(
    schema: &PayloadIndexSchema,
    filter: &Filter,
) -> Option<(JsonPath, Vec<PayloadFieldSchema>)> {
    one_unindexed_key(schema, PotentiallyUnindexed::Filter(filter))
}

pub fn one_unindexed_expression_key(
    schema: &PayloadIndexSchema,
    expr: &ExpressionInternal,
) -> Option<(JsonPath, Vec<PayloadFieldSchema>)> {
    one_unindexed_key(schema, PotentiallyUnindexed::Expression(expr))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::config::{
        CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector,
    };

    fn params_with_metadata_blind_index_key(key: &str) -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:payload".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "payload_blind_eq".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec![key.to_string()],
                    },
                    instance: "docs_blind_v1".to_string(),
                    binding: Some("metadata-exact-match-token/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    #[test]
    fn recovered_payload_index_schema_requires_keyword_for_metadata_blind_index() {
        let collection_params = params_with_metadata_blind_index_key("document_body__blind_eq");
        let mut schema = HashMap::new();
        schema.insert(
            "document_body__blind_eq".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Text),
        );

        let err = validate_payload_index_schema_for_encryption(
            schema.iter(),
            &collection_params,
            "recover",
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CollectionError::BadInput { description }
                if description.contains("recover payload index schema")
                    && description.contains("metadata blind-index field")
                    && description.contains("keyword schema")
        ));

        schema.insert(
            "document_body__blind_eq".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
        );
        validate_payload_index_schema_for_encryption(schema.iter(), &collection_params, "recover")
            .unwrap();
    }
}
