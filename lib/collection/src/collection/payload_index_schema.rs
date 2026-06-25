use std::path::{Path, PathBuf};

use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::save_on_disk::SaveOnDisk;
use qdrant_sec::{ENCRYPTED_VECTOR_SIDECAR_FIELD, METADATA_VALUE_BINDING};
use segment::json_path::JsonPath;
use segment::types::{Filter, PayloadFieldSchema, PayloadSchemaType};
use shard::files::PAYLOAD_INDEX_CONFIG_FILE;
pub use shard::payload_index_schema::PayloadIndexSchema;

use crate::collection::Collection;
use crate::config::{
    CollectionParams, EncryptionSelector, encryption_rule_uses_private_result_oram,
    private_result_oram_payload_selector_overlap_message,
};
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

    let action_label = if action == "create" {
        "create payload index".to_string()
    } else {
        format!("{action} payload index schema")
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
                    "cannot {action_label} on encrypted vector sidecar field '{field_name}'; use encrypted vector search APIs instead",
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
                if encryption_rule_uses_private_result_oram(rule) {
                    CollectionError::bad_input("private result ORAM payload field path is invalid")
                } else {
                    CollectionError::bad_input(format!(
                        "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                    ))
                }
            })?;

            for field_name in &field_names {
                if field_name.compatible(&encrypted_json_path) {
                    if encryption_rule_uses_private_result_oram(rule) {
                        let private_result_action_label = format!("{action_label} on");
                        return Err(CollectionError::bad_input(
                            private_result_oram_payload_selector_overlap_message(
                                &private_result_action_label,
                                field_name,
                                encrypted_path,
                            ),
                        ));
                    }
                    return Err(CollectionError::bad_input(format!(
                        "cannot {action_label} on encrypted payload field '{field_name}' because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                    )));
                }
            }
        }
    }

    for rule in &encryption.rules {
        let EncryptionSelector::MetadataKeys { keys } = &rule.selector else {
            continue;
        };
        if rule.binding.as_deref() != Some(METADATA_VALUE_BINDING) {
            continue;
        }

        for metadata_key in keys {
            let metadata_path = metadata_key.parse::<JsonPath>().map_err(|err| {
                CollectionError::bad_input(format!(
                    "encrypted metadata field path '{metadata_key}' is invalid: {err:?}",
                ))
            })?;

            for field_name in &field_names {
                if field_name.compatible(&metadata_path) {
                    return Err(CollectionError::bad_input(format!(
                        "cannot {action_label} on encrypted metadata value field '{field_name}' because it overlaps encrypted metadata path '{metadata_key}'; configure a blind index provider instead",
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

    let action_label = if action == "create" {
        "create payload index".to_string()
    } else {
        format!("{action} payload index schema")
    };

    for rule in &encryption.rules {
        let EncryptionSelector::MetadataKeys { keys } = &rule.selector else {
            continue;
        };
        if rule.binding.as_deref() != Some("metadata-exact-match-token/v1") {
            continue;
        }

        for metadata_key in keys {
            let metadata_path = metadata_key.parse::<JsonPath>().map_err(|err| {
                CollectionError::bad_input(format!(
                    "metadata blind-index field path '{metadata_key}' is invalid: {err:?}",
                ))
            })?;
            if field_name.compatible(&metadata_path) {
                if field_name != &metadata_path {
                    return Err(CollectionError::bad_input(format!(
                        "cannot {action_label} on metadata blind-index field '{field_name}' because it overlaps token field '{metadata_key}'; blind-index token indexes must target the exact token field",
                    )));
                }
                if field_schema.kind() != PayloadSchemaType::Keyword {
                    return Err(CollectionError::bad_input(format!(
                        "cannot {action_label} on metadata blind-index field '{field_name}' because it overlaps token field '{metadata_key}'; blind-index token indexes must use keyword schema",
                    )));
                }
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

    use qdrant_sec::PRIVATE_RESULT_ORAM_BINDING;

    use super::*;
    use crate::config::{
        CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector,
    };

    fn params_with_payload_path(path: &str) -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:payload".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec![path.to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    fn params_with_private_result_oram_path(path: &str) -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:result-private-rk".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 7,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "private_result_payload".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec![path.to_string()],
                    },
                    instance: "docs_private_result_oram_v1".to_string(),
                    binding: Some(PRIVATE_RESULT_ORAM_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

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

    fn params_with_metadata_value_key(key: &str) -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:payload".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "tenant_conf".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec![key.to_string()],
                    },
                    instance: "docs_metadata_v1".to_string(),
                    binding: Some(METADATA_VALUE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        }
    }

    fn params_with_encrypted_vector_name(name: &str) -> CollectionParams {
        CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:vector".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "vector_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec![name.to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
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

        schema.clear();
        schema.insert(
            "document_body__blind_eq.child".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
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
                    && description.contains("exact token field")
        ));
    }

    #[test]
    fn recovered_payload_index_schema_rejects_metadata_value_encrypted_paths() {
        let collection_params = params_with_metadata_value_key("tenant_id");
        let mut schema = HashMap::new();
        schema.insert(
            "tenant_id".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
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
                    && description.contains("encrypted metadata value field")
        ));

        schema.clear();
        schema.insert(
            "tenant_id.keyword".parse().unwrap(),
            PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
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
                if description.contains("encrypted metadata value field")
                    && description.contains("tenant_id.keyword")
        ));
    }

    #[test]
    fn create_shard_key_payload_index_schema_rejects_encrypted_path_replay() {
        let collection_params = params_with_payload_path("document.body");
        let mut schema = HashMap::new();

        for field_name in ["document", "document.body", "document.body.keyword"] {
            schema.clear();
            schema.insert(
                field_name.parse().unwrap(),
                PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
            );

            let err = validate_payload_index_schema_for_encryption(
                schema.iter(),
                &collection_params,
                "create shard key",
            )
            .unwrap_err();

            assert!(matches!(
                err,
                CollectionError::BadInput { description }
                    if description.contains("create shard key payload index schema")
                        && description.contains("encrypted payload field")
                        && description.contains("document.body")
            ));
        }
    }

    #[test]
    fn create_payload_index_rejects_private_result_oram_paths() {
        let collection_params = params_with_private_result_oram_path("document.body");
        let mut schema = HashMap::new();

        for field_name in ["document", "document.body", "document.body.keyword"] {
            let err = validate_payload_index_paths_for_encrypted_paths(
                [&field_name.parse().unwrap()],
                &collection_params,
                "create",
            )
            .unwrap_err();

            assert!(matches!(
                err,
                CollectionError::BadInput { description }
                    if description.contains("create payload index")
                        && description.contains("private result ORAM payload field")
                        && description.contains("/private-result-oram/session")
                        && !description.contains("document.body")
            ));

            for action in ["recover", "create shard key"] {
                schema.clear();
                schema.insert(
                    field_name.parse().unwrap(),
                    PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
                );
                let err = validate_payload_index_schema_for_encryption(
                    schema.iter(),
                    &collection_params,
                    action,
                )
                .unwrap_err();
                let action_label = format!("{action} payload index schema");
                assert!(matches!(
                    err,
                    CollectionError::BadInput { description }
                        if description.contains(&action_label)
                            && description.contains("private result ORAM payload field")
                            && description.contains("/private-result-oram/session")
                            && !description.contains("document.body")
                ));
            }
        }
    }

    #[test]
    fn payload_index_private_result_oram_invalid_payload_path_error_is_sanitized() {
        let secret_path = "document.body[private-result-index-secret";
        let collection_params = params_with_private_result_oram_path(secret_path);
        let field_name = "document".parse::<JsonPath>().unwrap();

        let err = validate_payload_index_paths_for_encrypted_paths(
            [&field_name],
            &collection_params,
            "create",
        )
        .expect_err("invalid private result ORAM selector must fail closed")
        .to_string();

        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-index-secret"), "{err}");
        assert!(!err.contains("JsonPath"), "{err}");
    }

    #[test]
    fn recovered_payload_index_schema_rejects_encrypted_vector_sidecar_children() {
        let collection_params = params_with_encrypted_vector_name("embedding");
        let mut schema = HashMap::new();

        for field_name in [
            format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\""),
            format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\".embedding"),
        ] {
            schema.clear();
            schema.insert(
                field_name.parse().unwrap(),
                PayloadFieldSchema::FieldType(PayloadSchemaType::Keyword),
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
                        && description.contains("encrypted vector sidecar field")
                        && description.contains(ENCRYPTED_VECTOR_SIDECAR_FIELD)
            ));
        }
    }

    #[test]
    fn create_payload_index_rejects_metadata_value_parent_and_child_paths() {
        let collection_params = params_with_metadata_value_key("metadata.tenant_id");

        for field_name in [
            "metadata",
            "metadata.tenant_id",
            "metadata.tenant_id.keyword",
        ] {
            let err = validate_payload_index_paths_for_encrypted_paths(
                [&field_name.parse().unwrap()],
                &collection_params,
                "create",
            )
            .unwrap_err();

            assert!(matches!(
                err,
                CollectionError::BadInput { description }
                    if description.contains("create payload index")
                        && description.contains("encrypted metadata value field")
                        && description.contains("metadata.tenant_id")
                        && description.contains("blind index")
            ));
        }
    }
}
