use std::path::{Path, PathBuf};

use common::counter::hardware_accumulator::HwMeasurementAcc;
use common::save_on_disk::SaveOnDisk;
use qdrant_sec::ENCRYPTED_VECTOR_SIDECAR_FIELD;
use segment::json_path::JsonPath;
use segment::types::{Filter, PayloadFieldSchema};
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
        if let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        {
            if encryption
                .rules
                .iter()
                .any(|rule| matches!(rule.selector, EncryptionSelector::VectorNames { .. }))
            {
                let sidecar_path = encrypted_vector_sidecar_path()?;
                if field_name.compatible(&sidecar_path) {
                    return Err(CollectionError::bad_input(format!(
                        "cannot create payload index on encrypted vector sidecar field '{field_name}'; use encrypted vector search APIs instead",
                    )));
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
                    if field_name.compatible(&encrypted_json_path) {
                        return Err(CollectionError::bad_input(format!(
                            "cannot create payload index on encrypted payload field '{field_name}' because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                        )));
                    }
                }
            }
        }

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
