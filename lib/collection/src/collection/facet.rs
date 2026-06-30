use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::counter::hardware_accumulator::HwMeasurementAcc;
use futures::TryStreamExt;
use futures::stream::FuturesUnordered;
use qdrant_sec::{ENCRYPTED_VECTOR_SIDECAR_FIELD, METADATA_VALUE_BINDING};
use segment::data_types::facets::{FacetParams, FacetResponse, FacetValue};
use segment::json_path::JsonPath;

use super::Collection;
use crate::config::{
    CollectionEncryptionConfig, EncryptionSelector, encryption_rule_uses_private_result_oram,
    private_result_oram_payload_selector_overlap_message,
};
use crate::operations::consistency_params::ReadConsistency;
use crate::operations::shard_selector_internal::ShardSelectorInternal;
use crate::operations::types::{CollectionError, CollectionResult};

impl Collection {
    pub async fn facet(
        &self,
        request: FacetParams,
        shard_selection: ShardSelectorInternal,
        read_consistency: Option<ReadConsistency>,
        timeout: Option<Duration>,
        hw_measurement_acc: HwMeasurementAcc,
    ) -> CollectionResult<FacetResponse> {
        self.ensure_crypto_migration_allows_regular_operation("reads")
            .await?;

        if let Some(encryption) = self
            .collection_config
            .read()
            .await
            .params
            .effective_encryption()
        {
            ensure_facet_key_does_not_touch_encrypted_payload(&request.key, &encryption)?;
        }
        self.ensure_filter_does_not_touch_encrypted_payload(request.filter.as_ref())
            .await?;

        if request.limit == 0 {
            return Ok(FacetResponse::default());
        }

        let limit = request.limit;
        let request = Arc::new(request);

        let shard_holder = self.shards_holder.read().await;
        let target_shards = shard_holder.select_shards(&shard_selection)?;

        let mut shards_reads_f = target_shards
            .iter()
            .map(|(shard, _shard_key)| {
                shard.facet(
                    request.clone(),
                    read_consistency,
                    shard_selection.is_shard_id(),
                    timeout,
                    hw_measurement_acc.clone(),
                )
            })
            .collect::<FuturesUnordered<_>>();

        // Collect results from all shards into a single map
        let mut aggregated_results: HashMap<FacetValue, usize> = HashMap::new();
        while let Some(response) = shards_reads_f.try_next().await? {
            for hit in response.hits {
                *aggregated_results.entry(hit.value).or_insert(0) += hit.count;
            }
        }

        Ok(FacetResponse::top_hits(aggregated_results, limit))
    }
}

fn ensure_facet_key_does_not_touch_encrypted_payload(
    key: &JsonPath,
    encryption: &CollectionEncryptionConfig,
) -> CollectionResult<()> {
    if encryption
        .rules
        .iter()
        .any(|rule| matches!(rule.selector, EncryptionSelector::VectorNames { .. }))
    {
        let sidecar_path = format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
            .parse::<JsonPath>()
            .map_err(|_| {
                CollectionError::bad_input("encrypted vector sidecar field path is invalid")
            })?;
        if key.compatible(&sidecar_path) {
            return Err(CollectionError::bad_input(
                "cannot facet on encrypted vector sidecar field; use encrypted vector search APIs instead",
            ));
        }
    }

    for rule in &encryption.rules {
        match &rule.selector {
            EncryptionSelector::PayloadPaths { paths } => {
                for encrypted_path in paths {
                    let encrypted_json_path = encrypted_path.parse::<JsonPath>().map_err(|_| {
                        if encryption_rule_uses_private_result_oram(rule) {
                            CollectionError::bad_input(
                                "private result ORAM payload field path is invalid",
                            )
                        } else {
                            CollectionError::bad_input("encrypted payload field path is invalid")
                        }
                    })?;
                    if key.compatible(&encrypted_json_path) {
                        if encryption_rule_uses_private_result_oram(rule) {
                            return Err(CollectionError::bad_input(
                                private_result_oram_payload_selector_overlap_message(
                                    key,
                                    encrypted_path,
                                ),
                            ));
                        }
                        return Err(CollectionError::bad_input(format!(
                            "cannot facet on encrypted payload field because it overlaps an encrypted payload selector; configure a blind index provider instead",
                        )));
                    }
                }
            }
            EncryptionSelector::MetadataKeys { keys } => {
                for metadata_key in keys {
                    let metadata_path = metadata_key.parse::<JsonPath>().map_err(|_| {
                        CollectionError::bad_input("metadata blind-index field path is invalid")
                    })?;
                    if key.compatible(&metadata_path) {
                        if rule.binding.as_deref() == Some(METADATA_VALUE_BINDING) {
                            return Err(CollectionError::bad_input(format!(
                                "cannot facet on encrypted metadata value field because it overlaps an encrypted metadata selector; configure a blind index provider instead",
                            )));
                        }
                        return Err(CollectionError::bad_input(format!(
                            "cannot facet on metadata blind-index field; blind-index token fields support exact-match filters only",
                        )));
                    }
                }
            }
            EncryptionSelector::VectorNames { .. } => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CollectionEncryptionConfig, CryptoMigrationState, EncryptionRuleRef};

    fn private_result_oram_encryption(path: &str) -> CollectionEncryptionConfig {
        CollectionEncryptionConfig {
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
                binding: Some(qdrant_sec::PRIVATE_RESULT_ORAM_BINDING.to_string()),
            }],
        }
    }

    #[test]
    fn facet_rejects_private_result_oram_payload_paths() {
        let encryption = private_result_oram_encryption("document.body");
        for key in ["document", "document.body", "document.body.lang"] {
            let key = key.parse::<JsonPath>().unwrap();
            let err = ensure_facet_key_does_not_touch_encrypted_payload(&key, &encryption)
                .expect_err("private result ORAM payload facets must fail closed");
            let message = err.to_string();
            assert!(message.contains("cannot use private result ORAM payload field"));
            assert!(!message.contains("document.body"));
            assert!(message.contains(qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER));
            assert!(message.contains("/private-result-oram/session"));
            assert!(!message.contains("configure a blind index provider"));
        }

        let public_key = "document.title".parse::<JsonPath>().unwrap();
        ensure_facet_key_does_not_touch_encrypted_payload(&public_key, &encryption)
            .expect("unrelated public payload facets should remain allowed");
    }

    #[test]
    fn facet_private_result_oram_invalid_payload_path_error_is_sanitized() {
        let secret_path = "document.body[private-result-facet-secret";
        let encryption = private_result_oram_encryption(secret_path);
        let key = "document".parse::<JsonPath>().unwrap();

        let err = ensure_facet_key_does_not_touch_encrypted_payload(&key, &encryption)
            .expect_err("invalid private result ORAM selector must fail closed")
            .to_string();

        assert!(err.contains("private result ORAM payload field path is invalid"));
        assert!(!err.contains(secret_path), "{err}");
        assert!(!err.contains("private-result-facet-secret"), "{err}");
        assert!(!err.contains("JsonPath"), "{err}");
    }
}
