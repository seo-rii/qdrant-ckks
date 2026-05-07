use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::counter::hardware_accumulator::HwMeasurementAcc;
use futures::TryStreamExt;
use futures::stream::FuturesUnordered;
use qdrant_sec::ENCRYPTED_VECTOR_SIDECAR_FIELD;
use segment::data_types::facets::{FacetParams, FacetResponse, FacetValue};
use segment::json_path::JsonPath;

use super::Collection;
use crate::config::EncryptionSelector;
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
        if request.limit == 0 {
            return Ok(FacetResponse::default());
        }

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
                let sidecar_path = format!("\"{ENCRYPTED_VECTOR_SIDECAR_FIELD}\"")
                    .parse::<JsonPath>()
                    .map_err(|err| {
                        CollectionError::bad_input(format!(
                            "encrypted vector sidecar field path '{ENCRYPTED_VECTOR_SIDECAR_FIELD}' is invalid: {err:?}",
                        ))
                    })?;
                if request.key.compatible(&sidecar_path) {
                    return Err(CollectionError::bad_input(format!(
                        "cannot facet on encrypted vector sidecar field '{}'; use encrypted vector search APIs instead",
                        request.key,
                    )));
                }
            }

            for rule in &encryption.rules {
                let EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
                    continue;
                };
                for encrypted_path in paths {
                    let encrypted_json_path = encrypted_path.parse().map_err(|err| {
                        CollectionError::bad_input(format!(
                            "encrypted payload field path '{encrypted_path}' is invalid: {err:?}",
                        ))
                    })?;
                    if request.key.compatible(&encrypted_json_path) {
                        return Err(CollectionError::bad_input(format!(
                            "cannot facet on encrypted payload field '{}' because it overlaps encrypted path '{encrypted_path}'; configure a blind index provider instead",
                            request.key,
                        )));
                    }
                }
            }
        }
        self.ensure_filter_does_not_touch_encrypted_payload(request.filter.as_ref())
            .await?;

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
