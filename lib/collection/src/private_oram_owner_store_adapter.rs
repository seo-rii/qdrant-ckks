#![allow(
    dead_code,
    reason = "D3-B3-B2 paired store evidence remains dormant until typed parent recovery is wired"
)]

use std::fmt::{self, Debug, Formatter};

use qdrant_sec::{
    PrivateHnswManifestValidationContext, PrivateOramAppendBucketRefV1,
    PrivateOramAppendMutationBundleV1, PrivateOramImmutableIndexV2,
    PrivateOramImmutableManifestBundleV2, PrivateOramImmutableManifestV2, PrivateOramIndexKindV2,
    PrivateOramIndexStateV2, PrivateOramSignatureVerification,
    PrivateResultOramManifestValidationContext, private_oram_append_mutation_v1_digest,
    private_oram_immutable_manifest_v2_digest, validate_private_oram_append_mutation_v1_shape,
    validate_private_oram_append_mutation_v1_signature,
    validate_private_oram_immutable_manifest_v2_shape,
    validate_private_oram_immutable_manifest_v2_signature,
    validate_private_oram_signed_state_v2_signature,
};

use crate::operations::types::{CollectionError, CollectionResult};
use crate::private_hnsw_oram_store::{
    PrivateHnswOramStore, PrivateHnswOwnerExactNewStoreTokenV1,
    PrivateHnswOwnerExactOldStoreTokenV1, PrivateHnswOwnerStoreObservationV1,
};
use crate::private_oram_owner_journal::{
    PrivateOramDurableOwnerPreparedTokenV1, PrivateOramOwnerFinalBucketBatchV1,
    PrivateOramOwnerJournal, PrivateOramOwnerJournalIndexDescriptorV1,
    PrivateOramOwnerJournalSnapshotV1, PrivateOramOwnerJournalTerminalIndexStateV1,
    PrivateOramOwnerRecoveryProjectionV1,
};
use crate::private_result_oram_store::{
    PrivateResultOramStore, PrivateResultOwnerExactNewStoreTokenV1,
    PrivateResultOwnerExactOldStoreTokenV1, PrivateResultOwnerStoreObservationV1,
};

#[derive(Clone, Copy)]
pub(crate) struct PrivateOramOwnerStorePairContextV1<'a> {
    pub(crate) owner_journal: &'a PrivateOramOwnerJournal,
    pub(crate) prepared_token: &'a PrivateOramDurableOwnerPreparedTokenV1,
    pub(crate) immutable_manifest: &'a PrivateOramImmutableManifestBundleV2,
    pub(crate) mutation_bundle: &'a PrivateOramAppendMutationBundleV1,
    pub(crate) signature_verification: PrivateOramSignatureVerification<'a>,
    pub(crate) hnsw_store: &'a PrivateHnswOramStore,
    pub(crate) hnsw_manifest_validation: PrivateHnswManifestValidationContext<'a>,
    pub(crate) hnsw_max_ciphertext_bytes: usize,
    pub(crate) result_store: &'a PrivateResultOramStore,
    pub(crate) result_manifest_validation: PrivateResultOramManifestValidationContext<'a>,
    pub(crate) result_max_ciphertext_bytes: usize,
}

impl Debug for PrivateOramOwnerStorePairContextV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerStorePairContextV1")
            .field("owner_journal", &self.owner_journal)
            .field("prepared_token", &self.prepared_token)
            .field("immutable_manifest", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .field("signature_verification", &self.signature_verification)
            .field("hnsw_store", &self.hnsw_store)
            .field("hnsw_manifest_validation", &self.hnsw_manifest_validation)
            .field("hnsw_max_ciphertext_bytes", &self.hnsw_max_ciphertext_bytes)
            .field("result_store", &self.result_store)
            .field(
                "result_manifest_validation",
                &self.result_manifest_validation,
            )
            .field(
                "result_max_ciphertext_bytes",
                &self.result_max_ciphertext_bytes,
            )
            .finish()
    }
}

/// Server-side resources used for a read-only recovery classification.
///
/// This value contains no parent consensus authority. Storage must pair it with a projection made
/// from `PrivateOramValidatedOwnerRecoveryAuthorityV1` before invoking the classifier.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct PrivateOramOwnerRecoveryStorePairResourcesV1<'a> {
    pub owner_journal: &'a PrivateOramOwnerJournal,
    pub immutable_manifest: &'a PrivateOramImmutableManifestBundleV2,
    pub mutation_bundle: &'a PrivateOramAppendMutationBundleV1,
    pub signature_verification: PrivateOramSignatureVerification<'a>,
    pub hnsw_store: &'a PrivateHnswOramStore,
    pub hnsw_manifest_validation: PrivateHnswManifestValidationContext<'a>,
    pub hnsw_max_ciphertext_bytes: usize,
    pub result_store: &'a PrivateResultOramStore,
    pub result_manifest_validation: PrivateResultOramManifestValidationContext<'a>,
    pub result_max_ciphertext_bytes: usize,
}

impl Debug for PrivateOramOwnerRecoveryStorePairResourcesV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerRecoveryStorePairResourcesV1")
            .field("owner_journal", &"[redacted]")
            .field("immutable_manifest", &"[redacted]")
            .field("mutation_bundle", &"[redacted]")
            .field("signature_verification", &"[redacted]")
            .field("hnsw_store", &"[redacted]")
            .field("hnsw_manifest_validation", &"[redacted]")
            .field("hnsw_max_ciphertext_bytes", &self.hnsw_max_ciphertext_bytes)
            .field("result_store", &"[redacted]")
            .field("result_manifest_validation", &"[redacted]")
            .field(
                "result_max_ciphertext_bytes",
                &self.result_max_ciphertext_bytes,
            )
            .finish()
    }
}

/// Read-only, non-authoritative observation of the paired canonical stores.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOramOwnerRecoveryStoreDispositionV1 {
    AllOld,
    AllNew,
    PartialNew,
    ThirdState,
}

#[derive(Clone, Copy)]
pub(crate) struct PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a> {
    journal_descriptor_digest: &'a str,
    prepared_state_digest: &'a str,
    immutable_manifest_digest: &'a str,
    immutable_manifest: &'a PrivateOramImmutableManifestV2,
    immutable_index: &'a PrivateOramImmutableIndexV2,
    descriptor: &'a PrivateOramOwnerJournalIndexDescriptorV1,
    old_state: &'a PrivateOramIndexStateV2,
    new_state: &'a PrivateOramIndexStateV2,
    final_buckets: &'a PrivateOramOwnerFinalBucketBatchV1,
}

impl Debug for PrivateOramOwnerIndexStoreInspectionAuthorityV1<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerIndexStoreInspectionAuthorityV1")
            .field("journal_descriptor_digest", &"[redacted]")
            .field("prepared_state_digest", &"[redacted]")
            .field("immutable_manifest_digest", &"[redacted]")
            .field("immutable_manifest", &"[redacted]")
            .field("kind", &self.descriptor.kind)
            .field("index_name", &"[redacted]")
            .field("old_epoch", &self.old_state.index_epoch)
            .field("new_epoch", &self.new_state.index_epoch)
            .field("final_bucket_count", &self.final_buckets.len())
            .finish()
    }
}

impl<'a> PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a> {
    pub(crate) fn journal_descriptor_digest(self) -> &'a str {
        self.journal_descriptor_digest
    }

    pub(crate) fn prepared_state_digest(self) -> &'a str {
        self.prepared_state_digest
    }

    pub(crate) fn immutable_manifest_digest(self) -> &'a str {
        self.immutable_manifest_digest
    }

    pub(crate) fn immutable_manifest(self) -> &'a PrivateOramImmutableManifestV2 {
        self.immutable_manifest
    }

    pub(crate) fn immutable_index(self) -> &'a PrivateOramImmutableIndexV2 {
        self.immutable_index
    }

    pub(crate) fn index_name(self) -> &'a str {
        &self.descriptor.index_name
    }

    pub(crate) fn old_state(self) -> &'a PrivateOramIndexStateV2 {
        self.old_state
    }

    pub(crate) fn new_state(self) -> &'a PrivateOramIndexStateV2 {
        self.new_state
    }

    pub(crate) fn final_bucket_refs(self) -> &'a [PrivateOramAppendBucketRefV1] {
        &self.descriptor.final_bucket_refs
    }

    pub(crate) fn final_buckets(self) -> &'a PrivateOramOwnerFinalBucketBatchV1 {
        self.final_buckets
    }

    pub(crate) fn hnsw_final_buckets(self) -> Option<&'a [qdrant_sec::PrivateHnswOramBucket]> {
        match self.final_buckets {
            PrivateOramOwnerFinalBucketBatchV1::Hnsw(buckets) => Some(buckets),
            PrivateOramOwnerFinalBucketBatchV1::Result(_) => None,
        }
    }

    pub(crate) fn result_final_buckets(self) -> Option<&'a [qdrant_sec::PrivateResultOramBucket]> {
        match self.final_buckets {
            PrivateOramOwnerFinalBucketBatchV1::Result(buckets) => Some(buckets),
            PrivateOramOwnerFinalBucketBatchV1::Hnsw(_) => None,
        }
    }
}

pub(crate) struct PrivateOramOwnerExactOldStorePairV1<'hnsw, 'result> {
    hnsw: PrivateHnswOwnerExactOldStoreTokenV1<'hnsw>,
    result: PrivateResultOwnerExactOldStoreTokenV1<'result>,
}

impl Debug for PrivateOramOwnerExactOldStorePairV1<'_, '_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerExactOldStorePairV1")
            .field("hnsw", &self.hnsw)
            .field("result", &self.result)
            .finish()
    }
}

impl PrivateOramOwnerExactOldStorePairV1<'_, '_> {
    pub(crate) fn terminal_index_states(&self) -> [PrivateOramOwnerJournalTerminalIndexStateV1; 2] {
        [
            PrivateOramOwnerJournalTerminalIndexStateV1 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: self.hnsw.index_name().to_string(),
                canonical_state_digest: self.hnsw.canonical_state_digest().to_string(),
            },
            PrivateOramOwnerJournalTerminalIndexStateV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: self.result.index_name().to_string(),
                canonical_state_digest: self.result.canonical_state_digest().to_string(),
            },
        ]
    }
}

pub(crate) struct PrivateOramOwnerExactNewStorePairV1<'hnsw, 'result> {
    hnsw: PrivateHnswOwnerExactNewStoreTokenV1<'hnsw>,
    result: PrivateResultOwnerExactNewStoreTokenV1<'result>,
}

impl Debug for PrivateOramOwnerExactNewStorePairV1<'_, '_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramOwnerExactNewStorePairV1")
            .field("hnsw", &self.hnsw)
            .field("result", &self.result)
            .finish()
    }
}

impl PrivateOramOwnerExactNewStorePairV1<'_, '_> {
    pub(crate) fn terminal_index_states(&self) -> [PrivateOramOwnerJournalTerminalIndexStateV1; 2] {
        [
            PrivateOramOwnerJournalTerminalIndexStateV1 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: self.hnsw.index_name().to_string(),
                canonical_state_digest: self.hnsw.canonical_state_digest().to_string(),
            },
            PrivateOramOwnerJournalTerminalIndexStateV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: self.result.index_name().to_string(),
                canonical_state_digest: self.result.canonical_state_digest().to_string(),
            },
        ]
    }
}

pub(crate) fn with_private_oram_owner_exact_old_store_pair_v1<R>(
    context: PrivateOramOwnerStorePairContextV1<'_>,
    action: impl for<'hnsw, 'result> FnOnce(
        PrivateOramOwnerExactOldStorePairV1<'hnsw, 'result>,
    ) -> CollectionResult<R>,
) -> CollectionResult<R> {
    let static_pair = validate_static_pair_context(
        context.owner_journal,
        context.hnsw_store,
        context.result_store,
        context.immutable_manifest,
        context.mutation_bundle,
        context.signature_verification,
    )?;
    let binding = context
        .owner_journal
        .bind_live_prepared_store_adapter_v1(context.prepared_token)
        .map_err(|_| invalid_authority())?;
    let pair = validate_child_pair_context(&static_pair, binding.snapshot())?;
    context.hnsw_store.with_owner_exact_old_store_v1(
        pair.hnsw,
        context.hnsw_max_ciphertext_bytes,
        context.hnsw_manifest_validation,
        |hnsw| {
            context.result_store.with_owner_exact_old_store_v1(
                pair.result,
                context.result_max_ciphertext_bytes,
                context.result_manifest_validation,
                |result| {
                    context
                        .owner_journal
                        .with_live_prepared_store_binding_v1(
                            context.prepared_token,
                            |live_binding| {
                                if live_binding != &binding {
                                    return Err(invalid_authority());
                                }
                                action(PrivateOramOwnerExactOldStorePairV1 { hnsw, result })
                            },
                        )
                        .map_err(|_| invalid_authority())?
                },
            )
        },
    )
}

pub(crate) fn with_private_oram_owner_exact_new_store_pair_v1<R>(
    context: PrivateOramOwnerStorePairContextV1<'_>,
    action: impl for<'hnsw, 'result> FnOnce(
        PrivateOramOwnerExactNewStorePairV1<'hnsw, 'result>,
    ) -> CollectionResult<R>,
) -> CollectionResult<R> {
    let static_pair = validate_static_pair_context(
        context.owner_journal,
        context.hnsw_store,
        context.result_store,
        context.immutable_manifest,
        context.mutation_bundle,
        context.signature_verification,
    )?;
    let binding = context
        .owner_journal
        .bind_live_prepared_store_adapter_v1(context.prepared_token)
        .map_err(|_| invalid_authority())?;
    let pair = validate_child_pair_context(&static_pair, binding.snapshot())?;
    context.hnsw_store.with_owner_exact_new_store_v1(
        pair.hnsw,
        context.hnsw_max_ciphertext_bytes,
        context.hnsw_manifest_validation,
        |hnsw| {
            context.result_store.with_owner_exact_new_store_v1(
                pair.result,
                context.result_max_ciphertext_bytes,
                context.result_manifest_validation,
                |result| {
                    context
                        .owner_journal
                        .with_live_prepared_store_binding_v1(
                            context.prepared_token,
                            |live_binding| {
                                if live_binding != &binding {
                                    return Err(invalid_authority());
                                }
                                action(PrivateOramOwnerExactNewStorePairV1 { hnsw, result })
                            },
                        )
                        .map_err(|_| invalid_authority())?
                },
            )
        },
    )
}

/// Classifies the two canonical stores while holding HNSW, result, and child locks in that order.
///
/// The returned disposition is an inert observation. It does not authorize roll-forward, abort,
/// finalize, or any other mutation.
#[doc(hidden)]
pub fn classify_private_oram_owner_recovery_store_pair_v1(
    projection: &PrivateOramOwnerRecoveryProjectionV1,
    resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
) -> CollectionResult<PrivateOramOwnerRecoveryStoreDispositionV1> {
    let static_pair = validate_static_pair_context(
        resources.owner_journal,
        resources.hnsw_store,
        resources.result_store,
        resources.immutable_manifest,
        resources.mutation_bundle,
        resources.signature_verification,
    )?;
    resources.hnsw_store.with_owner_store_lock_v1(|hnsw_lock| {
        resources
            .result_store
            .with_owner_store_lock_v1(|result_lock| {
                resources
                    .owner_journal
                    .with_revalidated_recovery_prepared_v1(projection, |binding| {
                        let pair = validate_child_pair_context(
                            &static_pair,
                            binding.untrusted_snapshot_view(),
                        )?;
                        let hnsw = hnsw_lock.classify_owner_state_v1(
                            pair.hnsw,
                            resources.hnsw_max_ciphertext_bytes,
                            resources.hnsw_manifest_validation,
                        )?;
                        let result = result_lock.classify_owner_state_v1(
                            pair.result,
                            resources.result_max_ciphertext_bytes,
                            resources.result_manifest_validation,
                        )?;
                        Ok(recovery_store_disposition(hnsw, result))
                    })
                    .map_err(|_| invalid_authority())?
            })
    })
}

fn recovery_store_disposition(
    hnsw: PrivateHnswOwnerStoreObservationV1<'_>,
    result: PrivateResultOwnerStoreObservationV1<'_>,
) -> PrivateOramOwnerRecoveryStoreDispositionV1 {
    match (hnsw, result) {
        (
            PrivateHnswOwnerStoreObservationV1::Old(_),
            PrivateResultOwnerStoreObservationV1::Old(_),
        ) => PrivateOramOwnerRecoveryStoreDispositionV1::AllOld,
        (
            PrivateHnswOwnerStoreObservationV1::New(_),
            PrivateResultOwnerStoreObservationV1::New(_),
        ) => PrivateOramOwnerRecoveryStoreDispositionV1::AllNew,
        (
            PrivateHnswOwnerStoreObservationV1::New(_),
            PrivateResultOwnerStoreObservationV1::Old(_),
        ) => PrivateOramOwnerRecoveryStoreDispositionV1::PartialNew,
        _ => PrivateOramOwnerRecoveryStoreDispositionV1::ThirdState,
    }
}

struct ValidatedStorePair<'a> {
    hnsw: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a>,
    result: PrivateOramOwnerIndexStoreInspectionAuthorityV1<'a>,
}

struct ValidatedStaticPair<'a> {
    manifest: &'a PrivateOramImmutableManifestV2,
    mutation: &'a qdrant_sec::PrivateOramAppendMutationV1,
    mutation_digest: String,
}

fn validate_static_pair_context<'a>(
    owner_journal: &PrivateOramOwnerJournal,
    hnsw_store: &PrivateHnswOramStore,
    result_store: &PrivateResultOramStore,
    immutable_manifest: &'a PrivateOramImmutableManifestBundleV2,
    mutation_bundle: &'a PrivateOramAppendMutationBundleV1,
    signature_verification: PrivateOramSignatureVerification<'a>,
) -> CollectionResult<ValidatedStaticPair<'a>> {
    validate_pair_store_paths(owner_journal, hnsw_store, result_store)?;
    let manifest = &immutable_manifest.manifest;
    let mutation = &mutation_bundle.mutation;
    validate_private_oram_immutable_manifest_v2_shape(manifest).map_err(|_| invalid_authority())?;
    validate_private_oram_immutable_manifest_v2_signature(
        manifest,
        Some(&immutable_manifest.signature),
        signature_verification,
    )
    .map_err(|_| invalid_authority())?;
    validate_private_oram_append_mutation_v1_shape(mutation).map_err(|_| invalid_authority())?;
    validate_private_oram_append_mutation_v1_signature(
        mutation,
        Some(&mutation_bundle.signature),
        signature_verification,
    )
    .map_err(|_| invalid_authority())?;
    validate_private_oram_signed_state_v2_signature(
        &mutation.old_state.state,
        Some(&mutation.old_state.signature),
        signature_verification,
    )
    .map_err(|_| invalid_authority())?;
    validate_private_oram_signed_state_v2_signature(
        &mutation.new_state.state,
        Some(&mutation.new_state.signature),
        signature_verification,
    )
    .map_err(|_| invalid_authority())?;

    let immutable_manifest_digest =
        private_oram_immutable_manifest_v2_digest(manifest).map_err(|_| invalid_authority())?;
    let mutation_digest =
        private_oram_append_mutation_v1_digest(mutation).map_err(|_| invalid_authority())?;
    let old = &mutation.old_state.state;
    let new = &mutation.new_state.state;
    if immutable_manifest_digest != mutation.manifest_digest
        || old.manifest_digest != immutable_manifest_digest
        || new.manifest_digest != immutable_manifest_digest
        || manifest.collection_id != mutation.collection_id
        || old.collection_id != mutation.collection_id
        || new.collection_id != mutation.collection_id
        || mutation.layout_generation != old.layout_generation
        || mutation.layout_generation != new.layout_generation
        || manifest.owner_signing_key_id != mutation.owner_signing_key_id
        || old.owner_signing_key_id != mutation.owner_signing_key_id
        || new.owner_signing_key_id != mutation.owner_signing_key_id
        || manifest.indexes.len() != 2
        || old.indexes.len() != 2
        || new.indexes.len() != 2
        || mutation.writebacks.len() != 2
        || manifest.indexes[0].kind() != PrivateOramIndexKindV2::Hnsw
        || manifest.indexes[1].kind() != PrivateOramIndexKindV2::Result
        || old.indexes[0].kind != PrivateOramIndexKindV2::Hnsw
        || old.indexes[1].kind != PrivateOramIndexKindV2::Result
        || new.indexes[0].kind != PrivateOramIndexKindV2::Hnsw
        || new.indexes[1].kind != PrivateOramIndexKindV2::Result
        || mutation.writebacks[0].kind != PrivateOramIndexKindV2::Hnsw
        || mutation.writebacks[1].kind != PrivateOramIndexKindV2::Result
    {
        return Err(invalid_authority());
    }

    Ok(ValidatedStaticPair {
        manifest,
        mutation,
        mutation_digest,
    })
}

fn validate_child_pair_context<'a>(
    static_pair: &'a ValidatedStaticPair<'_>,
    snapshot: &'a PrivateOramOwnerJournalSnapshotV1,
) -> CollectionResult<ValidatedStorePair<'a>> {
    // The live Prepared token or recovery rebind is the inductive authority for the full
    // owner-prepare validation. Store inspection inputs are derived only from that exact child.
    let manifest = static_pair.manifest;
    let mutation = static_pair.mutation;
    let descriptor = &snapshot.descriptor;
    let old = &mutation.old_state.state;
    let new = &mutation.new_state.state;
    if descriptor.collection_id != mutation.collection_id
        || descriptor.mutation_id != mutation.mutation_id
        || descriptor.signed_mutation_digest != static_pair.mutation_digest
        || descriptor.writer_lease_digest != mutation.writer_lease_digest
        || descriptor.writer_fence != mutation.writer_fence
        || descriptor.indexes.len() != 2
        || snapshot.final_buckets.len() != 2
    {
        return Err(invalid_authority());
    }

    let mut authorities = descriptor
        .indexes
        .iter()
        .zip(&snapshot.final_buckets)
        .zip(&manifest.indexes)
        .zip(&old.indexes)
        .zip(&new.indexes)
        .zip(&mutation.writebacks)
        .map(
            |(
                ((((descriptor, final_buckets), immutable_index), old_state), new_state),
                writeback,
            )| {
                if descriptor.kind != immutable_index.kind()
                    || descriptor.kind != old_state.kind
                    || descriptor.kind != new_state.kind
                    || descriptor.kind != writeback.kind
                    || descriptor.kind != final_buckets.buckets.kind()
                    || descriptor.index_name != immutable_index.index_name
                    || descriptor.index_name != old_state.index_name
                    || descriptor.index_name != new_state.index_name
                    || descriptor.index_name != writeback.index_name
                    || descriptor.index_name != final_buckets.index_name
                    || descriptor.old_epoch != old_state.index_epoch
                    || descriptor.new_epoch != new_state.index_epoch
                    || descriptor.old_root_hash != old_state.root_hash
                    || descriptor.new_root_hash != new_state.root_hash
                    || descriptor.writeback_digest != new_state.last_writeback_digest
                    || descriptor.read_path_count != writeback.read_path_count
                    || descriptor.read_transcript_digest != writeback.read_transcript_digest
                {
                    return Err(invalid_authority());
                }
                Ok(PrivateOramOwnerIndexStoreInspectionAuthorityV1 {
                    journal_descriptor_digest: &snapshot.descriptor.descriptor_digest,
                    prepared_state_digest: &snapshot.state.state_digest,
                    immutable_manifest_digest: &mutation.manifest_digest,
                    immutable_manifest: manifest,
                    immutable_index,
                    descriptor,
                    old_state,
                    new_state,
                    final_buckets: &final_buckets.buckets,
                })
            },
        )
        .collect::<CollectionResult<Vec<_>>>()?;
    let result = authorities.pop().ok_or_else(invalid_authority)?;
    let hnsw = authorities.pop().ok_or_else(invalid_authority)?;
    if !authorities.is_empty()
        || hnsw.old_state.kind != PrivateOramIndexKindV2::Hnsw
        || result.old_state.kind != PrivateOramIndexKindV2::Result
    {
        return Err(invalid_authority());
    }
    Ok(ValidatedStorePair { hnsw, result })
}

fn validate_pair_store_paths(
    owner_journal: &PrivateOramOwnerJournal,
    hnsw_store: &PrivateHnswOramStore,
    result_store: &PrivateResultOramStore,
) -> CollectionResult<()> {
    let expected_journal = PrivateOramOwnerJournal::new(hnsw_store.root_path());
    let collection_path = hnsw_store
        .root_path()
        .parent()
        .and_then(|private_hnsw_root| private_hnsw_root.parent())
        .ok_or_else(invalid_authority)?;
    let expected_result = PrivateResultOramStore::new(collection_path);
    if owner_journal.root_path() != expected_journal.root_path()
        || result_store.root_path() != expected_result.root_path()
    {
        return Err(invalid_authority());
    }
    Ok(())
}

fn invalid_authority() -> CollectionError {
    CollectionError::bad_request("private ORAM paired owner store authority is invalid")
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
        DistanceKind, FixedBudgetParams, OramKind, OramParams,
        PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER, PRIVATE_HNSW_ORAM_BINDING,
        PRIVATE_HNSW_ORAM_V2_BINDING, PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
        PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION, PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
        PRIVATE_RESULT_ORAM_BINDING, PRIVATE_RESULT_ORAM_V2_BINDING, PrivateHnswBucketAeadContext,
        PrivateHnswManifestValidationContext, PrivateHnswOramBucket, PrivateHnswOramManifest,
        PrivateHnswOramSignature, PrivateHnswOramUploadBundle, PrivateHnswParams,
        PrivateHnswSignatureVerification, PrivateHnswVectorEncoding,
        PrivateOramAppendIndexWritebackV1, PrivateOramAppendMutationV1,
        PrivateOramAppendWritebackDigestInput, PrivateOramImmutableIndexParamsV2,
        PrivateOramIndexCapacityV2, PrivateOramPointOperationKindV1, PrivateOramSignedStateV2,
        PrivateResultOramBucket, PrivateResultOramBucketCommitmentContext,
        PrivateResultOramManifest, PrivateResultOramManifestValidationContext,
        PrivateResultOramSignature, PrivateResultOramSignatureVerification,
        PrivateResultOramUploadBundle, ResultPrivacyMode, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER,
        VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER, package_private_oram_append_mutation_v1,
        package_private_oram_immutable_manifest_v2, package_private_oram_signed_state_v2,
        private_hnsw_bucket_commitment, private_hnsw_oram_bucket_ciphertext_bytes,
        private_oram_append_writeback_v1_digest, private_oram_immutable_manifest_v2_digest,
        private_oram_no_server_point_record_v1_digest, private_result_oram_bucket_ciphertext_bytes,
        private_result_oram_bucket_commitment, sign_private_hnsw_oram_manifest,
        sign_private_result_oram_manifest,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::private_hnsw_oram_store::PrivateHnswOramEpochState;
    use crate::private_oram_owner_journal::{
        PrivateOramOwnerFinalBucketBatchV1, PrivateOramOwnerFinalBucketIndexV1,
        PrivateOramOwnerJournalError, PrivateOramOwnerRecoveryIndexProjectionInputV1,
        PrivateOramOwnerRecoveryIndexProjectionV1, PrivateOramOwnerRecoveryProjectionV1,
    };
    use crate::private_result_oram_store::PrivateResultOramEpochState;

    const COLLECTION_ID: &str = "collection-uuid-1";
    const HNSW_INDEX: &str = "text";
    const RESULT_INDEX: &str = "private-payload";
    const HNSW_KEY: &str = "tenant-a/vector-rk";
    const RESULT_KEY: &str = "tenant-a/result-rk";
    const OWNER_KEY: &str = "tenant-a/private-oram-owner-v2";

    struct PairFixture {
        _temp: TempDir,
        public_key: Vec<u8>,
        immutable_manifest: PrivateOramImmutableManifestBundleV2,
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        hnsw_store: PrivateHnswOramStore,
        result_store: PrivateResultOramStore,
        owner_journal: PrivateOramOwnerJournal,
        prepared_token: PrivateOramDurableOwnerPreparedTokenV1,
        hnsw_final: Vec<PrivateHnswOramBucket>,
        result_final: Vec<PrivateResultOramBucket>,
    }

    fn digest(marker: u8) -> String {
        BASE64URL_NOPAD.encode(&[marker; 32])
    }

    fn oram() -> OramParams {
        OramParams {
            kind: OramKind::PathOram,
            bucket_size: 2,
            block_size_bytes: 512,
            tree_height: 1,
            path_batch_size: 2,
        }
    }

    fn capacity() -> PrivateOramIndexCapacityV2 {
        PrivateOramIndexCapacityV2 {
            bucket_count: 3,
            logical_capacity: 5,
            reserved_physical_slots: 1,
            max_client_stash_blocks: 1,
            fixed_append_read_path_count: 4,
            fixed_append_write_bucket_count: 8,
        }
    }

    fn ciphertext(size: usize, marker: u8) -> (String, String) {
        let mut bytes = vec![marker; size];
        bytes[0] = 1;
        (
            BASE64URL_NOPAD.encode(&bytes),
            BASE64URL_NOPAD.encode(Sha256::digest(&bytes).as_ref()),
        )
    }

    fn hnsw_bucket(
        manifest: &PrivateHnswOramManifest,
        bucket_id: u64,
        epoch: u64,
        marker: u8,
    ) -> PrivateHnswOramBucket {
        let (ciphertext, ciphertext_sha256) = ciphertext(
            private_hnsw_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
            marker,
        );
        let bucket_commitment = private_hnsw_bucket_commitment(
            PrivateHnswBucketAeadContext {
                collection_id: &manifest.collection_id,
                vector_name: &manifest.vector_name,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id,
                index_epoch: epoch,
            },
            &ciphertext_sha256,
        )
        .unwrap();
        PrivateHnswOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment,
        }
    }

    fn result_bucket(
        manifest: &PrivateResultOramManifest,
        bucket_id: u64,
        epoch: u64,
        marker: u8,
    ) -> PrivateResultOramBucket {
        let (ciphertext, ciphertext_sha256) = ciphertext(
            private_result_oram_bucket_ciphertext_bytes(&manifest.oram).unwrap(),
            marker,
        );
        let bucket_commitment = private_result_oram_bucket_commitment(
            PrivateResultOramBucketCommitmentContext {
                collection_id: &manifest.collection_id,
                key_id: &manifest.key_id,
                rk_id: &manifest.rk_id,
                rk_epoch: manifest.rk_epoch,
                bucket_id,
                index_epoch: epoch,
            },
            &ciphertext_sha256,
        )
        .unwrap();
        PrivateResultOramBucket {
            version: 1,
            bucket_id,
            index_epoch: epoch,
            ciphertext,
            ciphertext_sha256,
            bucket_commitment,
        }
    }

    fn hnsw_ref(bucket: &PrivateHnswOramBucket) -> PrivateOramAppendBucketRefV1 {
        PrivateOramAppendBucketRefV1 {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
            bucket_commitment: bucket.bucket_commitment.clone(),
        }
    }

    fn result_ref(bucket: &PrivateResultOramBucket) -> PrivateOramAppendBucketRefV1 {
        PrivateOramAppendBucketRefV1 {
            bucket_id: bucket.bucket_id,
            ciphertext_sha256: bucket.ciphertext_sha256.clone(),
            bucket_commitment: bucket.bucket_commitment.clone(),
        }
    }

    fn repeated_path_refs(
        final_refs: &[PrivateOramAppendBucketRefV1],
    ) -> Vec<PrivateOramAppendBucketRefV1> {
        [0, 1, 0, 2, 0, 1, 0, 2]
            .into_iter()
            .map(|index| final_refs[index].clone())
            .collect()
    }

    fn pair_fixture() -> PairFixture {
        pair_fixture_with_immutable_params(2, RESULT_KEY)
    }

    fn pair_fixture_with_immutable_dim(immutable_dim: u32) -> PairFixture {
        pair_fixture_with_immutable_params(immutable_dim, RESULT_KEY)
    }

    fn pair_fixture_with_immutable_params(
        immutable_dim: u32,
        immutable_result_key: &str,
    ) -> PairFixture {
        let temp = TempDir::new().unwrap();
        let collection_path = temp.path().join("collection");
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
        let hnsw_store = PrivateHnswOramStore::new(&collection_path, HNSW_INDEX).unwrap();
        let result_store = PrivateResultOramStore::new(&collection_path);
        let owner_journal = PrivateOramOwnerJournal::new(hnsw_store.root_path());

        let hnsw_params = PrivateHnswParams {
            m: 1,
            ef_construction: 4,
            max_layers: 2,
            fixed_neighbor_slots: 2,
        };
        let fixed_budget = FixedBudgetParams {
            enabled: true,
            upper_layer_steps: 2,
            base_layer_steps: 4,
            paths_per_round: 2,
            fixed_result_k: 1,
        };
        let mut hnsw_manifest = PrivateHnswOramManifest {
            version: 1,
            provider: VECTOR_PRIVATE_HNSW_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_HNSW_ORAM_BINDING.to_string(),
            collection_id: COLLECTION_ID.to_string(),
            vector_name: HNSW_INDEX.to_string(),
            key_id: HNSW_KEY.to_string(),
            rk_id: HNSW_KEY.to_string(),
            rk_epoch: 7,
            dim: 2,
            distance: DistanceKind::Cosine,
            hnsw: hnsw_params.clone(),
            oram: oram(),
            fixed_budget: fixed_budget.clone(),
            index_epoch: 11,
            root_hash: digest(1),
            bucket_count: 3,
            logical_node_count: 2,
            dummy_node_count: 3,
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let hnsw_buckets = (0..3)
            .map(|bucket_id| hnsw_bucket(&hnsw_manifest, bucket_id, 11, 10 + bucket_id as u8))
            .collect::<Vec<_>>();
        hnsw_manifest.root_hash = PrivateHnswOramStore::merkle_root_for_commitments(
            &hnsw_buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let hnsw_signature: PrivateHnswOramSignature =
            sign_private_hnsw_oram_manifest(&key_pair, &hnsw_manifest).unwrap();
        hnsw_store
            .write_initial_upload_bundle_with_signature(
                &PrivateHnswOramUploadBundle {
                    manifest: hnsw_manifest.clone(),
                    manifest_signature: hnsw_signature,
                    buckets: hnsw_buckets,
                },
                4096,
                PrivateHnswManifestValidationContext {
                    expected_collection_id: COLLECTION_ID,
                    expected_vector_name: HNSW_INDEX,
                    expected_key_id: HNSW_KEY,
                    expected_rk_id: HNSW_KEY,
                    min_rk_epoch: 7,
                    max_rk_epoch: 7,
                    expected_dim: 2,
                    expected_distance: DistanceKind::Cosine,
                    signature_verification: PrivateHnswSignatureVerification {
                        expected_key_id: OWNER_KEY,
                        public_key: key_pair.public_key().as_ref(),
                    },
                },
            )
            .unwrap();

        let mut result_manifest = PrivateResultOramManifest {
            version: 1,
            provider: PAYLOAD_PRIVATE_RESULT_ORAM_PROVIDER.to_string(),
            binding: PRIVATE_RESULT_ORAM_BINDING.to_string(),
            collection_id: COLLECTION_ID.to_string(),
            key_id: RESULT_KEY.to_string(),
            rk_id: RESULT_KEY.to_string(),
            rk_epoch: 7,
            oram: oram(),
            index_epoch: 11,
            root_hash: digest(2),
            bucket_count: 3,
            logical_result_count: 2,
            dummy_result_count: 3,
            owner_signing_key_id: OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let result_buckets = (0..3)
            .map(|bucket_id| result_bucket(&result_manifest, bucket_id, 11, 20 + bucket_id as u8))
            .collect::<Vec<_>>();
        result_manifest.root_hash = PrivateResultOramStore::merkle_root_for_commitments(
            &result_buckets
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let result_signature: PrivateResultOramSignature =
            sign_private_result_oram_manifest(&key_pair, &result_manifest).unwrap();
        result_store
            .write_initial_upload_bundle_with_signature(
                &PrivateResultOramUploadBundle {
                    manifest: result_manifest.clone(),
                    manifest_signature: result_signature,
                    buckets: result_buckets,
                },
                4096,
                PrivateResultOramManifestValidationContext {
                    expected_collection_id: COLLECTION_ID,
                    expected_key_id: RESULT_KEY,
                    expected_rk_id: RESULT_KEY,
                    min_rk_epoch: 7,
                    max_rk_epoch: 7,
                    signature_verification: PrivateResultOramSignatureVerification {
                        expected_key_id: OWNER_KEY,
                        public_key: key_pair.public_key().as_ref(),
                    },
                },
            )
            .unwrap();

        let immutable_manifest = PrivateOramImmutableManifestV2 {
            version: PRIVATE_ORAM_IMMUTABLE_MANIFEST_V2_VERSION,
            collection_id: COLLECTION_ID.to_string(),
            manifest_nonce: digest(3),
            indexes: vec![
                PrivateOramImmutableIndexV2 {
                    index_name: HNSW_INDEX.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Hnsw {
                        provider: VECTOR_PRIVATE_HNSW_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_HNSW_ORAM_V2_BINDING.to_string(),
                        key_id: HNSW_KEY.to_string(),
                        rk_id: HNSW_KEY.to_string(),
                        rk_epoch: 7,
                        dim: immutable_dim,
                        vector_encoding: PrivateHnswVectorEncoding::F32Le,
                        distance: DistanceKind::Cosine,
                        hnsw: hnsw_params,
                        oram: oram(),
                        fixed_search_budget: fixed_budget,
                        max_neighbor_rewrites: 1,
                    },
                    capacity: capacity(),
                },
                PrivateOramImmutableIndexV2 {
                    index_name: RESULT_INDEX.to_string(),
                    params: PrivateOramImmutableIndexParamsV2::Result {
                        provider: qdrant_sec::PAYLOAD_PRIVATE_RESULT_ORAM_V2_PROVIDER.to_string(),
                        binding: PRIVATE_RESULT_ORAM_V2_BINDING.to_string(),
                        key_id: immutable_result_key.to_string(),
                        rk_id: immutable_result_key.to_string(),
                        rk_epoch: 7,
                        oram: oram(),
                    },
                    capacity: capacity(),
                },
            ],
            result_privacy: ResultPrivacyMode::PrivatePayloadOramRequired,
            owner_signing_key_id: OWNER_KEY.to_string(),
            created_at_unix: 1_770_000_000,
        };
        let manifest_digest =
            private_oram_immutable_manifest_v2_digest(&immutable_manifest).unwrap();
        let immutable_manifest =
            package_private_oram_immutable_manifest_v2(&key_pair, immutable_manifest).unwrap();

        let hnsw_final = (0..3)
            .map(|bucket_id| hnsw_bucket(&hnsw_manifest, bucket_id, 12, 30 + bucket_id as u8))
            .collect::<Vec<_>>();
        let result_final = (0..3)
            .map(|bucket_id| result_bucket(&result_manifest, bucket_id, 12, 40 + bucket_id as u8))
            .collect::<Vec<_>>();
        let hnsw_new_root = PrivateHnswOramStore::merkle_root_for_commitments(
            &hnsw_final
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let result_new_root = PrivateResultOramStore::merkle_root_for_commitments(
            &result_final
                .iter()
                .map(|bucket| bucket.bucket_commitment.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let old_indexes = vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: HNSW_INDEX.to_string(),
                index_epoch: 11,
                root_hash: hnsw_manifest.root_hash.clone(),
                logical_count: 2,
                dummy_count: 3,
                last_writeback_digest: digest(50),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: RESULT_INDEX.to_string(),
                index_epoch: 11,
                root_hash: result_manifest.root_hash.clone(),
                logical_count: 2,
                dummy_count: 3,
                last_writeback_digest: digest(51),
            },
        ];
        let mut new_indexes = vec![
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: HNSW_INDEX.to_string(),
                index_epoch: 12,
                root_hash: hnsw_new_root,
                logical_count: 3,
                dummy_count: 2,
                last_writeback_digest: digest(52),
            },
            PrivateOramIndexStateV2 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: RESULT_INDEX.to_string(),
                index_epoch: 12,
                root_hash: result_new_root,
                logical_count: 3,
                dummy_count: 2,
                last_writeback_digest: digest(53),
            },
        ];
        let writebacks = vec![
            PrivateOramAppendIndexWritebackV1 {
                kind: PrivateOramIndexKindV2::Hnsw,
                index_name: HNSW_INDEX.to_string(),
                read_path_count: 4,
                read_transcript_digest: digest(54),
                updated_buckets: repeated_path_refs(
                    &hnsw_final.iter().map(hnsw_ref).collect::<Vec<_>>(),
                ),
            },
            PrivateOramAppendIndexWritebackV1 {
                kind: PrivateOramIndexKindV2::Result,
                index_name: RESULT_INDEX.to_string(),
                read_path_count: 4,
                read_transcript_digest: digest(55),
                updated_buckets: repeated_path_refs(
                    &result_final.iter().map(result_ref).collect::<Vec<_>>(),
                ),
            },
        ];
        for offset in 0..writebacks.len() {
            let old = &old_indexes[offset];
            let new = &new_indexes[offset];
            let writeback = &writebacks[offset];
            new_indexes[offset].last_writeback_digest =
                private_oram_append_writeback_v1_digest(PrivateOramAppendWritebackDigestInput {
                    collection_id: COLLECTION_ID,
                    manifest_digest: &manifest_digest,
                    kind: writeback.kind,
                    index_name: &writeback.index_name,
                    old_epoch: old.index_epoch,
                    new_epoch: new.index_epoch,
                    old_root_hash: &old.root_hash,
                    new_root_hash: &new.root_hash,
                    read_path_count: writeback.read_path_count,
                    read_transcript_digest: &writeback.read_transcript_digest,
                    updated_buckets: &writeback.updated_buckets,
                })
                .unwrap();
        }
        let mutation_id = digest(56);
        let old_state = package_private_oram_signed_state_v2(
            &key_pair,
            PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                layout_digest: digest(57),
                state_sequence: 1,
                indexes: old_indexes,
                client_state_digest: digest(58),
                last_mutation_id: Some(digest(63)),
                owner_signing_key_id: OWNER_KEY.to_string(),
                signed_at_unix: 1_770_000_100,
            },
        )
        .unwrap();
        let new_state = package_private_oram_signed_state_v2(
            &key_pair,
            PrivateOramSignedStateV2 {
                version: PRIVATE_ORAM_SIGNED_STATE_V2_VERSION,
                collection_id: COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                layout_digest: digest(57),
                state_sequence: 2,
                indexes: new_indexes,
                client_state_digest: digest(59),
                last_mutation_id: Some(mutation_id.clone()),
                owner_signing_key_id: OWNER_KEY.to_string(),
                signed_at_unix: 1_770_000_130,
            },
        )
        .unwrap();
        let mutation_bundle = package_private_oram_append_mutation_v1(
            &key_pair,
            PrivateOramAppendMutationV1 {
                version: PRIVATE_ORAM_APPEND_MUTATION_V1_VERSION,
                mutation_id: mutation_id.clone(),
                collection_id: COLLECTION_ID.to_string(),
                manifest_digest: manifest_digest.clone(),
                layout_generation: 1,
                writer_lease_digest: digest(60),
                writer_fence: 1,
                issued_at_unix: 1_770_000_120,
                expires_at_unix: 1_770_000_180,
                old_state,
                new_state,
                point_operation_kind: PrivateOramPointOperationKindV1::NoServerPointRecord,
                point_operation_digest: private_oram_no_server_point_record_v1_digest(
                    COLLECTION_ID,
                    &manifest_digest,
                    &mutation_id,
                )
                .unwrap(),
                writebacks,
                owner_signing_key_id: OWNER_KEY.to_string(),
            },
        )
        .unwrap();
        let (_, prepared_token) = owner_journal
            .prepare_store_adapter_test_fixture_v1(
                &mutation_bundle,
                7,
                &digest(61),
                &digest(62),
                vec![
                    PrivateOramOwnerFinalBucketIndexV1 {
                        index_name: HNSW_INDEX.to_string(),
                        buckets: PrivateOramOwnerFinalBucketBatchV1::Hnsw(hnsw_final.clone()),
                    },
                    PrivateOramOwnerFinalBucketIndexV1 {
                        index_name: RESULT_INDEX.to_string(),
                        buckets: PrivateOramOwnerFinalBucketBatchV1::Result(result_final.clone()),
                    },
                ],
            )
            .unwrap();

        PairFixture {
            _temp: temp,
            public_key: key_pair.public_key().as_ref().to_vec(),
            immutable_manifest,
            mutation_bundle,
            hnsw_store,
            result_store,
            owner_journal,
            prepared_token,
            hnsw_final,
            result_final,
        }
    }

    fn pair_context<'a>(fixture: &'a PairFixture) -> PrivateOramOwnerStorePairContextV1<'a> {
        PrivateOramOwnerStorePairContextV1 {
            owner_journal: &fixture.owner_journal,
            prepared_token: &fixture.prepared_token,
            immutable_manifest: &fixture.immutable_manifest,
            mutation_bundle: &fixture.mutation_bundle,
            signature_verification: PrivateOramSignatureVerification {
                expected_key_id: OWNER_KEY,
                public_key: &fixture.public_key,
            },
            hnsw_store: &fixture.hnsw_store,
            hnsw_manifest_validation: PrivateHnswManifestValidationContext {
                expected_collection_id: COLLECTION_ID,
                expected_vector_name: HNSW_INDEX,
                expected_key_id: HNSW_KEY,
                expected_rk_id: HNSW_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 2,
                expected_distance: DistanceKind::Cosine,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: OWNER_KEY,
                    public_key: &fixture.public_key,
                },
            },
            hnsw_max_ciphertext_bytes: 4096,
            result_store: &fixture.result_store,
            result_manifest_validation: PrivateResultOramManifestValidationContext {
                expected_collection_id: COLLECTION_ID,
                expected_key_id: RESULT_KEY,
                expected_rk_id: RESULT_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                signature_verification: PrivateResultOramSignatureVerification {
                    expected_key_id: OWNER_KEY,
                    public_key: &fixture.public_key,
                },
            },
            result_max_ciphertext_bytes: 4096,
        }
    }

    fn recovery_resources<'a>(
        fixture: &'a PairFixture,
    ) -> PrivateOramOwnerRecoveryStorePairResourcesV1<'a> {
        PrivateOramOwnerRecoveryStorePairResourcesV1 {
            owner_journal: &fixture.owner_journal,
            immutable_manifest: &fixture.immutable_manifest,
            mutation_bundle: &fixture.mutation_bundle,
            signature_verification: PrivateOramSignatureVerification {
                expected_key_id: OWNER_KEY,
                public_key: &fixture.public_key,
            },
            hnsw_store: &fixture.hnsw_store,
            hnsw_manifest_validation: PrivateHnswManifestValidationContext {
                expected_collection_id: COLLECTION_ID,
                expected_vector_name: HNSW_INDEX,
                expected_key_id: HNSW_KEY,
                expected_rk_id: HNSW_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                expected_dim: 2,
                expected_distance: DistanceKind::Cosine,
                signature_verification: PrivateHnswSignatureVerification {
                    expected_key_id: OWNER_KEY,
                    public_key: &fixture.public_key,
                },
            },
            hnsw_max_ciphertext_bytes: 4096,
            result_store: &fixture.result_store,
            result_manifest_validation: PrivateResultOramManifestValidationContext {
                expected_collection_id: COLLECTION_ID,
                expected_key_id: RESULT_KEY,
                expected_rk_id: RESULT_KEY,
                min_rk_epoch: 7,
                max_rk_epoch: 7,
                signature_verification: PrivateResultOramSignatureVerification {
                    expected_key_id: OWNER_KEY,
                    public_key: &fixture.public_key,
                },
            },
            result_max_ciphertext_bytes: 4096,
        }
    }

    #[derive(Clone, Copy)]
    enum RecoveryFixtureStoreState {
        Old,
        New,
        Third,
    }

    fn set_hnsw_recovery_state(fixture: &PairFixture, state: RecoveryFixtureStoreState) {
        let mutation = &fixture.mutation_bundle.mutation;
        match state {
            RecoveryFixtureStoreState::Old => {}
            RecoveryFixtureStoreState::New => fixture
                .hnsw_store
                .apply_owner_exact_new_test_fixture_v1(
                    &mutation.old_state.state.indexes[0],
                    &mutation.new_state.state.indexes[0],
                    &fixture.hnsw_final,
                    3,
                    4096,
                )
                .unwrap(),
            RecoveryFixtureStoreState::Third => {
                let old = fixture.hnsw_store.read_current_epoch().unwrap();
                fixture
                    .hnsw_store
                    .compare_and_swap_epoch(
                        &old,
                        &PrivateHnswOramEpochState {
                            index_epoch: old.index_epoch + 2,
                            root_hash: digest(200),
                        },
                    )
                    .unwrap();
            }
        }
    }

    fn set_result_recovery_state(fixture: &PairFixture, state: RecoveryFixtureStoreState) {
        let mutation = &fixture.mutation_bundle.mutation;
        match state {
            RecoveryFixtureStoreState::Old => {}
            RecoveryFixtureStoreState::New => fixture
                .result_store
                .apply_owner_exact_new_test_fixture_v1(
                    &mutation.old_state.state.indexes[1],
                    &mutation.new_state.state.indexes[1],
                    &fixture.result_final,
                    3,
                    4096,
                )
                .unwrap(),
            RecoveryFixtureStoreState::Third => {
                let old = fixture.result_store.read_current_epoch().unwrap();
                fixture
                    .result_store
                    .compare_and_swap_epoch(
                        &old,
                        &PrivateResultOramEpochState {
                            index_epoch: old.index_epoch + 2,
                            root_hash: digest(201),
                        },
                    )
                    .unwrap();
            }
        }
    }

    fn recovery_projection(
        fixture: &PairFixture,
    ) -> Result<PrivateOramOwnerRecoveryProjectionV1, PrivateOramOwnerJournalError> {
        let mutation = &fixture.mutation_bundle.mutation;
        let indexes = mutation
            .old_state
            .state
            .indexes
            .iter()
            .zip(&mutation.new_state.state.indexes)
            .zip(fixture.prepared_token.indexes())
            .map(|((old, new), prepared)| {
                PrivateOramOwnerRecoveryIndexProjectionV1::try_from_input(
                    PrivateOramOwnerRecoveryIndexProjectionInputV1 {
                        kind: old.kind,
                        index_name: &old.index_name,
                        old_epoch: old.index_epoch,
                        new_epoch: new.index_epoch,
                        old_root_hash: &old.root_hash,
                        new_root_hash: &new.root_hash,
                        writeback_digest: &new.last_writeback_digest,
                        prepared_journal_digest: prepared.prepared_journal_digest(),
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        PrivateOramOwnerRecoveryProjectionV1::try_new(
            7,
            &digest(61),
            &digest(62),
            &fixture.mutation_bundle,
            indexes,
        )
    }

    #[test]
    fn pair_store_paths_reject_cross_journal_and_cross_collection_substitution() {
        let temp = TempDir::new().unwrap();
        let collection = temp.path().join("collection-a");
        let hnsw = PrivateHnswOramStore::new(&collection, "text").unwrap();
        let result = PrivateResultOramStore::new(&collection);
        let journal = PrivateOramOwnerJournal::new(hnsw.root_path());
        validate_pair_store_paths(&journal, &hnsw, &result).unwrap();

        let other_hnsw = PrivateHnswOramStore::new(&collection, "other").unwrap();
        let other_journal = PrivateOramOwnerJournal::new(other_hnsw.root_path());
        let error = validate_pair_store_paths(&other_journal, &hnsw, &result)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Bad request: private ORAM paired owner store authority is invalid"
        );
        assert!(!error.contains(temp.path().to_string_lossy().as_ref()));

        let other_result = PrivateResultOramStore::new(temp.path().join("collection-b"));
        let error = validate_pair_store_paths(&journal, &hnsw, &other_result)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "Bad request: private ORAM paired owner store authority is invalid"
        );
        assert!(!error.contains(temp.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn exact_old_pair_binds_signed_mutation_prepared_journal_and_both_stores() {
        let fixture = pair_fixture();
        let states =
            with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |pair| {
                let rendered = format!("{pair:?}");
                assert!(!rendered.contains(HNSW_INDEX));
                assert!(!rendered.contains(RESULT_INDEX));
                Ok(pair.terminal_index_states())
            })
            .unwrap();

        assert_eq!(states[0].kind, PrivateOramIndexKindV2::Hnsw);
        assert_eq!(states[0].index_name, HNSW_INDEX);
        assert_eq!(states[1].kind, PrivateOramIndexKindV2::Result);
        assert_eq!(states[1].index_name, RESULT_INDEX);
        for state in states {
            assert_eq!(
                BASE64URL_NOPAD
                    .decode(state.canonical_state_digest.as_bytes())
                    .unwrap()
                    .len(),
                32
            );
        }
    }

    #[test]
    fn recovery_projection_rebinds_the_live_prepared_pair() {
        let fixture = pair_fixture();
        let projection = recovery_projection(&fixture).unwrap();
        let mut called = false;

        fixture
            .owner_journal
            .with_revalidated_recovery_prepared_v1(&projection, |binding| {
                called = true;
                let rendered = format!("{projection:?} {binding:?}");
                assert!(!rendered.contains(COLLECTION_ID));
                assert!(!rendered.contains(HNSW_INDEX));
                assert!(!rendered.contains(RESULT_INDEX));
                assert!(!rendered.contains(fixture.prepared_token.journal_descriptor_digest()));
            })
            .unwrap();

        assert!(called);
    }

    #[test]
    fn recovery_projection_constructor_rejects_noncanonical_pair_order() {
        let fixture = pair_fixture();
        let mutation = &fixture.mutation_bundle.mutation;
        let mut indexes = mutation
            .old_state
            .state
            .indexes
            .iter()
            .zip(&mutation.new_state.state.indexes)
            .zip(fixture.prepared_token.indexes())
            .map(|((old, new), prepared)| {
                PrivateOramOwnerRecoveryIndexProjectionV1::try_from_input(
                    PrivateOramOwnerRecoveryIndexProjectionInputV1 {
                        kind: old.kind,
                        index_name: &old.index_name,
                        old_epoch: old.index_epoch,
                        new_epoch: new.index_epoch,
                        old_root_hash: &old.root_hash,
                        new_root_hash: &new.root_hash,
                        writeback_digest: &new.last_writeback_digest,
                        prepared_journal_digest: prepared.prepared_journal_digest(),
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        indexes.swap(0, 1);

        assert_eq!(
            PrivateOramOwnerRecoveryProjectionV1::try_new(
                7,
                &digest(61),
                &digest(62),
                &fixture.mutation_bundle,
                indexes,
            )
            .unwrap_err(),
            PrivateOramOwnerJournalError::InvalidInput("indexes")
        );
    }

    #[test]
    fn recovery_classifier_covers_all_store_state_combinations() {
        use PrivateOramOwnerRecoveryStoreDispositionV1::{AllNew, AllOld, PartialNew, ThirdState};
        use RecoveryFixtureStoreState::{New, Old, Third};

        let cases = [
            (Old, Old, AllOld),
            (Old, New, ThirdState),
            (Old, Third, ThirdState),
            (New, Old, PartialNew),
            (New, New, AllNew),
            (New, Third, ThirdState),
            (Third, Old, ThirdState),
            (Third, New, ThirdState),
            (Third, Third, ThirdState),
        ];
        for (hnsw, result, expected) in cases {
            let fixture = pair_fixture();
            set_hnsw_recovery_state(&fixture, hnsw);
            set_result_recovery_state(&fixture, result);
            let projection = recovery_projection(&fixture).unwrap();

            let observed = classify_private_oram_owner_recovery_store_pair_v1(
                &projection,
                recovery_resources(&fixture),
            )
            .unwrap();

            assert_eq!(observed, expected);
            let rendered = format!("{projection:?} {:?}", recovery_resources(&fixture));
            assert!(!rendered.contains(COLLECTION_ID));
            assert!(!rendered.contains(&format!("\"{HNSW_INDEX}\"")));
            assert!(!rendered.contains(RESULT_INDEX));
            assert!(!rendered.contains(HNSW_KEY));
            assert!(!rendered.contains(RESULT_KEY));
            assert!(!rendered.contains(&digest(61)));
        }
    }

    #[test]
    fn recovery_classifier_errors_when_an_exact_pointer_has_corrupt_evidence() {
        let manifest_fixture = pair_fixture();
        let manifest_projection = recovery_projection(&manifest_fixture).unwrap();
        let (manifest, signature) = manifest_fixture.hnsw_store.read_manifest().unwrap();
        let mut substituted_manifest = manifest.clone();
        substituted_manifest.key_id = "tenant-a/substituted-hnsw-rk".to_string();
        manifest_fixture
            .hnsw_store
            .write_manifest(&substituted_manifest, &signature)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &manifest_projection,
                recovery_resources(&manifest_fixture),
            )
            .is_err()
        );
        manifest_fixture
            .hnsw_store
            .write_manifest(&manifest, &signature)
            .unwrap();
        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &manifest_projection,
                recovery_resources(&manifest_fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::AllOld
        );

        let commit_fixture = pair_fixture();
        let commit_projection = recovery_projection(&commit_fixture).unwrap();
        let current = commit_fixture.hnsw_store.read_current_epoch().unwrap();
        let expected_new = &commit_fixture
            .mutation_bundle
            .mutation
            .new_state
            .state
            .indexes[0];
        commit_fixture
            .hnsw_store
            .compare_and_swap_epoch(
                &current,
                &PrivateHnswOramEpochState {
                    index_epoch: expected_new.index_epoch,
                    root_hash: expected_new.root_hash.clone(),
                },
            )
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &commit_projection,
                recovery_resources(&commit_fixture),
            )
            .is_err()
        );

        let merkle_fixture = pair_fixture();
        let merkle_projection = recovery_projection(&merkle_fixture).unwrap();
        let leaves = vec![digest(210), digest(211), digest(212)];
        let root = PrivateHnswOramStore::merkle_root_for_commitments(&leaves).unwrap();
        merkle_fixture
            .hnsw_store
            .write_merkle_tree_from_commitments(11, root, leaves)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &merkle_projection,
                recovery_resources(&merkle_fixture),
            )
            .is_err()
        );

        let bucket_fixture = pair_fixture();
        let bucket_projection = recovery_projection(&bucket_fixture).unwrap();
        let (manifest, _) = bucket_fixture.hnsw_store.read_manifest().unwrap();
        let substituted = hnsw_bucket(&manifest, 0, 11, 213);
        bucket_fixture
            .hnsw_store
            .write_bucket(&substituted, 11, 3, 4096)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &bucket_projection,
                recovery_resources(&bucket_fixture),
            )
            .is_err()
        );
    }

    #[test]
    fn recovery_classifier_errors_when_result_exact_pointer_has_corrupt_evidence() {
        let manifest_fixture = pair_fixture();
        let manifest_projection = recovery_projection(&manifest_fixture).unwrap();
        let (manifest, signature) = manifest_fixture.result_store.read_manifest().unwrap();
        let mut substituted_manifest = manifest.clone();
        substituted_manifest.key_id = "tenant-a/substituted-result-rk".to_string();
        manifest_fixture
            .result_store
            .write_manifest(&substituted_manifest, &signature)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &manifest_projection,
                recovery_resources(&manifest_fixture),
            )
            .is_err()
        );
        manifest_fixture
            .result_store
            .write_manifest(&manifest, &signature)
            .unwrap();
        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &manifest_projection,
                recovery_resources(&manifest_fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::AllOld
        );

        let commit_fixture = pair_fixture();
        let commit_projection = recovery_projection(&commit_fixture).unwrap();
        let current = commit_fixture.result_store.read_current_epoch().unwrap();
        let expected_new = &commit_fixture
            .mutation_bundle
            .mutation
            .new_state
            .state
            .indexes[1];
        commit_fixture
            .result_store
            .compare_and_swap_epoch(
                &current,
                &PrivateResultOramEpochState {
                    index_epoch: expected_new.index_epoch,
                    root_hash: expected_new.root_hash.clone(),
                },
            )
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &commit_projection,
                recovery_resources(&commit_fixture),
            )
            .is_err()
        );

        let merkle_fixture = pair_fixture();
        let merkle_projection = recovery_projection(&merkle_fixture).unwrap();
        let leaves = vec![digest(220), digest(221), digest(222)];
        let root = PrivateResultOramStore::merkle_root_for_commitments(&leaves).unwrap();
        merkle_fixture
            .result_store
            .write_merkle_tree_from_commitments(11, root, leaves)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &merkle_projection,
                recovery_resources(&merkle_fixture),
            )
            .is_err()
        );

        let bucket_fixture = pair_fixture();
        let bucket_projection = recovery_projection(&bucket_fixture).unwrap();
        let (manifest, _) = bucket_fixture.result_store.read_manifest().unwrap();
        let substituted = result_bucket(&manifest, 0, 11, 223);
        bucket_fixture
            .result_store
            .write_bucket(&substituted, 11, 3, 4096)
            .unwrap();
        assert!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &bucket_projection,
                recovery_resources(&bucket_fixture),
            )
            .is_err()
        );
    }

    #[test]
    fn recovery_classifier_rejects_hnsw_and_child_lock_contention() {
        let fixture = pair_fixture();
        let projection = recovery_projection(&fixture).unwrap();

        fixture
            .hnsw_store
            .with_owner_store_lock_v1(|_| {
                let error = classify_private_oram_owner_recovery_store_pair_v1(
                    &projection,
                    recovery_resources(&fixture),
                )
                .unwrap_err()
                .to_string();
                assert!(error.contains("another private HNSW ORAM owner store operation"));
                assert!(!error.contains(COLLECTION_ID));
                Ok(())
            })
            .unwrap();

        fixture
            .owner_journal
            .with_exclusive_root_lock_test_v1(|| {
                let error = classify_private_oram_owner_recovery_store_pair_v1(
                    &projection,
                    recovery_resources(&fixture),
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    error,
                    "Bad request: private ORAM paired owner store authority is invalid"
                );
                assert!(!error.contains(COLLECTION_ID));
            })
            .unwrap();

        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &projection,
                recovery_resources(&fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::AllOld
        );
    }

    #[test]
    fn recovery_classifier_releases_hnsw_when_result_lock_is_contended() {
        let fixture = pair_fixture();
        let projection = recovery_projection(&fixture).unwrap();

        fixture
            .result_store
            .with_owner_store_lock_v1(|_| {
                let error = classify_private_oram_owner_recovery_store_pair_v1(
                    &projection,
                    recovery_resources(&fixture),
                )
                .unwrap_err()
                .to_string();
                assert!(error.contains("another private result ORAM owner store operation"));
                assert!(!error.contains(COLLECTION_ID));
                Ok(())
            })
            .unwrap();

        assert_eq!(
            classify_private_oram_owner_recovery_store_pair_v1(
                &projection,
                recovery_resources(&fixture),
            )
            .unwrap(),
            PrivateOramOwnerRecoveryStoreDispositionV1::AllOld
        );
    }

    #[test]
    fn exact_old_pair_rejects_mutation_signature_substitution_before_callback() {
        let fixture = pair_fixture();
        let mut tampered_mutation = fixture.mutation_bundle.clone();
        let mut signature = BASE64URL_NOPAD
            .decode(tampered_mutation.signature.sig.as_bytes())
            .unwrap();
        signature[0] ^= 1;
        tampered_mutation.signature.sig = BASE64URL_NOPAD.encode(&signature);
        let mut context = pair_context(&fixture);
        context.mutation_bundle = &tampered_mutation;
        let mut called = false;

        let error = with_private_oram_owner_exact_old_store_pair_v1(context, |_| {
            called = true;
            Ok(())
        })
        .unwrap_err()
        .to_string();

        assert!(!called);
        assert_eq!(
            error,
            "Bad request: private ORAM paired owner store authority is invalid"
        );
        assert!(!error.contains(&tampered_mutation.signature.sig));
    }

    #[test]
    fn exact_old_pair_rejects_signed_v2_to_physical_hnsw_mismatch() {
        let fixture = pair_fixture_with_immutable_dim(3);
        let mut called = false;

        let error = with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |_| {
            called = true;
            Ok(())
        })
        .unwrap_err()
        .to_string();

        assert!(!called);
        assert_eq!(
            error,
            "Bad request: private HNSW ORAM owner canonical store state does not match"
        );
        assert!(!error.contains(COLLECTION_ID));
        assert!(!error.contains(HNSW_KEY));
    }

    #[test]
    fn exact_old_pair_rejects_signed_v2_to_physical_result_mismatch() {
        let fixture = pair_fixture_with_immutable_params(2, "tenant-a/substituted-result-rk");
        let mut called = false;

        let error = with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |_| {
            called = true;
            Ok(())
        })
        .unwrap_err()
        .to_string();

        assert!(!called);
        assert_eq!(
            error,
            "Bad request: private result ORAM owner canonical store state does not match"
        );
        assert!(!error.contains(COLLECTION_ID));
        assert!(!error.contains("substituted-result-rk"));
    }

    #[test]
    fn exact_new_pair_binds_both_digest_commits_and_final_bucket_bodies() {
        let fixture = pair_fixture();
        let old_states =
            with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |pair| {
                Ok(pair.terminal_index_states())
            })
            .unwrap();
        let old = &fixture.mutation_bundle.mutation.old_state.state.indexes;
        let new = &fixture.mutation_bundle.mutation.new_state.state.indexes;
        fixture
            .hnsw_store
            .apply_owner_exact_new_test_fixture_v1(&old[0], &new[0], &fixture.hnsw_final, 3, 4096)
            .unwrap();
        fixture
            .result_store
            .apply_owner_exact_new_test_fixture_v1(&old[1], &new[1], &fixture.result_final, 3, 4096)
            .unwrap();

        let new_states =
            with_private_oram_owner_exact_new_store_pair_v1(pair_context(&fixture), |pair| {
                Ok(pair.terminal_index_states())
            })
            .unwrap();

        assert_eq!(new_states[0].kind, PrivateOramIndexKindV2::Hnsw);
        assert_eq!(new_states[1].kind, PrivateOramIndexKindV2::Result);
        assert_ne!(
            old_states[0].canonical_state_digest,
            new_states[0].canonical_state_digest
        );
        assert_ne!(
            old_states[1].canonical_state_digest,
            new_states[1].canonical_state_digest
        );
    }

    #[test]
    fn mixed_old_new_pair_mints_neither_phase_token() {
        let fixture = pair_fixture();
        let old = &fixture.mutation_bundle.mutation.old_state.state.indexes;
        let new = &fixture.mutation_bundle.mutation.new_state.state.indexes;
        fixture
            .hnsw_store
            .apply_owner_exact_new_test_fixture_v1(&old[0], &new[0], &fixture.hnsw_final, 3, 4096)
            .unwrap();

        let mut old_called = false;
        let old_error =
            with_private_oram_owner_exact_old_store_pair_v1(pair_context(&fixture), |_| {
                old_called = true;
                Ok(())
            })
            .unwrap_err()
            .to_string();
        let mut new_called = false;
        let new_error =
            with_private_oram_owner_exact_new_store_pair_v1(pair_context(&fixture), |_| {
                new_called = true;
                Ok(())
            })
            .unwrap_err()
            .to_string();

        assert!(!old_called);
        assert!(!new_called);
        assert_eq!(
            old_error,
            "Bad request: private HNSW ORAM owner canonical store state does not match"
        );
        assert_eq!(
            new_error,
            "Bad request: private result ORAM owner canonical store state does not match"
        );
    }
}
