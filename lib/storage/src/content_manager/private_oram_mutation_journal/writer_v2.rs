use std::fmt::{self, Debug, Formatter};
use std::io::{self, Write};
use std::path::Path;

use tempfile::NamedTempFile;

use super::*;
use crate::content_manager::private_oram_mutation_state_v2::{
    DecodedPrivateOramMutationStateUntrusted, PrivateOramMutationJournalPhaseV2,
    PrivateOramMutationJournalStateV2, PrivateOramMutationOwnerTerminalBatchV2,
    PrivateOramMutationPointStageEvidenceV2, canonical_private_oram_mutation_state_history_v2,
    decode_untrusted_private_oram_mutation_state, initial_private_oram_mutation_state_v2,
    next_private_oram_mutation_state_v2, private_oram_point_stage_evidence_v2_from_durable_token,
    record_digest_at_phase_v2, validate_private_oram_mutation_state_v2_structure,
};

const STATE_RECORDS_DIR: &str = "state_records";
const STATE_RECORD_FILE_SUFFIX: &str = ".json";
const FORMAT_FILE: &str = "format.json";
const V2_JOURNAL_FORMAT_VERSION: u16 = 2;
const MAX_FORMAT_BYTES: u64 = 1 << 12;
const MAX_V2_STATE_RECORDS: usize = 7;
const MAX_V2_HISTORY_BYTES: u64 = 256 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrivateOramMutationJournalFormatV2 {
    state_version: u16,
    descriptor_digest: String,
}

#[derive(Clone, PartialEq, Eq)]
pub(in crate::content_manager) struct PrivateOramMutationJournalStructuralSnapshotV2 {
    pub(super) descriptor: PrivateOramMutationJournalDescriptorV1,
    pub(super) state: PrivateOramMutationJournalStateV2,
    pending_next: Option<PrivateOramMutationJournalStateV2>,
}

impl Debug for PrivateOramMutationJournalStructuralSnapshotV2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramMutationJournalStructuralSnapshotV2")
            .field("descriptor", &self.descriptor)
            .field("state", &self.state)
            .field("has_pending_next", &self.pending_next.is_some())
            .finish()
    }
}

impl PrivateOramMutationJournalStructuralSnapshotV2 {
    pub(in crate::content_manager) fn validated_descriptor(
        &self,
    ) -> &PrivateOramMutationJournalDescriptorV1 {
        &self.descriptor
    }

    pub(in crate::content_manager) fn effective_state(&self) -> &PrivateOramMutationJournalStateV2 {
        self.pending_next.as_ref().unwrap_or(&self.state)
    }

    #[cfg(test)]
    pub(super) fn with_effective_state_for_test(
        &self,
        state: PrivateOramMutationJournalStateV2,
    ) -> Result<Self, PrivateOramMutationJournalError> {
        validate_private_oram_mutation_state_v2_structure(&self.descriptor, &state)?;
        Ok(Self {
            descriptor: self.descriptor.clone(),
            state,
            pending_next: None,
        })
    }

    #[cfg(test)]
    pub(super) fn pending_next_for_test(&self) -> Option<&PrivateOramMutationJournalStateV2> {
        self.pending_next.as_ref()
    }
}

impl PrivateOramMutationJournal {
    pub(super) fn begin_v2(
        &self,
        coordinator_peer_id: PeerId,
        owner_peer_ids: &[PeerId],
        mutation_bundle: PrivateOramAppendMutationBundleV1,
        preparing_lease: PrivateOramMutationLease,
        expected_consensus_old_state: PrivateOramConsensusCollectionStateV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let descriptor = self.build_descriptor(
            coordinator_peer_id,
            owner_peer_ids,
            mutation_bundle,
            preparing_lease,
            expected_consensus_old_state,
        )?;
        self.ensure_root_layout()?;
        let lock = self.acquire_lock()?;
        let root = lock.pinned_root_path();
        let active = root.join(ACTIVE_DIR);
        let temp = root.join(TEMP_DIR);
        if path_entry_exists(&active)? {
            let current = self.load_v2_locked_at_root(&root)?;
            if current.descriptor == descriptor {
                sync_directory(&active)
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                sync_directory(&root)
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                sync_directory(&temp)
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                lock.validate_root_identity()?;
                return Ok(current);
            }
            return Err(PrivateOramMutationJournalError::ConcurrentMutation);
        }

        let state = initial_private_oram_mutation_state_v2(&descriptor)?;
        let format = PrivateOramMutationJournalFormatV2 {
            state_version: V2_JOURNAL_FORMAT_VERSION,
            descriptor_digest: descriptor.descriptor_digest.clone(),
        };
        let staging = tempfile::Builder::new()
            .prefix("begin-v2-")
            .tempdir_in(&temp)
            .map_err(PrivateOramMutationJournalError::Io)?;
        set_private_directory_permissions(staging.path())?;
        create_private_directory(&staging.path().join(ACTIVE_TEMP_DIR))?;
        let records = staging.path().join(STATE_RECORDS_DIR);
        create_private_directory(&records)?;
        write_new_json_private(
            &staging.path().join(DESCRIPTOR_FILE),
            &descriptor,
            MAX_DESCRIPTOR_BYTES,
        )?;
        write_new_json_private(&staging.path().join(FORMAT_FILE), &format, MAX_FORMAT_BYTES)?;
        write_new_json_private(&staging.path().join(STATE_FILE), &state, MAX_STATE_BYTES)?;
        write_new_json_private(
            &records.join(state_record_file_name(state.sequence)?),
            &state,
            MAX_STATE_BYTES,
        )?;
        sync_directory(&records).map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        sync_directory(staging.path())?;

        let staging_path = staging.keep();
        match fs::rename(&staging_path, &active) {
            Ok(()) => {}
            Err(error) => {
                if path_entry_exists(&active)? {
                    let current = self.load_v2_locked_at_root(&root)?;
                    if current.descriptor == descriptor
                        && current.state == state
                        && current.pending_next.is_none()
                    {
                        sync_directory(&root)
                            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                        sync_directory(&temp)
                            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                        lock.validate_root_identity()?;
                        return Ok(current);
                    }
                }
                return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                    PrivateOramMutationJournalError::ConcurrentMutation
                } else {
                    PrivateOramMutationJournalError::Indeterminate
                });
            }
        }
        sync_directory(&root).map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        sync_directory(&temp).map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        let loaded = self.load_v2_locked_at_root(&root)?;
        lock.validate_root_identity()?;
        Ok(loaded)
    }

    pub(super) fn load_v2(
        &self,
    ) -> Result<
        Option<PrivateOramMutationJournalStructuralSnapshotV2>,
        PrivateOramMutationJournalError,
    > {
        if !path_entry_exists(&self.root)? {
            return Ok(None);
        }
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let lock = self.acquire_lock()?;
        let root = lock.pinned_root_path();
        if !path_entry_exists(&root.join(ACTIVE_DIR))? {
            lock.validate_root_identity()?;
            return Ok(None);
        }
        let snapshot = self.load_v2_locked_at_root(&root)?;
        lock.validate_root_identity()?;
        Ok(Some(snapshot))
    }

    #[cfg(test)]
    pub(super) fn mark_owners_prepared_v2(
        &self,
        owner_prepares: Vec<PrivateOramMutationOwnerPrepareEvidenceV1>,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let expected = owner_prepares.clone();
        self.transition_v2(
            PrivateOramMutationJournalPhaseV2::OwnersPrepared,
            move |descriptor, state| {
                validate_owner_prepares(descriptor, &expected)?;
                (state.owner_prepares == expected)
                    .then_some(())
                    .ok_or(PrivateOramMutationJournalError::InvalidTransition)
            },
            move |descriptor, _, next| {
                validate_owner_prepares(descriptor, &owner_prepares)?;
                next.owner_prepares = owner_prepares;
                Ok(())
            },
        )
    }

    #[cfg(test)]
    pub(super) fn validated_point_stage_parent_v2(
        &self,
    ) -> Result<PrivateOramValidatedPointStageParentV1, PrivateOramMutationJournalError> {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        let (phase, owners_prepared_record_digest, expected_child_descriptor_digest) =
            match (&snapshot.state.phase, snapshot.state.point_stage.as_ref()) {
                (PrivateOramMutationJournalPhaseV2::OwnersPrepared, None) => (
                    PrivateOramValidatedPointStageParentPhaseV1::OwnersPrepared,
                    snapshot.state.record_digest.clone(),
                    None,
                ),
                (
                    PrivateOramMutationJournalPhaseV2::PointStageDurable,
                    Some(PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
                        child_descriptor_digest,
                        parent_owners_prepared_record_digest,
                        ..
                    }),
                ) => (
                    PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
                    parent_owners_prepared_record_digest.clone(),
                    Some(child_descriptor_digest.clone()),
                ),
                (
                    PrivateOramMutationJournalPhaseV2::PointStageDurable,
                    Some(PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
                        parent_owners_prepared_record_digest,
                    }),
                ) => (
                    PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
                    parent_owners_prepared_record_digest.clone(),
                    None,
                ),
                _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
            };
        Ok(PrivateOramValidatedPointStageParentV1 {
            descriptor: snapshot.descriptor,
            owners_prepared_record_digest,
            phase,
            expected_child_descriptor_digest,
        })
    }

    pub(super) fn mark_private_point_stage_durable_v2(
        &self,
        durable_stage: &PrivateOramDurablePointStageTokenV1,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let evidence = private_oram_point_stage_evidence_v2_from_durable_token(durable_stage);
        self.mark_point_stage_durable_v2(
            durable_stage.parent_descriptor_digest(),
            durable_stage.parent_owners_prepared_record_digest(),
            evidence,
        )
    }

    pub(super) fn mark_no_server_point_stage_durable_v2(
        &self,
        parent: &PrivateOramValidatedPointStageParentV1,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        self.mark_point_stage_durable_v2(
            &parent.descriptor.descriptor_digest,
            &parent.owners_prepared_record_digest,
            PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord {
                parent_owners_prepared_record_digest: parent.owners_prepared_record_digest.clone(),
            },
        )
    }

    #[cfg(test)]
    pub(super) fn validated_decision_for_v2_state(
        &self,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        durable_point_stage: Option<&PrivateOramDurablePointStageTokenV1>,
    ) -> Result<PrivateOramValidatedMutationDecisionV2, PrivateOramMutationJournalError> {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_live_point_stage_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
            durable_point_stage,
        )?;
        let (_, _, evidence) =
            validated_reconcile_decision_for_v2_snapshot(&snapshot, reconcile_snapshot)?;
        let effective = snapshot.effective_state();
        Ok(PrivateOramValidatedMutationDecisionV2 {
            evidence,
            expected_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
            expected_predecessor_record_digest: record_digest_at_phase_v2(
                &snapshot.descriptor,
                effective,
                PrivateOramMutationJournalPhaseV2::PointStageDurable,
            )?,
        })
    }

    pub(super) fn mark_decision_durable_v2(
        &self,
        decision: &PrivateOramValidatedMutationDecisionV2,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedDecisionDurableV2,
        ),
        PrivateOramMutationJournalError,
    > {
        let expected = decision.evidence.clone();
        let expected_descriptor_digest = decision.expected_descriptor_digest.clone();
        let expected_predecessor_record_digest =
            decision.expected_predecessor_record_digest.clone();
        let snapshot = self.transition_v2(
            PrivateOramMutationJournalPhaseV2::DecisionDurable,
            move |descriptor, state| {
                (descriptor.descriptor_digest == expected_descriptor_digest
                    && record_digest_at_phase_v2(
                        descriptor,
                        state,
                        PrivateOramMutationJournalPhaseV2::PointStageDurable,
                    )? == expected_predecessor_record_digest
                    && state.decision.as_ref() == Some(&expected))
                .then_some(())
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)
            },
            |descriptor, current, next| {
                if descriptor.descriptor_digest != decision.expected_descriptor_digest
                    || current.record_digest != decision.expected_predecessor_record_digest
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                next.decision = Some(decision.evidence.clone());
                Ok(())
            },
        )?;
        let decision_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            &snapshot.state,
            PrivateOramMutationJournalPhaseV2::DecisionDurable,
        )?;
        Ok((
            snapshot,
            PrivateOramValidatedDecisionDurableV2 {
                evidence: decision.evidence.clone(),
                expected_descriptor_digest: decision.expected_descriptor_digest.clone(),
                decision_record_digest,
            },
        ))
    }

    #[cfg(test)]
    pub(super) fn mark_remote_terminal_claims_v2_for_test(
        &self,
        decision: &PrivateOramValidatedDecisionDurableV2,
        outcomes: &[PrivateOramTlsEndpointOwnerTerminalClaimV2],
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedRemotesTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        let mut owners = outcomes
            .iter()
            .map(|outcome| {
                let expected_digest = private_oram_owner_terminal_evidence_v2_digest(
                    &decision.expected_descriptor_digest,
                    outcome.kind,
                    &outcome.evidence,
                )?;
                if outcome.evidence.terminal_evidence_digest != expected_digest {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                Ok((outcome.kind, outcome.evidence.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        owners.sort_unstable_by_key(|(_, evidence)| evidence.owner_peer_id);
        if owners
            .windows(2)
            .any(|pair| pair[0].1.owner_peer_id == pair[1].1.owner_peer_id)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let kind = match decision.evidence.kind() {
            ValidatedPrivateOramMutationDecisionKindV2::ExactNew => {
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew
            }
            ValidatedPrivateOramMutationDecisionKindV2::ExactOldAbort => {
                PrivateOramMutationOwnerTerminalKindV2::AbortedOld
            }
        };
        if owners.iter().any(|(owner_kind, _)| *owner_kind != kind) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let batch = PrivateOramMutationOwnerTerminalBatchV2 {
            kind,
            owners: owners.into_iter().map(|(_, evidence)| evidence).collect(),
        };
        let snapshot = self.mark_owner_terminal_batch_v2(
            None,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
            &decision.evidence,
            &decision.expected_descriptor_digest,
            &decision.decision_record_digest,
            batch,
        )?;
        let remotes_terminal_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            &snapshot.state,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
        )?;
        Ok((
            snapshot,
            PrivateOramValidatedRemotesTerminalV2 {
                evidence: decision.evidence.clone(),
                expected_descriptor_digest: decision.expected_descriptor_digest.clone(),
                remotes_terminal_record_digest,
            },
        ))
    }

    #[cfg(test)]
    pub(super) fn mark_remotes_terminal_v2(
        &self,
        decision: &PrivateOramValidatedDecisionDurableV2,
        outcomes: &[PrivateOramValidatedOwnerRecoveryOutcomeV1],
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedRemotesTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        let snapshot = self.mark_owner_terminals_v2(
            None,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
            &decision.evidence,
            &decision.expected_descriptor_digest,
            &decision.decision_record_digest,
            outcomes,
        )?;
        let remotes_terminal_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            &snapshot.state,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
        )?;
        Ok((
            snapshot,
            PrivateOramValidatedRemotesTerminalV2 {
                evidence: decision.evidence.clone(),
                expected_descriptor_digest: decision.expected_descriptor_digest.clone(),
                remotes_terminal_record_digest,
            },
        ))
    }

    #[cfg(test)]
    pub(super) fn mark_local_terminal_v2(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        outcome: &PrivateOramValidatedOwnerRecoveryOutcomeV1,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.mark_local_terminal_v2_with_lock(None, remotes, outcome)
    }

    fn mark_local_terminal_v2_with_lock(
        &self,
        lock: Option<&PrivateOramMutationJournalLock>,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        outcome: &PrivateOramValidatedOwnerRecoveryOutcomeV1,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        let snapshot = self.mark_owner_terminals_v2(
            lock,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
            &remotes.evidence,
            &remotes.expected_descriptor_digest,
            &remotes.remotes_terminal_record_digest,
            std::slice::from_ref(outcome),
        )?;
        let local_terminal_record_digest = record_digest_at_phase_v2(
            &snapshot.descriptor,
            &snapshot.state,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        )?;
        Ok((
            snapshot,
            PrivateOramValidatedLocalTerminalV2 {
                evidence: remotes.evidence.clone(),
                expected_descriptor_digest: remotes.expected_descriptor_digest.clone(),
                local_terminal_record_digest,
            },
        ))
    }

    pub(super) fn recover_local_owner_and_mark_terminal_v2(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_local_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.recover_local_owner_and_mark_terminal_v2_with(
            remotes,
            reconcile_snapshot,
            authenticated_local_owner_peer_id,
            resources,
            |parent_lock, outcome| {
                self.mark_local_terminal_v2_with_lock(Some(parent_lock), remotes, outcome)
            },
        )
    }

    fn recover_local_owner_and_mark_terminal_v2_with(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_local_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
        publish_local_terminal: impl FnOnce(
            &PrivateOramMutationJournalLock,
            &PrivateOramValidatedOwnerRecoveryOutcomeV1,
        ) -> Result<
            (
                PrivateOramMutationJournalStructuralSnapshotV2,
                PrivateOramValidatedLocalTerminalV2,
            ),
            PrivateOramMutationJournalError,
        >,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.validate_owner_recovery_resources_v1(&resources)?;
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let parent_lock = self.acquire_lock()?;
        let root = parent_lock.pinned_root_path();
        let snapshot = self.load_v2_locked_at_root(&root)?;
        if snapshot.state.phase.sequence()
            < PrivateOramMutationJournalPhaseV2::RemotesTerminal.sequence()
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_remotes_terminal_token_v2(&snapshot.descriptor, &snapshot.state, remotes)?;
        if authenticated_local_owner_peer_id != snapshot.descriptor.coordinator_peer_id {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let (active_lease, disposition, decision) =
            validated_reconcile_decision_for_v2_snapshot(&snapshot, reconcile_snapshot)?;
        if decision != remotes.evidence {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let authority = build_owner_recovery_authority_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
            &active_lease,
            disposition,
            authenticated_local_owner_peer_id,
        )?;
        let live = PrivateOramLiveOwnerRecoveryAuthorityV1::new(
            authority,
            &parent_lock,
            &self.owner_recovery_parent_bridge,
            &self.owner_recovery_parent_verifier,
        );
        let resolved = live
            .recover_pair_then_v1(resources, |outcome| {
                publish_local_terminal(&parent_lock, &outcome)
            })
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        drop(live);
        let resolved = resolved.map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        let loaded = self
            .load_v2_locked_at_root(&root)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        if loaded != resolved.0 {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
        validate_local_terminal_token_v2(&loaded.descriptor, loaded.effective_state(), &resolved.1)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        parent_lock
            .validate_root_identity()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        Ok(resolved)
    }

    #[cfg(test)]
    pub(super) fn recover_local_owner_with_parent_terminal_failure_v2(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_local_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.recover_local_owner_and_mark_terminal_v2_with(
            remotes,
            reconcile_snapshot,
            authenticated_local_owner_peer_id,
            resources,
            |_, _| Err(PrivateOramMutationJournalError::InvalidTransition),
        )
    }

    #[cfg(test)]
    pub(super) fn recover_local_owner_with_post_parent_terminal_failure_v2(
        &self,
        remotes: &PrivateOramValidatedRemotesTerminalV2,
        reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
        authenticated_local_owner_peer_id: PeerId,
        resources: PrivateOramOwnerRecoveryStorePairResourcesV1<'_>,
    ) -> Result<
        (
            PrivateOramMutationJournalStructuralSnapshotV2,
            PrivateOramValidatedLocalTerminalV2,
        ),
        PrivateOramMutationJournalError,
    > {
        self.recover_local_owner_and_mark_terminal_v2_with(
            remotes,
            reconcile_snapshot,
            authenticated_local_owner_peer_id,
            resources,
            |parent_lock, outcome| {
                self.mark_local_terminal_v2_with_lock(Some(parent_lock), remotes, outcome)?;
                Err(PrivateOramMutationJournalError::InvalidTransition)
            },
        )
    }

    #[cfg(test)]
    pub(super) fn mark_private_point_resolved_v2(
        &self,
        local: &PrivateOramValidatedLocalTerminalV2,
        point_store: &PrivateOramPointStagingStore,
        outcome: PrivateOramPointResolutionOutcomeV2,
        receipt: PrivateOramPointResolutionReceiptV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let collection_path = self
            .root
            .parent()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if !point_store.belongs_to_collection(collection_path) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let parent_lock = self.acquire_lock()?;
        let root = parent_lock.pinned_root_path();
        let snapshot = self.load_v2_locked_at_root(&root)?;
        validate_local_terminal_token_v2(&snapshot.descriptor, snapshot.effective_state(), local)?;
        let evidence = match outcome {
            PrivateOramPointResolutionOutcomeV2::PublishedExactNew => {
                RawPrivateOramMutationPointResolutionEvidenceV2::PublishedExactNew { receipt }
            }
            PrivateOramPointResolutionOutcomeV2::AbortedExactOld => {
                RawPrivateOramMutationPointResolutionEvidenceV2::AbortedExactOld { receipt }
            }
        };
        validate_point_resolution_candidate_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
            &evidence,
        )?;
        if snapshot.effective_state().phase == PrivateOramMutationJournalPhaseV2::PointResolved {
            return self.mark_point_resolved_from_evidence_v2(Some(&parent_lock), local, &evidence);
        }
        let point_parent = validated_point_stage_parent_for_terminal_v2(
            &snapshot.descriptor,
            snapshot.effective_state(),
        )?;
        let resolved = point_store.with_consumed_live_stage(&point_parent, |live| {
            validate_live_point_stage_v2(
                &snapshot.descriptor,
                snapshot.effective_state(),
                Some(live.durable()),
            )?;
            if live.frame().point.vectors.is_empty() {
                validate_point_resolution_candidate_v2(
                    &snapshot.descriptor,
                    snapshot.effective_state(),
                    &evidence,
                )?;
                self.mark_point_resolved_from_evidence_v2(Some(&parent_lock), local, &evidence)
            } else {
                Err(PrivateOramMutationJournalError::InvalidTransition)
            }
        })??;
        parent_lock
            .validate_root_identity()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        Ok(resolved)
    }

    pub(super) fn mark_no_server_point_resolved_v2(
        &self,
        local: &PrivateOramValidatedLocalTerminalV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let evidence = RawPrivateOramMutationPointResolutionEvidenceV2::NoServerPointRecord {
            decision_kind: local.evidence.kind(),
            parent_local_terminal_record_digest: local.local_terminal_record_digest.clone(),
        };
        self.mark_point_resolved_from_evidence_v2(None, local, &evidence)
    }

    fn mark_point_resolved_from_evidence_v2(
        &self,
        lock: Option<&PrivateOramMutationJournalLock>,
        local: &PrivateOramValidatedLocalTerminalV2,
        evidence: &RawPrivateOramMutationPointResolutionEvidenceV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let expected_evidence = evidence.clone();
        let expected_decision = local.evidence.clone();
        let verify_descriptor_digest = local.expected_descriptor_digest.clone();
        let verify_local_record_digest = local.local_terminal_record_digest.clone();
        let update_descriptor_digest = local.expected_descriptor_digest.clone();
        let update_local_record_digest = local.local_terminal_record_digest.clone();
        let verify_existing =
            move |descriptor: &PrivateOramMutationJournalDescriptorV1,
                  state: &PrivateOramMutationJournalStateV2| {
                (descriptor.descriptor_digest == verify_descriptor_digest
                    && record_digest_at_phase_v2(
                        descriptor,
                        state,
                        PrivateOramMutationJournalPhaseV2::LocalTerminal,
                    )? == verify_local_record_digest
                    && state.decision.as_ref() == Some(&expected_decision)
                    && state.point_resolution.as_ref() == Some(&expected_evidence))
                .then_some(())
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)
            };
        let update = move |descriptor: &PrivateOramMutationJournalDescriptorV1,
                           current: &PrivateOramMutationJournalStateV2,
                           next: &mut PrivateOramMutationJournalStateV2| {
            if descriptor.descriptor_digest != update_descriptor_digest
                || current.record_digest != update_local_record_digest
                || current.decision.as_ref() != Some(&local.evidence)
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            next.point_resolution = Some(evidence.clone());
            Ok(())
        };
        if let Some(lock) = lock {
            self.transition_v2_locked(
                lock,
                PrivateOramMutationJournalPhaseV2::PointResolved,
                verify_existing,
                update,
            )
        } else {
            self.transition_v2(
                PrivateOramMutationJournalPhaseV2::PointResolved,
                verify_existing,
                update,
            )
        }
    }

    #[cfg(test)]
    pub(super) fn validated_local_terminal_for_current_v2(
        &self,
    ) -> Result<PrivateOramValidatedLocalTerminalV2, PrivateOramMutationJournalError> {
        let snapshot = self
            .load_v2()?
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        validated_local_terminal_from_v2_snapshot(&snapshot)
    }

    fn mark_owner_terminals_v2(
        &self,
        lock: Option<&PrivateOramMutationJournalLock>,
        phase: PrivateOramMutationJournalPhaseV2,
        decision: &RawPrivateOramMutationDecisionEvidenceV2,
        expected_descriptor_digest: &str,
        expected_predecessor_record_digest: &str,
        outcomes: &[PrivateOramValidatedOwnerRecoveryOutcomeV1],
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let mut owners = outcomes
            .iter()
            .map(validated_owner_terminal_evidence_v2)
            .collect::<Result<Vec<_>, _>>()?;
        owners.sort_unstable_by_key(|(_, evidence)| evidence.owner_peer_id);
        let kind = match decision.kind() {
            ValidatedPrivateOramMutationDecisionKindV2::ExactNew => {
                PrivateOramMutationOwnerTerminalKindV2::FinalizedNew
            }
            ValidatedPrivateOramMutationDecisionKindV2::ExactOldAbort => {
                PrivateOramMutationOwnerTerminalKindV2::AbortedOld
            }
        };
        if owners.iter().any(|(owner_kind, _)| *owner_kind != kind) {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let batch = PrivateOramMutationOwnerTerminalBatchV2 {
            kind,
            owners: owners.into_iter().map(|(_, evidence)| evidence).collect(),
        };
        self.mark_owner_terminal_batch_v2(
            lock,
            phase,
            decision,
            expected_descriptor_digest,
            expected_predecessor_record_digest,
            batch,
        )
    }

    fn mark_owner_terminal_batch_v2(
        &self,
        lock: Option<&PrivateOramMutationJournalLock>,
        phase: PrivateOramMutationJournalPhaseV2,
        decision: &RawPrivateOramMutationDecisionEvidenceV2,
        expected_descriptor_digest: &str,
        expected_predecessor_record_digest: &str,
        batch: PrivateOramMutationOwnerTerminalBatchV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let expected = batch.clone();
        let expected_decision = decision.clone();
        let verify_descriptor_digest = expected_descriptor_digest.to_string();
        let verify_predecessor_record_digest = expected_predecessor_record_digest.to_string();
        let update_descriptor_digest = expected_descriptor_digest.to_string();
        let update_predecessor_record_digest = expected_predecessor_record_digest.to_string();
        let predecessor_phase = match phase {
            PrivateOramMutationJournalPhaseV2::RemotesTerminal => {
                PrivateOramMutationJournalPhaseV2::DecisionDurable
            }
            PrivateOramMutationJournalPhaseV2::LocalTerminal => {
                PrivateOramMutationJournalPhaseV2::RemotesTerminal
            }
            _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
        };
        let verify_existing =
            move |descriptor: &PrivateOramMutationJournalDescriptorV1,
                  state: &PrivateOramMutationJournalStateV2| {
                let existing = match phase {
                    PrivateOramMutationJournalPhaseV2::RemotesTerminal => {
                        state.remote_terminals.as_ref()
                    }
                    PrivateOramMutationJournalPhaseV2::LocalTerminal => {
                        state.local_terminals.as_ref()
                    }
                    _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
                };
                (descriptor.descriptor_digest == verify_descriptor_digest
                    && record_digest_at_phase_v2(descriptor, state, predecessor_phase)?
                        == verify_predecessor_record_digest
                    && state.decision.as_ref() == Some(&expected_decision)
                    && existing == Some(&expected))
                .then_some(())
                .ok_or(PrivateOramMutationJournalError::InvalidTransition)
            };
        let update = move |descriptor: &PrivateOramMutationJournalDescriptorV1,
                           current: &PrivateOramMutationJournalStateV2,
                           next: &mut PrivateOramMutationJournalStateV2| {
            if descriptor.descriptor_digest != update_descriptor_digest
                || current.record_digest != update_predecessor_record_digest
                || current.decision.as_ref() != Some(decision)
            {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
            match phase {
                PrivateOramMutationJournalPhaseV2::RemotesTerminal => {
                    next.remote_terminals = Some(batch);
                }
                PrivateOramMutationJournalPhaseV2::LocalTerminal => {
                    next.local_terminals = Some(batch);
                }
                _ => return Err(PrivateOramMutationJournalError::InvalidTransition),
            }
            Ok(())
        };
        if let Some(lock) = lock {
            self.transition_v2_locked(lock, phase, verify_existing, update)
        } else {
            self.transition_v2(phase, verify_existing, update)
        }
    }

    fn mark_point_stage_durable_v2(
        &self,
        expected_descriptor_digest: &str,
        expected_owners_prepared_record_digest: &str,
        evidence: PrivateOramMutationPointStageEvidenceV2,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let expected_evidence = evidence.clone();
        self.transition_v2(
            PrivateOramMutationJournalPhaseV2::PointStageDurable,
            move |descriptor, state| {
                if descriptor.descriptor_digest != expected_descriptor_digest
                    || state.point_stage.as_ref() != Some(&expected_evidence)
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                Ok(())
            },
            move |descriptor, current, next| {
                if descriptor.descriptor_digest != expected_descriptor_digest
                    || current.record_digest != expected_owners_prepared_record_digest
                {
                    return Err(PrivateOramMutationJournalError::InvalidTransition);
                }
                next.point_stage = Some(evidence);
                Ok(())
            },
        )
    }

    fn transition_v2<Verify, Update>(
        &self,
        phase: PrivateOramMutationJournalPhaseV2,
        verify_existing: Verify,
        update: Update,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    where
        Verify: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV2,
        ) -> Result<(), PrivateOramMutationJournalError>,
        Update: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV2,
            &mut PrivateOramMutationJournalStateV2,
        ) -> Result<(), PrivateOramMutationJournalError>,
    {
        validate_private_directory(&self.root)?;
        validate_private_directory(&self.temp_path())?;
        let lock = self.acquire_lock()?;
        self.transition_v2_locked(&lock, phase, verify_existing, update)
    }

    fn transition_v2_locked<Verify, Update>(
        &self,
        lock: &PrivateOramMutationJournalLock,
        phase: PrivateOramMutationJournalPhaseV2,
        verify_existing: Verify,
        update: Update,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    where
        Verify: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV2,
        ) -> Result<(), PrivateOramMutationJournalError>,
        Update: FnOnce(
            &PrivateOramMutationJournalDescriptorV1,
            &PrivateOramMutationJournalStateV2,
            &mut PrivateOramMutationJournalStateV2,
        ) -> Result<(), PrivateOramMutationJournalError>,
    {
        lock.validate_root_identity()?;
        let root = lock.pinned_root_path();
        let current = self.load_v2_locked_at_root(&root)?;
        if current.state.phase.sequence() >= phase.sequence() {
            verify_existing(&current.descriptor, &current.state)?;
            sync_directory(&root.join(ACTIVE_DIR))
                .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
            lock.validate_root_identity()
                .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
            return Ok(current);
        }
        if current.state.phase.sequence() + 1 != phase.sequence() {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
        let next = next_private_oram_mutation_state_v2(
            &current.descriptor,
            &current.state,
            phase,
            |next| update(&current.descriptor, &current.state, next),
        )?;
        if current
            .pending_next
            .as_ref()
            .is_some_and(|pending| pending != &next)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        // A visible pending record may come from an attempt whose directory fsync failed.
        // Re-running the exact publisher re-establishes record durability before the pointer moves.
        publish_immutable_state_record_v2(&root, &next)?;
        publish_state_pointer_v2(&root, &next)?;
        let loaded = self
            .load_v2_locked_at_root(&root)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        if loaded.state != next || loaded.pending_next.is_some() {
            return Err(PrivateOramMutationJournalError::Indeterminate);
        }
        lock.validate_root_identity()
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
        Ok(loaded)
    }

    fn load_v2_locked_at_root(
        &self,
        root: &Path,
    ) -> Result<PrivateOramMutationJournalStructuralSnapshotV2, PrivateOramMutationJournalError>
    {
        let active = root.join(ACTIVE_DIR);
        required_v2_artifact(validate_private_directory(&active))?;
        required_v2_artifact(validate_private_directory(&active.join(ACTIVE_TEMP_DIR)))?;
        let descriptor: PrivateOramMutationJournalDescriptorV1 = required_v2_artifact(
            read_json_private(&active.join(DESCRIPTOR_FILE), MAX_DESCRIPTOR_BYTES),
        )?;
        validate_descriptor(&descriptor, self.signature_verification())?;
        let state_bytes = required_v2_artifact(read_private_bytes_bounded(
            &active.join(STATE_FILE),
            MAX_STATE_BYTES,
        ))?;
        let state = match decode_untrusted_private_oram_mutation_state(&descriptor, &state_bytes)? {
            DecodedPrivateOramMutationStateUntrusted::V1(_) => {
                if path_entry_exists(&active.join(FORMAT_FILE))?
                    || path_entry_exists(&active.join(STATE_RECORDS_DIR))?
                {
                    return Err(PrivateOramMutationJournalError::Corrupt);
                }
                return Err(PrivateOramMutationJournalError::LegacyV1State);
            }
            DecodedPrivateOramMutationStateUntrusted::UntrustedV2(state) => *state,
        };
        if !path_entry_exists(&active.join(FORMAT_FILE))? {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let format: PrivateOramMutationJournalFormatV2 = required_v2_artifact(read_json_private(
            &active.join(FORMAT_FILE),
            MAX_FORMAT_BYTES,
        ))?;
        if format.state_version != V2_JOURNAL_FORMAT_VERSION
            || format.descriptor_digest != descriptor.descriptor_digest
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let records = required_v2_artifact(load_state_history_v2(&active, &descriptor))?;
        let current_index = usize::try_from(
            state
                .sequence
                .checked_sub(1)
                .ok_or(PrivateOramMutationJournalError::Corrupt)?,
        )
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        if records.get(current_index) != Some(&state)
            || !(records.len() == current_index + 1 || records.len() == current_index + 2)
        {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let pending_next =
            (records.len() == current_index + 2).then(|| records[current_index + 1].clone());
        Ok(PrivateOramMutationJournalStructuralSnapshotV2 {
            descriptor,
            state,
            pending_next,
        })
    }
}

fn required_v2_artifact<T>(
    result: Result<T, PrivateOramMutationJournalError>,
) -> Result<T, PrivateOramMutationJournalError> {
    match result {
        Err(PrivateOramMutationJournalError::Io(error))
            if error.kind() == io::ErrorKind::NotFound =>
        {
            Err(PrivateOramMutationJournalError::Corrupt)
        }
        other => other,
    }
}

fn validated_owner_terminal_evidence_v2(
    outcome: &PrivateOramValidatedOwnerRecoveryOutcomeV1,
) -> Result<
    (
        PrivateOramMutationOwnerTerminalKindV2,
        PrivateOramMutationOwnerTerminalEvidenceV2,
    ),
    PrivateOramMutationJournalError,
> {
    let (kind, terminal) = match outcome {
        PrivateOramValidatedOwnerRecoveryOutcomeV1::Finalized { terminal, .. } => (
            PrivateOramMutationOwnerTerminalKindV2::FinalizedNew,
            terminal,
        ),
        PrivateOramValidatedOwnerRecoveryOutcomeV1::AbortedOld { terminal } => {
            (PrivateOramMutationOwnerTerminalKindV2::AbortedOld, terminal)
        }
        PrivateOramValidatedOwnerRecoveryOutcomeV1::ObservedOld => {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    };
    let mut evidence = PrivateOramMutationOwnerTerminalEvidenceV2 {
        owner_peer_id: terminal.owner_peer_id(),
        journal_descriptor_digest: terminal.journal_descriptor_digest().to_string(),
        prepared_state_digest: terminal.prepared_state_digest().to_string(),
        terminal_record_digest: terminal.terminal_record_digest().to_string(),
        parent_descriptor_digest: terminal.parent_descriptor_digest().to_string(),
        decision_authority_record_digest: terminal.consensus_authority_record_digest().to_string(),
        reconciliation_authority_digest: terminal.reconciliation_authority_digest().to_string(),
        indexes: terminal
            .indexes()
            .iter()
            .map(|index| PrivateOramMutationOwnerTerminalIndexEvidenceV2 {
                kind: index.kind(),
                index_name: index.index_name().to_string(),
                prepared_journal_digest: index.prepared_journal_digest().to_string(),
                terminal_state_digest: index.terminal_state_digest().to_string(),
            })
            .collect(),
        terminal_evidence_digest: String::new(),
    };
    evidence.terminal_evidence_digest = private_oram_owner_terminal_evidence_v2_digest(
        &evidence.parent_descriptor_digest,
        kind,
        &evidence,
    )?;
    Ok((kind, evidence))
}

fn validate_live_point_stage_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    durable_point_stage: Option<&PrivateOramDurablePointStageTokenV1>,
) -> Result<(), PrivateOramMutationJournalError> {
    match (&state.point_stage, durable_point_stage) {
        (
            Some(PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging { .. }),
            Some(durable),
        ) if durable.parent_descriptor_digest() == descriptor.descriptor_digest
            && state.point_stage.as_ref()
                == Some(&private_oram_point_stage_evidence_v2_from_durable_token(
                    durable,
                )) =>
        {
            Ok(())
        }
        (Some(PrivateOramMutationPointStageEvidenceV2::NoServerPointRecord { .. }), None) => Ok(()),
        _ => Err(PrivateOramMutationJournalError::InvalidTransition),
    }
}

fn validated_reconcile_decision_for_v2_snapshot(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
    reconcile_snapshot: &PrivateOramMutationReconcileSnapshotV1,
) -> Result<
    (
        PrivateOramMutationLease,
        PrivateOramMutationReconcileDispositionV1,
        RawPrivateOramMutationDecisionEvidenceV2,
    ),
    PrivateOramMutationJournalError,
> {
    if snapshot.state.phase.sequence()
        < PrivateOramMutationJournalPhaseV2::PointStageDurable.sequence()
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let active_lease =
        validate_reconcile_lease_slot(&snapshot.descriptor, reconcile_snapshot.lease_slot())?;
    let disposition = if reconcile_snapshot.consensus_state()
        == &snapshot.descriptor.expected_consensus_old_state
    {
        match &active_lease.phase {
            PrivateOramMutationLeasePhase::AbortDecided => {
                PrivateOramMutationReconcileDispositionV1::ExactOldAbortDecided
            }
            PrivateOramMutationLeasePhase::Preparing
            | PrivateOramMutationLeasePhase::ConsensusCommitted { .. } => {
                return Err(PrivateOramMutationJournalError::InvalidTransition);
            }
        }
    } else if reconcile_snapshot.consensus_state()
        == &expected_consensus_new_state(&snapshot.descriptor)?
        && matches!(
            &active_lease.phase,
            PrivateOramMutationLeasePhase::ConsensusCommitted { .. }
        )
    {
        PrivateOramMutationReconcileDispositionV1::ExactNew
    } else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    let evidence = build_validated_mutation_decision_evidence_v2(
        &snapshot.descriptor,
        &active_lease,
        disposition,
    )?;
    for state in std::iter::once(&snapshot.state).chain(snapshot.pending_next.iter()) {
        if state.phase.sequence() >= PrivateOramMutationJournalPhaseV2::DecisionDurable.sequence()
            && state.decision.as_ref() != Some(&evidence)
        {
            return Err(PrivateOramMutationJournalError::InvalidTransition);
        }
    }
    Ok((active_lease, disposition, evidence))
}

fn validate_remotes_terminal_token_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    remotes: &PrivateOramValidatedRemotesTerminalV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::RemotesTerminal.sequence()
        || descriptor.descriptor_digest != remotes.expected_descriptor_digest
        || state.decision.as_ref() != Some(&remotes.evidence)
        || record_digest_at_phase_v2(
            descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::RemotesTerminal,
        )? != remotes.remotes_terminal_record_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validated_local_terminal_from_v2_snapshot(
    snapshot: &PrivateOramMutationJournalStructuralSnapshotV2,
) -> Result<PrivateOramValidatedLocalTerminalV2, PrivateOramMutationJournalError> {
    let state = snapshot.effective_state();
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(PrivateOramValidatedLocalTerminalV2 {
        evidence: state
            .decision
            .clone()
            .ok_or(PrivateOramMutationJournalError::Corrupt)?,
        expected_descriptor_digest: snapshot.descriptor.descriptor_digest.clone(),
        local_terminal_record_digest: record_digest_at_phase_v2(
            &snapshot.descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        )?,
    })
}

fn validate_local_terminal_token_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    local: &PrivateOramValidatedLocalTerminalV2,
) -> Result<(), PrivateOramMutationJournalError> {
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence()
        || descriptor.descriptor_digest != local.expected_descriptor_digest
        || state.decision.as_ref() != Some(&local.evidence)
        || record_digest_at_phase_v2(
            descriptor,
            state,
            PrivateOramMutationJournalPhaseV2::LocalTerminal,
        )? != local.local_terminal_record_digest
    {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    Ok(())
}

fn validated_point_stage_parent_for_terminal_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<PrivateOramValidatedPointStageParentV1, PrivateOramMutationJournalError> {
    if state.phase.sequence() < PrivateOramMutationJournalPhaseV2::LocalTerminal.sequence() {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    }
    let PrivateOramMutationPointStageEvidenceV2::PrivateOramPointStaging {
        child_descriptor_digest,
        parent_owners_prepared_record_digest,
        ..
    } = state
        .point_stage
        .as_ref()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?
    else {
        return Err(PrivateOramMutationJournalError::InvalidTransition);
    };
    Ok(PrivateOramValidatedPointStageParentV1 {
        descriptor: descriptor.clone(),
        owners_prepared_record_digest: parent_owners_prepared_record_digest.clone(),
        phase: PrivateOramValidatedPointStageParentPhaseV1::PointStageDurable,
        expected_child_descriptor_digest: Some(child_descriptor_digest.clone()),
    })
}

fn validate_point_resolution_candidate_v2(
    descriptor: &PrivateOramMutationJournalDescriptorV1,
    state: &PrivateOramMutationJournalStateV2,
    evidence: &RawPrivateOramMutationPointResolutionEvidenceV2,
) -> Result<(), PrivateOramMutationJournalError> {
    match state.phase {
        PrivateOramMutationJournalPhaseV2::LocalTerminal => {
            next_private_oram_mutation_state_v2(
                descriptor,
                state,
                PrivateOramMutationJournalPhaseV2::PointResolved,
                |next| {
                    next.point_resolution = Some(evidence.clone());
                    Ok(())
                },
            )?;
            Ok(())
        }
        PrivateOramMutationJournalPhaseV2::PointResolved
            if state.point_resolution.as_ref() == Some(evidence) =>
        {
            Ok(())
        }
        _ => Err(PrivateOramMutationJournalError::InvalidTransition),
    }
}

fn load_state_history_v2(
    active: &Path,
    descriptor: &PrivateOramMutationJournalDescriptorV1,
) -> Result<Vec<PrivateOramMutationJournalStateV2>, PrivateOramMutationJournalError> {
    let records_path = active.join(STATE_RECORDS_DIR);
    validate_private_directory(&records_path)?;
    let mut record_paths = fs::read_dir(&records_path)
        .map_err(PrivateOramMutationJournalError::Io)?
        .map(|entry| entry.map_err(PrivateOramMutationJournalError::Io))
        .take(MAX_V2_STATE_RECORDS + 1)
        .collect::<Result<Vec<_>, _>>()?;
    if record_paths.is_empty() || record_paths.len() > MAX_V2_STATE_RECORDS {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    record_paths.sort_unstable_by_key(|entry| entry.file_name());
    let mut records = Vec::with_capacity(record_paths.len());
    let mut history_bytes = 0_u64;
    for (index, entry) in record_paths.into_iter().enumerate() {
        let sequence =
            u64::try_from(index + 1).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        let expected_file_name = state_record_file_name(sequence)?;
        if entry.file_name().to_str() != Some(expected_file_name.as_str()) {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let bytes = read_private_bytes_bounded(&entry.path(), MAX_STATE_BYTES)?;
        history_bytes = history_bytes
            .checked_add(
                u64::try_from(bytes.len()).map_err(|_| PrivateOramMutationJournalError::Corrupt)?,
            )
            .ok_or(PrivateOramMutationJournalError::Corrupt)?;
        if history_bytes > MAX_V2_HISTORY_BYTES {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        let state: PrivateOramMutationJournalStateV2 =
            serde_json::from_slice(&bytes).map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        if state.sequence != sequence {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        validate_private_oram_mutation_state_v2_structure(descriptor, &state)
            .map_err(|_| PrivateOramMutationJournalError::Corrupt)?;
        records.push(state);
    }
    let final_state = records
        .last()
        .ok_or(PrivateOramMutationJournalError::Corrupt)?;
    if canonical_private_oram_mutation_state_history_v2(descriptor, final_state)
        .map_err(|_| PrivateOramMutationJournalError::Corrupt)?
        != records
    {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(records)
}

#[allow(
    clippy::disallowed_methods,
    reason = "NamedTempFile exposes a borrowed std File needed for pre-publish fsync and metadata validation"
)]
fn publish_immutable_state_record_v2(
    root: &Path,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    let active = root.join(ACTIVE_DIR);
    let records = active.join(STATE_RECORDS_DIR);
    let temp = active.join(ACTIVE_TEMP_DIR);
    validate_private_directory(&records)?;
    validate_private_directory(&temp)?;
    let destination = records.join(state_record_file_name(state.sequence)?);
    if path_entry_exists(&destination)? {
        let existing: PrivateOramMutationJournalStateV2 =
            read_json_private(&destination, MAX_STATE_BYTES)?;
        if existing != *state {
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        sync_directory(&records)?;
        return Ok(());
    }

    let mut candidate =
        NamedTempFile::new_in(&temp).map_err(PrivateOramMutationJournalError::Io)?;
    serde_json::to_writer(&mut candidate, state)
        .map_err(|error| PrivateOramMutationJournalError::Io(io::Error::other(error)))?;
    candidate
        .flush()
        .map_err(PrivateOramMutationJournalError::Io)?;
    candidate
        .as_file()
        .sync_all()
        .map_err(PrivateOramMutationJournalError::Io)?;
    validate_private_file_metadata(
        &candidate
            .as_file()
            .metadata()
            .map_err(PrivateOramMutationJournalError::Io)?,
        MAX_STATE_BYTES,
    )?;
    if let Err(error) = candidate.persist_noclobber(&destination) {
        if path_entry_exists(&destination)? {
            let existing: PrivateOramMutationJournalStateV2 =
                read_json_private(&destination, MAX_STATE_BYTES)?;
            if existing == *state {
                sync_directory(&records)
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                sync_directory(&temp)
                    .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
                return Ok(());
            }
            return Err(PrivateOramMutationJournalError::Corrupt);
        }
        return Err(PrivateOramMutationJournalError::Io(error.error));
    }
    sync_directory(&records).map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    sync_directory(&temp).map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    let installed: PrivateOramMutationJournalStateV2 =
        read_json_private(&destination, MAX_STATE_BYTES)
            .map_err(|_| PrivateOramMutationJournalError::Indeterminate)?;
    if installed != *state {
        return Err(PrivateOramMutationJournalError::Indeterminate);
    }
    Ok(())
}

fn publish_state_pointer_v2(
    root: &Path,
    state: &PrivateOramMutationJournalStateV2,
) -> Result<(), PrivateOramMutationJournalError> {
    let active = root.join(ACTIVE_DIR);
    let state_path = active.join(STATE_FILE);
    let previous_file_sha256 = file_sha256(&state_path, MAX_STATE_BYTES)?;
    write_json_atomic_classified(
        &state_path,
        &active.join(ACTIVE_TEMP_DIR),
        state,
        previous_file_sha256,
        &FilesystemJournalSaveBackend,
    )
}

fn state_record_file_name(sequence: u64) -> Result<String, PrivateOramMutationJournalError> {
    if !(1..=MAX_V2_STATE_RECORDS as u64).contains(&sequence) {
        return Err(PrivateOramMutationJournalError::Corrupt);
    }
    Ok(format!("{sequence:020}{STATE_RECORD_FILE_SUFFIX}"))
}
