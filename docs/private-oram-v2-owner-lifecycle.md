# Private ORAM V2 Owner Lifecycle Authority

Status: dormant design contract. `owner-tombstone=0` remains mandatory until every
activation gate in this document passes.

This status applies to physical owner-history settlement and tombstone/GC authority.
It does not describe the activated strict mutation terminal chain in `docs/ckks.md`:
that chain retains owner capsules and terminal archives, and only releases the active
mutation lease after a Raft cleanup witness and local cleanup marker. Physical deletion
of those retained artifacts still depends on the owner lifecycle contract below.

The activated chain also requires an exact-generation runtime quiescence claim before
the local marker is published. It blocks new session/job acquisition, waits for the
detached worker liveness guard to end, releases the paired HNSW/result sessions, and
records a same-process cleanup tombstone. Mere registry absence is not authority unless
the process restarted while holding the process-lifetime exclusive peer identity lock.
The claim binds the complete collection/mutation/immutable-owner/generation identity,
process incarnation, and cleanup evidence digests. Marker and archive-receipt publication
are immutable, no-replace, and directory-fsynced; the archive destination must reopen as
the same inode pinned before rename. These guarantees authorize lease clear and acknowledgement only;
they do not authorize physical capsule/archive deletion.

Session admission and cleanup use one registry linearization boundary. An outstanding
open reservation or installed session prevents cleanup, while an installed cleanup claim
prevents a late session install. The final cleanup tombstone is published only after the
same locked transition rechecks that no reservation, session, or append job remains.

This document defines the authority boundary for cleaning owner-local pre-stage
artifacts after a negative append outcome. Owner-local files are untrusted evidence.
They never create an acknowledged lifecycle checkpoint or authorize their own replay.

## Authority Model

The protocol uses both of these retained values:

1. A global owner checkpoint table is the current authority floor.
2. Every append reservation contains an immutable copy of the exact checkpoint that
   it consumes.

A mutable table digest alone is not sufficient. Raft apply compares every reservation
target with the current table and atomically leases that predecessor. Later cleanup is
derived from the reservation copy, not from whichever table value is current then.

The table key is `(collection_incarnation_digest, owner_enrollment_id)`. A peer ID is
not an enrollment identity and may be reused only through a new enrollment.

Each checkpoint record binds:

- consensus history and Raft group identity;
- collection lifetime and collection incarnation;
- owner enrollment ID, peer ID, and store incarnation;
- checkpoint sequence and full lifecycle state;
- source kind, source record digest, and source apply locator;
- owner signer identity and epoch;
- activation, authority-registry, owner-registry, and membership epochs;
- repair readiness; and
- the canonical checkpoint-record digest.

`PrivateOramMutationAuthorityFloorV2`, which is persisted outside an installed Raft
snapshot, pins the aggregate ordinal and digest. Because the owner checkpoint table is
part of the aggregate core digest, restoring an older aggregate below that local floor
fails closed. Losing or rolling back both the installed Raft image and that independent
floor is outside automatic recovery: the node must not serve mutations until an
operator restores a newer floor or completes an explicit re-enrollment ceremony.

## Enrollment

An ordinary owner status response cannot bootstrap authority. Enrollment is:

```text
un_enrolled
  -> enrollment_prepared
  -> genesis_local_committed
  -> active
```

`OwnerEnrollmentPreparedV1` is committed before local initialization. It contains a
new non-reused enrollment ID, authority-selected store incarnation, owner identity and
signer epoch, registry and membership epochs, and the expected deterministic empty
generation-zero lifecycle state.

The owner creates a new empty namespace bound to that record. It must not adopt a
pre-existing superblock, terminal, journal, intent, retired payload, or quarantine
entry. The owner signs a genesis commitment only after the empty superblock and parent
directory are durable.

`OwnerEnrollmentActivatedV1` validates that exact commitment and installs the genesis
checkpoint in the global table. Reservations are rejected while enrollment is pending.
A non-empty legacy store requires an explicit trusted import protocol; status polling
is never an import mechanism.

## Reservation And Status

Reservation V3 is a new wire format. V2 records are not extended in place.

The coordinator first creates an attempt ID and a static attempt-context digest over
the mutation, scope, ordered owner descriptors, owner request digests, intent keys,
package hashes and lengths, registry epochs, and membership epoch. It reads the current
checkpoint table and sends a read-only challenge to each owner.

The status handler acquires the lifecycle read lock and performs no repair, migration,
key rotation, acknowledgement, or challenge persistence. Its signed attestation binds:

- protocol, version, and signature domain;
- complete consensus/collection scope and capability epoch;
- attempt ID, attempt-context digest, and challenge;
- owner index, peer, enrollment, signer, and store incarnation;
- expected checkpoint sequence and record digest;
- observed full lifecycle state;
- status mode (`ready_exact`, `unreconciled_terminal`, `repair_pending`, or
  `corrupt_or_forked`);
- terminal-capacity readiness; and
- activation, authority-registry, owner-registry, and membership epochs.

Reservation apply independently verifies the serialized attestation on every replica.
For normal admission, observed state must equal the retained checkpoint exactly. Lower,
equal-generation fork, higher/unacknowledged, incarnation mismatch, and registry/key
mismatch all fail closed. Raft then CASes the exact checkpoint records and leases every
owner atomically. Two reservations cannot consume one predecessor.

Owner pre-stage requires proof of the committed reservation and exact owner target.
Coordinator call ordering is not authority. A pre-stage request without committed proof
must perform zero filesystem writes.

## Negative Outcome And Grants

A retained negative outcome has one ordered disposition per reservation owner:

```text
prestage_committed(receipt identity)
no_write_authoritatively_known(orchestration proof)
publication_indeterminate
rejected_before_write(orchestration proof)
```

Local file absence is not proof of `no_write_authoritatively_known`. An indeterminate
owner prevents settlement until exact probing resolves it. `AdmissionRejected` normally
requires `prestage_committed` for every owner.

Cleanup cannot start immediately from a negative outcome. Raft first commits one
canonical ordered `OwnerCleanupGrantSetCommittedV1`. Every signed grant binds the exact
reservation, outcome, owner disposition, reserved checkpoint, authorized successor,
owner target, signer/registry epochs, and deterministic cleanup operation ID. Owners
accept a grant only with proof of this committed grant-set record.

## Local Commit And Evidence

The immutable terminal file and its containing-directory fsync are the cleanup
linearization point. The owner may then need superblock reconciliation or payload
relocation. These repairs do not create a second lifecycle transition.

A raw signed cleanup receipt is a prepared statement. It is never an all-owner
certificate input. After the terminal is durable, the owner emits a separately signed
`CommittedOwnerCleanupTerminalEvidenceV1` that binds the grant, operation ID, receipt
digest, terminal marker digest, previous and new lifecycle states, complete owner/scope
identity, and historical signer/registry epochs. Exact replay reconstructs the same
evidence from the persisted terminal.

`IndeterminateTerminalCommit` is not evidence. Exact deterministic terminal lookup must
classify it first. Evidence may be issued for terminal-committed states whose repair is
still pending; mutable repair status is not part of the security certificate.

## Settlement And Acknowledgement

The canonical all-owner settlement certificate contains one ordered entry per reserved
owner:

```text
cleanup_terminal_committed(verified committed evidence)
no_prestage_write(retained orchestration proof)
```

Missing, duplicate, reordered, foreign-incarnation, or raw-receipt entries are rejected.

`OwnerCleanupTerminalsAcknowledgedV1` is a dedicated Raft material operation. It does
not reuse admitted-mutation clear acknowledgement. Apply verifies the exact reservation,
negative outcome, grant set, certificate, owner cardinality/order, and current checkpoint
CAS. It atomically advances every affected owner checkpoint, marks the negative attempt
settled, and advances the aggregate digest. Identical replay is idempotent; a different
certificate for the same attempt is a security conflict. Partial checkpoint updates are
never observable.

Terminal acknowledgement and operational readiness are separate. New reservations and
history GC remain blocked until every owner reports the acknowledged successor exactly
and no unreconciled terminal or repair remains.

## Lock And Durability Order

The owner-local order is:

```text
owner lifecycle root -> canonical owner journal -> HNSW store -> result store
```

Callers must use shared acquisition helpers and must not upgrade a held shared lock.
Status is read-only. Cleanup terminal publication uses same-directory temporary creation,
bounded canonical write, file fsync, no-replace publication, and terminal-directory
fsync. Superblock replacement and payload relocation use equivalent directory-fsync
discipline. Failures after possible namespace publication but before durable directory
sync are indeterminate.

The mutation terminal coordinator adds a collection-key execution mutex outside this
owner-store order. It prevents two supervisor passes from independently acting on the
same generation; it is not held across unrelated collections. Before marker publication,
the coordinator must hold the opaque quiesced-cleanup permit. Before archive rename it
must revalidate the exact source descriptor, terminal record, generation, cleanup marker,
cleared tombstone, original owner, and storage incarnation. The archive root and receipt
directories are fsynced before clear acknowledgement can be proposed.

All namespace operations remain Linux-only and descriptor-relative, with symlink,
hardlink, ownership, mode, inode type, size, and inode-continuity checks. A malicious
same-user actor may still deny service; integrity failures remain fail closed.

## Version And Activation Gates

New reader support is deployed before any writer. Required new records include owner
enrollment, owner status attestation, reservation target/reservation V3, owner prestage
dispositions, cleanup grant set, committed terminal evidence, settlement certificate,
cleanup acknowledgement, and repair completion.

The mixed-version floor must cover voters, learners, leaders, snapshot readers, and
joining peers. After the floor or first new-format record, downgrade is unsupported.
Operational rollback means disabling new writes while retaining upgraded readers.

`owner-tombstone` may change from `0` only after codec, direct-precommit rejection,
two-owner partial outcome, process-kill/fsync, rollback/fork, key-rotation, snapshot-floor,
and old-peer-rejoin tests all pass. Initial rollout retains all outcome, grant,
certificate, and terminal history; GC is deferred.
