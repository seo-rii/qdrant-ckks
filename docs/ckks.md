# qdrant-sec encryption boundary

The `sec` branch adds a small `qdrant-sec` workspace crate for encrypted
payload text and OpenFHE CKKS vector ciphertext envelopes.

Current scope is encrypted storage plus a conservative CKKS sidecar search path,
not HNSW-native encrypted vector indexing. Payload text encryption happens
before storage. CKKS vector selectors have a server-side ingest/storage path:
selected dense vectors are encrypted through the configured OpenFHE bridge and
stored as reserved payload sidecar envelopes, while the plaintext vector is
removed from the dense vector write. REST/gRPC nearest-neighbor `search` and
root direct `query` over an encrypted vector name use a brute-force sidecar scan
and ask the OpenFHE bridge to score each stored ciphertext against the plaintext
query vector. The same sidecar scorer also handles raw-dense average-vector
recommend requests and raw-dense target-only discover requests by reducing them
to plaintext dense query vectors.
This branch still does not add encrypted query vectors, client-held CKKS
search, score decryption, or an HNSW-compatible ciphertext search executor.

Unsupported search/index features for CKKS ciphertext vectors in this branch:

- HNSW similarity search directly over CKKS ciphertext
- quantization over CKKS ciphertext
- recommend/discover flows that require point-id examples, discover context
  pairs, or vector arithmetic over encrypted values
- grouped lookup over CKKS ciphertext sidecars
- mixed plaintext and encrypted vector searches in one batch
- payload filtering over encrypted metadata
- shard transfer or snapshot restore without matching runtime keys and OpenFHE
  context material

## Feature support matrix

This branch is intentionally fail-closed for encrypted data paths that are not
fully wired. The table below is the user-facing contract for the current
implementation.

| API/path | Server-side payload AEAD | Client-side payload envelope | CKKS vector envelope |
| --- | --- | --- | --- |
| `upsert` payload/vector | Supported for selected JSON string fields. Values are encrypted before storage and client-supplied `$qdrant_sec` markers are rejected. | Supported for selected fields that already contain a valid `$qdrant_client_aead` marker. Qdrant validates schema, AAD metadata, key policy, and a mandatory Ed25519 signature, but does not decrypt. | Supported for selected dense vectors. Qdrant encrypts through the OpenFHE bridge, stores `$qdrant_sec_vectors` sidecar payload envelopes, and removes plaintext vectors from dense vector storage. Sparse and multi-dense encrypted vectors fail closed. |
| `set_payload` / `overwrite_payload` | Supported for explicit point ids when Qdrant can bind AAD to each point id. Multi-point updates are fanned out into one encrypted operation per point; filter-based and key-path encrypted-field updates fail closed. | Same explicit-point-id limitation as server-side payload writes. Clients must provide one envelope per point/field; filter-based and key-path encrypted-field updates fail closed. | Not applicable. |
| `update_vectors` | Not applicable. | Not applicable. | Supported for point-specific dense vector updates by writing the encrypted sidecar payload and omitting the plaintext vector update. Sparse and multi-dense encrypted vectors fail closed. |
| Payload indexes, filters, facets, ordering, grouping, and formulas | Plaintext indexes, read/update filters, facet keys, order-by keys, group-by keys, and formula payload references over encrypted paths, parent paths, or child paths are rejected. Searching, mutating by filter, ordering, grouping, or aggregating encrypted content requires a future blind-index provider. | Same policy. The opaque ciphertext field is not searchable, orderable, groupable, facetable, or usable in mutation filters as plaintext. | The reserved `$qdrant_sec_vectors` sidecar field is not indexable, filterable, orderable, groupable, facetable, or usable in formulas. Payload filtering/faceting over encrypted metadata is unsupported. |
| `retrieve`, `scroll`, `search`, and `query` result payloads | Stored `$qdrant_sec` markers are returned raw. There is no `decrypt_payload` option or RBAC capability yet. | Stored `$qdrant_client_aead` markers are returned raw for SDK/client decryption. | Stored vector sidecar payload envelopes are returned raw when payloads are requested. REST/gRPC nearest-neighbor dense-vector `search`, `search/groups`, root direct `query`, root direct `query/groups`, raw-dense average-vector `recommend`, and raw-dense target-only `discover` are supported through brute-force sidecar scoring with runtime OpenFHE settings. HNSW/quantization/ACORN/indexed-only search params, point-id recommend/discover examples, discover context pairs, search matrix, prefetch/fusion/MMR, encrypted query vectors, and mixed encrypted/plaintext batch search remain unsupported. |
| Snapshots | Snapshot archives are expected to contain envelopes only; payload sentinel snapshot leakage is covered by integration tests. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings, including missing material, wrong wrapped-RK key, and provider key-id mismatch cases. | Same stored-value behavior as server-side payloads. Qdrant cannot validate client AEAD tags without client keys. | Restore requires matching OpenFHE context/runtime material; missing runtime instance/material/backend preflight is wired, while wrong-context restore coverage is still missing. |
| Shard transfer / replication | Encrypted collection data-movement operations require matching non-secret crypto runtime capability fingerprints in peer metadata. Operations fail closed if any involved peer has missing or mismatched metadata. Automatic dead-replica recovery only proposes encrypted shard transfers from source peers with matching parity metadata. | Same policy; client-envelope verifier policy must match across nodes before encrypted transfers are allowed. | Same policy; matching OpenFHE context and metadata AEAD material must be enforced before encrypted transfers are allowed. |
| Metadata encryption | Not implemented. `metadata_keys` selectors are reserved and rejected. | Not implemented. | Not implemented. |

## Payload text

Selected JSON string fields are replaced with a single marker object:

```json
{
  "$qdrant_sec": {
    "kind": "payload_text",
    "envelope": {
      "version": 1,
      "algorithm": "AES-256-GCM",
      "key_id": "tenant-a:payload",
      "material_fingerprint": "...",
      "rk_id": "tenant-a/payload-v1",
      "rk_epoch": 3,
      "nonce": "...",
      "ciphertext": "..."
    },
    "schema_version": 1,
    "encryption_epoch": 0
  }
}
```

The AEAD associated data binds ciphertexts to `collection`, `point_id`, and field
path. Moving a ciphertext to another point or field must fail authentication.
Payload selectors are object dot paths only. Array syntax, wildcards, and
numeric path components such as `items[].name`, `items.*.name`, or
`items.0.name` are rejected instead of being interpreted as array traversal.
Selector components that collide with reserved envelope markers
`$qdrant_sec`, `$qdrant_client_aead`, or `$qdrant_ciphertext` are rejected.

Runtime crypto instances currently accept only these provider IDs:
`payload/aes-256-gcm@v1`, `payload/client-aead@v1`, and
`vector/openfhe-ckks@v1`. Unknown provider IDs fail runtime settings
validation instead of being treated as extension points.
`payload/aes-256-gcm@v1` must bind a `materials.sym_key` resource key and set
an explicit `options.material_fingerprint_id`; it must not configure
`backend_ref`; it is an in-process AEAD provider, not an OpenFHE bridge client.
`vector/openfhe-ckks@v1` must bind `materials.sym_key` for vector envelope
metadata sealing, set `options.material_fingerprint_id`, and configure
`backend_ref` for the OpenFHE bridge.
Runtime crypto materials currently accept only `symmetric_key_32`,
`wrapping_key_32`, and `wrapped_symmetric_key_32` kinds.

### Client-side encrypted payloads

Zero-trust client-side payload encryption uses a separate provider from
server-side `payload/aes-256-gcm@v1` encryption:

```yaml
crypto:
  instances:
    docs_payload_client_v1:
      provider: payload/client-aead@v1
      materials: {}
      # backend_ref must be omitted. This provider is server-blind:
      # Qdrant stores and verifies client envelopes, but never holds the
      # client data key or runs a bridge/backend for this payload field.
      options:
        key_id: tenant-a/client-rk-2026-04
        key_id_required: true
        expected_rk_id: tenant-a/client-rk-2026-04
        min_rk_epoch: 3
        max_rk_epoch: 3
        signature_public_keys:
          tenant-a/client-signing-v1: base64url-no-pad-ed25519-public-key
          tenant-a/client-signing-v2: base64url-no-pad-ed25519-public-key
params:
  encryption:
    version: 1
    key_id: tenant-a/client-rk-2026-04
    crypto_schema_version: 1
    # For client-envelope bindings, this is the pinned active client RK epoch
    # that the collection guard rechecks before storage.
    encryption_epoch: 3
    migration_state: active
    rules:
      - id: body_client_conf
        selector:
          kind: payload_paths
          paths: [body]
        instance: docs_payload_client_v1
        binding: client-payload-envelope/v1
```

`payload/client-aead@v1` fails runtime validation if `materials` is non-empty,
`backend_ref` is configured, or server-side options such as `retired_materials`
are present. Server-side wrapping keys/RKs belong to `payload/aes-256-gcm@v1`;
client-side payload envelopes must keep client data keys outside the Qdrant
process. Startup validation also fails unless
`key_id` is required and `expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch`
are set explicitly. If the instance also sets `options.key_id`, it must match
`expected_rk_id`; at collection binding time `expected_rk_id` must also match
the collection encryption `key_id`. `min_rk_epoch` and `max_rk_epoch` must be
identical; broad epoch ranges are rejected so a client provider pins exactly one
active resource-key epoch.
For collection rules bound to `client-payload-envelope/v1`, `encryption_epoch`
must be non-zero and match that active client RK epoch. The collection write
guard uses it as a second fail-closed check even after the public runtime write
plan has verified the envelope.

This provider does not receive plaintext and does not unwrap a data key. The
client encrypts before insert and Qdrant only validates the envelope schema,
AAD metadata, key policy, nonce/ciphertext encoding, and Ed25519 signature
before storing the opaque ciphertext. By default every write must carry a valid
`signature` object whose `key_id` selects one configured public key from
`signature_public_keys`. The legacy single-key options `signature_key_id` and
`signature_public_key_b64` are still accepted, but they cannot be mixed with
`signature_public_keys`.

Unsigned client envelopes are rejected. Qdrant cannot verify the client-side
AES-GCM tag without the client data key, so the Ed25519 signature is the
write-time authenticity check for this zero-trust mode.

Client envelopes must carry `rk_id`, `rk_epoch`, and
`kdf_domain: qdrant-sec/client-payload-text/v1`. Provider instances must pin
`expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch` to a single active epoch
so stale, retired, or wrong client resource-key epochs fail closed during
rotation.
Envelope `key_id`, `rk_id`, and `signature.key_id` values, plus matching
provider options such as `key_id`, `expected_rk_id`, and signature registry
keys, must use the bounded qdrant-sec crypto identifier syntax
`[A-Za-z0-9._:/@-]`.

For payload writes, the `aad.collection_id` value is the collection's stable
crypto identity. Encrypted collection create/recovery paths must have a
persisted collection UUID; existing encrypted snapshot recovery fails closed if
either side is missing a UUID or if the UUIDs differ. Public encrypted write
paths and the collection write guard fail closed when an encrypted collection
does not have a persisted UUID; collection names are not accepted as the
production crypto identity.

Qdrant rejects duplicate client-side AEAD nonces within a single public write
request, including `update_batch`, and records validated nonces in a
collection-local replay cache keyed by the collection's stable crypto identity
and `(key_id, rk_id, rk_epoch, nonce)`. The cache is persisted under the
collection directory and loaded on collection restart, so replay is caught
across later requests and same-node reloads. On collection load, Qdrant also
scans already stored `$qdrant_client_aead` envelope markers for configured
client-payload paths and backfills missing replay-cache entries; stored duplicate
nonces fail closed. A cluster-wide replay index is not implemented, so
`payload/client-aead@v1` collection runtime validation and public writes fail
closed when `cluster.enabled=true`; clustered zero-trust client envelope ingest
requires a future consensus-backed nonce ledger. SDKs must still generate fresh
96-bit CSPRNG nonces and regenerate envelopes on retry instead of replaying
failed request bodies. Nonces are recorded before shard storage is attempted so
the policy fails secure; if a write returns an error after envelope validation,
clients must build a new envelope with a new nonce before retrying.

```json
{
  "body": {
    "$qdrant_client_aead": {
      "version": 1,
      "kind": "payload_text",
      "algorithm": "AES-256-GCM",
      "key_id": "tenant-a/client-rk-2026-04",
      "rk_id": "tenant-a/client-rk-2026-04",
      "rk_epoch": 3,
      "kdf_domain": "qdrant-sec/client-payload-text/v1",
      "aad": {
        "collection_id": "persisted-collection-uuid",
        "point_id": "1",
        "field_path": "body",
        "schema_version": 1
      },
      "nonce": "base64url-no-pad-96-bit-nonce",
      "ciphertext": "base64url-no-pad-client-ciphertext",
      "signature": {
        "alg": "ed25519",
        "key_id": "tenant-a/client-signing-v1",
        "sig": "base64url-no-pad-signature"
      }
    }
  }
}
```

Client envelopes are not server envelopes. Public writes to a
`payload/aes-256-gcm@v1` rule reject client-supplied `$qdrant_sec` markers, and
`payload/client-aead@v1` rules require `$qdrant_client_aead` markers. Because
Qdrant does not have the client data key in this mode, it cannot verify the
AES-GCM tag or decrypt responses; clients or SDKs must decrypt returned
envelopes. Client envelopes must include `rk_id`, `rk_epoch`, and
`kdf_domain: qdrant-sec/client-payload-text/v1` so resource-key identity is explicit
even though Qdrant cannot unwrap the client key. The Ed25519 signature covers the
client envelope header, AAD, nonce, ciphertext, signature algorithm, and
signature key id.

Storage does not trust marker shape alone. Public write plans must validate the
client envelope and produce a runtime-verified proof keyed by collection id,
point id, field path, key id, `rk_id`, `rk_epoch`, nonce, ciphertext digest, and
signature digest. The collection write guard recomputes that identity from the
stored marker and accepts the write only when it matches the runtime proof.

Blind-index query integration is not implemented yet. Exact-match search
requires a future client blind-index field, and range, geo, or full-text search
over client ciphertext remains unsupported.

SDKs that implement this mode must do all cryptographic data-key operations
outside Qdrant:

- Generate a random client RK and derive the payload AEAD key with
  `qdrant-sec/client-payload-text/v1`; do not send the RK to Qdrant.
- Generate a fresh 96-bit CSPRNG nonce for every envelope and regenerate the
  envelope on retry instead of replaying a failed request body.
- Canonicalize AAD with the collection crypto identity, point id, field path,
  schema version, `key_id`, `rk_id`, and `rk_epoch` before signing.
- Sign the envelope with the configured Ed25519 key and rotate signing keys via
  the `signature_public_keys` registry.
- Verify and decrypt raw `$qdrant_client_aead` envelopes on read. Qdrant will
  return the opaque envelope, not plaintext.
- If exact-match filtering is required, generate a separate blind-index token
  with a different client key/HKDF domain. Plain Qdrant payload indexes remain
  unsupported for encrypted fields.

Collection encryption rules are configured only through the canonical
`params.encryption` section. The old `params.ckks` shape is no longer accepted
on public REST/gRPC create/update paths; use explicit provider bindings instead:

```yaml
params:
  encryption:
    version: 1
    key_id: tenant-a:docs
    crypto_schema_version: 1
    encryption_epoch: 0
    migration_state: active
    rules:
      - id: docs_payload
        selector:
          payload_paths: [body]
        instance: docs_payload_v1
        binding: payload-field/v1
```

Metadata encryption is not implemented yet. The generic control-plane types
reserve a `metadata_keys` selector for future value encryption and exact-match
token designs, but collection validation rejects metadata selectors in this
branch. Payload filtering over encrypted metadata, including range, geo, and
full-text filtering, is unsupported until a separate blind-index design exists.

Runtime settings provide key material and providers through the canonical
`crypto` section. The old runtime `ckks` section and `master_key_b64` /
`resource_key_b64` direct-key shape are rejected by startup validation; define a
`payload/aes-256-gcm@v1` or `payload/client-aead@v1` instance instead:

```yaml
crypto:
  allow_inline_key_material: false
  instances:
    docs_payload_v1:
      provider: payload/aes-256-gcm@v1
      materials:
        sym_key: tenant-a/payload-v1
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/payload@v1
  materials:
    tenant-a/payload-v1:
      kind: wrapped_symmetric_key_32
      wrapped_by: tenant-a/mk
      wrap_algorithm: AES-256-GCM
      nonce: base64url-no-pad-12-byte-nonce
      wrapped_key_b64: base64url-no-pad-wrapped-rk
      rk_id: tenant-a/payload-rk
      rk_epoch: 3
      state: active
      scope: collection:uuid
    tenant-a/mk:
      kind: wrapping_key_32
      source: env
      env: QDRANT_CRYPTO_MK_B64
```

The generic `crypto` control plane supports a safer MK/RK hierarchy:

- `wrapping_key_32` is an MK/KEK loaded from env/file/fd/inline material.
- `wrapped_symmetric_key_32` is a random collection or rule RK wrapped by that
  MK using AES-256-GCM.
- Payload text and CKKS vector envelope AEAD keys are still purpose-specific
  HKDF subkeys derived from the unwrapped RK.

Provider `options` are allowlisted per provider. `payload/aes-256-gcm@v1`
accepts only `key_id`, `material_fingerprint_id`, and `retired_materials`;
`payload/client-aead@v1` accepts only its client envelope policy and signature
options; `vector/openfhe-ckks@v1` accepts only `key_id`,
`material_fingerprint_id`, `profile`, `crypto_context_b64`, and
`public_key_b64`. Unknown options fail startup/runtime validation instead of
being silently ignored.

Provider `materials` roles are also allowlisted. Server-side payload AEAD and
OpenFHE CKKS vector-envelope providers accept only `materials.sym_key`; the
client-side AEAD provider must not configure any server material or backend.
Unexpected material roles fail validation instead of being silently ignored.

For tests and future vector-envelope work, a generic OpenFHE backend is
configured under `crypto.backends` and referenced from a
`vector/openfhe-ckks@v1` instance:

```yaml
crypto:
  backends:
    openfhe_local:
      kind: process
      program: /usr/local/bin/openfhe-bridge
      sha256_b64: base64url-no-pad-sha256-of-bridge
  instances:
    docs_vector_v1:
      provider: vector/openfhe-ckks@v1
      backend_ref: openfhe_local
      materials:
        sym_key: tenant-a/vector-v1
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/vector@v1
        profile: ckks-128-n16384-d4-scale50
        crypto_context_b64: base64url-no-pad-openfhe-context
        public_key_b64: base64url-no-pad-openfhe-public-key
```

Direct MK/RK materials must set `source` explicitly; qdrant-sec does not infer
`env`, `file`, `fd`, or `inline` from whichever field happens to be present.
When a material uses `source: file`, the path must be absolute and point to a
regular non-symlink file. On Unix, qdrant-sec rejects group/world-accessible key
files and rejects group/world-writable parent directories. The file and each
parent directory must be owned by root or the qdrant process user so file-backed
MK/RK material is not accidentally exposed or swapped through broad filesystem
permissions.
When a material uses `source: fd`, the `fd` must reference an already-open Unix
file descriptor containing the base64url-no-pad 32-byte material. Qdrant
marks the descriptor close-on-exec during validation and duplicates it with
close-on-exec before reading, so the original descriptor is not closed by
material loading and secret descriptors are not inherited by bridge child
processes. FD-backed material avoids storing the secret or a secret file path in
config, but operators must still provide the descriptor at the beginning of the
encoded material and keep cluster runtime parity aligned.

Wrapped RK material may declare a lifecycle `state`:

- `active` or omitted: the RK can be unwrapped and used for new encryption.
- `retired`: the RK is read-only and must not be selected for new write plans.
- `disabled`: the RK must not be unwrapped by runtime crypto but may retain
  wrapped material for an explicit future enable/rollback operation.
- `destroyed`: the RK must not retain `wrapped_by`, `nonce`, `wrap_algorithm`,
  or `wrapped_key_b64`; only non-secret identity metadata such as `rk_epoch`,
  `scope`, and `state` remains for audit/preflight.

Runtime validation includes this non-secret state in the cluster capability
fingerprint so nodes disagreeing on RK lifecycle cannot silently accept the same
collection plan.
Provider `materials.sym_key` bindings for new server-side payload/vector writes
must reference an `active` wrapped RK; retired keys are accepted only through the
explicit `retired_materials` read-only rotation list.

Data envelopes record the runtime `key_id`, material fingerprint, and, for
wrapped RK material, the `rk_id` plus `rk_epoch` used for the RK-derived subkey.
They do not reference the MK directly, so MK rotation can rewrap the stored RK
manifest without rewriting payload/vector envelopes. The low-level
`rewrap_resource_key` helper implements that primitive by unwrapping the RK with
the old MK/AAD and immediately wrapping the same RK with the new MK/AAD. The
runtime `rewrap_runtime_resource_key_materials_by_master_key` helper batches
that primitive for every `active` or `retired` wrapped RK that references the
old MK, preserving each RK's epoch, scope, and lifecycle state. `disabled` and
`destroyed` RK records are not implicitly unwrapped during MK rotation.
RK rotation still requires a data re-encryption job and should use the explicit
re-encryption mode rather than normal write-path idempotency. The
`rk_id`/`rk_epoch` fields are included in AEAD AAD for server-generated payload
and vector envelopes, so storage-side edits to resource-key identity fail closed.
During RK rotation, `payload/aes-256-gcm@v1` instances may list old read-only
keys in `options.retired_materials` as objects containing `material` and
`material_fingerprint_id`. Normal public writes still use only `materials.sym_key`
for new encryption, while the admin re-encryption path can decrypt stale
envelopes with the retired keyring entry and re-seal them with the active RK.

Payload AEAD AAD also binds the stable collection crypto identity, point id, and
canonical field path. On public writes Qdrant uses the collection UUID and
rejects encrypted collection configs that are missing that stable identity.

The wrapped RK AES-GCM AAD is a length-prefixed tuple of `qdrant-sec`, `v1`,
`resource-key-wrap`, the material reference, `rk_epoch`, `scope`, `wrapped_by`,
and `AES-256-GCM`. Changing the material reference, epoch, scope, or wrapping MK
therefore requires rewrapping the RK.

The generic `crypto` control plane can define reserved
`vector/openfhe-ckks@v1` runtime instances must bind both the OpenFHE process
backend and a `sym_key` metadata key material. The bridge encrypts selected
dense embeddings, while the `sym_key` protects the stored vector envelope
metadata:

```yaml
crypto:
  instances:
    docs_vector_v1:
      provider: vector/openfhe-ckks@v1
      materials:
        sym_key: tenant-a/vector-v1
      backend_ref: openfhe_local
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/vector@v1
        profile: ckks-128-n16384-d4-scale50
        crypto_context_b64: base64url-no-pad-openfhe-context
        public_key_b64: base64url-no-pad-openfhe-public-key
    docs_payload_v1:
      provider: payload/aes-256-gcm@v1
      materials:
        sym_key: tenant-a/payload-v1
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/payload@v1
        retired_materials:
          - material: tenant-a/payload-v0
            material_fingerprint_id: tenant-a/payload@v0
  materials:
    tenant-a/mk-v1:
      kind: wrapping_key_32
      source: env
      env: QDRANT_CRYPTO_MK_B64
    tenant-a/payload-v1:
      kind: wrapped_symmetric_key_32
      wrapped_by: tenant-a/mk-v1
      wrap_algorithm: AES-256-GCM
      rk_epoch: 3
      state: active
      scope: collection:docs
      nonce: base64url-no-pad-96-bit-nonce
      wrapped_key_b64: base64url-no-pad-wrapped-rk
    tenant-a/payload-v0:
      kind: wrapped_symmetric_key_32
      wrapped_by: tenant-a/mk-v1
      wrap_algorithm: AES-256-GCM
      rk_epoch: 2
      state: retired
      scope: collection:docs
      nonce: base64url-no-pad-96-bit-nonce
      wrapped_key_b64: base64url-no-pad-wrapped-rk
    tenant-a/vector-v1:
      kind: symmetric_key_32
      source: env
      env: QDRANT_VECTOR_METADATA_KEY_B64
  backends:
    openfhe_local:
      kind: process_pool
      program: /usr/local/bin/openfhe-bridge
      sha256_b64: base64url-no-pad-sha256-of-bridge
```

Generic OpenFHE backends currently accept only `process` or `process_pool`.
Any other backend `kind` is rejected during runtime settings validation.
On Linux, Qdrant sets `no_new_privs` and a parent-death `SIGKILL` immediately
before spawning the configured bridge process. This is not a complete sandbox,
but it prevents privilege gain through setuid binaries or file capabilities and
reduces orphaned plaintext-bearing bridge exposure after bridge path, ownership,
mode, parent directory, and optional SHA-256 pin checks have passed.

Collection encryption rules and runtime instances must use the same explicit
provider instance and `key_id`; runtime validation rejects missing instances,
missing material, provider/selector mismatches, and key-id mismatches instead of
falling back to legacy defaults. The configured 32-byte RK is not used directly
as an AEAD key. Qdrant derives purpose-specific HKDF-SHA256 subkeys for payload text
(`qdrant-sec/payload-text/v1`) and CKKS vector envelopes
(`qdrant-sec/vector-envelope/v1`) before constructing AES-GCM ciphers.
`crypto.allow_inline_key_material` defaults to `false` so inline key material is
rejected at startup unless explicitly enabled for local development fixtures.
Decrypt paths can be configured with active plus retired AEAD keys; new writes
always use the active key, and
envelopes record the active key id plus material fingerprint.
Server-side public writes reject fields that already contain a
`$qdrant_sec` marker so clients cannot smuggle stale or wrong-key envelopes.
If the matching runtime crypto settings or key material are absent, selected
plaintext fields are not stored as a fallback; the collection write guard rejects
the operation instead.
Rotation/backfill code must use the explicit `ReencryptIfStale` mode so old
schema/epoch/key envelopes are opened and sealed again under the current active
key.
Admin migration plans are intentionally stricter than normal config validation:
`Encrypting -> Active`, `Rotating -> Active`, and `Decrypting -> Disabled`
completion plans require non-empty verified checkpoints with every shard fully
processed. Every migration transition must name a non-zero `target_epoch`.
Initial encryption and rotation plans must also carry syntactically valid
resource-key ids so a migration cannot mark a collection active without a
traceable RK lineage. Rotation plans reject identical active and retired RK ids;
rotation must introduce a distinct active RK before the old RK becomes
read-only. `retired_rk_id` is only valid on rotation transitions. Completion
transitions cannot be marked as `dry_run`, so a dry-run preflight cannot be
reused as the operation that marks encrypted data verified or decrypted.
Read paths currently return stored encrypted markers as raw payload values.
There is no `decrypt_payload` response option, RBAC capability, or automatic
server-side payload decryption policy yet; adding decrypted responses requires
a dedicated authorization model across retrieve, scroll, search, export, logs,
and telemetry.
Generic server-side crypto instances require
`options.material_fingerprint_id` to be an opaque deployment-local key version
id. Payload and vector runtime validation rejects missing values so envelopes
do not fall back to key-derived fingerprints. Low-level test helpers may still
construct deterministic fingerprints directly from key material, but production
runtime configuration must provide explicit opaque fingerprint ids.
If the old `ckks` runtime section is configured, startup validation fails and
requires migration to the canonical `crypto` control plane before encrypted
writes are accepted.

## Storage path threat model

The intended security boundary is encrypt-before-storage for selected payload
string fields and CKKS vector ciphertext envelopes. This branch does not yet
claim complete end-to-end leakage coverage for every Qdrant storage and cluster
path; the table below is the current contract until integration tests cover each
row.

| Path | Expected protected content | Current status | Required gate before production use |
| --- | --- | --- | --- |
| REST/gRPC ingress | Request payload and plaintext embeddings may exist in process memory until encryption completes. | Trusted Qdrant process boundary. Slow-request log values and request hashes redact payloads, vectors, universal query vectors, and payload filter literals before serialization/hash calculation. | Keep request/body logging disabled or redacted for encrypted fields and embeddings. |
| WAL | Selected payload strings and CKKS vector metadata should be stored only as envelopes after encryption. | Payload sentinel leakage scans cover public server-side/client-side payload ingress and collection directory files, including WAL files. CKKS vector sidecar unit coverage verifies plaintext vectors are removed before storage, but WAL/segment vector byte-pattern scans still need end-to-end coverage. | Add optimizer temp-path coverage, vector byte-pattern leakage scans, and broaden cluster storage scans. |
| Segment files | Selected payload strings should appear as marker/envelope JSON; CKKS vector plaintext should not be stored by the CKKS envelope path. | Payload sentinel leakage scans cover persisted collection files after graceful stop. Optimizer temp-path scans are still missing. | Add optimizer temp-path leakage tests. |
| Payload indexes | AEAD-encrypted fields are not searchable as plaintext. | Index creation over encrypted payload paths and parent/child overlaps is rejected. | Keep rejecting plaintext indexes until a blind index provider exists. |
| HNSW graph and quantization | CKKS ciphertext vectors are searched through a brute-force sidecar scan, not through HNSW or quantization. | REST/gRPC nearest-neighbor search can score stored CKKS ciphertext envelopes through the OpenFHE bridge using the collection distance metric. Raw-dense average-vector recommend and raw-dense target-only discover are reduced to the same plaintext-query sidecar scoring path. HNSW/quantization paths remain unsupported for encrypted vectors. | Reject/avoid CKKS ciphertext vectors in HNSW, quantization, point-id recommend/discover, and discover-context flows until a dedicated encrypted index/executor exists. |
| Snapshots | Snapshot archives should contain encrypted payload/vector envelopes and enough metadata to preflight required keys/context and stable collection identity. | Payload sentinel leakage scan now creates and scans a collection snapshot archive. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings for missing instance/material/backend, wrong wrapped-RK key, provider key-id mismatch, missing encrypted collection UUID, and UUID mismatch. Wrong CKKS context restore tests are still missing. | Add restore tests for wrong CKKS context and broaden restore coverage across cluster paths. |
| Shard transfer and replication | Sender and receiver must have matching crypto runtime material and CKKS context. | App telemetry, peer metadata, and distributed telemetry expose a non-secret crypto runtime capability fingerprint. Encrypted collection data-movement operations validate involved peer metadata and fail closed on missing or mismatched fingerprints. Automatic dead-replica recovery skips source peers without matching parity metadata. `/readyz` does not mark the node ready for encrypted collections while peer metadata fingerprints are missing or mismatched. | Broaden distributed integration coverage and cluster-wide parity tests. |
| Telemetry, logs, and audit | No plaintext payload bodies or embeddings should be emitted. | Bridge request bodies and stderr are not included in returned errors. Collection telemetry and slow-request log-value/request-hash smoke tests cover payload/vector/filter/query sentinels. | Broaden audit/log capture coverage around any new request logging surfaces. |

## CKKS vectors

`EncryptedCkksVector` stores an AEAD-sealed metadata envelope. The sealed body
contains the OpenFHE CKKS ciphertext plus `key_id`, `vector_name`, `slots`, and
`context_digest`, so storage-side tampering of vector metadata fails closed. The
AEAD key comes from the collection CKKS runtime key material, while the OpenFHE
public material still encrypts the embedding itself:

```json
{
  "version": 1,
  "scheme": "openfhe-ckks",
  "envelope": {
    "version": 1,
    "algorithm": "AES-256-GCM",
    "key_id": "tenant-a:ckks",
    "material_fingerprint": "...",
    "rk_id": "tenant-a/vector-v1",
    "rk_epoch": 3,
    "nonce": "...",
    "ciphertext": "..."
  }
}
```

The vector envelope uses `collection identity`, `point_id`, and `vector_name`
AAD binding. New callers should pass the persisted collection UUID or a stable
crypto collection id as the vector collection identity. Collection-level
encrypted vector write/read/search guards require a persisted UUID and do not
fall back to collection name. Moving an encrypted vector envelope to a different
point, vector name, or collection identity must fail authentication after
unwrap.
Inside the sealed body, `context_digest` is still the SHA-256 digest over the
CKKS parameters, serialized OpenFHE crypto context, and public key. It is
intended to prevent mixing ciphertexts created for incompatible contexts.
CKKS parameters are restricted to the allowlisted
`ckks-128-n16384-d4-scale50` profile in this branch. Generic
`vector/openfhe-ckks@v1` runtime instances must set this `profile` option plus
`crypto_context_b64` and `public_key_b64`; a missing profile, missing public
material, or raw profile name is rejected before collection creation.
`batch_size` may be lower than the profile slot count, but raw
modulus/depth/scale combinations are rejected. OpenFHE bridge encrypt, batch
encrypt, and scoring responses must include `security_profile`; Qdrant verifies
that it matches the requested allowlisted profile. Carrying richer
security-level/noise-budget metadata remains future hardening.

Nearest-neighbor search over an encrypted vector name is implemented only for
REST/gRPC dense query vectors when runtime `crypto` settings are available on
the serving node. This includes legacy `search` requests and root direct
nearest-neighbor `query` requests. Qdrant scrolls the encrypted sidecar payloads,
validates each CKKS envelope against the active OpenFHE public material/context
digest, and sends `score_plaintext_query` requests to the bridge. Result
ordering and `score_threshold` follow the configured Qdrant distance metric:
`dot`/`cosine` are larger-is-better, while `euclid`/`manhattan` are
smaller-is-better. `search/groups` and root direct `query/groups` are supported
only when the group field is plaintext payload, `with_lookup` is disabled, and
runtime OpenFHE settings are available; Qdrant scores the sidecar brute-force,
groups the ranked hits, and returns the requested payload without returning
plaintext vectors. This executor is intentionally brute-force: it does not use
HNSW pruning, quantization, ACORN/indexed-only params, search matrix,
prefetch/fusion/MMR, or encrypted query ciphertexts. Legacy `recommend` and
universal recommend queries are supported only for `average_vector` strategy
when every positive/negative example is a raw dense vector supplied by the
client; point-id, sparse, best-score, and sum-score examples fail closed because
Qdrant does not retain plaintext vectors. Legacy `discover` and universal
discover queries are supported only for a raw dense target with no context
pairs. Direct collection-internal calls without runtime settings still fail
closed for encrypted vector names. The
`$qdrant_sec_vectors` payload sidecar is an internal ciphertext container:
clients may receive it raw when payloads are requested, but Qdrant rejects
payload indexes, filters, ordering, grouping, facets, and formula references
that target the sidecar field.

## OpenFHE bridge protocol

`CommandOpenFheBackend` invokes an external bridge binary as a long-lived worker.
The bridge reads newline-delimited JSON requests from stdin and writes one
newline-delimited JSON response per request to stdout. The backend reuses the
same child process while the bridge stays healthy and respawns it if the worker
exits between requests.
Vector encryption requests use `operation: encrypt`; plaintext-query scoring
requests use `operation: score_plaintext_query` for single-point scoring or
`operation: score_plaintext_query_batch` for scroll-batch scoring. Both include
the profile parameters, OpenFHE public material, collection/vector routing
metadata, the collection `distance` metric (`dot`, `cosine`, `euclid`, or
`manhattan`), plaintext query values, and stored CKKS ciphertext bytes. Batch
score responses must preserve request item order and return exactly one finite
score per item. All encrypt, batch encrypt, and scoring responses must include
`security_profile`, and it must equal the configured allowlisted CKKS profile.
The subprocess backend still enforces a positive `timeout_ms` and caps
stdout/stderr collection so a hung or noisy bridge cannot block Qdrant
indefinitely or force unbounded memory growth. Returned errors do not include
the request body or bridge stderr.

The OpenFHE bridge is part of the trusted computing base because it receives
plaintext embeddings before producing CKKS ciphertext. Runtime configuration
therefore accepts only absolute bridge paths that resolve to executable regular
files, rejects symlinks and group/world-writable binaries or parent directories
on Unix, and requires the binary plus every parent directory to be owned by root
or the Qdrant process user. Generic process backends must set `sha256_b64` to
pin the expected bridge binary digest; generic runtime validation and checked
backend construction both hash the bridge through a no-follow file descriptor
on Unix.
Treat any bridge path change as privileged code
execution under the Qdrant service account. On Linux, the checked bridge spawn path also
sets `no_new_privs`, parent-death `SIGKILL`, and `RLIMIT_CORE=0` so the
plaintext-bearing bridge cannot gain extra privileges through
setuid/file-capability execution, is killed if Qdrant exits, and does not
produce normal core dumps. The bridge child also drops inherited environment
variables named `QDRANT` or whose names start with `QDRANT_`, so env-backed
Qdrant settings and crypto material are not handed to the bridge process by
default.

Request fields:

```json
{
  "version": 1,
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "point_id": "point-1",
  "vector_name": "embedding",
  "parameters": {
    "poly_modulus_degree": 16384,
    "multiplicative_depth": 4,
    "scaling_mod_size": 50,
    "first_mod_size": 60,
    "batch_size": 8192
  },
  "crypto_context": "base64url-no-pad",
  "public_key": "base64url-no-pad",
  "values": [0.125, -42.5, 9.75]
}
```

Response fields:

```json
{
  "version": 1,
  "ciphertext": "base64url-no-pad-openfhe-ciphertext"
}
```

The Rust `CkksVectorBackend` trait also exposes `encrypt_batch` so backends can
amortize vector encryption overhead. `CommandOpenFheBackend` sends one
newline-delimited batch request with shared parameters/material and per-point
items:

```json
{
  "version": 1,
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "vector_name": "embedding",
  "parameters": {
    "poly_modulus_degree": 16384,
    "multiplicative_depth": 4,
    "scaling_mod_size": 50,
    "first_mod_size": 60,
    "batch_size": 8192
  },
  "crypto_context": "base64url-no-pad",
  "public_key": "base64url-no-pad",
  "items": [
    { "point_id": "point-1", "values": [0.125, -42.5] },
    { "point_id": "point-2", "values": [9.75, 3.5] }
  ]
}
```

The bridge response must preserve item order:

```json
{
  "version": 1,
  "ciphertexts": [
    "base64url-no-pad-openfhe-ciphertext-1",
    "base64url-no-pad-openfhe-ciphertext-2"
  ]
}
```

`CkksVectorEncryptor` still validates each input vector before the backend call
and seals every returned ciphertext with per-point AAD.

Plaintext-query batch scoring uses the same shared context and query fields,
but each item carries the stored ciphertext for one point:

```json
{
  "version": 1,
  "operation": "score_plaintext_query_batch",
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "vector_name": "embedding",
  "distance": "dot",
  "parameters": {
    "poly_modulus_degree": 16384,
    "multiplicative_depth": 4,
    "scaling_mod_size": 50,
    "first_mod_size": 60,
    "batch_size": 8192
  },
  "crypto_context": "base64url-no-pad",
  "public_key": "base64url-no-pad",
  "query_values": [0.25, -1.5],
  "items": [
    { "point_id": "point-1", "ciphertext": "base64url-no-pad-ciphertext-1" },
    { "point_id": "point-2", "ciphertext": "base64url-no-pad-ciphertext-2" }
  ]
}
```

The bridge response must preserve item order and include the expected profile:

```json
{
  "version": 1,
  "security_profile": "ckks-128-n16384-d4-scale50",
  "scores": [9.0, 4.0]
}
```

If the response score count differs from the request item count, or any score
is non-finite, Qdrant discards the bridge response and fails the search.

The Rust side does not include request or bridge stderr in returned errors to
avoid accidentally propagating plaintext embeddings into logs.
