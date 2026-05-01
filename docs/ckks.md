# qdrant-sec encryption boundary

The `sec` branch adds a small `qdrant-ckks` workspace crate for encrypted
payload text and OpenFHE CKKS vector ciphertext envelopes.

Current scope is encrypted storage plumbing, not CKKS-native vector search.
Payload text encryption happens before storage, and CKKS vectors are wrapped as
ciphertext envelopes, but this branch does not add encrypted query vectors,
homomorphic scoring, score decryption, or an HNSW-compatible ciphertext search
executor. Collections that enable CKKS vectors must treat that path as
at-rest/envelope protection unless a separate plaintext or surrogate search path
is explicitly configured.

Unsupported search/index features for CKKS ciphertext vectors in this branch:

- HNSW similarity search directly over CKKS ciphertext
- quantization over CKKS ciphertext
- recommend/discover flows that require vector arithmetic over encrypted values
- payload filtering over encrypted metadata
- shard transfer or snapshot restore without matching runtime keys and OpenFHE
  context material

## Feature support matrix

This branch is intentionally fail-closed for encrypted data paths that are not
fully wired. The table below is the user-facing contract for the current
implementation.

| API/path | Server-side payload AEAD | Client-side payload envelope | CKKS vector envelope |
| --- | --- | --- | --- |
| `upsert` payload | Supported for selected JSON string fields. Values are encrypted before storage and client-supplied `$qdrant_ckks` markers are rejected. | Supported for selected fields that already contain a valid `$qdrant_client_aead` marker. Qdrant validates schema, AAD metadata, key policy, and a mandatory Ed25519 signature, but does not decrypt. | Unsupported. CKKS vector selectors are rejected until ciphertext storage/search semantics are implemented. |
| `set_payload` / `overwrite_payload` | Supported for explicit point ids when Qdrant can bind AAD to each point id. Multi-point updates are fanned out into one encrypted operation per point; filter-based and key-path encrypted-field updates fail closed. | Same explicit-point-id limitation as server-side payload writes. Clients must provide one envelope per point/field; filter-based and key-path encrypted-field updates fail closed. | Not applicable. |
| `update_vectors` | Not applicable. | Not applicable. | Unsupported. Plaintext writes to encrypted vector names fail closed. |
| Payload indexes, filters, facets, ordering, grouping, and formulas | Plaintext indexes, read/update filters, facet keys, order-by keys, group-by keys, and formula payload references over encrypted paths, parent paths, or child paths are rejected. Searching, mutating by filter, ordering, grouping, or aggregating encrypted content requires a future blind-index provider. | Same policy. The opaque ciphertext field is not searchable, orderable, groupable, facetable, or usable in mutation filters as plaintext. | Payload filtering/faceting over encrypted metadata is unsupported. |
| `retrieve`, `scroll`, and `search` result payloads | Stored `$qdrant_ckks` markers are returned raw. There is no `decrypt_payload` option or RBAC capability yet. | Stored `$qdrant_client_aead` markers are returned raw for SDK/client decryption. | Search over CKKS ciphertext vectors is unsupported; separate plaintext or surrogate vectors must be modeled explicitly outside this branch. |
| Snapshots | Snapshot archives are expected to contain envelopes only; payload sentinel snapshot leakage is covered by integration tests. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings, including missing material, wrong wrapped-RK key, and provider key-id mismatch cases. | Same stored-value behavior as server-side payloads. Qdrant cannot validate client AEAD tags without client keys. | Restore requires matching OpenFHE context/runtime material; missing runtime instance/material/backend preflight is wired, while wrong-context restore coverage is still missing. |
| Shard transfer / replication | Requires matching crypto runtime material on all nodes. Cluster parity checks are not implemented yet. | Requires matching client-envelope verifier policy on all nodes. | Requires matching OpenFHE context and metadata AEAD material on all nodes; cluster parity checks are not implemented yet. |
| Metadata encryption | Not implemented. `metadata_keys` selectors are reserved and rejected. | Not implemented. | Not implemented. |

## Payload text

Selected JSON string fields are replaced with a single marker object:

```json
{
  "$qdrant_ckks": {
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
`$qdrant_ckks`, `$qdrant_client_aead`, or `$qdrant_ciphertext` are rejected.

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
    encryption_epoch: 0
    migration_state: active
    rules:
      - id: body_client_conf
        selector:
          kind: payload_paths
          paths: [body]
        instance: docs_payload_client_v1
        binding: client-payload-envelope/v1
```

`payload/client-aead@v1` fails runtime validation if `materials` is non-empty
or `backend_ref` is configured. Server-side wrapping keys/RKs belong to
`payload/aes-256-gcm@v1`; client-side payload envelopes must keep client data
keys outside the Qdrant process. It also fails validation unless
`key_id` is required and `expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch`
are set explicitly. `expected_rk_id` must match the collection encryption
`key_id`. `min_rk_epoch` and `max_rk_epoch` must be identical; broad epoch
ranges are rejected so a client provider pins exactly one active resource-key
epoch.

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
`kdf_domain: qdrant/client-payload-text/v1`. Provider instances must pin
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
request, including `update_batch`, by tracking `(key_id, rk_id, rk_epoch,
nonce)` while validating envelopes. This is a request-local guard only. A
persistent replay index is not implemented, so SDKs must generate fresh 96-bit
CSPRNG nonces and regenerate envelopes on retry instead of replaying failed
request bodies.

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
      "kdf_domain": "qdrant/client-payload-text/v1",
      "aad": {
        "collection_id": "collection-uuid-or-legacy-name",
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
`payload/aes-256-gcm@v1` rule reject client-supplied `$qdrant_ckks` markers, and
`payload/client-aead@v1` rules require `$qdrant_client_aead` markers. Because
Qdrant does not have the client data key in this mode, it cannot verify the
AES-GCM tag or decrypt responses; clients or SDKs must decrypt returned
envelopes. Client envelopes must include `rk_id`, `rk_epoch`, and
`kdf_domain: qdrant/client-payload-text/v1` so resource-key identity is explicit
even though Qdrant cannot unwrap the client key. The Ed25519 signature covers the
client envelope header, AAD,
nonce, ciphertext, signature algorithm, and signature key id. Blind-index query
integration is not implemented yet. Exact-match search requires a future client
blind-index field, and range, geo, or full-text search over client ciphertext
remains unsupported.

SDKs that implement this mode must do all cryptographic data-key operations
outside Qdrant:

- Generate a random client RK and derive the payload AEAD key with
  `qdrant/client-payload-text/v1`; do not send the RK to Qdrant.
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

Collection params enable encryption and select fields/vectors per collection:

```yaml
params:
  ckks:
    enabled: true
    key_id: tenant-a:docs
    payload_text_fields: [body]
    vector_names: [embedding]
```

Metadata encryption is not implemented yet. The generic control-plane types
reserve a `metadata_keys` selector for future value encryption and exact-match
token designs, but collection validation rejects metadata selectors in this
branch. Payload filtering over encrypted metadata, including range, geo, and
full-text filtering, is unsupported until a separate blind-index design exists.

Runtime settings provide key material per collection. In the legacy `ckks`
adapter, `resource_key_b64` is a direct 32-byte resource key (RK), not a master
key-encryption key. The old `master_key_b64` name remains as a legacy alias only
and cannot be configured together with `resource_key_b64`. Prefer injecting that
legacy RK through environment variables such as
`QDRANT__CKKS__COLLECTIONS__docs__RESOURCE_KEY_B64` instead of committing it to
config files:

```yaml
ckks:
  enabled: true
  allow_inline_key_material: false
  collections:
    docs:
      key_id: tenant-a:docs
      resource_key_b64: base64url-no-pad-32-byte-key
      openfhe_bridge_path: /usr/local/bin/openfhe-bridge
      openfhe_bridge_sha256_b64: base64url-no-pad-sha256-of-bridge
```

The generic `crypto` control plane supports a safer MK/RK hierarchy:

- `wrapping_key_32` is an MK/KEK loaded from env/file/inline material.
- `wrapped_symmetric_key_32` is a random collection or rule RK wrapped by that
  MK using AES-256-GCM.
- Payload text and CKKS vector envelope AEAD keys are still purpose-specific
  HKDF subkeys derived from the unwrapped RK.

Wrapped RK material may declare a lifecycle `state`:

- `active` or omitted: the RK can be unwrapped and used for new encryption.
- `retired`: the RK is read-only and must not be selected for new write plans.
- `disabled` or `destroyed`: the RK must not be unwrapped by runtime crypto.

Runtime validation includes this non-secret state in the cluster capability
fingerprint so nodes disagreeing on RK lifecycle cannot silently accept the same
collection plan.

Data envelopes record the runtime `key_id`, material fingerprint, and, for
wrapped RK material, the `rk_id` plus `rk_epoch` used for the RK-derived subkey.
They do not reference the MK directly, so MK rotation can rewrap the stored RK
manifest without rewriting payload/vector envelopes. The low-level
`rewrap_resource_key` helper implements that primitive by unwrapping the RK with
the old MK/AAD and immediately wrapping the same RK with the new MK/AAD. RK
rotation still requires a data re-encryption job and should use the explicit
re-encryption mode rather than normal write-path idempotency. The
`rk_id`/`rk_epoch` fields are included in AEAD AAD for server-generated payload
and vector envelopes, so storage-side edits to resource-key identity fail closed.

Payload AEAD AAD also binds the stable collection crypto identity, point id, and
canonical field path. On public writes Qdrant uses the collection UUID and
rejects encrypted collection configs that are missing that stable identity.

The wrapped RK AES-GCM AAD is a length-prefixed tuple of `qdrant-sec`, `v1`,
`resource-key-wrap`, the material reference, `rk_epoch`, `scope`, `wrapped_by`,
and `AES-256-GCM`. Changing the material reference, epoch, scope, or wrapping MK
therefore requires rewrapping the RK.

In the generic `crypto` control plane, vector rules must bind both the OpenFHE
process backend and a `sym_key` metadata key material. The bridge encrypts the
embedding, while the `sym_key` protects the stored vector envelope metadata:

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
    docs_payload_v1:
      provider: payload/aes-256-gcm@v1
      materials:
        sym_key: tenant-a/payload-v1
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/payload@v1
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

If both collection params and the matching `ckks.collections.<name>` runtime
entry specify `key_id`, they must match. Otherwise the collection value wins,
then the collection runtime value, then the global default. This prevents
accidentally encrypting a collection with the wrong key.
The configured 32-byte master key is not used directly as an AEAD key. Qdrant
derives purpose-specific HKDF-SHA256 subkeys for payload text
(`qdrant/payload-text/v1`) and CKKS vector envelopes
(`qdrant/vector-envelope/v1`) before constructing AES-GCM ciphers.
`crypto.allow_inline_key_material` and `ckks.allow_inline_key_material` default
to `false` so inline key material is rejected at startup unless explicitly
enabled for local development fixtures. Decrypt paths can be configured with
active plus retired AEAD keys; new writes always use the active key, and
envelopes record the active key id plus material fingerprint.
Server-side public writes reject fields that already contain a
`$qdrant_ckks` marker so clients cannot smuggle stale or wrong-key envelopes.
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
do not fall back to key-derived fingerprints. Direct legacy CKKS settings and
low-level test helpers can still fall back to a deterministic fingerprint
derived from the key material; that fallback is not secret, can reveal key reuse
across collections or deployments, and should be limited to migration or local
development fixtures.
When `ckks.enabled` is true, startup validates any configured key ids, master
keys, and OpenFHE bridge paths so bad runtime key material fails before the
first encrypted write.

## Storage path threat model

The intended security boundary is encrypt-before-storage for selected payload
string fields and CKKS vector ciphertext envelopes. This branch does not yet
claim complete end-to-end leakage coverage for every Qdrant storage and cluster
path; the table below is the current contract until integration tests cover each
row.

| Path | Expected protected content | Current status | Required gate before production use |
| --- | --- | --- | --- |
| REST/gRPC ingress | Request payload and plaintext embeddings may exist in process memory until encryption completes. | Trusted Qdrant process boundary. | Avoid request/body logging for encrypted fields and embeddings. |
| WAL | Selected payload strings and CKKS vector metadata should be stored only as envelopes after encryption. | Payload sentinel leakage scan covers the collection directory, including WAL files, for the marker-upsert path. Vector-pattern scans are still missing. | Add vector-pattern scans and cover public API encryption ingress. |
| Segment files | Selected payload strings should appear as marker/envelope JSON; CKKS vector plaintext should not be stored by the CKKS envelope path. | Payload sentinel leakage scan covers persisted collection files after graceful stop. Optimizer temp-path and vector-pattern scans are still missing. | Add optimizer temp-path and vector-pattern leakage tests. |
| Payload indexes | AEAD-encrypted fields are not searchable as plaintext. | Index creation over encrypted payload paths and parent/child overlaps is rejected. | Keep rejecting plaintext indexes until a blind index provider exists. |
| HNSW graph and quantization | CKKS ciphertext vectors are not HNSW-searchable in this branch. | Unsupported. | Reject/avoid CKKS ciphertext vectors in HNSW, quantization, recommend, and discover flows. |
| Snapshots | Snapshot archives should contain encrypted payload/vector envelopes and enough metadata to preflight required keys/context and stable collection identity. | Payload sentinel leakage scan now creates and scans a collection snapshot archive. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings for missing instance/material/backend, wrong wrapped-RK key, provider key-id mismatch, missing encrypted collection UUID, and UUID mismatch. Wrong CKKS context restore tests are still missing. | Add restore tests for wrong CKKS context and broaden restore coverage across cluster paths. |
| Shard transfer and replication | Sender and receiver must have matching crypto runtime material and CKKS context. | App and distributed peer telemetry expose a non-secret crypto runtime capability fingerprint that operators or future cluster code can compare, but shard transfer does not yet enforce parity automatically. | Add cluster capability parity checks and fail-closed transfer tests. |
| Telemetry, logs, and audit | No plaintext payload bodies or embeddings should be emitted. | Bridge request bodies and stderr are not included in returned errors; broader logging scans are still missing. | Add telemetry/log smoke tests with sentinel values. |

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
`vector/openfhe-ckks@v1` runtime instances must set this `profile` option; a
missing profile or raw profile name is rejected before collection creation.
`batch_size` may be lower than the profile slot count, but raw
modulus/depth/scale combinations are rejected until the OpenFHE bridge returns
and verifies explicit security-level metadata.

## OpenFHE bridge protocol

`CommandOpenFheBackend` invokes an external bridge binary as a long-lived worker.
The bridge reads newline-delimited JSON requests from stdin and writes one
newline-delimited JSON response per request to stdout. The backend reuses the
same child process while the bridge stays healthy and respawns it if the worker
exits between requests.
The subprocess backend still enforces a timeout and caps stdout/stderr
collection so a hung or noisy bridge cannot block Qdrant indefinitely or force
unbounded memory growth. Returned errors do not include the request body or
bridge stderr.

The OpenFHE bridge is part of the trusted computing base because it receives
plaintext embeddings before producing CKKS ciphertext. Runtime configuration
therefore accepts only absolute bridge paths that resolve to executable regular
files, rejects symlinks and group/world-writable binaries or parent directories
on Unix, and requires the binary plus every parent directory to be owned by root
or the Qdrant process user. Set `sha256_b64` in generic backends or
`openfhe_bridge_sha256_b64` in legacy CKKS runtime settings to pin the expected
bridge binary digest. Treat any bridge path change as privileged code execution
under the Qdrant service account.

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

The Rust side does not include request or bridge stderr in returned errors to
avoid accidentally propagating plaintext embeddings into logs.
