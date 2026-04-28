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
| `upsert` payload | Supported for selected JSON string fields. Values are encrypted before storage and client-supplied `$qdrant_ckks` markers are rejected. | Supported for selected fields that already contain a valid `$qdrant_client_aead` marker. Qdrant validates schema, AAD metadata, key policy, and optional Ed25519 signature, but does not decrypt. | Unsupported. CKKS vector selectors are rejected until ciphertext storage/search semantics are implemented. |
| `set_payload` / `overwrite_payload` | Supported for a single explicit point when Qdrant can bind AAD to the point id. Filter-based, key-path, and multi-point encrypted-field updates fail closed. | Same point-id limitation as server-side payload writes. Clients must provide one envelope per point/field. | Not applicable. |
| `update_vectors` | Not applicable. | Not applicable. | Unsupported. Plaintext writes to encrypted vector names fail closed. |
| Payload indexes, filters, facets, ordering, grouping, and formulas | Plaintext indexes, filters, facet keys, order-by keys, group-by keys, and formula payload references over encrypted paths, parent paths, or child paths are rejected. Searching, ordering, grouping, or aggregating encrypted content requires a future blind-index provider. | Same policy. The opaque ciphertext field is not searchable, orderable, groupable, or facetable as plaintext. | Payload filtering/faceting over encrypted metadata is unsupported. |
| `retrieve`, `scroll`, and `search` result payloads | Stored `$qdrant_ckks` markers are returned raw. There is no `decrypt_payload` option or RBAC capability yet. | Stored `$qdrant_client_aead` markers are returned raw for SDK/client decryption. | Search over CKKS ciphertext vectors is unsupported; separate plaintext or surrogate vectors must be modeled explicitly outside this branch. |
| Snapshots | Snapshot archives are expected to contain envelopes only; payload sentinel snapshot leakage is covered by integration tests. Restore key preflight is still missing. | Same stored-value behavior as server-side payloads. Qdrant cannot validate client AEAD tags without client keys. | Restore requires matching OpenFHE context/runtime material, but fail-closed restore preflight is not implemented yet. |
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
      options:
        key_id: tenant-a/client-rk-2026-04
        key_id_required: true
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

This provider does not receive plaintext and does not unwrap a data key. The
client encrypts before insert and Qdrant only validates the envelope schema,
AAD metadata, key policy, nonce/ciphertext encoding, and optional Ed25519
signature before storing the opaque ciphertext. If
`signature_public_keys` is configured, every write must carry a valid
`signature` object whose `key_id` selects one configured public key. The legacy
single-key options `signature_key_id` and `signature_public_key_b64` are still
accepted, but they cannot be mixed with `signature_public_keys`.

For payload writes, the `aad.collection_id` value is the collection's stable
crypto identity. New collection configs should use the persisted collection UUID
when available; legacy/test collections without a UUID fall back to the
collection name.

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
envelopes. The Ed25519 signature covers the client envelope header, AAD,
nonce, ciphertext, signature algorithm, and signature key id. Blind-index query
integration is not implemented yet. Exact-match search requires a future client
blind-index field, and range, geo, or full-text search over client ciphertext
remains unsupported.

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
adapter, `master_key_b64` is a direct 32-byte resource key (RK), not a master
key-encryption key. Prefer injecting that legacy RK through environment
variables such as `QDRANT__CKKS__COLLECTIONS__docs__MASTER_KEY_B64` instead of
committing it to config files:

```yaml
ckks:
  enabled: true
  allow_inline_key_material: false
  collections:
    docs:
      key_id: tenant-a:docs
      master_key_b64: base64url-no-pad-32-byte-key
      openfhe_bridge_path: /usr/local/bin/openfhe-bridge
      openfhe_bridge_sha256_b64: base64url-no-pad-sha256-of-bridge
```

The generic `crypto` control plane supports a safer MK/RK hierarchy:

- `wrapping_key_32` is an MK/KEK loaded from env/file/inline material.
- `wrapped_symmetric_key_32` is a random collection or rule RK wrapped by that
  MK using AES-256-GCM.
- Payload text and CKKS vector envelope AEAD keys are still purpose-specific
  HKDF subkeys derived from the unwrapped RK.

Data envelopes record the runtime `key_id`, material fingerprint, and, for
wrapped RK material, the `rk_id` plus `rk_epoch` used for the RK-derived subkey.
They do not reference the MK directly, so MK rotation can rewrap the stored RK
manifest without rewriting payload/vector envelopes. The low-level
`rewrap_resource_key` helper implements that primitive by unwrapping the RK with
the old MK/AAD and immediately wrapping the same RK with the new MK/AAD. RK
rotation still requires a data re-encryption job and should use the explicit
re-encryption mode rather than normal write-path idempotency. The
`rk_id`/`rk_epoch` fields are included in AEAD AAD when present, so storage-side
edits to resource-key identity fail closed.

Payload AEAD AAD also binds the stable collection crypto identity, point id, and
canonical field path. On public writes Qdrant uses the collection UUID when the
collection config has one and falls back to the collection name only for legacy
configs without a UUID.

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
Rotation/backfill code must use the explicit `ReencryptIfStale` mode so old
schema/epoch/key envelopes are opened and sealed again under the current active
key.
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
| Snapshots | Snapshot archives should contain encrypted payload/vector envelopes and enough metadata to preflight required keys/context. | Payload sentinel leakage scan now creates and scans a collection snapshot archive. Restore key/context preflight is still missing. | Add restore preflight for missing/wrong keys and wrong CKKS context. |
| Shard transfer and replication | Sender and receiver must have matching crypto runtime material and CKKS context. | Not yet implemented. | Add cluster capability parity checks and fail-closed transfer tests. |
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

The vector envelope uses the same `collection`, `point_id`, and `vector_name`
AAD binding as payload encryption. Moving an encrypted vector envelope to a
different point or vector name must fail authentication after unwrap.
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

The Rust side does not include request or bridge stderr in returned errors to
avoid accidentally propagating plaintext embeddings into logs.
