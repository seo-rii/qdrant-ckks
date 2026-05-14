# qdrant-sec encryption boundary

The `sec` branch adds a small `qdrant-sec` workspace crate for encrypted
payload text and OpenFHE CKKS vector ciphertext envelopes.

Current scope is encrypted storage plus CKKS sidecar search. Payload text
encryption happens before storage. CKKS vector selectors have a server-side
ingest/storage path:
selected dense vectors are encrypted through the configured OpenFHE bridge and
stored as reserved payload sidecar envelopes, while the plaintext vector is
removed from the dense vector write. REST/gRPC nearest-neighbor `search` and
root direct `query` over an encrypted vector name use sidecar scoring that first
asks the OpenFHE bridge to encrypt the query vector, then scores stored
ciphertexts against that encrypted query ciphertext. When `hnsw_ef` is provided
on a raw dense or stored point-id nearest-neighbor request, Qdrant builds an
experimental ciphertext sidecar candidate graph and searches it with encrypted
query scores; otherwise it uses the exact brute-force sidecar scan. The same
sidecar scorer also handles root direct `query` and `query/groups` requests
that use a point id as the nearest-neighbor query. Qdrant loads that point's
stored CKKS sidecar envelope
and asks the bridge to score stored ciphertexts against it without reading a
plaintext vector. The same sidecar scorer also handles raw-dense recommend requests
(`average_vector`, `best_score`, and `sum_scores`), legacy discover requests
and universal discover/context requests with raw-dense or point-id
target/context examples.
REST/gRPC universal `query`/`query/groups` and REST/gRPC legacy
`search`/`search/groups` nearest-neighbor requests may also provide a
client-supplied CKKS encrypted query ciphertext envelope. Qdrant
validates the envelope version, scheme, allowlisted profile, context digest, and
slot count against the active vector rule, then sends the ciphertext directly to
`score_encrypted_query_batch` without asking the bridge to encrypt a plaintext
query. Score decryption and reuse of Qdrant's plaintext-vector `HNSWIndex` file
format for CKKS ciphertexts remain out of scope. The experimental sidecar HNSW
path now uses a segment-level CKKS ciphertext vector index primitive; that
primitive can expose and persist its graph as a segment index artifact, while
the serving query path still sources encrypted records from the reserved
payload sidecar.

Unsupported search/index features for CKKS ciphertext vectors in this branch:

- reuse of the plaintext-vector `HNSWIndex` graph file format directly over CKKS ciphertext
- quantization over CKKS ciphertext
- recommend/discover/context flows that require client-supplied encrypted query
  ciphertexts or server-side vector arithmetic over encrypted values
- grouped lookup that requests encrypted vectors from the lookup collection
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
| Payload indexes, filters, facets, ordering, grouping, and formulas | Plaintext indexes, read/update filters, facet keys, order-by keys, group-by keys, and formula payload references over encrypted paths, parent paths, child paths, or `metadata/aes-256-gcm@v1` metadata value paths are rejected. Exact-match search can use a separate client-generated blind-index token field configured through `metadata/blind-index-hmac@v1`; encrypted content itself is not indexed. | Same policy. The opaque ciphertext field is not searchable, orderable, groupable, facetable, or usable in mutation filters as plaintext. Exact-match search requires a separate blind-index token field. | The reserved `$qdrant_sec_vectors` sidecar field is not indexable, filterable, orderable, groupable, facetable, or usable in formulas. Payload filtering/faceting over encrypted metadata is unsupported unless it uses a separate blind-index token field. |
| `retrieve`, `scroll`, `search`, and `query` result payloads | Stored `$qdrant_sec` markers are returned raw by default. REST/gRPC `retrieve`, `scroll`, legacy `search`, batch search, universal `query`, batch query, `recommend`, batch recommend, `discover`, batch discover, and grouped result hits may use `{"encrypted_payload":"decrypted"}` to decrypt server-side payload text and metadata value AEAD fields only when runtime crypto settings are available and the caller has global manage access or collection `payload_decrypt` capability; the same mode fails closed without runtime settings or sufficient privilege. REST payload selectors may use `{"encrypted_payload":"redacted"}` to return payloads while replacing encrypted marker values with redaction sentinels. Group lookup payloads remain raw/redacted only because they may come from a different collection. | Stored `$qdrant_client_aead` markers are returned raw by default for SDK/client decryption, or redacted with the same `encrypted_payload` selector. Qdrant never decrypts client-side envelopes. | Stored vector sidecar payload envelopes are returned raw by default when payloads are requested, or redacted with the same `encrypted_payload` selector. Read/search/query/recommend/discover paths, including grouped variants, reject `with_vector=true` or selectors that request encrypted vector names; clients must request the payload sidecar instead. REST/gRPC nearest-neighbor dense-vector `search`, `search/groups`, REST/gRPC legacy client-encrypted nearest `search`, REST/gRPC legacy client-encrypted nearest `search/groups`, root direct `query`, root direct point-id nearest `query`, root direct REST/gRPC client-encrypted nearest `query`, root direct `query/groups`, root direct point-id nearest `query/groups`, root direct REST/gRPC client-encrypted nearest `query/groups`, root direct `NearestWithMmr` and `NearestWithMmr` query groups, `search/matrix`, raw-dense/point-id `recommend` (`average_vector`, `best_score`, `sum_scores`), legacy `discover` with raw-dense or point-id target/context examples, and universal `discover`/`discover groups`/`context`/`context groups` queries with raw-dense or point-id target/context examples are supported with runtime OpenFHE settings. Batch search/query/recommend/discover may mix encrypted vector names and plaintext vector names; each request is routed independently and output order is preserved. Nearest-neighbor requests may set `hnsw_ef` to use the ciphertext sidecar candidate graph for raw dense query vectors, client-encrypted query ciphertexts, and stored point-id query vectors; exact requests and non-HNSW requests use brute-force sidecar scoring. Matrix requests sample stored sidecars and score pairwise stored ciphertexts. Universal query prefetches over encrypted vector names are supported for RRF/DBSF fusion and as non-fusion candidate filters for encrypted or plaintext root queries. MMR uses query-to-candidate CKKS scores for relevance and candidate-to-candidate CKKS scores for diversity on large-better metrics. Quantization/ACORN/indexed-only search params remain unsupported. |
| Snapshots | Snapshot archives are expected to contain envelopes only; payload sentinel snapshot leakage is covered by integration tests. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings, including missing material, wrong wrapped-RK key, and provider key-id mismatch cases. | Same stored-value behavior as server-side payloads. Qdrant cannot validate client AEAD tags without client keys. | Restore requires matching OpenFHE context/runtime material. Missing runtime instance/material/backend and invalid OpenFHE public-material preflight are covered; valid-but-different context drift is enforced by runtime capability parity and envelope `context_digest` checks when sidecars are opened/scored. |
| Shard transfer / replication | Encrypted collection data-movement operations require matching non-secret crypto runtime capability fingerprints in peer metadata. Operations fail closed if any involved peer has missing or mismatched metadata. Automatic dead-replica recovery only proposes encrypted shard transfers from source peers with matching parity metadata. | Same policy; client-envelope verifier policy must match across nodes before encrypted transfers are allowed. | Same policy; matching OpenFHE context and metadata AEAD material must be enforced before encrypted transfers are allowed. |
| Metadata encryption | `metadata/aes-256-gcm@v1` supports selected JSON string metadata values with `metadata-value/v1`; these values use the same server-side AEAD envelope, fail closed for plaintext indexing/filtering, and participate in `encrypted_payload:"decrypted"` reads under the same `payload_decrypt` access policy. `metadata_keys` selectors also support client-generated exact-match blind-index token fields with `metadata-exact-match-token/v1`. | Client-side metadata value encryption should use `payload/client-aead@v1` on the metadata field plus a separate blind-index token field for exact match. Qdrant stores opaque blind-index tokens and never computes them. | CKKS vector metadata sealing is separate from payload metadata value encryption. |

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
`payload/aes-256-gcm@v1`, `payload/client-aead@v1`,
`metadata/aes-256-gcm@v1`, `metadata/blind-index-hmac@v1`, and
`vector/openfhe-ckks@v1`.
Unknown provider IDs fail runtime settings
validation instead of being treated as extension points.
`payload/aes-256-gcm@v1` must bind a `materials.sym_key` resource key and set
an explicit `options.material_fingerprint_id`; it must not configure
`backend_ref`; it is an in-process AEAD provider, not an OpenFHE bridge client.
`metadata/aes-256-gcm@v1` has the same material and fingerprint requirements,
but it must be selected through `metadata_keys` with `metadata-value/v1`.
`vector/openfhe-ckks@v1` must bind `materials.sym_key` for vector envelope
metadata sealing, set `options.material_fingerprint_id`, and configure
`backend_ref` for the OpenFHE bridge.
`metadata/blind-index-hmac@v1` is server-blind: clients compute exact-match
tokens outside Qdrant, and the runtime instance only pins non-secret key lineage
metadata with `key_id`, `expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch`.
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
    docs_body_blind_v1:
      provider: metadata/blind-index-hmac@v1
      materials: {}
      # backend_ref must be omitted. The HMAC/blind-index key is client-held;
      # Qdrant only stores and indexes the resulting opaque exact-match token.
      options:
        key_id: tenant-a/client-rk-2026-04
        expected_rk_id: tenant-a/client-rk-2026-04
        min_rk_epoch: 3
        max_rk_epoch: 3
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
      - id: body_blind_eq
        selector:
          kind: metadata_keys
          keys: [body__blind_eq]
        instance: docs_body_blind_v1
        binding: metadata-exact-match-token/v1
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
`signature_public_keys`. Legacy single-key verifier options
`signature_key_id` and `signature_public_key_b64` are rejected; use the
registry form so key rotation and runtime parity checks cover the full verifier
policy.

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

Exact-match search over client-side ciphertext uses a separate client-generated
blind-index token field. Qdrant stores and indexes the opaque token, not the
plaintext, and filters must target that token field directly. Range, geo, and
full-text search over client ciphertext remain unsupported.

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
  with a different client key/HKDF domain and store it in a configured
  `metadata-exact-match-token/v1` field. Plain Qdrant payload indexes remain
  unsupported for encrypted fields themselves.

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

Metadata value encryption uses the `metadata_keys` selector with
`metadata-value/v1` and `metadata/aes-256-gcm@v1`. It encrypts selected JSON
string metadata fields through the same server-side AEAD envelope machinery as
payload text, while keeping metadata value rules separate from payload and
blind-index bindings. Plaintext indexes, filters, facets, order-by, group-by,
and formula references over encrypted metadata value paths fail closed. Exact
match over encrypted metadata still requires a separate client-generated token
field using `metadata-exact-match-token/v1` with
`metadata/blind-index-hmac@v1`. Collection config must set a non-empty `key_id`
and non-zero `encryption_epoch` for both metadata value and token fields so
restore, rotation, and runtime parity checks have explicit key-lineage
metadata.

```yaml
crypto:
  instances:
    docs_metadata_value_v1:
      provider: metadata/aes-256-gcm@v1
      materials:
        sym_key: tenant-a/metadata-v1
      options:
        key_id: tenant-a:docs
        material_fingerprint_id: tenant-a/metadata@v1
params:
  encryption:
    version: 1
    key_id: tenant-a:docs
    crypto_schema_version: 1
    encryption_epoch: 3
    migration_state: active
    rules:
      - id: tenant_metadata
        selector:
          metadata_keys: [tenant_id]
        instance: docs_metadata_value_v1
        binding: metadata-value/v1
```

```yaml
params:
  encryption:
    version: 1
    key_id: tenant-a:docs
    crypto_schema_version: 1
    encryption_epoch: 3
    migration_state: active
    rules:
      - id: docs_body
        selector:
          payload_paths: [body]
        instance: docs_payload_client_v1
        binding: client-payload-envelope/v1
      - id: docs_body_blind_eq
        selector:
          metadata_keys: [body__blind_eq]
        instance: docs_body_blind_v1
        binding: metadata-exact-match-token/v1
```

Clients should compute `body__blind_eq` outside Qdrant with a domain-separated
blind-index key such as `qdrant-sec/client-payload-blind-index/v1`, then query
that token field with ordinary exact-match payload filters.
Token payload values must be base64url-no-padding strings that decode to a
32-byte HMAC-SHA256 output. Qdrant does not hold the blind-index key, but it
does fail closed on missing, non-string, malformed, or wrong-length token
fields before writing them to storage. Key-path payload updates to blind-index
token fields are rejected; write them as full payload objects so the collection
guard can validate the token shape. Payload indexes on blind-index token fields
must target the exact token field and use the `keyword` schema. Filters on blind-index token fields are
also limited to exact-match string tokens, including `match.value`,
`match.any`, and `match.except`; range, geo, full-text, null/empty, or
wrong-length token filters fail closed. Blind-index token fields are not
orderable, groupable, facetable, or usable in score formulas; they are intended
only for exact-match equality filtering over opaque HMAC tokens.

```json
{
  "filter": {
    "must": [
      {
        "key": "body__blind_eq",
        "match": { "value": "base64url-no-pad-client-blind-index-token" }
      }
    ]
  }
}
```

Runtime settings provide key material and providers through the canonical
`crypto` section. The old runtime `ckks` section is no longer part of the
settings schema; `master_key_b64` / `resource_key_b64` direct-key material must
not be used. Define a
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

- `wrapping_key_32` is an MK/KEK loaded from env/file/`unix_socket`/`vault_kv2`/fd/inline material.
- `wrapped_symmetric_key_32` is a random collection or rule RK wrapped by that
  MK using AES-256-GCM.
- Payload text and CKKS vector envelope AEAD keys are still purpose-specific
  HKDF subkeys derived from the unwrapped RK.

Provider `options` are allowlisted per provider. `payload/aes-256-gcm@v1`
accepts only `key_id`, `material_fingerprint_id`, and `retired_materials`;
`payload/client-aead@v1` accepts only its client envelope policy and signature
options; `metadata/blind-index-hmac@v1` accepts only `key_id`,
`expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch`; `vector/openfhe-ckks@v1`
accepts only `key_id`, `material_fingerprint_id`, `profile`,
`crypto_context_b64`, and `public_key_b64`. Unknown options fail startup/runtime
validation instead of being silently ignored.

Provider `materials` roles are also allowlisted. Server-side payload AEAD and
OpenFHE CKKS vector-envelope providers accept only `materials.sym_key`;
client-side AEAD and blind-index token providers must not configure any server
material or backend. Unexpected material roles fail validation instead of being
silently ignored.

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
`env`, `file`, `unix_socket`, `vault_kv2`, `fd`, or `inline` from whichever
field happens to be present.
When a material uses `source: env`, the `env` name must be non-empty and contain
only ASCII alphanumeric characters or `_`; malformed environment references fail
startup validation instead of being deferred to material load time.
When a material uses `source: file`, the path must be absolute and point to a
regular non-symlink file. On Unix, qdrant-sec rejects group/world-accessible key
files and rejects group/world-writable parent directories. The file and each
parent directory must be owned by root or the qdrant process user so file-backed
MK/RK material is not accidentally exposed or swapped through broad filesystem
permissions.
When a material uses `source: unix_socket`, the same `path` field must point to
an absolute, non-symlink Unix domain socket. On Unix, qdrant-sec rejects sockets
that are group/world-accessible and applies the same parent-directory
owner/mode checks as file-backed material. At startup/material-load time Qdrant
connects to the socket, reads a base64url-no-pad 32-byte material, and closes
the connection. This keeps the raw MK/RK out of config and persistent key files,
but the local socket service becomes part of the key-management TCB and must
preserve cluster runtime parity.
When a material uses `source: vault_kv2`, `path` must be the full Vault KV v2
data endpoint URL, for example `/v1/<mount>/data/<secret>`. Metadata/list
endpoints and bare mount paths are rejected. `env` must name the environment
variable that contains the Vault token, and `vault_field` must name the string
field under `data.data` that contains the base64url-no-pad 32-byte material. The
Vault token value must be non-empty and a valid HTTP header value. The URL must
use HTTPS; loopback HTTP is accepted only for tests/dev. Query strings and
fragments are rejected so Vault tokens or field selectors are not accidentally
placed in config URLs. Username/password URL credentials are also rejected; use
the `env` token source instead. Vault material fetches do not follow HTTP
redirects; redirects must be resolved in the configured, validated URL.
Vault-backed material keeps the MK/RK out of config files, but the Vault token
source, Vault policy, and Vault availability become part of the key-management
TCB and must be identical across nodes that can write encrypted collections.
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
Operators can expose this primitive through the manage-only
`POST /crypto/resource-keys/rewrap` endpoint:

```json
{
  "old_wrapped_by": "tenant-a/mk-v1",
  "new_wrapped_by": "tenant-a/mk-v2"
}
```

The endpoint does not mutate in-memory settings or collection config. It returns
a config patch containing only the rewrapped `wrapped_symmetric_key_32` material
records that should be applied to the deployment config or external secret
backend. This keeps MK rotation scoped to O(number of wrapped RKs) and avoids
rewriting payload/vector data envelopes. The old and new MK material must both be
available in the current runtime during the rewrap, and operators should roll out
the resulting material patch atomically across nodes so runtime parity
fingerprints stay aligned.
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

Snapshot download and shard snapshot streaming APIs are storage-level exports.
They only support raw encrypted marker export. `encrypted_payload=raw` is accepted
as an explicit no-op, while `encrypted_payload=decrypted` and
`encrypted_payload=redacted` fail during query parsing. Decrypted or redacted data
export needs a separate audited data-export API rather than being folded into
snapshot archive streams.

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
      scope: collection:uuid-123e4567-e89b-12d3-a456-426614174000
      nonce: base64url-no-pad-96-bit-nonce
      wrapped_key_b64: base64url-no-pad-wrapped-rk
    tenant-a/payload-v0:
      kind: wrapped_symmetric_key_32
      wrapped_by: tenant-a/mk-v1
      wrap_algorithm: AES-256-GCM
      rk_epoch: 2
      state: retired
      scope: collection:uuid-123e4567-e89b-12d3-a456-426614174000
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
On Linux, Qdrant sets `no_new_privs`, a parent-death `SIGKILL`, `RLIMIT_CORE=0`,
and, for checked bridge binaries, `RLIMIT_FSIZE=0` immediately before spawning
the configured bridge process. This is not a complete sandbox, but it prevents
privilege gain through setuid binaries or file capabilities, reduces orphaned
plaintext-bearing bridge exposure, disables normal core dumps, and prevents the
checked bridge from writing regular files after bridge path, ownership, mode,
parent directory, and optional SHA-256 pin checks have passed. Treat these
settings as pre-exec process hardening, not as a post-exec confinement boundary:
kernel attributes such as dumpability can be reset by `exec`, and production
deployments that need a strict bridge sandbox should still run the bridge under
an external confinement layer such as seccomp, AppArmor, Landlock, or a
dedicated container profile.

Collection encryption rules and runtime instances must use the same explicit
provider instance and `key_id`; runtime validation rejects missing instances,
missing material, provider/selector mismatches, and key-id mismatches instead of
falling back to legacy defaults. For server-side payload/vector AEAD envelopes,
`key_id` uses the narrower AEAD key-id syntax `[A-Za-z0-9._:-]`; resource-key
ids, material fingerprint ids, client `rk_id`, and signature key ids may use the
bounded qdrant-sec crypto identifier syntax that also permits `/` and `@`.
The configured 32-byte RK is not used directly
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
The REST control plane is split into three admin-only steps:

```text
POST /collections/{collection_name}/crypto/migration/plan
POST /collections/{collection_name}/crypto/migration/run-payloads
POST /collections/{collection_name}/crypto/migration/rewrite-payloads
POST /collections/{collection_name}/crypto/migration/decrypt-payloads
```

Use `plan` to start `Disabled -> Encrypting`, `Active -> Rotating`, or
`Active -> Decrypting`. While a collection is in `Encrypting` or `Rotating`,
`rewrite-payloads` scans local shards, opens stale server-side payload
envelopes with the active plus retired runtime keyring, and reseals them under
the active RK/epoch. While a collection is in `Decrypting`, `decrypt-payloads`
opens server-side payload envelopes and writes plaintext payload values back.
Client-side `$qdrant_client_aead` envelopes are store-only and cannot be
decrypted by Qdrant, so decrypt migration rejects collections that still bind a
client-side payload provider.

Both rewrite endpoints return `CryptoMigrationCheckpoint` values. A verified
checkpoint represents shard coverage, not only bytes changed: rerunning a
migration over already-current payloads still returns `rewritten_points ==
total_points` so the checkpoint can close the migration safely. The separate
`changed_points` counter reports how many payload records actually changed on
that run, so operators can distinguish first-pass rewrites from idempotent
verification reruns. Submit those checkpoints back to `plan` for `Encrypting ->
Active`, `Rotating -> Active`, or `Decrypting -> Disabled` completion. If a
rewrite request fails after nonce/key or payload validation, do not mark the
plan complete; fix the runtime/material state and rerun the rewrite endpoint to
produce fresh verified checkpoints.
For server-side payload migrations, `run-payloads` combines the rewrite/decrypt
scan with the completion transition. The request must name the active RK id and,
when completing `Rotating -> Active`, the retired RK id:

```json
{
  "active_rk_id": "rk/docs/4",
  "retired_rk_id": "rk/docs/3",
  "dry_run": false
}
```

The endpoint first verifies the current collection state is `Encrypting`,
`Rotating`, or `Decrypting` and preflights the supplied active/retired RK ids
against the current collection config. Invalid completion requests fail before
any payload rewrite/decrypt scan starts. Valid requests then run the appropriate
payload rewrite/decrypt scan, build the completion `CryptoMigrationPlan` from
the returned verified checkpoints, validate it again against the current
collection config, and submit the admin completion operation. If `dry_run` is
`true`, the endpoint still validates runtime material and returns verified
checkpoints plus the completion plan it would submit, but it does not write
payload changes and does not apply the completion transition. It is still a
foreground admin operation, not a cluster-wide background scheduler; interrupted
or failed runs should be rerun to produce fresh checkpoints.
After a verified `Decrypting -> Disabled` completion, the stored encryption
section remains as audit/migration metadata, but it is not treated as effective
encryption for write/read guards. Re-enabling encryption must start a new admin
migration transition rather than relying on ordinary params updates.
Read paths return stored encrypted markers as raw payload values by default.
REST and gRPC clients can request `with_payload: {"encrypted_payload":"redacted"}` to
receive payloads with server-side, client-side, and CKKS vector sidecar marker
values replaced by redaction sentinels. The same redaction policy is applied to
batch search/query/recommend/discover results, grouped result hits, and grouped
lookup payloads.
`encrypted_payload: "decrypted"` is supported for REST/gRPC retrieve, scroll,
legacy search, batch search, universal query, batch query, recommend, batch
recommend, discover, batch discover, and grouped result hits over server-side
`$qdrant_sec` payload fields when the Qdrant node has matching runtime crypto
settings and the caller has global manage access or collection-scoped
`payload_decrypt: true` access. That mode requests raw
encrypted markers from the collection layer,
decrypts only server-side payload text and metadata value AEAD fields in the API
runtime layer, leaves client-side `$qdrant_client_aead` envelopes opaque, and
fails closed if runtime settings are unavailable or invalid. Group lookup
payloads are not decrypted because lookups may target another collection.
JWT RBAC claims must grant the decrypt capability explicitly:

```json
{
  "access": [
    {
      "collection": "docs",
      "access": "r",
      "payload_decrypt": true
    }
  ]
}
```

Decrypted export remains future work; slow request logs and request hashes use
redacted request values, and collection telemetry has sentinel coverage so
decrypted plaintext is not intentionally emitted there.
Client-side-only envelope collections must use `raw` or `redacted`; requesting
`decrypted` fails closed because Qdrant has no client data key.
The REST single-point `GET /collections/{collection}/points/{id}` endpoint has
no request body, so it accepts the same read policy through the
`encrypted_payload=raw|redacted|decrypted` query parameter.
Generic server-side crypto instances require
`options.material_fingerprint_id` to be an opaque deployment-local key version
id. Payload and vector runtime validation rejects missing values so envelopes
do not fall back to key-derived fingerprints. Low-level test helpers may still
construct deterministic fingerprints directly from key material, but production
runtime configuration must provide explicit opaque fingerprint ids.
If the old `ckks` runtime section is configured, settings parsing fails with an
unknown-field error. Migrate to the canonical `crypto` control plane before
enabling encrypted writes.

## Storage path threat model

The intended security boundary is encrypt-before-storage for selected payload
string fields and CKKS vector ciphertext envelopes. This branch does not yet
claim complete end-to-end leakage coverage for every Qdrant storage and cluster
path; the table below is the current contract until integration tests cover each
row.

| Path | Expected protected content | Current status | Required gate before production use |
| --- | --- | --- | --- |
| REST/gRPC ingress | Request payload and plaintext embeddings may exist in process memory until encryption completes. | Trusted Qdrant process boundary. Slow-request log values and request hashes redact payloads, vectors, universal query vectors, and payload filter literals before serialization/hash calculation. | Keep request/body logging disabled or redacted for encrypted fields and embeddings. |
| WAL | Selected payload strings and CKKS vector metadata should be stored only as envelopes after encryption. | Payload sentinel leakage scans cover public server-side/client-side payload ingress and collection directory files, including WAL files. CKKS vector sidecar coverage verifies plaintext vectors are removed before storage and scans collection files for successful encrypted-vector f32/f64 byte patterns. `wal_inspector` redacts collection update operations by default and requires `--raw` to print raw encrypted markers. | Broaden cluster storage scans. |
| Segment and optimizer temp files | Selected payload strings should appear as marker/envelope JSON; CKKS vector plaintext should not be stored by the CKKS envelope path. | Payload sentinel leakage scans cover persisted collection files after graceful stop, and public ingress leakage coverage also scans an explicit optimizer temp directory. `segment_inspector` redacts server payload, client payload, metadata ciphertext, and CKKS vector sidecar markers by default and requires `--raw-payload` for raw marker output. | Broaden optimizer coverage as new temp-file paths are introduced. |
| Payload indexes | AEAD-encrypted fields are not searchable as plaintext. Exact-match search must use separate client-generated blind-index token fields. | Index creation over encrypted payload paths and parent/child overlaps is rejected. `metadata/blind-index-hmac@v1` token fields may be indexed only on the exact token field with `keyword` schema and filtered as opaque HMAC-SHA256 tokens, but parent/child token indexes, non-keyword token indexes, order-by, grouping, facets, and formulas over token fields fail closed. | Keep rejecting plaintext indexes over encrypted content; broaden blind-index SDK and query-mode coverage as new search flows are added. |
| HNSW graph and quantization | CKKS ciphertext vectors are searched through sidecar ciphertext scoring, not through plaintext dense vector storage. | REST/gRPC nearest-neighbor search can score stored CKKS ciphertext envelopes through the OpenFHE bridge using the collection distance metric. `hnsw_ef` uses the segment-level CKKS ciphertext vector index primitive to build/search an encrypted-candidate graph; exact and non-HNSW requests use brute force. The serving graph cache is persisted under the collection directory by stable crypto identity plus ciphertext fingerprint for restart reuse. Segment optimization counts encrypted sidecar bytes, assigns immutable `CkksCiphertextHnsw` segment index artifacts, and persists their private graph files instead of plaintext HNSW, mmap conversion, or quantization. Persisted graphs must be private, owned by root or the Qdrant process user, stored under a trusted parent directory chain, reciprocal, and connected. Raw-dense recommend and raw-dense discover use the same encrypted-query sidecar scoring path but remain brute-force. Quantization remains unsupported for encrypted vectors, and collection validation rejects per-vector or collection-level quantization configs for encrypted vector names. | Broaden distributed rebuild/recovery coverage before treating it as a production-grade segment-native ciphertext index. |
| Snapshots | Snapshot archives should contain encrypted payload/vector envelopes and enough metadata to preflight required keys/context and stable collection identity. | Payload sentinel leakage scan now creates and scans a collection snapshot archive. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings for missing instance/material/backend, wrong wrapped-RK key, provider key-id mismatch, missing encrypted collection UUID, UUID mismatch, and invalid CKKS public material. Valid-but-different CKKS public-material drift is covered by peer runtime parity and sidecar `context_digest` open/score checks. | Broaden restore coverage across cluster paths and add full archive-level sidecar scan coverage if restore starts validating stored sidecars before load. |
| Shard transfer and replication | Sender and receiver must have matching crypto runtime material and CKKS context. | App telemetry, peer metadata, and distributed telemetry expose a non-secret crypto runtime capability fingerprint. Encrypted collection data-movement operations validate involved peer metadata and fail closed on missing or mismatched fingerprints. Automatic dead-replica recovery skips source peers without matching parity metadata. `/readyz` does not mark the node ready for encrypted collections while peer metadata fingerprints are missing or mismatched. | Broaden distributed integration coverage and cluster-wide parity tests. |
| Telemetry, logs, and audit | No plaintext payload bodies, embeddings, ciphertext blobs, signatures, wrapping keys, or runtime key material should be emitted. | Bridge request bodies and stderr are not included in returned errors. Collection telemetry and slow-request log-value/request-hash smoke tests cover payload/vector/filter/query sentinels, crypto envelope fields, plural batch fields, and camel/kebab-case secret field spellings. App telemetry exposes only a non-secret crypto runtime capability fingerprint and regression tests assert inline/wrapped key material and verifier key options are not serialized. | Broaden audit/log capture coverage around any new request logging surfaces. |

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
that it matches the requested allowlisted profile. Responses may also include
`security_level_bits` and `noise_budget_bits`; when present, Qdrant rejects
reported security below 128 bits and rejects non-finite or negative noise budget
metadata.

Nearest-neighbor search over an encrypted vector name is implemented for
REST/gRPC dense query vectors and root direct point-id nearest `query` or
`query/groups` requests when runtime `crypto` settings are available on the
serving node. This includes legacy `search` requests and root direct
nearest-neighbor `query` requests. For raw dense query vectors, Qdrant scrolls
the encrypted sidecar payloads,
validates each CKKS envelope against the active OpenFHE public material/context
digest, sends `encrypt_query` to the bridge, and then sends
`score_encrypted_query_batch` requests over the encrypted query ciphertext plus
stored sidecar ciphertexts. For point-id nearest `query`, Qdrant first retrieves
the referenced point's stored CKKS sidecar envelope and uses its stored
ciphertext as the encrypted query in `score_encrypted_query_batch`; plaintext
vectors are still not stored or read. The same stored-query sidecar scoring is
used before plaintext payload grouping for root direct point-id `query/groups`.
REST universal nearest `query` and `query/groups` may supply a client-side
encrypted query envelope instead of a raw dense vector:

```json
{
  "$qdrant_sec_ckks_query": {
    "version": 1,
    "scheme": "openfhe-ckks",
    "security_profile": "ckks-128-n16384-d4-scale50",
    "context_digest": "...",
    "slots": 1536,
    "ciphertext": "..."
  }
}
```

The `context_digest` must match the active OpenFHE public material and CKKS
parameter profile for the encrypted vector rule, `slots` must match each stored
sidecar envelope being scored, and `ciphertext` is base64url without padding.
Qdrant does not decrypt or validate the CKKS ciphertext itself; it treats the
validated bytes as the encrypted query input to the OpenFHE bridge scoring API.
Result ordering and
`score_threshold` follow the configured Qdrant distance metric:
`dot`/`cosine` are larger-is-better, while `euclid`/`manhattan` are
smaller-is-better. If `hnsw_ef` is set and `exact=false`, nearest-neighbor
search builds and searches a ciphertext sidecar candidate graph with
stored-ciphertext-to-stored-ciphertext bridge scoring for graph links and
encrypted-query bridge scoring for traversal candidates. Stored point-id
nearest `query`/`query/groups` requests also use the sidecar graph when
`hnsw_ef` is provided, scoring traversal candidates against the referenced
point's stored ciphertext. Segment optimization counts CKKS vector sidecar
ciphertext bytes for encrypted vector thresholds and builds an immutable
`CkksCiphertextHnsw` vector index artifact instead of plaintext HNSW, plain
mmap conversion, or quantization. For unfiltered nearest-neighbor requests,
serving-time CKKS search first loads those segment-native artifacts for
unfiltered requests without an explicit read-consistency override. Indexed
segments are searched through their native CKKS graph, while sidecars that still
live in non-indexed segments are brute-force scored and merged. If a target shard
is not locally inspectable, a filter narrows the candidate set, or the request
requires explicit read consistency, Qdrant falls back to the collection-level
sidecar graph cache/brute-force path. Because segment optimization does not own
the OpenFHE scoring runtime, optimizer-built segment artifacts use a
deterministic connected candidate graph; serving-time CKKS search still scores
visited ciphertext candidates through the runtime bridge.

The collection-level sidecar graph cache is keyed by stable collection crypto
identity, vector name, score direction, graph parameters, and a fingerprint of
the stored ciphertext sidecars, so rename/recreate boundaries and
payload/vector changes build a new graph instead of reusing stale links. The
cache is an acceleration for the current serving process and is also persisted
under the collection directory for restart reuse. Persisted graph cache files
are treated as untrusted hints:
the cache directory must be a private non-symlink directory owned by root or the
Qdrant process user, every non-sticky parent directory in the path must be
owned by root or the Qdrant process user and not group/world-writable, cache
files and stale temp files must be private regular files owned by root or the
Qdrant process user, oversized files are rejected, and metadata/fingerprint
mismatches or disconnected/non-reciprocal graphs are ignored before Qdrant
rebuilds the graph. Trusted sticky ancestors such as `/tmp` are allowed only
above the private cache directory so test and temp deployments can still use
standard temporary roots. Qdrant prunes old persisted graph cache files by count
and total size after writing a new graph. It is still not the plaintext-vector
`HNSWIndex` file format and should be treated as an experimental ciphertext
candidate index until distributed rebuild and recovery coverage is broader.
`search/groups`, `recommend/groups`, and root direct `query/groups` are
supported when the group field is plaintext payload and runtime OpenFHE settings
are available. `with_lookup` is supported for lookup payloads and plaintext
vectors; lookup payloads use their own `with_payload` encrypted read policy,
and lookup requests that ask for encrypted vectors fail closed. Grouped paths
still use brute-force sidecar scoring.
REST and gRPC search matrix requests over an encrypted vector name sample stored
sidecar envelopes and use stored-ciphertext-to-stored-ciphertext bridge scoring
for pairwise nearests inside the sample; encrypted matrix sampling is
deterministic over the filtered sidecar scan rather than the plaintext random
vector sampler. Universal query prefetches over encrypted vector names may feed
root RRF/DBSF fusion, including mixed plaintext and encrypted prefetch sources.
Non-fusion prefetches are evaluated first and converted to a candidate-id filter
before the encrypted or plaintext root query is rescored. Quantization,
ACORN/indexed-only params remain unsupported. Root direct
`NearestWithMmr` and `NearestWithMmr` query groups over an encrypted vector name
use CKKS sidecar scoring for both query-to-candidate relevance and
candidate-to-candidate diversity; they are limited to large-better metrics
(`dot`/`cosine`). Legacy and
universal recommend queries are supported for `average_vector`, `best_score`,
and `sum_scores` with raw dense examples and point-id examples from the same
encrypted vector sidecar. Single-positive point-id `average_vector` loads that
point's stored sidecar ciphertext as the query, while multi-example point-id
`average_vector` scores every raw dense or stored point-id example independently
and combines the scores as positive and negative averages. Raw-dense
`average_vector` is reduced to one plaintext query vector which is encrypted
through the bridge before scoring; `best_score` and `sum_scores` encrypt each
raw dense example or load each point-id sidecar and score it against the stored
sidecar ciphertexts before combining the scores with the same objective as
Qdrant's plaintext recommend path. Sparse examples fail closed because Qdrant
does not retain sparse encrypted vector sidecars. `best_score` and `sum_scores`
are accepted only for large-better metrics (`dot`/`cosine`) in this sidecar
executor; small-better metrics (`euclid`/`manhattan`) fail closed until the
bridge exposes raw similarity scores for those metrics. Legacy and universal
`discover` support raw dense and point-id target/context examples by loading
stored sidecar ciphertexts for point-id examples. Discover sidecar scoring uses
the same rank plus scaled-sigmoid target objective as Qdrant's plaintext
discover path. Universal `context` queries are supported for raw dense and
point-id context pair examples and use the same pair-rank objective as Qdrant's
plaintext context path.
Discover and context sidecar scoring are accepted only for large-better metrics
(`dot`/`cosine`). Direct collection-internal calls without runtime settings
still fail closed for encrypted vector names. The
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
Single vector encryption requests use `operation: encrypt`; batch vector
encryption requests use `operation: encrypt_batch`; query-vector encryption
requests use `operation: encrypt_query`. Encrypted-query scoring requests use
`operation: score_encrypted_query` for single-point scoring or
`operation: score_encrypted_query_batch` for scroll-batch scoring. Legacy
`score_plaintext_query` operations are kept as a backend compatibility API but
the Qdrant search path uses encrypted-query scoring. All bridge
requests include a deterministic `context_id` and collection/vector routing
metadata. The first successful request for a `context_id` on a bridge worker
also includes the profile parameters plus OpenFHE public material. After that,
Qdrant treats the context as registered on that worker and omits `parameters`,
`crypto_context`, and `public_key` from subsequent requests using the same
`context_id`. If the worker exits or is discarded, the replacement worker must
receive the full material again before it can process cached-context requests.
The `context_id` is the base64url SHA-256 digest Qdrant also stores in CKKS
vector envelopes, so the bridge can cache OpenFHE contexts/public keys by id
while Qdrant avoids sending large public material on every vector operation.
Scoring requests additionally include the collection `distance` metric (`dot`,
`cosine`, `euclid`, or `manhattan`), an encrypted query ciphertext, and stored
CKKS ciphertext bytes. Batch responses must preserve request item order and
return exactly one ciphertext or finite score per item. All encrypt, batch
encrypt, and scoring responses must include
`security_profile`, and it must equal the configured allowlisted CKKS profile.
Responses may include `security_level_bits` and `noise_budget_bits`; Qdrant
validates those optional fields when supplied and fails closed on sub-128-bit
security levels, negative noise budgets, or non-finite noise budgets.
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
on Unix. On Linux, checked bridge workers are spawned through a
`/proc/self/fd/<fd>` path backed by the same no-follow validated bridge file
descriptor held open through `spawn`, which narrows the path-swap window between
validation, hashing, and execution.
Treat any bridge path change as privileged code execution under the Qdrant
service account. On Linux, the checked bridge spawn path also sets
`no_new_privs`, parent-death `SIGKILL`, `RLIMIT_CORE=0`, and `RLIMIT_FSIZE=0`
so the plaintext-bearing bridge cannot gain extra privileges through
setuid/file-capability execution, is killed if Qdrant exits, does not produce
normal core dumps, and cannot write regular files. Checked bridge workers start
from `/` rather than inheriting Qdrant's working directory, with an empty
inherited environment plus a fixed
`/usr/sbin:/usr/bin:/sbin:/bin` `PATH` for `/usr/bin/env` shebang compatibility,
so env-backed Qdrant settings, crypto material, `LD_PRELOAD`, `PYTHONPATH`, and
other service environment values are not handed to the bridge process by
default. Test-only unchecked bridge workers still remove `QDRANT`/`QDRANT_*`
and explicitly configured sensitive env names.

Request fields:

```json
{
  "version": 1,
  "operation": "encrypt",
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "point_id": "point-1",
  "vector_name": "embedding",
  "context_id": "base64url-no-pad-context-digest",
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

After the worker has successfully processed one request for the same
`context_id`, later requests omit the public material fields:

```json
{
  "version": 1,
  "operation": "score_encrypted_query_batch",
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "vector_name": "embedding",
  "distance": "dot",
  "context_id": "base64url-no-pad-context-digest",
  "encrypted_query": "base64url-no-pad-query-ciphertext",
  "items": [
    { "point_id": "point-1", "ciphertext": "base64url-no-pad-ciphertext-1" }
  ]
}
```

Response fields:

```json
{
  "version": 1,
  "security_profile": "ckks-128-n16384-d4-scale50",
  "ciphertext": "base64url-no-pad-openfhe-ciphertext"
}
```

The Rust `CkksVectorBackend` trait also exposes `encrypt_batch` so backends can
amortize vector encryption overhead. `CommandOpenFheBackend` sends one
newline-delimited batch request with shared context and per-point items. The
first request for a worker/context carries the public material shown below;
subsequent requests for the same context omit those public material fields:

```json
{
  "version": 1,
  "operation": "encrypt_batch",
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "vector_name": "embedding",
  "context_id": "base64url-no-pad-context-digest",
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
  "security_profile": "ckks-128-n16384-d4-scale50",
  "ciphertexts": [
    "base64url-no-pad-openfhe-ciphertext-1",
    "base64url-no-pad-openfhe-ciphertext-2"
  ]
}
```

`CkksVectorEncryptor` still validates each input vector before the backend call
and seals every returned ciphertext with per-point AAD.

Encrypted-query batch scoring uses the same shared context and query ciphertext,
while each item carries the stored ciphertext for one point:

```json
{
  "version": 1,
  "operation": "score_encrypted_query_batch",
  "scheme": "openfhe-ckks",
  "collection": "docs",
  "vector_name": "embedding",
  "distance": "dot",
  "context_id": "base64url-no-pad-context-digest",
  "parameters": {
    "poly_modulus_degree": 16384,
    "multiplicative_depth": 4,
    "scaling_mod_size": 50,
    "first_mod_size": 60,
    "batch_size": 8192
  },
  "crypto_context": "base64url-no-pad",
  "public_key": "base64url-no-pad",
  "encrypted_query": "base64url-no-pad-query-ciphertext",
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
