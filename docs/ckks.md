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
on a raw dense or stored point-id nearest-neighbor request, Qdrant uses an
existing segment-native or persisted experimental ciphertext sidecar candidate
graph and searches it with encrypted query scores; otherwise it uses the exact
brute-force sidecar scan. The same
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
| `retrieve`, `scroll`, `search`, and `query` result payloads | Stored `$qdrant_sec` markers are returned raw by default. REST/gRPC `retrieve`, `scroll`, legacy `search`, batch search, universal `query`, batch query, `recommend`, batch recommend, `discover`, batch discover, and grouped result hits may use `{"encrypted_payload":"decrypted"}` to decrypt server-side payload text and metadata value AEAD fields only when runtime crypto settings are available and the caller has global manage access or collection `payload_decrypt` capability; the same mode fails closed without runtime settings or sufficient privilege. REST payload selectors may use `{"encrypted_payload":"redacted"}` to return payloads while replacing encrypted marker values with redaction sentinels. Group lookup payloads remain raw/redacted only because they may come from a different collection. | Stored `$qdrant_client_aead` markers are returned raw by default for SDK/client decryption, or redacted with the same `encrypted_payload` selector. Qdrant never decrypts client-side envelopes. | Stored vector sidecar payload envelopes are returned raw by default when payloads are requested, or redacted with the same `encrypted_payload` selector. Read/search/query/recommend/discover paths, including grouped variants, reject `with_vector=true` or selectors that request encrypted vector names; clients must request the payload sidecar instead. REST/gRPC nearest-neighbor dense-vector `search`, `search/groups`, REST/gRPC legacy client-encrypted nearest `search`, REST/gRPC legacy client-encrypted nearest `search/groups`, root direct `query`, root direct point-id nearest `query`, root direct REST/gRPC client-encrypted nearest `query`, root direct `query/groups`, root direct point-id nearest `query/groups`, root direct REST/gRPC client-encrypted nearest `query/groups`, root direct `NearestWithMmr` and `NearestWithMmr` query groups, `search/matrix`, raw-dense/point-id `recommend` (`average_vector`, `best_score`, `sum_scores`), legacy `discover` with raw-dense or point-id target/context examples, and universal `discover`/`discover groups`/`context`/`context groups` queries with raw-dense or point-id target/context examples are supported with runtime OpenFHE settings. Batch search/query/recommend/discover may mix encrypted vector names and plaintext vector names; each request is routed independently and output order is preserved. Nearest-neighbor requests may set `hnsw_ef` to use the ciphertext sidecar candidate graph for raw dense query vectors, client-encrypted query ciphertexts, and stored point-id query vectors; exact requests and non-HNSW requests use brute-force sidecar scoring. Matrix requests sample stored sidecars and score pairwise stored ciphertexts. Universal query prefetches over encrypted vector names are supported for RRF/DBSF fusion and as non-fusion candidate filters for encrypted or plaintext root queries. MMR uses query-to-candidate CKKS scores for relevance and candidate-to-candidate CKKS scores for diversity on large-better metrics. Client-encrypted query envelopes fail closed when `cluster.enabled=true` until a consensus-backed query nonce replay ledger exists. Quantization/ACORN/indexed-only search params remain unsupported. |
| Snapshots | Snapshot archives are expected to contain envelopes only; payload sentinel snapshot leakage is covered by integration tests. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings, including missing material, wrong wrapped-RK key, and provider key-id mismatch cases. | Same stored-value behavior as server-side payloads. Qdrant cannot validate client AEAD tags without client keys. | Restore requires matching OpenFHE context/runtime material. Missing runtime instance/material/backend and invalid OpenFHE public-material preflight are covered; valid-but-different context drift is enforced by runtime capability parity and envelope `context_digest` checks when sidecars are opened/scored. |
| Shard transfer / replication | Encrypted collection data-movement operations require matching non-secret crypto runtime capability fingerprints in peer metadata. Operations fail closed if any involved peer has missing or mismatched metadata. Automatic dead-replica recovery only proposes encrypted shard transfers from source peers with matching parity metadata. | Same policy; client-envelope verifier policy must match across nodes before encrypted transfers are allowed. | Same policy; matching OpenFHE context and metadata AEAD material must be enforced before encrypted transfers are allowed. |
| Metadata encryption | `metadata/aes-256-gcm@v1` supports selected JSON string metadata values with `metadata-value/v1`; these values use the same server-side AEAD envelope, fail closed for plaintext indexing/filtering, and participate in `encrypted_payload:"decrypted"` reads under the same `payload_decrypt` access policy. `metadata_keys` selectors also support client-generated exact-match blind-index token fields with `metadata-exact-match-token/v1`. | Client-side metadata value encryption should use `payload/client-aead@v1` on the metadata field plus a separate blind-index token field for exact match. Qdrant stores opaque blind-index tokens and never computes them. | CKKS vector metadata sealing is separate from payload metadata value encryption. |

`vector/private-hnsw-oram@v1` is stricter than the generic encrypted
data-movement policy above: shard transfer starts, resharding progress,
shard-key layout changes, replica removal, shard snapshot export/recovery, and
automatic dead-replica shard transfer recovery fail closed until encrypted ORAM
bucket movement and epoch/root ownership are consensus-backed. Consensus snapshot
apply also rejects private ORAM transfer state, non-empty resharding state, and
shard-info layout, membership, or shard layout config changes.

Private ORAM search and result-fetch providers have their own client-led
contract:

| API/path | `vector/private-hnsw-oram@v1` | `payload/private-result-oram@v1` |
| --- | --- | --- |
| Runtime profile | Strict zero-trust compatible. Server materials and backends are forbidden, RK epoch must be pinned, fixed-budget search is required, and signing verifiers are mandatory. | Strict zero-trust compatible. Server materials and backends are forbidden, RK epoch must be pinned, Path ORAM policy is allowlisted, and signing verifiers are mandatory. |
| Collection binding | One vector name per `private-hnsw-oram/v1` rule. It cannot overlap `vector/openfhe-ckks@v1` or `vector/client-ckks@v1` on the same vector name. | One `private-result-oram/v1` payload binding in v1. It is required when a private HNSW manifest uses `result_privacy: private_payload_oram_required`. |
| Normal Qdrant reads/writes | Dense vector upsert/update, point/vector delete, collection peer `SyncPoints`, `with_vector` reads, ordinary search/query/recommend/discover, grouped paths, search matrix, and `lookup_from`/point-id reference-vector resolution fail closed for the private vector; clients must use the private HNSW session APIs. | Point create/replace/delete, full payload replacement/clear, protected-path payload writes, indexes, filters, ordering, grouping, facets, formulas, and raw payload reads fail closed for the private result path; public non-overlapping payload merges remain ordinary. |
| Dedicated APIs | Manifest upload/read, encrypted bucket upload, session open/close, signed `read_paths`, and signed writeback commit are open. Qdrant validates shape, signatures, Merkle proofs, and epoch/root CAS only. | Manifest upload/read, encrypted bucket upload, session open/close, signed `read_buckets`, and signed writeback commit are open. Qdrant validates shape, signatures, Merkle proofs, and epoch/root CAS only. |
| Snapshot/restore | Collection, storage, REST, and CLI/startup recovery preflight validate manifest signatures, current epoch/root, every bucket, Merkle metadata, and paired result ORAM policy before accepting a restored store. | Collection, storage, REST, and CLI/startup recovery preflight validate manifest signatures, current epoch/root, every bucket, Merkle metadata, and configured binding/runtime policy before accepting a restored store. |
| Cluster mode | Manifest upload, bucket upload, session open, `read_paths`, and commit remain fail closed in distributed mode. Raft now persists an internal private-ORAM epoch/root CAS record, and the internal dispatcher bridge waits for local Raft apply with exact-replay idempotence, conflicting-stale rejection, and snapshot-restore coverage. The API guard remains until encrypted bucket ownership and movement are coupled to that record; layout movement operations and consensus snapshot state-apply changes are blocked before shard transfer, resharding, or shard-info mutation proceeds. | Manifest upload, bucket upload, session open, `read_buckets`, and commit remain fail closed in distributed mode. The same internal Raft epoch/root CAS record and awaited dispatcher bridge cover result ORAM identity with exact-replay idempotence, but result bucket replication and API commit integration are still required before the guard can open; result ORAM bucket movement and consensus snapshot state-apply changes follow the same cluster guard policy. |

The internal Dispatcher writeback coordinator enforces durable local prepare,
awaited Raft epoch/root CAS, then idempotent local finalize. If Raft rejects the
CAS, the coordinator invokes a signed-journal abort that removes the journal
only when the local epoch, Merkle tree, and every target bucket still match the
old view; any partial local mutation preserves the journal and fails closed. If
finalize fails after Raft apply, retrying the same operation reuses exact-CAS
idempotence before running finalize again. This is an internal recovery boundary
only; distributed private ORAM routes remain closed until encrypted bucket
replication and ownership are coupled to the same operation.

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
`payload/private-result-oram@v1`,
`metadata/aes-256-gcm@v1`, `metadata/blind-index-hmac@v1`,
`vector/openfhe-ckks@v1`, `vector/client-ckks@v1`, and
`vector/private-hnsw-oram@v1`.
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
`vector/client-ckks@v1` is server-blind opaque vector storage: it forbids
server materials/backends and pins client CKKS public material, RK lineage,
`search_mode: opaque_storage_only`, and signing public keys.
`vector/private-hnsw-oram@v1` is server-blind searchable ANN storage: it also
forbids server materials/backends and pins RK lineage, private HNSW/Path
ORAM/fixed-budget policy, integrity requirements, and signing public keys.
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
The language-neutral fixture
`docs/qdrant-sec-resource-key-rotation-test-vector.json` fixes the
length-prefixed RK-wrap AAD, old/new local MKs, deterministic test nonces, and
wrapped RK ciphertexts so SDKs can verify MK rewrap compatibility without
learning any production key material.
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
even though Qdrant cannot unwrap the client key. If the payload also writes
blind-index token fields, the client envelope should include a `blind_indexes`
array of `{ "field_path": "...", "token": "..." }` objects. The Ed25519
signature covers the client envelope header, AAD, sorted blind-index token
manifest, nonce, ciphertext, signature algorithm, and signature key id.
`docs/qdrant-sec-client-payload-signature-test-vector.json` freezes the
canonical length-prefixed signing bytes so external SDKs can verify
interoperability against the server implementation.

Storage does not trust marker shape alone. Public write plans must validate the
client envelope and produce a runtime-verified proof keyed by collection id,
point id, field path, key id, `rk_id`, `rk_epoch`, nonce, ciphertext digest, and
signature digest. The collection write guard recomputes that identity from the
stored marker and accepts the write only when it matches the runtime proof.
Peer replay uses a stricter boundary: target peers do not accept client payload
envelopes on the basis of origin-peer verification alone. Until peer operations
carry verifier policy plus a consensus-backed client nonce ledger, any
`$qdrant_client_aead` marker in a peer replay/update path fails closed instead
of skipping Ed25519 verification on the receiving peer.

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
Blind-index tokens deliberately leak equality patterns: the same normalized
plaintext under the same tenant, stable collection crypto id, field path, and
RK epoch produces the same token. Low-cardinality values such as status flags,
booleans, country codes, or small enums can therefore leak frequency
information even though Qdrant never sees the blind-index key. SDKs should
domain-separate the token key by tenant, collection crypto id, field path,
provider id, `rk_id`, and `rk_epoch`, and operators should avoid blind-indexing
fields where equality or frequency leakage is unacceptable.
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
`docs/qdrant-sec-client-blind-index-test-vector.json` freezes one
length-prefixed token-message and HMAC output so external SDKs can verify their
normalization and token generation.

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

- `wrapping_key_32` is an MK/KEK loaded from env/file/`unix_socket`/`vault_kv2`/fd/inline material, or an external AWS KMS / Vault Transit key reference.
- `wrapped_symmetric_key_32` is a random collection or rule RK wrapped by that
  MK using AES-256-GCM, AWS KMS, or Vault Transit.
- Payload text and CKKS vector envelope AEAD keys are still purpose-specific
  HKDF subkeys derived from the unwrapped RK.

Provider `options` are allowlisted per provider. `payload/aes-256-gcm@v1`
accepts only `key_id`, `material_fingerprint_id`, and `retired_materials`;
`payload/client-aead@v1` accepts only its client envelope policy and signature
options; `metadata/aes-256-gcm@v1` accepts the same server-side AEAD options as
payload AEAD; `metadata/blind-index-hmac@v1` accepts only `key_id`,
`expected_rk_id`, `min_rk_epoch`, and `max_rk_epoch`; `vector/openfhe-ckks@v1`
accepts only `key_id`, `material_fingerprint_id`, `profile`,
`crypto_context_b64`, `public_key_b64`, `allow_plaintext_queries`,
`plaintext_query_tcb_ack`, `score_plaintext_output_tcb_ack`, and
`signature_public_keys`; `vector/client-ckks@v1` accepts only `key_id`,
`expected_rk_id`, `min_rk_epoch`, `max_rk_epoch`, `search_mode`, `profile`,
`crypto_context_b64`, `public_key_b64`, and `signature_public_keys`;
`vector/private-hnsw-oram@v1` accepts only `key_id`, `expected_rk_id`,
`min_rk_epoch`, `max_rk_epoch`, `search_execution`, `search_mode`,
`result_privacy`, `distance`, `dim`, `hnsw`, `oram`, `fixed_budget`,
`integrity`, and `signature_public_keys`; `payload/private-result-oram@v1`
accepts only `key_id`, `expected_rk_id`, `min_rk_epoch`, `max_rk_epoch`,
`oram`, `integrity`, and `signature_public_keys`; its
`private-result-oram/v1` collection binding validation requires a matching
payload rule backed by that provider, no server materials/backend, pinned RK
epoch, Path ORAM shape policy, integrity policy, and a non-empty signing
verifier registry.
Manifest/bucket upload, session open/close, signed `read_buckets`, and signed
commit REST/gRPC APIs are open, and bucket reads/commits are session-bound with
single-writer epoch/root CAS. Unknown options
fail startup/runtime validation instead of being silently ignored.
Collection-facing private HNSW
ORAM runtime validation errors use fixed descriptions and do not append the
inner setup error detail, so unsupported option names, option values, and reason
strings are not reflected through collection API failures.

Provider `materials` roles are also allowlisted. Server-side payload AEAD and
OpenFHE CKKS vector-envelope providers accept only `materials.sym_key`;
client-side AEAD and blind-index token providers must not configure any server
material or backend. Unexpected material roles fail validation instead of being
silently ignored.

Set `crypto.zero_trust_profile: strict` when the deployment goal is complete
zero trust rather than server-managed encryption. Strict mode is a fail-closed
profile: it rejects server-held crypto materials, OpenFHE bridge backends,
server-side payload/metadata AEAD providers, and the trusted-bridge
`vector/openfhe-ckks@v1` provider. The accepted providers in strict mode are
server-blind `payload/client-aead@v1`, `payload/private-result-oram@v1`,
`metadata/blind-index-hmac@v1`, `vector/client-ckks@v1`, and
`vector/private-hnsw-oram@v1`. Use the non-strict trusted-bridge profile only when
operators explicitly accept that Qdrant/bridge may observe embeddings, scores,
access patterns, and ranking order.

`vector/client-ckks@v1` is a server-blind vector ingest provider. It must not
configure server materials or an OpenFHE backend. Clients submit a signed
`$qdrant_sec_client_ckks_vector` sidecar envelope under
`$qdrant_sec_vectors.<vector_name>`; Qdrant validates schema, stable collection
identity, point id, vector name, `key_id`, `rk_id`, pinned `rk_epoch`,
`context_digest`, ciphertext hash, and Ed25519 signature before storing the
opaque CKKS ciphertext. Plaintext dense vector writes to that vector name are
rejected. The provider must set `search_mode: opaque_storage_only`, which is an
explicit API contract that Qdrant stores the signed opaque vector envelope but
does not score, rank, or index it server-side. Search over these opaque client
vector envelopes fails closed; do not confuse this ingest contract with the
trusted-bridge `vector/openfhe-ckks@v1` search provider.

`vector/openfhe-ckks@v1` remains a trusted-bridge model: Qdrant/bridge may see
plaintext embeddings at ingest and plaintext scores at search. Do not use the
server-side OpenFHE provider as a zero-trust vector insert contract.

`vector/private-hnsw-oram@v1` is the strict zero-trust searchable ANN provider
contract. It uses binding `private-hnsw-oram/v1`, forbids server materials and
OpenFHE backends even outside strict mode, requires pinned RK id/epoch,
configured Ed25519 signing public keys, `search_execution: client_led`,
`search_mode: private_hnsw_oram`, explicit `result_privacy`, and fixed-budget
search in strict mode. Runtime validation also rejects unknown top-level and
nested private HNSW ORAM options instead of silently accepting secret-like policy
drift. Qdrant does not store point-level dense vectors for this provider and
does not score, traverse HNSW, or delete point-level CKKS sidecar vectors
server-side; normal vector writes, `delete_points`, `delete_vectors`, and
server scoring, including legacy search/batch search, ordinary query/fusion/context/MMR,
recommend/discover, `lookup_from` or point-id reference-vector resolution,
grouped search/query, and search matrix paths, fail closed and direct clients
to the private HNSW ORAM session APIs. Collection peer
`SyncPoints` batches are also rejected for private HNSW ORAM collections because
v1 shard transfer must preserve encrypted bucket/epoch parity instead of
replaying point-level sync. Phase 11 implements
the encrypted bucket store and session read/commit APIs behind this validated
control-plane contract.
Collection config and runtime validation require `vector/private-hnsw-oram@v1`
and `private-hnsw-oram/v1` to be paired exactly, reject multi-vector v1 rules,
and reject overlap with `vector/client-ckks@v1` or `vector/openfhe-ckks@v1`
bindings for the same vector name.
Private HNSW ORAM vector names must also be safe collection-local store path
components, so collection config, manifest, and signed request validation reject
names such as `.`, `..`, names containing `/` or `:`, and names longer than 128
bytes before any bucket-store path is constructed. They also reject names that
normalize to client-owned ORAM state aliases such as `client.state`,
`clientStateSnapshot.json`, `encryptedClientStateSnapshots.json`,
`position.map`, or `stashBackups.json`, including dotted extension forms.
The same private-session guidance is returned even when runtime crypto settings
are absent, so private HNSW ORAM vectors do not fall through to CKKS/OpenFHE
runtime fallback messages on ordinary vector upsert/update, inference-derived
vector writes, point delete, peer `SyncPoints`, `delete_vectors`,
query/search/recommend/discover/group/matrix APIs, `lookup_from` source-vector
resolution, or lower-level collection peer/internal write guards.
Ordinary retrieve/scroll reads that do not request vector output remain allowed,
because they do not ask Qdrant to reveal or score the private vector.
Collection-internal direct query/search/search-matrix entrypoints make the same
binding distinction: `private-hnsw-oram/v1` returns private ORAM session
guidance, while other encrypted vector bindings keep the CKKS sidecar runtime
entrypoint guidance.
Point-level `retrieve`/`scroll` requests that ask for this vector with
`with_vector` also fail closed with the same private HNSW ORAM session guidance;
Qdrant does not expose a CKKS sidecar payload for this provider.
Payload export rejects `with_vector` before applying encrypted payload policy
and points callers at the provider-appropriate vector read or private session
API instead of the ordinary read API.
The gRPC telemetry wrappers attach only the collection label for private HNSW
and private result ORAM calls; vector names, session ids, path labels, bucket
ids, and root hashes are not copied into telemetry extensions.
REST close-session paths route session id shape and length failures through the
same common validator as request bodies, so oversized or malformed session ids
receive the redacted `session_id is invalid` error instead of an early path
validation response.
The private ORAM bucket store is canonical encrypted index data, not an
untrusted acceleration hint: manifests, epoch files, Merkle metadata, and
buckets must live under private non-symlink directories. Directory creation
checks symlink/type before chmod so symlink targets are not hardened by mistake,
and Unix group/world access on bucket directories or files is rejected fail
closed.
Bucket-file read bounds account for base64url expansion of the configured
decoded ciphertext limit plus bounded JSON metadata overhead, so the largest
allowlisted ORAM bucket shapes remain readable without weakening oversized-file
rejection.
Runtime and signed-manifest validation keep fixed path budgets executable:
`oram.path_batch_size` must fit within the Path ORAM leaf count, and
`fixed_budget.paths_per_round` must equal `oram.path_batch_size`. This prevents
SDK/server disagreement and avoids configurations that could only be satisfied
by duplicate `read_paths` labels.
They also reject `dim`, `hnsw.fixed_neighbor_slots`, and
`oram.block_size_bytes` combinations that cannot hold the fixed-size f32 node
block layout. For example, a 1536-dimensional index with 64 fixed neighbor
slots requires a 16 KiB block-size allowlist entry rather than 8 KiB.
Signed manifests must also match the runtime instance's `hnsw`, `oram`, and
`fixed_budget` policies exactly; upload fails closed if the client signs a
manifest for a different ORAM shape or search budget than the configured
runtime provider.
Signed private HNSW and private result ORAM writebacks persist a validated
pending journal before changing any active bucket. Retrying the same
owner-signed commit revalidates that journal, idempotently rewrites its
encrypted buckets and Merkle tree, applies epoch/root CAS when still needed,
verifies the final state, and removes the journal with a directory fsync. This
resumes crashes before writeback, between bucket/Merkle writes and epoch CAS,
or immediately after epoch CAS. Until retry completes, the current epoch is
either still old or atomically advanced to new, and mixed root/bucket reads
fail closed. A pending journal also keeps snapshot preflight closed because
private ORAM temporary directories must be empty. After a process restart,
opening a replacement session at the signed new epoch detects the journal,
reserves the index write window, verifies and completes the journal, then
atomically converts that reservation into the new session writer lease. Invalid
or tampered journals keep session open fail closed.
Collection snapshots include private HNSW ORAM bucket files as ciphertext-only
JSON artifacts after rejecting non-directory or symlinked private ORAM snapshot
sources, unsupported source file types, client-owned ORAM state files, and
non-empty private ORAM temp write directories. Snapshot source preflight and
archive append also reject non-canonical private ORAM store entries before they
are written to the archive, and validate current epoch plus canonical epoch
commit file contents again at archive time. Client-owned state detection covers
snake_case, camelCase, kebab-case, and dot-separated aliases for client state,
encrypted client state snapshots, position maps, ORAM/token position maps, and
stashes, including `ciphertext_sha256` backup variants and payload fetch token
singular/plural aliases such as `payloadFetchToken`, `payloadFetchTokens`, and
`payload.fetch.token`.
Empty private ORAM temp directories are omitted from the archive;
snapshot tests seal a plaintext sentinel into a client bucket and assert that
the raw snapshot archive and restored bucket file do not contain the sentinel
bytes.
Snapshot restore preflight applies the same fail-closed tree hardening: private
ORAM restore roots, HNSW vector store directories, and nested entries must be
non-symlink regular files or directories, with unsupported file types and
unexpected client-owned state aliases rejected before manifest/epoch/bucket
parity is accepted. Restore also rejects files outside the canonical store
layout: manifest/signature files, encrypted bucket files in the manifest range,
`merkle/nodes.dat`, `epochs/current.json`, and canonical numeric epoch commit
files. Epoch commit files must parse as bounded JSON epoch/root records, carry a
canonical 32-byte base64url root hash, and match the epoch encoded in the
filename.
Collection and full snapshot creation also fail closed while any active private
HNSW ORAM or private result ORAM session exists for the collection, because a
session may be remapping paths and writing back buckets. While a private ORAM
collection/full snapshot guard is active, new session opens and manifest/bucket
uploads fail closed for the same reason. The error is sanitized and does not
include collection-local private ORAM filesystem paths or bucket roots.
Public REST and gRPC collection update/delete paths acquire the same private
ORAM lifecycle guard before submitting the collection meta operation. That keeps
vector/HNSW/quantization config changes and collection deletion from overlapping
active private ORAM sessions or manifest/bucket upload write windows, and it
also keeps collection/full snapshots from overlapping lifecycle operations.
While the lifecycle operation is in flight, new private ORAM sessions/uploads
and new collection/full snapshots fail closed.
REST and gRPC route fixtures cover both directions of this exclusion for private
HNSW ORAM and private result ORAM session/upload APIs, collection/full snapshot
creation with active lifecycle or active session guards, shard snapshot
list/create/stream/download/delete, shard recovery, and partial snapshot
manifest/recover-from routes. REST collection recovery fixtures also cover
active session/snapshot/upload guards.
Snapshot creation also fails closed while a private HNSW ORAM or private result
ORAM manifest/bucket upload write-window guard is active for the collection,
because upload writes canonical manifest, bucket, Merkle, and epoch files.
Snapshot creation also refuses to archive orphan private HNSW ORAM vector stores
whose on-disk store does not match a configured private HNSW ORAM encryption
rule, or configured private HNSW ORAM vector rules whose on-disk store is
missing.
Before writing an archive, collection snapshot creation also runs the same
private HNSW ORAM manifest/current epoch/bucket/Merkle layout parity preflight
used by restore. Missing bucket files or root mismatches fail closed without
reflecting collection-local paths, root hashes, or bucket ciphertexts.
Restore preflight rejects result-private manifests, collection/vector context
mismatches, vector dimension/distance mismatches, manifest signature key-id
mismatches, Path ORAM tree_height/bucket_count mismatches, current epoch/root
mismatches, bucket commitment roots that do not reconstruct the manifest
`root_hash`, and missing encrypted bucket files anywhere in the manifest bucket
range before shard restore proceeds. Symlinked vector directories and bucket
files are rejected by the same restore preflight. If a private HNSW ORAM store
root exists, every on-disk vector store must match a configured private HNSW
ORAM encryption rule, and every configured private HNSW ORAM vector must have a
store. Orphan stores, missing configured stores, and parent store symlinks fail
closed before manifest or bucket data is trusted.
The live REST and gRPC fixtures also exercise adversarial commit handling: a
commit with a non-increasing new epoch is rejected, a validly-shaped but wrong
Ed25519 signature is rejected, and replaying a previous old epoch/root after a
successful commit is rejected against the active session state. The commit path
also preflights the store's current epoch/root against the active session before
bucket or Merkle writeback starts, and the store writeback helper also requires
the stored signed manifest's epoch/root and bucket_count to match the commit old
context before accepting updated buckets. The `read_paths` path performs the
same current epoch/root preflight before returning encrypted buckets, so a
rolled back or mixed current epoch fails closed before bucket ciphertexts are
served.
It now reads buckets through the collection store's batch+proof helper, which
rechecks current epoch/root and fails closed if any returned bucket commitment
does not match the corresponding Merkle proof leaf.
They also reject opening a second session for the same private index while the
first session is active, exercising the MVP single-writer lock at the route
layer. After registering a session, session open rechecks the stored
manifest/signature/current epoch; if a concurrent manifest or epoch update was
observed during open, the new session is closed and the request fails before any
ORAM path reads are served. Session open also requires encrypted bucket/Merkle
metadata for the signed manifest epoch/root, so a manifest-only upload state
does not open a session. Session open requests with `fixed_budget=false` in
strict mode or a non-current desired epoch are rejected before any ORAM path
reads are served. `private_payload_oram_required` is accepted at HNSW
manifest/session policy only when the collection also has a
`private-result-oram/v1` payload binding; otherwise it fails closed. Client id
shape errors are sanitized without echoing the submitted client id; session
clients must use non-empty safe ASCII resource-id characters within the
configured length bound.
Expired sessions are purged from the registry before use and release the
single-writer lock for that private index; using an expired session id for
`read_paths`, `commit`, or `close` fails closed.
Oversized or malformed session ids are rejected before registry lookup without
reflecting the submitted value, while unknown well-shaped session ids still use
the sanitized missing/expired-session error.
`read_paths`, `commit`, and encrypted bucket upload also validate submitted
root hashes as canonical 32-byte base64url values before registry/storage
epoch comparisons, without reflecting malformed values.
`read_paths` and `commit` client signatures are length-checked as fixed
64-byte Ed25519 base64url values before decode/verification.
Runtime `signature_public_keys` verifier entries are likewise treated as fixed
authorizer policy: the registry must be non-empty, key ids must be valid
resource ids, entries must be 32-byte Ed25519 base64url public keys, and
duplicate public keys under multiple ids are rejected before signature
verification.
Signed manifest upload and initial encrypted bucket upload are also rejected
while an active session holds the same private index, so a bulk upload cannot
race a client-led traversal/writeback session. The upload path also holds a
registry write-window guard while manifest or bucket files are being written;
same-index session opens and duplicate uploads fail closed until that guard is
released.
The manifest signs the upload anchor epoch/root and non-secret index policy,
while `epochs/current.json`, Merkle metadata, and CAS are authoritative for the
live epoch/root after writeback commits. A writeback commit that advances
epoch/root does not require Qdrant to receive a freshly signed manifest before a
later session can open at that new epoch. REST and gRPC live fixtures now close
the committed session, verify that the closed session id cannot be reused for
`read_paths`, verify that unknown close-session ids are not reflected in error
responses, and re-open successfully at the committed epoch without manifest
refresh. They also use the reopened session's live epoch/root to perform a
signed `read_paths` call, so post-commit progress is covered past session open.
For initial signed manifest upload, Qdrant writes the manifest/signature before
publishing `epochs/current.json`, so a manifest-store write failure does not
leave a current epoch without a corresponding signed manifest.
If the stored manifest already matches the current epoch/root, repeated
manifest upload is accepted only as a byte-identical no-op. A refreshed signed
manifest is still accepted after commit when `epochs/current.json` has advanced
past the stored manifest and the uploaded manifest matches the new current
epoch/root.
Unknown session id handling for `read_paths`, `commit`, and `close` returns
sanitized errors without echoing the submitted session id.
SDKs may use `refresh_private_hnsw_oram_manifest_for_commit` or
`sign_private_hnsw_oram_manifest_refresh` when a commit plan was built from
the same signed manifest and they want an updated signed manifest body. The
server does not require that refresh for session reopen; clients that continue
from `epochs/current.json` without uploading a refreshed manifest must use
`plan_private_hnsw_oram_commit_for_manifest_context` so bucket commitments
remain bound to the signed manifest lineage while the old epoch/root comes from
the live store state rather than the older upload-anchor manifest.
Before the first signed manifest upload, REST and gRPC manifest read, bucket
upload, and session open calls fail closed with a sanitized `NotFound`
response; they do not surface collection-local private ORAM paths. Corrupt
stored manifest reads are also sanitized without exposing collection-local
`private_hnsw_oram` filesystem paths.
Signed manifest uploads whose collection/vector, key lineage, or vector
metadata context does not match the route and runtime context fail closed
before manifest persistence. Unsupported manifest signature algorithms and
malformed manifest signature errors are sanitized without echoing the submitted
algorithm or signature body. Signature key id lookup failures for manifest
upload, `read_paths`, and `commit` are also sanitized without echoing the
submitted key id. Manifest upload validates the signature algorithm, key-id
shape, and signature body shape before looking up the configured public key, so
malformed signed requests do not reach the verifier registry lookup boundary.
Manifest upload/read, bucket upload, session open, and snapshot restore
preflight also require the stored manifest signature `key_id` to match the
manifest's `owner_signing_key_id` before the verifier public key is looked up,
so non-owner manifest key ids do not reach the registry lookup boundary.
Runtime validation rejects registering the same Ed25519 verifier public key
under multiple key ids. This keeps `owner_signing_key_id` authorization
unambiguous even though the HNSW v1 canonical manifest signature format binds
the owner through the signature header and verifier selection.
The SDK/server manifest signature validators also validate manifest shape before
canonical manifest signature message construction. SDK signing helpers reject
malformed manifests, path-count mismatches, malformed path labels/roots, and
malformed commit hashes, non-advancing commit epochs, and empty commits before
constructing canonical signature messages. Server verification and SDK signing
use the checked `try_private_hnsw_oram_*_signature_message` builders, so
oversized canonical domain, string, path-count, or bucket-count fields fail
closed instead of truncating length prefixes. The older infallible HNSW ORAM
message-builder wrappers are not part of the public contract; callers must use
the checked builders. `docs/qdrant-sec-private-hnsw-oram-signature-test-vector.json`
freezes manifest, `read_paths`, and `commit` canonical messages, SHA-256
digests, and deterministic Ed25519 signatures for SDK interoperability.
The checked `read_paths` and `commit` message builders also reject unsupported
request signature algorithms and malformed signature key ids before canonical
message construction.
The `read_paths` and `commit` client signatures use the same key-id shape check
before verifier lookup; invalid key ids are rejected without echoing the
submitted value. For active sessions, the request key id must match the session
manifest's `owner_signing_key_id` before the verifier public key is looked up,
so non-owner key ids do not reach the registry lookup boundary. The `read_paths`
and `commit` crypto validators also reject malformed collection/vector/key
lineage, `requested_paths`/path-count mismatches, and non-advancing commit
epochs before signature body parsing or canonical message construction.
Unsupported request signature algorithms on these paths are rejected without
echoing the submitted algorithm value.
The REST/gRPC `read_paths` and `commit` handlers run request-shape preflight
for bounded path labels, root hashes, padding, and updated-bucket refs before
bucket access or writeback. Shape-valid requests then verify the client
signature before bucket-path derivation, Merkle preparation, or writeback.
Manifest-store layout failures during upload are sanitized without exposing
collection-local `private_hnsw_oram` filesystem paths.
Path ORAM manifests must also bind `bucket_count` to the canonical full binary
tree size implied by `tree_height`, so malformed layouts are rejected before a
session can reach `read_paths`. The SDK Path ORAM helpers reject `tree_height =
0` as a degenerate tree shape, matching manifest/runtime validation.
Runtime validation currently caps private HNSW and private result ORAM
`tree_height` at 20 because the MVP stores Merkle metadata as bounded JSON;
larger trees require the future compact/proof-oriented Merkle store before they
can be accepted safely.
It also caps the decoded ciphertext bytes in one fixed ORAM read batch, computed
from `path_batch_size * (tree_height + 1)` and the fixed bucket ciphertext size,
so a runtime policy cannot create an oversized `read_paths` or `read_buckets`
response.
Initial bucket upload also rejects incomplete bucket sets, duplicated bucket
ids, malformed bucket ciphertext, and ciphertext hash mismatches before
encrypted bucket files are written. Bucket commitments must also match the
server-verifiable commitment over collection/vector/key lineage, bucket id,
index epoch, and `ciphertext_sha256`. Upload and commit ingress additionally
bound the base64url ciphertext length before decode and then check that decoded
bucket ciphertext length exactly matches the fixed Path ORAM bucket size implied
by `oram.bucket_size` and `oram.block_size_bytes`; a shorter or longer
ciphertext is rejected even when its hash and commitment are self-consistent.
The initial upload ordering and fixed-size ciphertext ingress errors are fixed
messages and do not echo bucket ids, bucket epochs, or bucket ciphertexts.
The malformed ciphertext, fixed-size mismatch, bucket hash/commitment/root hash
shape, bucket commitment context mismatch, and Merkle root mismatch error paths
do not echo the submitted ciphertext or computed Merkle root into REST response bodies or gRPC
status messages, and epoch/root mismatch handling does not echo the submitted
root hash. Bucket-store layout failures during upload are sanitized without
exposing collection-local `private_hnsw_oram` filesystem paths. Corrupt
current-epoch metadata observed during bucket upload or session open is
sanitized the same way.
The collection-local private HNSW ORAM store also avoids reflecting bucket ids
or bucket epochs in bucket read/proof/commit validation errors, and its
current-epoch, Merkle tree context, and bucket-shape errors are fixed messages
without stored/requested epoch, bucket-count, bucket-id, or unsupported-version
values. Its file/directory hardening helpers also use fixed messages instead of
reflecting collection-local paths, temp filenames, symlink targets, or OS error
strings.
Session-open stale epoch errors do not echo the requested or current epoch.
Unsupported runtime `result_privacy` values and collection/runtime vector
dim/distance mismatches are also fixed messages that keep the structured
failure reason without reflecting submitted option values or actual vector
shape values. The `qdrant-sec` private HNSW provider/client and private result
ORAM helper error `Display` implementations keep structured enum fields for
callers while avoiding bucket ids, epochs, versions, ciphertext lengths, leaf
labels, or unsupported algorithm values in rendered strings.
REST and gRPC `read_paths` error handling is checked for non-reflection:
epoch/root mismatches and malformed path labels fail without echoing the
submitted root hash, submitted path label, or any stored bucket ciphertext into
the response body/status message. The path-to-bucket derivation helper also
maps lower-level leaf-label decode failures to the same fixed message. Exact
duplicate path labels are rejected before bucket reads so a larger path batch
cannot satisfy the fixed budget by repeating the same leaf. Missing encrypted
bucket/proof data is
reported as sanitized unavailable bucket data without exposing collection-local
`private_hnsw_oram` filesystem paths.
Before returning a `read_paths` response, Qdrant also checks that each encrypted
bucket commitment matches the same-position Merkle proof leaf. Bucket/proof
mismatches fail closed without echoing bucket ciphertexts or store paths.
For successful fixed-budget reads, the server preserves each requested ORAM
path's full bucket sequence instead of collapsing the response to a unique
bucket set. Shared prefix buckets may therefore appear more than once in the
response, and the SDK Merkle verifier accepts only byte-identical repeated
bucket/proof entries. This keeps the encrypted bucket response length fixed at
`requested_paths * (tree_height + 1)`. SDK proof JSON verification bounds the
proof body before parsing so oversized proof responses fail as malformed proof
JSON rather than reaching the JSON parser.
Active sessions do not keep serving under stale runtime policy. Each `read_paths`
and `commit` call compares the session manifest against the current runtime
context, including collection/vector identity, key lineage, vector metadata,
result privacy, and the `hnsw`/`oram`/`fixed_budget` policy; drift fails closed.
REST and gRPC route fixtures both exercise this by opening a session under one
runtime policy and then rejecting `read_paths` or `commit` through a service
with drifted `fixed_budget` or `oram` options.
The request signing key must also match the session manifest's
`owner_signing_key_id`; merely being present in `signature_public_keys` is not
enough to authorize ORAM read or commit requests for that private index.
For `read_paths`, the server bounds each ORAM leaf label to the canonical
fixed-length base64url form and rejects duplicate path labels without
reflecting malformed labels. After fixed-budget and session epoch/root checks,
shape-valid requests verify the Ed25519 request signature before computing
bucket paths. The SDK/server read-path signature message builder and validator
also shape-check the root hash, path labels, padding metadata, and duplicate
path-label invariant before signature body parsing.
For `commit`, the server bounds `old_root_hash` and `new_root_hash` to
canonical 32-byte base64url strings and rejects empty, oversized, duplicate, or
malformed updated-bucket refs before storage writes. Shape-valid requests
verify the Ed25519 request signature before preparing Merkle/writeback metadata.
The commit signature message builders and validators also reject empty commits,
non-advancing epochs, malformed roots, duplicate
bucket refs, and malformed updated bucket ciphertext hashes before signature
acceptance.
Malformed client signature shape errors for `read_paths` and `commit` are also
sanitized so submitted signature bodies and unsupported algorithm values are not
echoed.
Commit error handling follows the same boundary: malformed updated bucket
ciphertext, malformed new root hashes, and old epoch/root mismatches are
rejected without echoing the submitted ciphertext, new root hash, or old root
hash into the REST body or gRPC status message. Missing commit Merkle metadata
is reported without exposing
collection-local `private_hnsw_oram` filesystem paths. Empty and oversized
`updated_buckets` commits are rejected by fixed writeback request-size
validation before bucket writes are attempted; the SDK/server commit signature
validator also rejects empty commit bucket lists and malformed root hashes
before signature body parsing. Each updated bucket `ciphertext_sha256` is
shape-checked before signature message construction, and each updated bucket
must also carry exactly the manifest-derived fixed ciphertext size.
Commit writebacks also validate every updated bucket commitment against the
bucket ciphertext hash plus collection/vector/key lineage and the proposed
bucket epoch before Merkle metadata is prepared or bucket files are written.
The same live fixtures reject `read_paths` calls whose path count, requested
path count, or dummy padding flag does not match the configured fixed path
budget, before bucket reads are served. Valid `read_paths` calls must carry an
Ed25519 client signature over
collection/vector identity, key lineage, epoch/root, path labels, and padding
metadata before encrypted buckets are returned.
Snapshot restore preflight follows the same result-privacy boundary: private
HNSW ORAM manifests with `private_payload_oram_required` require a configured
private result ORAM payload binding and corresponding result ORAM snapshot store.
It also requires the paired result ORAM snapshot manifest's
`oram.path_batch_size` to divide the private HNSW
`fixed_budget.fixed_result_k`, matching runtime validation and preventing a
restored index from producing partial final `read_buckets` batches. Restore
preflight also checks every
manifest-range bucket for the manifest-derived fixed ciphertext size and verifies
each bucket commitment against collection/vector/key lineage, bucket epoch, and
`ciphertext_sha256` before accepting the Merkle root.
The startup snapshot mapping recovery path runs the same private HNSW ORAM
restore-layout preflight after crypto runtime validation, so CLI recovery
cannot bypass bucket/root consistency checks that are enforced by storage-level
snapshot recovery. Store-originated layout failures in this CLI path are
sanitized before reporting, so collection-local `private_hnsw_oram` paths and
stored bucket bodies are not reflected; CLI layout failures are fixed messages
that also avoid bucket ids and bucket commitment mismatch details.
Private HNSW vector store names must also be safe store path components and
are rejected if they compact to reserved client-owned state aliases such as
`client.state`, `position.map`, `client_state_ciphertext_sha256`,
`client_state_ciphertexts_sha256`, `clientStateCiphertextsSha256`, or `stash`;
snapshot source/archive and restore preflight apply the same checks before
archiving or accepting ORAM store contents.
CLI and REST snapshot recovery also validate stored private HNSW ORAM manifest
and private result ORAM manifest signatures against the runtime
`signature_public_keys` registry after the restore-layout preflight passes, so
tampered manifest signatures fail closed without exposing bucket roots,
ciphertexts, or store paths. Storage-level snapshot recovery also runs private
HNSW ORAM and private result ORAM restore-layout preflight before shard restore
begins and applies the same sanitization before returning layout failures to
callers. Collection-level snapshot manifest and bucket-contract mismatch errors
also avoid reflecting manifest ids, vector names, dimensions, bucket ids, or
bucket ciphertexts.

Current result privacy support has two explicit modes. `result_privacy:
ids_visible` keeps Qdrant blind to vectors, query vectors, visited HNSW nodes,
distances, and client-side top-k during the private session, but a later
ordinary retrieve leaks the retrieved point ids to Qdrant.
`private_payload_oram_required` is accepted only when the same collection also
binds a `payload/private-result-oram@v1` rule through `private-result-oram/v1`,
and result payload fetches must then go through the private result ORAM
session/read/commit path rather than ordinary retrieve. The dedicated result
ORAM REST/gRPC path can upload/read signed manifests plus encrypted bucket
batches, open fixed-budget sessions, return Merkle-proven bucket batches, and
apply signed writeback commits through epoch/root CAS.
Ordinary point upsert, sync, and point delete/delete-by-filter fail closed for a
collection with a `private-result-oram/v1` payload binding because they can
create, replace, or remove payload state outside the private result ORAM epoch
contract. Payload writes also fail closed when they can affect the protected
path: key-less `overwrite_payload` is treated as a full payload replacement,
key-less `set_payload` rejects parent/child path overlap, and `delete_payload`
or payload clear operations that touch the protected path direct callers to the
private result ORAM session APIs instead of falling through to the regular
server/client payload envelope write path. Non-overlapping public payload merges
and explicit sibling paths, such as a `document.title` write beside protected
`document.body`, stay on the ordinary update path.
Ordinary raw payload reads through retrieve, scroll, search, or query also fail
closed when `with_payload` would return a `private-result-oram/v1` payload path.
The public gRPC `GetPoints`, `ScrollPoints`, `SearchPoints`, batch/grouped
search, `RecommendPoints`, batch/grouped recommend, `DiscoverPoints`, batch
discover, `QueryPoints`, and grouped/batch query wrappers follow the same
fail-closed read guard before returning raw protected payload bytes.
Grouped gRPC `with_lookup` payload requests and REST group lookup preflight use
the same guard when the lookup collection is bound to `private-result-oram/v1`.
Callers may omit payloads or request redacted encrypted payload output, so
payload-omitted retrieve/scroll/search requests remain ordinary. Raw or
server-decrypted result payload bytes require the private result ORAM
session/read/commit APIs.
Trusted-bridge CKKS sidecar fallback paths, including point-id query resolution,
grouped search/query, and search matrix sampling, request only the reserved
vector sidecar field and any required group key instead of full raw payloads, so
they do not accidentally read private result ORAM payload paths while resolving
encrypted vector sidecars.
Ordinary server-side selectors that would inspect a private result ORAM payload
path, including filters, order-by, group-by, facets, and formula payload
variables/conditions, fail closed with the same private result ORAM session API
guidance rather than suggesting a blind-index fallback.
The gRPC facet, count filter, scroll filter/order-by, formula query, grouped
search, and grouped query wrappers enforce the same selector guard after
converting their payload paths.
Payload index/schema creation or deletion on a `private-result-oram/v1` payload
path, including gRPC create/delete-field-index wrappers, is also rejected by the
encrypted payload index guard. Public create/delete-field-index requests check
write/extras authorization before this private-result guard, so unauthorized
callers receive the normal forbidden response without provider/session details.
Result ORAM snapshot restore preflight is open for configured
`private-result-oram/v1` bindings and validates manifest/current epoch, buckets,
Merkle metadata, and runtime Ed25519 signatures. The SDK search result now
propagates each node block's `payload_fetch_token`, and a client-side helper
fails closed when `private_payload_oram_required` hits do not all carry payload
fetch tokens. A follow-on SDK helper turns those hit tokens into an exactly
`fixed_result_k` private result ORAM fetch-token batch, padding from a caller
provided distinct dummy-token pool so the eventual result fetch has fixed
logical volume. The helper validates the whole supplied dummy-token pool,
including unused extra tokens, and rejects any duplicate, hit-token collision,
duplicate hit node/point, or non-finite hit distance before it emits a fetch
plan. Collection runtime validation requires a compatible result ORAM binding
whose `oram.path_batch_size` divides the private HNSW
`fixed_budget.fixed_result_k`, so SDKs do not emit a smaller final
`read_buckets` batch. The result ORAM client fetch planner and verified fetch
wrapper also reject token batches that are not an exact multiple of
`oram.path_batch_size` and reject fetched payload blocks with duplicate point
tokens before returning a token-fetch result. The private result ORAM client
contract can now map that fixed token batch through the client-held
token-position map into session
`read_buckets` bucket-id sequences that preserve shared path bucket duplicates,
so ORAM path volume is not reduced by deduplicating overlapping paths. The SDK
ordered planner distributes same-leaf tokens across fixed-size read batches
when the configured batch count can accommodate them, and rejects impossible
leaf-collision schedules before a server request is built. Server read
validation accepts duplicate bucket ids for shared path prefixes but rejects
empty, repeated full-path, non-whole-path-shaped, non-canonical Path ORAM heap
paths, or batches that do not exactly match the configured fixed path budget.
New SDK integrations should use
`plan_private_result_oram_ordered_read_bucket_batches_for_fetch_tokens` before
signing `read_buckets` requests when token positions may share a leaf. The
crypto crate also
exposes canonical `read_buckets`
message/sign/verify helpers that bind collection/key lineage, index epoch,
root hash, bucket count, and the exact padded bucket-id sequence; REST and gRPC
`read_buckets` handlers now require that signature before encrypted buckets are
read or detailed path-shape errors are returned.
`sign_private_result_oram_read_buckets_for_manifest_context` derives that read
signature context from the signed manifest lineage while taking the live index
epoch/root explicitly. It enforces the fixed `oram.path_batch_size *
(oram.tree_height + 1)` bucket-id volume and canonical Path ORAM heap path shape
before signing. `sign_private_result_oram_read_buckets_for_manifest` is the
convenience wrapper for the first read after upload or after an optional
manifest refresh, when the signed manifest epoch/root is the live read context.
The planner also rejects missing token positions, duplicate fetch tokens,
duplicate token-position entries, and out-of-range leaves before a server
request is built. The crypto crate also has a client-only private result ORAM
payload block/plaintext bucket codec for
fixed-size bucket contents:
payload bytes, payload fetch token, point token, generation, and deletion state
are encoded inside the client-encrypted bucket body and are never server
validated as plaintext. Client AEAD helpers can seal/open those plaintext
buckets into `PrivateResultOramBucket` ciphertexts with collection/key/epoch
AAD, context-bound bucket commitments, ciphertext hash checks, and
Merkle-proof-before-open verification for read batches. The SDK-side result ORAM
state/access helper can now use the client-held token position map and stash to
access a payload fetch token on a Path ORAM path, remap it to a new leaf, and
produce plaintext writeback buckets for the commit path; the plaintext bucket
codec and access helper reject duplicate payload fetch tokens and duplicate
point tokens before decrypted path blocks are absorbed into the stash. A
higher-level verified
token-fetch helper now rebuilds the expected bucket path sequence from the
client position map before opening server batches, consumes only matching
planned encrypted bucket batches, overlays local writebacks between batched Path
ORAM accesses, returns payload blocks, and reseals unique writeback buckets for
the result ORAM commit planner. The server commit guard caps each owner-signed
writeback set to `oram.path_batch_size * (oram.tree_height + 1)` buckets, so
commit volume cannot expand to the full manifest `bucket_count`; it still
rejects empty commits, duplicate bucket ids, malformed bucket hashes, stale
epoch/root, and invalid signatures before storage changes. Multi-batch result
fetches therefore use repeated fixed-size read/commit windows. The HNSW SDK
finalizer maps only real HNSW hits back to fetched payload blocks and validates
the fetched token set, point-token binding, and deleted-payload rejection before
exposing payload bytes to the caller. A canonical plaintext client-state
snapshot shape now round-trips the result ORAM token position map and stash for
client-side backup validation; snapshot export/import rejects duplicate stash
payload tokens, duplicate stash point tokens, and malformed stash payload block
versions, payload lengths, or stash map-key/token mismatches before state
recovery. An encrypted
snapshot helper rejects malformed collection AAD context identifiers and seals
that backup under a client-derived state key with collection/key/epoch/root AAD
plus ciphertext hash checks. Result ORAM read/commit signature contexts also
reject malformed collection and key identifiers before signing. New SDK code should derive
`PrivateResultOramClientKeys` from the signed result manifest rather than the
deprecated legacy domain-only helper; the manifest-bound derivation length-prefixes
collection id, RK id, and RK epoch into the HKDF info context before deriving
bucket and client-state subkeys. Server-side HNSW manifest upload, bucket upload,
session open, and snapshot restore preflight now accept
`private_payload_oram_required` only when the same collection also has a
`private-result-oram/v1` payload rule backed by
`payload/private-result-oram@v1`; without that binding they continue to fail
closed. Normal Qdrant search APIs remain client-led-session-only for private
HNSW vectors.
The crypto crate defines the payload/result ORAM manifest shape through
`PrivateResultOramManifest`, `PrivateResultOramBucket`, and the checked
`try_private_result_oram_*_signature_message` builders. The older infallible
message-builder wrappers are not part of the public contract; production signing
and verification use the checked builders so canonical field-length or
bucket-count overflow fails closed before Ed25519 verification/signing.
`docs/qdrant-sec-private-result-oram-signature-test-vector.json` freezes
manifest, `read_buckets`, and `commit` canonical messages, SHA-256 digests, and
deterministic Ed25519 signatures for SDK interoperability. It can
validate manifest shape, including
canonical Path ORAM tree_height/bucket_count consistency,
logical plus dummy count against ORAM bucket capacity, Ed25519 signatures,
collection/key/epoch context, and root hash pinning;
the commit signature builder defines the signed bucket writeback CAS input used
by commit handlers. `validate_private_result_oram_bucket_shape`
checks bucket version, epoch, range, ciphertext size, ciphertext SHA-256, and
bucket commitment encoding. `private_result_oram_bucket_commitment` binds a
bucket commitment to collection/key lineage, bucket id, index epoch, and
`ciphertext_sha256`, while encoded ciphertext length is bounded before decode
and `private_result_oram_merkle_root_for_commitments`
fixes the root hash calculation over those commitments.
`plan_private_result_oram_commit` prepares signed writeback plans from the live
old epoch/root and current leaf commitments by checking old-root consistency,
bucket epoch/range uniqueness, the next root, and commit signature bucket refs.
`plan_private_result_oram_commit_for_manifest_context` adds manifest lineage,
bucket-count, fixed writeback budget, and context-bound bucket commitment
validation while still taking the live old epoch/root explicitly.
`plan_private_result_oram_commit_for_manifest` is the stricter convenience
variant for the first commit after upload or after an optional signed manifest
refresh: it uses the signed manifest epoch/root/bucket_count as the old commit
context.
`sign_private_result_oram_manifest` and
`sign_private_result_oram_commit` provide the matching SDK-side Ed25519 signing
helpers, while `sign_private_result_oram_read_buckets_for_manifest_context`
signs manifest-lineage-bound fixed-size `read_buckets` requests with a live
epoch/root. `PrivateResultOramUploadBundle` and
`package_private_result_oram_upload_bundle` package a signed manifest with a
complete ordered bucket set whose commitments match the manifest root.
`validate_private_result_oram_upload_bundle` and the bundle's
`validate_initial_upload_contract` method let SDKs and runtime upload handlers
preflight decoded result bundles with one contract: they validate manifest
shape, ordered bucket ids, bucket ciphertext hash/size, context-bound bucket
commitments, and the manifest Merkle root.
`validate_private_result_oram_upload_bundle_with_signature` and the bundle's
`validate_initial_upload_contract_with_signature` method add the owner Ed25519
verification context to that preflight so runtime upload handlers do not have to
stitch shape validation and manifest signature verification together by hand.
The collection-local result ORAM store uses the shape helper for initial bundle
ingest, then applies its runtime ciphertext size cap before writing files. Its
signed ingest entrypoint uses the combined upload-bundle/manifest-signature
helper before creating the private result ORAM layout, so a bad owner Ed25519
signature leaves `epochs/current.json` absent and does not write bucket files.
The separate manifest upload helper publishes the initial epoch only after the
manifest/signature write succeeds, accepts current manifest reupload only when
the stored manifest and signature are byte-identical, and allows a post-commit
manifest refresh when `current.json` has already advanced to the new
epoch/root. REST and gRPC live fixtures also reopen at that committed epoch
without manifest refresh and perform a signed `read_buckets` call using the
live epoch/root.
Manifest upload, manifest read, session open, bucket upload, and snapshot
restore preflight validate the stored manifest signature shape and require the
signature `key_id` to match the manifest's `owner_signing_key_id` before looking
up the runtime `signature_public_keys` entry. A non-owner manifest signature key
therefore fails with the same sanitized owner-mismatch error whether or not the
key id is configured.
`refresh_private_result_oram_manifest_for_commit` and
`sign_private_result_oram_manifest_refresh` mirror the private HNSW helper by
first validating the current result ORAM manifest shape and deriving the next
signed manifest only when a commit plan's old epoch/root matches it. The
collection crate implements
`PrivateResultOramStore` for the payload/result layer. It writes
`private_result_oram/manifest.json`,
`manifest.sig`, encrypted bucket files, Merkle commitment metadata, and
`epochs/current.json` with the same private directory hardening and epoch CAS
contract used by private HNSW ORAM. Its upload bundle preflight validates
manifest signature shape and owner key id before store writes, and the signed
initial upload path verifies the owner Ed25519 signature before layout creation.
Upload bundle,
commit, and stored Merkle-tree root mismatch errors do not reflect computed
Merkle roots; bucket read/proof/commit validation errors also avoid reflecting
bucket ids or bucket epochs. Current-epoch and Merkle tree context errors are
also fixed messages without stored/requested epoch, bucket-count, or
unsupported-version values. Its file/directory hardening helpers also avoid
reflecting collection-local paths, temp filenames, symlink targets, or OS error
strings. The writeback helper preflights stale current epochs, bucket count, and
bucket commitment context before bucket/Merkle writes. It rejects
empty writebacks before storage state changes, and REST/gRPC commit request-size
validation allows at most the manifest `bucket_count` updated buckets so
multi-batch fixed result fetches can be committed without exceeding a
single-read-batch limit. Its signed writeback entrypoint verifies the SDK
Ed25519 commit signature against the stored manifest lineage
before delegating to that helper, so an invalid commit signature leaves the
current epoch, buckets, and Merkle metadata unchanged. The REST/gRPC commit
handlers reject empty, duplicate, and malformed writeback refs before Merkle or
writeback validation runs, and shape-valid invalid signatures fail without
storage changes. SDK commit planning, signing, and verification also reject
empty commit bucket lists and malformed updated bucket ciphertext hashes, and
validate each updated bucket commitment against the bucket ciphertext hash plus
collection/key lineage and the proposed bucket epoch before preparing Merkle
metadata.
For result ORAM `read_buckets` and `commit`, the request signature shape is
preflighted before session access. Once the active session is resolved, the
request signing key must match the session manifest's `owner_signing_key_id`
before the verifier public key is looked up; non-owner key ids therefore do not
reach the registry lookup boundary and are rejected without echoing the
submitted key id. Unsupported request signature algorithms on these two paths
are rejected on the same generic validation path without echoing the submitted
algorithm value.
The `read_buckets` handler verifies the canonical signed bucket-id sequence
before returning detailed path-shape or bucket-range errors, so unauthenticated
malformed read batches stay on the generic signature-failure path. The crypto
read-buckets message builder, signer, and validator also derive the Path ORAM
tree height from the signed `bucket_count` and reject non-canonical tree sizes,
partial paths, and invalid root-to-leaf bucket sequences before signature
acceptance. The `read_buckets` and `commit` message builders also reject
unsupported request signature algorithms and malformed signature key ids before
canonical message construction.
Directory hardening also checks symlink/type before chmod. It also exposes
`read_merkle_path_batch` with the canonical qdrant-sec
`merkle_path_batch/v1` proof DTO; the REST/gRPC `read_buckets` API returns these
server-verifiable bucket commitment proofs without opening ciphertexts. The
store generator rejects empty bucket batches. `read_bucket_batch_with_proof`
preflights the current epoch/root before reading encrypted buckets, returns the
bucket batch with its Merkle proof, and fails closed if any proof leaf does not
match the returned bucket commitment. The SDK-side
`verify_private_result_oram_merkle_proof` and JSON helper validate proof kind,
epoch/root, bucket count, sibling level/position, and bucket commitment matches
against the same DTO emitted by the collection store. They reject empty
proof/bucket sets, preserve fixed-size path-batch semantics by allowing
repeated bucket/proof entries only when the duplicate entries are
byte-identical, reject oversized proof JSON before parsing, and fail closed on
conflicting duplicates.
`write_initial_upload_bundle` validates an SDK-packaged
signed manifest plus complete ordered bucket set, writes the manifest, Merkle
metadata, encrypted buckets, and initial epoch state, and keeps root mismatch
failures fail-closed. Repeated initial epoch writes are idempotent only for the
same epoch/root and leave the stored current epoch untouched on mismatch.
Repeated initial upload bundles with that same epoch/root are accepted as no-op
only when the stored manifest/signature, Merkle tree, and bucket set already
match the incoming bundle.
`commit_writeback` mirrors the private HNSW ORAM commit order by rejecting empty
or non-advancing writebacks, preflighting current epoch/root and stored manifest
context, validating updated bucket ciphertext/hash plus context-bound
commitments, preparing the Merkle update, writing updated encrypted buckets,
writing Merkle metadata, then applying epoch/root CAS. The live private result ORAM
REST/gRPC commit handlers delegate their signed writeback to
`commit_writeback_with_signature`, so the canonical Ed25519 commit signature,
fixed ciphertext size, context-bound bucket commitment, durable pending
journal, Merkle update, and epoch/root CAS share the same storage boundary.
Exact commit retries resume before-write, mid-write, and post-CAS process
failures idempotently; journal signature or shape tampering fails before active
state changes. Invalid signatures, malformed ciphertext, stale roots, and
commitment-context mismatches likewise fail before bucket, Merkle, or epoch
state changes; runtime error mapping preserves only safe failure categories
such as `ciphertext` or `commit signature` without echoing ciphertext bodies,
bucket ids, or root hashes.
Bucket `index_epoch` records the epoch when that encrypted bucket was last
written. After a writeback commit, unchanged buckets may still carry an older
bucket epoch as long as the current Merkle root commits to their existing
bucket commitment; reads reject buckets newer than the requested session epoch.
Collection snapshots include the `private_result_oram/` directory only when
collection encryption has a configured `private-result-oram/v1` binding backed
by `payload/private-result-oram@v1`. Snapshot creation preflights that
configured store before writing the archive, and rejects orphan result ORAM
stores, missing bucket files, unexpected non-canonical store files, and other
layout drift fail closed. Restore preflight applies the same runtime-bound check
before accepting the recovered collection. The preflight verifies the stored
manifest/signature, current epoch/root, encrypted buckets, and Merkle metadata
against runtime policy.
Snapshot creation and restore still reject symlinks inside the result ORAM
source tree without reflecting symlink targets or bucket filenames. Guard
inspection failures are fixed messages and do not reflect collection paths,
reserved directory names, or OS error strings.
The CLI/startup snapshot mapping preflight applies the same runtime-bound
private result ORAM checks before accepting a recovered collection.
Cluster runtime parity uses the existing crypto capability fingerprint for this
provider as well. The fingerprint includes non-secret private HNSW ORAM and
private result ORAM policy such as tree shape, fixed budget, result privacy mode,
and signing verifier digests, while redacting raw verifier public keys. A peer
with a different ORAM shape or signing verifier fails runtime capability parity
before it can be treated as an equivalent private-ORAM-capable node. The mismatch diagnostic
names the peer and fail-closed condition but does not echo the local or peer
fingerprint strings.
Shard transfer start operations are also blocked while a collection is configured
with private HNSW ORAM or private result ORAM bucket stores. The MVP stores
those private indexes as collection-level encrypted ORAM buckets, and shard
transfer does not yet copy bucket files or move epoch/root ownership through
consensus, so transfer start operations fail closed instead of producing a
partial private index on the receiver.
Resharding start and progress operations are blocked for the same collection
shape. The current resharding data path migrates point payload/vector records
through a shard proxy, but it does not migrate collection-local private ORAM
bucket stores or establish consensus-backed epoch/root ownership for the new
shard layout. `AbortResharding` remains allowed for cleanup, while commit,
finish, and replica-state progress from resharding states fail closed.
Shard-key layout changes are blocked for the same reason: `create_sharding_key`
and `drop_sharding_key` would add or remove shard placement without migrating
collection-local private ORAM buckets or transferring epoch/root ownership.
Replica removal is also blocked: `drop_replica` and direct replica-set remove
meta-ops would change local shard ownership without a private ORAM bucket
ownership protocol.
Manual shard snapshot creation, streaming, download, partial snapshot manifests,
and shard snapshot recovery fail closed for the same reason: shard snapshots do
not yet carry the collection-local private ORAM bucket store with epoch/root
parity. Use collection snapshot/restore preflight for private ORAM collections
until shard-level bucket parity is implemented.
Automatic dead-replica shard transfer recovery also skips private ORAM bucket
store collections for the same reason; parity alone is insufficient until bucket
movement and epoch/root ownership are consensus-backed. As a final guard,
existing consensus transfer and resharding progress records for private ORAM
collections are rejected before the local transfer task starts moving shard data,
the transfer progresses replica state, or resharding commits hash-ring or
replica-state progress. `Abort` remains allowed so unsupported transfer and
resharding records can be cleaned up without moving encrypted ORAM buckets.
Consensus snapshot apply uses the same fail-closed stance. Incoming shard
transfer state, non-empty resharding state, and shard layout config changes are
rejected for private ORAM collections, while empty cleanup state remains
allowed. Incoming shard-info state must preserve the current shard id set,
shard-key mapping, and replica membership, and must not introduce resharding
replica states; otherwise snapshot apply fails before it can create, remove, or
reassign local shard data without a private ORAM bucket migration protocol.
Distributed private ORAM epoch operations themselves fail closed in this MVP:
manifest upload, bucket upload, session open, session-bound reads, and commits
do not proceed until epoch/root CAS is backed by consensus rather than
node-local files.

The Rust reference SDK helpers in `qdrant-sec` now cover the MVP build/upload
preparation loop. `build_private_hnsw_oram_plaintext_index_from_f32_points`
constructs a deterministic one-layer f32 neighbor graph for fixtures and
reference clients, and
`build_private_hnsw_oram_plaintext_index_from_layered_f32_points` accepts
explicit per-node HNSW levels to populate canonical level masks and
per-neighbor levels for layered fixtures; it also applies an HNSW-style
redundant-neighbor pruning heuristic before sealing the graph.
`build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points` derives
deterministic geometric levels from random opaque node ids via
`private_hnsw_level_from_node_id`, then delegates to the layered builder.
`build_private_hnsw_oram_plaintext_index_from_blocks` packs prebuilt private
HNSW node blocks into Path ORAM plaintext buckets and client position state,
and `seal_private_hnsw_oram_plaintext_index` seals those buckets into
upload-ready encrypted `PrivateHnswOramBucket` records plus a Merkle
`root_hash`. `build_private_hnsw_oram_manifest_from_encrypted_index`
copies the encrypted build metadata into a signed manifest-ready
`PrivateHnswOramManifest`, so clients can build, seal, manifest, sign, and
upload without recomputing server-visible index metadata.
New SDK code should derive `PrivateHnswClientKeys` from the signed HNSW
manifest rather than the deprecated legacy domain-only helper; the manifest-bound
derivation length-prefixes collection id, vector name, RK id, and RK epoch into
the HKDF info context before deriving node, bucket, position-map, payload-token,
and blind-result subkeys.
`package_private_hnsw_oram_upload_bundle` wraps that manifest, its Ed25519
signature, and the sealed buckets into a serde-compatible upload bundle for
REST/gRPC SDK distribution. `validate_private_hnsw_oram_upload_bundle` and the
bundle's `validate_initial_upload_contract` method let SDKs preflight decoded
upload bundles before calling Qdrant: they require a complete bucket set, reject
duplicate or missing bucket ids, verify bucket ciphertext SHA-256 and bucket
commitments against the manifest context, require the manifest signature shape
and owner key id to match the manifest, require each decoded ciphertext to match
the manifest-derived fixed bucket ciphertext size, and recompute the manifest
Merkle root. HNSW ORAM bucket commitments use the
`qdrant-sec/private-hnsw-oram-bucket-commitment/v1` domain with 4-byte
big-endian length-prefixed collection id, vector name, key id, and RK id,
followed by RK epoch, bucket id, index epoch, and the decoded
`ciphertext_sha256`; the manifest Merkle root is computed over the ordered
bucket commitments after padding the leaf level to the next power of two with
zero hashes. `validate_private_hnsw_oram_upload_bundle_with_signature` and the
bundle's `validate_initial_upload_contract_with_signature` method add the
runtime manifest validation context and Ed25519 verification to that preflight.
The collection-local private HNSW ORAM store exposes matching initial upload
bundle entrypoints; the signed variant verifies the owner Ed25519 manifest
signature before creating the private index layout, so a bad signature leaves
`epochs/current.json` absent and does not write bucket files.
For ORAM path reads, `sign_private_hnsw_oram_read_paths_for_manifest_context`
derives the signed read context from the signed manifest lineage plus the live
epoch/root and enforces the manifest's fixed `oram.path_batch_size` and
tree-bounded leaf labels before producing the Ed25519 request signature.
`sign_private_hnsw_oram_read_paths_for_manifest` is the convenience wrapper for
the first read after upload or after an optional manifest refresh, when the
manifest epoch/root is the live read context.
The collection store returns `merkle_path_batch/v1` proofs for the encrypted
bucket sequence served by `read_paths`, including repeated bucket/proof entries
when fixed-size ORAM paths share buckets. The SDK-side Merkle proof verifier and
JSON helper validate kind, epoch/root, bucket count, sibling order, and bucket
commitment matches against that store-emitted DTO. Duplicate entries are allowed
only when the repeated bucket/proof data is byte-identical; conflicting
duplicates, empty proof/bucket sets, oversized proof JSON, or commitment
mismatches fail closed before bucket ciphertext is opened.
Before submitting an ORAM writeback, clients can call
`plan_private_hnsw_oram_commit_for_manifest_context` with the live old
epoch/root, current leaf commitments, and signed manifest to produce signature
bucket refs while validating collection/vector/key lineage, fixed writeback
budget, and updated bucket commitments. When the live old epoch/root is the
same as the signed manifest, `plan_private_hnsw_oram_commit_for_manifest` is a
convenience wrapper for the first commit after upload or after an optional
signed manifest refresh. After the writeback commit succeeds, clients can
optionally call `refresh_private_hnsw_oram_manifest_for_commit` to derive the
next signed manifest body from that manifest-bound plan, or
`sign_private_hnsw_oram_manifest_refresh` to derive and sign it in one step;
both first validate the current manifest shape and reject a plan whose old
epoch/root does not match it. Session open and later commits do not require this
refresh because the live epoch/root is tracked by current epoch CAS and Merkle
metadata; without a refreshed manifest, clients should continue with
`plan_private_hnsw_oram_commit_for_manifest_context` using the current
epoch/root returned by the session/read state.
The server-side private HNSW tests now package a tiny SDK-built encrypted index,
sign its manifest, and verify that the initial
bucket upload bundle satisfies the same manifest epoch/root and Merkle
commitment contract used by REST/gRPC bucket upload. The collection store tests
also exercise a packaged
upload/read_paths/verified-search/writeback-commit round trip against
SDK-sealed buckets. The qdrant route-layer tests reuse that SDK package across
the REST JSON DTOs and gRPC protobuf messages for manifest upload, bucket
upload, session open, ORAM `read_paths`, and commit request/response shapes.
The gRPC fixture also feeds a route-shaped `read_paths` response with encrypted
buckets and a Merkle path batch proof into the SDK verifier, so proof-bearing
wire responses are checked before bucket decryption. Dispatcher-backed REST and
gRPC live route tests now create encrypted collections with stable UUIDs, upload
the SDK manifest and bucket bundle through the private HNSW APIs, open sessions,
sign live `read_paths` requests, verify responses with the SDK Merkle verifier,
commit writeback buckets, close the sessions, and re-open at the new epoch
without refreshing the signed manifest. Initial manifest upload
creates the private epoch layout when no current epoch exists; repeated uploads
still require the current epoch/root to match, and a mismatched upload leaves
the stored current epoch untouched. ORAM commits may carry unchanged
buckets forward from an older bucket epoch; the current Merkle root commits to
each bucket commitment, and clients open each bucket with the epoch recorded in
that bucket while rejecting buckets newer than the requested index epoch. Search
clients should open server `read_paths` responses with
`search_private_hnsw_oram_encrypted_verified`, which preflights the client-pinned
root hash and manifest-derived bucket count before issuing a server read, then
checks the response epoch/root/bucket count and Merkle path batch proof before
decrypting buckets or issuing ORAM writeback. SDKs may keep high-level HNSW
nodes in a local
`PrivateHnswClientNodeCache` and call the `*_with_cache` search helpers. A cache
hit still consumes a padding ORAM access through `padding_node_id`, so fixed-step
request volume remains constant while the client uses its local upper-layer node
copy for traversal and distance calculation. The verified cache helper applies
the same Merkle proof check before bucket decryption, state remap, or writeback.
`PrivateHnswSearchResult::access_metrics` returns
`PrivateHnswSearchAccessMetrics` with path-access count, unique leaf count,
fixed-step budget, and budget-exhaustion status for latency/ORAM-volume
benchmarks without exposing plaintext vectors, distances beyond client-local
hits, or decrypted neighbor lists. The exhausted flag is set only when the path
count, completed step count, and canonical access leaf-label shape all match the
fixed budget. Strict SDK flows should call
`validate_private_hnsw_strict_search_result` before result fetch or commit so a
search that stopped before consuming `fixed_steps` is treated as a failed
fixed-budget search, not a shortened private query. The strict validator also
requires canonical access leaf-label shape, finite hit distances, and unique hit
node/point identifiers. The private result ORAM payload finalizer repeats the
same hit-shape check before returning payload bytes for real hits.
`cargo bench -p qdrant-sec --bench private_hnsw_oram_bench` provides the
initial SDK-side benchmark harness for plaintext reference index build and
fixed-budget plaintext ORAM-HNSW traversal, including an upper-layer client
cache variant, plus client-AEAD encrypted bucket open/reseal traversal. It is
intentionally client-local: the benchmark exercises ORAM path read/writeback
closures, speculative prefetch planning, neighbor-clustered leaf planning, and
directional neighbor filtering, and access metrics, but it does not route
vectors or queries through Qdrant.
`plan_private_hnsw_oram_speculative_prefetch` prepares fixed-count padded
neighbor path labels from the client position map, deduplicating real candidate
leaves and filling the remaining request slots with unique dummy leaves before
the SDK calls `read_paths`. This keeps SDK-generated batches compatible with
the server-side duplicate path-label guard while still preserving a fixed path
count; the leaf-label bucket-path helper also rejects duplicate labels before
producing a request bucket sequence. Runtime and manifest validation reject path
budgets larger than the available unique ORAM leaves. `plan_private_hnsw_oram_neighbor_clustered_leaves` provides a
deterministic graph-order leaf assignment helper for bulk builds, so SDK
experiments can place entry-near neighbor chains on adjacent ORAM leaves before
calling `build_private_hnsw_oram_plaintext_index_from_blocks`; the helper
requires the requested entry node to be present in the build block set and
fails closed instead of silently falling back to the first block.
The plaintext index builder rejects duplicate node ids, point tokens, and
payload fetch tokens before bucket placement so malformed indexes cannot defer
result-token ambiguity to search or private result fetch validation. HNSW node
block codec validation rejects empty/non-contiguous level masks, neighbor levels
outside the node level mask, self-neighbors, and duplicate same-level neighbor
entries while still allowing the same neighbor id on different HNSW levels; it
also rejects malformed, empty, or non-finite `f32_le` vector bytes at codec
decode time. The plaintext bucket codec and client Path ORAM access also reject
duplicate point tokens and duplicate payload fetch tokens before decrypted path
blocks can be absorbed into the stash, leaving the client state unchanged on
that malformed-path boundary.
`plan_private_hnsw_oram_directional_neighbor_filter` is an experimental
client-local helper for Compass-style directional neighbor filtering: given the
current node block, decrypted neighbor blocks, and the query vector, it keeps
only neighbor nodes that move in the query direction and ranks them by
client-side distance before the SDK chooses which padded ORAM paths to request.
`plan_private_hnsw_oram_graph_traversal_path_batch` composes that filter with
the client position map and speculative prefetch padding to produce a fixed-size
`read_paths` label batch for graph-traversal tailored ORAM experiments. The
`*_with_stats` variant keeps the same padded labels while also reporting how
many directional neighbors survived before missing position-map entries were
dropped, so SDK benchmarks can separate graph-filter selectivity from ORAM path
volume.

Client state is mandatory backup material for this provider. Qdrant snapshots
contain encrypted buckets, manifest, and epoch/root metadata, but not the ORAM
position map or stash. SDKs should persist `PrivateHnswOramClientStateSnapshot`
from `PrivateHnswOramClientState::to_snapshot` alongside their RK/signing-key
backup and restore it with `PrivateHnswOramClientState::from_snapshot` before
opening sessions against a pinned epoch/root. For encrypted local backups,
`seal_private_hnsw_oram_client_state_snapshot` uses the RK-derived
position-map subkey, rejects malformed position map/stash snapshots before
producing ciphertext, rejects duplicate position/stash entries, duplicate stash
point/payload fetch tokens, malformed leaf labels, and malformed stash node
blocks, vector bytes, neighbor shapes, level masks, or stash map-key/node-id
mismatches at snapshot export/import, and
binds the ciphertext to collection id,
vector name, RK id/epoch, index epoch, and root hash after rejecting malformed
collection AAD context identifiers, path-like vector names, and client-state
alias vector names. The same vector-name shape is enforced for HNSW bucket AEAD
contexts, manifest-build contexts, read-path signature contexts, and
commit-signature contexts;
`open_private_hnsw_oram_client_state_snapshot` bounds the encoded ciphertext
length and validates the ciphertext hash shape before decode, then rejects hash
tamper or epoch/root context mismatch before returning the snapshot. The
encrypted backup DTO does not serialize plaintext position-map entries, leaf
labels, stash blocks, point tokens, or payload fetch tokens outside the AEAD
ciphertext.
New SDK code should derive `PrivateHnswClientKeys` from the signed manifest
rather than the deprecated legacy domain-only helper. The manifest-bound derivation
length-prefixes collection id, vector name, RK id, and RK epoch into the HKDF
info context before deriving node, bucket, position-map, payload-token, and
blind-result subkeys, so accidental RK reuse across private HNSW indexes does
not produce the same client subkeys. The crypto-crate bucket/search fixtures and
the collection-store and REST/gRPC route fixtures now build their SDK-sealed
private HNSW buckets with the same context-bound derivation path.

The client CKKS vector sidecar signature message is canonical and
length-prefixed for SDK interop. The byte string is:

1. 4-byte big-endian length + ASCII domain
   `qdrant-sec/client-ckks-vector-signature/v1`.
2. 1-byte `version`.
3. For each UTF-8 field below, a 4-byte big-endian length followed by field
   bytes: `scheme`, `security_profile`, `collection_id`, `point_id`,
   `vector_name`, `key_id`, `rk_id`, `context_digest`, `ciphertext_sha256`,
   `ciphertext`, `signature.alg`, `signature.key_id`.
4. 8-byte big-endian `rk_epoch` immediately after `rk_id`.
5. 8-byte big-endian `slots` immediately after `context_digest`.

The `sig` bytes themselves are not included in the signed message. Any change
to the sidecar routing metadata, key lineage, public context digest, slot count,
ciphertext hash, or ciphertext bytes invalidates the Ed25519 signature.
`docs/qdrant-sec-client-ckks-vector-signature-test-vector.json` freezes the
canonical signing bytes for SDK interop, and the server test suite verifies the
helper against that fixture.

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
      signature_public_key_b64: base64url-no-pad-ed25519-public-key
      signature_b64: base64url-no-pad-ed25519-signature-over-domain-and-sha256
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
        # Required for every vector/openfhe-ckks@v1 instance because the bridge
        # returns finite plaintext ranking scores to Qdrant, even when the query
        # vector itself is supplied as an encrypted CKKS envelope.
        score_plaintext_output_tcb_ack: qdrant-sec-ckks-score-output-tcb-v1
        allow_plaintext_queries: false
        signature_public_keys:
          tenant-a/query-signing-v1: base64url-no-pad-ed25519-public-key
        # Required only when allow_plaintext_queries is true.
        # plaintext_query_tcb_ack: qdrant-sec-ckks-plaintext-query-tcb-v1
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
the `env` token source instead. Non-loopback Vault URLs must also set
`expected_host` to the exact configured URL authority, including port when a
non-default port is used. Qdrant rejects the material before loading the Vault
token if `expected_host` is missing or does not match, so a config drift cannot
silently redirect Vault credentials or RK material to an attacker-controlled
host. Vault material fetches do not follow HTTP redirects; redirects must be
resolved in the configured, validated URL.
Vault-backed material keeps the MK/RK out of config files, but the Vault token
source, Vault policy, and Vault availability become part of the key-management
TCB and must be identical across nodes that can write encrypted collections.
Vault KV v2, AWS KMS, and Vault Transit materials may set `timeout_ms` between
`1` and `30000`; when omitted, Qdrant uses a 5000 ms HTTP timeout and never
follows redirects. This keeps resource-key lifecycle endpoints bounded even
when an external key provider is slow.
External key-provider materials may also set non-secret
`provider_key_version` and `provider_attestation_id` identifiers. These values
are not key material and are safe to expose in sanitized config views, but they
are included in the crypto runtime capability fingerprint so mixed KMS/Vault
key versions, attestation policies, or rollout cohorts fail closed before
encrypted writes, shard transfer, or restore use the wrong provider state.
When a wrapping material uses `source: aws_kms`, it must be
`kind: wrapping_key_32`, `path` must be the AWS KMS key id, alias, or ARN, and
`env` must be an environment-variable prefix. Qdrant reads
`${env}_ACCESS_KEY_ID`, `${env}_SECRET_ACCESS_KEY`, `${env}_REGION`, optional
`${env}_SESSION_TOKEN`, and optional `${env}_ENDPOINT_URL`. The endpoint
defaults to `https://kms.${region}.amazonaws.com/`; custom endpoints must use
HTTPS except loopback HTTP for tests/dev and must not include credentials, path,
query, or fragment components. Remote custom endpoints require `expected_host`
and the endpoint authority must match it exactly. If `expected_host` is set for
the default AWS endpoint, the computed `kms.${region}.amazonaws.com` authority
must also match. Qdrant signs AWS KMS `Encrypt`/`Decrypt`
requests with SigV4, sends RK plaintext only inside those KMS calls, records
`wrapped_symmetric_key_32.wrap_algorithm: aws-kms`, and stores the returned KMS
ciphertext blob as `wrapped_key_b64`. AWS KMS material is only valid for
MK/KEK wrapping; it cannot be used as a direct server-side payload/vector RK
source.
When a wrapping material uses `source: vault_transit`, it must be
`kind: wrapping_key_32`, and `path` must be the Vault Transit key metadata URL,
for example `/v1/<mount>/transit/keys/<key>`. qdrant-sec derives the
corresponding `/encrypt/<key>` and `/decrypt/<key>` endpoints and sends the RK
plaintext only to Vault Transit for wrap/unwrap. The config never contains the
MK bytes, and `wrapped_symmetric_key_32.wrap_algorithm` becomes
`vault-transit`. As with Vault KV v2, the URL must use HTTPS except loopback
HTTP for tests/dev, credentials/query/fragment components are rejected, and
`env` must name the Vault token environment variable. Non-loopback Vault
Transit URLs require `expected_host` with the exact URL authority for the same
host-pinning reason as Vault KV v2. Vault Transit material is only valid for
MK/KEK wrapping; it cannot be used as a direct server-side payload/vector RK
source.
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
Operators can generate a fresh random RK for RK rotation through the manage-only
`POST /crypto/resource-keys/generate` endpoint:

```json
{
  "material": "tenant-a/payload-rk-v4",
  "wrapped_by": "tenant-a/mk-v2",
  "rk_epoch": 4,
  "scope": "collection:docs/payload:body"
}
```

The endpoint returns a config patch for one new `wrapped_symmetric_key_32`
material with `state=active`; it does not mutate runtime settings or collection
config. Operators must apply the patch, update the provider's active
`materials.sym_key`, move the old RK into `options.retired_materials`, and then
run the payload/vector migration before disabling or destroying the old RK.

Operators can expose the MK rotation primitive through the manage-only
`POST /crypto/resource-keys/rewrap` endpoint:

```json
{
  "old_wrapped_by": "tenant-a/mk-v1",
  "new_wrapped_by": "tenant-a/mk-v2",
  "dry_run": false
}
```

The endpoint does not mutate in-memory settings or collection config. It returns
a config patch containing only the rewrapped `wrapped_symmetric_key_32` material
records that should be applied to the deployment config or external secret
backend. This keeps MK rotation scoped to O(number of wrapped RKs) and avoids
rewriting payload/vector data envelopes. The `old_wrapped_by` and
`new_wrapped_by` values are validated as crypto material identifiers before any
runtime lookup, and they must reference different `wrapping_key_32` materials.
Set `dry_run: true` to return only the target material count and estimated
external provider call count; dry-run never unwraps or rewraps RK material and
never returns secret-bearing patch fields.
The old and new MK material must both be available in the current runtime during
the rewrap, and operators should roll out the resulting material patch
atomically across nodes so runtime parity fingerprints stay aligned.

Operators can inspect the non-secret collection crypto manifest before and after
rotation:

```text
GET /collections/{collection_name}/crypto/manifest
```

The endpoint is manage-only and first revalidates the collection config against
the current runtime crypto settings. It returns the stable collection crypto id,
schema/epoch/state, each rule's provider and binding, active material references,
retired material references, and client-side RK policy. It does not return
`value_b64`, `wrapped_key_b64`, nonces, signatures, or public material. If a
runtime material referenced by the collection is missing RK epoch metadata or no
longer satisfies the provider policy, manifest generation fails closed instead
of reporting a stale or incomplete key lifecycle view.

After an RK rotation migration has been verified and the runtime provider no
longer references the old RK in either `materials.sym_key` or
`options.retired_materials`, operators can request a non-mutating retirement
patch:

```json
POST /crypto/resource-keys/retire
{
  "materials": ["tenant-a/payload-rk-v3"],
  "target_state": "disabled"
}
```

`target_state` is currently limited to `disabled`. The endpoint rejects active
RKs and any retired RK that is still referenced by a runtime crypto instance. A
`disabled` patch preserves wrapped key material for a future explicit rollback
or enable operation. `destroyed` retirement is intentionally rejected until it is
bound to a persisted, non-dry-run migration completion proof; shredding wrapped
RK material based only on runtime-reference cleanup can permanently orphan old
envelopes.

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
Collection snapshot creation requires encrypted collections to be in
`migration_state=active`; snapshots taken while encryption, rotation, or
decryption migration is in flight are rejected because those archives cannot be
restored without a future verified migration recovery manifest.

Snapshot download and shard snapshot streaming APIs are storage-level exports.
They only support raw encrypted marker export. `encrypted_payload=raw` is accepted
as an explicit no-op, while `encrypted_payload=decrypted` and
`encrypted_payload=redacted` fail during query parsing. Decrypted or redacted data
export must use the audited payload export endpoint instead of snapshot archive
streams:

```text
POST /collections/{collection_name}/points/export?encrypted_payload=raw
POST /collections/{collection_name}/points/export?encrypted_payload=redacted
POST /collections/{collection_name}/points/export?encrypted_payload=decrypted
```

The endpoint accepts the usual scroll body for pagination and filtering, but it
overrides `with_payload` with the explicit encrypted payload policy from the
query string and rejects `with_vector`. `decrypted` export requires the same
collection-scoped `payload_decrypt` capability as decrypted reads and emits a
separate audit method (`export_decrypted_payload`) before the underlying scroll.
Client-side `$qdrant_client_aead` envelopes still cannot be decrypted by
Qdrant; use `raw` or `redacted` for those collections.

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
        score_plaintext_output_tcb_ack: qdrant-sec-ckks-score-output-tcb-v1
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
      kind: process_pool_landlock_netns
      program: /usr/local/bin/openfhe-bridge
      sha256_b64: base64url-no-pad-sha256-of-bridge
```

Generic OpenFHE backends currently accept `process`, `process_pool`, and on
Linux the Landlock-enforcing `process_landlock` / `process_pool_landlock`
variants. Linux also supports
`process_landlock_netns` / `process_pool_landlock_netns`, which add a bridge
child network-namespace split before `exec` for deployments that can run the
bridge without host network access. Any other backend `kind` is rejected during
runtime settings validation.
On Linux, Qdrant sets `no_new_privs`, a parent-death `SIGKILL`, `RLIMIT_CORE=0`,
and, for checked bridge binaries, `RLIMIT_FSIZE=0` immediately before spawning
the configured bridge process. This is not a complete sandbox, but it prevents
privilege gain through setuid binaries or file capabilities, reduces orphaned
plaintext-bearing bridge exposure, disables normal core dumps, and prevents the
checked bridge from writing regular files after bridge path, ownership, mode,
parent directory, and optional SHA-256 pin checks have passed. Treat these
settings as pre-exec process hardening. The Landlock variants additionally
install a write-deny Landlock ruleset in the bridge child before `exec`, blocking
regular file writes, file creation, removal, rename/link, and truncation
operations for kernels that support the configured Landlock ABI. Production
deployments that need Qdrant-managed network egress isolation can select the
`*_landlock_netns` variants; bridge startup then fails closed if the host denies
network namespace creation. These sandbox and egress policy labels are included
in the crypto runtime capability fingerprint, so mixed cluster policies fail
parity checks. Deployments that need broader confinement should still run the
bridge under an external seccomp/AppArmor/container profile. See
[`openfhe-bridge-sandbox.md`](openfhe-bridge-sandbox.md) for a hardened
deployment checklist and starter AppArmor/seccomp examples.

Server-side inference is also a plaintext boundary. If clients submit
`Document`, `Image`, or `Object` vectors for encrypted vector names, Qdrant must
embed that input before CKKS encryption or search scoring. The remote inference
HTTP client does not follow redirects, and request-provided `*-api-key` headers
are forwarded only when their exact header names are listed in
`inference.allowed_api_key_headers`. Remote inference URLs must use HTTPS unless
they target loopback HTTP for local development. Non-loopback endpoints must set
`inference.expected_host` to the exact configured URL authority, including port
when present; Qdrant rejects the endpoint before sending inference input or
forwarding tokens if the URL host drifts. Leave `allowed_api_key_headers` empty
for zero-trust deployments and require clients to submit dense vectors or
client-encrypted CKKS query envelopes produced outside Qdrant.

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
Runtime payload code must use the resource-key constructors so this derivation
is centralized. The `PayloadTextEncryptor::new_with_derived_*_unchecked`
constructors are safe-Rust fixture and compatibility escape hatches for ciphers
or keyrings that have already been domain-separated; `unchecked` is a
cryptographic provenance warning, not a Rust `unsafe` contract.
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
The REST control plane is split into two admin-only steps:

```text
POST /collections/{collection_name}/crypto/migration/plan
POST /collections/{collection_name}/crypto/migration/run-payloads
```

Use `plan` to start `Disabled -> Encrypting`, `Active -> Rotating`, or
`Active -> Decrypting`. `run-payloads` is the only public payload rewrite entry
point: it combines the server-side payload rewrite/decrypt scan with completion
plan construction and submission. The request must name the active RK id and,
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
payload changes and does not apply the completion transition.
`CryptoMigrationCheckpoint` values represent shard coverage, not only bytes
changed: rerunning a migration over already-current payloads still returns
`rewritten_points == total_points` so the checkpoint can close the migration
safely. The separate `changed_points` counter reports how many payload records
actually changed on that run, so operators can distinguish first-pass rewrites
from idempotent verification reruns. Client-side `$qdrant_client_aead`
envelopes are store-only and cannot be decrypted by Qdrant, so decrypt
migration rejects collections that still bind a client-side payload provider.
This is still a foreground admin operation, not a cluster-wide background
scheduler; interrupted or failed runs should be rerun to produce fresh
checkpoints. The older standalone rewrite/decrypt endpoints were intentionally
removed so operators cannot mutate payload bytes without also validating and
submitting the matching completion plan.
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
When `crypto.zero_trust_profile: strict` is enabled, `decrypted` read mode is
disabled entirely; strict zero-trust deployments must return raw/redacted
envelopes and decrypt in the client SDK.
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

Decrypted snapshot export remains unsupported; REST access logs and denied-auth
audit paths template-redact private ORAM session ids and redact private ORAM
query strings and unexpected private ORAM endpoint tail segments. Slow request
logs and request hashes use redacted request values, including private HNSW ORAM
path/read/access traversal labels, entry and visited node ids, level masks,
neighbor/candidate aliases, query vector/embedding/plaintext aliases,
score/distance aliases, candidate heaps, candidate and node score/distance
aliases, request/commit/read/manifest signatures, private result ORAM bucket
ids, session ids, bucket commitments, leaf commitments, read bucket ids, bucket
id sequences, updated bucket writebacks, access-volume count aliases,
client-state/client-states, ciphertext/hash/sha256 fields, and payload/result
tokens; snake_case and camelCase singular/plural aliases are covered for private
ORAM access-pattern, bucket, commitment, signature, query, candidate,
score/distance, client-state, and token fields.
REST access-log and JSON-validation sanitizers recognize private ORAM markers
only at the route position after `/collections/{collection}`; ordinary
collections named `private-hnsw` or `private-result-oram` keep normal access-log
query strings and validation errors.
Collection telemetry has sentinel coverage so decrypted plaintext is not
intentionally emitted there, and app telemetry serializes only the runtime
capability fingerprint rather than private ORAM key ids, verifier key ids, or
`signature_public_keys` registry entries. Panic telemetry, health-check panic
messages, gRPC status logging, and denied-auth audit errors apply the same
redaction helper before serialization; they redact qdrant-sec envelope markers,
secret-like crypto fields, private ORAM owner/signing key id aliases,
signature-public-key registry aliases, and private ORAM path/root/bucket/node,
query vector/embedding/plaintext, score/distance, candidate/node score,
candidate/node distance, token, client-state ciphertext/hash/sha256, proof, and access-volume
count/length aliases. REST private ORAM wire DTO `Debug` wrappers also redact
upload/read bucket counts alongside roots, ciphertext bodies, commitments, and
signatures, and SDK private ORAM upload bundle debug output redacts upload
bucket counts. SDK private HNSW search access metrics redact path/leaf/fixed
step counts and budget-exhaustion state. Common private ORAM session debug output
redacts bucket counts, tree height, path-batch size, and derived ciphertext byte
budgets, and it does not render the embedded manifest. SDK private HNSW
node/search/build debug output also redacts deleted/generation state,
payload-token presence, build-point vector lengths, build bucket counts, Merkle
proof bucket counts, encrypted bucket-batch bucket counts, and manifest-build
HNSW/ORAM/fixed-budget policy internals. Private result ORAM SDK debug output
applies the same client-state tree-height and bucket-count redaction to client
configs, Merkle proofs, encrypted bucket batches, and read-signature inputs.
Collection-local private ORAM store debug output also redacts Merkle tree/proof
bucket counts.
Private HNSW ORAM commit errors use a fixed writeback-budget message and do not
reflect the concrete max writeback bucket count.
Private result ORAM commit errors follow the same rule for fixed writeback
budget failures.
Private result ORAM bucket validation contexts redact expected epochs, bucket
counts, and ciphertext size limits. Audit events never include request bodies.
Prometheus request metrics may include fixed REST/gRPC endpoint labels and the
collection label for private ORAM manifest, session, read, and commit APIs, but
they do not include path labels, bucket ids, session ids, ciphertext bodies, or
client-state fields, including `*_ciphertext_sha256` client-state aliases. The OpenAPI and gRPC consistency gates pin the private
ORAM REST method/path/operation ids and generated gRPC method paths using exact
route-shape matching. Metrics canonicalization strips query strings only for
otherwise fixed routes and drops malformed/lookalike or extra-tail private ORAM
paths, so these metrics labels cannot silently drift away from the published
API surface. gRPC private HNSW/result ORAM services use the same collection
telemetry wrapper as other collection-scoped services, but the wrapper attaches
only `collection_name` and not vector names, session ids, path labels, bucket
ids, roots, ciphertext, client-state fields, or `*_ciphertext_sha256` aliases.
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
| HNSW graph and quantization | CKKS ciphertext vectors are searched through sidecar ciphertext scoring, not through plaintext dense vector storage. | REST/gRPC nearest-neighbor search can score stored CKKS ciphertext envelopes through the OpenFHE bridge using the collection distance metric. `hnsw_ef` uses existing segment-native or persisted CKKS ciphertext graph artifacts; exact and non-HNSW requests use brute force. Query-time foreground graph build is disabled so cache misses fail fast instead of performing O(n²) stored-ciphertext scoring. Segment optimization counts encrypted sidecar bytes, assigns immutable `CkksCiphertextHnsw` segment index artifacts, and persists their private graph files instead of plaintext HNSW, mmap conversion, or quantization. Persisted graphs must be private, owned by root or the Qdrant process user, stored under a trusted parent directory chain, reciprocal, and connected. Raw-dense recommend and raw-dense discover use the same encrypted-query sidecar scoring path but remain brute-force. Quantization remains unsupported for encrypted vectors, and collection validation rejects per-vector or collection-level quantization configs for encrypted vector names. | Broaden distributed rebuild/recovery coverage before treating it as a production-grade segment-native ciphertext index. |
| Snapshots | Snapshot archives should contain encrypted payload/vector envelopes and enough metadata to preflight required keys/context and stable collection identity. | Payload sentinel leakage scan now creates and scans a collection snapshot archive. Collection snapshot creation rejects encrypted configs whose migration state is not `active`. Collection, shard, and CLI startup snapshot recover paths preflight runtime crypto settings for missing instance/material/backend, wrong wrapped-RK key, provider key-id mismatch, missing encrypted collection UUID, UUID mismatch, non-active migration state, and invalid CKKS public material. Valid-but-different CKKS public-material drift is covered by peer runtime parity and sidecar `context_digest` open/score checks. | Broaden restore coverage across cluster paths and add full archive-level sidecar scan coverage if restore starts validating stored sidecars before load. |
| Shard transfer and replication | Sender and receiver must have matching crypto runtime material and CKKS context. | App telemetry, peer metadata, and distributed telemetry expose a non-secret crypto runtime capability fingerprint. Encrypted collection data-movement operations validate involved peer metadata and fail closed on missing or mismatched fingerprints. Automatic dead-replica recovery skips source peers without matching parity metadata. `/readyz` does not mark the node ready for encrypted collections while peer metadata fingerprints are missing or mismatched. | Broaden distributed integration coverage and cluster-wide parity tests. |
| Telemetry, logs, and audit | No plaintext payload bodies, embeddings, ciphertext blobs, signatures, wrapping keys, verifier public-key bodies, or runtime key material should be emitted. | Bridge request bodies and stderr are not included in returned errors. Collection telemetry and slow-request log-value/request-hash smoke tests cover payload/vector/filter/query sentinels, crypto envelope fields, plural batch fields, and camel/kebab-case secret field spellings. Audit events do not include request bodies, and denied audit error strings redact qdrant-sec envelope markers plus secret-like crypto fields. App telemetry exposes only a non-secret crypto runtime capability fingerprint and regression tests assert inline/wrapped key material plus client-envelope/private-ORAM verifier key options are not serialized. | Broaden audit/log capture coverage around any new request logging surfaces. |

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
CKKS parameters are restricted through the crypto crate's allowlisted profile
registry, which currently contains only `ckks-128-n16384-d4-scale50` in this
branch. Generic
`vector/openfhe-ckks@v1` runtime instances must set this `profile` option plus
`crypto_context_b64`, `public_key_b64`, and
`score_plaintext_output_tcb_ack: qdrant-sec-ckks-score-output-tcb-v1`; a
missing profile, missing public material, missing score-output TCB
acknowledgement, or raw profile name is rejected before collection creation.
`batch_size` may be lower than the profile slot count, but raw
modulus/depth/scale combinations are rejected. OpenFHE bridge encrypt, batch
encrypt, and scoring responses must include `security_profile`; Qdrant verifies
that it matches the requested allowlisted profile. Responses may also include
`security_level_bits` and `noise_budget_bits`; when present, Qdrant rejects
reported security below 128 bits and rejects non-finite or negative noise budget
metadata.

Nearest-neighbor search over an encrypted vector name is implemented for
client-encrypted CKKS query envelopes and root direct point-id nearest `query`
or `query/groups` requests when runtime `crypto` settings are available on the
serving node. Raw dense REST/gRPC query vectors are rejected by default for
`vector/openfhe-ckks@v1`; setting `allow_plaintext_queries: true` also requires
`plaintext_query_tcb_ack: qdrant-sec-ckks-plaintext-query-tcb-v1`. This explicit
acknowledgement opts into a server-side query plaintext TCB for client-supplied
numeric dense vectors. Query vectors produced by Qdrant inference (`document`,
`image`, or `object` inputs) remain rejected for encrypted vector names because
they would send client plaintext to the inference service before CKKS scoring.
In the raw dense opt-in mode, Qdrant scrolls the encrypted sidecar payloads,
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
    "collection_id": "collection-stable-crypto-id",
    "vector_name": "text",
    "key_id": "tenant-a:vector",
    "rk_id": "tenant-a/vector-v1",
    "rk_epoch": 3,
    "query_nonce": "base64url-no-pad-96-bit-query-nonce",
    "context_digest": "...",
    "slots": 1536,
    "ciphertext_sha256": "base64url-no-pad-sha256-of-ciphertext",
    "ciphertext": "...",
    "signature": {
      "alg": "ed25519",
      "key_id": "tenant-a/query-signing-v1",
      "sig": "base64url-no-pad-ed25519-signature"
    }
  }
}
```

The `collection_id`, `vector_name`, `key_id`, `rk_id`, and `rk_epoch` fields must
match the active encrypted vector rule's stable collection crypto identity and
resource-key lineage. `query_nonce` is mandatory 96-bit base64url-no-padding
client randomness and is cryptographically bound into the query signature; SDKs
must regenerate it when retrying a request body. Qdrant also records
`collection_id`, `vector_name`, `key_id`, `rk_id`, `rk_epoch`, and
`query_nonce` in a bounded process-local TTL replay cache before bridge scoring,
rejecting recent replays with an error that instructs clients to create a fresh
envelope. The signer key is still validated and included in non-secret warning
metadata, but it is not part of the freshness key; the same CKKS resource-key
lineage cannot reuse a query nonce by switching signers. This is a replay guard,
not a cluster-wide ledger. When `cluster.enabled=true`, client-supplied CKKS
encrypted query envelopes fail closed until a consensus-backed query nonce
ledger exists, so local replay caches are not silently treated as a distributed
freshness guarantee. The
`context_digest` must match the active OpenFHE public material and CKKS parameter profile for that rule,
`slots` must match each stored sidecar envelope being scored,
`ciphertext_sha256` must match the decoded ciphertext bytes, and `ciphertext` is
base64url without padding. The `signature` object is mandatory for
client-supplied encrypted query envelopes: `alg` must be `ed25519`, `key_id`
must select a configured `signature_public_keys` entry on the active
`vector/openfhe-ckks@v1` runtime instance, and `sig` must verify the
domain-separated query metadata, query nonce, and ciphertext under
`qdrant-sec/client-ckks-query-signature/v1`. gRPC carries the same proof through
`query_nonce`, `signature_alg`, `signature_key_id`, and `signature_b64`.
Qdrant does not decrypt or validate the CKKS ciphertext itself; it treats the
validated bytes as the encrypted query input to the OpenFHE bridge scoring API.

The client CKKS query signature message is canonical and length-prefixed so SDKs
can produce interoperable envelopes. The byte string is:

1. ASCII domain `qdrant-sec/client-ckks-query-signature/v1\0`.
2. For each UTF-8 field below, an 8-byte big-endian length followed by the field
   bytes: `version`, `scheme`, `security_profile`, `collection_id`,
   `vector_name`, `key_id`, `rk_id`, `rk_epoch`, `query_nonce`,
   `context_digest`, `slots`, `ciphertext_sha256`, `signature.alg`,
   `signature.key_id`.
3. An 8-byte big-endian length followed by the decoded CKKS query ciphertext
   bytes.

For the current profile the first fields are `version=1`,
`scheme=openfhe-ckks`, and
`security_profile=ckks-128-n16384-d4-scale50`. `ciphertext_sha256` is the
base64url-no-padding SHA-256 digest of the decoded ciphertext bytes and is
signed before the ciphertext bytes themselves are appended. Any field ordering
change, missing field, stale `query_nonce`, wrong `rk_epoch`, or changed
ciphertext bytes invalidates the Ed25519 signature.
`docs/ckks-client-query-signature-test-vector.json` contains a known-answer
fixture for SDKs and is checked by the server unit tests.

Result ordering and
`score_threshold` follow the configured Qdrant distance metric:
`dot`/`cosine` are larger-is-better, while `euclid`/`manhattan` are
smaller-is-better. If `hnsw_ef` is set and `exact=false`, nearest-neighbor
search uses a ciphertext sidecar candidate graph with encrypted-query bridge
scoring for traversal candidates. Query-time foreground graph construction is
disabled: if no segment-native or persisted graph is available for the requested
sidecar set, the request fails fast and callers must retry without `hnsw_ef` or
rebuild the encrypted vector index. Stored point-id nearest `query`/`query/groups`
requests also use the sidecar graph when `hnsw_ef` is provided, scoring
traversal candidates against the referenced point's stored ciphertext. Segment
optimization counts CKKS vector sidecar
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
the stored ciphertext sidecars, so rename/recreate boundaries and payload/vector
changes do not reuse stale links. The in-memory cache is an acceleration for the
current serving process, and Qdrant may load pre-existing persisted graph hints
under the collection directory. Persisted graph cache files are treated as
untrusted hints:
the cache directory must be a private non-symlink directory owned by root or the
Qdrant process user, every non-sticky parent directory in the path must be
owned by root or the Qdrant process user and not group/world-writable, cache
files and stale temp files must be private regular files owned by root or the
Qdrant process user, oversized files are rejected, and metadata/fingerprint
mismatches or disconnected/non-reciprocal graphs are ignored. Qdrant does not
build a replacement collection-level graph on the read path because that would
require foreground pairwise CKKS scoring. Trusted sticky ancestors such as `/tmp`
are allowed only above the private cache directory so test and temp deployments
can still use standard temporary roots. Query execution does not write new
collection-level persisted graphs or prune cache files. It is still not the
plaintext-vector
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
the request body or bridge stderr. Process-pool backends also fail fast when
all configured workers are already busy, rather than queuing additional
plaintext-bearing bridge requests behind a busy worker.

The OpenFHE bridge is part of the trusted computing base because it receives
plaintext embeddings before producing CKKS ciphertext and returns finite
plaintext ranking scores to Qdrant for CKKS sidecar search. Encrypted query
envelopes keep query vectors out of Qdrant's numeric request body, but they do
not make vector ranking server-blind: the bridge and Qdrant still learn score
ordering and returned score values. Runtime configuration
therefore accepts only absolute bridge paths that resolve to executable regular
files, rejects symlinks and group/world-writable binaries or parent directories
on Unix, and requires the binary plus every parent directory to be owned by root
or the Qdrant process user. Generic process backends must set `sha256_b64` to
pin the expected bridge binary digest; generic runtime validation and checked
backend construction both hash the bridge through a no-follow file descriptor
on Unix. Operators can additionally set `signature_public_key_b64` and
`signature_b64` to require an Ed25519 signature over the domain-separated
bridge digest (`qdrant-sec/openfhe-bridge-binary-signature/v1 || sha256`).
The signature fields must be configured together, are included in the runtime
capability fingerprint, and therefore participate in cluster parity checks.
On Linux, checked bridge workers are spawned through a
`/proc/self/fd/<fd>` path backed by the same no-follow validated bridge file
descriptor held open through `spawn`, which narrows the path-swap window between
validation, hashing, and execution.
On non-Linux platforms, checked OpenFHE bridge construction fails closed because
qdrant-sec cannot provide the Linux fd-backed exec mitigation. Deployments that
need the trusted OpenFHE bridge must run that provider on Linux; strict
zero-trust deployments should use the client-led private HNSW ORAM provider
instead of a trusted bridge.
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
If the backend kind is `process_landlock_netns` or
`process_pool_landlock_netns`, Qdrant also asks Linux to place the bridge child
in a fresh network namespace before `exec`. This is the only Qdrant-managed
bridge egress-deny mode; plain `process_*` and `process_*_landlock` kinds keep
the host network namespace and rely on external firewall, AppArmor, seccomp, or
container policy for network confinement.

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
