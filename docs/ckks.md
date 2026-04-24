# qdrant-ckks encryption boundary

This branch adds a small `qdrant-ckks` workspace crate for encrypted payload text
and OpenFHE CKKS vector ciphertext envelopes.

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
      "nonce": "...",
      "ciphertext": "..."
    }
  }
}
```

The AEAD associated data binds ciphertexts to `collection`, `point_id`, and field
path. Moving a ciphertext to another point or field must fail authentication.

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

Runtime settings provide key material per collection. Prefer injecting keys
through environment variables such as
`QDRANT__CKKS__COLLECTIONS__docs__MASTER_KEY_B64` instead of committing them to
config files:

```yaml
ckks:
  enabled: true
  collections:
    docs:
      key_id: tenant-a:docs
      master_key_b64: base64url-no-pad-32-byte-key
      openfhe_bridge_path: /usr/local/bin/openfhe-bridge
```

If both collection params and the matching `ckks.collections.<name>` runtime
entry specify `key_id`, they must match. Otherwise the collection value wins,
then the collection runtime value, then the global default. This prevents
accidentally encrypting a collection with the wrong key.
The configured 32-byte master key is not used directly as an AEAD key. Qdrant
derives purpose-specific HKDF-SHA256 subkeys for payload text
(`qdrant/payload-text/v1`) and CKKS vector envelopes
(`qdrant/vector-envelope/v1`) before constructing AES-GCM ciphers.
When `ckks.enabled` is true, startup validates any configured key ids, master
keys, and OpenFHE bridge paths so bad runtime key material fails before the
first encrypted write.

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
files, rejects symlinks and world-writable binaries on Unix, and requires the
binary to be owned by root or the Qdrant process user. Treat any bridge path
change as privileged code execution under the Qdrant service account.

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
