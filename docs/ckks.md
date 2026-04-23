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

## CKKS vectors

`EncryptedCkksVector` stores OpenFHE CKKS ciphertext bytes, not plaintext
embeddings:

```json
{
  "version": 1,
  "scheme": "openfhe-ckks",
  "key_id": "tenant-a:ckks",
  "vector_name": "embedding",
  "slots": 3,
  "context_digest": "...",
  "ciphertext": "..."
}
```

The `context_digest` is a SHA-256 digest over the CKKS parameters, serialized
OpenFHE crypto context, and public key. It is intended to prevent mixing
ciphertexts created for incompatible contexts.

## OpenFHE bridge protocol

`CommandOpenFheBackend` invokes an external bridge binary. The bridge reads one
JSON request from stdin and writes one JSON response to stdout.

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
