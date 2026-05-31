//! Encryption and crypto control-plane primitives for qdrant-sec.
//!
//! This crate intentionally keeps cryptographic boundaries outside the hot vector
//! storage path until the OpenFHE backend is configured. The types here are
//! serializable and testable without linking OpenFHE into every Qdrant build.

pub mod aead;
pub mod control_plane;
pub mod openfhe;
pub mod payload;
pub mod private_hnsw_client;
pub mod private_hnsw_oram;
pub mod vector;

pub use aead::{
    AeadCipher, AeadKeyring, CKKS_VECTOR_KEY_DOMAIN, EncryptedEnvelope, EncryptionContext,
    EncryptionError, EncryptionPurpose, LOCAL_RESOURCE_KEY_WRAP_CIPHERTEXT_B64_LEN,
    LOCAL_RESOURCE_KEY_WRAP_CIPHERTEXT_LEN, LocalMasterKeyProvider, METADATA_VALUE_KEY_DOMAIN,
    MasterKeyProvider, PAYLOAD_TEXT_KEY_DOMAIN, RESOURCE_KEY_WRAP_ALGORITHM, SecretKey,
    WrappedKeyBlob, rewrap_resource_key,
};
pub use control_plane::{
    CLIENT_PAYLOAD_ENVELOPE_BINDING, CiphertextEnvelope, CompiledCollectionCryptoPlan,
    CompiledMetadataRule, CompiledPayloadRule, CompiledVectorRule, ControlPlaneError,
    CryptoCapability, CryptoRegistry, CryptoSuite, GENERIC_CIPHERTEXT_MARKER,
    METADATA_AES_GCM_PROVIDER, METADATA_BLIND_INDEX_PROVIDER, METADATA_EXACT_MATCH_TOKEN_BINDING,
    METADATA_VALUE_BINDING, MetadataProviderFactory, PAYLOAD_AES_GCM_PROVIDER,
    PAYLOAD_CLIENT_AEAD_PROVIDER, PAYLOAD_FIELD_BINDING, PRIVATE_HNSW_ORAM_BINDING,
    PayloadProviderFactory, VECTOR_CLIENT_CKKS_PROVIDER, VECTOR_ENVELOPE_BINDING,
    VECTOR_OPENFHE_CKKS_PROVIDER, VECTOR_PRIVATE_HNSW_ORAM_PROVIDER, VectorProviderFactory,
};
pub use openfhe::CommandOpenFheBackend;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use openfhe::linux_landlock_write_deny_supported_for_tests;
pub use payload::{
    CLIENT_ENCRYPTED_PAYLOAD_MARKER, ClientPayloadEnvelopeKey, ClientPayloadNonceReplayKey,
    ClientPayloadSignatureVerification, ClientPayloadValidationContext,
    ClientPayloadVerifiedEnvelopeKey, ENCRYPTED_PAYLOAD_MARKER, ExistingPayloadMode,
    METADATA_VALUE_ENVELOPE_KIND, PAYLOAD_TEXT_ENVELOPE_KIND, PayloadEncryptionError,
    PayloadEncryptionPolicy, PayloadTextEncryptor, ServerPayloadEnvelopeKey,
    ServerPayloadValidationContext, ServerPayloadVerifiedEnvelopeKey, client_payload_envelope_key,
    client_payload_nonce_replay_key, client_payload_signature_key_id,
    client_payload_signature_message, is_client_encrypted_payload_value,
    is_encrypted_payload_value, server_payload_envelope_key, validate_client_payload_value,
    validate_client_payload_value_after_runtime_verification,
    validate_client_payload_value_for_peer_replay, validate_client_payload_value_for_runtime,
    validate_server_payload_value_after_runtime_encryption,
    validate_server_payload_value_for_peer_replay, validate_server_payload_value_metadata,
};
pub use private_hnsw_client::{
    PRIVATE_HNSW_BLIND_RESULT_DOMAIN, PRIVATE_HNSW_BUCKET_AEAD_DOMAIN,
    PRIVATE_HNSW_NODE_AEAD_DOMAIN, PRIVATE_HNSW_ORAM_MERKLE_PROOF_KIND,
    PRIVATE_HNSW_PAYLOAD_TOKEN_DOMAIN, PRIVATE_HNSW_POSITION_MAP_DOMAIN,
    PrivateHnswBucketAeadBaseContext, PrivateHnswBucketAeadContext, PrivateHnswBuildPoint,
    PrivateHnswClientCommitBucketRef, PrivateHnswClientCommitPlan, PrivateHnswClientError,
    PrivateHnswClientKeys, PrivateHnswClientNodeCache, PrivateHnswClientStateAeadContext,
    PrivateHnswCommitSignatureContext, PrivateHnswEncryptedClientStateSnapshot,
    PrivateHnswEncryptedIndexBuild, PrivateHnswEncryptedPathBatch, PrivateHnswManifestBuildContext,
    PrivateHnswMerkleSiblingPosition, PrivateHnswNodeBlockPlaintext, PrivateHnswOramAccessResult,
    PrivateHnswOramClientConfig, PrivateHnswOramClientState, PrivateHnswOramClientStateSnapshot,
    PrivateHnswOramMerkleProof, PrivateHnswOramMerkleProofLeaf, PrivateHnswOramMerkleSibling,
    PrivateHnswOramPlaintextBucket, PrivateHnswOramUploadBundle, PrivateHnswPlaintextIndexBuild,
    PrivateHnswPositionMapSnapshotEntry, PrivateHnswSearchHit, PrivateHnswSearchParams,
    PrivateHnswSearchResult, PrivateHnswSpeculativePrefetchPlan, PrivateHnswVectorEncoding,
    access_private_hnsw_oram_path, build_private_hnsw_oram_manifest_from_encrypted_index,
    build_private_hnsw_oram_plaintext_index_from_auto_layered_f32_points,
    build_private_hnsw_oram_plaintext_index_from_blocks,
    build_private_hnsw_oram_plaintext_index_from_f32_points,
    build_private_hnsw_oram_plaintext_index_from_layered_f32_points,
    decode_private_hnsw_node_block, decode_private_hnsw_oram_bucket_plaintext,
    decode_private_hnsw_oram_leaf_label, empty_private_hnsw_oram_plaintext_bucket,
    encode_private_hnsw_node_block, encode_private_hnsw_oram_bucket_plaintext,
    encode_private_hnsw_oram_leaf_label, open_private_hnsw_oram_bucket,
    open_private_hnsw_oram_client_state_snapshot, open_private_hnsw_oram_plaintext_bucket,
    open_private_hnsw_oram_verified_path_batch, package_private_hnsw_oram_upload_bundle,
    plan_private_hnsw_oram_commit, plan_private_hnsw_oram_neighbor_clustered_leaves,
    plan_private_hnsw_oram_speculative_prefetch, private_hnsw_bucket_commitment,
    private_hnsw_level_from_node_id, private_hnsw_node_reaches_level,
    private_hnsw_oram_bucket_count, private_hnsw_oram_bucket_ids_for_leaf,
    private_hnsw_oram_bucket_ids_for_leaf_labels, private_hnsw_oram_leaf_count,
    private_hnsw_oram_merkle_root_for_commitments, seal_private_hnsw_oram_bucket,
    seal_private_hnsw_oram_client_state_snapshot, seal_private_hnsw_oram_plaintext_bucket,
    seal_private_hnsw_oram_plaintext_index, search_private_hnsw_oram_encrypted,
    search_private_hnsw_oram_encrypted_verified,
    search_private_hnsw_oram_encrypted_verified_with_cache,
    search_private_hnsw_oram_encrypted_with_cache, search_private_hnsw_oram_plaintext,
    search_private_hnsw_oram_plaintext_with_cache, sign_private_hnsw_oram_commit,
    sign_private_hnsw_oram_manifest, verify_private_hnsw_oram_merkle_proof,
    verify_private_hnsw_oram_merkle_proof_json,
};
pub use private_hnsw_oram::{
    DistanceKind, FixedBudgetParams, OramKind, OramParams,
    PRIVATE_HNSW_ORAM_COMMIT_SIGNATURE_DOMAIN, PRIVATE_HNSW_ORAM_MANIFEST_SIGNATURE_DOMAIN,
    PrivateHnswEpoch, PrivateHnswManifestValidationContext, PrivateHnswOramBucket,
    PrivateHnswOramCommitBucketRef, PrivateHnswOramCommitSignatureInput, PrivateHnswOramError,
    PrivateHnswOramManifest, PrivateHnswOramSignature, PrivateHnswParams,
    PrivateHnswSignatureVerification, ResultPrivacyMode,
    private_hnsw_oram_commit_signature_message, private_hnsw_oram_manifest_signature_message,
    validate_private_hnsw_oram_commit_signature, validate_private_hnsw_oram_manifest,
    validate_private_hnsw_oram_manifest_shape, validate_private_hnsw_oram_manifest_signature,
    validate_private_hnsw_oram_manifest_signature_shape,
};
pub use vector::{
    CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CKKS_PUBLIC_MATERIAL_MAX_CRYPTO_CONTEXT_BYTES,
    CKKS_PUBLIC_MATERIAL_MAX_PUBLIC_KEY_BYTES, CKKS_SCHEME, CLIENT_CKKS_VECTOR_MARKER,
    CkksBatchEncryptionInput, CkksEncryptedQueryScoreBatchInput, CkksEncryptedQueryScoreBatchItem,
    CkksEncryptedQueryScoreInput, CkksEncryptionInput, CkksError, CkksParameters,
    CkksPlaintextQueryScoreBatchInput, CkksPlaintextQueryScoreInput, CkksPublicMaterial,
    CkksQueryEncryptionInput, CkksVectorBackend, CkksVectorBatchItem, CkksVectorEncryptor,
    CkksVectorSidecarDeleteTarget, CkksVectorSidecarEnvelopeKey,
    CkksVectorVerifiedSidecarDeleteKey, CkksVectorVerifiedSidecarKey,
    ClientCkksVectorSidecarEnvelopeKey, ClientCkksVectorSignatureVerification,
    ClientCkksVectorValidationContext, ClientCkksVectorVerifiedSidecarKey,
    ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector,
    VerifiedCkksVector, ckks_vector_sidecar_envelope_key, ckks_vector_verified_sidecar_delete_key,
    client_ckks_vector_sidecar_envelope_key, client_ckks_vector_signature_message,
    encrypted_ckks_vector_payload_value, is_client_ckks_vector_payload_value,
    is_encrypted_ckks_vector_payload_value, validate_client_ckks_vector_payload_value_for_runtime,
};
