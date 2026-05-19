//! Encryption and crypto control-plane primitives for qdrant-sec.
//!
//! This crate intentionally keeps cryptographic boundaries outside the hot vector
//! storage path until the OpenFHE backend is configured. The types here are
//! serializable and testable without linking OpenFHE into every Qdrant build.

pub mod aead;
pub mod control_plane;
pub mod openfhe;
pub mod payload;
pub mod vector;

pub use aead::{
    AeadCipher, AeadKeyring, CKKS_VECTOR_KEY_DOMAIN, EncryptedEnvelope, EncryptionContext,
    EncryptionError, EncryptionPurpose, LocalMasterKeyProvider, MasterKeyProvider,
    PAYLOAD_TEXT_KEY_DOMAIN, RESOURCE_KEY_WRAP_ALGORITHM, SecretKey, WrappedKeyBlob,
    rewrap_resource_key,
};
pub use control_plane::{
    CLIENT_PAYLOAD_ENVELOPE_BINDING, CiphertextEnvelope, CompiledCollectionCryptoPlan,
    CompiledMetadataRule, CompiledPayloadRule, CompiledVectorRule, ControlPlaneError,
    CryptoCapability, CryptoRegistry, CryptoSuite, GENERIC_CIPHERTEXT_MARKER,
    METADATA_AES_GCM_PROVIDER, METADATA_BLIND_INDEX_PROVIDER, METADATA_EXACT_MATCH_TOKEN_BINDING,
    METADATA_VALUE_BINDING, MetadataProviderFactory, PAYLOAD_AES_GCM_PROVIDER,
    PAYLOAD_CLIENT_AEAD_PROVIDER, PAYLOAD_FIELD_BINDING, PayloadProviderFactory,
    VECTOR_ENVELOPE_BINDING, VECTOR_OPENFHE_CKKS_PROVIDER, VectorProviderFactory,
};
pub use openfhe::CommandOpenFheBackend;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use openfhe::linux_landlock_write_deny_supported_for_tests;
pub use payload::{
    CLIENT_ENCRYPTED_PAYLOAD_MARKER, ClientPayloadEnvelopeKey, ClientPayloadNonceReplayKey,
    ClientPayloadSignatureVerification, ClientPayloadValidationContext,
    ClientPayloadVerifiedEnvelopeKey, ENCRYPTED_PAYLOAD_MARKER, ExistingPayloadMode,
    PayloadEncryptionError, PayloadEncryptionPolicy, PayloadTextEncryptor,
    ServerPayloadEnvelopeKey, ServerPayloadValidationContext, ServerPayloadVerifiedEnvelopeKey,
    client_payload_envelope_key, client_payload_nonce_replay_key, client_payload_signature_key_id,
    client_payload_signature_message, is_client_encrypted_payload_value,
    is_encrypted_payload_value, server_payload_envelope_key, validate_client_payload_value,
    validate_client_payload_value_after_runtime_verification,
    validate_client_payload_value_for_runtime,
    validate_server_payload_value_after_runtime_encryption, validate_server_payload_value_metadata,
};
pub use vector::{
    CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CKKS_SCHEME, CkksBatchEncryptionInput,
    CkksEncryptedQueryScoreBatchInput, CkksEncryptedQueryScoreBatchItem,
    CkksEncryptedQueryScoreInput, CkksEncryptionInput, CkksError, CkksParameters,
    CkksPlaintextQueryScoreBatchInput, CkksPlaintextQueryScoreInput, CkksPublicMaterial,
    CkksQueryEncryptionInput, CkksVectorBackend, CkksVectorBatchItem, CkksVectorEncryptor,
    CkksVectorSidecarEnvelopeKey, CkksVectorVerifiedSidecarDeleteKey, CkksVectorVerifiedSidecarKey,
    ENCRYPTED_CKKS_VECTOR_MARKER, ENCRYPTED_VECTOR_SIDECAR_FIELD, EncryptedCkksVector,
    VerifiedCkksVector, ckks_vector_sidecar_envelope_key, ckks_vector_verified_sidecar_delete_key,
    encrypted_ckks_vector_payload_value, is_encrypted_ckks_vector_payload_value,
};
