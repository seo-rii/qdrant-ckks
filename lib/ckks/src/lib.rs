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
    METADATA_BLIND_INDEX_PROVIDER, METADATA_VALUE_BINDING, MetadataProviderFactory,
    PAYLOAD_AES_GCM_PROVIDER, PAYLOAD_CLIENT_AEAD_PROVIDER, PAYLOAD_FIELD_BINDING,
    PayloadProviderFactory, VECTOR_ENVELOPE_BINDING, VECTOR_OPENFHE_CKKS_PROVIDER,
    VectorProviderFactory,
};
pub use openfhe::CommandOpenFheBackend;
pub use payload::{
    CLIENT_ENCRYPTED_PAYLOAD_MARKER, ClientPayloadSignatureVerification,
    ClientPayloadValidationContext, ENCRYPTED_PAYLOAD_MARKER, ExistingPayloadMode,
    PayloadEncryptionError, PayloadEncryptionPolicy, PayloadTextEncryptor,
    client_payload_signature_message, is_client_encrypted_payload_value,
    is_encrypted_payload_value, validate_client_payload_value,
};
pub use vector::{
    CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CKKS_SCHEME, CkksEncryptionInput, CkksError,
    CkksParameters, CkksPublicMaterial, CkksVectorBackend, CkksVectorEncryptor,
    EncryptedCkksVector, VerifiedCkksVector,
};
