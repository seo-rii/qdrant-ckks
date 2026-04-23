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
    AeadCipher, EncryptedEnvelope, EncryptionContext, EncryptionError, EncryptionPurpose, SecretKey,
};
pub use control_plane::{
    CiphertextEnvelope, CompiledCollectionCryptoPlan, CompiledMetadataRule, CompiledPayloadRule,
    CompiledVectorRule, ControlPlaneError, CryptoCapability, CryptoRegistry, CryptoSuite,
    GENERIC_CIPHERTEXT_MARKER, METADATA_BLIND_INDEX_PROVIDER, METADATA_VALUE_BINDING,
    MetadataProviderFactory, PAYLOAD_AES_GCM_PROVIDER, PAYLOAD_FIELD_BINDING,
    PayloadProviderFactory, VECTOR_ENVELOPE_BINDING, VECTOR_OPENFHE_CKKS_PROVIDER,
    VectorProviderFactory,
};
pub use openfhe::CommandOpenFheBackend;
pub use payload::{
    ENCRYPTED_PAYLOAD_MARKER, PayloadEncryptionError, PayloadEncryptionPolicy,
    PayloadTextEncryptor, is_encrypted_payload_value,
};
pub use vector::{
    CKKS_SCHEME, CkksEncryptionInput, CkksError, CkksParameters, CkksPublicMaterial,
    CkksVectorBackend, CkksVectorEncryptor, EncryptedCkksVector, VerifiedCkksVector,
};
