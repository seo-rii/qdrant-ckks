//! Encryption support primitives for qdrant-ckks.
//!
//! This crate intentionally keeps cryptographic boundaries outside the hot vector
//! storage path until the OpenFHE backend is configured. The types here are
//! serializable and testable without linking OpenFHE into every Qdrant build.

pub mod aead;
pub mod openfhe;
pub mod payload;
pub mod vector;

pub use aead::{
    AeadCipher, EncryptedEnvelope, EncryptionContext, EncryptionError, EncryptionPurpose, SecretKey,
};
pub use openfhe::CommandOpenFheBackend;
pub use payload::{
    ENCRYPTED_PAYLOAD_MARKER, PayloadEncryptionError, PayloadEncryptionPolicy,
    PayloadTextEncryptor, is_encrypted_payload_value,
};
pub use vector::{
    CKKS_SCHEME, CkksEncryptionInput, CkksError, CkksParameters, CkksPublicMaterial,
    CkksVectorBackend, CkksVectorEncryptor, EncryptedCkksVector,
};
