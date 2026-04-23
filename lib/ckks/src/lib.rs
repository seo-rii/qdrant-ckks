//! Encryption support primitives for qdrant-ckks.
//!
//! This crate intentionally keeps cryptographic boundaries outside the hot vector
//! storage path until the OpenFHE backend is configured. The types here are
//! serializable and testable without linking OpenFHE into every Qdrant build.

pub mod aead;

pub use aead::{
    AeadCipher, EncryptedEnvelope, EncryptionContext, EncryptionError, EncryptionPurpose, SecretKey,
};
