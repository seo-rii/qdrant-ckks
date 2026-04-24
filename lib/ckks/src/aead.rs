use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

const VERSION: u8 = 1;
const ALGORITHM: &str = "AES-256-GCM";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_KEY_ID_LEN: usize = 128;
const HKDF_SALT: &[u8] = b"qdrant-ckks-aead-master-key-v1";

pub const PAYLOAD_TEXT_KEY_DOMAIN: &[u8] = b"qdrant/payload-text/v1";
pub const CKKS_VECTOR_KEY_DOMAIN: &[u8] = b"qdrant/vector-envelope/v1";

#[derive(Error, Debug, PartialEq, Eq)]
pub enum EncryptionError {
    #[error("encryption key must be exactly 32 bytes")]
    InvalidKeyLength,
    #[error("key id must be 1..=128 ASCII characters from [A-Za-z0-9._:-]")]
    InvalidKeyId,
    #[error("failed to obtain cryptographically secure random bytes")]
    RandomFailure,
    #[error("failed to derive encryption subkey")]
    KeyDerivationFailed,
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported envelope algorithm {0}")]
    UnsupportedAlgorithm(String),
    #[error("envelope key id does not match the active key")]
    KeyMismatch,
    #[error("envelope field is not valid base64url without padding")]
    InvalidEncoding,
    #[error("nonce must decode to 96 bits")]
    InvalidNonceLength,
    #[error("ciphertext is shorter than the authentication tag")]
    InvalidCiphertextLength,
    #[error("encryption failed")]
    SealFailed,
    #[error("decryption authentication failed")]
    OpenFailed,
}

pub struct SecretKey {
    bytes: [u8; KEY_LEN],
}

struct SecretKeyLen;

impl hkdf::KeyType for SecretKeyLen {
    fn len(&self) -> usize {
        KEY_LEN
    }
}

impl SecretKey {
    pub fn generate() -> Result<Self, EncryptionError> {
        let rng = SystemRandom::new();
        let mut bytes = [0u8; KEY_LEN];
        rng.fill(&mut bytes)
            .map_err(|_| EncryptionError::RandomFailure)?;
        Ok(Self { bytes })
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, EncryptionError> {
        let bytes: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| EncryptionError::InvalidKeyLength)?;
        Ok(Self { bytes })
    }

    pub fn derive_subkey(&self, domain: &[u8]) -> Result<Self, EncryptionError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
        let prk = salt.extract(self.as_bytes());
        let info = [domain];
        let okm = prk
            .expand(&info, SecretKeyLen)
            .map_err(|_| EncryptionError::KeyDerivationFailed)?;
        let mut bytes = [0u8; KEY_LEN];
        okm.fill(&mut bytes)
            .map_err(|_| EncryptionError::KeyDerivationFailed)?;
        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("bytes", &"[redacted; 32 bytes]")
            .finish()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionPurpose {
    PayloadText,
    CkksVector,
}

impl EncryptionPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PayloadText => "payload_text",
            Self::CkksVector => "ckks_vector",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionContext<'a> {
    pub purpose: EncryptionPurpose,
    pub collection: &'a str,
    pub point_id: Option<&'a str>,
    pub field_path: Option<&'a str>,
    pub vector_name: Option<&'a str>,
}

impl<'a> EncryptionContext<'a> {
    pub const fn payload_text(collection: &'a str, point_id: &'a str, field_path: &'a str) -> Self {
        Self {
            purpose: EncryptionPurpose::PayloadText,
            collection,
            point_id: Some(point_id),
            field_path: Some(field_path),
            vector_name: None,
        }
    }

    pub const fn ckks_vector(collection: &'a str, point_id: &'a str, vector_name: &'a str) -> Self {
        Self {
            purpose: EncryptionPurpose::CkksVector,
            collection,
            point_id: Some(point_id),
            field_path: None,
            vector_name: Some(vector_name),
        }
    }

    fn aad_bytes(&self) -> Vec<u8> {
        let values = [
            "qdrant-ckks",
            "v1",
            self.purpose.as_str(),
            self.collection,
            self.point_id.unwrap_or_default(),
            self.field_path.unwrap_or_default(),
            self.vector_name.unwrap_or_default(),
        ];

        let mut aad = Vec::new();
        for value in values {
            let bytes = value.as_bytes();
            aad.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            aad.extend_from_slice(bytes);
        }
        aad
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub version: u8,
    pub algorithm: String,
    pub key_id: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl Debug for EncryptedEnvelope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedEnvelope")
            .field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("nonce", &"[redacted]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

pub struct AeadCipher {
    key_id: String,
    key: SecretKey,
}

impl AeadCipher {
    pub fn new(key_id: impl Into<String>, key: SecretKey) -> Result<Self, EncryptionError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        Ok(Self { key_id, key })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        context: EncryptionContext<'_>,
    ) -> Result<EncryptedEnvelope, EncryptionError> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| EncryptionError::RandomFailure)?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, self.key.as_bytes())
            .map_err(|_| EncryptionError::SealFailed)?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = context.aad_bytes();
        let mut in_out = plaintext.to_vec();

        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(aad.as_slice()), &mut in_out)
            .map_err(|_| EncryptionError::SealFailed)?;
        in_out.extend_from_slice(tag.as_ref());

        Ok(EncryptedEnvelope {
            version: VERSION,
            algorithm: ALGORITHM.to_string(),
            key_id: self.key_id.clone(),
            nonce: BASE64URL_NOPAD.encode(&nonce_bytes),
            ciphertext: BASE64URL_NOPAD.encode(&in_out),
        })
    }

    pub fn decrypt(
        &self,
        envelope: &EncryptedEnvelope,
        context: EncryptionContext<'_>,
    ) -> Result<Vec<u8>, EncryptionError> {
        if envelope.version != VERSION {
            return Err(EncryptionError::UnsupportedVersion(envelope.version));
        }
        if envelope.algorithm != ALGORITHM {
            return Err(EncryptionError::UnsupportedAlgorithm(
                envelope.algorithm.clone(),
            ));
        }
        if envelope.key_id != self.key_id {
            return Err(EncryptionError::KeyMismatch);
        }
        validate_key_id(&envelope.key_id)?;

        let nonce_bytes = BASE64URL_NOPAD
            .decode(envelope.nonce.as_bytes())
            .map_err(|_| EncryptionError::InvalidEncoding)?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| EncryptionError::InvalidNonceLength)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut ciphertext = BASE64URL_NOPAD
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|_| EncryptionError::InvalidEncoding)?;
        if ciphertext.len() < TAG_LEN {
            return Err(EncryptionError::InvalidCiphertextLength);
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, self.key.as_bytes())
            .map_err(|_| EncryptionError::OpenFailed)?;
        let key = LessSafeKey::new(unbound_key);
        let aad = context.aad_bytes();
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext)
            .map_err(|_| EncryptionError::OpenFailed)?;
        Ok(plaintext.to_vec())
    }
}

pub(crate) fn validate_key_id(key_id: &str) -> Result<(), EncryptionError> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
        return Err(EncryptionError::InvalidKeyId);
    }

    if key_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        Ok(())
    } else {
        Err(EncryptionError::InvalidKeyId)
    }
}
