use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    #[error("envelope material fingerprint does not match the active key")]
    MaterialFingerprintMismatch,
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

    fn aad_bytes_with_suffix(
        &self,
        envelope_header: &EnvelopeHeader<'_>,
        aad_suffix: &[u8],
    ) -> Vec<u8> {
        let values = [
            "qdrant-ckks",
            "v1",
            self.purpose.as_str(),
            self.collection,
            self.point_id.unwrap_or_default(),
            self.field_path.unwrap_or_default(),
            self.vector_name.unwrap_or_default(),
            envelope_header.algorithm,
            envelope_header.key_id,
            envelope_header.material_fingerprint,
            envelope_header.nonce,
        ];

        let mut aad = Vec::new();
        for value in values {
            let bytes = value.as_bytes();
            aad.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            aad.extend_from_slice(bytes);
        }
        aad.extend_from_slice(&envelope_header.version.to_be_bytes());
        aad.extend_from_slice(&(aad_suffix.len() as u32).to_be_bytes());
        aad.extend_from_slice(aad_suffix);
        aad
    }
}

struct EnvelopeHeader<'a> {
    version: u8,
    algorithm: &'a str,
    key_id: &'a str,
    material_fingerprint: &'a str,
    nonce: &'a str,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub version: u8,
    pub algorithm: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub material_fingerprint: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl Debug for EncryptedEnvelope {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedEnvelope")
            .field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("material_fingerprint", &self.material_fingerprint)
            .field("nonce", &"[redacted]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

pub struct AeadCipher {
    key_id: String,
    material_fingerprint: String,
    key: SecretKey,
}

impl AeadCipher {
    pub fn new(key_id: impl Into<String>, key: SecretKey) -> Result<Self, EncryptionError> {
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        let material_fingerprint = key.material_fingerprint();
        Ok(Self {
            key_id,
            material_fingerprint,
            key,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn material_fingerprint(&self) -> &str {
        &self.material_fingerprint
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        context: EncryptionContext<'_>,
    ) -> Result<EncryptedEnvelope, EncryptionError> {
        self.encrypt_with_aad_suffix(plaintext, context, &[])
    }

    pub(crate) fn encrypt_with_aad_suffix(
        &self,
        plaintext: &[u8],
        context: EncryptionContext<'_>,
        aad_suffix: &[u8],
    ) -> Result<EncryptedEnvelope, EncryptionError> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| EncryptionError::RandomFailure)?;
        let nonce_b64 = BASE64URL_NOPAD.encode(&nonce_bytes);

        let unbound_key = UnboundKey::new(&AES_256_GCM, self.key.as_bytes())
            .map_err(|_| EncryptionError::SealFailed)?;
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = context.aad_bytes_with_suffix(
            &EnvelopeHeader {
                version: VERSION,
                algorithm: ALGORITHM,
                key_id: &self.key_id,
                material_fingerprint: &self.material_fingerprint,
                nonce: &nonce_b64,
            },
            aad_suffix,
        );
        let mut in_out = plaintext.to_vec();

        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(aad.as_slice()), &mut in_out)
            .map_err(|_| EncryptionError::SealFailed)?;
        in_out.extend_from_slice(tag.as_ref());

        Ok(EncryptedEnvelope {
            version: VERSION,
            algorithm: ALGORITHM.to_string(),
            key_id: self.key_id.clone(),
            material_fingerprint: self.material_fingerprint.clone(),
            nonce: nonce_b64,
            ciphertext: BASE64URL_NOPAD.encode(&in_out),
        })
    }

    pub fn decrypt(
        &self,
        envelope: &EncryptedEnvelope,
        context: EncryptionContext<'_>,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_with_aad_suffix(envelope, context, &[])
    }

    pub(crate) fn decrypt_with_aad_suffix(
        &self,
        envelope: &EncryptedEnvelope,
        context: EncryptionContext<'_>,
        aad_suffix: &[u8],
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
        if !envelope.material_fingerprint.is_empty()
            && envelope.material_fingerprint != self.material_fingerprint
        {
            return Err(EncryptionError::MaterialFingerprintMismatch);
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
        let aad = context.aad_bytes_with_suffix(
            &EnvelopeHeader {
                version: envelope.version,
                algorithm: &envelope.algorithm,
                key_id: &envelope.key_id,
                material_fingerprint: &envelope.material_fingerprint,
                nonce: &envelope.nonce,
            },
            aad_suffix,
        );
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext)
            .map_err(|_| EncryptionError::OpenFailed)?;
        Ok(plaintext.to_vec())
    }
}

pub struct AeadKeyring {
    active: AeadCipher,
    retired: Vec<AeadCipher>,
}

impl AeadKeyring {
    pub fn new(active: AeadCipher) -> Self {
        Self {
            active,
            retired: Vec::new(),
        }
    }

    pub fn with_retired(mut self, retired: AeadCipher) -> Self {
        self.retired.push(retired);
        self
    }

    pub fn key_id(&self) -> &str {
        self.active.key_id()
    }

    pub fn material_fingerprint(&self) -> &str {
        self.active.material_fingerprint()
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        context: EncryptionContext<'_>,
    ) -> Result<EncryptedEnvelope, EncryptionError> {
        self.encrypt_with_aad_suffix(plaintext, context, &[])
    }

    pub(crate) fn encrypt_with_aad_suffix(
        &self,
        plaintext: &[u8],
        context: EncryptionContext<'_>,
        aad_suffix: &[u8],
    ) -> Result<EncryptedEnvelope, EncryptionError> {
        self.active
            .encrypt_with_aad_suffix(plaintext, context, aad_suffix)
    }

    pub fn decrypt(
        &self,
        envelope: &EncryptedEnvelope,
        context: EncryptionContext<'_>,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_with_aad_suffix(envelope, context, &[])
    }

    pub(crate) fn decrypt_with_aad_suffix(
        &self,
        envelope: &EncryptedEnvelope,
        context: EncryptionContext<'_>,
        aad_suffix: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        match self
            .active
            .decrypt_with_aad_suffix(envelope, context, aad_suffix)
        {
            Ok(plaintext) => Ok(plaintext),
            Err(active_error @ EncryptionError::KeyMismatch)
            | Err(active_error @ EncryptionError::MaterialFingerprintMismatch)
            | Err(active_error @ EncryptionError::OpenFailed) => {
                for retired in &self.retired {
                    match retired.decrypt_with_aad_suffix(envelope, context, aad_suffix) {
                        Ok(plaintext) => return Ok(plaintext),
                        Err(EncryptionError::KeyMismatch)
                        | Err(EncryptionError::MaterialFingerprintMismatch)
                        | Err(EncryptionError::OpenFailed) => {}
                        Err(error) => return Err(error),
                    }
                }

                Err(active_error)
            }
            Err(error) => Err(error),
        }
    }
}

impl SecretKey {
    fn material_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"qdrant-ckks-aead-material-fingerprint-v1");
        hasher.update(self.as_bytes());
        BASE64URL_NOPAD.encode(&hasher.finalize())
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
