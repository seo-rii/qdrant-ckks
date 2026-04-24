use std::fmt::{self, Debug, Formatter};

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::aead::{
    AeadCipher, EncryptedEnvelope, EncryptionContext, EncryptionError, SecretKey, validate_key_id,
};

pub const CKKS_SCHEME: &str = "openfhe-ckks";
const VERSION: u8 = 1;
const MAX_VECTOR_NAME_LEN: usize = 255;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CkksError {
    #[error("ckks key id is invalid")]
    InvalidKeyId,
    #[error("ckks vector name is invalid")]
    InvalidVectorName,
    #[error("ckks context value is invalid: {0}")]
    InvalidContext(String),
    #[error("ckks parameters are invalid: {0}")]
    InvalidParameters(String),
    #[error("ckks vector must contain at least one value")]
    EmptyVector,
    #[error("ckks vector has {len} values but batch size only allows {batch_size}")]
    VectorTooWide { len: usize, batch_size: usize },
    #[error("ckks vector value at index {index} is not finite")]
    NonFiniteValue { index: usize },
    #[error("openfhe backend returned empty ciphertext")]
    EmptyCiphertext,
    #[error("unsupported ckks vector envelope version {0}")]
    UnsupportedEnvelopeVersion(u8),
    #[error("unsupported ckks vector scheme {0}")]
    UnsupportedScheme(String),
    #[error("ckks vector envelope is malformed: {0}")]
    MalformedEnvelope(String),
    #[error("openfhe backend failed: {0}")]
    Backend(String),
    #[error(transparent)]
    Envelope(#[from] EncryptionError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CkksParameters {
    pub poly_modulus_degree: u32,
    pub multiplicative_depth: u32,
    pub scaling_mod_size: u32,
    pub first_mod_size: u32,
    pub batch_size: u32,
}

impl CkksParameters {
    pub const fn openfhe_default_128_bit() -> Self {
        Self {
            poly_modulus_degree: 16_384,
            multiplicative_depth: 4,
            scaling_mod_size: 50,
            first_mod_size: 60,
            batch_size: 8_192,
        }
    }

    pub fn validate(&self) -> Result<(), CkksError> {
        if self.poly_modulus_degree < 2_048
            || self.poly_modulus_degree > 1_048_576
            || !self.poly_modulus_degree.is_power_of_two()
        {
            return Err(CkksError::InvalidParameters(
                "poly_modulus_degree must be a power of two in 2048..=1048576".to_string(),
            ));
        }
        if self.multiplicative_depth == 0 || self.multiplicative_depth > 64 {
            return Err(CkksError::InvalidParameters(
                "multiplicative_depth must be in 1..=64".to_string(),
            ));
        }
        if !(20..=80).contains(&self.scaling_mod_size) {
            return Err(CkksError::InvalidParameters(
                "scaling_mod_size must be in 20..=80".to_string(),
            ));
        }
        if self.first_mod_size < self.scaling_mod_size || self.first_mod_size > 90 {
            return Err(CkksError::InvalidParameters(
                "first_mod_size must be >= scaling_mod_size and <= 90".to_string(),
            ));
        }

        let max_slots = self.poly_modulus_degree / 2;
        if self.batch_size == 0 || self.batch_size > max_slots {
            return Err(CkksError::InvalidParameters(format!(
                "batch_size must be in 1..={max_slots}",
            )));
        }

        Ok(())
    }
}

impl Default for CkksParameters {
    fn default() -> Self {
        Self::openfhe_default_128_bit()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CkksPublicMaterial {
    crypto_context: Vec<u8>,
    public_key: Vec<u8>,
}

impl CkksPublicMaterial {
    pub fn new(
        crypto_context: impl Into<Vec<u8>>,
        public_key: impl Into<Vec<u8>>,
    ) -> Result<Self, CkksError> {
        let crypto_context = crypto_context.into();
        let public_key = public_key.into();
        if crypto_context.is_empty() {
            return Err(CkksError::InvalidContext(
                "crypto_context must not be empty".to_string(),
            ));
        }
        if public_key.is_empty() {
            return Err(CkksError::InvalidContext(
                "public_key must not be empty".to_string(),
            ));
        }

        Ok(Self {
            crypto_context,
            public_key,
        })
    }

    pub fn crypto_context(&self) -> &[u8] {
        &self.crypto_context
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn digest_for(&self, parameters: &CkksParameters) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"qdrant-ckks-openfhe-context-v1");
        hasher.update(parameters.poly_modulus_degree.to_be_bytes());
        hasher.update(parameters.multiplicative_depth.to_be_bytes());
        hasher.update(parameters.scaling_mod_size.to_be_bytes());
        hasher.update(parameters.first_mod_size.to_be_bytes());
        hasher.update(parameters.batch_size.to_be_bytes());
        hasher.update((self.crypto_context.len() as u64).to_be_bytes());
        hasher.update(&self.crypto_context);
        hasher.update((self.public_key.len() as u64).to_be_bytes());
        hasher.update(&self.public_key);
        BASE64URL_NOPAD.encode(&hasher.finalize())
    }
}

#[derive(Clone, Debug)]
pub struct CkksEncryptionInput<'a> {
    pub parameters: &'a CkksParameters,
    pub public_material: &'a CkksPublicMaterial,
    pub collection: &'a str,
    pub point_id: &'a str,
    pub vector_name: &'a str,
    pub values: &'a [f64],
}

pub trait CkksVectorBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError>;
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EncryptedCkksVector {
    pub version: u8,
    pub scheme: String,
    pub envelope: EncryptedEnvelope,
}

impl Debug for EncryptedCkksVector {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedCkksVector")
            .field("version", &self.version)
            .field("scheme", &self.scheme)
            .field("envelope", &self.envelope)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VerifiedCkksVector {
    pub key_id: String,
    pub vector_name: String,
    pub slots: usize,
    pub context_digest: String,
    pub ciphertext: String,
}

pub struct CkksVectorEncryptor<B> {
    metadata_cipher: AeadCipher,
    vector_name: String,
    parameters: CkksParameters,
    backend: B,
}

impl<B> CkksVectorEncryptor<B>
where
    B: CkksVectorBackend,
{
    pub fn new(
        key_id: impl Into<String>,
        vector_name: impl Into<String>,
        parameters: CkksParameters,
        metadata_key: SecretKey,
        backend: B,
    ) -> Result<Self, CkksError> {
        let key_id = key_id.into();
        validate_key_id(&key_id).map_err(|_| CkksError::InvalidKeyId)?;

        let vector_name = vector_name.into();
        if vector_name.len() > MAX_VECTOR_NAME_LEN || vector_name.contains('\0') {
            return Err(CkksError::InvalidVectorName);
        }

        parameters.validate()?;

        Ok(Self {
            metadata_cipher: AeadCipher::new(key_id, metadata_key)?,
            vector_name,
            parameters,
            backend,
        })
    }

    pub fn encrypt(
        &self,
        collection: &str,
        point_id: &str,
        public_material: &CkksPublicMaterial,
        values: &[f64],
    ) -> Result<EncryptedCkksVector, CkksError> {
        if collection.is_empty() || collection.contains('\0') {
            return Err(CkksError::InvalidContext(
                "collection must be non-empty and must not contain NUL".to_string(),
            ));
        }
        if point_id.is_empty() || point_id.contains('\0') {
            return Err(CkksError::InvalidContext(
                "point_id must be non-empty and must not contain NUL".to_string(),
            ));
        }
        if values.is_empty() {
            return Err(CkksError::EmptyVector);
        }
        if values.len() > self.parameters.batch_size as usize {
            return Err(CkksError::VectorTooWide {
                len: values.len(),
                batch_size: self.parameters.batch_size as usize,
            });
        }
        if let Some((index, _)) = values
            .iter()
            .enumerate()
            .find(|(_, value)| !value.is_finite())
        {
            return Err(CkksError::NonFiniteValue { index });
        }

        let ciphertext = self.backend.encrypt(CkksEncryptionInput {
            parameters: &self.parameters,
            public_material,
            collection,
            point_id,
            vector_name: &self.vector_name,
            values,
        })?;
        if ciphertext.is_empty() {
            return Err(CkksError::EmptyCiphertext);
        }

        let envelope = self.metadata_cipher.encrypt(
            serde_json::to_vec(&VerifiedCkksVector {
                key_id: self.metadata_cipher.key_id().to_string(),
                vector_name: self.vector_name.clone(),
                slots: values.len(),
                context_digest: public_material.digest_for(&self.parameters),
                ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
            })
            .map_err(|err| CkksError::MalformedEnvelope(err.to_string()))?
            .as_slice(),
            EncryptionContext::ckks_vector(collection, point_id, &self.vector_name),
        )?;

        Ok(EncryptedCkksVector {
            version: VERSION,
            scheme: CKKS_SCHEME.to_string(),
            envelope,
        })
    }

    pub fn open(
        &self,
        collection: &str,
        point_id: &str,
        expected_public_material: &CkksPublicMaterial,
        encrypted: &EncryptedCkksVector,
    ) -> Result<VerifiedCkksVector, CkksError> {
        if encrypted.version != VERSION {
            return Err(CkksError::UnsupportedEnvelopeVersion(encrypted.version));
        }
        if encrypted.scheme != CKKS_SCHEME {
            return Err(CkksError::UnsupportedScheme(encrypted.scheme.clone()));
        }

        let verified: VerifiedCkksVector = serde_json::from_slice(&self.metadata_cipher.decrypt(
            &encrypted.envelope,
            EncryptionContext::ckks_vector(collection, point_id, &self.vector_name),
        )?)
        .map_err(|err| CkksError::MalformedEnvelope(err.to_string()))?;

        if verified.key_id != self.metadata_cipher.key_id() {
            return Err(CkksError::MalformedEnvelope(
                "stored key id does not match active key".to_string(),
            ));
        }
        if verified.vector_name != self.vector_name {
            return Err(CkksError::MalformedEnvelope(
                "stored vector name does not match encryptor".to_string(),
            ));
        }
        if verified.slots == 0 || verified.slots > self.parameters.batch_size as usize {
            return Err(CkksError::MalformedEnvelope(
                "stored slot count is out of range".to_string(),
            ));
        }
        let digest = BASE64URL_NOPAD
            .decode(verified.context_digest.as_bytes())
            .map_err(|_| {
                CkksError::MalformedEnvelope("stored context digest is invalid".to_string())
            })?;
        if digest.len() != 32 {
            return Err(CkksError::MalformedEnvelope(
                "stored context digest has unexpected length".to_string(),
            ));
        }
        if verified.context_digest != expected_public_material.digest_for(&self.parameters) {
            return Err(CkksError::MalformedEnvelope(
                "stored context digest does not match active context".to_string(),
            ));
        }
        let ciphertext = BASE64URL_NOPAD
            .decode(verified.ciphertext.as_bytes())
            .map_err(|_| {
                CkksError::MalformedEnvelope("stored ciphertext is invalid".to_string())
            })?;
        if ciphertext.is_empty() {
            return Err(CkksError::MalformedEnvelope(
                "stored ciphertext is empty".to_string(),
            ));
        }

        Ok(verified)
    }
}
