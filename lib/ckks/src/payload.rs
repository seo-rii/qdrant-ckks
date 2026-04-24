use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::aead::{AeadCipher, AeadKeyring, EncryptedEnvelope, EncryptionContext, EncryptionError};

pub const ENCRYPTED_PAYLOAD_MARKER: &str = "$qdrant_ckks";
const PAYLOAD_TEXT_KIND: &str = "payload_text";
const CRYPTO_SCHEMA_VERSION: u16 = 1;
const DEFAULT_ENCRYPTION_EPOCH: u64 = 0;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PayloadEncryptionError {
    #[error("payload encryption policy must contain at least one field")]
    EmptyPolicy,
    #[error("payload encryption field path is invalid: {0}")]
    InvalidFieldPath(String),
    #[error("required payload field is missing: {0}")]
    MissingField(String),
    #[error("payload field path expects an object parent: {0}")]
    ExpectedObjectParent(String),
    #[error("payload field {field} must be a string, found {found}")]
    ExpectedString { field: String, found: &'static str },
    #[error("payload field {field} must contain an encrypted qdrant-ckks envelope, found {found}")]
    ExpectedEncryptedEnvelope { field: String, found: &'static str },
    #[error("payload field contains a malformed qdrant-ckks envelope: {0}")]
    MalformedEnvelope(String),
    #[error("payload field contains unsupported qdrant-ckks envelope kind: {0}")]
    UnsupportedEnvelopeKind(String),
    #[error("payload field contains unsupported qdrant-ckks schema version: {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("payload field encryption epoch does not match active policy")]
    EncryptionEpochMismatch,
    #[error("payload plaintext is not valid UTF-8 after decryption: {0}")]
    InvalidUtf8(String),
    #[error(transparent)]
    Crypto(#[from] EncryptionError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadEncryptionPolicy {
    fields: Vec<String>,
    strict_missing_fields: bool,
}

impl PayloadEncryptionPolicy {
    pub fn new<I, S>(fields: I) -> Result<Self, PayloadEncryptionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut normalized = Vec::new();

        for field in fields {
            let field = field.into();
            if field.is_empty()
                || field.starts_with('.')
                || field.ends_with('.')
                || field.split('.').any(|part| {
                    part.is_empty() || part == ENCRYPTED_PAYLOAD_MARKER || part.contains('\0')
                })
            {
                return Err(PayloadEncryptionError::InvalidFieldPath(field));
            }

            if !normalized.iter().any(|existing| existing == &field) {
                normalized.push(field);
            }
        }

        if normalized.is_empty() {
            return Err(PayloadEncryptionError::EmptyPolicy);
        }

        Ok(Self {
            fields: normalized,
            strict_missing_fields: false,
        })
    }

    pub fn with_strict_missing_fields(mut self, strict: bool) -> Self {
        self.strict_missing_fields = strict;
        self
    }

    pub fn fields(&self) -> &[String] {
        &self.fields
    }
}

pub struct PayloadTextEncryptor {
    collection: String,
    keyring: AeadKeyring,
    crypto_schema_version: u16,
    encryption_epoch: u64,
}

impl PayloadTextEncryptor {
    pub fn new(
        collection: impl Into<String>,
        cipher: AeadCipher,
    ) -> Result<Self, PayloadEncryptionError> {
        Self::new_with_keyring(collection, AeadKeyring::new(cipher))
    }

    pub fn new_with_keyring(
        collection: impl Into<String>,
        keyring: AeadKeyring,
    ) -> Result<Self, PayloadEncryptionError> {
        let collection = collection.into();
        if collection.is_empty() || collection.contains('\0') {
            return Err(PayloadEncryptionError::InvalidFieldPath(
                "collection".to_string(),
            ));
        }
        Ok(Self {
            collection,
            keyring,
            crypto_schema_version: CRYPTO_SCHEMA_VERSION,
            encryption_epoch: DEFAULT_ENCRYPTION_EPOCH,
        })
    }

    pub fn with_encryption_epoch(mut self, encryption_epoch: u64) -> Self {
        self.encryption_epoch = encryption_epoch;
        self
    }

    pub fn encrypt_selected_fields(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
    ) -> Result<usize, PayloadEncryptionError> {
        let mut encrypted = 0;

        for field in policy.fields() {
            let Some(value) = locate_path_mut(payload, field)? else {
                if policy.strict_missing_fields {
                    return Err(PayloadEncryptionError::MissingField(field.clone()));
                }
                continue;
            };

            if extract_envelope(value, field)?.is_some() {
                continue;
            }

            let plaintext = match value {
                Value::String(plaintext) => plaintext.as_bytes().to_vec(),
                other => {
                    return Err(PayloadEncryptionError::ExpectedString {
                        field: field.clone(),
                        found: json_type_name(other),
                    });
                }
            };

            let context = EncryptionContext::payload_text(&self.collection, point_id, field);
            let aad_suffix = payload_metadata_aad(
                PAYLOAD_TEXT_KIND,
                self.crypto_schema_version,
                self.encryption_epoch,
            );
            let envelope =
                self.keyring
                    .encrypt_with_aad_suffix(&plaintext, context, &aad_suffix)?;
            *value = stored_envelope_value(
                envelope,
                field,
                self.crypto_schema_version,
                self.encryption_epoch,
            )?;
            encrypted += 1;
        }

        Ok(encrypted)
    }

    pub fn decrypt_selected_fields(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
    ) -> Result<usize, PayloadEncryptionError> {
        let mut decrypted = 0;

        for field in policy.fields() {
            let Some(value) = locate_path_mut(payload, field)? else {
                if policy.strict_missing_fields {
                    return Err(PayloadEncryptionError::MissingField(field.clone()));
                }
                continue;
            };

            let envelope = extract_envelope(value, field)?.ok_or_else(|| {
                PayloadEncryptionError::ExpectedEncryptedEnvelope {
                    field: field.clone(),
                    found: json_type_name(value),
                }
            })?;
            let context = EncryptionContext::payload_text(&self.collection, point_id, field);
            let aad_suffix = payload_metadata_aad(
                &envelope.kind,
                envelope.schema_version,
                envelope.encryption_epoch,
            );
            let plaintext =
                self.keyring
                    .decrypt_with_aad_suffix(&envelope.envelope, context, &aad_suffix)?;
            if envelope.schema_version != self.crypto_schema_version {
                return Err(PayloadEncryptionError::UnsupportedSchemaVersion(
                    envelope.schema_version,
                ));
            }
            if envelope.encryption_epoch != self.encryption_epoch {
                return Err(PayloadEncryptionError::EncryptionEpochMismatch);
            }
            let plaintext = String::from_utf8(plaintext)
                .map_err(|err| PayloadEncryptionError::InvalidUtf8(err.to_string()))?;

            *value = Value::String(plaintext);
            decrypted += 1;
        }

        Ok(decrypted)
    }
}

pub fn is_encrypted_payload_value(value: &Value) -> bool {
    extract_envelope(value, ENCRYPTED_PAYLOAD_MARKER)
        .map(|envelope| envelope.is_some())
        .unwrap_or(false)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPayloadEnvelope {
    kind: String,
    #[serde(default = "default_crypto_schema_version")]
    schema_version: u16,
    #[serde(default)]
    encryption_epoch: u64,
    envelope: EncryptedEnvelope,
}

const fn default_crypto_schema_version() -> u16 {
    CRYPTO_SCHEMA_VERSION
}

fn locate_path_mut<'a>(
    payload: &'a mut Map<String, Value>,
    field_path: &str,
) -> Result<Option<&'a mut Value>, PayloadEncryptionError> {
    let mut parts = field_path.split('.');
    let first = parts
        .next()
        .ok_or_else(|| PayloadEncryptionError::InvalidFieldPath(field_path.to_string()))?;
    let Some(mut value) = payload.get_mut(first) else {
        return Ok(None);
    };

    for part in parts {
        match value {
            Value::Object(object) => {
                let Some(next) = object.get_mut(part) else {
                    return Ok(None);
                };
                value = next;
            }
            _ => {
                return Err(PayloadEncryptionError::ExpectedObjectParent(
                    field_path.to_string(),
                ));
            }
        }
    }

    Ok(Some(value))
}

fn stored_envelope_value(
    envelope: EncryptedEnvelope,
    field: &str,
    schema_version: u16,
    encryption_epoch: u64,
) -> Result<Value, PayloadEncryptionError> {
    let envelope = StoredPayloadEnvelope {
        kind: PAYLOAD_TEXT_KIND.to_string(),
        schema_version,
        encryption_epoch,
        envelope,
    };
    let value = serde_json::to_value(envelope)
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field.to_string()))?;
    Ok(Value::Object(Map::from_iter([(
        ENCRYPTED_PAYLOAD_MARKER.to_string(),
        value,
    )])))
}

fn payload_metadata_aad(kind: &str, schema_version: u16, encryption_epoch: u64) -> Vec<u8> {
    let mut aad = Vec::new();
    for value in [kind.as_bytes()] {
        aad.extend_from_slice(&(value.len() as u32).to_be_bytes());
        aad.extend_from_slice(value);
    }
    aad.extend_from_slice(&schema_version.to_be_bytes());
    aad.extend_from_slice(&encryption_epoch.to_be_bytes());
    aad
}

fn extract_envelope(
    value: &Value,
    field: &str,
) -> Result<Option<StoredPayloadEnvelope>, PayloadEncryptionError> {
    let Value::Object(object) = value else {
        return Ok(None);
    };
    let Some(envelope) = object.get(ENCRYPTED_PAYLOAD_MARKER) else {
        return Ok(None);
    };
    if object.len() != 1 {
        return Err(PayloadEncryptionError::MalformedEnvelope(field.to_string()));
    }

    let envelope: StoredPayloadEnvelope = serde_json::from_value(envelope.clone())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field.to_string()))?;
    if envelope.kind != PAYLOAD_TEXT_KIND {
        return Err(PayloadEncryptionError::UnsupportedEnvelopeKind(
            envelope.kind,
        ));
    }

    Ok(Some(envelope))
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
