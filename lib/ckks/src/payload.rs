use data_encoding::BASE64URL_NOPAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::aead::{
    AeadCipher, AeadKeyring, EncryptedEnvelope, EncryptionContext, EncryptionError,
    PAYLOAD_TEXT_KEY_DOMAIN, SecretKey, validate_encrypted_envelope_metadata,
    validate_resource_key_id,
};

pub const ENCRYPTED_PAYLOAD_MARKER: &str = "$qdrant_ckks";
pub const CLIENT_ENCRYPTED_PAYLOAD_MARKER: &str = "$qdrant_client_aead";
const PAYLOAD_TEXT_KIND: &str = "payload_text";
const CLIENT_PAYLOAD_ALGORITHM: &str = "AES-256-GCM";
const CLIENT_PAYLOAD_KDF_DOMAIN: &str = "qdrant/client-payload-text/v1";
const CLIENT_PAYLOAD_SIGNATURE_DOMAIN: &str = "qdrant/client-payload-signature/v1";
const CLIENT_PAYLOAD_SIGNATURE_ALGORITHM: &str = "ed25519";
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
    #[error("payload field is already encrypted: {0}")]
    AlreadyEncrypted(String),
    #[error("payload field contains a malformed qdrant-ckks envelope: {0}")]
    MalformedEnvelope(String),
    #[error("payload field contains unsupported qdrant-ckks envelope kind: {0}")]
    UnsupportedEnvelopeKind(String),
    #[error("payload field contains unsupported client envelope algorithm: {0}")]
    UnsupportedClientAlgorithm(String),
    #[error("payload field client envelope AAD does not match expected {0}")]
    ClientEnvelopeAadMismatch(String),
    #[error("payload field client envelope key id is missing")]
    MissingClientKeyId,
    #[error("payload field client envelope key id does not match policy")]
    ClientKeyIdMismatch,
    #[error("payload field client envelope resource key id does not match policy")]
    ClientResourceKeyIdMismatch,
    #[error("payload field client envelope resource key epoch is outside policy")]
    ClientResourceKeyEpochMismatch,
    #[error("payload field client envelope nonce was already used in this write request")]
    ClientNonceReplay,
    #[error("client payload nonce replay cache key is malformed")]
    MalformedClientNonceReplayCacheKey,
    #[error("payload field client envelope signature is missing")]
    MissingClientSignature,
    #[error("payload field client envelope signature key id does not match policy")]
    ClientSignatureKeyIdMismatch,
    #[error("payload field contains unsupported client envelope signature algorithm: {0}")]
    UnsupportedClientSignatureAlgorithm(String),
    #[error("payload field client envelope signature verification failed")]
    InvalidClientSignature,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingPayloadMode {
    SkipExisting,
    ReencryptIfStale,
    FailIfExisting,
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
                    part.is_empty()
                        || part == ENCRYPTED_PAYLOAD_MARKER
                        || part == CLIENT_ENCRYPTED_PAYLOAD_MARKER
                        || part == "$qdrant_ciphertext"
                        || part.contains('\0')
                        || part.contains('[')
                        || part.contains(']')
                        || part.contains('*')
                        || part.bytes().all(|byte| byte.is_ascii_digit())
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientPayloadValidationContext<'a> {
    pub collection_id: &'a str,
    pub point_id: &'a str,
    pub field_path: &'a str,
    pub expected_key_id: Option<&'a str>,
    pub expected_rk_id: Option<&'a str>,
    pub min_rk_epoch: Option<u64>,
    pub max_rk_epoch: Option<u64>,
    pub key_id_required: bool,
    pub signature_required: bool,
    pub signature_verification: Option<ClientPayloadSignatureVerification<'a>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientPayloadSignatureVerification<'a> {
    pub expected_key_id: &'a str,
    pub public_key: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientPayloadNonceReplayKey {
    key_id: String,
    rk_id: String,
    rk_epoch: u64,
    nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientPayloadEnvelopeKey {
    collection_id: String,
    point_id: String,
    field_path: String,
    key_id: String,
    rk_id: String,
    rk_epoch: u64,
    nonce: String,
    ciphertext_sha256_b64: String,
    signature_key_id: String,
    signature_sha256_b64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientPayloadVerifiedEnvelopeKey {
    envelope_key: ClientPayloadEnvelopeKey,
}

impl ClientPayloadNonceReplayKey {
    pub fn cache_key(&self) -> String {
        format!(
            "{}\x1f{}\x1f{}\x1f{}",
            self.key_id, self.rk_id, self.rk_epoch, self.nonce,
        )
    }

    pub fn cache_key_for_collection(&self, collection_crypto_id: &str) -> String {
        format!("{}\x1f{}", collection_crypto_id, self.cache_key())
    }

    pub fn validate_cache_key_for_collection(
        cache_key: &str,
    ) -> Result<(), PayloadEncryptionError> {
        let mut parts = cache_key.split('\x1f');
        let Some(collection_crypto_id) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        let Some(key_id) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        let Some(rk_id) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        let Some(rk_epoch) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        let Some(nonce) = parts.next() else {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        };
        if parts.next().is_some()
            || collection_crypto_id.is_empty()
            || key_id.is_empty()
            || rk_id.is_empty()
            || rk_epoch.is_empty()
            || nonce.is_empty()
        {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        }
        validate_resource_key_id(key_id)?;
        validate_resource_key_id(rk_id)?;
        rk_epoch
            .parse::<u64>()
            .map_err(|_| PayloadEncryptionError::MalformedClientNonceReplayCacheKey)?;
        let nonce = BASE64URL_NOPAD
            .decode(nonce.as_bytes())
            .map_err(|_| PayloadEncryptionError::MalformedClientNonceReplayCacheKey)?;
        if nonce.len() != 12 {
            return Err(PayloadEncryptionError::MalformedClientNonceReplayCacheKey);
        }

        Ok(())
    }
}

impl ClientPayloadVerifiedEnvelopeKey {
    pub fn envelope_key(&self) -> &ClientPayloadEnvelopeKey {
        &self.envelope_key
    }
}

impl PayloadTextEncryptor {
    pub fn new_from_resource_key(
        collection: impl Into<String>,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
    ) -> Result<Self, PayloadEncryptionError> {
        let payload_key = resource_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)?;
        Self::new_with_derived_cipher_unchecked(collection, AeadCipher::new(key_id, payload_key)?)
    }

    pub fn new_from_resource_key_with_material_fingerprint(
        collection: impl Into<String>,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
    ) -> Result<Self, PayloadEncryptionError> {
        let payload_key = resource_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)?;
        Self::new_with_derived_cipher_unchecked(
            collection,
            AeadCipher::new_with_material_fingerprint(
                key_id,
                payload_key,
                material_fingerprint_id,
            )?,
        )
    }

    pub fn new_from_resource_key_with_metadata(
        collection: impl Into<String>,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
        rk_id: impl Into<String>,
        rk_epoch: u64,
    ) -> Result<Self, PayloadEncryptionError> {
        let payload_key = resource_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)?;
        let cipher = AeadCipher::new_with_material_fingerprint(
            key_id,
            payload_key,
            material_fingerprint_id,
        )?
        .with_resource_key_metadata(rk_id, rk_epoch)?;
        Self::new_with_derived_cipher_unchecked(collection, cipher)
    }

    /// Builds an encryptor from an already domain-separated AEAD cipher.
    ///
    /// Runtime code that starts from a collection/rule resource key should use
    /// `new_from_resource_key*` so the payload-text HKDF domain is applied in
    /// one place.
    pub fn new_with_derived_cipher_unchecked(
        collection: impl Into<String>,
        cipher: AeadCipher,
    ) -> Result<Self, PayloadEncryptionError> {
        Self::new_with_derived_keyring_unchecked(collection, AeadKeyring::new(cipher))
    }

    /// Builds an encryptor from an already domain-separated AEAD keyring.
    ///
    /// Prefer `new_from_resource_key*` for production runtime code.
    pub fn new_with_derived_keyring_unchecked(
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

    pub fn with_retired_resource_key(
        mut self,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
    ) -> Result<Self, PayloadEncryptionError> {
        let payload_key = resource_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)?;
        let retired = AeadCipher::new_with_material_fingerprint(
            key_id,
            payload_key,
            material_fingerprint_id,
        )?;
        self.keyring = self.keyring.with_retired(retired);
        Ok(self)
    }

    pub fn with_retired_resource_key_metadata(
        mut self,
        key_id: impl Into<String>,
        resource_key: &SecretKey,
        material_fingerprint_id: impl Into<String>,
        rk_id: impl Into<String>,
        rk_epoch: u64,
    ) -> Result<Self, PayloadEncryptionError> {
        let payload_key = resource_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)?;
        let retired = AeadCipher::new_with_material_fingerprint(
            key_id,
            payload_key,
            material_fingerprint_id,
        )?
        .with_resource_key_metadata(rk_id, rk_epoch)?;
        self.keyring = self.keyring.with_retired(retired);
        Ok(self)
    }

    pub fn encrypt_selected_fields(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
    ) -> Result<usize, PayloadEncryptionError> {
        self.encrypt_selected_fields_with_mode(
            point_id,
            payload,
            policy,
            ExistingPayloadMode::SkipExisting,
        )
    }

    pub fn encrypt_selected_fields_with_mode(
        &self,
        point_id: &str,
        payload: &mut Map<String, Value>,
        policy: &PayloadEncryptionPolicy,
        existing_mode: ExistingPayloadMode,
    ) -> Result<usize, PayloadEncryptionError> {
        let mut encrypted = 0;

        for field in policy.fields() {
            let Some(value) = locate_path_mut(payload, field)? else {
                if policy.strict_missing_fields {
                    return Err(PayloadEncryptionError::MissingField(field.clone()));
                }
                continue;
            };

            if let Some(existing_envelope) = extract_envelope(value, field)? {
                match existing_mode {
                    ExistingPayloadMode::SkipExisting => continue,
                    ExistingPayloadMode::FailIfExisting => {
                        return Err(PayloadEncryptionError::AlreadyEncrypted(field.clone()));
                    }
                    ExistingPayloadMode::ReencryptIfStale => {
                        if existing_envelope.schema_version == self.crypto_schema_version
                            && existing_envelope.encryption_epoch == self.encryption_epoch
                            && existing_envelope.envelope.key_id == self.keyring.key_id()
                            && existing_envelope.envelope.material_fingerprint
                                == self.keyring.material_fingerprint()
                        {
                            continue;
                        }

                        let context =
                            EncryptionContext::payload_text(&self.collection, point_id, field);
                        let old_aad_suffix = payload_metadata_aad(
                            &existing_envelope.kind,
                            existing_envelope.schema_version,
                            existing_envelope.encryption_epoch,
                        );
                        let plaintext = self.keyring.decrypt_with_aad_suffix(
                            &existing_envelope.envelope,
                            context,
                            &old_aad_suffix,
                        )?;
                        let new_aad_suffix = payload_metadata_aad(
                            PAYLOAD_TEXT_KIND,
                            self.crypto_schema_version,
                            self.encryption_epoch,
                        );
                        let envelope = self.keyring.encrypt_with_aad_suffix(
                            &plaintext,
                            context,
                            &new_aad_suffix,
                        )?;
                        *value = stored_envelope_value(
                            envelope,
                            field,
                            self.crypto_schema_version,
                            self.encryption_epoch,
                        )?;
                        encrypted += 1;
                        continue;
                    }
                }
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

pub fn is_client_encrypted_payload_value(value: &Value) -> bool {
    extract_client_envelope(value, CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .map(|envelope| envelope.is_some())
        .unwrap_or(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerPayloadValidationContext<'a> {
    pub field_path: &'a str,
    pub key_id: Option<&'a str>,
    pub crypto_schema_version: u16,
    pub encryption_epoch: u64,
}

pub fn validate_server_payload_value_metadata(
    value: &Value,
    context: ServerPayloadValidationContext<'_>,
) -> Result<(), PayloadEncryptionError> {
    let envelope = extract_envelope(value, context.field_path)?.ok_or_else(|| {
        PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: context.field_path.to_string(),
            found: json_type_name(value),
        }
    })?;

    if envelope.schema_version != context.crypto_schema_version {
        return Err(PayloadEncryptionError::UnsupportedSchemaVersion(
            envelope.schema_version,
        ));
    }
    if envelope.encryption_epoch != context.encryption_epoch {
        return Err(PayloadEncryptionError::EncryptionEpochMismatch);
    }
    validate_encrypted_envelope_metadata(&envelope.envelope)?;
    if let Some(key_id) = context.key_id
        && envelope.envelope.key_id != key_id
    {
        return Err(PayloadEncryptionError::Crypto(EncryptionError::KeyMismatch));
    }

    Ok(())
}

pub fn validate_client_payload_value(
    value: &Value,
    context: ClientPayloadValidationContext<'_>,
) -> Result<(), PayloadEncryptionError> {
    let envelope = extract_client_envelope(value, context.field_path)?.ok_or_else(|| {
        PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: context.field_path.to_string(),
            found: json_type_name(value),
        }
    })?;

    if envelope.version != CRYPTO_SCHEMA_VERSION {
        return Err(PayloadEncryptionError::UnsupportedSchemaVersion(
            envelope.version,
        ));
    }
    if envelope.kind != PAYLOAD_TEXT_KIND {
        return Err(PayloadEncryptionError::UnsupportedEnvelopeKind(
            envelope.kind,
        ));
    }
    if envelope.algorithm != CLIENT_PAYLOAD_ALGORITHM {
        return Err(PayloadEncryptionError::UnsupportedClientAlgorithm(
            envelope.algorithm,
        ));
    }
    if context.key_id_required && envelope.key_id.as_deref().is_none_or(str::is_empty) {
        return Err(PayloadEncryptionError::MissingClientKeyId);
    }
    if let Some(key_id) = envelope.key_id.as_deref() {
        validate_resource_key_id(key_id)?;
    }
    if let Some(expected_key_id) = context.expected_key_id {
        if envelope.key_id.as_deref() != Some(expected_key_id) {
            return Err(PayloadEncryptionError::ClientKeyIdMismatch);
        }
    }
    let rk_id = envelope
        .rk_id
        .as_deref()
        .ok_or_else(|| PayloadEncryptionError::MalformedEnvelope(context.field_path.to_string()))?;
    if rk_id.is_empty() {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            context.field_path.to_string(),
        ));
    }
    validate_resource_key_id(rk_id)?;
    if let Some(expected_rk_id) = context.expected_rk_id
        && rk_id != expected_rk_id
    {
        return Err(PayloadEncryptionError::ClientResourceKeyIdMismatch);
    }
    let rk_epoch = envelope
        .rk_epoch
        .ok_or_else(|| PayloadEncryptionError::MalformedEnvelope(context.field_path.to_string()))?;
    if context
        .min_rk_epoch
        .is_some_and(|min_rk_epoch| rk_epoch < min_rk_epoch)
        || context
            .max_rk_epoch
            .is_some_and(|max_rk_epoch| rk_epoch > max_rk_epoch)
    {
        return Err(PayloadEncryptionError::ClientResourceKeyEpochMismatch);
    }
    if envelope.kdf_domain.as_deref() != Some(CLIENT_PAYLOAD_KDF_DOMAIN) {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            context.field_path.to_string(),
        ));
    }
    if envelope.aad.collection_id != context.collection_id {
        return Err(PayloadEncryptionError::ClientEnvelopeAadMismatch(
            "collection_id".to_string(),
        ));
    }
    if envelope.aad.point_id != context.point_id {
        return Err(PayloadEncryptionError::ClientEnvelopeAadMismatch(
            "point_id".to_string(),
        ));
    }
    if envelope.aad.field_path != context.field_path {
        return Err(PayloadEncryptionError::ClientEnvelopeAadMismatch(
            "field_path".to_string(),
        ));
    }
    if envelope.aad.schema_version != CRYPTO_SCHEMA_VERSION {
        return Err(PayloadEncryptionError::UnsupportedSchemaVersion(
            envelope.aad.schema_version,
        ));
    }
    let nonce = BASE64URL_NOPAD
        .decode(envelope.nonce.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(context.field_path.to_string()))?;
    if nonce.len() != 12 {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            context.field_path.to_string(),
        ));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(context.field_path.to_string()))?;
    if ciphertext.len() < 16 {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            context.field_path.to_string(),
        ));
    }
    validate_client_payload_signature(
        &envelope,
        context.signature_required,
        context.signature_verification,
    )?;

    Ok(())
}

pub fn validate_client_payload_value_for_runtime(
    value: &Value,
    context: ClientPayloadValidationContext<'_>,
) -> Result<ClientPayloadVerifiedEnvelopeKey, PayloadEncryptionError> {
    if context.signature_verification.is_none() {
        return Err(PayloadEncryptionError::InvalidClientSignature);
    }
    validate_client_payload_value(value, context)?;
    let envelope_key =
        client_payload_envelope_key(value, context.field_path)?.ok_or_else(|| {
            PayloadEncryptionError::ExpectedEncryptedEnvelope {
                field: context.field_path.to_string(),
                found: json_type_name(value),
            }
        })?;

    Ok(ClientPayloadVerifiedEnvelopeKey { envelope_key })
}

pub fn client_payload_envelope_key(
    value: &Value,
    field_path: &str,
) -> Result<Option<ClientPayloadEnvelopeKey>, PayloadEncryptionError> {
    let Some(envelope) = extract_client_envelope(value, field_path)? else {
        return Ok(None);
    };
    let Some(key_id) = envelope.key_id else {
        return Ok(None);
    };
    let Some(rk_id) = envelope.rk_id else {
        return Ok(None);
    };
    let Some(rk_epoch) = envelope.rk_epoch else {
        return Ok(None);
    };
    let Some(signature) = envelope.signature else {
        return Ok(None);
    };
    let ciphertext = BASE64URL_NOPAD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    let ciphertext_digest = Sha256::digest(&ciphertext);
    let ciphertext_sha256_b64 = BASE64URL_NOPAD.encode(ciphertext_digest.as_ref());
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    let signature_digest = Sha256::digest(&signature_bytes);
    let signature_sha256_b64 = BASE64URL_NOPAD.encode(signature_digest.as_ref());

    Ok(Some(ClientPayloadEnvelopeKey {
        collection_id: envelope.aad.collection_id,
        point_id: envelope.aad.point_id,
        field_path: envelope.aad.field_path,
        key_id,
        rk_id,
        rk_epoch,
        nonce: envelope.nonce,
        ciphertext_sha256_b64,
        signature_key_id: signature.key_id,
        signature_sha256_b64,
    }))
}

pub fn client_payload_signature_message(
    value: &Value,
    field_path: &str,
) -> Result<Vec<u8>, PayloadEncryptionError> {
    let envelope = extract_client_envelope(value, field_path)?.ok_or_else(|| {
        PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: field_path.to_string(),
            found: json_type_name(value),
        }
    })?;
    if envelope.signature.is_none() {
        return Err(PayloadEncryptionError::MissingClientSignature);
    }
    Ok(client_payload_signature_message_for_envelope(&envelope))
}

pub fn client_payload_signature_key_id(
    value: &Value,
    field_path: &str,
) -> Result<Option<String>, PayloadEncryptionError> {
    let envelope = extract_client_envelope(value, field_path)?.ok_or_else(|| {
        PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: field_path.to_string(),
            found: json_type_name(value),
        }
    })?;
    let Some(signature) = envelope.signature else {
        return Ok(None);
    };
    if signature.key_id.is_empty() {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            envelope.aad.field_path,
        ));
    }
    validate_resource_key_id(&signature.key_id)?;

    Ok(Some(signature.key_id))
}

pub fn client_payload_nonce_replay_key(
    value: &Value,
    field_path: &str,
) -> Result<Option<ClientPayloadNonceReplayKey>, PayloadEncryptionError> {
    let Some(envelope) = extract_client_envelope(value, field_path)? else {
        return Ok(None);
    };
    let key_id = envelope
        .key_id
        .ok_or(PayloadEncryptionError::MissingClientKeyId)?;
    if key_id.is_empty() {
        return Err(PayloadEncryptionError::MissingClientKeyId);
    }
    validate_resource_key_id(&key_id)?;
    let rk_id = envelope
        .rk_id
        .ok_or_else(|| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    if rk_id.is_empty() {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            field_path.to_string(),
        ));
    }
    validate_resource_key_id(&rk_id)?;
    let rk_epoch = envelope
        .rk_epoch
        .ok_or_else(|| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    let nonce = BASE64URL_NOPAD
        .decode(envelope.nonce.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field_path.to_string()))?;
    if nonce.len() != 12 {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            field_path.to_string(),
        ));
    }

    Ok(Some(ClientPayloadNonceReplayKey {
        key_id,
        rk_id,
        rk_epoch,
        nonce: envelope.nonce,
    }))
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ClientPayloadEnvelope {
    version: u16,
    kind: String,
    algorithm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rk_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rk_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf_domain: Option<String>,
    aad: ClientPayloadAad,
    nonce: String,
    ciphertext: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<ClientPayloadSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ClientPayloadAad {
    collection_id: String,
    point_id: String,
    field_path: String,
    #[serde(default = "default_crypto_schema_version")]
    schema_version: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ClientPayloadSignature {
    alg: String,
    key_id: String,
    sig: String,
}

fn validate_client_payload_signature(
    envelope: &ClientPayloadEnvelope,
    signature_required: bool,
    signature_verification: Option<ClientPayloadSignatureVerification<'_>>,
) -> Result<(), PayloadEncryptionError> {
    let Some(signature) = &envelope.signature else {
        return if signature_required || signature_verification.is_some() {
            Err(PayloadEncryptionError::MissingClientSignature)
        } else {
            Ok(())
        };
    };

    if signature.alg != CLIENT_PAYLOAD_SIGNATURE_ALGORITHM {
        return Err(PayloadEncryptionError::UnsupportedClientSignatureAlgorithm(
            signature.alg.clone(),
        ));
    }
    if signature.key_id.is_empty() {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            envelope.aad.field_path.clone(),
        ));
    }
    validate_resource_key_id(&signature.key_id)?;
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.sig.as_bytes())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(envelope.aad.field_path.clone()))?;
    if signature_bytes.len() != 64 {
        return Err(PayloadEncryptionError::MalformedEnvelope(
            envelope.aad.field_path.clone(),
        ));
    }

    if let Some(verification) = signature_verification {
        if signature.key_id != verification.expected_key_id {
            return Err(PayloadEncryptionError::ClientSignatureKeyIdMismatch);
        }
        if verification.public_key.len() != 32 {
            return Err(PayloadEncryptionError::InvalidClientSignature);
        }
        let message = client_payload_signature_message_for_envelope(envelope);
        UnparsedPublicKey::new(&ED25519, verification.public_key)
            .verify(&message, &signature_bytes)
            .map_err(|_| PayloadEncryptionError::InvalidClientSignature)?;
    }

    Ok(())
}

fn client_payload_signature_message_for_envelope(envelope: &ClientPayloadEnvelope) -> Vec<u8> {
    let mut message = Vec::new();
    push_len_prefixed(&mut message, CLIENT_PAYLOAD_SIGNATURE_DOMAIN.as_bytes());
    push_u16(&mut message, envelope.version);
    push_len_prefixed(&mut message, envelope.kind.as_bytes());
    push_len_prefixed(&mut message, envelope.algorithm.as_bytes());
    push_optional_string(&mut message, envelope.key_id.as_deref());
    push_optional_string(&mut message, envelope.rk_id.as_deref());
    push_optional_u64(&mut message, envelope.rk_epoch);
    push_optional_string(&mut message, envelope.kdf_domain.as_deref());
    push_len_prefixed(&mut message, envelope.aad.collection_id.as_bytes());
    push_len_prefixed(&mut message, envelope.aad.point_id.as_bytes());
    push_len_prefixed(&mut message, envelope.aad.field_path.as_bytes());
    push_u16(&mut message, envelope.aad.schema_version);
    push_len_prefixed(&mut message, envelope.nonce.as_bytes());
    push_len_prefixed(&mut message, envelope.ciphertext.as_bytes());
    if let Some(signature) = &envelope.signature {
        push_len_prefixed(&mut message, signature.alg.as_bytes());
        push_len_prefixed(&mut message, signature.key_id.as_bytes());
    } else {
        push_len_prefixed(&mut message, &[]);
        push_len_prefixed(&mut message, &[]);
    }
    message
}

fn push_len_prefixed(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u32).to_be_bytes());
    message.extend_from_slice(value);
}

fn push_optional_string(message: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            message.push(1);
            push_len_prefixed(message, value.as_bytes());
        }
        None => message.push(0),
    }
}

fn push_optional_u64(message: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            message.push(1);
            message.extend_from_slice(&value.to_be_bytes());
        }
        None => message.push(0),
    }
}

fn push_u16(message: &mut Vec<u8>, value: u16) {
    message.extend_from_slice(&value.to_be_bytes());
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

fn extract_client_envelope(
    value: &Value,
    field: &str,
) -> Result<Option<ClientPayloadEnvelope>, PayloadEncryptionError> {
    let Value::Object(object) = value else {
        return Ok(None);
    };
    let Some(envelope) = object.get(CLIENT_ENCRYPTED_PAYLOAD_MARKER) else {
        return Ok(None);
    };
    if object.len() != 1 {
        return Err(PayloadEncryptionError::MalformedEnvelope(field.to_string()));
    }

    let envelope: ClientPayloadEnvelope = serde_json::from_value(envelope.clone())
        .map_err(|_| PayloadEncryptionError::MalformedEnvelope(field.to_string()))?;

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
