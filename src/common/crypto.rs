use std::fs;

use collection::config::{
    CkksCollectionConfig, CollectionEncryptionConfig, CollectionParams, EncryptionSelector,
};
use data_encoding::BASE64URL_NOPAD;
use qdrant_ckks::{
    AeadCipher, CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CKKS_VECTOR_KEY_DOMAIN,
    CLIENT_PAYLOAD_ENVELOPE_BINDING, ClientPayloadSignatureVerification,
    ClientPayloadValidationContext, ExistingPayloadMode, LocalMasterKeyProvider, MasterKeyProvider,
    PAYLOAD_AES_GCM_PROVIDER, PAYLOAD_CLIENT_AEAD_PROVIDER, PayloadEncryptionError,
    PayloadEncryptionPolicy, PayloadTextEncryptor, RESOURCE_KEY_WRAP_ALGORITHM, SecretKey,
    VECTOR_OPENFHE_CKKS_PROVIDER, WrappedKeyBlob, client_payload_signature_key_id,
    rewrap_resource_key, validate_client_payload_value,
};
use segment::json_path::JsonPath;
use segment::types::Payload;
use serde_json::Value;
use storage::content_manager::collection_meta_ops::CreateCollection;
use storage::content_manager::errors::StorageError;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::settings::{
    CryptoBackendConfig, CryptoInstanceConfig, CryptoMaterialConfig, CryptoSettings, Settings,
};

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CryptoSetupError {
    #[error("crypto material {material} must specify exactly one source")]
    InvalidMaterialSourceCount { material: String },
    #[error("crypto material {material} has unsupported source {material_source}")]
    UnsupportedMaterialSource {
        material: String,
        material_source: String,
    },
    #[error("crypto material {material} source does not match configured fields")]
    MaterialSourceMismatch { material: String },
    #[error("crypto material {material} wrapped resource key config is invalid: {reason}")]
    InvalidWrappedMaterial { material: String, reason: String },
    #[error("crypto material {material} references unknown wrapping key material {wrapped_by}")]
    UnknownWrappingMaterial {
        material: String,
        wrapped_by: String,
    },
    #[error(
        "crypto material {material} wrapping key material {wrapped_by} has unsupported kind {kind}"
    )]
    UnsupportedWrappingMaterialKind {
        material: String,
        wrapped_by: String,
        kind: String,
    },
    #[error("crypto material {material} uses unsupported wrap algorithm {algorithm}")]
    UnsupportedWrapAlgorithm { material: String, algorithm: String },
    #[error("crypto material {material} uses inline key material but inline material is disabled")]
    InlineMaterialDisabled { material: String },
    #[error("crypto backend {backend} of kind {kind} requires program")]
    MissingBackendProgram { backend: String, kind: String },
    #[error("crypto backend {backend} program path is invalid: {program}")]
    InvalidBackendProgram { backend: String, program: String },
    #[error("crypto backend {backend} size is invalid: {reason}")]
    InvalidBackendSize { backend: String, reason: String },
    #[error(
        "crypto instance {instance} references unknown material {material_ref} for role {role}"
    )]
    UnknownMaterial {
        instance: String,
        role: String,
        material_ref: String,
    },
    #[error("crypto instance {instance} references unknown backend {backend_ref}")]
    UnknownBackend {
        instance: String,
        backend_ref: String,
    },
    #[error(transparent)]
    LegacyCkks(#[from] crate::common::ckks::CkksSetupError),
}

const PAYLOAD_SYM_KEY_ROLE: &str = "sym_key";
const SYMMETRIC_KEY_32_KIND: &str = "symmetric_key_32";
const WRAPPING_KEY_32_KIND: &str = "wrapping_key_32";
const WRAPPED_SYMMETRIC_KEY_32_KIND: &str = "wrapped_symmetric_key_32";
const MATERIAL_FINGERPRINT_ID_OPTION: &str = "material_fingerprint_id";
const KEY_ID_REQUIRED_OPTION: &str = "key_id_required";
const SIGNATURE_PUBLIC_KEY_B64_OPTION: &str = "signature_public_key_b64";
const SIGNATURE_PUBLIC_KEYS_OPTION: &str = "signature_public_keys";
const SIGNATURE_KEY_ID_OPTION: &str = "signature_key_id";
const CKKS_PROFILE_OPTION: &str = "profile";

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PayloadWriteSetupError {
    #[error("collection {collection} references unknown payload crypto instance {instance}")]
    UnknownInstance {
        collection: String,
        instance: String,
    },
    #[error(
        "collection {collection} rule {rule_id} uses unsupported provider {provider} for payload encryption"
    )]
    UnsupportedProvider {
        collection: String,
        rule_id: String,
        provider: String,
    },
    #[error("collection {collection} client payload rule {rule_id} must use binding {binding}")]
    InvalidClientEnvelopeBinding {
        collection: String,
        rule_id: String,
        binding: String,
    },
    #[error("payload crypto instance {instance} must bind role {role} to a symmetric key material")]
    MissingMaterialBinding { instance: String, role: String },
    #[error("payload crypto instance {instance} key_id option must be a string")]
    InvalidInstanceKeyId { instance: String },
    #[error("payload crypto instance {instance} signature_key_id option must be a string")]
    InvalidClientSignatureKeyId { instance: String },
    #[error(
        "payload crypto instance {instance} signature_public_key_b64 option must be a base64url Ed25519 public key"
    )]
    InvalidClientSignaturePublicKey { instance: String },
    #[error(
        "payload crypto instance {instance} signature_public_keys option must be an object mapping signature key ids to base64url Ed25519 public keys"
    )]
    InvalidClientSignaturePublicKeys { instance: String },
    #[error(
        "payload crypto instance {instance} must not mix signature_public_keys with signature_key_id/signature_public_key_b64"
    )]
    MixedClientSignatureKeyConfig { instance: String },
    #[error(
        "payload crypto instance {instance} must set signature_key_id when signature_public_key_b64 is set"
    )]
    MissingClientSignatureKeyId { instance: String },
    #[error(
        "payload crypto instance {instance} must set signature_public_key_b64 when signature_key_id is set"
    )]
    MissingClientSignaturePublicKey { instance: String },
    #[error("payload crypto instance {instance} material_fingerprint_id option must be a string")]
    InvalidInstanceMaterialFingerprintId { instance: String },
    #[error("payload crypto instance {instance} must set material_fingerprint_id")]
    MissingMaterialFingerprintId { instance: String },
    #[error("collection {collection} payload encryption is missing a key id")]
    MissingKeyId { collection: String },
    #[error(
        "collection {collection} key id does not match payload crypto instance {instance} key id"
    )]
    CollectionKeyMismatch {
        collection: String,
        instance: String,
    },
    #[error("payload crypto material {material} uses unsupported kind {kind}")]
    UnsupportedMaterialKind { material: String, kind: String },
    #[error(
        "payload crypto material {material} references unknown wrapping key material {wrapped_by}"
    )]
    UnknownWrappingMaterial {
        material: String,
        wrapped_by: String,
    },
    #[error(
        "payload crypto material {material} wrapping key material {wrapped_by} has unsupported kind {kind}"
    )]
    UnsupportedWrappingMaterialKind {
        material: String,
        wrapped_by: String,
        kind: String,
    },
    #[error("payload crypto material {material} wrapped resource key config is invalid: {reason}")]
    InvalidWrappedMaterial { material: String, reason: String },
    #[error("payload crypto material {material} uses unsupported wrap algorithm {algorithm}")]
    UnsupportedWrapAlgorithm { material: String, algorithm: String },
    #[error("payload crypto material {material} is missing environment variable {env}")]
    MissingMaterialEnv { material: String, env: String },
    #[error("payload crypto material {material} file path is missing")]
    MissingMaterialPath { material: String },
    #[error("payload crypto material {material} inline value is missing")]
    MissingInlineMaterial { material: String },
    #[error("payload crypto material {material} file {path} could not be read")]
    UnreadableMaterialFile { material: String, path: String },
    #[error("payload crypto material {material} must be base64url without padding")]
    InvalidMaterialEncoding { material: String },
    #[error("payload crypto material {material} must decode to exactly 32 bytes")]
    InvalidMaterialLength { material: String },
    #[error(transparent)]
    LegacyCkks(#[from] crate::common::ckks::CkksSetupError),
    #[error(transparent)]
    Payload(#[from] PayloadEncryptionError),
}

enum PayloadWriteRule {
    ServerEncrypt {
        encryptor: PayloadTextEncryptor,
        policy: PayloadEncryptionPolicy,
    },
    ClientEnvelope {
        policy: PayloadEncryptionPolicy,
        expected_key_id: Option<String>,
        key_id_required: bool,
        signature_verifier: Option<ClientPayloadSignatureVerifier>,
    },
}

enum ClientPayloadSignatureVerifier {
    Single { key_id: String, public_key: Vec<u8> },
    Registry(std::collections::HashMap<String, Vec<u8>>),
}

impl ClientPayloadSignatureVerifier {
    fn verification_for_value<'a>(
        &'a self,
        value: &Value,
        field: &str,
    ) -> Result<ClientPayloadSignatureVerification<'a>, PayloadWriteSetupError> {
        match self {
            Self::Single { key_id, public_key } => Ok(ClientPayloadSignatureVerification {
                expected_key_id: key_id,
                public_key,
            }),
            Self::Registry(public_keys) => {
                let signature_key_id = client_payload_signature_key_id(value, field)?
                    .ok_or(PayloadEncryptionError::MissingClientSignature)?;
                let Some((expected_key_id, public_key)) =
                    public_keys.get_key_value(&signature_key_id)
                else {
                    return Err(PayloadWriteSetupError::Payload(
                        PayloadEncryptionError::ClientSignatureKeyIdMismatch,
                    ));
                };
                Ok(ClientPayloadSignatureVerification {
                    expected_key_id,
                    public_key,
                })
            }
        }
    }
}

pub struct PayloadWritePlan {
    collection_crypto_id: String,
    rules: Vec<PayloadWriteRule>,
}

impl PayloadWritePlan {
    pub fn encrypt_payload(
        &self,
        point_id: &str,
        payload: &mut Payload,
    ) -> Result<usize, PayloadWriteSetupError> {
        let mut encrypted = 0;

        for rule in &self.rules {
            match rule {
                PayloadWriteRule::ServerEncrypt { encryptor, policy } => {
                    encrypted += encryptor.encrypt_selected_fields_with_mode(
                        point_id,
                        &mut payload.0,
                        policy,
                        ExistingPayloadMode::FailIfExisting,
                    )?;
                }
                PayloadWriteRule::ClientEnvelope {
                    policy,
                    expected_key_id,
                    key_id_required,
                    signature_verifier,
                } => {
                    for field in policy.fields() {
                        let encrypted_path = field.parse::<JsonPath>().map_err(|_| {
                            PayloadWriteSetupError::Payload(
                                PayloadEncryptionError::InvalidFieldPath(field.clone()),
                            )
                        })?;
                        for value in encrypted_path.value_get(&payload.0) {
                            let signature_verification = signature_verifier
                                .as_ref()
                                .map(|verifier| verifier.verification_for_value(value, field))
                                .transpose()?;
                            validate_client_payload_value(
                                value,
                                ClientPayloadValidationContext {
                                    collection_id: &self.collection_crypto_id,
                                    point_id,
                                    field_path: field,
                                    expected_key_id: expected_key_id.as_deref(),
                                    key_id_required: *key_id_required,
                                    signature_verification,
                                },
                            )?;
                            encrypted += 1;
                        }
                    }
                }
            }
        }

        Ok(encrypted)
    }

    pub fn reencrypt_payload_if_stale(
        &self,
        point_id: &str,
        payload: &mut Payload,
    ) -> Result<usize, PayloadWriteSetupError> {
        let mut encrypted = 0;

        for rule in &self.rules {
            match rule {
                PayloadWriteRule::ServerEncrypt { encryptor, policy } => {
                    encrypted += encryptor.encrypt_selected_fields_with_mode(
                        point_id,
                        &mut payload.0,
                        policy,
                        ExistingPayloadMode::ReencryptIfStale,
                    )?;
                }
                PayloadWriteRule::ClientEnvelope {
                    policy,
                    expected_key_id,
                    key_id_required,
                    signature_verifier,
                } => {
                    for field in policy.fields() {
                        let encrypted_path = field.parse::<JsonPath>().map_err(|_| {
                            PayloadWriteSetupError::Payload(
                                PayloadEncryptionError::InvalidFieldPath(field.clone()),
                            )
                        })?;
                        for value in encrypted_path.value_get(&payload.0) {
                            let signature_verification = signature_verifier
                                .as_ref()
                                .map(|verifier| verifier.verification_for_value(value, field))
                                .transpose()?;
                            validate_client_payload_value(
                                value,
                                ClientPayloadValidationContext {
                                    collection_id: &self.collection_crypto_id,
                                    point_id,
                                    field_path: field,
                                    expected_key_id: expected_key_id.as_deref(),
                                    key_id_required: *key_id_required,
                                    signature_verification,
                                },
                            )?;
                        }
                    }
                }
            }
        }

        Ok(encrypted)
    }

    pub fn touches_selected_fields(&self, payload: &Payload, key: Option<&JsonPath>) -> bool {
        self.rules.iter().any(|rule| {
            rule.policy().fields().iter().any(|field| {
                let Ok(encrypted_path) = field.parse::<JsonPath>() else {
                    return true;
                };

                if let Some(key) = key {
                    key.compatible(&encrypted_path)
                } else {
                    encrypted_path
                        .value_get(&payload.0)
                        .into_iter()
                        .next()
                        .is_some()
                }
            })
        })
    }
}

impl PayloadWriteRule {
    fn policy(&self) -> &PayloadEncryptionPolicy {
        match self {
            Self::ServerEncrypt { policy, .. } | Self::ClientEnvelope { policy, .. } => policy,
        }
    }
}

pub fn payload_write_plan_for_collection(
    settings: &Settings,
    collection_name: &str,
    params: &CollectionParams,
) -> Result<Option<PayloadWritePlan>, PayloadWriteSetupError> {
    payload_write_plan_for_collection_with_crypto_id(
        settings,
        collection_name,
        collection_name,
        params,
    )
}

pub fn payload_write_plan_for_collection_with_crypto_id(
    settings: &Settings,
    collection_name: &str,
    collection_crypto_id: &str,
    params: &CollectionParams,
) -> Result<Option<PayloadWritePlan>, PayloadWriteSetupError> {
    if let Some(encryption) = &params.encryption {
        return generic_payload_write_plan(
            &effective_settings(settings),
            collection_name,
            collection_crypto_id,
            encryption,
        );
    }

    let Some(ckks) = params.ckks.as_ref() else {
        return Ok(None);
    };

    if settings.ckks.is_configured() {
        let Some((encryptor, policy)) = crate::common::ckks::payload_text_encryptor_for_collection(
            &settings.ckks,
            collection_name,
            Some(ckks),
        )?
        else {
            return Ok(None);
        };

        return Ok(Some(PayloadWritePlan {
            collection_crypto_id: collection_name.to_string(),
            rules: vec![PayloadWriteRule::ServerEncrypt { encryptor, policy }],
        }));
    }

    let Some(encryption) = CollectionEncryptionConfig::from_legacy_ckks(ckks) else {
        return Ok(None);
    };
    generic_payload_write_plan(
        &effective_settings(settings),
        collection_name,
        collection_crypto_id,
        &encryption,
    )
}

pub fn validate_create_collection_crypto_runtime(
    settings: &Settings,
    collection_name: &str,
    create_collection: &CreateCollection,
) -> Result<(), StorageError> {
    let params = CollectionParams {
        encryption: create_collection.encryption.clone(),
        ckks: create_collection.ckks.clone(),
        ..CollectionParams::empty()
    };
    validate_collection_crypto_runtime(settings, collection_name, &params)
}

pub fn validate_collection_crypto_runtime(
    settings: &Settings,
    collection_name: &str,
    params: &CollectionParams,
) -> Result<(), StorageError> {
    if let Some(encryption) = &params.encryption {
        return validate_generic_collection_crypto_runtime(
            &effective_settings(settings),
            collection_name,
            encryption,
        );
    }

    let Some(ckks) = params.ckks.as_ref() else {
        return Ok(());
    };

    if settings.ckks.is_configured() {
        return validate_legacy_collection_crypto_runtime(&settings.ckks, collection_name, ckks);
    }

    let Some(encryption) = CollectionEncryptionConfig::from_legacy_ckks(ckks) else {
        return Ok(());
    };
    validate_generic_collection_crypto_runtime(
        &effective_settings(settings),
        collection_name,
        &encryption,
    )
}

pub fn effective_settings(settings: &Settings) -> CryptoSettings {
    if settings.crypto.is_configured() {
        settings.crypto.clone()
    } else {
        CryptoSettings::from_legacy_ckks(&settings.ckks)
    }
}

pub fn validate_runtime_config(settings: &Settings) -> Result<(), CryptoSetupError> {
    if settings.crypto.is_configured() {
        validate_crypto_settings(&settings.crypto)?;
    }
    if settings.ckks.is_configured() {
        crate::common::ckks::validate_runtime_config(&settings.ckks)?;
    }

    Ok(())
}

fn validate_crypto_settings(settings: &CryptoSettings) -> Result<(), CryptoSetupError> {
    for (material_name, material) in &settings.materials {
        validate_material(material_name, material, settings.allow_inline_key_material)?;
    }

    for (material_name, material) in &settings.materials {
        if material.kind != WRAPPED_SYMMETRIC_KEY_32_KIND {
            continue;
        }

        let wrapped_by = material.wrapped_by.as_deref().ok_or_else(|| {
            CryptoSetupError::InvalidWrappedMaterial {
                material: material_name.clone(),
                reason: "missing wrapped_by".to_string(),
            }
        })?;
        let Some(wrapping_material) = settings.materials.get(wrapped_by) else {
            return Err(CryptoSetupError::UnknownWrappingMaterial {
                material: material_name.clone(),
                wrapped_by: wrapped_by.to_string(),
            });
        };
        if wrapping_material.kind != WRAPPING_KEY_32_KIND {
            return Err(CryptoSetupError::UnsupportedWrappingMaterialKind {
                material: material_name.clone(),
                wrapped_by: wrapped_by.to_string(),
                kind: wrapping_material.kind.clone(),
            });
        }
    }

    for (backend_name, backend) in &settings.backends {
        validate_backend(backend_name, backend)?;
    }

    for (instance_name, instance) in &settings.instances {
        for (role, material_ref) in &instance.materials {
            if !settings.materials.contains_key(material_ref) {
                return Err(CryptoSetupError::UnknownMaterial {
                    instance: instance_name.clone(),
                    role: role.clone(),
                    material_ref: material_ref.clone(),
                });
            }
        }

        if let Some(backend_ref) = &instance.backend_ref
            && !settings.backends.contains_key(backend_ref)
        {
            return Err(CryptoSetupError::UnknownBackend {
                instance: instance_name.clone(),
                backend_ref: backend_ref.clone(),
            });
        }
    }

    Ok(())
}

fn validate_material(
    material_name: &str,
    material: &CryptoMaterialConfig,
    allow_inline_key_material: bool,
) -> Result<(), CryptoSetupError> {
    if material.kind == WRAPPED_SYMMETRIC_KEY_32_KIND {
        return validate_wrapped_resource_key_material(material_name, material);
    }

    if material.wrapped_by.is_some()
        || material.wrap_algorithm.is_some()
        || material.nonce.is_some()
        || material.wrapped_key_b64.is_some()
        || material.rk_epoch.is_some()
        || material.scope.is_some()
    {
        return Err(CryptoSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "wrapped key fields are only valid for wrapped_symmetric_key_32 materials"
                .to_string(),
        });
    }

    let configured_sources = usize::from(material.env.is_some())
        + usize::from(material.path.is_some())
        + usize::from(material.value_b64.is_some());

    if configured_sources != 1 {
        return Err(CryptoSetupError::InvalidMaterialSourceCount {
            material: material_name.to_string(),
        });
    }

    match material.source.as_deref() {
        None => Ok(()),
        Some("env")
            if material.env.is_some()
                && material.path.is_none()
                && material.value_b64.is_none() =>
        {
            Ok(())
        }
        Some("file")
            if material.path.is_some()
                && material.env.is_none()
                && material.value_b64.is_none() =>
        {
            Ok(())
        }
        Some("inline")
            if material.value_b64.is_some()
                && material.env.is_none()
                && material.path.is_none() =>
        {
            if allow_inline_key_material {
                Ok(())
            } else {
                Err(CryptoSetupError::InlineMaterialDisabled {
                    material: material_name.to_string(),
                })
            }
        }
        Some("env" | "file" | "inline") => Err(CryptoSetupError::MaterialSourceMismatch {
            material: material_name.to_string(),
        }),
        Some(source) => Err(CryptoSetupError::UnsupportedMaterialSource {
            material: material_name.to_string(),
            material_source: source.to_string(),
        }),
    }
}

fn validate_wrapped_resource_key_material(
    material_name: &str,
    material: &CryptoMaterialConfig,
) -> Result<(), CryptoSetupError> {
    if material.source.is_some()
        || material.env.is_some()
        || material.path.is_some()
        || material.value_b64.is_some()
    {
        return Err(CryptoSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "wrapped resource keys must not configure direct source/env/path/value_b64"
                .to_string(),
        });
    }

    if material.wrapped_by.is_none() {
        return Err(CryptoSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "missing wrapped_by".to_string(),
        });
    }
    if material.nonce.is_none() {
        return Err(CryptoSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "missing nonce".to_string(),
        });
    }
    if material.wrapped_key_b64.is_none() {
        return Err(CryptoSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "missing wrapped_key_b64".to_string(),
        });
    }
    if material.rk_epoch.is_none() {
        return Err(CryptoSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "missing rk_epoch".to_string(),
        });
    }
    if material.scope.as_deref().is_none_or(str::is_empty) {
        return Err(CryptoSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "missing scope".to_string(),
        });
    }

    let algorithm = material
        .wrap_algorithm
        .as_deref()
        .unwrap_or(RESOURCE_KEY_WRAP_ALGORITHM);
    if algorithm != RESOURCE_KEY_WRAP_ALGORITHM {
        return Err(CryptoSetupError::UnsupportedWrapAlgorithm {
            material: material_name.to_string(),
            algorithm: algorithm.to_string(),
        });
    }

    Ok(())
}

fn validate_backend(
    backend_name: &str,
    backend: &CryptoBackendConfig,
) -> Result<(), CryptoSetupError> {
    match backend.kind.as_str() {
        "process_pool" => {
            if backend.size == Some(0) {
                return Err(CryptoSetupError::InvalidBackendSize {
                    backend: backend_name.to_string(),
                    reason: "process_pool size must be at least 1".to_string(),
                });
            }
        }
        "process" => {
            if backend.size.is_some_and(|size| size > 1) {
                return Err(CryptoSetupError::InvalidBackendSize {
                    backend: backend_name.to_string(),
                    reason: "process backend size must be omitted or 1".to_string(),
                });
            }
        }
        _ => {}
    }

    if matches!(backend.kind.as_str(), "process" | "process_pool") {
        let Some(program) = backend.program.as_deref() else {
            return Err(CryptoSetupError::MissingBackendProgram {
                backend: backend_name.to_string(),
                kind: backend.kind.clone(),
            });
        };
        crate::common::ckks::validate_bridge_path_with_sha256(
            program,
            backend.sha256_b64.as_deref(),
        )
        .map_err(|_| CryptoSetupError::InvalidBackendProgram {
            backend: backend_name.to_string(),
            program: program.to_string(),
        })?;
    }

    Ok(())
}

fn generic_payload_write_plan(
    runtime_settings: &CryptoSettings,
    collection_name: &str,
    collection_crypto_id: &str,
    encryption: &CollectionEncryptionConfig,
) -> Result<Option<PayloadWritePlan>, PayloadWriteSetupError> {
    let mut rules = Vec::new();

    for rule in &encryption.rules {
        let EncryptionSelector::PayloadPaths { paths } = &rule.selector else {
            continue;
        };
        let instance = runtime_settings
            .instances
            .get(&rule.instance)
            .ok_or_else(|| PayloadWriteSetupError::UnknownInstance {
                collection: collection_name.to_string(),
                instance: rule.instance.clone(),
            })?;
        let policy = PayloadEncryptionPolicy::new(paths.clone())?;
        match instance.provider.as_str() {
            PAYLOAD_AES_GCM_PROVIDER => {
                let material_ref =
                    instance
                        .materials
                        .get(PAYLOAD_SYM_KEY_ROLE)
                        .ok_or_else(|| PayloadWriteSetupError::MissingMaterialBinding {
                            instance: rule.instance.clone(),
                            role: PAYLOAD_SYM_KEY_ROLE.to_string(),
                        })?;
                let material = runtime_settings
                    .materials
                    .get(material_ref)
                    .ok_or_else(|| PayloadWriteSetupError::MissingMaterialBinding {
                        instance: rule.instance.clone(),
                        role: PAYLOAD_SYM_KEY_ROLE.to_string(),
                    })?;

                let key_id =
                    resolve_payload_key_id(collection_name, encryption, &rule.instance, instance)?;
                let resource_key = decode_resource_key(runtime_settings, material_ref, material)?;
                let material_fingerprint_id =
                    match instance.options.get(MATERIAL_FINGERPRINT_ID_OPTION) {
                        Some(material_fingerprint_id) => {
                            material_fingerprint_id.as_str().ok_or_else(|| {
                                PayloadWriteSetupError::InvalidInstanceMaterialFingerprintId {
                                    instance: rule.instance.clone(),
                                }
                            })?
                        }
                        None => {
                            return Err(PayloadWriteSetupError::MissingMaterialFingerprintId {
                                instance: rule.instance.clone(),
                            });
                        }
                    };
                let encryptor = if let Some(rk_epoch) = material.rk_epoch {
                    PayloadTextEncryptor::new_from_resource_key_with_metadata(
                        collection_crypto_id,
                        key_id,
                        &resource_key,
                        material_fingerprint_id,
                        material_ref.clone(),
                        rk_epoch,
                    )
                } else {
                    PayloadTextEncryptor::new_from_resource_key_with_material_fingerprint(
                        collection_crypto_id,
                        key_id,
                        &resource_key,
                        material_fingerprint_id,
                    )
                }?
                .with_encryption_epoch(encryption.encryption_epoch);

                rules.push(PayloadWriteRule::ServerEncrypt { encryptor, policy });
            }
            PAYLOAD_CLIENT_AEAD_PROVIDER => {
                if rule.binding.as_deref() != Some(CLIENT_PAYLOAD_ENVELOPE_BINDING) {
                    return Err(PayloadWriteSetupError::InvalidClientEnvelopeBinding {
                        collection: collection_name.to_string(),
                        rule_id: rule.id.clone(),
                        binding: CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string(),
                    });
                }
                let expected_key_id = resolve_optional_payload_key_id(
                    collection_name,
                    encryption,
                    &rule.instance,
                    instance,
                )?;
                let key_id_required = match instance.options.get(KEY_ID_REQUIRED_OPTION) {
                    None | Some(Value::Null) => true,
                    Some(Value::Bool(value)) => *value,
                    Some(_) => {
                        return Err(PayloadWriteSetupError::InvalidInstanceKeyId {
                            instance: rule.instance.clone(),
                        });
                    }
                };
                let signature_verifier =
                    client_payload_signature_verifier(instance, &rule.instance)?;
                rules.push(PayloadWriteRule::ClientEnvelope {
                    policy,
                    expected_key_id: expected_key_id.map(ToOwned::to_owned),
                    key_id_required,
                    signature_verifier,
                });
            }
            _ => {
                return Err(PayloadWriteSetupError::UnsupportedProvider {
                    collection: collection_name.to_string(),
                    rule_id: rule.id.clone(),
                    provider: instance.provider.clone(),
                });
            }
        }
    }

    if rules.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PayloadWritePlan {
            collection_crypto_id: collection_crypto_id.to_string(),
            rules,
        }))
    }
}

fn client_payload_signature_verifier(
    instance: &CryptoInstanceConfig,
    instance_id: &str,
) -> Result<Option<ClientPayloadSignatureVerifier>, PayloadWriteSetupError> {
    let signature_key_id = match instance.options.get(SIGNATURE_KEY_ID_OPTION) {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => {
            return Err(PayloadWriteSetupError::InvalidClientSignatureKeyId {
                instance: instance_id.to_string(),
            });
        }
    };
    let signature_public_key = match instance.options.get(SIGNATURE_PUBLIC_KEY_B64_OPTION) {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => {
            return Err(PayloadWriteSetupError::InvalidClientSignaturePublicKey {
                instance: instance_id.to_string(),
            });
        }
    };
    let signature_public_keys = match instance.options.get(SIGNATURE_PUBLIC_KEYS_OPTION) {
        None | Some(Value::Null) => None,
        Some(Value::Object(value)) => Some(value),
        Some(_) => {
            return Err(PayloadWriteSetupError::InvalidClientSignaturePublicKeys {
                instance: instance_id.to_string(),
            });
        }
    };

    if signature_public_keys.is_some()
        && (signature_key_id.is_some() || signature_public_key.is_some())
    {
        return Err(PayloadWriteSetupError::MixedClientSignatureKeyConfig {
            instance: instance_id.to_string(),
        });
    }

    if let Some(signature_public_keys) = signature_public_keys {
        if signature_public_keys.is_empty() {
            return Err(PayloadWriteSetupError::InvalidClientSignaturePublicKeys {
                instance: instance_id.to_string(),
            });
        }

        let mut public_keys = std::collections::HashMap::new();
        for (key_id, public_key_b64) in signature_public_keys {
            if key_id.is_empty() {
                return Err(PayloadWriteSetupError::InvalidClientSignaturePublicKeys {
                    instance: instance_id.to_string(),
                });
            }
            let Some(public_key_b64) = public_key_b64.as_str() else {
                return Err(PayloadWriteSetupError::InvalidClientSignaturePublicKeys {
                    instance: instance_id.to_string(),
                });
            };
            let public_key = BASE64URL_NOPAD
                .decode(public_key_b64.as_bytes())
                .map_err(
                    |_| PayloadWriteSetupError::InvalidClientSignaturePublicKey {
                        instance: instance_id.to_string(),
                    },
                )?;
            if public_key.len() != 32 {
                return Err(PayloadWriteSetupError::InvalidClientSignaturePublicKey {
                    instance: instance_id.to_string(),
                });
            }
            public_keys.insert(key_id.clone(), public_key);
        }

        return Ok(Some(ClientPayloadSignatureVerifier::Registry(public_keys)));
    }

    match (signature_key_id, signature_public_key) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(PayloadWriteSetupError::MissingClientSignaturePublicKey {
            instance: instance_id.to_string(),
        }),
        (None, Some(_)) => Err(PayloadWriteSetupError::MissingClientSignatureKeyId {
            instance: instance_id.to_string(),
        }),
        (Some(key_id), Some(public_key_b64)) => {
            let public_key = BASE64URL_NOPAD
                .decode(public_key_b64.as_bytes())
                .map_err(
                    |_| PayloadWriteSetupError::InvalidClientSignaturePublicKey {
                        instance: instance_id.to_string(),
                    },
                )?;
            if public_key.len() != 32 {
                return Err(PayloadWriteSetupError::InvalidClientSignaturePublicKey {
                    instance: instance_id.to_string(),
                });
            }
            Ok(Some(ClientPayloadSignatureVerifier::Single {
                key_id: key_id.to_string(),
                public_key,
            }))
        }
    }
}

fn validate_generic_collection_crypto_runtime(
    runtime_settings: &CryptoSettings,
    collection_name: &str,
    encryption: &CollectionEncryptionConfig,
) -> Result<(), StorageError> {
    let payload_rules: Vec<_> = encryption
        .rules
        .iter()
        .filter(|rule| matches!(rule.selector, EncryptionSelector::PayloadPaths { .. }))
        .cloned()
        .collect();
    if !payload_rules.is_empty() {
        let payload_only_encryption = CollectionEncryptionConfig {
            version: encryption.version,
            key_id: encryption.key_id.clone(),
            crypto_schema_version: encryption.crypto_schema_version,
            encryption_epoch: encryption.encryption_epoch,
            migration_state: encryption.migration_state.clone(),
            rules: payload_rules,
        };
        generic_payload_write_plan(
            runtime_settings,
            collection_name,
            collection_name,
            &payload_only_encryption,
        )
        .map_err(|err| {
            StorageError::bad_input(format!(
                "collection {collection_name} payload crypto runtime validation failed: {err}"
            ))
        })?;
    }

    for rule in &encryption.rules {
        if !matches!(rule.selector, EncryptionSelector::VectorNames { .. }) {
            continue;
        }

        let Some(instance) = runtime_settings.instances.get(&rule.instance) else {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} references unknown crypto instance {}",
                rule.instance
            )));
        };
        if instance.provider != VECTOR_OPENFHE_CKKS_PROVIDER {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} rule {} must use provider {VECTOR_OPENFHE_CKKS_PROVIDER}, found {}",
                rule.id, instance.provider
            )));
        }
        let profile = match instance.options.get(CKKS_PROFILE_OPTION) {
            Some(Value::String(profile)) => profile.as_str(),
            Some(_) => {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} profile option must be a string",
                    rule.instance
                )));
            }
            None => {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} must set allowlisted profile {CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50}",
                    rule.instance
                )));
            }
        };
        if profile != CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50 {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} profile {profile} is not allowlisted; expected {CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50}",
                rule.instance
            )));
        }

        let instance_key_id = match instance.options.get("key_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(key_id)) => Some(key_id.as_str()),
            Some(_) => {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} key_id option must be a string",
                    rule.instance
                )));
            }
        };
        let key_id = match (encryption.key_id.as_deref(), instance_key_id) {
            (Some(collection_key_id), Some(runtime_key_id))
                if collection_key_id != runtime_key_id =>
            {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} key id does not match vector crypto instance {} key id",
                    rule.instance
                )));
            }
            (None, None) => {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} is missing a key id",
                    rule.instance
                )));
            }
            (Some(collection_key_id), _) => collection_key_id,
            (None, Some(runtime_key_id)) => runtime_key_id,
        };

        let Some(backend_ref) = instance.backend_ref.as_deref() else {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} is missing backend_ref",
                rule.instance
            )));
        };
        if !runtime_settings.backends.contains_key(backend_ref) {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} references unknown backend {backend_ref}",
                rule.instance
            )));
        }

        let Some(material_ref) = instance.materials.get(PAYLOAD_SYM_KEY_ROLE) else {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} is missing metadata key material binding {PAYLOAD_SYM_KEY_ROLE}",
                rule.instance
            )));
        };
        let Some(material) = runtime_settings.materials.get(material_ref) else {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} references unknown metadata key material {material_ref}",
                rule.instance
            )));
        };
        let resource_key = decode_resource_key(runtime_settings, material_ref, material).map_err(|err| {
            StorageError::bad_input(format!(
                "collection {collection_name} vector crypto metadata key validation failed: {err}"
            ))
        })?;
        if instance
            .options
            .get(MATERIAL_FINGERPRINT_ID_OPTION)
            .is_none()
        {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} must set material_fingerprint_id",
                rule.instance
            )));
        }
        if let Some(material_fingerprint_id) = instance.options.get(MATERIAL_FINGERPRINT_ID_OPTION)
        {
            let Some(material_fingerprint_id) = material_fingerprint_id.as_str() else {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} material_fingerprint_id option must be a string",
                    rule.instance
                )));
            };
            let metadata_key = resource_key.derive_subkey(CKKS_VECTOR_KEY_DOMAIN).map_err(|err| {
                StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto metadata key validation failed: {err}"
                ))
            })?;
            let metadata_cipher = AeadCipher::new_with_material_fingerprint(
                key_id,
                metadata_key,
                material_fingerprint_id,
            )
            .map_err(|err| {
                StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto metadata key validation failed: {err}"
                ))
            })?;
            if let Some(rk_epoch) = material.rk_epoch {
                metadata_cipher
                    .with_resource_key_metadata(material_ref, rk_epoch)
                    .map_err(|err| {
                        StorageError::bad_input(format!(
                            "collection {collection_name} vector crypto metadata key validation failed: {err}"
                        ))
                    })?;
            }
        }
    }

    Ok(())
}

fn resolve_payload_key_id<'a>(
    collection_name: &str,
    encryption: &'a CollectionEncryptionConfig,
    instance_name: &str,
    instance: &'a CryptoInstanceConfig,
) -> Result<&'a str, PayloadWriteSetupError> {
    let instance_key_id = match instance.options.get("key_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(key_id)) => Some(key_id.as_str()),
        Some(_) => {
            return Err(PayloadWriteSetupError::InvalidInstanceKeyId {
                instance: instance_name.to_string(),
            });
        }
    };

    match (encryption.key_id.as_deref(), instance_key_id) {
        (Some(collection_key_id), Some(runtime_key_id)) if collection_key_id != runtime_key_id => {
            Err(PayloadWriteSetupError::CollectionKeyMismatch {
                collection: collection_name.to_string(),
                instance: instance_name.to_string(),
            })
        }
        (Some(collection_key_id), _) => Ok(collection_key_id),
        (None, Some(runtime_key_id)) => Ok(runtime_key_id),
        (None, None) => Err(PayloadWriteSetupError::MissingKeyId {
            collection: collection_name.to_string(),
        }),
    }
}

fn resolve_optional_payload_key_id<'a>(
    collection_name: &str,
    encryption: &'a CollectionEncryptionConfig,
    instance_name: &str,
    instance: &'a CryptoInstanceConfig,
) -> Result<Option<&'a str>, PayloadWriteSetupError> {
    let instance_key_id = match instance.options.get("key_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(key_id)) => Some(key_id.as_str()),
        Some(_) => {
            return Err(PayloadWriteSetupError::InvalidInstanceKeyId {
                instance: instance_name.to_string(),
            });
        }
    };

    match (encryption.key_id.as_deref(), instance_key_id) {
        (Some(collection_key_id), Some(runtime_key_id)) if collection_key_id != runtime_key_id => {
            Err(PayloadWriteSetupError::CollectionKeyMismatch {
                collection: collection_name.to_string(),
                instance: instance_name.to_string(),
            })
        }
        (Some(collection_key_id), _) => Ok(Some(collection_key_id)),
        (None, Some(runtime_key_id)) => Ok(Some(runtime_key_id)),
        (None, None) => Ok(None),
    }
}

fn decode_resource_key(
    runtime_settings: &CryptoSettings,
    material_name: &str,
    material: &CryptoMaterialConfig,
) -> Result<SecretKey, PayloadWriteSetupError> {
    match material.kind.as_str() {
        SYMMETRIC_KEY_32_KIND => decode_direct_material_key(material_name, material),
        WRAPPED_SYMMETRIC_KEY_32_KIND => {
            decode_wrapped_resource_key(runtime_settings, material_name, material)
        }
        kind => Err(PayloadWriteSetupError::UnsupportedMaterialKind {
            material: material_name.to_string(),
            kind: kind.to_string(),
        }),
    }
}

fn decode_wrapped_resource_key(
    runtime_settings: &CryptoSettings,
    material_name: &str,
    material: &CryptoMaterialConfig,
) -> Result<SecretKey, PayloadWriteSetupError> {
    let wrapped_by = material.wrapped_by.as_deref().ok_or_else(|| {
        PayloadWriteSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "missing wrapped_by".to_string(),
        }
    })?;
    let wrapping_material = runtime_settings.materials.get(wrapped_by).ok_or_else(|| {
        PayloadWriteSetupError::UnknownWrappingMaterial {
            material: material_name.to_string(),
            wrapped_by: wrapped_by.to_string(),
        }
    })?;
    if wrapping_material.kind != WRAPPING_KEY_32_KIND {
        return Err(PayloadWriteSetupError::UnsupportedWrappingMaterialKind {
            material: material_name.to_string(),
            wrapped_by: wrapped_by.to_string(),
            kind: wrapping_material.kind.clone(),
        });
    }

    let algorithm = material
        .wrap_algorithm
        .as_deref()
        .unwrap_or(RESOURCE_KEY_WRAP_ALGORITHM);
    if algorithm != RESOURCE_KEY_WRAP_ALGORITHM {
        return Err(PayloadWriteSetupError::UnsupportedWrapAlgorithm {
            material: material_name.to_string(),
            algorithm: algorithm.to_string(),
        });
    }
    let nonce =
        material
            .nonce
            .as_ref()
            .ok_or_else(|| PayloadWriteSetupError::InvalidWrappedMaterial {
                material: material_name.to_string(),
                reason: "missing nonce".to_string(),
            })?;
    let wrapped_key = material.wrapped_key_b64.as_ref().ok_or_else(|| {
        PayloadWriteSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "missing wrapped_key_b64".to_string(),
        }
    })?;

    let master_key = decode_direct_material_key(wrapped_by, wrapping_material)?;
    let provider = LocalMasterKeyProvider::new(wrapped_by, master_key)
        .map_err(|err| PayloadWriteSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;
    let wrapped = WrappedKeyBlob {
        version: 1,
        algorithm: algorithm.to_string(),
        mk_id: wrapped_by.to_string(),
        nonce: nonce.clone(),
        wrapped_key: wrapped_key.clone(),
    };
    let aad = resource_key_wrap_aad(material_name, material, wrapped_by, algorithm);
    provider
        .unwrap_resource_key(&wrapped, &aad)
        .map_err(|err| PayloadWriteSetupError::Payload(PayloadEncryptionError::Crypto(err)))
}

pub fn rewrap_runtime_resource_key_material(
    runtime_settings: &CryptoSettings,
    material_name: &str,
    new_wrapped_by: &str,
) -> Result<CryptoMaterialConfig, PayloadWriteSetupError> {
    let material = runtime_settings
        .materials
        .get(material_name)
        .ok_or_else(|| PayloadWriteSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "unknown material".to_string(),
        })?;
    if material.kind != WRAPPED_SYMMETRIC_KEY_32_KIND {
        return Err(PayloadWriteSetupError::UnsupportedMaterialKind {
            material: material_name.to_string(),
            kind: material.kind.clone(),
        });
    }

    let old_wrapped_by = material.wrapped_by.as_deref().ok_or_else(|| {
        PayloadWriteSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "missing wrapped_by".to_string(),
        }
    })?;
    let algorithm = material
        .wrap_algorithm
        .as_deref()
        .unwrap_or(RESOURCE_KEY_WRAP_ALGORITHM);
    if algorithm != RESOURCE_KEY_WRAP_ALGORITHM {
        return Err(PayloadWriteSetupError::UnsupportedWrapAlgorithm {
            material: material_name.to_string(),
            algorithm: algorithm.to_string(),
        });
    }

    let old_wrapping_material =
        runtime_settings
            .materials
            .get(old_wrapped_by)
            .ok_or_else(|| PayloadWriteSetupError::UnknownWrappingMaterial {
                material: material_name.to_string(),
                wrapped_by: old_wrapped_by.to_string(),
            })?;
    if old_wrapping_material.kind != WRAPPING_KEY_32_KIND {
        return Err(PayloadWriteSetupError::UnsupportedWrappingMaterialKind {
            material: material_name.to_string(),
            wrapped_by: old_wrapped_by.to_string(),
            kind: old_wrapping_material.kind.clone(),
        });
    }
    let new_wrapping_material =
        runtime_settings
            .materials
            .get(new_wrapped_by)
            .ok_or_else(|| PayloadWriteSetupError::UnknownWrappingMaterial {
                material: material_name.to_string(),
                wrapped_by: new_wrapped_by.to_string(),
            })?;
    if new_wrapping_material.kind != WRAPPING_KEY_32_KIND {
        return Err(PayloadWriteSetupError::UnsupportedWrappingMaterialKind {
            material: material_name.to_string(),
            wrapped_by: new_wrapped_by.to_string(),
            kind: new_wrapping_material.kind.clone(),
        });
    }

    let old_nonce =
        material
            .nonce
            .as_ref()
            .ok_or_else(|| PayloadWriteSetupError::InvalidWrappedMaterial {
                material: material_name.to_string(),
                reason: "missing nonce".to_string(),
            })?;
    let old_wrapped_key = material.wrapped_key_b64.as_ref().ok_or_else(|| {
        PayloadWriteSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "missing wrapped_key_b64".to_string(),
        }
    })?;

    let old_provider = LocalMasterKeyProvider::new(
        old_wrapped_by,
        decode_direct_material_key(old_wrapped_by, old_wrapping_material)?,
    )
    .map_err(|err| PayloadWriteSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;
    let new_provider = LocalMasterKeyProvider::new(
        new_wrapped_by,
        decode_direct_material_key(new_wrapped_by, new_wrapping_material)?,
    )
    .map_err(|err| PayloadWriteSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;

    let old_wrapped = WrappedKeyBlob {
        version: 1,
        algorithm: algorithm.to_string(),
        mk_id: old_wrapped_by.to_string(),
        nonce: old_nonce.clone(),
        wrapped_key: old_wrapped_key.clone(),
    };
    let mut rewrapped_material = material.clone();
    rewrapped_material.wrapped_by = Some(new_wrapped_by.to_string());
    rewrapped_material.wrap_algorithm = Some(algorithm.to_string());
    let old_aad = resource_key_wrap_aad(material_name, material, old_wrapped_by, algorithm);
    let new_aad = resource_key_wrap_aad(
        material_name,
        &rewrapped_material,
        new_wrapped_by,
        algorithm,
    );
    let rewrapped = rewrap_resource_key(
        &old_provider,
        &new_provider,
        &old_wrapped,
        &old_aad,
        &new_aad,
    )
    .map_err(|err| PayloadWriteSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;
    rewrapped_material.nonce = Some(rewrapped.nonce);
    rewrapped_material.wrapped_key_b64 = Some(rewrapped.wrapped_key);

    Ok(rewrapped_material)
}

fn resource_key_wrap_aad(
    material_name: &str,
    material: &CryptoMaterialConfig,
    wrapped_by: &str,
    algorithm: &str,
) -> Vec<u8> {
    let epoch = material
        .rk_epoch
        .map(|epoch| epoch.to_string())
        .unwrap_or_default();
    let scope = material.scope.as_deref().unwrap_or_default();
    let values = [
        "qdrant-sec",
        "v1",
        "resource-key-wrap",
        material_name,
        &epoch,
        scope,
        wrapped_by,
        algorithm,
    ];

    let mut aad = Vec::new();
    for value in values {
        let bytes = value.as_bytes();
        aad.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        aad.extend_from_slice(bytes);
    }
    aad
}

fn decode_direct_material_key(
    material_name: &str,
    material: &CryptoMaterialConfig,
) -> Result<SecretKey, PayloadWriteSetupError> {
    let encoded = match material.source.as_deref() {
        Some("env") => {
            let env = material.env.as_deref().ok_or_else(|| {
                PayloadWriteSetupError::MissingMaterialEnv {
                    material: material_name.to_string(),
                    env: "<missing>".to_string(),
                }
            })?;
            std::env::var(env).map_err(|_| PayloadWriteSetupError::MissingMaterialEnv {
                material: material_name.to_string(),
                env: env.to_string(),
            })?
        }
        Some("file") => {
            let path = material.path.as_deref().ok_or_else(|| {
                PayloadWriteSetupError::MissingMaterialPath {
                    material: material_name.to_string(),
                }
            })?;
            fs::read_to_string(path).map_err(|_| {
                PayloadWriteSetupError::UnreadableMaterialFile {
                    material: material_name.to_string(),
                    path: path.to_string(),
                }
            })?
        }
        Some("inline") => material.value_b64.clone().ok_or_else(|| {
            PayloadWriteSetupError::MissingInlineMaterial {
                material: material_name.to_string(),
            }
        })?,
        Some(_) | None => {
            if let Some(env) = material.env.as_deref() {
                std::env::var(env).map_err(|_| PayloadWriteSetupError::MissingMaterialEnv {
                    material: material_name.to_string(),
                    env: env.to_string(),
                })?
            } else if let Some(path) = material.path.as_deref() {
                fs::read_to_string(path).map_err(|_| {
                    PayloadWriteSetupError::UnreadableMaterialFile {
                        material: material_name.to_string(),
                        path: path.to_string(),
                    }
                })?
            } else {
                material.value_b64.clone().ok_or_else(|| {
                    PayloadWriteSetupError::MissingInlineMaterial {
                        material: material_name.to_string(),
                    }
                })?
            }
        }
    };

    let encoded = encoded.trim();
    let decoded = Zeroizing::new(BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| {
        PayloadWriteSetupError::InvalidMaterialEncoding {
            material: material_name.to_string(),
        }
    })?);
    SecretKey::try_from_slice(decoded.as_slice()).map_err(|_| {
        PayloadWriteSetupError::InvalidMaterialLength {
            material: material_name.to_string(),
        }
    })
}

fn validate_legacy_collection_crypto_runtime(
    runtime_config: &crate::settings::CkksConfig,
    collection_name: &str,
    collection_config: &CkksCollectionConfig,
) -> Result<(), StorageError> {
    if !collection_config.payload_text_fields.is_empty() {
        crate::common::ckks::payload_text_encryptor_for_collection(
            runtime_config,
            collection_name,
            Some(collection_config),
        )
        .map_err(|err| {
            StorageError::bad_input(format!(
                "collection {collection_name} payload crypto runtime validation failed: {err}"
            ))
        })?;
    }

    if collection_config.vector_names.is_empty() {
        return Ok(());
    }
    if crate::common::ckks::openfhe_bridge_for_collection(
        runtime_config,
        collection_name,
        Some(collection_config),
    )
    .is_none()
    {
        return Err(StorageError::bad_input(format!(
            "collection {collection_name} CKKS vector runtime validation failed: missing OpenFHE bridge backend"
        )));
    }

    let collection_runtime = runtime_config.collections.get(collection_name);
    let collection_runtime_key_id =
        collection_runtime.and_then(|runtime| runtime.key_id.as_deref());
    match (
        collection_config.key_id.as_deref(),
        collection_runtime_key_id,
    ) {
        (Some(collection_key_id), Some(runtime_key_id)) if collection_key_id != runtime_key_id => {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} key id does not match CKKS runtime key id"
            )));
        }
        (Some(_), _) => {}
        (None, Some(_)) => {}
        (None, None) if runtime_config.key_id.is_none() => {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} CKKS vector runtime validation failed: missing key id"
            )));
        }
        (None, None) => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use collection::config::{
        CkksCollectionConfig, CollectionEncryptionConfig, CollectionParams, CryptoMigrationState,
        EncryptionRuleRef, EncryptionSelector,
    };
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_ckks::{
        CLIENT_ENCRYPTED_PAYLOAD_MARKER, CLIENT_PAYLOAD_ENVELOPE_BINDING, LocalMasterKeyProvider,
        MasterKeyProvider, RESOURCE_KEY_WRAP_ALGORITHM, client_payload_signature_message,
        is_client_encrypted_payload_value, is_encrypted_payload_value,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;

    use super::*;
    use crate::settings::{CkksConfig, CryptoInstanceConfig};

    #[test]
    fn validate_crypto_settings_rejects_missing_material_and_backend_refs() {
        let mut settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_v1".to_string(),
                CryptoInstanceConfig {
                    provider: "payload/aes-256-gcm@v1".to_string(),
                    materials: HashMap::from([(
                        "sym_key".to_string(),
                        "tenant-a/payload-v1".to_string(),
                    )]),
                    backend_ref: Some("missing-backend".to_string()),
                    options: json!({}),
                },
            )]),
            materials: HashMap::new(),
            backends: HashMap::new(),
        };

        assert_eq!(
            validate_crypto_settings(&settings),
            Err(CryptoSetupError::UnknownMaterial {
                instance: "docs_payload_v1".to_string(),
                role: "sym_key".to_string(),
                material_ref: "tenant-a/payload-v1".to_string(),
            }),
        );

        settings.materials.insert(
            "tenant-a/payload-v1".to_string(),
            CryptoMaterialConfig {
                kind: "symmetric_key_32".to_string(),
                source: Some("inline".to_string()),
                env: None,
                path: None,
                value_b64: Some("AQID".to_string()),
                ..CryptoMaterialConfig::default()
            },
        );

        assert_eq!(
            validate_crypto_settings(&settings),
            Err(CryptoSetupError::UnknownBackend {
                instance: "docs_payload_v1".to_string(),
                backend_ref: "missing-backend".to_string(),
            }),
        );
    }

    #[test]
    fn validate_crypto_settings_rejects_invalid_material_source_shapes() {
        assert_eq!(
            validate_material(
                "tenant-a/payload-v1",
                &CryptoMaterialConfig {
                    kind: "symmetric_key_32".to_string(),
                    source: Some("inline".to_string()),
                    env: None,
                    path: Some("/tmp/key.bin".to_string()),
                    value_b64: Some("AQID".to_string()),
                    ..CryptoMaterialConfig::default()
                },
                true,
            ),
            Err(CryptoSetupError::InvalidMaterialSourceCount {
                material: "tenant-a/payload-v1".to_string(),
            }),
        );

        assert_eq!(
            validate_material(
                "tenant-a/payload-v1",
                &CryptoMaterialConfig {
                    kind: "symmetric_key_32".to_string(),
                    source: Some("kms".to_string()),
                    env: Some("QDRANT_PAYLOAD_KEY".to_string()),
                    path: None,
                    value_b64: None,
                    ..CryptoMaterialConfig::default()
                },
                true,
            ),
            Err(CryptoSetupError::UnsupportedMaterialSource {
                material: "tenant-a/payload-v1".to_string(),
                material_source: "kms".to_string(),
            }),
        );
    }

    #[test]
    fn validate_crypto_settings_can_reject_inline_key_material() {
        let settings = CryptoSettings {
            allow_inline_key_material: false,
            materials: HashMap::from([(
                "tenant-a/payload-v1".to_string(),
                CryptoMaterialConfig {
                    kind: "symmetric_key_32".to_string(),
                    source: Some("inline".to_string()),
                    env: None,
                    path: None,
                    value_b64: Some("AQID".to_string()),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            ..CryptoSettings::default()
        };

        assert_eq!(
            validate_crypto_settings(&settings),
            Err(CryptoSetupError::InlineMaterialDisabled {
                material: "tenant-a/payload-v1".to_string(),
            }),
        );
    }

    #[test]
    fn validate_crypto_settings_rejects_wrapped_resource_key_without_mk() {
        let settings = CryptoSettings {
            materials: HashMap::from([(
                "tenant-a/payload-rk-v1".to_string(),
                CryptoMaterialConfig {
                    kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                    wrapped_by: Some("tenant-a/mk-v1".to_string()),
                    wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                    nonce: Some("nonce".to_string()),
                    wrapped_key_b64: Some("wrapped".to_string()),
                    rk_epoch: Some(3),
                    scope: Some("collection:docs".to_string()),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            ..CryptoSettings::default()
        };

        assert_eq!(
            validate_crypto_settings(&settings),
            Err(CryptoSetupError::UnknownWrappingMaterial {
                material: "tenant-a/payload-rk-v1".to_string(),
                wrapped_by: "tenant-a/mk-v1".to_string(),
            }),
        );
    }

    #[test]
    fn validate_crypto_settings_requires_wrapped_resource_key_identity() {
        let base_material = CryptoMaterialConfig {
            kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
            wrapped_by: Some("tenant-a/mk-v1".to_string()),
            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
            nonce: Some("nonce".to_string()),
            wrapped_key_b64: Some("wrapped".to_string()),
            ..CryptoMaterialConfig::default()
        };
        let wrapping_material = CryptoMaterialConfig {
            kind: WRAPPING_KEY_32_KIND.to_string(),
            source: Some("inline".to_string()),
            env: None,
            path: None,
            value_b64: Some(BASE64URL_NOPAD.encode(&[91u8; 32])),
            ..CryptoMaterialConfig::default()
        };

        let missing_epoch = CryptoSettings {
            allow_inline_key_material: true,
            materials: HashMap::from([
                ("tenant-a/mk-v1".to_string(), wrapping_material.clone()),
                ("tenant-a/payload-rk-v1".to_string(), base_material.clone()),
            ]),
            ..CryptoSettings::default()
        };
        assert_eq!(
            validate_crypto_settings(&missing_epoch),
            Err(CryptoSetupError::InvalidWrappedMaterial {
                material: "tenant-a/payload-rk-v1".to_string(),
                reason: "missing rk_epoch".to_string(),
            }),
        );

        let missing_scope = CryptoSettings {
            allow_inline_key_material: true,
            materials: HashMap::from([
                ("tenant-a/mk-v1".to_string(), wrapping_material),
                (
                    "tenant-a/payload-rk-v1".to_string(),
                    CryptoMaterialConfig {
                        rk_epoch: Some(3),
                        ..base_material
                    },
                ),
            ]),
            ..CryptoSettings::default()
        };
        assert_eq!(
            validate_crypto_settings(&missing_scope),
            Err(CryptoSetupError::InvalidWrappedMaterial {
                material: "tenant-a/payload-rk-v1".to_string(),
                reason: "missing scope".to_string(),
            }),
        );
    }

    #[test]
    fn validate_backend_requires_program_for_process_kinds() {
        assert_eq!(
            validate_backend(
                "openfhe_local",
                &CryptoBackendConfig {
                    kind: "process_pool".to_string(),
                    program: None,
                    sha256_b64: None,
                    size: Some(4),
                    timeout_ms: Some(5_000),
                },
            ),
            Err(CryptoSetupError::MissingBackendProgram {
                backend: "openfhe_local".to_string(),
                kind: "process_pool".to_string(),
            }),
        );

        assert_eq!(
            validate_backend(
                "openfhe_local",
                &CryptoBackendConfig {
                    kind: "process_pool".to_string(),
                    program: Some("relative-openfhe-bridge".to_string()),
                    sha256_b64: None,
                    size: Some(4),
                    timeout_ms: Some(5_000),
                },
            ),
            Err(CryptoSetupError::InvalidBackendProgram {
                backend: "openfhe_local".to_string(),
                program: "relative-openfhe-bridge".to_string(),
            }),
        );
    }

    #[test]
    fn validate_backend_rejects_invalid_pool_size() {
        assert_eq!(
            validate_backend(
                "openfhe_local",
                &CryptoBackendConfig {
                    kind: "process_pool".to_string(),
                    program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                    sha256_b64: None,
                    size: Some(0),
                    timeout_ms: Some(5_000),
                },
            ),
            Err(CryptoSetupError::InvalidBackendSize {
                backend: "openfhe_local".to_string(),
                reason: "process_pool size must be at least 1".to_string(),
            }),
        );

        assert_eq!(
            validate_backend(
                "openfhe_local",
                &CryptoBackendConfig {
                    kind: "process".to_string(),
                    program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                    sha256_b64: None,
                    size: Some(2),
                    timeout_ms: Some(5_000),
                },
            ),
            Err(CryptoSetupError::InvalidBackendSize {
                backend: "openfhe_local".to_string(),
                reason: "process backend size must be omitted or 1".to_string(),
            }),
        );
    }

    #[test]
    fn payload_write_plan_encrypts_generic_payload_fields() {
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            "tenant-a/payload-v1".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/payload@v5",
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/payload-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: SYMMETRIC_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        env: None,
                        path: None,
                        value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 5,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();
        let mut payload = segment::types::Payload(
            json!({ "body": "secret body" })
                .as_object()
                .unwrap()
                .clone(),
        );
        let public_payload =
            segment::types::Payload(json!({ "title": "public" }).as_object().unwrap().clone());
        let body_path = "body".parse::<JsonPath>().unwrap();

        assert!(plan.touches_selected_fields(&payload, None));
        assert!(plan.touches_selected_fields(&public_payload, Some(&body_path)));
        assert!(!plan.touches_selected_fields(&public_payload, None));
        assert_eq!(plan.encrypt_payload("point-1", &mut payload).unwrap(), 1);
        let body = payload.0.get("body").unwrap();
        assert!(is_encrypted_payload_value(body));
        assert_eq!(
            body.get("$qdrant_ckks")
                .and_then(|marker| marker.get("envelope"))
                .and_then(|envelope| envelope.get("material_fingerprint"))
                .and_then(|fingerprint| fingerprint.as_str()),
            Some("tenant-a/payload@v5"),
        );
    }

    #[test]
    fn payload_write_plan_reencrypts_stale_envelopes_only_in_migration_mode() {
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            "tenant-a/payload-v1".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/payload@v5",
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/payload-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: SYMMETRIC_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        env: None,
                        path: None,
                        value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        };
        let mut params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 5,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();
        let mut payload = segment::types::Payload(
            json!({ "body": "rotate this" })
                .as_object()
                .unwrap()
                .clone(),
        );
        assert_eq!(plan.encrypt_payload("point-1", &mut payload).unwrap(), 1);

        params.encryption.as_mut().unwrap().encryption_epoch = 6;
        let rotated_plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();
        assert!(matches!(
            rotated_plan.encrypt_payload("point-1", &mut payload),
            Err(PayloadWriteSetupError::Payload(
                PayloadEncryptionError::AlreadyEncrypted(field)
            )) if field == "body"
        ));

        assert_eq!(
            rotated_plan
                .reencrypt_payload_if_stale("point-1", &mut payload)
                .unwrap(),
            1,
        );
        assert_eq!(
            payload
                .0
                .get("body")
                .and_then(|body| body.get("$qdrant_ckks"))
                .and_then(|marker| marker.get("encryption_epoch"))
                .and_then(|epoch| epoch.as_u64()),
            Some(6),
        );
        assert_eq!(
            rotated_plan
                .reencrypt_payload_if_stale("point-1", &mut payload)
                .unwrap(),
            0,
        );
    }

    #[test]
    fn payload_write_plan_requires_explicit_material_fingerprint_id() {
        let mut settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            "tenant-a/payload-v1".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({ "key_id": "tenant-a:docs" }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/payload-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: SYMMETRIC_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        env: None,
                        path: None,
                        value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 5,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        assert!(matches!(
            payload_write_plan_for_collection(&settings, "docs", &params),
            Err(PayloadWriteSetupError::MissingMaterialFingerprintId { instance })
                if instance == "docs_payload_v1"
        ));

        settings
            .crypto
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options = json!({
            "key_id": "tenant-a:docs",
            "material_fingerprint_id": "tenant-a/payload@v5",
        });
        assert!(payload_write_plan_for_collection(&settings, "docs", &params).is_ok());
    }

    #[test]
    fn payload_write_plan_accepts_valid_client_envelopes_without_server_key_material() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "key_id_required": true,
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let mut payload = segment::types::Payload(
            json!({
                "body": {
                    CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                        "version": 1,
                        "kind": "payload_text",
                        "algorithm": "AES-256-GCM",
                        "key_id": "tenant-a/client-rk-2026-04",
                        "rk_id": "tenant-a/client-rk-2026-04",
                        "rk_epoch": 3,
                        "kdf_domain": "qdrant/client-payload-text/v1",
                        "aad": {
                            "collection_id": "docs",
                            "point_id": "point-1",
                            "field_path": "body",
                            "schema_version": 1
                        },
                        "nonce": "AAAAAAAAAAAAAAAA",
                        "ciphertext": "AQID",
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );

        let plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();
        assert_eq!(plan.encrypt_payload("point-1", &mut payload).unwrap(), 1);
        assert!(is_client_encrypted_payload_value(
            payload.0.get("body").unwrap()
        ));
        assert!(!is_encrypted_payload_value(payload.0.get("body").unwrap()));
    }

    #[test]
    fn payload_write_plan_rejects_non_client_values_for_client_provider() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "key_id_required": true,
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();

        let mut plaintext_payload = segment::types::Payload(
            json!({ "body": "client plaintext must not enter store-only provider" })
                .as_object()
                .unwrap()
                .clone(),
        );
        assert!(matches!(
            plan.encrypt_payload("point-1", &mut plaintext_payload),
            Err(PayloadWriteSetupError::Payload(
                PayloadEncryptionError::ExpectedEncryptedEnvelope { field, .. }
            )) if field == "body"
        ));

        let mut server_marker_payload = segment::types::Payload(
            json!({ "body": { "$qdrant_ckks": { "kind": "payload_text" } } })
                .as_object()
                .unwrap()
                .clone(),
        );
        assert!(matches!(
            plan.encrypt_payload("point-1", &mut server_marker_payload),
            Err(PayloadWriteSetupError::Payload(
                PayloadEncryptionError::ExpectedEncryptedEnvelope { field, .. }
            )) if field == "body"
        ));
    }

    #[test]
    fn payload_write_plan_uses_explicit_crypto_collection_id_for_client_envelopes() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({ "key_id": "tenant-a/client-rk-2026-04" }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let mut payload = segment::types::Payload(
            json!({
                "body": {
                    CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                        "version": 1,
                        "kind": "payload_text",
                        "algorithm": "AES-256-GCM",
                        "key_id": "tenant-a/client-rk-2026-04",
                        "rk_id": "tenant-a/client-rk-2026-04",
                        "rk_epoch": 3,
                        "kdf_domain": "qdrant/client-payload-text/v1",
                        "aad": {
                            "collection_id": "crypto-docs-uuid",
                            "point_id": "point-1",
                            "field_path": "body",
                            "schema_version": 1
                        },
                        "nonce": "AAAAAAAAAAAAAAAA",
                        "ciphertext": "AQID"
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );

        let plan = payload_write_plan_for_collection_with_crypto_id(
            &settings,
            "docs",
            "crypto-docs-uuid",
            &params,
        )
        .unwrap()
        .unwrap();

        assert_eq!(plan.encrypt_payload("point-1", &mut payload).unwrap(), 1);
    }

    #[test]
    fn payload_write_plan_rejects_client_envelope_aad_mismatch() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({ "key_id": "tenant-a/client-rk-2026-04" }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let mut payload = segment::types::Payload(
            json!({
                "body": {
                    CLIENT_ENCRYPTED_PAYLOAD_MARKER: {
                        "version": 1,
                        "kind": "payload_text",
                        "algorithm": "AES-256-GCM",
                        "key_id": "tenant-a/client-rk-2026-04",
                        "rk_id": "tenant-a/client-rk-2026-04",
                        "rk_epoch": 3,
                        "kdf_domain": "qdrant/client-payload-text/v1",
                        "aad": {
                            "collection_id": "docs",
                            "point_id": "point-2",
                            "field_path": "body",
                            "schema_version": 1
                        },
                        "nonce": "AAAAAAAAAAAAAAAA",
                        "ciphertext": "AQID"
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();

        assert!(matches!(
            plan.encrypt_payload("point-1", &mut payload),
            Err(PayloadWriteSetupError::Payload(
                PayloadEncryptionError::ClientEnvelopeAadMismatch(field)
            )) if field == "point_id"
        ));
    }

    #[test]
    fn payload_write_plan_requires_client_envelope_binding_for_client_provider() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({ "key_id": "tenant-a/client-rk-2026-04" }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: None,
                }],
            }),
            ..CollectionParams::empty()
        };

        assert!(matches!(
            payload_write_plan_for_collection(&settings, "docs", &params),
            Err(PayloadWriteSetupError::InvalidClientEnvelopeBinding {
                collection,
                rule_id,
                binding,
            }) if collection == "docs"
                && rule_id == "body_client_conf"
                && binding == CLIENT_PAYLOAD_ENVELOPE_BINDING
        ));
    }

    #[test]
    fn payload_write_plan_validates_client_signature_verifier_options() {
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let settings_with_options = |options: serde_json::Value| Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options,
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };

        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::MissingClientSignaturePublicKey { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::MissingClientSignatureKeyId { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": "not-base64",
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::InvalidClientSignaturePublicKey { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_public_keys": "not-an-object",
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::InvalidClientSignaturePublicKeys { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    "signature_public_keys": {
                        "tenant-a/client-signing-v2": BASE64URL_NOPAD.encode(&[12u8; 32]),
                    },
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::MixedClientSignatureKeyConfig { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_public_keys": {},
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::InvalidClientSignaturePublicKeys { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_public_keys": {
                        "tenant-a/client-signing-v1": "not-base64",
                    },
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::InvalidClientSignaturePublicKey { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                })),
                "docs",
                &params,
            )
            .is_ok()
        );
        assert!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_public_keys": {
                        "tenant-a/client-signing-v1": BASE64URL_NOPAD.encode(&[11u8; 32]),
                        "tenant-a/client-signing-v2": BASE64URL_NOPAD.encode(&[12u8; 32]),
                    },
                })),
                "docs",
                &params,
            )
            .is_ok()
        );
    }

    #[test]
    fn payload_write_plan_verifies_client_envelope_signature() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let mut signed_envelope = {
            let mut marker = serde_json::Map::new();
            marker.insert(
                CLIENT_ENCRYPTED_PAYLOAD_MARKER.to_string(),
                json!({
                    "version": 1,
                    "kind": "payload_text",
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a/client-rk-2026-04",
                    "rk_id": "tenant-a/client-rk-2026-04",
                    "rk_epoch": 3,
                    "kdf_domain": "qdrant/client-payload-text/v1",
                    "aad": {
                        "collection_id": "docs",
                        "point_id": "point-1",
                        "field_path": "body",
                        "schema_version": 1
                    },
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AQID",
                    "signature": {
                        "alg": "ed25519",
                        "key_id": "tenant-a/client-signing-v1",
                        "sig": ""
                    }
                }),
            );
            Value::Object(marker)
        };
        let message = client_payload_signature_message(&signed_envelope, "body").unwrap();
        let signature = key_pair.sign(&message);
        signed_envelope
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("signature")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "sig".to_string(),
                Value::String(BASE64URL_NOPAD.encode(signature.as_ref())),
            );

        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "signature_key_id": "tenant-a/client-signing-v1",
                            "signature_public_key_b64": BASE64URL_NOPAD
                                .encode(key_pair.public_key().as_ref()),
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();
        let payload_from_envelope =
            |envelope: Value| Payload(json!({ "body": envelope }).as_object().unwrap().clone());

        let mut valid_payload = payload_from_envelope(signed_envelope.clone());
        assert_eq!(
            plan.encrypt_payload("point-1", &mut valid_payload).unwrap(),
            1
        );

        let mut tampered_envelope = signed_envelope;
        tampered_envelope
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("ciphertext".to_string(), Value::String("BAUG".to_string()));
        let mut tampered_payload = payload_from_envelope(tampered_envelope);

        assert!(matches!(
            plan.encrypt_payload("point-1", &mut tampered_payload),
            Err(PayloadWriteSetupError::Payload(
                PayloadEncryptionError::InvalidClientSignature
            ))
        ));
    }

    #[test]
    fn payload_write_plan_selects_client_signature_from_registry() {
        let rng = SystemRandom::new();
        let pkcs8_v1 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair_v1 = Ed25519KeyPair::from_pkcs8(pkcs8_v1.as_ref()).unwrap();
        let pkcs8_v2 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair_v2 = Ed25519KeyPair::from_pkcs8(pkcs8_v2.as_ref()).unwrap();

        let mut signed_envelope = {
            let mut marker = serde_json::Map::new();
            marker.insert(
                CLIENT_ENCRYPTED_PAYLOAD_MARKER.to_string(),
                json!({
                    "version": 1,
                    "kind": "payload_text",
                    "algorithm": "AES-256-GCM",
                    "key_id": "tenant-a/client-rk-2026-04",
                    "rk_id": "tenant-a/client-rk-2026-04",
                    "rk_epoch": 3,
                    "kdf_domain": "qdrant/client-payload-text/v1",
                    "aad": {
                        "collection_id": "docs",
                        "point_id": "point-1",
                        "field_path": "body",
                        "schema_version": 1
                    },
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AQID",
                    "signature": {
                        "alg": "ed25519",
                        "key_id": "tenant-a/client-signing-v2",
                        "sig": ""
                    }
                }),
            );
            Value::Object(marker)
        };
        let message = client_payload_signature_message(&signed_envelope, "body").unwrap();
        let signature = key_pair_v2.sign(&message);
        signed_envelope
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("signature")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "sig".to_string(),
                Value::String(BASE64URL_NOPAD.encode(signature.as_ref())),
            );

        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "signature_public_keys": {
                                "tenant-a/client-signing-v1": BASE64URL_NOPAD
                                    .encode(key_pair_v1.public_key().as_ref()),
                                "tenant-a/client-signing-v2": BASE64URL_NOPAD
                                    .encode(key_pair_v2.public_key().as_ref()),
                            },
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a/client-rk-2026-04".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_client_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_client_v1".to_string(),
                    binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();
        let payload_from_envelope =
            |envelope: Value| Payload(json!({ "body": envelope }).as_object().unwrap().clone());

        let mut valid_payload = payload_from_envelope(signed_envelope.clone());
        assert_eq!(
            plan.encrypt_payload("point-1", &mut valid_payload).unwrap(),
            1
        );

        let mut unknown_key_envelope = signed_envelope;
        unknown_key_envelope
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .get_mut("signature")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "key_id".to_string(),
                Value::String("tenant-a/client-signing-v3".to_string()),
            );
        let mut unknown_key_payload = payload_from_envelope(unknown_key_envelope);

        assert!(matches!(
            plan.encrypt_payload("point-1", &mut unknown_key_payload),
            Err(PayloadWriteSetupError::Payload(
                PayloadEncryptionError::ClientSignatureKeyIdMismatch
            ))
        ));
    }

    #[test]
    fn payload_write_plan_unwraps_wrapped_resource_key_material() {
        let mk_material = "tenant-a/mk-v1";
        let rk_material = "tenant-a/payload-rk-v3";
        let mut wrapped_rk_config = CryptoMaterialConfig {
            kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
            wrapped_by: Some(mk_material.to_string()),
            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
            rk_epoch: Some(3),
            scope: Some("collection:docs".to_string()),
            ..CryptoMaterialConfig::default()
        };
        let aad = resource_key_wrap_aad(
            rk_material,
            &wrapped_rk_config,
            mk_material,
            RESOURCE_KEY_WRAP_ALGORITHM,
        );
        let wrapped = LocalMasterKeyProvider::new(mk_material, SecretKey::from_bytes([91u8; 32]))
            .unwrap()
            .wrap_resource_key(&SecretKey::from_bytes([92u8; 32]), &aad)
            .unwrap();
        wrapped_rk_config.nonce = Some(wrapped.nonce);
        wrapped_rk_config.wrapped_key_b64 = Some(wrapped.wrapped_key);

        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            rk_material.to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/payload-rk@v3",
                        }),
                    },
                )]),
                materials: HashMap::from([
                    (
                        mk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: WRAPPING_KEY_32_KIND.to_string(),
                            source: Some("inline".to_string()),
                            env: None,
                            path: None,
                            value_b64: Some(BASE64URL_NOPAD.encode(&[91u8; 32])),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (rk_material.to_string(), wrapped_rk_config),
                ]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 3,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };
        let mut payload = segment::types::Payload(
            json!({ "body": "wrapped resource key secret" })
                .as_object()
                .unwrap()
                .clone(),
        );

        let mut missing_fingerprint_settings = settings.clone();
        missing_fingerprint_settings
            .crypto
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .remove(MATERIAL_FINGERPRINT_ID_OPTION);
        assert!(matches!(
            payload_write_plan_for_collection(&missing_fingerprint_settings, "docs", &params),
            Err(PayloadWriteSetupError::MissingMaterialFingerprintId { instance })
                if instance == "docs_payload_v1"
        ));

        let plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();
        assert_eq!(plan.encrypt_payload("point-1", &mut payload).unwrap(), 1);
        let body = payload.0.get("body").unwrap();
        assert!(is_encrypted_payload_value(body));
        assert_eq!(
            body.get("$qdrant_ckks")
                .and_then(|marker| marker.get("envelope"))
                .and_then(|envelope| envelope.get("material_fingerprint"))
                .and_then(|fingerprint| fingerprint.as_str()),
            Some("tenant-a/payload-rk@v3"),
        );
        assert_eq!(
            body.get("$qdrant_ckks")
                .and_then(|marker| marker.get("envelope"))
                .and_then(|envelope| envelope.get("rk_id"))
                .and_then(|rk_id| rk_id.as_str()),
            Some(rk_material),
        );
        assert_eq!(
            body.get("$qdrant_ckks")
                .and_then(|marker| marker.get("envelope"))
                .and_then(|envelope| envelope.get("rk_epoch"))
                .and_then(|rk_epoch| rk_epoch.as_u64()),
            Some(3),
        );
    }

    #[test]
    fn runtime_resource_key_rewrap_preserves_data_key_for_mk_rotation() {
        let old_mk_material = "tenant-a/mk-v1";
        let new_mk_material = "tenant-a/mk-v2";
        let rk_material = "tenant-a/payload-rk-v3";
        let mut wrapped_rk_config = CryptoMaterialConfig {
            kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
            wrapped_by: Some(old_mk_material.to_string()),
            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
            rk_epoch: Some(3),
            scope: Some("collection:docs".to_string()),
            ..CryptoMaterialConfig::default()
        };
        let aad = resource_key_wrap_aad(
            rk_material,
            &wrapped_rk_config,
            old_mk_material,
            RESOURCE_KEY_WRAP_ALGORITHM,
        );
        let wrapped =
            LocalMasterKeyProvider::new(old_mk_material, SecretKey::from_bytes([91u8; 32]))
                .unwrap()
                .wrap_resource_key(&SecretKey::from_bytes([92u8; 32]), &aad)
                .unwrap();
        wrapped_rk_config.nonce = Some(wrapped.nonce);
        wrapped_rk_config.wrapped_key_b64 = Some(wrapped.wrapped_key);

        let runtime_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::new(),
            materials: HashMap::from([
                (
                    old_mk_material.to_string(),
                    CryptoMaterialConfig {
                        kind: WRAPPING_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[91u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                ),
                (
                    new_mk_material.to_string(),
                    CryptoMaterialConfig {
                        kind: WRAPPING_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[93u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                ),
                (rk_material.to_string(), wrapped_rk_config),
            ]),
            backends: HashMap::new(),
        };
        let old_resource_key = decode_wrapped_resource_key(
            &runtime_settings,
            rk_material,
            runtime_settings.materials.get(rk_material).unwrap(),
        )
        .unwrap();
        let old_encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs",
            "tenant-a:docs",
            &old_resource_key,
            "tenant-a/payload-rk@v3",
            rk_material,
            3,
        )
        .unwrap();
        let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
        let mut payload = segment::types::Payload(
            json!({ "body": "mk rotation keeps data key" })
                .as_object()
                .unwrap()
                .clone(),
        );
        old_encryptor
            .encrypt_selected_fields("point-1", &mut payload.0, &policy)
            .unwrap();

        let rewrapped =
            rewrap_runtime_resource_key_material(&runtime_settings, rk_material, new_mk_material)
                .unwrap();
        assert_eq!(rewrapped.wrapped_by.as_deref(), Some(new_mk_material));
        assert_eq!(rewrapped.rk_epoch, Some(3));
        assert_eq!(rewrapped.scope.as_deref(), Some("collection:docs"));

        let mut rewrapped_settings = runtime_settings.clone();
        rewrapped_settings
            .materials
            .insert(rk_material.to_string(), rewrapped);
        let new_resource_key = decode_wrapped_resource_key(
            &rewrapped_settings,
            rk_material,
            rewrapped_settings.materials.get(rk_material).unwrap(),
        )
        .unwrap();
        let new_encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs",
            "tenant-a:docs",
            &new_resource_key,
            "tenant-a/payload-rk@v3",
            rk_material,
            3,
        )
        .unwrap();

        assert_eq!(
            new_encryptor
                .decrypt_selected_fields("point-1", &mut payload.0, &policy)
                .unwrap(),
            1,
        );
        assert_eq!(
            payload.0.get("body").and_then(Value::as_str),
            Some("mk rotation keeps data key"),
        );
    }

    #[test]
    fn payload_write_plan_supports_legacy_collection_and_runtime_ckks() {
        let settings = Settings {
            ckks: CkksConfig {
                enabled: true,
                allow_inline_key_material: true,
                key_id: Some("tenant-a:docs".to_string()),
                master_key_b64: Some(BASE64URL_NOPAD.encode(&[9u8; 32])),
                ..CkksConfig::default()
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            ckks: Some(CkksCollectionConfig {
                enabled: true,
                key_id: Some("tenant-a:docs".to_string()),
                payload_text_fields: vec!["body".to_string()],
                vector_names: Vec::new(),
            }),
            ..CollectionParams::empty()
        };

        let plan = payload_write_plan_for_collection(&settings, "docs", &params)
            .unwrap()
            .unwrap();
        let mut payload = segment::types::Payload(
            json!({ "body": "legacy secret" })
                .as_object()
                .unwrap()
                .clone(),
        );

        assert_eq!(plan.encrypt_payload("point-1", &mut payload).unwrap(), 1);
        assert!(is_encrypted_payload_value(payload.0.get("body").unwrap()));
    }

    #[test]
    fn payload_write_plan_rejects_unknown_payload_instance() {
        let settings = Settings {
            crypto: CryptoSettings::default(),
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "missing_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = match payload_write_plan_for_collection(&settings, "docs", &params) {
            Err(err) => err,
            Ok(_) => panic!("missing payload instance must fail"),
        };
        assert_eq!(
            err,
            PayloadWriteSetupError::UnknownInstance {
                collection: "docs".to_string(),
                instance: "missing_payload_v1".to_string(),
            },
        );
    }

    #[test]
    fn validate_collection_crypto_runtime_accepts_generic_payload_and_vector_rules() {
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([
                    (
                        "docs_payload_v1".to_string(),
                        CryptoInstanceConfig {
                            provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                            materials: HashMap::from([(
                                PAYLOAD_SYM_KEY_ROLE.to_string(),
                                "tenant-a/payload-v1".to_string(),
                            )]),
                            backend_ref: None,
                            options: json!({
                                "key_id": "tenant-a:docs",
                                "material_fingerprint_id": "tenant-a/payload@v2",
                            }),
                        },
                    ),
                    (
                        "docs_vector_v1".to_string(),
                        CryptoInstanceConfig {
                            provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                            materials: HashMap::from([(
                                PAYLOAD_SYM_KEY_ROLE.to_string(),
                                "tenant-a/vector-v1".to_string(),
                            )]),
                            backend_ref: Some("openfhe_local".to_string()),
                            options: json!({
                                "key_id": "tenant-a:docs",
                                "material_fingerprint_id": "tenant-a/vector@v2",
                                "profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                            }),
                        },
                    ),
                ]),
                materials: HashMap::from([
                    (
                        "tenant-a/payload-v1".to_string(),
                        CryptoMaterialConfig {
                            kind: SYMMETRIC_KEY_32_KIND.to_string(),
                            source: Some("inline".to_string()),
                            env: None,
                            path: None,
                            value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (
                        "tenant-a/vector-v1".to_string(),
                        CryptoMaterialConfig {
                            kind: SYMMETRIC_KEY_32_KIND.to_string(),
                            source: Some("inline".to_string()),
                            env: None,
                            path: None,
                            value_b64: Some(BASE64URL_NOPAD.encode(&[8u8; 32])),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                ]),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                        sha256_b64: None,
                        size: Some(1),
                        timeout_ms: Some(5_000),
                    },
                )]),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![
                    EncryptionRuleRef {
                        id: "body_conf".to_string(),
                        selector: EncryptionSelector::PayloadPaths {
                            paths: vec!["body".to_string()],
                        },
                        instance: "docs_payload_v1".to_string(),
                        binding: Some("payload-field/v1".to_string()),
                    },
                    EncryptionRuleRef {
                        id: "embedding_conf".to_string(),
                        selector: EncryptionSelector::VectorNames {
                            names: vec!["embedding".to_string()],
                        },
                        instance: "docs_vector_v1".to_string(),
                        binding: Some("vector-envelope/v1".to_string()),
                    },
                ],
            }),
            ..CollectionParams::empty()
        };

        validate_collection_crypto_runtime(&settings, "docs", &params).unwrap();
    }

    #[test]
    fn validate_collection_crypto_runtime_rejects_snapshot_payload_rule_without_runtime_material() {
        let settings = Settings::new(None).unwrap();
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("payload-field/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_collection_crypto_runtime(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { ref description } if description.contains("unknown payload crypto instance docs_payload_v1")),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn validate_collection_crypto_runtime_rejects_snapshot_vector_rule_without_runtime_instance() {
        let settings = Settings::new(None).unwrap();
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_collection_crypto_runtime(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { ref description } if description.contains("unknown crypto instance docs_vector_v1")),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn validate_collection_crypto_runtime_accepts_wrapped_vector_resource_key_metadata() {
        let mk_material = "tenant-a/mk-v1";
        let rk_material = "tenant-a/vector-rk-v3";
        let mut wrapped_rk_config = CryptoMaterialConfig {
            kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
            wrapped_by: Some(mk_material.to_string()),
            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
            rk_epoch: Some(3),
            scope: Some("collection:docs/vector:embedding".to_string()),
            ..CryptoMaterialConfig::default()
        };
        let aad = resource_key_wrap_aad(
            rk_material,
            &wrapped_rk_config,
            mk_material,
            RESOURCE_KEY_WRAP_ALGORITHM,
        );
        let wrapped = LocalMasterKeyProvider::new(mk_material, SecretKey::from_bytes([91u8; 32]))
            .unwrap()
            .wrap_resource_key(&SecretKey::from_bytes([92u8; 32]), &aad)
            .unwrap();
        wrapped_rk_config.nonce = Some(wrapped.nonce);
        wrapped_rk_config.wrapped_key_b64 = Some(wrapped.wrapped_key);

        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            rk_material.to_string(),
                        )]),
                        backend_ref: Some("openfhe_local".to_string()),
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/vector-rk@v3",
                            "profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                        }),
                    },
                )]),
                materials: HashMap::from([
                    (
                        mk_material.to_string(),
                        CryptoMaterialConfig {
                            kind: WRAPPING_KEY_32_KIND.to_string(),
                            source: Some("inline".to_string()),
                            env: None,
                            path: None,
                            value_b64: Some(BASE64URL_NOPAD.encode(&[91u8; 32])),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (rk_material.to_string(), wrapped_rk_config),
                ]),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                        sha256_b64: None,
                        size: Some(1),
                        timeout_ms: Some(5_000),
                    },
                )]),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        validate_collection_crypto_runtime(&settings, "docs", &params).unwrap();
    }

    #[test]
    fn validate_collection_crypto_runtime_rejects_vector_provider_mismatch() {
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            "tenant-a/payload-v1".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({ "key_id": "tenant-a:docs" }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/payload-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: SYMMETRIC_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        env: None,
                        path: None,
                        value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_collection_crypto_runtime(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { description } if description.contains(VECTOR_OPENFHE_CKKS_PROVIDER))
        );
    }

    #[test]
    fn validate_collection_crypto_runtime_rejects_unallowlisted_vector_profile() {
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            "tenant-a/vector-v1".to_string(),
                        )]),
                        backend_ref: Some("openfhe_local".to_string()),
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/vector@v2",
                            "profile": "raw-unsafe",
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/vector-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: SYMMETRIC_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        env: None,
                        path: None,
                        value_b64: Some(BASE64URL_NOPAD.encode(&[8u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                        sha256_b64: None,
                        size: Some(1),
                        timeout_ms: Some(5_000),
                    },
                )]),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_collection_crypto_runtime(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { description } if description.contains("not allowlisted"))
        );
    }

    #[test]
    fn validate_collection_crypto_runtime_requires_vector_profile() {
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            "tenant-a/vector-v1".to_string(),
                        )]),
                        backend_ref: Some("openfhe_local".to_string()),
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "material_fingerprint_id": "tenant-a/vector@v2",
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/vector-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: SYMMETRIC_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        env: None,
                        path: None,
                        value_b64: Some(BASE64URL_NOPAD.encode(&[8u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                        sha256_b64: None,
                        size: Some(1),
                        timeout_ms: Some(5_000),
                    },
                )]),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_collection_crypto_runtime(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { description } if description.contains("must set allowlisted profile"))
        );
    }

    #[test]
    fn validate_collection_crypto_runtime_requires_vector_material_fingerprint_id() {
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            "tenant-a/vector-v1".to_string(),
                        )]),
                        backend_ref: Some("openfhe_local".to_string()),
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/vector-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: SYMMETRIC_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        env: None,
                        path: None,
                        value_b64: Some(BASE64URL_NOPAD.encode(&[8u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                        sha256_b64: None,
                        size: Some(1),
                        timeout_ms: Some(5_000),
                    },
                )]),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_collection_crypto_runtime(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { description } if description.contains("must set material_fingerprint_id"))
        );
    }

    #[test]
    fn validate_collection_crypto_runtime_rejects_vector_missing_metadata_key_material() {
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_vector_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: Some("openfhe_local".to_string()),
                        options: json!({ "key_id": "tenant-a:docs" }),
                    },
                )]),
                materials: HashMap::new(),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                        sha256_b64: None,
                        size: Some(1),
                        timeout_ms: Some(5_000),
                    },
                )]),
            },
            ..Settings::new(None).unwrap()
        };
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "embedding_conf".to_string(),
                    selector: EncryptionSelector::VectorNames {
                        names: vec!["embedding".to_string()],
                    },
                    instance: "docs_vector_v1".to_string(),
                    binding: Some("vector-envelope/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_collection_crypto_runtime(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { description } if description.contains("metadata key material binding"))
        );
    }
}
