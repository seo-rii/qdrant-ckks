use std::fs;

use collection::config::{
    CkksCollectionConfig, CollectionEncryptionConfig, CollectionParams, EncryptionSelector,
};
use data_encoding::BASE64URL_NOPAD;
use qdrant_ckks::{
    AeadCipher, CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CKKS_VECTOR_KEY_DOMAIN,
    ExistingPayloadMode, LocalMasterKeyProvider, MasterKeyProvider, PAYLOAD_AES_GCM_PROVIDER,
    PAYLOAD_TEXT_KEY_DOMAIN, PayloadEncryptionError, PayloadEncryptionPolicy, PayloadTextEncryptor,
    RESOURCE_KEY_WRAP_ALGORITHM, SecretKey, VECTOR_OPENFHE_CKKS_PROVIDER, WrappedKeyBlob,
};
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
    #[error("payload crypto instance {instance} must bind role {role} to a symmetric key material")]
    MissingMaterialBinding { instance: String, role: String },
    #[error("payload crypto instance {instance} key_id option must be a string")]
    InvalidInstanceKeyId { instance: String },
    #[error("payload crypto instance {instance} material_fingerprint_id option must be a string")]
    InvalidInstanceMaterialFingerprintId { instance: String },
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

struct PayloadWriteRule {
    encryptor: PayloadTextEncryptor,
    policy: PayloadEncryptionPolicy,
}

pub struct PayloadWritePlan {
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
            encrypted += rule.encryptor.encrypt_selected_fields_with_mode(
                point_id,
                &mut payload.0,
                &rule.policy,
                ExistingPayloadMode::FailIfExisting,
            )?;
        }

        Ok(encrypted)
    }
}

pub fn payload_write_plan_for_collection(
    settings: &Settings,
    collection_name: &str,
    params: &CollectionParams,
) -> Result<Option<PayloadWritePlan>, PayloadWriteSetupError> {
    if let Some(encryption) = &params.encryption {
        return generic_payload_write_plan(
            &effective_settings(settings),
            collection_name,
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
            rules: vec![PayloadWriteRule { encryptor, policy }],
        }));
    }

    let Some(encryption) = CollectionEncryptionConfig::from_legacy_ckks(ckks) else {
        return Ok(None);
    };
    generic_payload_write_plan(&effective_settings(settings), collection_name, &encryption)
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
        if instance.provider != PAYLOAD_AES_GCM_PROVIDER {
            return Err(PayloadWriteSetupError::UnsupportedProvider {
                collection: collection_name.to_string(),
                rule_id: rule.id.clone(),
                provider: instance.provider.clone(),
            });
        }

        let material_ref = instance
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

        let key_id = resolve_payload_key_id(collection_name, encryption, &rule.instance, instance)?;
        let resource_key = decode_resource_key(runtime_settings, material_ref, material)?;
        let payload_key = resource_key
            .derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)
            .map_err(|err| PayloadWriteSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;
        let cipher = if let Some(material_fingerprint_id) =
            instance.options.get(MATERIAL_FINGERPRINT_ID_OPTION)
        {
            let material_fingerprint_id = material_fingerprint_id.as_str().ok_or_else(|| {
                PayloadWriteSetupError::InvalidInstanceMaterialFingerprintId {
                    instance: rule.instance.clone(),
                }
            })?;
            AeadCipher::new_with_material_fingerprint(key_id, payload_key, material_fingerprint_id)
        } else {
            AeadCipher::new(key_id, payload_key)
        }
        .map_err(|err| PayloadWriteSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;
        let policy = PayloadEncryptionPolicy::new(paths.clone())?;
        let encryptor = PayloadTextEncryptor::new(collection_name, cipher)?
            .with_encryption_epoch(encryption.encryption_epoch);

        rules.push(PayloadWriteRule { encryptor, policy });
    }

    if rules.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PayloadWritePlan { rules }))
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
        generic_payload_write_plan(runtime_settings, collection_name, &payload_only_encryption)
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
        if let Some(profile) = instance.options.get(CKKS_PROFILE_OPTION) {
            let Some(profile) = profile.as_str() else {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} profile option must be a string",
                    rule.instance
                )));
            };
            if profile != CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50 {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} profile {profile} is not allowlisted; expected {CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50}",
                    rule.instance
                )));
            }
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
            AeadCipher::new_with_material_fingerprint(
                key_id,
                metadata_key,
                material_fingerprint_id,
            )
            .map_err(|err| {
                StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto metadata key validation failed: {err}"
                ))
            })?;
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
        LocalMasterKeyProvider, MasterKeyProvider, RESOURCE_KEY_WRAP_ALGORITHM,
        is_encrypted_payload_value,
    };
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
                            options: json!({ "key_id": "tenant-a:docs" }),
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
