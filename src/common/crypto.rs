use std::collections::{BTreeMap, HashSet};
use std::fs;

use collection::config::{
    CkksCollectionConfig, CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams,
    EncryptionSelector,
};
use data_encoding::BASE64URL_NOPAD;
use qdrant_ckks::{
    AeadCipher, CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CKKS_VECTOR_KEY_DOMAIN,
    CLIENT_PAYLOAD_ENVELOPE_BINDING, ClientPayloadNonceReplayKey,
    ClientPayloadSignatureVerification, ClientPayloadValidationContext, ExistingPayloadMode,
    LocalMasterKeyProvider, MasterKeyProvider, PAYLOAD_AES_GCM_PROVIDER,
    PAYLOAD_CLIENT_AEAD_PROVIDER, PAYLOAD_FIELD_BINDING, PayloadEncryptionError,
    PayloadEncryptionPolicy, PayloadTextEncryptor, RESOURCE_KEY_WRAP_ALGORITHM, SecretKey,
    VECTOR_ENVELOPE_BINDING, VECTOR_OPENFHE_CKKS_PROVIDER, WrappedKeyBlob,
    client_payload_nonce_replay_key, client_payload_signature_key_id, rewrap_resource_key,
    validate_client_payload_value,
};
use segment::json_path::JsonPath;
use segment::types::Payload;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use storage::content_manager::collection_meta_ops::CreateCollection;
use storage::content_manager::errors::StorageError;
use thiserror::Error;
use validator::Validate;
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
    #[error("crypto instance {instance} option {option} is invalid: {reason}")]
    InvalidInstanceOption {
        instance: String,
        option: String,
        reason: String,
    },
    #[error(transparent)]
    LegacyCkks(#[from] crate::common::ckks::CkksSetupError),
}

const PAYLOAD_SYM_KEY_ROLE: &str = "sym_key";
const SYMMETRIC_KEY_32_KIND: &str = "symmetric_key_32";
const WRAPPING_KEY_32_KIND: &str = "wrapping_key_32";
const WRAPPED_SYMMETRIC_KEY_32_KIND: &str = "wrapped_symmetric_key_32";
const RESOURCE_KEY_STATE_ACTIVE: &str = "active";
const RESOURCE_KEY_STATE_RETIRED: &str = "retired";
const RESOURCE_KEY_STATE_DISABLED: &str = "disabled";
const RESOURCE_KEY_STATE_DESTROYED: &str = "destroyed";
const MATERIAL_FINGERPRINT_ID_OPTION: &str = "material_fingerprint_id";
const KEY_ID_REQUIRED_OPTION: &str = "key_id_required";
const EXPECTED_RK_ID_OPTION: &str = "expected_rk_id";
const MIN_RK_EPOCH_OPTION: &str = "min_rk_epoch";
const MAX_RK_EPOCH_OPTION: &str = "max_rk_epoch";
const RETIRED_MATERIALS_OPTION: &str = "retired_materials";
const RETIRED_MATERIAL_REF_OPTION: &str = "material";
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
    #[error("collection {collection} server payload rule {rule_id} must use binding {binding}")]
    InvalidPayloadBinding {
        collection: String,
        rule_id: String,
        binding: String,
    },
    #[error(
        "payload crypto instance {instance} uses client-side payload provider and must not configure server materials or backend_ref"
    )]
    ClientProviderMustBeServerBlind { instance: String },
    #[error("payload crypto instance {instance} must bind role {role} to a symmetric key material")]
    MissingMaterialBinding { instance: String, role: String },
    #[error("payload crypto instance {instance} key_id option must be a string")]
    InvalidInstanceKeyId { instance: String },
    #[error("payload crypto instance {instance} must require client envelope key_id")]
    ClientKeyIdMustBeRequired { instance: String },
    #[error("payload crypto instance {instance} expected_rk_id option must be a string")]
    InvalidClientResourceKeyId { instance: String },
    #[error("payload crypto instance {instance} expected_rk_id must match the collection key_id")]
    ClientResourceKeyIdCollectionMismatch { instance: String },
    #[error(
        "payload crypto instance {instance} must set expected_rk_id for client payload envelopes"
    )]
    MissingClientResourceKeyId { instance: String },
    #[error("payload crypto instance {instance} {option} option must be an unsigned integer")]
    InvalidClientResourceKeyEpoch { instance: String, option: String },
    #[error("payload crypto instance {instance} must set {option} for client payload envelopes")]
    MissingClientResourceKeyEpoch { instance: String, option: String },
    #[error("payload crypto instance {instance} min_rk_epoch must be <= max_rk_epoch")]
    InvalidClientResourceKeyEpochRange { instance: String },
    #[error(
        "payload crypto instance {instance} must pin min_rk_epoch and max_rk_epoch to the same active client resource-key epoch"
    )]
    ClientResourceKeyEpochMustBePinned { instance: String },
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
    #[error("payload crypto instance {instance} must configure client signature verification")]
    MissingClientSignatureVerifier { instance: String },
    #[error("payload crypto instance {instance} material_fingerprint_id option must be a string")]
    InvalidInstanceMaterialFingerprintId { instance: String },
    #[error("payload crypto instance {instance} must set material_fingerprint_id")]
    MissingMaterialFingerprintId { instance: String },
    #[error(
        "payload crypto instance {instance} retired_materials option must be an array of objects with material and material_fingerprint_id"
    )]
    InvalidRetiredMaterials { instance: String },
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
        expected_rk_id: Option<String>,
        min_rk_epoch: Option<u64>,
        max_rk_epoch: Option<u64>,
        key_id_required: bool,
        signature_required: bool,
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
    pub fn has_server_encrypt_rules(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| matches!(rule, PayloadWriteRule::ServerEncrypt { .. }))
    }

    pub fn has_client_envelope_rules(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| matches!(rule, PayloadWriteRule::ClientEnvelope { .. }))
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "test helper for exercising payload write plans without constructing public update operations"
        )
    )]
    pub fn encrypt_payload(
        &self,
        point_id: &str,
        payload: &mut Payload,
    ) -> Result<usize, PayloadWriteSetupError> {
        let mut seen_client_nonces = HashSet::new();
        self.encrypt_payload_with_replay_cache(point_id, payload, &mut seen_client_nonces)
    }

    pub(crate) fn encrypt_payload_with_replay_cache(
        &self,
        point_id: &str,
        payload: &mut Payload,
        seen_client_nonces: &mut HashSet<ClientPayloadNonceReplayKey>,
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
                    expected_rk_id,
                    min_rk_epoch,
                    max_rk_epoch,
                    key_id_required,
                    signature_required,
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
                                    expected_rk_id: expected_rk_id.as_deref(),
                                    min_rk_epoch: *min_rk_epoch,
                                    max_rk_epoch: *max_rk_epoch,
                                    key_id_required: *key_id_required,
                                    signature_required: *signature_required,
                                    signature_verification,
                                },
                            )?;
                            let Some(nonce_replay_key) =
                                client_payload_nonce_replay_key(value, field)?
                            else {
                                return Err(PayloadWriteSetupError::Payload(
                                    PayloadEncryptionError::ExpectedEncryptedEnvelope {
                                        field: field.clone(),
                                        found: "object",
                                    },
                                ));
                            };
                            if !seen_client_nonces.insert(nonce_replay_key) {
                                return Err(PayloadWriteSetupError::Payload(
                                    PayloadEncryptionError::ClientNonceReplay,
                                ));
                            }
                            encrypted += 1;
                        }
                    }
                }
            }
        }

        Ok(encrypted)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "reserved for the admin crypto migration path that re-encrypts stale payload envelopes"
        )
    )]
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
                    expected_rk_id,
                    min_rk_epoch,
                    max_rk_epoch,
                    key_id_required,
                    signature_required,
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
                                    expected_rk_id: expected_rk_id.as_deref(),
                                    min_rk_epoch: *min_rk_epoch,
                                    max_rk_epoch: *max_rk_epoch,
                                    key_id_required: *key_id_required,
                                    signature_required: *signature_required,
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

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "test helper; production callers use the crypto-id aware payload write plan builder"
    )
)]
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

pub fn validate_recovered_collection_crypto_runtime(
    settings: &Settings,
    collection_name: &str,
    params: &CollectionParams,
) -> Result<(), StorageError> {
    if let Some(encryption) = &params.encryption {
        encryption.validate().map_err(|err| {
            StorageError::bad_input(format!(
                "recovered collection {collection_name} encryption config is invalid: {err}",
            ))
        })?;
    }
    if let Some(ckks) = &params.ckks {
        ckks.validate().map_err(|err| {
            StorageError::bad_input(format!(
                "recovered collection {collection_name} ckks config is invalid: {err}",
            ))
        })?;
    }

    validate_collection_crypto_runtime(settings, collection_name, params)
}

pub fn validate_recovered_collection_crypto_config(
    settings: &Settings,
    collection_name: &str,
    config: &CollectionConfigInternal,
) -> Result<(), StorageError> {
    if config.params.effective_encryption().is_some() && config.uuid.is_none() {
        return Err(StorageError::bad_input(format!(
            "recovered encrypted collection {collection_name} is missing a stable UUID; \
             encrypted payload/vector AAD requires an explicit stable collection identity",
        )));
    }

    validate_recovered_collection_crypto_runtime(settings, collection_name, &config.params)
}

pub fn effective_settings(settings: &Settings) -> CryptoSettings {
    if settings.crypto.is_configured() {
        settings.crypto.clone()
    } else {
        CryptoSettings::from_legacy_ckks(&settings.ckks)
    }
}

pub fn crypto_runtime_capability_fingerprint(settings: &Settings) -> String {
    let mut instances = BTreeMap::new();
    for (instance_name, instance) in &settings.crypto.instances {
        let mut materials = BTreeMap::new();
        for (role, material_ref) in &instance.materials {
            materials.insert(role, material_ref);
        }
        instances.insert(
            instance_name,
            json!({
                "provider": instance.provider,
                "materials": materials,
                "backend_ref": instance.backend_ref,
                "options": instance.options,
            }),
        );
    }

    let mut materials = BTreeMap::new();
    for (material_name, material) in &settings.crypto.materials {
        materials.insert(
            material_name,
            json!({
                "kind": material.kind,
                "source": material.source,
                "env": material.env,
                "path": material.path,
                "has_value_b64": material.value_b64.is_some(),
                "wrapped_by": material.wrapped_by,
                "wrap_algorithm": material.wrap_algorithm,
                "has_nonce": material.nonce.is_some(),
                "has_wrapped_key_b64": material.wrapped_key_b64.is_some(),
                "rk_epoch": material.rk_epoch,
                "state": material.state,
                "scope": material.scope,
            }),
        );
    }

    let mut backends = BTreeMap::new();
    for (backend_name, backend) in &settings.crypto.backends {
        backends.insert(
            backend_name,
            json!({
                "kind": backend.kind,
                "program": backend.program,
                "sha256_b64": backend.sha256_b64,
                "size": backend.size,
                "timeout_ms": backend.timeout_ms,
            }),
        );
    }

    let mut legacy_collections = BTreeMap::new();
    for (collection_name, collection) in &settings.ckks.collections {
        legacy_collections.insert(
            collection_name,
            json!({
                "key_id": collection.key_id,
                "has_master_key_b64": collection.master_key_b64.is_some(),
                "has_resource_key_b64": collection.resource_key_b64.is_some(),
                "openfhe_bridge_path": collection.openfhe_bridge_path,
                "openfhe_bridge_sha256_b64": collection.openfhe_bridge_sha256_b64,
            }),
        );
    }

    let view = json!({
        "version": 1,
        "crypto": {
            "allow_inline_key_material": settings.crypto.allow_inline_key_material,
            "instances": instances,
            "materials": materials,
            "backends": backends,
        },
        "legacy_ckks": {
            "enabled": settings.ckks.enabled,
            "allow_inline_key_material": settings.ckks.allow_inline_key_material,
            "key_id": settings.ckks.key_id,
            "has_master_key_b64": settings.ckks.master_key_b64.is_some(),
            "has_resource_key_b64": settings.ckks.resource_key_b64.is_some(),
            "openfhe_bridge_path": settings.ckks.openfhe_bridge_path,
            "openfhe_bridge_sha256_b64": settings.ckks.openfhe_bridge_sha256_b64,
            "collections": legacy_collections,
        },
    });
    let canonical = serde_json::to_vec(&view)
        .expect("serializing sanitized crypto runtime capability fingerprint cannot fail");
    let digest = Sha256::digest(&canonical);
    BASE64URL_NOPAD.encode(&digest)
}

pub fn validate_crypto_runtime_capability_parity<'a>(
    settings: &Settings,
    peer_fingerprints: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<(), StorageError> {
    let local_fingerprint = crypto_runtime_capability_fingerprint(settings);
    for (peer_id, peer_fingerprint) in peer_fingerprints {
        if peer_fingerprint != local_fingerprint {
            return Err(StorageError::bad_input(format!(
                "crypto runtime capability mismatch for peer {peer_id}: local fingerprint {local_fingerprint} does not match peer fingerprint {peer_fingerprint}; encrypted shard transfer and replication must fail closed",
            )));
        }
    }

    Ok(())
}

pub fn validate_runtime_config(settings: &Settings) -> Result<(), CryptoSetupError> {
    let _capability_fingerprint = crypto_runtime_capability_fingerprint(settings);
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

        if instance.provider == PAYLOAD_AES_GCM_PROVIDER
            && let Some(retired_materials) = instance.options.get(RETIRED_MATERIALS_OPTION)
        {
            let active_material_ref = instance.materials.get(PAYLOAD_SYM_KEY_ROLE);
            let Some(retired_materials) = retired_materials.as_array() else {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: RETIRED_MATERIALS_OPTION.to_string(),
                    reason: "expected an array of objects".to_string(),
                });
            };
            let mut seen_retired_material_refs = HashSet::new();
            for retired_material in retired_materials {
                let Some(retired_material) = retired_material.as_object() else {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: RETIRED_MATERIALS_OPTION.to_string(),
                        reason: "expected an array of objects".to_string(),
                    });
                };
                let Some(retired_material_ref) = retired_material
                    .get(RETIRED_MATERIAL_REF_OPTION)
                    .and_then(Value::as_str)
                else {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: RETIRED_MATERIALS_OPTION.to_string(),
                        reason: "missing material".to_string(),
                    });
                };
                if active_material_ref.is_some_and(|active| active == retired_material_ref) {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: RETIRED_MATERIALS_OPTION.to_string(),
                        reason: "retired material must not be the active sym_key".to_string(),
                    });
                }
                if !seen_retired_material_refs.insert(retired_material_ref) {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: RETIRED_MATERIALS_OPTION.to_string(),
                        reason: "duplicate retired material".to_string(),
                    });
                }
                let Some(retired_material_fingerprint_id) = retired_material
                    .get(MATERIAL_FINGERPRINT_ID_OPTION)
                    .and_then(Value::as_str)
                else {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: RETIRED_MATERIALS_OPTION.to_string(),
                        reason: "missing material_fingerprint_id".to_string(),
                    });
                };
                if !is_crypto_identifier(retired_material_fingerprint_id) {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: RETIRED_MATERIALS_OPTION.to_string(),
                        reason: "invalid material_fingerprint_id".to_string(),
                    });
                }
                let Some(retired_material_config) = settings.materials.get(retired_material_ref)
                else {
                    return Err(CryptoSetupError::UnknownMaterial {
                        instance: instance_name.clone(),
                        role: RETIRED_MATERIALS_OPTION.to_string(),
                        material_ref: retired_material_ref.to_string(),
                    });
                };
                if retired_material_config.kind == WRAPPED_SYMMETRIC_KEY_32_KIND
                    && wrapped_resource_key_state(retired_material_config)
                        != RESOURCE_KEY_STATE_RETIRED
                {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: RETIRED_MATERIALS_OPTION.to_string(),
                        reason: "wrapped retired material must have state retired".to_string(),
                    });
                }
            }
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
        || material.state.is_some()
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
    match wrapped_resource_key_state(material) {
        RESOURCE_KEY_STATE_ACTIVE
        | RESOURCE_KEY_STATE_RETIRED
        | RESOURCE_KEY_STATE_DISABLED
        | RESOURCE_KEY_STATE_DESTROYED => {}
        state => {
            return Err(CryptoSetupError::InvalidWrappedMaterial {
                material: material_name.to_string(),
                reason: format!("unsupported state {state}"),
            });
        }
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

fn wrapped_resource_key_state(material: &CryptoMaterialConfig) -> &str {
    material
        .state
        .as_deref()
        .unwrap_or(RESOURCE_KEY_STATE_ACTIVE)
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
                if rule
                    .binding
                    .as_deref()
                    .is_some_and(|binding| binding != PAYLOAD_FIELD_BINDING)
                {
                    return Err(PayloadWriteSetupError::InvalidPayloadBinding {
                        collection: collection_name.to_string(),
                        rule_id: rule.id.clone(),
                        binding: PAYLOAD_FIELD_BINDING.to_string(),
                    });
                }
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
                let mut encryptor = if let Some(rk_epoch) = material.rk_epoch {
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

                if let Some(retired_materials) = instance.options.get(RETIRED_MATERIALS_OPTION) {
                    let Some(retired_materials) = retired_materials.as_array() else {
                        return Err(PayloadWriteSetupError::InvalidRetiredMaterials {
                            instance: rule.instance.clone(),
                        });
                    };
                    let mut seen_retired_material_refs = HashSet::new();
                    for retired_material in retired_materials {
                        let Some(retired_material) = retired_material.as_object() else {
                            return Err(PayloadWriteSetupError::InvalidRetiredMaterials {
                                instance: rule.instance.clone(),
                            });
                        };
                        let Some(retired_material_ref) = retired_material
                            .get(RETIRED_MATERIAL_REF_OPTION)
                            .and_then(Value::as_str)
                        else {
                            return Err(PayloadWriteSetupError::InvalidRetiredMaterials {
                                instance: rule.instance.clone(),
                            });
                        };
                        if retired_material_ref == material_ref
                            || !seen_retired_material_refs.insert(retired_material_ref)
                        {
                            return Err(PayloadWriteSetupError::InvalidRetiredMaterials {
                                instance: rule.instance.clone(),
                            });
                        }
                        let Some(retired_material_fingerprint_id) = retired_material
                            .get(MATERIAL_FINGERPRINT_ID_OPTION)
                            .and_then(Value::as_str)
                        else {
                            return Err(PayloadWriteSetupError::InvalidRetiredMaterials {
                                instance: rule.instance.clone(),
                            });
                        };
                        let retired_material_config = runtime_settings
                            .materials
                            .get(retired_material_ref)
                            .ok_or_else(|| PayloadWriteSetupError::MissingMaterialBinding {
                                instance: rule.instance.clone(),
                                role: PAYLOAD_SYM_KEY_ROLE.to_string(),
                            })?;
                        let retired_resource_key = decode_retired_resource_key(
                            runtime_settings,
                            retired_material_ref,
                            retired_material_config,
                        )?;
                        encryptor = if let Some(rk_epoch) = retired_material_config.rk_epoch {
                            encryptor.with_retired_resource_key_metadata(
                                key_id,
                                &retired_resource_key,
                                retired_material_fingerprint_id,
                                retired_material_ref,
                                rk_epoch,
                            )
                        } else {
                            encryptor.with_retired_resource_key(
                                key_id,
                                &retired_resource_key,
                                retired_material_fingerprint_id,
                            )
                        }?;
                    }
                }

                rules.push(PayloadWriteRule::ServerEncrypt { encryptor, policy });
            }
            PAYLOAD_CLIENT_AEAD_PROVIDER => {
                if !instance.materials.is_empty() || instance.backend_ref.is_some() {
                    return Err(PayloadWriteSetupError::ClientProviderMustBeServerBlind {
                        instance: rule.instance.clone(),
                    });
                }
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
                    Some(Value::Bool(true)) => true,
                    Some(Value::Bool(false)) => {
                        return Err(PayloadWriteSetupError::ClientKeyIdMustBeRequired {
                            instance: rule.instance.clone(),
                        });
                    }
                    Some(_) => {
                        return Err(PayloadWriteSetupError::InvalidInstanceKeyId {
                            instance: rule.instance.clone(),
                        });
                    }
                };
                let expected_rk_id = match instance.options.get(EXPECTED_RK_ID_OPTION) {
                    None | Some(Value::Null) => {
                        return Err(PayloadWriteSetupError::MissingClientResourceKeyId {
                            instance: rule.instance.clone(),
                        });
                    }
                    Some(Value::String(value)) if is_crypto_identifier(value) => {
                        Some(value.clone())
                    }
                    Some(Value::String(_)) => {
                        return Err(PayloadWriteSetupError::InvalidClientResourceKeyId {
                            instance: rule.instance.clone(),
                        });
                    }
                    Some(_) => {
                        return Err(PayloadWriteSetupError::InvalidClientResourceKeyId {
                            instance: rule.instance.clone(),
                        });
                    }
                };
                if expected_rk_id.as_deref() != expected_key_id {
                    return Err(
                        PayloadWriteSetupError::ClientResourceKeyIdCollectionMismatch {
                            instance: rule.instance.clone(),
                        },
                    );
                }
                let min_rk_epoch = match instance.options.get(MIN_RK_EPOCH_OPTION) {
                    None | Some(Value::Null) => {
                        return Err(PayloadWriteSetupError::MissingClientResourceKeyEpoch {
                            instance: rule.instance.clone(),
                            option: MIN_RK_EPOCH_OPTION.to_string(),
                        });
                    }
                    Some(Value::Number(value)) => value
                        .as_u64()
                        .ok_or_else(|| PayloadWriteSetupError::InvalidClientResourceKeyEpoch {
                            instance: rule.instance.clone(),
                            option: MIN_RK_EPOCH_OPTION.to_string(),
                        })?
                        .into(),
                    Some(_) => {
                        return Err(PayloadWriteSetupError::InvalidClientResourceKeyEpoch {
                            instance: rule.instance.clone(),
                            option: MIN_RK_EPOCH_OPTION.to_string(),
                        });
                    }
                };
                let max_rk_epoch = match instance.options.get(MAX_RK_EPOCH_OPTION) {
                    None | Some(Value::Null) => {
                        return Err(PayloadWriteSetupError::MissingClientResourceKeyEpoch {
                            instance: rule.instance.clone(),
                            option: MAX_RK_EPOCH_OPTION.to_string(),
                        });
                    }
                    Some(Value::Number(value)) => value
                        .as_u64()
                        .ok_or_else(|| PayloadWriteSetupError::InvalidClientResourceKeyEpoch {
                            instance: rule.instance.clone(),
                            option: MAX_RK_EPOCH_OPTION.to_string(),
                        })?
                        .into(),
                    Some(_) => {
                        return Err(PayloadWriteSetupError::InvalidClientResourceKeyEpoch {
                            instance: rule.instance.clone(),
                            option: MAX_RK_EPOCH_OPTION.to_string(),
                        });
                    }
                };
                if let (Some(min_rk_epoch), Some(max_rk_epoch)) = (min_rk_epoch, max_rk_epoch)
                    && min_rk_epoch > max_rk_epoch
                {
                    return Err(PayloadWriteSetupError::InvalidClientResourceKeyEpochRange {
                        instance: rule.instance.clone(),
                    });
                }
                if min_rk_epoch != max_rk_epoch {
                    return Err(PayloadWriteSetupError::ClientResourceKeyEpochMustBePinned {
                        instance: rule.instance.clone(),
                    });
                }
                let (signature_required, signature_verifier) =
                    client_payload_signature_verifier(instance, &rule.instance)?;
                rules.push(PayloadWriteRule::ClientEnvelope {
                    policy,
                    expected_key_id: expected_key_id.map(ToOwned::to_owned),
                    expected_rk_id,
                    min_rk_epoch,
                    max_rk_epoch,
                    key_id_required,
                    signature_required,
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
) -> Result<(bool, Option<ClientPayloadSignatureVerifier>), PayloadWriteSetupError> {
    let signature_key_id = match instance.options.get(SIGNATURE_KEY_ID_OPTION) {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if is_crypto_identifier(value) => Some(value.as_str()),
        Some(Value::String(_)) => {
            return Err(PayloadWriteSetupError::InvalidClientSignatureKeyId {
                instance: instance_id.to_string(),
            });
        }
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
            if !is_crypto_identifier(key_id) {
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

        return Ok((
            true,
            Some(ClientPayloadSignatureVerifier::Registry(public_keys)),
        ));
    }

    match (signature_key_id, signature_public_key) {
        (None, None) => Err(PayloadWriteSetupError::MissingClientSignatureVerifier {
            instance: instance_id.to_string(),
        }),
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
            Ok((
                true,
                Some(ClientPayloadSignatureVerifier::Single {
                    key_id: key_id.to_string(),
                    public_key,
                }),
            ))
        }
    }
}

fn is_crypto_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
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

        if rule
            .binding
            .as_deref()
            .is_some_and(|binding| binding != VECTOR_ENVELOPE_BINDING)
        {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} vector rule {} must use binding {VECTOR_ENVELOPE_BINDING}",
                rule.id
            )));
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
        Some(Value::String(key_id)) if is_crypto_identifier(key_id) => Some(key_id.as_str()),
        Some(Value::String(_)) => {
            return Err(PayloadWriteSetupError::InvalidInstanceKeyId {
                instance: instance_name.to_string(),
            });
        }
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
        Some(Value::String(key_id)) if is_crypto_identifier(key_id) => Some(key_id.as_str()),
        Some(Value::String(_)) => {
            return Err(PayloadWriteSetupError::InvalidInstanceKeyId {
                instance: instance_name.to_string(),
            });
        }
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

fn decode_retired_resource_key(
    runtime_settings: &CryptoSettings,
    material_name: &str,
    material: &CryptoMaterialConfig,
) -> Result<SecretKey, PayloadWriteSetupError> {
    match material.kind.as_str() {
        SYMMETRIC_KEY_32_KIND => decode_direct_material_key(material_name, material),
        WRAPPED_SYMMETRIC_KEY_32_KIND => decode_wrapped_resource_key_for_state(
            runtime_settings,
            material_name,
            material,
            RESOURCE_KEY_STATE_RETIRED,
        ),
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
    decode_wrapped_resource_key_for_state(
        runtime_settings,
        material_name,
        material,
        RESOURCE_KEY_STATE_ACTIVE,
    )
}

fn decode_wrapped_resource_key_for_state(
    runtime_settings: &CryptoSettings,
    material_name: &str,
    material: &CryptoMaterialConfig,
    expected_state: &str,
) -> Result<SecretKey, PayloadWriteSetupError> {
    match (wrapped_resource_key_state(material), expected_state) {
        (state, expected) if state == expected => {}
        (RESOURCE_KEY_STATE_ACTIVE, RESOURCE_KEY_STATE_RETIRED) => {
            return Err(PayloadWriteSetupError::InvalidWrappedMaterial {
                material: material_name.to_string(),
                reason: "active resource key material cannot be used as retired decryption key"
                    .to_string(),
            });
        }
        (RESOURCE_KEY_STATE_RETIRED, RESOURCE_KEY_STATE_ACTIVE) => {
            return Err(PayloadWriteSetupError::InvalidWrappedMaterial {
                material: material_name.to_string(),
                reason: "retired resource key material cannot be used for active encryption"
                    .to_string(),
            });
        }
        (RESOURCE_KEY_STATE_DISABLED | RESOURCE_KEY_STATE_DESTROYED, _) => {
            return Err(PayloadWriteSetupError::InvalidWrappedMaterial {
                material: material_name.to_string(),
                reason: format!(
                    "resource key material state {} cannot be unwrapped",
                    wrapped_resource_key_state(material)
                ),
            });
        }
        (state, _) => {
            return Err(PayloadWriteSetupError::InvalidWrappedMaterial {
                material: material_name.to_string(),
                reason: format!("unsupported state {state}"),
            });
        }
    }

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

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reserved for the admin MK rotation operation that rewraps resource keys without data rewrite"
    )
)]
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
    use std::collections::{HashMap, HashSet};

    use collection::config::{
        CkksCollectionConfig, CollectionConfigInternal, CollectionEncryptionConfig,
        CollectionParams, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, WalConfig,
    };
    use collection::optimizers_builder::OptimizersConfig;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_ckks::{
        CLIENT_ENCRYPTED_PAYLOAD_MARKER, CLIENT_PAYLOAD_ENVELOPE_BINDING, LocalMasterKeyProvider,
        MasterKeyProvider, RESOURCE_KEY_WRAP_ALGORITHM, client_payload_signature_message,
        is_client_encrypted_payload_value, is_encrypted_payload_value,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::{Value, json};
    use uuid::Uuid;

    use super::*;
    use crate::settings::{CkksConfig, CryptoInstanceConfig};

    fn recovered_config(params: CollectionParams, uuid: Option<Uuid>) -> CollectionConfigInternal {
        CollectionConfigInternal {
            params,
            hnsw_config: segment::types::HnswConfig::default(),
            optimizer_config: OptimizersConfig {
                deleted_threshold: 0.1,
                vacuum_min_vector_number: 1000,
                default_segment_number: 0,
                max_segment_size: None,
                #[expect(deprecated)]
                memmap_threshold: None,
                indexing_threshold: Some(100_000),
                flush_interval_sec: 60,
                max_optimization_threads: Some(0),
                prevent_unoptimized: None,
            },
            wal_config: WalConfig::default(),
            quantization_config: None,
            strict_mode_config: None,
            uuid,
            metadata: None,
        }
    }

    fn signed_client_envelope(
        collection_id: &str,
        point_id: &str,
        field_path: &str,
        signing_key_id: &str,
    ) -> (serde_json::Value, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut envelope = {
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
                        "collection_id": collection_id,
                        "point_id": point_id,
                        "field_path": field_path,
                        "schema_version": 1
                    },
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AQID",
                    "signature": {
                        "alg": "ed25519",
                        "key_id": signing_key_id,
                        "sig": ""
                    }
                }),
            );
            Value::Object(marker)
        };
        let message = client_payload_signature_message(&envelope, field_path).unwrap();
        let signature = key_pair.sign(&message);
        envelope
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

        (envelope, key_pair.public_key().as_ref().to_vec())
    }

    fn client_policy_options(mut options: serde_json::Value) -> serde_json::Value {
        let object = options.as_object_mut().unwrap();
        object.insert(
            EXPECTED_RK_ID_OPTION.to_string(),
            json!("tenant-a/client-rk-2026-04"),
        );
        object.insert(MIN_RK_EPOCH_OPTION.to_string(), json!(3));
        object.insert(MAX_RK_EPOCH_OPTION.to_string(), json!(3));
        options
    }

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
    fn validate_crypto_settings_rejects_invalid_retired_payload_materials() {
        let mut settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_v1".to_string(),
                CryptoInstanceConfig {
                    provider: "payload/aes-256-gcm@v1".to_string(),
                    materials: HashMap::from([(
                        PAYLOAD_SYM_KEY_ROLE.to_string(),
                        "tenant-a/payload-v2".to_string(),
                    )]),
                    backend_ref: None,
                    options: json!({
                        "material_fingerprint_id": "tenant-a/payload@v2",
                        "retired_materials": [{
                            "material": "tenant-a/payload-v1",
                            "material_fingerprint_id": "tenant-a/payload@v1",
                        }],
                    }),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/payload-v2".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[2_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::new(),
        };

        assert_eq!(
            validate_crypto_settings(&settings),
            Err(CryptoSetupError::UnknownMaterial {
                instance: "docs_payload_v1".to_string(),
                role: RETIRED_MATERIALS_OPTION.to_string(),
                material_ref: "tenant-a/payload-v1".to_string(),
            }),
        );

        settings.materials.insert(
            "tenant-a/payload-v1".to_string(),
            CryptoMaterialConfig {
                kind: SYMMETRIC_KEY_32_KIND.to_string(),
                source: Some("inline".to_string()),
                value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                ..CryptoMaterialConfig::default()
            },
        );
        validate_crypto_settings(&settings).unwrap();

        settings.materials.insert(
            "tenant-a/mk".to_string(),
            CryptoMaterialConfig {
                kind: WRAPPING_KEY_32_KIND.to_string(),
                source: Some("inline".to_string()),
                value_b64: Some(BASE64URL_NOPAD.encode(&[9_u8; 32])),
                ..CryptoMaterialConfig::default()
            },
        );
        settings.materials.insert(
            "tenant-a/payload-v1".to_string(),
            CryptoMaterialConfig {
                kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                wrapped_by: Some("tenant-a/mk".to_string()),
                wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                nonce: Some(BASE64URL_NOPAD.encode(&[3_u8; 12])),
                wrapped_key_b64: Some(BASE64URL_NOPAD.encode(&[4_u8; 48])),
                rk_epoch: Some(1),
                scope: Some("collection:docs".to_string()),
                ..CryptoMaterialConfig::default()
            },
        );
        assert!(matches!(
            validate_crypto_settings(&settings),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));
        settings
            .materials
            .get_mut("tenant-a/payload-v1")
            .unwrap()
            .state = Some(RESOURCE_KEY_STATE_RETIRED.to_string());
        validate_crypto_settings(&settings).unwrap();

        settings
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .get_mut(RETIRED_MATERIALS_OPTION)
            .unwrap()
            .as_array_mut()
            .unwrap()[0]
            .as_object_mut()
            .unwrap()
            .insert(
                MATERIAL_FINGERPRINT_ID_OPTION.to_string(),
                json!("tenant a/payload@v1"),
            );
        assert!(matches!(
            validate_crypto_settings(&settings),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));
        settings
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .get_mut(RETIRED_MATERIALS_OPTION)
            .unwrap()
            .as_array_mut()
            .unwrap()[0]
            .as_object_mut()
            .unwrap()
            .insert(
                MATERIAL_FINGERPRINT_ID_OPTION.to_string(),
                json!("tenant-a/payload@v1"),
            );
        validate_crypto_settings(&settings).unwrap();

        settings
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(
                RETIRED_MATERIALS_OPTION.to_string(),
                json!([{
                    "material": "tenant-a/payload-v2",
                    "material_fingerprint_id": "tenant-a/payload@v2",
                }]),
            );
        assert!(matches!(
            validate_crypto_settings(&settings),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));
    }

    #[test]
    fn crypto_runtime_capability_fingerprint_redacts_key_material() {
        let mut settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "payload/aes-256-gcm@v1".to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            "tenant-a/docs-rk".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a/docs",
                            "material_fingerprint_id": "tenant-a/docs-rk@v1",
                        }),
                    },
                )]),
                materials: HashMap::from([
                    (
                        "tenant-a/mk".to_string(),
                        CryptoMaterialConfig {
                            kind: WRAPPING_KEY_32_KIND.to_string(),
                            source: Some("inline".to_string()),
                            env: None,
                            path: None,
                            value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                            wrapped_by: None,
                            wrap_algorithm: None,
                            nonce: None,
                            wrapped_key_b64: None,
                            rk_epoch: None,
                            state: None,
                            scope: None,
                        },
                    ),
                    (
                        "tenant-a/docs-rk".to_string(),
                        CryptoMaterialConfig {
                            kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                            source: Some("wrapped".to_string()),
                            env: None,
                            path: None,
                            value_b64: None,
                            wrapped_by: Some("tenant-a/mk".to_string()),
                            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                            nonce: Some(BASE64URL_NOPAD.encode(&[2_u8; 12])),
                            wrapped_key_b64: Some(BASE64URL_NOPAD.encode(&[3_u8; 48])),
                            rk_epoch: Some(3),
                            state: None,
                            scope: Some("collection:docs".to_string()),
                        },
                    ),
                ]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        };
        let fingerprint = crypto_runtime_capability_fingerprint(&settings);

        settings
            .crypto
            .materials
            .get_mut("tenant-a/mk")
            .unwrap()
            .value_b64 = Some(BASE64URL_NOPAD.encode(&[9_u8; 32]));
        settings
            .crypto
            .materials
            .get_mut("tenant-a/docs-rk")
            .unwrap()
            .nonce = Some(BASE64URL_NOPAD.encode(&[8_u8; 12]));
        settings
            .crypto
            .materials
            .get_mut("tenant-a/docs-rk")
            .unwrap()
            .wrapped_key_b64 = Some(BASE64URL_NOPAD.encode(&[7_u8; 48]));

        assert_eq!(
            fingerprint,
            crypto_runtime_capability_fingerprint(&settings),
            "fingerprint must not expose or depend on inline/wrapped key bytes",
        );

        settings
            .crypto
            .materials
            .get_mut("tenant-a/docs-rk")
            .unwrap()
            .rk_epoch = Some(4);

        assert_ne!(
            fingerprint,
            crypto_runtime_capability_fingerprint(&settings),
            "fingerprint must change when non-secret runtime capability metadata changes",
        );

        let epoch_fingerprint = crypto_runtime_capability_fingerprint(&settings);
        settings
            .crypto
            .materials
            .get_mut("tenant-a/docs-rk")
            .unwrap()
            .state = Some(RESOURCE_KEY_STATE_RETIRED.to_string());

        assert_ne!(
            epoch_fingerprint,
            crypto_runtime_capability_fingerprint(&settings),
            "fingerprint must change when resource key lifecycle state changes",
        );
    }

    #[test]
    fn crypto_runtime_capability_parity_rejects_peer_mismatch() {
        let settings = Settings {
            crypto: CryptoSettings {
                allow_inline_key_material: true,
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: "payload/aes-256-gcm@v1".to_string(),
                        materials: HashMap::from([(
                            PAYLOAD_SYM_KEY_ROLE.to_string(),
                            "tenant-a/docs-rk".to_string(),
                        )]),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a/docs",
                            "material_fingerprint_id": "tenant-a/docs-rk@v1",
                        }),
                    },
                )]),
                materials: HashMap::from([
                    (
                        "tenant-a/mk".to_string(),
                        CryptoMaterialConfig {
                            kind: WRAPPING_KEY_32_KIND.to_string(),
                            source: Some("inline".to_string()),
                            value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                    (
                        "tenant-a/docs-rk".to_string(),
                        CryptoMaterialConfig {
                            kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                            source: Some("wrapped".to_string()),
                            wrapped_by: Some("tenant-a/mk".to_string()),
                            wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                            nonce: Some(BASE64URL_NOPAD.encode(&[2_u8; 12])),
                            wrapped_key_b64: Some(BASE64URL_NOPAD.encode(&[3_u8; 48])),
                            rk_epoch: Some(3),
                            scope: Some("collection:docs".to_string()),
                            ..CryptoMaterialConfig::default()
                        },
                    ),
                ]),
                backends: HashMap::new(),
            },
            ..Settings::new(None).unwrap()
        };
        let local_fingerprint = crypto_runtime_capability_fingerprint(&settings);
        validate_crypto_runtime_capability_parity(
            &settings,
            [("peer-a", local_fingerprint.as_str())],
        )
        .unwrap();

        let mut peer_with_different_secret_bytes = settings.clone();
        peer_with_different_secret_bytes
            .crypto
            .materials
            .get_mut("tenant-a/mk")
            .unwrap()
            .value_b64 = Some(BASE64URL_NOPAD.encode(&[9_u8; 32]));
        peer_with_different_secret_bytes
            .crypto
            .materials
            .get_mut("tenant-a/docs-rk")
            .unwrap()
            .wrapped_key_b64 = Some(BASE64URL_NOPAD.encode(&[8_u8; 48]));
        let peer_secret_fingerprint =
            crypto_runtime_capability_fingerprint(&peer_with_different_secret_bytes);
        validate_crypto_runtime_capability_parity(
            &settings,
            [("peer-secret-redacted", peer_secret_fingerprint.as_str())],
        )
        .unwrap();

        let mut peer_with_different_epoch = settings.clone();
        peer_with_different_epoch
            .crypto
            .materials
            .get_mut("tenant-a/docs-rk")
            .unwrap()
            .rk_epoch = Some(4);
        let peer_epoch_fingerprint =
            crypto_runtime_capability_fingerprint(&peer_with_different_epoch);
        let err = validate_crypto_runtime_capability_parity(
            &settings,
            [("peer-b", peer_epoch_fingerprint.as_str())],
        )
        .expect_err("runtime capability mismatch must fail closed");

        assert!(
            err.to_string()
                .contains("crypto runtime capability mismatch")
        );
        assert!(err.to_string().contains("peer-b"));
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
    fn validate_crypto_settings_rejects_unknown_wrapped_resource_key_state() {
        let wrapping_material = CryptoMaterialConfig {
            kind: WRAPPING_KEY_32_KIND.to_string(),
            source: Some("inline".to_string()),
            env: None,
            path: None,
            value_b64: Some(BASE64URL_NOPAD.encode(&[91u8; 32])),
            ..CryptoMaterialConfig::default()
        };
        let settings = CryptoSettings {
            allow_inline_key_material: true,
            materials: HashMap::from([
                ("tenant-a/mk-v1".to_string(), wrapping_material),
                (
                    "tenant-a/payload-rk-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                        wrapped_by: Some("tenant-a/mk-v1".to_string()),
                        wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                        nonce: Some("nonce".to_string()),
                        wrapped_key_b64: Some("wrapped".to_string()),
                        rk_epoch: Some(3),
                        state: Some("paused".to_string()),
                        scope: Some("collection:docs".to_string()),
                        ..CryptoMaterialConfig::default()
                    },
                ),
            ]),
            ..CryptoSettings::default()
        };

        assert_eq!(
            validate_crypto_settings(&settings),
            Err(CryptoSetupError::InvalidWrappedMaterial {
                material: "tenant-a/payload-rk-v1".to_string(),
                reason: "unsupported state paused".to_string(),
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

        let mut rotated_settings = settings.clone();
        rotated_settings.crypto.materials.insert(
            "tenant-a/payload-v2".to_string(),
            CryptoMaterialConfig {
                kind: SYMMETRIC_KEY_32_KIND.to_string(),
                source: Some("inline".to_string()),
                env: None,
                path: None,
                value_b64: Some(BASE64URL_NOPAD.encode(&[8u8; 32])),
                ..CryptoMaterialConfig::default()
            },
        );
        let rotated_instance = rotated_settings
            .crypto
            .instances
            .get_mut("docs_payload_v1")
            .unwrap();
        rotated_instance.materials.insert(
            PAYLOAD_SYM_KEY_ROLE.to_string(),
            "tenant-a/payload-v2".to_string(),
        );
        let options = rotated_instance.options.as_object_mut().unwrap();
        options.insert(
            MATERIAL_FINGERPRINT_ID_OPTION.to_string(),
            json!("tenant-a/payload@v6"),
        );
        options.insert(
            RETIRED_MATERIALS_OPTION.to_string(),
            json!([{
                "material": "tenant-a/payload-v1",
                "material_fingerprint_id": "tenant-a/payload@v5",
            }]),
        );

        params.encryption.as_mut().unwrap().encryption_epoch = 6;
        let mut active_as_retired_settings = rotated_settings.clone();
        active_as_retired_settings
            .crypto
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(
                RETIRED_MATERIALS_OPTION.to_string(),
                json!([{
                    "material": "tenant-a/payload-v2",
                    "material_fingerprint_id": "tenant-a/payload@v6",
                }]),
            );
        assert!(matches!(
            payload_write_plan_for_collection(&active_as_retired_settings, "docs", &params),
            Err(PayloadWriteSetupError::InvalidRetiredMaterials { .. })
        ));

        let rotated_plan = payload_write_plan_for_collection(&rotated_settings, "docs", &params)
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
            payload
                .0
                .get("body")
                .and_then(|body| body.get("$qdrant_ckks"))
                .and_then(|marker| marker.get("envelope"))
                .and_then(|envelope| envelope.get("material_fingerprint"))
                .and_then(|fingerprint| fingerprint.as_str()),
            Some("tenant-a/payload@v6"),
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
    fn payload_write_plan_accepts_valid_signed_client_envelopes_without_server_key_material() {
        let (signed_envelope, public_key) =
            signed_client_envelope("docs", "point-1", "body", "tenant-a/client-signing-v1");
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: client_policy_options(json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "key_id_required": true,
                            "signature_key_id": "tenant-a/client-signing-v1",
                            "signature_public_key_b64": BASE64URL_NOPAD.encode(&public_key),
                        })),
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
            json!({ "body": signed_envelope })
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
                        options: client_policy_options(json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "key_id_required": true,
                            "signature_key_id": "tenant-a/client-signing-v1",
                            "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                        })),
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
        let (signed_envelope, public_key) = signed_client_envelope(
            "crypto-docs-uuid",
            "point-1",
            "body",
            "tenant-a/client-signing-v1",
        );
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_client_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: client_policy_options(json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "signature_key_id": "tenant-a/client-signing-v1",
                            "signature_public_key_b64": BASE64URL_NOPAD.encode(&public_key),
                        })),
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
            json!({ "body": signed_envelope })
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
                        options: client_policy_options(json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "signature_key_id": "tenant-a/client-signing-v1",
                            "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                        })),
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
    fn payload_write_plan_enforces_client_resource_key_policy() {
        let (signed_envelope, public_key) =
            signed_client_envelope("docs", "point-1", "body", "tenant-a/client-signing-v1");
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
                            "expected_rk_id": "tenant-a/client-rk-2026-04",
                            "min_rk_epoch": 3,
                            "max_rk_epoch": 3,
                            "signature_key_id": "tenant-a/client-signing-v1",
                            "signature_public_key_b64": BASE64URL_NOPAD.encode(&public_key),
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

        let mut wrong_rk_envelope = signed_envelope.clone();
        wrong_rk_envelope
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "rk_id".to_string(),
                Value::String("tenant-a/old-client-rk".to_string()),
            );
        let mut wrong_rk_payload = payload_from_envelope(wrong_rk_envelope);
        assert!(matches!(
            plan.encrypt_payload("point-1", &mut wrong_rk_payload),
            Err(PayloadWriteSetupError::Payload(
                PayloadEncryptionError::ClientResourceKeyIdMismatch
            ))
        ));

        let mut stale_epoch_envelope = signed_envelope;
        stale_epoch_envelope
            .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("rk_epoch".to_string(), json!(2));
        let mut stale_epoch_payload = payload_from_envelope(stale_epoch_envelope);
        assert!(matches!(
            plan.encrypt_payload("point-1", &mut stale_epoch_payload),
            Err(PayloadWriteSetupError::Payload(
                PayloadEncryptionError::ClientResourceKeyEpochMismatch
            ))
        ));
    }

    #[test]
    fn payload_write_plan_rejects_client_nonce_replay_with_shared_cache() {
        let (first_envelope, first_public_key) =
            signed_client_envelope("docs", "point-1", "body", "tenant-a/client-signing-v1");
        let (second_envelope, second_public_key) =
            signed_client_envelope("docs", "point-2", "body", "tenant-a/client-signing-v2");
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
                            "expected_rk_id": "tenant-a/client-rk-2026-04",
                            "min_rk_epoch": 3,
                            "max_rk_epoch": 3,
                            "signature_public_keys": {
                                "tenant-a/client-signing-v1": BASE64URL_NOPAD.encode(&first_public_key),
                                "tenant-a/client-signing-v2": BASE64URL_NOPAD.encode(&second_public_key),
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
        let mut seen_client_nonces = HashSet::new();
        let payload_from_envelope =
            |envelope: Value| Payload(json!({ "body": envelope }).as_object().unwrap().clone());

        let mut first_payload = payload_from_envelope(first_envelope);
        assert_eq!(
            plan.encrypt_payload_with_replay_cache(
                "point-1",
                &mut first_payload,
                &mut seen_client_nonces,
            )
            .unwrap(),
            1,
        );

        let mut second_payload = payload_from_envelope(second_envelope);
        assert!(matches!(
            plan.encrypt_payload_with_replay_cache(
                "point-2",
                &mut second_payload,
                &mut seen_client_nonces,
            ),
            Err(PayloadWriteSetupError::Payload(
                PayloadEncryptionError::ClientNonceReplay
            ))
        ));

        let mut fresh_request_payload = second_payload;
        assert_eq!(
            plan.encrypt_payload("point-2", &mut fresh_request_payload)
                .unwrap(),
            1,
        );
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
    fn payload_write_plan_rejects_client_binding_for_server_provider() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({ "key_id": "tenant-a:docs" }),
                    },
                )]),
                ..CryptoSettings::default()
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
                    id: "body_conf".to_string(),
                    selector: EncryptionSelector::PayloadPaths {
                        paths: vec!["body".to_string()],
                    },
                    instance: "docs_payload_v1".to_string(),
                    binding: Some(CLIENT_PAYLOAD_ENVELOPE_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        assert!(matches!(
            payload_write_plan_for_collection(&settings, "docs", &params),
            Err(PayloadWriteSetupError::InvalidPayloadBinding {
                collection,
                rule_id,
                binding,
            }) if collection == "docs"
                && rule_id == "body_conf"
                && binding == PAYLOAD_FIELD_BINDING
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
        let raw_settings_with_options = |options: serde_json::Value| Settings {
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
        let settings_with_options = |options: serde_json::Value| -> Settings {
            raw_settings_with_options(client_policy_options(options))
        };

        assert!(matches!(
            payload_write_plan_for_collection(
                &raw_settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    "min_rk_epoch": 3,
                    "max_rk_epoch": 3,
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::MissingClientResourceKeyId { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &raw_settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "expected_rk_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    "max_rk_epoch": 3,
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::MissingClientResourceKeyEpoch { instance, option })
                if instance == "docs_payload_client_v1" && option == MIN_RK_EPOCH_OPTION
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &raw_settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "expected_rk_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    "min_rk_epoch": 3,
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::MissingClientResourceKeyEpoch { instance, option })
                if instance == "docs_payload_client_v1" && option == MAX_RK_EPOCH_OPTION
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &raw_settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "expected_rk_id": "tenant-a/other-client-rk",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    "min_rk_epoch": 3,
                    "max_rk_epoch": 3,
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::ClientResourceKeyIdCollectionMismatch { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &raw_settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "expected_rk_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    "min_rk_epoch": 4,
                    "max_rk_epoch": 3,
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::InvalidClientResourceKeyEpochRange { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &raw_settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "expected_rk_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    "min_rk_epoch": 3,
                    "max_rk_epoch": 4,
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::ClientResourceKeyEpochMustBePinned { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "not valid",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::InvalidInstanceKeyId { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &raw_settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "expected_rk_id": "not valid",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    "min_rk_epoch": 3,
                    "max_rk_epoch": 3,
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::InvalidClientResourceKeyId { instance })
                if instance == "docs_payload_client_v1"
        ));

        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "key_id_required": false,
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::ClientKeyIdMustBeRequired { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::MissingClientSignatureVerifier { instance })
                if instance == "docs_payload_client_v1"
        ));
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "not valid",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::InvalidClientSignatureKeyId { instance })
                if instance == "docs_payload_client_v1"
        ));
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
                        "not valid": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    },
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
    fn payload_write_plan_keeps_client_provider_server_blind() {
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
        let base_instance = CryptoInstanceConfig {
            provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
            materials: HashMap::new(),
            backend_ref: None,
            options: client_policy_options(json!({
                "key_id": "tenant-a/client-rk-2026-04",
                "signature_key_id": "tenant-a/client-signing-v1",
                "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
            })),
        };

        let settings_with_instance = |instance: CryptoInstanceConfig| Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([("docs_payload_client_v1".to_string(), instance)]),
                materials: HashMap::from([(
                    "tenant-a/server-rk".to_string(),
                    CryptoMaterialConfig {
                        kind: SYMMETRIC_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        env: None,
                        path: None,
                        value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                backends: HashMap::from([(
                    "openfhe_local".to_string(),
                    CryptoBackendConfig {
                        kind: "noop".to_string(),
                        program: None,
                        sha256_b64: None,
                        size: None,
                        timeout_ms: None,
                    },
                )]),
                allow_inline_key_material: true,
            },
            ..Settings::new(None).unwrap()
        };

        let mut material_bound = base_instance.clone();
        material_bound.materials = HashMap::from([(
            PAYLOAD_SYM_KEY_ROLE.to_string(),
            "tenant-a/server-rk".to_string(),
        )]);
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_instance(material_bound),
                "docs",
                &params
            ),
            Err(PayloadWriteSetupError::ClientProviderMustBeServerBlind { instance })
                if instance == "docs_payload_client_v1"
        ));

        let mut backend_bound = base_instance;
        backend_bound.backend_ref = Some("openfhe_local".to_string());
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_instance(backend_bound),
                "docs",
                &params
            ),
            Err(PayloadWriteSetupError::ClientProviderMustBeServerBlind { instance })
                if instance == "docs_payload_client_v1"
        ));
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
                        options: client_policy_options(json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "signature_key_id": "tenant-a/client-signing-v1",
                            "signature_public_key_b64": BASE64URL_NOPAD
                                .encode(key_pair.public_key().as_ref()),
                        })),
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
                        options: client_policy_options(json!({
                            "key_id": "tenant-a/client-rk-2026-04",
                            "signature_public_keys": {
                                "tenant-a/client-signing-v1": BASE64URL_NOPAD
                                    .encode(key_pair_v1.public_key().as_ref()),
                                "tenant-a/client-signing-v2": BASE64URL_NOPAD
                                    .encode(key_pair_v2.public_key().as_ref()),
                            },
                        })),
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

        for (state, expected_error) in [
            (
                RESOURCE_KEY_STATE_RETIRED,
                "retired resource key material cannot be used for active encryption",
            ),
            (
                RESOURCE_KEY_STATE_DISABLED,
                "resource key material state disabled cannot be unwrapped",
            ),
            (
                RESOURCE_KEY_STATE_DESTROYED,
                "resource key material state destroyed cannot be unwrapped",
            ),
        ] {
            let mut state_settings = settings.clone();
            state_settings
                .crypto
                .materials
                .get_mut(rk_material)
                .unwrap()
                .state = Some(state.to_string());
            assert!(matches!(
                payload_write_plan_for_collection(&state_settings, "docs", &params),
                Err(PayloadWriteSetupError::InvalidWrappedMaterial { material, reason })
                    if material == rk_material && reason == expected_error
            ));
        }

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

        let mut retired_runtime_settings = runtime_settings.clone();
        retired_runtime_settings
            .materials
            .get_mut(rk_material)
            .unwrap()
            .state = Some(RESOURCE_KEY_STATE_RETIRED.to_string());
        let retired_rewrapped = rewrap_runtime_resource_key_material(
            &retired_runtime_settings,
            rk_material,
            new_mk_material,
        )
        .unwrap();
        assert_eq!(
            retired_rewrapped.state.as_deref(),
            Some(RESOURCE_KEY_STATE_RETIRED)
        );
        assert_eq!(
            retired_rewrapped.wrapped_by.as_deref(),
            Some(new_mk_material)
        );
        assert_eq!(retired_rewrapped.rk_epoch, Some(3));
        assert_eq!(retired_rewrapped.scope.as_deref(), Some("collection:docs"));

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
    fn validate_recovered_collection_crypto_runtime_rejects_invalid_crypto_selectors() {
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

        let err = validate_recovered_collection_crypto_runtime(&settings, "docs", &params)
            .expect_err("recovered vector selector must fail schema validation");
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("recovered collection docs encryption config is invalid")
                    && description.contains("unsupported_encryption_selector")),
            "unexpected error: {err:?}",
        );

        let legacy_params = CollectionParams {
            ckks: Some(CkksCollectionConfig {
                enabled: true,
                key_id: Some("tenant-a:docs".to_string()),
                payload_text_fields: Vec::new(),
                vector_names: vec!["embedding".to_string()],
            }),
            ..CollectionParams::empty()
        };
        let err = validate_recovered_collection_crypto_runtime(&settings, "docs", &legacy_params)
            .expect_err("recovered legacy vector selector must fail schema validation");
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("recovered collection docs ckks config is invalid")
                    && description.contains("unsupported_ckks_vector_selector")),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn validate_recovered_collection_crypto_config_requires_encrypted_uuid() {
        let settings = Settings::new(None).unwrap();
        let encrypted_params = CollectionParams {
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

        let err = validate_recovered_collection_crypto_config(
            &settings,
            "docs",
            &recovered_config(encrypted_params, None),
        )
        .expect_err("encrypted snapshot config without UUID must fail before runtime lookup");
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("recovered encrypted collection docs is missing a stable UUID")),
            "unexpected error: {err:?}",
        );

        validate_recovered_collection_crypto_config(
            &settings,
            "docs",
            &recovered_config(CollectionParams::empty(), None),
        )
        .unwrap();
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
    fn validate_collection_crypto_runtime_rejects_wrong_vector_binding() {
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
                    binding: Some(PAYLOAD_FIELD_BINDING.to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_collection_crypto_runtime(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("vector rule embedding_conf must use binding")
                    && description.contains(VECTOR_ENVELOPE_BINDING)),
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
